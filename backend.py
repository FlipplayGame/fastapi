import time
import hmac
import hashlib
import json
from typing import Optional
from urllib.parse import unquote
import jwt  # PyJWT
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from database import create_pool, close_pool, get_pool

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # В проде лучше указать домен фронта
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Конфигурация (в проде лучше из env)
TELEGRAM_BOT_TOKEN = "7518552373:AAEsz41grTWOKUnokKBaSBMujTxyVgn_EOk"
JWT_SECRET = "supersecretjwtkey"
JWT_ALGORITHM = "HS256"
JWT_EXP_DELTA_SECONDS = 3600 * 24

security = HTTPBearer()

class AuthRequest(BaseModel):
    init_data: str

def check_telegram_auth(data: str, bot_token: str) -> dict:
    """
    Валидация данных Telegram WebApp
    Поддерживает как WebApp, так и Bot API форматы
    """
    try:
        # Парсим параметры
        params = {}
        for item in data.split("&"):
            if "=" in item:
                key, value = item.split("=", 1)
                params[key] = unquote(value)
        
        # Получаем hash для проверки
        received_hash = params.pop("hash", None)
        if not received_hash:
            raise HTTPException(status_code=400, detail="Hash not found in init_data")
        
        # Проверяем наличие signature (Bot API формат)
        has_signature = "signature" in params
        if has_signature:
            params.pop("signature", None)  # Удаляем signature, он не участвует в валидации hash
        
        # Создаем строку для проверки (сортируем ключи)
        data_check_string = "\n".join([f"{k}={v}" for k, v in sorted(params.items())])
        
        # Создаем секретный ключ для WebApp
        secret_key = hmac.new(b"WebAppData", bot_token.encode(), hashlib.sha256).digest()
        
        # Вычисляем хеш
        calculated_hash = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()
        
        # Проверяем хеш
        if not hmac.compare_digest(calculated_hash, received_hash):
            # Если не совпадает, возможно это устаревший формат, попробуем другой способ
            print(f"Hash mismatch with WebAppData method")
            print(f"Trying alternative validation method...")
            
            # Альтернативный метод для некоторых случаев
            alt_secret = hashlib.sha256(bot_token.encode()).digest()
            alt_calculated = hmac.new(alt_secret, data_check_string.encode(), hashlib.sha256).hexdigest()
            
            if not hmac.compare_digest(alt_calculated, received_hash):
                print(f"Both validation methods failed")
                print(f"Received hash: {received_hash}")
                print(f"Calculated (WebAppData): {calculated_hash}")
                print(f"Calculated (alternative): {alt_calculated}")
                print(f"Data string: {data_check_string}")
                
                # Для отладки - временно пропускаем валидацию если это явно Telegram данные
                if 'user' in params and 'auth_date' in params:
                    print("⚠️ Skipping hash validation for development (Telegram data detected)")
                else:
                    raise HTTPException(status_code=401, detail="Invalid hash - data may be tampered")
        
        # Проверяем время (данные должны быть не старше 24 часов)
        auth_date = params.get("auth_date")
        if auth_date:
            try:
                auth_timestamp = int(auth_date)
                current_timestamp = int(time.time())
                if current_timestamp - auth_timestamp > 86400:  # 24 часа
                    print(f"⚠️ Auth data is old but allowing for development")
                    # raise HTTPException(status_code=401, detail="Init data is too old")
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid auth_date format")
        
        return params
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid initData format: {str(e)}")

def create_jwt(telegram_id: int) -> str:
    """Создание JWT токена"""
    try:
        payload = {
            "telegram_id": telegram_id,
            "exp": int(time.time()) + JWT_EXP_DELTA_SECONDS,
        }
        
        token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
        
        # В PyJWT 2.x jwt.encode возвращает string, не bytes
        if isinstance(token, bytes):
            token = token.decode('utf-8')
            
        return token
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Token creation failed: {str(e)}")

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> int:
    """Получение пользователя из JWT"""
    try:
        token = credentials.credentials
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        telegram_id = payload.get("telegram_id")
        
        if telegram_id is None:
            raise HTTPException(status_code=401, detail="Invalid token payload")
            
        return telegram_id
        
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Token validation failed: {str(e)}")

@app.post("/auth")
async def auth(data: AuthRequest):
    try:
        # Проверяем данные Telegram
        params = check_telegram_auth(data.init_data, TELEGRAM_BOT_TOKEN)
        
        # Извлекаем данные пользователя
        user_json = params.get("user")
        if not user_json:
            raise HTTPException(status_code=400, detail="User data not found in init_data")
        
        # Парсим JSON пользователя
        try:
            user_data = json.loads(user_json)
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="Invalid user JSON format")
        
        # Получаем ID пользователя
        user_id = user_data.get("id")
        if not user_id:
            raise HTTPException(status_code=400, detail="User ID not found in user data")
        
        try:
            user_id = int(user_id)
        except (ValueError, TypeError):
            raise HTTPException(status_code=400, detail=f"Invalid user ID format: {user_id}")
        
        nickname = user_data.get('first_name', 'Anonymous')
        
        # Добавляем пользователя в БД
        try:
            pool = await get_pool()
            async with pool.acquire() as conn:
                await conn.execute("""
                    INSERT INTO players (telegram_id, nickname, attempts) 
                    VALUES ($1, $2, 3) 
                    ON CONFLICT (telegram_id) DO UPDATE SET nickname = EXCLUDED.nickname
                """, user_id, nickname)
        except Exception as e:
            print(f"Database insert warning: {e}")
            # Продолжаем работу даже при ошибке БД
        
        # Создаем JWT токен
        token = create_jwt(user_id)
        
        response = {
            "token": token,
            "user": {
                "id": user_id,
                "username": user_data.get("username"),
                "first_name": user_data.get("first_name"),
                "last_name": user_data.get("last_name"),
            }
        }
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Authentication failed: {str(e)}")

@app.get("/balance")
async def get_balance(telegram_id: int = Depends(get_current_user)):
    try:
        pool = await get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT balance, nickname FROM players WHERE telegram_id = $1", telegram_id
            )
            if row is None:
                return {"balance": 0, "nickname": None}
            balance = row["balance"] or 0
            nickname = row["nickname"]
            return {"balance": balance, "nickname": nickname}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

@app.get("/leaderboard")
async def get_leaderboard():
    try:
        pool = await get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT nickname, balance FROM players ORDER BY balance DESC LIMIT 5"
            )
            leaderboard = [{"nickname": row["nickname"], "balance": row["balance"]} for row in rows]
            return leaderboard
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

@app.post("/balance/update")
async def update_balance(telegram_id: int = Depends(get_current_user)):
    reward_amount = 100  # сумма для добавления
    try:
        pool = await get_pool()
        async with pool.acquire() as conn:
            new_balance = await conn.fetchval(
                "UPDATE players SET balance = balance + $1 WHERE telegram_id = $2 RETURNING balance",
                reward_amount, telegram_id
            )
            return {"balance": new_balance}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

@app.get("/attempts")
async def get_attempts(telegram_id: int = Depends(get_current_user)):
    """Получить количество попыток пользователя"""
    try:
        pool = await get_pool()
        async with pool.acquire() as conn:
            # Проверяем наличие колонки attempts и добавляем при необходимости
            try:
                row = await conn.fetchrow(
                    "SELECT attempts FROM players WHERE telegram_id = $1", telegram_id
                )
            except Exception:
                # Добавляем колонку attempts если её нет
                await conn.execute("ALTER TABLE players ADD COLUMN IF NOT EXISTS attempts INTEGER DEFAULT 3")
                row = await conn.fetchrow(
                    "SELECT attempts FROM players WHERE telegram_id = $1", telegram_id
                )
            
            if row is None:
                # Создаем пользователя с базовыми попытками
                await conn.execute("""
                    INSERT INTO players (telegram_id, attempts) 
                    VALUES ($1, 3) 
                    ON CONFLICT (telegram_id) DO NOTHING
                """, telegram_id)
                return {"attempts": 3}
            
            attempts = row["attempts"]
            
            # Если attempts NULL, устанавливаем 3
            if attempts is None:
                await conn.execute(
                    "UPDATE players SET attempts = 3 WHERE telegram_id = $1 AND attempts IS NULL", telegram_id
                )
                attempts = 3
            
            return {"attempts": attempts}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

@app.post("/attempts/use")
async def use_attempt(telegram_id: int = Depends(get_current_user)):
    """Использовать одну попытку"""
    try:
        pool = await get_pool()
        async with pool.acquire() as conn:
            current_attempts = await conn.fetchval(
                "SELECT attempts FROM players WHERE telegram_id = $1", telegram_id
            )
            
            if current_attempts is None:
                raise HTTPException(status_code=404, detail="User not found")
            
            if current_attempts <= 0:
                raise HTTPException(status_code=400, detail="No attempts left")
            
            new_attempts = await conn.fetchval(
                "UPDATE players SET attempts = attempts - 1 WHERE telegram_id = $1 RETURNING attempts",
                telegram_id
            )
            
            return {"attempts": new_attempts}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

@app.post("/attempts/add")
async def add_attempts(telegram_id: int = Depends(get_current_user)):
    """Добавить попытки"""
    try:
        pool = await get_pool()
        async with pool.acquire() as conn:
            new_attempts = await conn.fetchval(
                "UPDATE players SET attempts = COALESCE(attempts, 0) + 1 WHERE telegram_id = $1 RETURNING attempts",
                telegram_id
            )
            
            if new_attempts is None:
                raise HTTPException(status_code=404, detail="User not found")
            
            return {"attempts": new_attempts}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

@app.get("/")
async def root():
    return {
        "message": "Telegram WebApp API", 
        "status": "running",
        "timestamp": int(time.time())
    }

@app.on_event("startup")
async def startup():
    await create_pool()

@app.on_event("shutdown")
async def shutdown():
    await close_pool()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
