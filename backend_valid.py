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
    Валидация данных Telegram WebApp с правильным алгоритмом
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
        
        # Удаляем signature если присутствует (не участвует в валидации hash)
        params.pop("signature", None)
        
        # Обрабатываем photo_url - заменяем / на \/ как в оригинальных данных
        user_json = params.get("user")
        if user_json:
            try:
                user_data = json.loads(user_json)
                if "photo_url" in user_data and user_data["photo_url"]:
                    # Восстанавливаем экранированные слеши как в исходных данных
                    user_data["photo_url"] = user_data["photo_url"].replace("/", "\\/")
                    params["user"] = json.dumps(user_data, separators=(',', ':'))
            except json.JSONDecodeError:
                pass
        
        # Создаем строку для проверки (сортируем ключи)
        data_check_string = "\n".join([f"{k}={v}" for k, v in sorted(params.items())])
        
        print(f"Data check string: {repr(data_check_string)}")
        
        # Создаем секретный ключ для WebApp (правильный алгоритм)
        secret_key = hmac.new(b"WebAppData", bot_token.encode(), hashlib.sha256).digest()
        
        # Вычисляем хеш
        calculated_hash = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()
        
        print(f"Calculated hash: {calculated_hash}")
        print(f"Received hash:   {received_hash}")
        
        # Проверяем хеш
        if not hmac.compare_digest(calculated_hash, received_hash):
            raise HTTPException(status_code=401, detail="Invalid hash - data may be tampered")
        
        # Проверяем время (данные должны быть не старше 24 часов)
        auth_date = params.get("auth_date")
        if auth_date:
            try:
                auth_timestamp = int(auth_date)
                current_timestamp = int(time.time())
                if current_timestamp - auth_timestamp > 86400:  # 24 часа
                    raise HTTPException(status_code=401, detail="Init data is too old")
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid auth_date format")
        
        # Возвращаем params с исходным user JSON (без экранированных слешей)
        if user_json:
            params["user"] = user_json
        
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
