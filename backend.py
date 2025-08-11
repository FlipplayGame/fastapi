import time
import hmac
import hashlib
import os
from typing import Optional
import jwt  # PyJWT
import json
from urllib.parse import unquote
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from database import create_pool, close_pool, get_pool

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # В продакшене указать конкретные домены
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Конфигурация (лучше вынести в переменные окружения)
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "7518552373:AAEsz41grTWOKUnokKBaSBMujTxyVgn_EOk")
JWT_SECRET = os.getenv("JWT_SECRET", "supersecretjwtkey")
JWT_ALGORITHM = "HS256"
JWT_EXP_DELTA_SECONDS = 3600 * 24

security = HTTPBearer()

class AuthRequest(BaseModel):
    init_data: str

class GuessGameRequest(BaseModel):
    guess: int

class StartGuessGameRequest(BaseModel):
    difficulty: str = "medium"


def check_telegram_auth(data: str, bot_token: str) -> dict:
    """
    Валидация initData от Telegram WebApp
    """
    try:
        print(f"🔍 Validating init_data: {data}")
        
        # Парсим параметры
        params = {}
        for item in data.split("&"):
            if "=" in item:
                key, value = item.split("=", 1)
                params[key] = unquote(value)
        
        # Извлекаем hash для проверки
        received_hash = params.pop("hash", None)
        if not received_hash:
            raise HTTPException(status_code=400, detail="Hash parameter missing")
        
        # Удаляем лишние поля (signature не должно быть в WebApp)
        params.pop("signature", None)
        
        # Создаем строку для проверки
        data_check_arr = []
        for key, value in sorted(params.items()):
            data_check_arr.append(f"{key}={value}")
        
        data_check_string = "\n".join(data_check_arr)
        
        # Создаем секретный ключ
        secret_key = hmac.new(
            "WebAppData".encode(), 
            bot_token.encode(), 
            hashlib.sha256
        ).digest()
        
        # Вычисляем хеш
        calculated_hash = hmac.new(
            secret_key, 
            data_check_string.encode(), 
            hashlib.sha256
        ).hexdigest()
        
        # Сравниваем хеши
        if not hmac.compare_digest(calculated_hash, received_hash):
            print(f"❌ Hash mismatch:")
            print(f"   Received: {received_hash}")
            print(f"   Calculated: {calculated_hash}")
            print(f"   Data string: {data_check_string}")
            raise HTTPException(status_code=400, detail="Invalid hash signature")
        
        # Проверяем время (опционально, данные не должны быть старше 1 часа)
        auth_date = params.get("auth_date")
        if auth_date:
            try:
                auth_timestamp = int(auth_date)
                current_timestamp = int(time.time())
                if current_timestamp - auth_timestamp > 3600:  # 1 час
                    raise HTTPException(status_code=400, detail="Data is too old")
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid auth_date format")
        
        print("✅ Telegram WebApp data validated successfully")
        return params
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"💥 Error validating initData: {e}")
        raise HTTPException(status_code=400, detail=f"Invalid initData: {str(e)}")


def create_jwt(telegram_id: int) -> str:
    """Создание JWT токена"""
    try:
        payload = {
            "telegram_id": telegram_id,
            "exp": int(time.time()) + JWT_EXP_DELTA_SECONDS,
        }
        
        token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
        print(f"✅ JWT created for user {telegram_id}")
        
        # PyJWT 2.x возвращает string
        if isinstance(token, bytes):
            token = token.decode('utf-8')
            
        return token
        
    except Exception as e:
        print(f"💥 JWT creation error: {e}")
        raise HTTPException(status_code=500, detail="Token creation failed")


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
        print(f"💥 Token validation error: {e}")
        raise HTTPException(status_code=401, detail="Token validation failed")


@app.post("/auth")
async def auth(data: AuthRequest):
    print(f"\n🚀 === AUTH REQUEST ===")
    
    try:
        # Валидируем данные Telegram WebApp
        params = check_telegram_auth(data.init_data, TELEGRAM_BOT_TOKEN)
        
        # Извлекаем данные пользователя
        user_json = params.get("user")
        if not user_json:
            raise HTTPException(status_code=400, detail="User data not found")
        
        # Парсим JSON пользователя
        try:
            user_data = json.loads(user_json)
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="Invalid user JSON format")
        
        # Получаем ID пользователя
        user_id = user_data.get("id")
        if not user_id:
            raise HTTPException(status_code=400, detail="User ID not found")
        
        try:
            user_id = int(user_id)
        except (ValueError, TypeError):
            raise HTTPException(status_code=400, detail="Invalid user ID format")
        
        nickname = user_data.get('first_name', 'Anonymous')
        
        print(f"✅ User authenticated: ID {user_id}, Name: {nickname}")
        
        # Добавляем/обновляем пользователя в БД
        try:
            pool = await get_pool()
            async with pool.acquire() as conn:
                await conn.execute("""
                    INSERT INTO players (telegram_id, nickname, attempts, balance) 
                    VALUES ($1, $2, 3, 0) 
                    ON CONFLICT (telegram_id) DO UPDATE SET 
                        nickname = EXCLUDED.nickname
                """, user_id, nickname)
        except Exception as e:
            print(f"⚠️ Database error: {e}")
            # Продолжаем работу
        
        # Создаем JWT токен
        token = create_jwt(user_id)
        
        return {
            "token": token,
            "user": {
                "id": user_id,
                "username": user_data.get("username"),
                "first_name": user_data.get("first_name"),
                "last_name": user_data.get("last_name"),
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"💥 Auth error: {e}")
        raise HTTPException(status_code=500, detail="Authentication failed")


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
            
            return {
                "balance": row["balance"] or 0,
                "nickname": row["nickname"]
            }
    except Exception as e:
        print(f"💥 Balance error: {e}")
        raise HTTPException(status_code=500, detail="Database error")


@app.get("/leaderboard")
async def get_leaderboard():
    try:
        pool = await get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT nickname, balance FROM players ORDER BY balance DESC LIMIT 10"
            )
            return [{"nickname": row["nickname"], "balance": row["balance"]} for row in rows]
    except Exception as e:
        print(f"💥 Leaderboard error: {e}")
        raise HTTPException(status_code=500, detail="Database error")


@app.post("/balance/update")
async def update_balance(telegram_id: int = Depends(get_current_user)):
    """Добавить 100 к балансу"""
    try:
        pool = await get_pool()
        async with pool.acquire() as conn:
            new_balance = await conn.fetchval(
                "UPDATE players SET balance = COALESCE(balance, 0) + 100 WHERE telegram_id = $1 RETURNING balance",
                telegram_id
            )
            if new_balance is None:
                raise HTTPException(status_code=404, detail="User not found")
            
            return {"balance": new_balance}
    except HTTPException:
        raise
    except Exception as e:
        print(f"💥 Balance update error: {e}")
        raise HTTPException(status_code=500, detail="Database error")


@app.get("/attempts")
async def get_attempts(telegram_id: int = Depends(get_current_user)):
    """Получить количество попыток"""
    try:
        pool = await get_pool()
        async with pool.acquire() as conn:
            # Добавляем колонку attempts если её нет
            try:
                await conn.execute("ALTER TABLE players ADD COLUMN IF NOT EXISTS attempts INTEGER DEFAULT 3")
            except:
                pass  # Колонка уже существует
            
            attempts = await conn.fetchval(
                "SELECT attempts FROM players WHERE telegram_id = $1", telegram_id
            )
            
            if attempts is None:
                # Пользователь не найден, создаем
                await conn.execute(
                    "INSERT INTO players (telegram_id, attempts) VALUES ($1, 3) ON CONFLICT (telegram_id) DO NOTHING",
                    telegram_id
                )
                attempts = 3
            
            # Если attempts NULL, устанавливаем 3
            if attempts is None:
                await conn.execute(
                    "UPDATE players SET attempts = 3 WHERE telegram_id = $1 AND attempts IS NULL", 
                    telegram_id
                )
                attempts = 3
            
            return {"attempts": attempts}
    except Exception as e:
        print(f"💥 Get attempts error: {e}")
        raise HTTPException(status_code=500, detail="Database error")


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
        print(f"💥 Use attempt error: {e}")
        raise HTTPException(status_code=500, detail="Database error")


@app.post("/attempts/add")
async def add_attempts(telegram_id: int = Depends(get_current_user)):
    """Добавить одну попытку"""
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
        print(f"💥 Add attempts error: {e}")
        raise HTTPException(status_code=500, detail="Database error")


@app.get("/")
async def root():
    return {
        "message": "Telegram WebApp API", 
        "status": "running",
        "timestamp": int(time.time())
    }


@app.on_event("startup")
async def startup():
    print("🚀 Starting up...")
    await create_pool()
    print("✅ Database pool created")


@app.on_event("shutdown")
async def shutdown():
    print("🛑 Shutting down...")
    await close_pool()
    print("✅ Database pool closed")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
