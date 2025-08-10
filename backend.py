import time
import hmac
import hashlib
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
    allow_origins=["*"],  # В проде лучше указать домен фронта
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Секреты (в проде лучше из env)
TELEGRAM_BOT_TOKEN = "7518552373:AAEsz41grTWOKUnokKBaSBMujTxyVgn_EOk"
JWT_SECRET = "supersecretjwtkey"
JWT_ALGORITHM = "HS256"
JWT_EXP_DELTA_SECONDS = 3600 * 24

security = HTTPBearer()


def check_telegram_auth(data: str, bot_token: str) -> dict:
    """
    ВРЕМЕННО: валидация отключена для отладки
    TODO: После выяснения причин с signature - включить валидацию
    """
    try:
        print(f"🔍 Analyzing init_data: {data}")
        
        # Парсим параметры
        params = {}
        for item in data.split("&"):
            if "=" in item:
                key, value = item.split("=", 1)
                params[key] = unquote(value)
        
        print("📋 Parsed parameters:")
        for key, value in params.items():
            if key == 'user':
                print(f"  {key}: {value}")
            else:
                print(f"  {key}: {value}")
        
        # Проверяем наличие signature (не должно быть в WebApp!)
        if 'signature' in params:
            print("⚠️ WARNING: signature field detected - this is NOT standard WebApp format!")
        
        # Убираем служебные поля
        params.pop("hash", None)
        params.pop("signature", None)  # Убираем signature
        
        print("✅ Validation bypassed (debug mode)")
        return params
        
    except Exception as e:
        print(f"💥 Error parsing initData: {e}")
        raise HTTPException(status_code=400, detail=f"Invalid initData format: {str(e)}")


def create_jwt(telegram_id: int) -> str:
    """Создание JWT токена с исправленной обработкой"""
    try:
        payload = {
            "telegram_id": telegram_id,
            "exp": int(time.time()) + JWT_EXP_DELTA_SECONDS,
        }
        
        # Создаем токен
        token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
        
        print(f"✅ JWT created for user {telegram_id}")
        
        # В PyJWT 2.x jwt.encode возвращает string, не bytes
        if isinstance(token, bytes):
            token = token.decode('utf-8')
            
        return token
        
    except Exception as e:
        print(f"💥 JWT creation error: {e}")
        raise HTTPException(status_code=500, detail=f"Token creation failed: {str(e)}")


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> int:
    """Получение пользователя из JWT с улучшенной отладкой"""
    try:
        token = credentials.credentials
        print(f"🔐 Validating JWT token: {token[:20]}...")
        
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        telegram_id = payload.get("telegram_id")
        
        if telegram_id is None:
            print("❌ No telegram_id in payload")
            raise HTTPException(status_code=401, detail="Invalid token payload")
            
        print(f"✅ JWT valid for user {telegram_id}")
        return telegram_id
        
    except jwt.ExpiredSignatureError:
        print("❌ Token expired")
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError as e:
        print(f"❌ Invalid token: {e}")
        raise HTTPException(status_code=401, detail="Invalid token")
    except Exception as e:
        print(f"💥 Token validation error: {e}")
        raise HTTPException(status_code=401, detail=f"Token validation failed: {str(e)}")


class AuthRequest(BaseModel):
    init_data: str


@app.post("/auth")
async def auth(data: AuthRequest):
    print(f"\n🚀 === AUTH REQUEST ===")
    print(f"Received init_data: {data.init_data}")
    
    try:
        # Парсим и проверяем данные
        params = check_telegram_auth(data.init_data, TELEGRAM_BOT_TOKEN)
        
        # Извлекаем данные пользователя
        user_json = params.get("user")
        if not user_json:
            raise HTTPException(status_code=400, detail="User data not found in init_data")
        
        print(f"👤 User JSON: {user_json}")
        
        # Парсим JSON пользователя
        try:
            user_data = json.loads(user_json)
            print(f"🔍 Parsed user_data: {user_data}")
        except json.JSONDecodeError as e:
            print(f"❌ JSON decode error: {e}")
            raise HTTPException(status_code=400, detail="Invalid user JSON format")
        
        # Получаем и преобразуем ID пользователя
        user_id_raw = user_data.get("id")
        print(f"🆔 Raw user_id from JSON: {user_id_raw} (type: {type(user_id_raw)})")
        
        if not user_id_raw:
            raise HTTPException(status_code=400, detail="User ID not found in user data")
        
        # Преобразуем в int
        try:
            user_id = int(user_id_raw)
            print(f"✅ Converted user_id: {user_id} (type: {type(user_id)})")
        except (ValueError, TypeError) as e:
            print(f"❌ Cannot convert user_id to int: {user_id_raw}, error: {e}")
            raise HTTPException(status_code=400, detail=f"Invalid user ID format: {user_id_raw}")
        
        nickname = user_data.get('first_name', 'Anonymous')
        
        print(f"✅ User authenticated:")
        print(f"   ID: {user_id} (type: {type(user_id).__name__})")
        print(f"   Username: {user_data.get('username', 'N/A')}")
        print(f"   Name: {nickname}")
        
        # Добавляем пользователя в БД
        try:
            pool = await get_pool()
            async with pool.acquire() as conn:
                await conn.execute("""
                    INSERT INTO players (telegram_id, nickname) 
                    VALUES ($1, $2) 
                    ON CONFLICT (telegram_id) DO NOTHING
                """, user_id, nickname)
                print(f"✅ User {user_id} added to database (or already exists)")
        
        except Exception as e:
            print(f"⚠️ Database insert warning: {e}")
            # Продолжаем работу даже при ошибке БД
        
        # Создаем JWT токен с int значением
        try:
            token = create_jwt(user_id)
            print(f"✅ JWT token created for user {user_id}")
        except Exception as e:
            print(f"❌ JWT creation error: {e}")
            raise HTTPException(status_code=500, detail=f"Token creation failed: {str(e)}")
        
        response = {
            "token": token,
            "user": {
                "id": user_id,
                "username": user_data.get("username"),
                "first_name": user_data.get("first_name"),
                "last_name": user_data.get("last_name"),
            }
        }
        
        print(f"✅ Auth successful, returning token")
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"💥 Unexpected auth error: {e}")
        print(f"💥 Error type: {type(e)}")
        import traceback
        traceback.print_exc()
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
        print(f"💥 Balance error: {e}")
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")



@app.post("/balance/update")
async def get_balance_update(telegram_id: int = Depends(get_current_user)):
    current_game = 100  # сумма для добавления
    try:
        pool = await get_pool()
        async with pool.acquire() as conn:
            # Обновляем баланс и возвращаем новое значение
            new_balance = await conn.fetchval(
                "UPDATE players SET balance = balance + $1 WHERE telegram_id = $2 RETURNING balance",
                current_game, telegram_id
            )
            return {"balance": new_balance}
    except Exception as e:
        print(f"💥 Balance error: {e}")
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")




@app.get("/me")
async def get_me(telegram_id: int = Depends(get_current_user)):
    """Тестовый эндпоинт для проверки JWT"""
    return {
        "telegram_id": telegram_id, 
        "message": "JWT authentication works!",
        "timestamp": int(time.time())
    }


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


# Для локального запуска
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
