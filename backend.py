import time
import hmac
import hashlib
import jwt
from urllib.parse import unquote
from fastapi import FastAPI, HTTPException, Depends, Body
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
    try:
        # Парсим параметры из строки
        params = {}
        for item in data.split("&"):
            if "=" in item:
                key, value = item.split("=", 1)
                # URL-декодируем значения
                params[key] = unquote(value)
        
        print(f"Parsed params: {params}")
        
        # Извлекаем хеш
        hash_to_check = params.pop("hash", None)
        if not hash_to_check:
            raise HTTPException(status_code=400, detail="Missing hash")
        
        # Удаляем signature, если есть (не участвует в валидации)
        params.pop("signature", None)
        
        # Создаем строку для проверки
        data_check_string = "\n".join(f"{k}={v}" for k, v in sorted(params.items()))
        print(f"Data check string: {data_check_string}")
        
        # Создаем секретный ключ
        secret_key = hashlib.sha256(bot_token.encode()).digest()
        
        # Вычисляем HMAC
        hmac_hash = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()
        print(f"Expected hash: {hmac_hash}")
        print(f"Received hash: {hash_to_check}")
        
        if not hmac.compare_digest(hmac_hash, hash_to_check):
            raise HTTPException(status_code=403, detail="Invalid initData hash")
        
        # Проверяем время (данные не должны быть старше 24 часов)
        auth_date = int(params.get("auth_date", 0))
        current_time = int(time.time())
        if current_time - auth_date > 86400:  # 24 часа
            raise HTTPException(status_code=403, detail="initData is too old")
        
        return params
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error parsing initData: {e}")
        raise HTTPException(status_code=400, detail=f"Invalid initData format: {str(e)}")


def create_jwt(telegram_id: int):
    payload = {
        "telegram_id": telegram_id,
        "exp": time.time() + JWT_EXP_DELTA_SECONDS,
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token


def get_current_user(token: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(token.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        telegram_id = payload.get("telegram_id")
        if telegram_id is None:
            raise HTTPException(status_code=401, detail="Invalid token payload")
        return telegram_id
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")


class AuthRequest(BaseModel):
    init_data: str


@app.post("/auth")
async def auth(data: AuthRequest):
    print("Получен init_data:", data.init_data)
    try:
        params = check_telegram_auth(data.init_data, TELEGRAM_BOT_TOKEN)
        
        # Парсим user из JSON строки
        import json
        user_data = json.loads(params.get("user", "{}"))
        user_id = user_data.get("id")
        
        if not user_id:
            raise HTTPException(status_code=400, detail="User ID not found in initData")
            
        token = create_jwt(user_id)
        return {"token": token}
        
    except HTTPException as e:
        print("Ошибка проверки initData:", e.detail)
        raise e
    except Exception as e:
        print(f"Unexpected error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@app.get("/balance")
async def get_balance(telegram_id: int = Depends(get_current_user)):
    pool = await get_pool()
    async with pool.acquire() as conn:
        result = await conn.fetchval(
            "SELECT balance FROM players WHERE nickname = $1", str(telegram_id)
        )
        return {"balance": result or 0}


@app.on_event("startup")
async def startup():
    await create_pool()


@app.on_event("shutdown")
async def shutdown():
    await close_pool()
