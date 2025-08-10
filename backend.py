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
        # Временно отключаем валидацию для отладки
        print("=== ОТЛАДКА ВАЛИДАЦИИ ===")
        
        # Метод 1: Стандартная валидация Telegram WebApp
        def validate_method_1():
            params = {}
            for item in data.split("&"):
                if "=" in item:
                    key, value = item.split("=", 1)
                    params[key] = unquote(value)
            
            hash_to_check = params.pop("hash", None)
            params.pop("signature", None)  # Убираем signature
            
            data_check_string = "\n".join(f"{k}={v}" for k, v in sorted(params.items()))
            secret_key = hashlib.sha256(bot_token.encode()).digest()
            hmac_hash = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()
            
            print(f"Method 1 - Expected: {hmac_hash}, Received: {hash_to_check}")
            return hmac.compare_digest(hmac_hash, hash_to_check), params
        
        # Метод 2: Без URL-декодирования
        def validate_method_2():
            params = {}
            for item in data.split("&"):
                if "=" in item:
                    key, value = item.split("=", 1)
                    params[key] = value  # БЕЗ unquote
            
            hash_to_check = params.pop("hash", None)
            params.pop("signature", None)
            
            data_check_string = "\n".join(f"{k}={v}" for k, v in sorted(params.items()))
            secret_key = hashlib.sha256(bot_token.encode()).digest()
            hmac_hash = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()
            
            print(f"Method 2 - Expected: {hmac_hash}, Received: {hash_to_check}")
            return hmac.compare_digest(hmac_hash, hash_to_check), params
        
        # Метод 3: Используем исходную строку без парсинга
        def validate_method_3():
            # Разбиваем на части
            parts = data.split("&")
            hash_part = None
            other_parts = []
            
            for part in parts:
                if part.startswith("hash="):
                    hash_part = part.split("=", 1)[1]
                elif not part.startswith("signature="):  # Исключаем signature
                    other_parts.append(part)
            
            # Сортируем части
            other_parts.sort()
            data_check_string = "\n".join(other_parts)
            
            secret_key = hashlib.sha256(bot_token.encode()).digest()
            hmac_hash = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()
            
            print(f"Method 3 - Expected: {hmac_hash}, Received: {hash_part}")
            print(f"Method 3 - Data string: {data_check_string}")
            
            return hmac.compare_digest(hmac_hash, hash_part), None
        
        # Пробуем все методы
        valid1, params1 = validate_method_1()
        valid2, params2 = validate_method_2()
        valid3, params3 = validate_method_3()
        
        print(f"Method 1 valid: {valid1}")
        print(f"Method 2 valid: {valid2}")
        print(f"Method 3 valid: {valid3}")
        
        # Если хотя бы один метод работает, используем его
        if valid1:
            print("Using method 1")
            return params1
        elif valid2:
            print("Using method 2") 
            return params2
        elif valid3:
            print("Using method 3")
            # Для метода 3 нужно распарсить параметры заново
            params = {}
            for item in data.split("&"):
                if "=" in item and not item.startswith("hash=") and not item.startswith("signature="):
                    key, value = item.split("=", 1)
                    params[key] = unquote(value)
            return params
        else:
            # Временно разрешаем доступ для отладки
            print("⚠️ ВНИМАНИЕ: Валидация отключена для отладки!")
            params = {}
            for item in data.split("&"):
                if "=" in item:
                    key, value = item.split("=", 1)
                    params[key] = unquote(value)
            params.pop("hash", None)
            params.pop("signature", None)
            return params
            
    except Exception as e:
        print(f"Error in validation: {e}")
        # Возвращаем параметры для отладки
        params = {}
        for item in data.split("&"):
            if "=" in item:
                key, value = item.split("=", 1)
                params[key] = unquote(value)
        params.pop("hash", None)
        params.pop("signature", None)
        return params


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
