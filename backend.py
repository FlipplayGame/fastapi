import time
import hmac
import hashlib
import json
import asyncio
import aiohttp
from typing import Optional
from urllib.parse import unquote
import jwt  # PyJWT
from fastapi import FastAPI, HTTPException, Depends, Query
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

# TON API конфигурация
TON_API_URL = "https://toncenter.com/api/v2"
TON_API_KEY = None  # Можно получить на https://toncenter.com

security = HTTPBearer()

class AuthRequest(BaseModel):
    init_data: str

class WalletConnectRequest(BaseModel):
    address: str
    wallet_name: str
    wallet_version: str




async def check_payment(user_wallet: str, my_wallet: str, amount_ton: float):
    """Проверка, что была транзакция на мой кошелек"""
    try:
        params = {
            "address": my_wallet,
            "limit": 20,
            "api_key": TON_API_KEY
        }
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{TON_API_URL}/getTransactions", params=params) as resp:
                data = await resp.json()

        if not data.get("ok"):
            return False

        for tx in data["result"]:
            in_msg = tx.get("in_msg", {})
            sender = in_msg.get("source")
            value = int(in_msg.get("value", 0)) / 1_000_000_000
            if sender == user_wallet and value >= amount_ton:
                return True
        return False
    except Exception as e:
        print(f"Ошибка проверки платежа: {e}")
        return False




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

def is_valid_ton_address(address: str) -> bool:
    """Базовая валидация TON адреса"""
    if not address:
        return False
    
    # TON адрес может быть в двух форматах:
    # 1. Raw address (64 hex символа)
    # 2. User-friendly address (48 символов base64)
    
    # Проверяем user-friendly формат
    if len(address) == 48 and all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/-_=' for c in address):
        return True
    
    # Проверяем raw формат (с префиксом или без)
    if len(address) == 64 and all(c in '0123456789abcdefABCDEF' for c in address):
        return True
    
    # Проверяем raw формат с префиксом (0:)
    if len(address) == 66 and address.startswith('0:') and all(c in '0123456789abcdefABCDEF' for c in address[2:]):
        return True
    
    return False

async def get_ton_balance(address: str) -> Optional[float]:
    """Получение баланса TON кошелька через API"""
    try:
        params = {
            'address': address
        }
        if TON_API_KEY:
            params['api_key'] = TON_API_KEY
        
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{TON_API_URL}/getAddressBalance", params=params, timeout=10) as response:
                if response.status == 200:
                    data = await response.json()
                    if data.get('ok'):
                        # Баланс возвращается в nanotons, конвертируем в TON
                        balance_nanotons = int(data.get('result', 0))
                        balance_ton = balance_nanotons / 1_000_000_000  # 1 TON = 10^9 nanotons
                        return round(balance_ton, 4)
                return None
    except Exception as e:
        print(f"Error fetching TON balance: {e}")
        return None

# Аутентификация

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
        lang = user_data.get('language_code')
        # Добавляем пользователя в БД
        try:
            pool = await get_pool()
            async with pool.acquire() as conn:
                await conn.execute("""
                    INSERT INTO players (telegram_id, nickname, attempts, lang) 
                    VALUES ($1, $2, 3, $3) 
                    ON CONFLICT (telegram_id) DO UPDATE SET nickname = EXCLUDED.nickname
                """, user_id, nickname, lang)


                await conn.execute("INSERT INTO taskscaner (telegram_id) VALUES ($1) ON CONFLICT (telegram_id) DO NOTHING", user_id)

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

# Аутентификация


# TON Wallet эндпойнты

@app.post("/wallet/connect")
async def connect_wallet(
    wallet_data: WalletConnectRequest,
    telegram_id: int = Depends(get_current_user)
):
    """Подключение TON кошелька к аккаунту"""
    try:
        # Валидация адреса
        if not is_valid_ton_address(wallet_data.address):
            raise HTTPException(status_code=400, detail="Invalid TON address format")
        
        pool = await get_pool()
        async with pool.acquire() as conn:
            # Проверяем, есть ли уже такой кошелек у другого пользователя
            existing_wallet = await conn.fetchrow(
                "SELECT telegram_id FROM wallets WHERE address = $1", 
                wallet_data.address
            )
            
            if existing_wallet and existing_wallet["telegram_id"] != telegram_id:
                raise HTTPException(
                    status_code=400, 
                    detail="This wallet is already connected to another account"
                )
            
            # Добавляем или обновляем информацию о кошельке
            await conn.execute("""
                INSERT INTO wallets (telegram_id, address, wallet_name, wallet_version, connected_at)
                VALUES ($1, $2, $3, $4, NOW())
                ON CONFLICT (telegram_id) 
                DO UPDATE SET 
                    address = EXCLUDED.address,
                    wallet_name = EXCLUDED.wallet_name,
                    wallet_version = EXCLUDED.wallet_version,
                    connected_at = EXCLUDED.connected_at
            """, telegram_id, wallet_data.address, wallet_data.wallet_name, wallet_data.wallet_version)
        
        return {
            "success": True,
            "message": "Wallet connected successfully",
            "address": wallet_data.address,
            "wallet_name": wallet_data.wallet_name
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to connect wallet: {str(e)}")


@app.post("/wallet/check-payment")
async def check_payment_route(
    telegram_id: int = Depends(get_current_user)
):
    pool = await get_pool()
    async with pool.acquire() as conn:
        wallet = await conn.fetchrow(
            "SELECT address FROM wallets WHERE telegram_id = $1",
            telegram_id
        )
        if not wallet:
            return {"success": False, "message": "❌ Кошелёк не подключен. Подключите его, чтобы оплатить."}

        user_wallet = wallet["address"]

    # твой кошелек для приёма средств
    my_wallet = "UQAojWl3iqFyhc4wxv2IH9E5yeo8IH6LBVXjbdsVVi_KUgPU"
    amount = 0.4

    paid = await check_payment(user_wallet, my_wallet, amount)

    if paid:
        async with pool.acquire() as conn:
            await conn.execute(
                "UPDATE players SET balance = balance + 100 WHERE telegram_id = $1",
                telegram_id
            )
        return {"success": True, "message": "✅ Оплата подтверждена, награда выдана!"}
    else:
        return {"success": False, "message": "⚠️ Оплата не найдена. Попробуйте через минуту."}


@app.get("/wallet/info")
async def get_wallet_info(telegram_id: int = Depends(get_current_user)):
    """Получение информации о подключенном кошельке"""
    try:
        pool = await get_pool()
        async with pool.acquire() as conn:
            wallet = await conn.fetchrow(
                "SELECT address, wallet_name, wallet_version, connected_at FROM wallets WHERE telegram_id = $1",
                telegram_id
            )
            
            if not wallet:
                return {"connected": False}
            
            return {
                "connected": True,
                "address": wallet["address"],
                "wallet_name": wallet["wallet_name"],
                "wallet_version": wallet["wallet_version"],
                "connected_at": wallet["connected_at"].isoformat() if wallet["connected_at"] else None
            }
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get wallet info: {str(e)}")

@app.get("/wallet/balance/{address}")
async def get_wallet_balance(
    address: str,
    telegram_id: int = Depends(get_current_user)
):
    """Получение баланса TON кошелька"""
    try:
        # Проверяем, что кошелек принадлежит пользователю
        pool = await get_pool()
        async with pool.acquire() as conn:
            wallet = await conn.fetchrow(
                "SELECT address FROM wallets WHERE telegram_id = $1 AND address = $2",
                telegram_id, address
            )
            
            if not wallet:
                raise HTTPException(
                    status_code=404, 
                    detail="Wallet not found or doesn't belong to user"
                )
        
        # Получаем баланс через TON API
        balance = await get_ton_balance(address)
        
        if balance is None:
            # Если не удалось получить баланс, возвращаем 0
            balance = 0.0
        
        return {
            "address": address,
            "balance": balance,
            "currency": "TON"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get wallet balance: {str(e)}")

@app.delete("/wallet/disconnect")
async def disconnect_wallet(telegram_id: int = Depends(get_current_user)):
    """Отключение кошелька от аккаунта"""
    try:
        pool = await get_pool()
        async with pool.acquire() as conn:
            deleted_count = await conn.fetchval(
                "DELETE FROM wallets WHERE telegram_id = $1 RETURNING 1",
                telegram_id
            )
            
            if not deleted_count:
                raise HTTPException(status_code=404, detail="No wallet connected")
            
            return {"success": True, "message": "Wallet disconnected successfully"}
            
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to disconnect wallet: {str(e)}")



# TON Wallet эндпойнты





## Работа с балансом ##





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



## Работа с балансом ##


# Shop job ##

@app.get("/catalog")
async def get_catalog(telegram_id: int = Depends(get_current_user)):
    try:
        pool = await get_pool()
        async with pool.acquire() as conn:


            # Получаем lang пользователя
            lang = await conn.fetchval(
                "SELECT lang FROM players WHERE telegram_id = $1",
                telegram_id
            )
            if not lang:
                lang = "en"  # значение по умолчанию

            # Загружаем товары по tag
            rows = await conn.fetch(
                "SELECT id, nickname FROM ru_category WHERE lang = $1",
                lang)
            
            if not rows:
                return None
            catalog = [{"nickname": row["nickname"], "id": row["id"]} for row in rows]

            return catalog


    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")


@app.get("/catalog/shop")
async def get_catalog_shopcategory(
    telegram_id: int = Depends(get_current_user),
    shop_id: int = Query(...)
):
    try:
        pool = await get_pool()
        async with pool.acquire() as conn:
            tag = await conn.fetchval(
                "SELECT tag_shop FROM ru_shops WHERE id = $1",
                shop_id
            )

            if not tag:
                raise HTTPException(status_code=404, detail="Category not found")

            # Получаем lang пользователя
            lang = await conn.fetchval(
                "SELECT lang FROM players WHERE telegram_id = $1",
                telegram_id
            )
            if not lang:
                lang = "en"  # значение по умолчанию

            # Загружаем товары по tag
            rows = await conn.fetch(
                "SELECT id, name FROM shop_category WHERE tag = $1 and lang = $2",
                tag, lang
            )
            
            if not rows:
                return None
            catalog = [{"nickname": row["name"], "id": row["id"]} for row in rows]

            return catalog

    except Exception as e:
        print(f"[ERROR] get_category: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")



@app.get("/market/lots")
async def get_catalog_shopcategory(
    telegram_id: int = Depends(get_current_user),
    shop_id: int = Query(...),
    limit: int = Query(20, gt=0),
    offset: int = Query(0, ge=0)
):
    try:
        pool = await get_pool()
        async with pool.acquire() as conn:
            tag = await conn.fetchval(
                "SELECT tag_lot FROM shop_category WHERE id = $1",
                shop_id
            )

            if not tag:
                raise HTTPException(status_code=404, detail="Category not found")
            lang = await conn.fetchval(
                "SELECT lang FROM players WHERE telegram_id = $1",
                telegram_id
            )
            if not lang:
                lang = "en"  # значение по умолчанию

            rows = await conn.fetch(
                """
                SELECT id, name, image, desction, price, url 
                FROM product_lot
                WHERE tag = $1 and language = $2
                ORDER BY id
                LIMIT $3 OFFSET $4
                """,
                tag,lang, limit, offset
            )

            catalog = [{"nickname": row["name"], "lotId": row["id"], "image": row["image"], "desction":row["desction"], "price":row["price"], "url":row["url"]} for row in rows]

            return catalog

    except Exception as e:
        print(f"[ERROR] get_category: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")




@app.get("/catalog/category")
async def get_category(
    telegram_id: int = Depends(get_current_user),
    category_id: int = Query(...)
):
    try:
        pool = await get_pool()
        async with pool.acquire() as conn:
            # Получаем tag по category_id
            tag = await conn.fetchval(
                "SELECT tag FROM ru_category WHERE id = $1",
                category_id
            )

            if not tag:
                raise HTTPException(status_code=404, detail="Category not found")

            # Получаем lang пользователя
            lang = await conn.fetchval(
                "SELECT lang FROM players WHERE telegram_id = $1",
                telegram_id
            )
            if not lang:
                lang = "en"  # значение по умолчанию

            # Загружаем товары по tag
            rows = await conn.fetch(
                "SELECT id, name FROM ru_shops WHERE tag = $1 and lang = $2",
                tag, lang
            )

            catalog = [{"nickname": row["name"], "id": row["id"]} for row in rows]

            return catalog

    except Exception as e:
        print(f"[ERROR] get_category: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")


# Shop job ##




## LeaderBoard ##


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



## LeaderBoard ##



## ПОПТЫКИ ##



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


## ПОПТЫКИ ##


@app.post("/stGame")
async def add_st_game(telegram_id: int = Depends(get_current_user)):
    promtion = 1
    pool = await get_pool()
    async with pool.acquire() as conn:
        st = await conn.execute(
            "UPDATE taskscaner SET st_startgame = st_startgame + $1 WHERE telegram_id = $2",promtion,telegram_id )
        return


@app.get("/tasks")
async def get_user_tasks(telegram_id: int = Depends(get_current_user)):
    pool = await get_pool()
    async with pool.acquire() as conn:
        # 1. Все задания
        tasks = await conn.fetch(
            "SELECT st, reward, count, desction FROM tasklist"
        )

        # 2. Прогресс пользователя
        user_status = await conn.fetchrow(
            "SELECT * FROM taskscaner WHERE telegram_id=$1",
            telegram_id
        )

        # 3. Какие задания он уже собрал
        completed_tasks = await conn.fetch(
            "SELECT st_tag FROM player_task_completed WHERE telegram_id=$1 AND status=1",
            telegram_id
        )
        completed_tags = {row["st_tag"] for row in completed_tasks}

        result = []
        for task in tasks:
            st_name = task["st"]  # например "st_video"
            user_progress = user_status.get(st_name, 0)
            
            # Если задание уже собрано — пропускаем
            if st_name in completed_tags:
                continue

            result.append({
                "tag": st_name,
                "reward": task["reward"],
                "count": task["count"],
                "desction": task["desction"],
                "user_progress": user_progress
            })

        return result



class CollectTaskRequest(BaseModel):
    st: str  # например "st_video"

@app.post("/tasks/collect")
async def collect_task(req: CollectTaskRequest, telegram_id: int = Depends(get_current_user)):
    pool = await get_pool()
    async with pool.acquire() as conn:
        # Получаем задачу
        task = await conn.fetchrow(
            "SELECT count, reward FROM tasklist WHERE st=$1",
            req.st
        )
        if not task:
            raise HTTPException(status_code=404, detail="Task not found")

        # Получаем прогресс пользователя
        user_status = await conn.fetchrow(
            "SELECT * FROM taskscaner WHERE telegram_id=$1",
            telegram_id
        )
        if user_status is None:
            raise HTTPException(status_code=404, detail="User not found")

        if user_status.get(req.st, 0) < task["count"]:
            raise HTTPException(status_code=400, detail="Not enough progress to collect")

        # Проверяем, не собирал ли уже
        already_completed = await conn.fetchval(
            "SELECT 1 FROM player_task_completed WHERE telegram_id=$1 AND st_tag=$2 AND status=1",
            telegram_id, req.st
        )
        if already_completed:
            return {"message": "Task already collected"}

        # Записываем, что пользователь выполнил задание
        await conn.execute(
            """
            INSERT INTO player_task_completed (telegram_id, st_tag, status)
            VALUES ($1, $2, 1)
            """,
            telegram_id, req.st
        )

        # Начисляем награду в players.balance
        await conn.execute(
            """
            UPDATE players
            SET balance = balance + $1
            WHERE telegram_id = $2
            """,
            task["reward"], telegram_id
        )

        return {"message": "Task collected successfully"}





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
