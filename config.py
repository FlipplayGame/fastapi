import os
from dotenv import load_dotenv

# Загружаем переменные из .env
load_dotenv()

class PostgresConfig:
    USER = os.getenv("POSTGRES_USER")
    PASSWORD = os.getenv("POSTGRES_PASSWORD")
    DATABASE = os.getenv("POSTGRES_DB")
    HOST = os.getenv("POSTGRES_HOST")
    PORT = os.getenv("POSTGRES_PORT")
    POOL_MIN = int(os.getenv("POSTGRES_POOL_MIN", 5))  # Значение по умолчанию: 5
    POOL_MAX = int(os.getenv("POSTGRES_POOL_MAX", 10)) # Значение по умолчанию: 10

class BotConfig:
    TOKEN = os.getenv("BOT_TOKEN")

# Проверка, что переменные загружены
if not all([PostgresConfig.USER, PostgresConfig.PASSWORD, PostgresConfig.HOST, BotConfig.TOKEN]):
    raise ValueError("Не все переменные окружения заданы в .env!")