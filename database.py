import asyncpg
from asyncpg.pool import Pool
from typing import Optional
from config import PostgresConfig

_db_pool: Optional[Pool] = None

async def create_pool() -> Pool:
    """Создаёт пул соединений с Postgres."""
    global _db_pool
    if _db_pool is None:
        _db_pool = await asyncpg.create_pool(
            user=PostgresConfig.USER,
            password=PostgresConfig.PASSWORD,
            database=PostgresConfig.DATABASE,
            host=PostgresConfig.HOST,
            port=PostgresConfig.PORT,
            min_size=PostgresConfig.POOL_MIN,
            max_size=PostgresConfig.POOL_MAX,
            statement_cache_size=0  # <--- добавлено для совместимости с PgBouncer
        )
    return _db_pool

async def close_pool() -> None:
    global _db_pool
    if _db_pool is not None:
        await _db_pool.close()
        _db_pool = None

async def get_pool() -> Pool:
    if _db_pool is None:
        return await create_pool()
    return _db_pool