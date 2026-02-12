"""
Authorization cache for stateless header-based authentication.

Caches LDAP authorization results to reduce load on the LDAP server.
Uses the same backend as the session store (memory or Redis).

Includes per-key locking to prevent thundering herd / DOS on LDAP:
- In-memory backend: uses asyncio.Lock (per-process)
- Redis backend: uses distributed SETNX lock (across all workers)
"""

import asyncio
import hashlib
import time
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from nginx_ldap_auth.logging import logger
from nginx_ldap_auth.settings import Settings

# In-memory cache: key -> (authorized, expires_at)
_cache: dict[str, tuple[bool, float]] = {}

# Per-key locks for in-memory backend
_key_locks: dict[str, asyncio.Lock] = {}
_key_locks_lock = asyncio.Lock()

# Distributed lock TTL (seconds) - should be longer than typical LDAP query time
_REDIS_LOCK_TTL = 10


def _make_cache_key(username: str, authorization_filter: str | None) -> str:
    """Generate cache key from username and filter hash."""
    if authorization_filter is None:
        filter_hash = "none"
    else:
        filter_hash = hashlib.sha256(authorization_filter.encode()).hexdigest()[:16]
    return f"header_auth:{username}:{filter_hash}"


def _get_redis_connection():
    """Get Redis connection from the session store."""
    from nginx_ldap_auth.app.main import store
    from starsessions.stores.redis import RedisStore

    if isinstance(store, RedisStore):
        return store._connection
    return None


def _is_redis_backend() -> bool:
    """Check if Redis is the configured backend."""
    settings = Settings()
    return settings.session_backend == "redis" and settings.redis_url is not None


# --- Public API ---


@asynccontextmanager
async def authorization_lock(
    username: str, authorization_filter: str | None
) -> AsyncGenerator[None, None]:
    """
    Acquire a lock for the given username/filter combination.

    For in-memory backend: uses asyncio.Lock (protects within process)
    For Redis backend: uses distributed SETNX lock (protects across workers)

    Usage:
        async with authorization_lock(username, filter):
            # Only one request at a time (per worker or globally) reaches here
            result = await check_ldap(...)
    """
    key = _make_cache_key(username, authorization_filter)

    if _is_redis_backend():
        async with _redis_lock(key):
            yield
    else:
        async with await _get_memory_lock(key):
            yield


async def get_cached_authorization(
    username: str, authorization_filter: str | None
) -> bool | None:
    """
    Get cached authorization result.

    Returns True/False if cached, None if not in cache.
    """
    key = _make_cache_key(username, authorization_filter)

    if _is_redis_backend():
        return await _redis_get(key)
    else:
        return _memory_get(key)


async def set_cached_authorization(
    username: str, authorization_filter: str | None, authorized: bool
) -> None:
    """Cache an authorization result."""
    settings = Settings()
    if settings.header_auth_cache_ttl <= 0:
        return  # Caching disabled

    key = _make_cache_key(username, authorization_filter)

    if _is_redis_backend():
        await _redis_set(key, authorized, settings.header_auth_cache_ttl)
    else:
        _memory_set(key, authorized, settings.header_auth_cache_ttl)


# --- In-memory implementation ---


async def _get_memory_lock(key: str) -> asyncio.Lock:
    """Get or create a lock for a specific cache key."""
    async with _key_locks_lock:
        if key not in _key_locks:
            _key_locks[key] = asyncio.Lock()
        return _key_locks[key]


def _memory_get(key: str) -> bool | None:
    entry = _cache.get(key)
    if entry is None:
        logger.debug("cache.miss", key=key, backend="memory")
        return None

    authorized, expires_at = entry
    if time.time() > expires_at:
        del _cache[key]
        logger.debug("cache.expired", key=key, backend="memory")
        return None

    logger.debug("cache.hit", key=key, authorized=authorized, backend="memory")
    return authorized


def _memory_set(key: str, authorized: bool, ttl: int) -> None:
    _cache[key] = (authorized, time.time() + ttl)
    logger.debug("cache.set", key=key, authorized=authorized, ttl=ttl, backend="memory")


# --- Redis implementation ---


async def _redis_get(key: str) -> bool | None:
    redis = _get_redis_connection()
    if redis is None:
        return _memory_get(key)  # Fallback

    settings = Settings()
    full_key = f"{settings.redis_prefix}{key}"
    value = await redis.get(full_key)

    if value is None:
        logger.debug("cache.miss", key=full_key, backend="redis")
        return None

    authorized = value == b"1" or value == "1"
    logger.debug("cache.hit", key=full_key, authorized=authorized, backend="redis")
    return authorized


async def _redis_set(key: str, authorized: bool, ttl: int) -> None:
    redis = _get_redis_connection()
    if redis is None:
        _memory_set(key, authorized, ttl)  # Fallback
        return

    settings = Settings()
    full_key = f"{settings.redis_prefix}{key}"
    value = "1" if authorized else "0"
    await redis.setex(full_key, ttl, value)
    logger.debug("cache.set", key=full_key, authorized=authorized, ttl=ttl, backend="redis")


@asynccontextmanager
async def _redis_lock(key: str) -> AsyncGenerator[None, None]:
    """
    Distributed lock using Redis SETNX pattern.

    Acquires a lock that works across all workers/processes.
    If lock cannot be acquired, waits and retries with exponential backoff.
    """
    redis = _get_redis_connection()
    if redis is None:
        # Fallback to memory lock if Redis unavailable
        async with await _get_memory_lock(key):
            yield
        return

    settings = Settings()
    lock_key = f"{settings.redis_prefix}lock:{key}"
    acquired = False
    retry_delay = 0.01  # Start with 10ms
    max_delay = 0.5  # Max 500ms between retries
    max_wait = _REDIS_LOCK_TTL  # Don't wait longer than lock TTL

    start_time = time.time()

    try:
        while not acquired:
            # Try to acquire lock with NX (only set if not exists) and EX (expiry)
            acquired = await redis.set(lock_key, "1", nx=True, ex=_REDIS_LOCK_TTL)

            if acquired:
                logger.debug("cache.lock.acquired", key=lock_key)
                break

            # Check if we've waited too long
            if time.time() - start_time > max_wait:
                # Give up waiting, proceed without lock (better than blocking forever)
                logger.warning("cache.lock.timeout", key=lock_key)
                break

            # Wait with exponential backoff
            await asyncio.sleep(retry_delay)
            retry_delay = min(retry_delay * 2, max_delay)

        yield

    finally:
        if acquired:
            await redis.delete(lock_key)
            logger.debug("cache.lock.released", key=lock_key)


# --- Test helpers ---


def reset_cache() -> None:
    """Reset cache state (for testing)."""
    global _cache, _key_locks
    _cache = {}
    _key_locks = {}
