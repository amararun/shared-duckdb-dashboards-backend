"""
DuckDB Dashboards Backend API
FastAPI server for querying DuckDB files with read-only and admin endpoints.
"""

from fastapi import FastAPI, HTTPException, Request, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
from typing import Optional, Dict
import duckdb
import os
import sys
import secrets
import logging
import json
import hashlib
import asyncio
from functools import partial
from datetime import date, datetime, time
from decimal import Decimal
from dotenv import load_dotenv
from cachetools import TTLCache
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from starlette.status import HTTP_429_TOO_MANY_REQUESTS


def get_client_ip(request: Request) -> str:
    """Get client IP from custom header (Cloudflare-safe).

    Priority: X-Original-Client-IP (custom, won't be stripped by Cloudflare)
    → X-Forwarded-For → request.client.host
    """
    # Custom header set by Vercel proxy - Cloudflare won't strip this
    original_ip = request.headers.get("x-original-client-ip", "")
    if original_ip:
        return original_ip.strip()

    # Fallback to standard headers
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()

    # Direct connection fallback
    if request.client:
        return request.client.host

    return "unknown"

load_dotenv()

# Configuration
API_KEY = os.getenv("API_KEY")
if not API_KEY:
    raise RuntimeError("API_KEY environment variable not set")

ADMIN_API_KEY = os.getenv("ADMIN_API_KEY")  # Optional - for admin endpoints

DATA_DIR = os.getenv("DATA_DIR", "./data")
MAX_ROWS = int(os.getenv("MAX_ROWS", "10000"))
MAX_UPLOAD_SIZE = int(os.getenv("MAX_UPLOAD_SIZE", str(500 * 1024 * 1024)))  # 500MB default
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

# Cache configuration from env vars
CACHE_MAX_SIZE = int(os.getenv("CACHE_MAX_SIZE", "2000"))  # Max queries per file
CACHE_TTL = int(os.getenv("CACHE_TTL", "2592000"))  # 30 days in seconds

# Query timeout for read-only endpoint (milliseconds) - prevents runaway queries
QUERY_TIMEOUT_MS = int(os.getenv("QUERY_TIMEOUT_MS", "30000"))  # 30 seconds default

# Rate limiting configuration (per IP address)
# Burst: allows parallel queries on page load (dashboards send 10-15 queries at once)
# Sustained: prevents scripts from hammering the API continuously
RATE_LIMIT_BURST = os.getenv("RATE_LIMIT_BURST", "20/second")
RATE_LIMIT_SUSTAINED = os.getenv("RATE_LIMIT_SUSTAINED", "500/minute")

VERSION = "1.4.1"

# Query cache - auto-created per file
query_caches: Dict[str, TTLCache] = {}

def get_cache(filename: str) -> TTLCache:
    """Get or create cache for a file."""
    if filename not in query_caches:
        query_caches[filename] = TTLCache(maxsize=CACHE_MAX_SIZE, ttl=CACHE_TTL)
        logger.info(f"Created cache for {filename} (maxsize={CACHE_MAX_SIZE}, ttl={CACHE_TTL}s)")
    return query_caches[filename]

def get_cache_key(sql: str, limit: int) -> str:
    """Generate cache key from SQL and limit."""
    return hashlib.md5(f"{sql}:{limit}".encode()).hexdigest()

# Logging setup
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Request model
class QueryRequest(BaseModel):
    sql: str
    limit: Optional[int] = None

# Initialize FastAPI
app = FastAPI(title="DuckDB Dashboards API", version=VERSION)

# Initialize rate limiter (by client IP from custom header)
limiter = Limiter(key_func=get_client_ip)
app.state.limiter = limiter
logger.info(f"Rate limiting enabled: burst={RATE_LIMIT_BURST}, sustained={RATE_LIMIT_SUSTAINED} (using X-Original-Client-IP)")

# Custom 429 handler with user-friendly error message
@app.exception_handler(RateLimitExceeded)
async def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    # Get client IP for logging (not exposed to user)
    client_ip = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
    if not client_ip:
        client_ip = request.headers.get("x-real-ip", "")
    if not client_ip:
        client_ip = getattr(request.client, "host", "unknown") if request.client else "unknown"

    # Log with full details for debugging
    logger.warning(f"Rate limit exceeded for IP {client_ip}: {exc.detail}")

    return JSONResponse(
        status_code=HTTP_429_TOO_MANY_REQUESTS,
        content={
            "detail": "Rate limit exceeded. Please slow down and try again. If you believe this is an error, use the bug report button in the app.",
            "error_type": "rate_limit_exceeded"
        }
    )

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Add API Monitor middleware for centralized logging (optional)
# Requires API_MONITOR_URL and API_MONITOR_KEY env vars
# See: https://pypi.org/project/tigzig-api-monitor/
try:
    from tigzig_api_monitor import APIMonitorMiddleware
    app.add_middleware(
        APIMonitorMiddleware,
        app_name="DUCKDB_DASHBOARDS_BACKEND",
        include_prefixes=("/api/",),
    )
except Exception:
    pass  # Monitoring disabled - package not installed or not configured

# SQL validation - block dangerous keywords for read-only endpoint
BLOCKED = ['INSERT', 'UPDATE', 'DELETE', 'DROP', 'ALTER', 'CREATE', 'TRUNCATE', 'EXEC', 'EXECUTE']

def verify_request(request: Request):
    """Verify API key from Authorization header."""
    auth = request.headers.get("Authorization")
    if not auth:
        raise HTTPException(status_code=401, detail="Missing Authorization")
    scheme, _, token = auth.partition(" ")
    if scheme.lower() != "bearer" or not secrets.compare_digest(token, API_KEY):
        raise HTTPException(status_code=403, detail="Invalid API key")

def verify_admin_request(request: Request):
    """Verify Admin API key from Authorization header."""
    if not ADMIN_API_KEY:
        raise HTTPException(status_code=503, detail="Admin API not configured")

    auth = request.headers.get("Authorization")
    if not auth:
        raise HTTPException(status_code=401, detail="Missing Authorization")
    scheme, _, token = auth.partition(" ")
    if scheme.lower() != "bearer" or not secrets.compare_digest(token, ADMIN_API_KEY):
        raise HTTPException(status_code=403, detail="Invalid admin API key")

def serialize_row(row):
    """Convert row values to JSON-serializable types."""
    return [
        val.isoformat() if isinstance(val, (date, datetime, time)) else
        float(val) if isinstance(val, Decimal) else val
        for val in row
    ]

# ============== Synchronous Database Helpers ==============
# These run in thread pool via run_in_executor to avoid blocking the event loop

def _execute_duckdb_query_sync(filepath: str, sql: str, row_limit: int):
    """Synchronous DuckDB query execution - runs in thread pool."""
    conn = duckdb.connect(filepath, read_only=True)
    try:
        result = conn.execute(sql).fetchmany(row_limit + 1)
        columns = [desc[0] for desc in conn.description]
        return columns, result
    finally:
        conn.close()

def _execute_duckdb_admin_query_sync(filepath: str, sql: str, row_limit: int):
    """Synchronous DuckDB admin query execution - runs in thread pool."""
    conn = duckdb.connect(filepath, read_only=False)
    try:
        result = conn.execute(sql)
        if result.description:
            fetched = result.fetchmany(row_limit + 1)
            columns = [desc[0] for desc in result.description]
            return {"has_results": True, "columns": columns, "rows": fetched}
        else:
            return {"has_results": False}
    finally:
        conn.close()

def _list_tables_sync(filepath: str):
    """Synchronous table listing - runs in thread pool."""
    conn = duckdb.connect(filepath, read_only=True)
    try:
        tables = [row[0] for row in conn.execute("SHOW TABLES").fetchall()]
        table_info = []
        for table in tables:
            count = conn.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
            table_info.append({"name": table, "row_count": count})
        return table_info
    finally:
        conn.close()

def _validate_duckdb_file_sync(filepath: str):
    """Synchronous DuckDB file validation - runs in thread pool."""
    conn = duckdb.connect(filepath, read_only=True)
    try:
        conn.execute("SHOW TABLES")
        return True
    finally:
        conn.close()

def _validate_parquet_file_sync(filepath: str):
    """Synchronous Parquet file validation - runs in thread pool."""
    conn = duckdb.connect(":memory:")
    try:
        conn.execute(f"SELECT * FROM read_parquet('{filepath}') LIMIT 1")
        return True
    finally:
        conn.close()

@app.get("/health")
async def health():
    return {"status": "ok", "version": VERSION}

# ============== Read-Only Query Endpoint ==============

@app.post("/api/query/{filename}")
@limiter.limit(RATE_LIMIT_BURST)
@limiter.limit(RATE_LIMIT_SUSTAINED)
async def query_file(filename: str, query: QueryRequest, request: Request):
    """Execute read-only SQL query against a DuckDB file. Rate limited per IP."""

    verify_request(request)

    # Security: prevent path traversal
    if "/" in filename or "\\" in filename or ".." in filename:
        raise HTTPException(status_code=400, detail="Invalid filename")

    if not filename.endswith(".duckdb"):
        filename = filename + ".duckdb"

    # Validate SQL is read-only
    sql_upper = query.sql.upper()
    for kw in BLOCKED:
        if kw in sql_upper:
            raise HTTPException(status_code=403, detail=f"Operation not allowed: {kw}")

    filepath = os.path.join(DATA_DIR, filename)
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail=f"File not found")

    # Check cache first
    row_limit = min(query.limit or MAX_ROWS, MAX_ROWS)
    cache = get_cache(filename)
    cache_key = get_cache_key(query.sql, row_limit)

    if cache_key in cache:
        logger.debug(f"Cache hit for {filename}: {query.sql[:50]}...")
        return cache[cache_key]

    try:
        # Run blocking DuckDB operations in thread pool with timeout
        loop = asyncio.get_event_loop()
        timeout_seconds = QUERY_TIMEOUT_MS / 1000  # Convert ms to seconds

        try:
            columns, result = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    partial(_execute_duckdb_query_sync, filepath, query.sql, row_limit)
                ),
                timeout=timeout_seconds
            )
        except asyncio.TimeoutError:
            raise HTTPException(
                status_code=408,
                detail=f"Query timed out after {int(timeout_seconds)} seconds. Try a simpler query."
            )

        truncated = len(result) > row_limit
        if truncated:
            result = result[:row_limit]

        rows = [serialize_row(row) for row in result]

        response = {"columns": columns, "rows": rows, "row_count": len(rows), "truncated": truncated}

        # Store in cache
        cache[cache_key] = response
        logger.debug(f"Cached query for {filename}: {query.sql[:50]}...")

        return response

    except duckdb.Error as e:
        raise HTTPException(status_code=400, detail=f"Query error: {str(e)}")

# ============== Admin Endpoints ==============

@app.post("/api/admin/query/{filename}")
async def admin_query_file(filename: str, query: QueryRequest, request: Request):
    """
    Execute ANY SQL query against a DuckDB file (admin access).
    Requires ADMIN_API_KEY. No SQL restrictions.
    """
    verify_admin_request(request)

    # Security: prevent path traversal
    if "/" in filename or "\\" in filename or ".." in filename:
        raise HTTPException(status_code=400, detail="Invalid filename")

    if not filename.endswith(".duckdb"):
        filename = filename + ".duckdb"

    filepath = os.path.join(DATA_DIR, filename)
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail=f"File not found")

    try:
        row_limit = min(query.limit or MAX_ROWS, MAX_ROWS)

        # Run blocking DuckDB operations in thread pool to avoid blocking event loop
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None,
            partial(_execute_duckdb_admin_query_sync, filepath, query.sql, row_limit)
        )

        # Check if query returns results
        if result["has_results"]:
            fetched = result["rows"]
            columns = result["columns"]

            truncated = len(fetched) > row_limit
            if truncated:
                fetched = fetched[:row_limit]

            rows = [serialize_row(row) for row in fetched]

            logger.info(f"Admin query on {filename}: {query.sql[:100]}... ({len(rows)} rows)")
            return {"columns": columns, "rows": rows, "row_count": len(rows), "truncated": truncated}
        else:
            # DDL/DML query with no result set
            logger.info(f"Admin DDL/DML on {filename}: {query.sql[:100]}...")
            return {"columns": [], "rows": [], "row_count": 0, "truncated": False, "message": "Query executed successfully"}

    except duckdb.Error as e:
        logger.error(f"Admin query error on {filename}: {e}")
        raise HTTPException(status_code=400, detail=f"Query error: {str(e)}")

@app.get("/api/admin/files")
async def list_files(request: Request):
    """List all DuckDB files in the data directory."""
    verify_admin_request(request)

    try:
        files = []
        for f in os.listdir(DATA_DIR):
            if f.endswith(".duckdb") or f.endswith(".parquet"):
                filepath = os.path.join(DATA_DIR, f)
                size_bytes = os.path.getsize(filepath)
                files.append({
                    "name": f,
                    "size_bytes": size_bytes,
                    "size_mb": round(size_bytes / (1024 * 1024), 2)
                })
        files.sort(key=lambda x: x["name"])
        return {"files": files, "count": len(files)}
    except Exception as e:
        logger.error(f"Error listing files: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/admin/files/{filename}/tables")
async def list_tables(filename: str, request: Request):
    """List all tables in a DuckDB file with row counts."""
    verify_admin_request(request)

    if "/" in filename or "\\" in filename or ".." in filename:
        raise HTTPException(status_code=400, detail="Invalid filename")

    if not filename.endswith(".duckdb"):
        filename = filename + ".duckdb"

    filepath = os.path.join(DATA_DIR, filename)
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail=f"File not found")

    try:
        # Run blocking DuckDB operations in thread pool to avoid blocking event loop
        loop = asyncio.get_event_loop()
        table_info = await loop.run_in_executor(
            None,
            partial(_list_tables_sync, filepath)
        )
        return {"filename": filename, "tables": table_info, "count": len(table_info)}
    except Exception as e:
        logger.error(f"Error listing tables in {filename}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/admin/files/upload")
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    custom_name: Optional[str] = Form(None)
):
    """Upload a DuckDB or Parquet file."""
    verify_admin_request(request)

    filename = custom_name if custom_name else file.filename
    if not filename:
        raise HTTPException(status_code=400, detail="Filename required")

    # Security: prevent path traversal
    if "/" in filename or "\\" in filename or ".." in filename:
        raise HTTPException(status_code=400, detail="Invalid filename")

    # Ensure proper extension
    if not filename.endswith(".duckdb") and not filename.endswith(".parquet"):
        filename = filename + ".duckdb"

    filepath = os.path.join(DATA_DIR, filename)

    try:
        total_size = 0
        with open(filepath, "wb") as f:
            while True:
                chunk = await file.read(1024 * 1024)  # 1MB chunks
                if not chunk:
                    break
                total_size += len(chunk)
                if total_size > MAX_UPLOAD_SIZE:
                    f.close()
                    os.remove(filepath)
                    raise HTTPException(
                        status_code=413,
                        detail=f"File too large. Max size: {MAX_UPLOAD_SIZE // (1024*1024)}MB"
                    )
                f.write(chunk)

        # Validate file - run in thread pool to avoid blocking event loop
        try:
            loop = asyncio.get_event_loop()
            if filename.endswith(".parquet"):
                await loop.run_in_executor(
                    None,
                    partial(_validate_parquet_file_sync, filepath)
                )
            else:
                await loop.run_in_executor(
                    None,
                    partial(_validate_duckdb_file_sync, filepath)
                )
        except Exception as e:
            os.remove(filepath)
            raise HTTPException(status_code=400, detail=f"Invalid file: {str(e)}")

        logger.info(f"Uploaded file: {filename} ({total_size} bytes)")
        return {
            "message": "File uploaded successfully",
            "filename": filename,
            "size_bytes": total_size,
            "size_mb": round(total_size / (1024 * 1024), 2)
        }
    except HTTPException:
        raise
    except Exception as e:
        if os.path.exists(filepath):
            os.remove(filepath)
        logger.error(f"Error uploading file: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/admin/files/{filename}")
async def delete_file(filename: str, request: Request):
    """Delete a file from the data directory."""
    verify_admin_request(request)

    if "/" in filename or "\\" in filename or ".." in filename:
        raise HTTPException(status_code=400, detail="Invalid filename")

    filepath = os.path.join(DATA_DIR, filename)
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail=f"File not found")

    try:
        os.remove(filepath)
        logger.info(f"Deleted file: {filename}")
        return {"message": f"File '{filename}' deleted successfully"}
    except Exception as e:
        logger.error(f"Error deleting file {filename}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/admin/files/{filename}/download")
async def download_file(filename: str, request: Request):
    """Download a file."""
    verify_admin_request(request)

    if "/" in filename or "\\" in filename or ".." in filename:
        raise HTTPException(status_code=400, detail="Invalid filename")

    filepath = os.path.join(DATA_DIR, filename)
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail=f"File not found")

    return FileResponse(
        path=filepath,
        filename=filename,
        media_type="application/octet-stream"
    )

# ============== Cache Admin Endpoints ==============

@app.get("/api/admin/cache/stats")
async def cache_stats(request: Request):
    """Get cache statistics for all files. Dumps cache to temp file to measure size."""
    verify_admin_request(request)

    stats = {}
    total_entries = 0

    for filename, cache in query_caches.items():
        stats[filename] = {
            "entries": len(cache),
            "maxsize": cache.maxsize,
            "ttl_seconds": int(cache.ttl)
        }
        total_entries += len(cache)

    # Dump cache to temp file to measure size
    dump_size_bytes = 0
    dump_file = os.path.join(DATA_DIR, "_cache_dump_temp.json")
    try:
        dump_data = {}
        for filename, cache in query_caches.items():
            dump_data[filename] = {k: v for k, v in cache.items()}

        with open(dump_file, "w") as f:
            json.dump(dump_data, f)

        dump_size_bytes = os.path.getsize(dump_file)
        os.remove(dump_file)
    except Exception as e:
        logger.warning(f"Could not measure cache size: {e}")
        if os.path.exists(dump_file):
            os.remove(dump_file)

    return {
        "caches": stats,
        "total_entries": total_entries,
        "estimated_size_bytes": dump_size_bytes,
        "estimated_size_mb": round(dump_size_bytes / (1024 * 1024), 2),
        "config": {
            "max_size_per_file": CACHE_MAX_SIZE,
            "ttl_seconds": CACHE_TTL,
            "ttl_days": round(CACHE_TTL / 86400, 1)
        }
    }

@app.delete("/api/admin/cache/clear/{filename}")
async def cache_clear(filename: str, request: Request):
    """Clear cache for a specific file."""
    verify_admin_request(request)

    if "/" in filename or "\\" in filename or ".." in filename:
        raise HTTPException(status_code=400, detail="Invalid filename")

    if not filename.endswith(".duckdb"):
        filename = filename + ".duckdb"

    if filename in query_caches:
        entries_cleared = len(query_caches[filename])
        query_caches[filename].clear()
        logger.info(f"Cleared cache for {filename} ({entries_cleared} entries)")
        return {"message": f"Cache cleared for {filename}", "entries_cleared": entries_cleared}
    else:
        return {"message": f"No cache exists for {filename}", "entries_cleared": 0}

@app.delete("/api/admin/cache/clear")
async def cache_clear_all(request: Request):
    """Clear cache for all files."""
    verify_admin_request(request)

    total_cleared = 0
    files_cleared = []

    for filename, cache in query_caches.items():
        entries = len(cache)
        cache.clear()
        total_cleared += entries
        files_cleared.append({"filename": filename, "entries_cleared": entries})

    logger.info(f"Cleared all caches ({total_cleared} total entries)")
    return {
        "message": "All caches cleared",
        "total_entries_cleared": total_cleared,
        "files": files_cleared
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
