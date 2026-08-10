⚠️ **This repo is archived and no longer maintained.** It stays up as reference code for the build guides. No updates, including security updates, so review before you use any of it anywhere serious. The live apps run on newer, hardened versions of this code.

# DuckDB Dashboards Backend

FastAPI server for querying DuckDB/Parquet files. Read-only queries with caching, rate limiting, and admin endpoints for file management.

## Endpoints

**Read-Only** (API_KEY)
- `POST /api/query/{filename}` - Execute read-only SQL
- `GET /health` - Health check

**Admin** (ADMIN_API_KEY)
- `POST /api/admin/query/{filename}` - Execute any SQL
- `GET /api/admin/files` - List files
- `POST /api/admin/files/upload` - Upload file
- `GET /api/admin/files/{filename}/tables` - List tables with row counts
- `GET /api/admin/files/{filename}/download` - Download file
- `DELETE /api/admin/files/{filename}` - Delete file
- `GET /api/admin/cache/stats` - Cache statistics
- `DELETE /api/admin/cache/clear/{filename}` - Clear file cache
- `DELETE /api/admin/cache/clear` - Clear all caches

## Authentication

```
Authorization: Bearer YOUR_API_KEY
```

## Usage

```bash
curl -X POST "https://your-server/api/query/mydata.duckdb" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"sql": "SELECT * FROM users LIMIT 10"}'
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `API_KEY` | required | Read-only access key |
| `ADMIN_API_KEY` | - | Admin access key |
| `DATA_DIR` | `./data` | Directory for database files |
| `MAX_ROWS` | `10000` | Max rows per query |
| `MAX_UPLOAD_SIZE` | `524288000` | Max upload (500MB) |
| `QUERY_TIMEOUT_MS` | `30000` | Query timeout (30s) |
| `CACHE_TTL` | `2592000` | Cache TTL (30 days) |
| `CACHE_MAX_SIZE` | `2000` | Max cached queries per file |
| `RATE_LIMIT_BURST` | `20/second` | Burst rate limit |
| `RATE_LIMIT_SUSTAINED` | `500/minute` | Sustained rate limit |

## Security Hardening

This application has been hardened with the following security measures:

- **API Key Authentication**: Bearer token auth with `secrets.compare_digest` for timing-safe comparison. Separate keys for read-only and admin access.
- **SQL Validation**: Read-only endpoint blocks INSERT, UPDATE, DELETE, DROP, ALTER, CREATE, TRUNCATE and other write operations
- **Path Traversal Prevention**: Blocks `/`, `\`, `..` in filenames to prevent directory traversal attacks
- **Rate Limiting**: Burst (20/second) + sustained (500/minute) per-IP rate limits (configurable via env vars)
- **Query Timeout**: 30-second query timeout to prevent runaway queries (configurable via `QUERY_TIMEOUT_MS`)
- **CORS**: Configured with `allow_credentials=False`
- **Cloudflare IP Extraction**: Extracts real client IP from proxy headers for accurate rate limiting

## Run

```bash
pip install -r requirements.txt
uvicorn app:app --host 0.0.0.0 --port 8000
```

## API Monitoring

This API optionally uses [tigzig-api-monitor](https://pypi.org/project/tigzig-api-monitor/), an open-source centralized logging middleware for FastAPI. Set `API_MONITOR_URL` and `API_MONITOR_KEY` env vars to enable.

**Data Capture**: The middleware captures client IP, request path, status codes, response times, and request bodies. This data is sent to a configurable logging endpoint.

**Data Retention**: The middleware captures data but does not manage its lifecycle. It is the deployer's responsibility to implement appropriate data retention and deletion policies in accordance with their own compliance requirements (GDPR, CCPA, etc.).

**Graceful Degradation**: If the logging service is unavailable or not configured, API calls proceed normally — logging fails silently without affecting functionality.

**Self-Hosting**: The package is available on [PyPI](https://pypi.org/project/tigzig-api-monitor/). To self-host, configure your own database endpoint.

## License

MIT License

## Author

Built by [Amar Harolikar](https://www.linkedin.com/in/amarharolikar/)

Explore 30+ open source AI tools for analytics, databases & automation at [tigzig.com](https://tigzig.com)
