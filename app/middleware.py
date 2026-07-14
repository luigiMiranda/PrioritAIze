"""Authentication / API-key middleware — Phase 2 §5.

When ``APP_API_KEY`` is set in the environment, this middleware enforces:

- ``X-API-Key`` header on ``/api/*`` routes.
- ``Authorization: Bearer <key>`` on web routes (except static files and
  health check).

Leave ``APP_API_KEY`` empty to disable authentication (default for local dev).
"""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from app.config import APP_API_KEY

PUBLIC_PREFIXES = ("/static/", "/health")
API_PREFIX = "/api"


class AuthMiddleware(BaseHTTPMiddleware):
    """Simple API-key / bearer-token gate."""

    async def dispatch(self, request: Request, call_next):
        # No auth configured → passthrough
        if not APP_API_KEY:
            return await call_next(request)

        path = request.url.path

        # Always allow static assets & health check
        if path.startswith(PUBLIC_PREFIXES):
            return await call_next(request)

        # API routes require X-API-Key header
        if path.startswith(API_PREFIX):
            key = request.headers.get("X-API-Key", "")
            if key != APP_API_KEY:
                return JSONResponse(
                    {"error": "Missing or invalid X-API-Key header"},
                    status_code=401,
                )
            return await call_next(request)

        # Web routes require Authorization: Bearer <key> or a session cookie
        auth_header = request.headers.get("Authorization", "")
        cookie_auth = request.cookies.get("cvrs_auth", "")

        if auth_header.startswith("Bearer ") and auth_header[7:] == APP_API_KEY:
            return await call_next(request)

        if cookie_auth == APP_API_KEY:
            return await call_next(request)

        # Unauthenticated — show a simple login page for GET requests
        if request.method == "GET":
            from fastapi.responses import HTMLResponse

            return HTMLResponse(
                _LOGIN_HTML,
                status_code=200,
            )

        return JSONResponse({"error": "Unauthorized"}, status_code=401)


_LOGIN_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>CVRS — Login</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
<div class="container mt-5" style="max-width:400px">
  <div class="card shadow">
    <div class="card-body text-center">
      <h3 class="mb-3">&#x1f510; CVRS Authentication</h3>
      <form method="POST" action="/login">
        <div class="mb-3">
          <label for="key" class="form-label">API Key</label>
          <input type="password" class="form-control" id="key" name="key"
                 placeholder="Enter your API key" required>
        </div>
        <button type="submit" class="btn btn-primary w-100">Sign In</button>
      </form>
    </div>
  </div>
</div>
</body>
</html>"""
