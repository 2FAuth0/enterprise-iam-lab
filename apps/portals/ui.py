from html import escape
from pathlib import Path

from fastapi import Depends, FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException

from .auth import OIDC, Session, Settings, install_auth


def shell(title: str, heading: str, content: str, session: Session | None = None):
    title = escape(title)
    account = '<a href="/login">Sign in</a>'
    csrf = ""
    if session:
        csrf = f'<meta name="csrf-token" content="{escape(session.csrf)}">'
        account = """
        <a href="/me">My identity</a>
        <form method="post" data-method="POST" action="/logout">
          <button type="submit">Sign out</button>
        </form>
        """
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  {csrf}
  <title>{escape(heading)} | {title}</title>
  <link rel="stylesheet" href="/static/portal.css">
  <script src="/static/portal.js" defer></script>
</head>
<body>
  <header><nav aria-label="Portal">
    <a href="/"><strong>Northstar Analytics</strong> / {title}</a>{account}
  </nav></header>
  <main><h1>{escape(heading)}</h1>
    {content}
    <p id="feedback" role="status" aria-live="polite"></p>
  </main>
</body>
</html>"""


def portal(title: str, settings: Settings, oidc: OIDC | None, data_url: str, data_label: str):
    app = FastAPI(title=title, docs_url=None, redoc_url=None, openapi_url=None)
    app.mount("/static", StaticFiles(directory=Path(__file__).with_name("static")), name="static")
    current, authenticated, require_role = install_auth(app, settings, oidc or OIDC(settings))

    @app.middleware("http")
    async def response_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; script-src 'self'; style-src 'self'; "
            "connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        )
        return response

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException):
        if "application/json" in request.headers.get("accept", ""):
            return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
        heading = {401: "Sign-in required", 403: "Access denied"}.get(
            exc.status_code, "Request could not be completed"
        )
        content = f"<p>{escape(str(exc.detail))}</p><p><a href='/login'>Sign in with Keycloak</a></p>"
        return HTMLResponse(shell(title, heading, content, current(request)), exc.status_code)

    @app.get("/", response_class=HTMLResponse)
    async def home(request: Request):
        session = current(request)
        content = '<p><a href="/login">Sign in with Keycloak</a> to access this portal.</p>'
        if session:
            content = (
                f"<p>Signed in as <strong>{escape(session.name)}</strong>.</p>"
                f'<p><a href="{data_url}">{data_label}</a></p>'
            )
        return shell(title, title, content, session)

    @app.get("/me", response_class=HTMLResponse)
    async def me(request: Request, session: Session = Depends(authenticated)):
        if "application/json" in request.headers.get("accept", ""):
            return JSONResponse({"sub": session.subject, "name": session.name, "acr": session.acr})
        content = (
            f"<dl><dt>Account</dt><dd>{escape(session.name)}</dd>"
            f"<dt>Subject</dt><dd>{escape(session.subject)}</dd>"
            f"<dt>Authentication context</dt><dd>{escape(session.acr or 'Unavailable')}</dd></dl>"
        )
        return shell(title, "My identity", content, session)

    return app, require_role
