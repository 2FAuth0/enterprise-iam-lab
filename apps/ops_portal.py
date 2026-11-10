"""Operations portal with a fail-closed, time-bounded approval interface."""

import time
from collections.abc import Callable
from typing import Literal

from fastapi import Depends, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, ConfigDict

from .portals.auth import OIDC, Session, Settings
from .portals.ui import portal, shell

TITLE = "Operations Portal"
CHANGE_CONFIG = "ops:change-config"
# Returns the expiry of a currently valid grant for this issuer, subject and action.
ApprovalLookup = Callable[[str, str, str], float | None]


class ConfigUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reporting_interval: Literal["5 minutes", "15 minutes", "30 minutes"]


def create_app(
    settings: Settings | None = None, *, oidc: OIDC | None = None,
    approval_lookup: ApprovalLookup | None = None,
):
    settings = settings or Settings.from_env("ops-portal", 8001)
    app, require_role = portal(TITLE, settings, oidc, "/ops/metrics", "View operations metrics")
    interval = "15 minutes"

    @app.get("/ops/metrics", response_class=HTMLResponse)
    async def metrics(session: Session = Depends(require_role("ops-viewer"))):
        options = "".join(
            f'<option{" selected" if value == interval else ""}>{value}</option>'
            for value in ("5 minutes", "15 minutes", "30 minutes")
        )
        content = f"""
        <p>Sample metrics and a simulated reporting configuration.</p>
        <table><thead><tr><th scope="col">Metric</th><th scope="col">Value</th></tr></thead>
        <tbody><tr><td>Processed batches today</td><td>48</td></tr>
        <tr><td>Queued batches</td><td>3</td></tr><tr><td>Failed batches</td><td>1</td></tr>
        </tbody></table>
        <h2>Reporting configuration</h2>
        <p>Changes require Operations admin access, MFA and active approval.
        <a href="/login?mfa=true">Sign in with MFA</a></p>
        <form method="post" data-method="POST" action="/ops/config">
          <label for="interval">Reporting interval</label>
          <select id="interval" name="reporting_interval">{options}</select>
          <button type="submit">Save</button>
        </form>
        """
        return shell(TITLE, "Operations metrics", content, session)

    @app.post("/ops/config")
    async def change_config(
        update: ConfigUpdate,
        session: Session = Depends(require_role("ops-admin", write=True)),
    ):
        nonlocal interval
        if not settings.mfa_acr or session.acr != settings.mfa_acr:
            raise HTTPException(403, "This action requires verified MFA assurance.")
        try:
            expires = (
                approval_lookup(settings.issuer, session.subject, CHANGE_CONFIG)
                if approval_lookup is not None else None
            )
        except Exception:
            raise HTTPException(503, "Administrative approval could not be verified.") from None
        if type(expires) not in (int, float) or not time.time() < expires < float("inf"):
            raise HTTPException(403, "This action requires an active administrative approval.")
        interval = update.reporting_interval
        return {"reporting_interval": interval}

    return app
