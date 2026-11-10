# Running the Northstar portals

From the repository root, use the lab's Python environment. The commands below assume it lives at `.venv`.

```sh
.venv/bin/python -m pip install -r apps/requirements-dev.txt
cp -n apps/.env.example apps/.env
```

Fill in the two existing Keycloak client secrets in `apps/.env` and restrict access to the file with `chmod 600 apps/.env`. It is gitignored. In each terminal, load the portal configuration before starting its server.

```sh
set -a
. apps/.env
set +a
.venv/bin/python -m uvicorn apps.hr_portal:create_app --factory --host 127.0.0.1 --port 8000 --workers 1 --no-access-log
```

```sh
set -a
. apps/.env
set +a
.venv/bin/python -m uvicorn apps.ops_portal:create_app --factory --host 127.0.0.1 --port 8001 --workers 1 --no-access-log
```

Open [HR Portal](http://localhost:8000/) and [Operations Portal](http://localhost:8001/). Use `localhost` in the browser so the callback, cookie host, and CSRF origin agree. The landing pages start without Keycloak. Sign-in and protected business requests require it.

Run the offline suite with `.venv/bin/python -m pytest -q`. It includes the existing harness tests and portal tests with a simulated provider. The server-rendered pages use a small script for JSON edits and logout. Requests made manually need the portal's session cookie, exact `Origin`, and `X-CSRF-Token` from the current page. Set `Accept: application/json` for JSON responses from `/me` and authorization errors.

- HR edits only the job title on an existing fictional record. Send `{"title":"Lead Analyst"}` to `PATCH /hr/people/101`.
- Operations accepts `{"reporting_interval":"5 minutes"}` at `POST /ops/config`. The other allowed values are `15 minutes` and `30 minutes`. Writes require a verified approval provider.
- Both portals keep synthetic records and settings in memory. Restarting restores the fixtures and clears local sessions.
