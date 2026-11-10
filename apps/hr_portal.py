"""HR portal with fictional, process-local employee records."""

from html import escape

from fastapi import Depends, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, ConfigDict, StringConstraints
from typing import Annotated

from .portals.auth import OIDC, Session, Settings
from .portals.ui import portal, shell

TITLE = "HR Portal"
PEOPLE = {
    101: {"name": "Mara Vale", "department": "People Operations", "title": "HR Analyst"},
    102: {"name": "Jules Venn", "department": "Operations", "title": "Service Coordinator"},
    103: {"name": "Niko Fen", "department": "Finance", "title": "Budget Analyst"},
}


class PersonUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=80)]


def create_app(settings: Settings | None = None, *, oidc: OIDC | None = None):
    settings = settings or Settings.from_env("hr-portal", 8000)
    app, require_role = portal(TITLE, settings, oidc, "/hr/people", "View employee records")
    people = {key: person.copy() for key, person in PEOPLE.items()}

    @app.get("/hr/people", response_class=HTMLResponse)
    async def list_people(session: Session = Depends(require_role("hr-viewer"))):
        rows = []
        for key, person in people.items():
            rows.append(f"""
                <tr><td>{escape(person['name'])}</td><td>{escape(person['department'])}</td>
                <td><form method="post" data-method="PATCH" action="/hr/people/{key}">
                  <input aria-label="Job title for {escape(person['name'])}"
                         name="title" value="{escape(person['title'])}" required maxlength="80">
                  <button type="submit">Save</button>
                </form></td></tr>
            """)
        content = """
        <p>Fictional employee records for the IAM lab. Saving job titles requires HR editor access.</p>
        <table><thead><tr><th scope="col">Name</th><th scope="col">Department</th>
        <th scope="col">Job title</th></tr></thead><tbody>
        """ + "".join(rows) + "</tbody></table>"
        return shell(TITLE, "Employee records", content, session)

    @app.patch("/hr/people/{person_id}")
    async def update_person(
        person_id: int, update: PersonUpdate,
        session: Session = Depends(require_role("hr-editor", write=True)),
    ):
        if person_id not in people:
            raise HTTPException(404, "Employee record not found.")
        people[person_id]["title"] = update.title
        return {"id": person_id, **people[person_id]}

    return app
