import json

import httpx
import pytest

from provisioning import KeycloakClient
from provisioning.exceptions import SearchVisibilityUnverified
from provisioning.lab_joiner import main

ADMIN = "/admin/realms/northstar-analytics"
TOKEN = "/realms/northstar-analytics/protocol/openid-connect/token"
EVENT = {
    "event_id": "lab-event-001", "employee_id": "JML-LAB-001", "username": "jml.lab.synthetic001",
    "first_name": "Synthetic", "last_name": "Employee", "email": "synthetic001@example.test",
    "department": "Engineering", "event_type": "JOINER",
}
GROUPS = {
    "staging": "/Provisioning-Staging", "managed": "/Provisioning-Managed",
    "HR": "/Departments/HR", "Engineering": "/Departments/Engineering",
    "Finance": "/Departments/Finance", "Operations": "/Departments/Operations",
}
SECRET = "test-client-secret"
ACCESS_TOKEN = "mock-access-token"


class MockKeycloak:
    def __init__(self):
        self.users = []
        self.memberships = set()
        self.calls = []
        self.writes = []
        self.fail_write = None
        self.fail_read_after = None
        self.search_status = 200
        self.token_status = 200
        self.count_override = None
        self.page_override = None
        self.user_after_create = None
        self.before_create = lambda: None

    def group(self, group_id):
        path = GROUPS[group_id]
        return {"id": group_id, "name": path.rsplit("/", 1)[-1], "path": path}

    def __call__(self, request):
        path = request.url.path
        self.calls.append((request.method, path, dict(request.url.params)))
        if path == TOKEN:
            assert request.method == "POST"
            assert request.content == b"grant_type=client_credentials"
            return httpx.Response(self.token_status, json={
                "access_token": ACCESS_TOKEN, "token_type": "Bearer", "expires_in": 60,
            })

        assert request.headers["Authorization"] == f"Bearer {ACCESS_TOKEN}"
        resource = path.removeprefix(ADMIN)
        if request.method == "GET":
            if resource.startswith("/groups/"):
                return httpx.Response(200, json=self.group(resource.rsplit("/", 1)[-1]))
            if resource in {"/users/count", "/users"}:
                username = request.url.params.get("username")
                matches = [
                    user for user in self.users
                    if username is None or user["username"] == username
                ]
                if resource.endswith("/count"):
                    count = len(matches) if self.count_override is None else self.count_override
                    return httpx.Response(self.search_status, json=count)
                if self.page_override is not None:
                    return httpx.Response(self.search_status, json=self.page_override)
                offset = int(request.url.params["first"])
                limit = int(request.url.params["max"])
                return httpx.Response(self.search_status, json=matches[offset:offset + limit])
            if self.fail_read_after is not None and self.writes[-1:] == [self.fail_read_after]:
                return httpx.Response(403)
            if resource == "/users/created":
                return httpx.Response(200, json=self.user_after_create)
            if resource == "/users/created/groups/count":
                return httpx.Response(200, json={"count": len(self.memberships)})
            assert resource == "/users/created/groups"
            groups = [self.group(group) for group in sorted(self.memberships)]
            return httpx.Response(200, json=groups if request.url.params["first"] == "0" else [])

        operations = {
            ("POST", "/users"): "create",
            ("PUT", "/users/created/groups/managed"): "enroll",
            ("PUT", "/users/created/groups/Engineering"): "assign",
            ("DELETE", "/users/created/groups/staging"): "remove staging",
        }
        operation = operations[request.method, resource]
        self.writes.append(operation)
        if operation == "create":
            self.before_create()
            payload = json.loads(request.content)
            assert payload["enabled"] is False and payload["emailVerified"] is False
            assert payload["groups"] == ["/Provisioning-Staging"]
            self.user_after_create = {**payload, "id": "created"}
            self.users.append(self.user_after_create)
            self.memberships.add("staging")
            if self.fail_write == "timeout":
                raise httpx.ReadTimeout("Ambiguous creation", request=request)
            if self.fail_write == "location":
                return httpx.Response(201)
            return httpx.Response(201, headers={"Location": ADMIN + "/users/created"})
        assert self.user_after_create["enabled"] is False
        if operation == self.fail_write:
            return httpx.Response(403)
        group = resource.rsplit("/", 1)[-1]
        if request.method == "PUT":
            self.memberships.add(group)
        else:
            self.memberships.remove(group)
        return httpx.Response(204)


@pytest.fixture
def lab(monkeypatch, tmp_path):
    service = MockKeycloak()
    real_client = httpx.Client
    monkeypatch.setattr(httpx, "Client", lambda **kwargs: real_client(
        **{**kwargs, "transport": httpx.MockTransport(service)},
    ))
    path = tmp_path / "event.json"
    path.write_text(json.dumps(EVENT), encoding="utf-8")
    for name, value in {
        "KEYCLOAK_BASE_URL": "http://127.0.0.1:8080",
        "KEYCLOAK_REALM": "northstar-analytics",
        "KEYCLOAK_CLIENT_ID": "iam-provisioning-worker",
        "KEYCLOAK_CLIENT_SECRET": SECRET,
        "IAM_TEST_STAGING_GROUP_ID": "staging",
        "IAM_PREFLIGHT_MANAGED_GROUP_ID": "managed",
        "IAM_PREFLIGHT_DEPARTMENT_GROUPS": json.dumps({
            name: {"id": name, "name": name, "path": GROUPS[name]}
            for name in ("HR", "Engineering", "Finance", "Operations")
        }),
    }.items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("IAM_LAB_MODE", raising=False)
    return path, service


def execute(lab, monkeypatch):
    path, _ = lab
    monkeypatch.setenv("IAM_LAB_MODE", "1")
    return main(["--event", str(path), "--execute"])


def test_live_execution_disabled_by_default(lab, capsys):
    path, service = lab
    assert main(["--event", str(path), "--execute"]) == 2
    assert "IAM_LAB_MODE=1" in capsys.readouterr().out
    assert not service.calls


def test_env_opt_in_does_not_change_ordinary_client(lab, monkeypatch):
    _, service = lab
    monkeypatch.setenv("IAM_LAB_MODE", "1")
    with KeycloakClient.from_env() as client:
        assert client.search_visibility_verified is False
        with pytest.raises(SearchVisibilityUnverified):
            client.find_user_by_employee_id(EVENT["employee_id"])
    assert not service.calls


@pytest.mark.parametrize(("name", "value"), [
    ("KEYCLOAK_BASE_URL", "https://keycloak.example"),
    ("KEYCLOAK_BASE_URL", "https://localhost.example"),
    ("KEYCLOAK_BASE_URL", "https://127.0.0.1@keycloak.example"),
    ("KEYCLOAK_REALM", "other-realm"),
    ("KEYCLOAK_CLIENT_ID", "other-client"),
])
def test_live_rejects_wrong_target_before_network(lab, monkeypatch, name, value):
    monkeypatch.setenv(name, value)
    assert execute(lab, monkeypatch) == 2
    assert not lab[1].calls


@pytest.mark.parametrize("change", [
    {"username": "ordinary.employee"}, {"username": "jml.lab."},
    {"employee_id": "EMP-101"}, {"email": "employee@northstar.example"},
    {"department": "Administrators"},
])
def test_live_rejects_non_lab_event_before_network(lab, monkeypatch, change):
    lab[0].write_text(json.dumps({**EVENT, **change}), encoding="utf-8")
    assert execute(lab, monkeypatch) == 2
    assert not lab[1].calls


def test_dry_run_validates_fixture_and_makes_no_calls(lab, capsys):
    path, service = lab
    assert main(["--event", str(path), "--dry-run"]) == 0
    output = capsys.readouterr().out
    assert "DRY RUN" in output
    assert "Live check" in output
    assert "not proof of global uniqueness" in output
    assert "PASS provisioned" not in output
    assert not service.calls


@pytest.mark.parametrize("conflict", ["employee", "username", "duplicate"])
def test_matching_or_ambiguous_identity_stops_creation(lab, monkeypatch, conflict):
    _, service = lab
    if conflict == "username":
        service.users.append({"id": "existing", "username": EVENT["username"]})
    else:
        service.users.append({
            "id": "existing", "username": "other.user",
            "attributes": {"employee_id": [EVENT["employee_id"]]},
        })
        if conflict == "duplicate":
            service.users.append({**service.users[0], "id": "another", "username": "another.user"})
    assert execute(lab, monkeypatch) == 1
    assert not service.writes
    if conflict != "duplicate":
        assert any(params.get("username") == EVENT["username"] for _, _, params in service.calls)


@pytest.mark.parametrize(("field", "value"), [
    ("token_status", 401), ("search_status", 401), ("search_status", 403), ("search_status", 404),
    ("count_override", 1), ("count_override", True), ("page_override", {"invalid": "page"}),
])
def test_failed_or_incomplete_search_cannot_authorize_creation(lab, monkeypatch, field, value):
    _, service = lab
    setattr(service, field, value)
    assert execute(lab, monkeypatch) != 0
    assert not service.writes


def test_end_to_end_prints_identity_before_creation_and_never_activates(lab, monkeypatch, capsys):
    _, service = lab
    assert main(["--event", str(lab[0]), "--dry-run"]) == 0
    capsys.readouterr()

    def check_before_create():
        output = capsys.readouterr().out
        assert EVENT["username"] in output and EVENT["event_id"] in output
        assert "not proof of global uniqueness" in output
        assert SECRET not in output and ACCESS_TOKEN not in output

    service.before_create = check_before_create
    assert execute(lab, monkeypatch) == 0
    assert service.writes == ["create", "enroll", "assign", "remove staging"]
    assert service.user_after_create["enabled"] is False
    assert service.memberships == {"managed", "Engineering"}
    assert "PASS provisioned_disabled" in capsys.readouterr().out
    assert execute(lab, monkeypatch) == 1
    assert service.writes == ["create", "enroll", "assign", "remove staging"]


@pytest.mark.parametrize(("failure", "expected"), [
    ("timeout", ["create"]),
    ("location", ["create"]),
    ("enroll", ["create", "enroll"]),
    ("assign", ["create", "enroll", "assign"]),
    ("remove staging", ["create", "enroll", "assign", "remove staging"]),
])
def test_write_failure_stops_without_retry_and_reports_identity(lab, monkeypatch, capsys, failure, expected):
    _, service = lab
    service.fail_write = failure
    assert execute(lab, monkeypatch) == 1
    assert service.writes == expected
    assert service.user_after_create["enabled"] is False
    output = capsys.readouterr().out
    assert "Reconcile before retrying" in output
    assert EVENT["username"] in output and EVENT["event_id"] in output
    assert SECRET not in output and ACCESS_TOKEN not in output


@pytest.mark.parametrize("step", ["create", "enroll", "assign", "remove staging"])
def test_failed_read_back_stops_workflow(lab, monkeypatch, step):
    _, service = lab
    service.fail_read_after = step
    assert execute(lab, monkeypatch) == 1
    assert service.writes[-1] == step
    assert service.user_after_create["enabled"] is False
