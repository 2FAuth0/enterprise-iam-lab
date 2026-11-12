import json

import httpx
import pytest

from provisioning.lab_leaver import main

REALM = "northstar-analytics"
ADMIN = f"/admin/realms/{REALM}"
TOKEN = f"/realms/{REALM}/protocol/openid-connect/token"
USER = "/users/lab-user"
EVENT = {
    "event_id": "leaver-demo", "employee_id": "JML-LAB-001", "username": "jml.lab.employee001",
}
DEPARTMENTS = {
    name: {"id": name.lower(), "name": name, "path": f"/Departments/{name}"}
    for name in ("HR", "Engineering", "Finance", "Operations")
}
GROUPS = {
    "managed": {"id": "managed", "name": "Provisioning-Managed", "path": "/Provisioning-Managed"},
    **{group["id"]: group for group in DEPARTMENTS.values()},
}


class MockKeycloak:
    def __init__(self):
        self.calls = []
        self.writes = []
        self.memberships = {"managed", "engineering"}
        self.user = {
            "id": "lab-user", "username": EVENT["username"], "enabled": True,
            "attributes": {"employee_id": [EVENT["employee_id"]]},
        }
        self.logout_status = 204

    def __call__(self, request):
        path = request.url.path
        self.calls.append((request.method, path))
        if path == TOKEN:
            return httpx.Response(200, json={
                "access_token": "mock-access-token", "token_type": "Bearer", "expires_in": 60,
            })
        resource = path.removeprefix(ADMIN)
        if request.method == "GET":
            if resource == "/users/count":
                return httpx.Response(200, json=1)
            if resource == "/users":
                return httpx.Response(200, json=[self.user] if request.url.params["first"] == "0" else [])
            if resource.startswith("/groups/"):
                return httpx.Response(200, json=GROUPS[resource.rsplit("/", 1)[-1]])
            if resource == USER:
                return httpx.Response(200, json=self.user)
            if resource == USER + "/groups/count":
                return httpx.Response(200, json={"count": len(self.memberships)})
            assert resource == USER + "/groups"
            groups = [GROUPS[group] for group in self.memberships]
            return httpx.Response(200, json=groups if request.url.params["first"] == "0" else [])

        self.writes.append((request.method, resource))
        if resource == USER:
            assert request.method == "PUT"
            assert json.loads(request.content) == {"enabled": False}
            self.user["enabled"] = False
        elif resource == USER + "/logout":
            assert request.method == "POST" and self.user["enabled"] is False
            return httpx.Response(self.logout_status)
        else:
            assert (request.method, resource) == ("DELETE", USER + "/groups/engineering")
            assert self.user["enabled"] is False
            self.memberships.remove("engineering")
        return httpx.Response(204)


@pytest.fixture
def lab(monkeypatch, tmp_path):
    service = MockKeycloak()
    real_client = httpx.Client
    monkeypatch.setattr(httpx, "Client", lambda **kwargs: real_client(
        **{**kwargs, "transport": httpx.MockTransport(service)},
    ))
    event = tmp_path / "leaver.json"
    event.write_text(json.dumps(EVENT), encoding="utf-8")
    for name, value in {
        "KEYCLOAK_BASE_URL": "http://127.0.0.1:8080",
        "KEYCLOAK_REALM": REALM,
        "KEYCLOAK_CLIENT_ID": "iam-provisioning-worker",
        "KEYCLOAK_CLIENT_SECRET": "mock-client-secret",
        "IAM_TEST_STAGING_GROUP_ID": "staging",
        "IAM_PREFLIGHT_MANAGED_GROUP_ID": "managed",
        "IAM_PREFLIGHT_DEPARTMENT_GROUPS": json.dumps(DEPARTMENTS),
    }.items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("IAM_LAB_MODE", raising=False)
    return event, service


def args(lab, mode, user_id="lab-user"):
    return ["--event", str(lab[0]), "--expected-user-id", user_id, mode]


def test_dry_run_and_disabled_live_mode_make_no_calls(lab, capsys):
    assert main(args(lab, "--dry-run")) == 0
    assert "No termination performed" in capsys.readouterr().out
    assert main(args(lab, "--execute")) == 2
    assert not lab[1].calls


@pytest.mark.parametrize(("name", "value"), [
    ("KEYCLOAK_BASE_URL", "https://remote.example"),
    ("KEYCLOAK_REALM", "other-realm"),
    ("KEYCLOAK_CLIENT_ID", "other-client"),
])
def test_lab_rejects_wrong_target_without_http(lab, monkeypatch, name, value):
    monkeypatch.setenv("IAM_LAB_MODE", "1")
    monkeypatch.setenv(name, value)
    assert main(args(lab, "--execute")) == 2
    assert not lab[1].calls


@pytest.mark.parametrize("overrides", [{"username": "real.user"}, {"employee_id": "EMP-101"}])
def test_lab_rejects_non_synthetic_identity(lab, monkeypatch, overrides):
    monkeypatch.setenv("IAM_LAB_MODE", "1")
    lab[0].write_text(json.dumps({**EVENT, **overrides}), encoding="utf-8")
    assert main(args(lab, "--execute")) == 2
    assert not lab[1].calls


def test_lab_requires_matching_expected_id(lab, monkeypatch):
    monkeypatch.setenv("IAM_LAB_MODE", "1")
    with pytest.raises(SystemExit) as failure:
        main(["--event", str(lab[0]), "--execute"])
    assert failure.value.code == 2 and not lab[1].calls
    assert main(args(lab, "--execute", "different-id")) == 1
    assert not lab[1].writes


@pytest.mark.parametrize(("logout_status", "exit_code", "expected_status", "revoked"), [
    (204, 0, "accepted", True), (403, 1, "rejected", True), (503, 1, "unknown", False),
])
def test_lab_write_sequence_and_sanitized_status(lab, monkeypatch, capsys, logout_status, exit_code, expected_status, revoked):
    monkeypatch.setenv("IAM_LAB_MODE", "1")
    service = lab[1]
    service.logout_status = logout_status
    assert main(args(lab, "--execute")) == exit_code
    expected = [("PUT", USER), ("POST", USER + "/logout")]
    if revoked:
        expected.append(("DELETE", USER + "/groups/engineering"))
    assert service.writes == expected
    first_write = service.calls.index(("PUT", ADMIN + USER))
    assert ("GET", ADMIN + USER) in service.calls[:first_write]
    assert ("GET", ADMIN + USER + "/groups/count") in service.calls[:first_write]
    output = capsys.readouterr().out
    assert EVENT["event_id"] in output.splitlines()[0] and EVENT["username"] in output.splitlines()[0]
    assert f"logout_request={expected_status}" in output
    assert "mock-access-token" not in output and "mock-client-secret" not in output
    assert service.user["enabled"] is False
    assert service.memberships == ({"managed"} if revoked else {"managed", "engineering"})
