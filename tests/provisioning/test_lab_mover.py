import json

import httpx
import pytest

from provisioning.lab_mover import main

ADMIN = "/admin/realms/northstar-analytics"
TOKEN = "/realms/northstar-analytics/protocol/openid-connect/token"
USER = "/users/disposable-id"
EVENT = {
    "event_id": "mover-lab-001", "employee_id": "JML-LAB-001", "username": "jml.lab.employee001",
    "from_department": "Engineering", "to_department": "Finance",
}
DEPARTMENTS = {
    name: {"id": name.lower(), "name": name, "path": f"/Departments/{name}"}
    for name in ("HR", "Engineering", "Finance", "Operations")
}
GROUPS = {
    "managed": {"id": "managed", "name": "Provisioning-Managed", "path": "/Provisioning-Managed"},
    "admin": {"id": "admin", "name": "Administrators", "path": "/Administrators"},
    **{group["id"]: group for group in DEPARTMENTS.values()},
}
SECRET = "mock-client-secret"
ACCESS_TOKEN = "mock-access-token"


class MockKeycloak:
    def __init__(self):
        self.user = {
            "id": "disposable-id", "username": EVENT["username"], "enabled": False,
            "attributes": {"employee_id": [EVENT["employee_id"]]},
        }
        self.direct_override = {}
        self.memberships = {"managed", "engineering"}
        self.calls = []
        self.writes = []
        self.fail_write = None
        self.fail_revocation_readback = False
        self.search_extra = []
        self.count_delta = 0
        self.group_override = {}

    def __call__(self, request):
        path = request.url.path
        self.calls.append((request.method, path, dict(request.url.params)))
        if path == TOKEN:
            assert request.method == "POST"
            assert request.content == b"grant_type=client_credentials"
            return httpx.Response(200, json={
                "access_token": ACCESS_TOKEN, "token_type": "Bearer", "expires_in": 60,
            })

        assert request.headers["Authorization"] == f"Bearer {ACCESS_TOKEN}"
        resource = path.removeprefix(ADMIN)
        if request.method == "GET":
            if resource.startswith("/groups/"):
                group_id = resource.rsplit("/", 1)[-1]
                return httpx.Response(200, json={**GROUPS[group_id], **self.group_override.get(group_id, {})})
            if resource in {"/users", "/users/count"}:
                username = request.url.params.get("username")
                matching = [
                    user for user in [self.user, *self.search_extra]
                    if username is None or user["username"] == username
                ]
                if resource.endswith("/count"):
                    return httpx.Response(200, json=len(matching) + self.count_delta)
                return httpx.Response(200, json=matching if request.url.params["first"] == "0" else [])
            if resource == USER:
                return httpx.Response(200, json={**self.user, **self.direct_override})
            if resource == USER + "/groups/count":
                return httpx.Response(200, json={"count": len(self.memberships)})
            assert resource == USER + "/groups"
            groups = [GROUPS[group_id] for group_id in sorted(self.memberships)]
            return httpx.Response(200, json=groups if request.url.params["first"] == "0" else [])

        operation = {
            ("DELETE", USER + "/groups/engineering"): "revoke",
            ("PUT", USER + "/groups/finance"): "assign",
        }[request.method, resource]
        self.writes.append(operation)
        if operation == self.fail_write:
            return httpx.Response(403)
        if self.fail_write == "timeout" and operation == "revoke":
            self.memberships.remove("engineering")
            raise httpx.ReadTimeout("Ambiguous revoke", request=request)
        if operation == "assign":
            assert self.memberships == {"managed"}
            self.memberships.add("finance")
        elif not self.fail_revocation_readback:
            self.memberships.remove("engineering")
        return httpx.Response(204)


@pytest.fixture
def lab(monkeypatch, tmp_path):
    service = MockKeycloak()
    real_client = httpx.Client
    monkeypatch.setattr(httpx, "Client", lambda **kwargs: real_client(
        **{**kwargs, "transport": httpx.MockTransport(service)},
    ))
    event = tmp_path / "mover.json"
    event.write_text(json.dumps(EVENT), encoding="utf-8")
    for name, value in {
        "KEYCLOAK_BASE_URL": "http://127.0.0.1:8080",
        "KEYCLOAK_REALM": "northstar-analytics",
        "KEYCLOAK_CLIENT_ID": "iam-provisioning-worker",
        "KEYCLOAK_CLIENT_SECRET": SECRET,
        "IAM_TEST_STAGING_GROUP_ID": "staging",
        "IAM_PREFLIGHT_MANAGED_GROUP_ID": "managed",
        "IAM_PREFLIGHT_DEPARTMENT_GROUPS": json.dumps(DEPARTMENTS),
    }.items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("IAM_LAB_MODE", raising=False)
    return event, service


def args(lab, mode, user_id="disposable-id"):
    return ["--event", str(lab[0]), "--expected-user-id", user_id, mode]


def execute(lab, monkeypatch, user_id="disposable-id"):
    monkeypatch.setenv("IAM_LAB_MODE", "1")
    return main(args(lab, "--execute", user_id))


def test_lab_mode_disabled_by_default(lab):
    assert main(args(lab, "--execute")) == 2
    assert not lab[1].calls


@pytest.mark.parametrize(("name", "value"), [
    ("KEYCLOAK_BASE_URL", "https://keycloak.example"),
    ("KEYCLOAK_BASE_URL", "https://localhost.example"),
    ("KEYCLOAK_REALM", "other-realm"),
    ("KEYCLOAK_CLIENT_ID", "other-client"),
])
def test_rejects_unsafe_target_without_http(lab, monkeypatch, name, value):
    monkeypatch.setenv(name, value)
    assert execute(lab, monkeypatch) == 2
    assert not lab[1].calls


@pytest.mark.parametrize("override", [
    {"username": "ordinary.employee"}, {"username": "jml.lab."},
    {"employee_id": "EMP-001"}, {"to_department": "Administrators"},
])
def test_non_synthetic_or_invalid_event_rejected(lab, monkeypatch, override):
    lab[0].write_text(json.dumps({**EVENT, **override}), encoding="utf-8")
    assert execute(lab, monkeypatch) == 2
    assert not lab[1].calls


def test_missing_expected_id_is_rejected(lab, monkeypatch):
    monkeypatch.setenv("IAM_LAB_MODE", "1")
    with pytest.raises(SystemExit) as failure:
        main(["--event", str(lab[0]), "--execute"])
    assert failure.value.code == 2
    assert not lab[1].calls
    assert execute(lab, monkeypatch, "") == 2
    assert not lab[1].calls


def test_incorrect_expected_id_is_rejected(lab, monkeypatch):
    assert execute(lab, monkeypatch, "another-id") == 1
    assert not lab[1].writes


@pytest.mark.parametrize("override", [
    {"username": "jml.lab.other"},
    {"attributes": {"employee_id": ["JML-LAB-OTHER"]}},
])
def test_expected_id_must_pass_direct_identity_readback(lab, monkeypatch, override):
    service = lab[1]
    service.direct_override = override
    assert execute(lab, monkeypatch) == 1
    assert ("GET", ADMIN + USER, {}) in service.calls
    assert not service.writes


@pytest.mark.parametrize("memberships", [
    {"managed", "engineering", "admin"}, {"engineering"}, {"managed", "finance"},
])
def test_unexpected_or_missing_membership_is_rejected(lab, monkeypatch, memberships):
    lab[1].memberships = memberships
    assert execute(lab, monkeypatch) == 1
    assert not lab[1].writes


@pytest.mark.parametrize(("group", "override"), [
    ("engineering", {"id": "different-id"}),
    ("finance", {"name": "Administrators"}),
    ("finance", {"path": "/Privileged"}),
])
def test_group_metadata_must_match_approved_values(lab, monkeypatch, group, override):
    lab[1].group_override[group] = override
    assert execute(lab, monkeypatch) == 1
    assert not lab[1].writes


def test_dry_run_makes_zero_http_requests(lab, capsys):
    assert main(args(lab, "--dry-run")) == 0
    assert not lab[1].calls
    output = capsys.readouterr().out
    assert "DRY RUN" in output and "Revoke Engineering" in output
    assert "PASS transferred" not in output


@pytest.mark.parametrize("enabled", [True, False])
def test_mock_transfer_verifies_revocation_first_and_preserves_enabled(lab, monkeypatch, capsys, enabled):
    service = lab[1]
    service.user["enabled"] = enabled
    assert execute(lab, monkeypatch) == 0
    assert service.writes == ["revoke", "assign"]
    assert service.memberships == {"managed", "finance"}
    assert service.user["enabled"] is enabled
    revoke = service.calls.index(("DELETE", ADMIN + USER + "/groups/engineering", {}))
    grant = service.calls.index(("PUT", ADMIN + USER + "/groups/finance", {}))
    assert ("GET", ADMIN + USER, {}) in service.calls[:revoke]
    assert ("GET", ADMIN + USER + "/groups/count", {}) in service.calls[revoke:grant]
    assert any(params.get("username") == EVENT["username"] for _, _, params in service.calls)
    output = capsys.readouterr().out
    assert "PASS transferred" in output
    assert SECRET not in output and ACCESS_TOKEN not in output


@pytest.mark.parametrize(("failure", "writes", "groups"), [
    ("revoke", ["revoke"], {"managed", "engineering"}),
    ("assign", ["revoke", "assign"], {"managed"}),
    ("timeout", ["revoke"], {"managed"}),
])
def test_partial_failure_stops_without_retry_or_restoring_access(lab, monkeypatch, capsys, failure, writes, groups):
    service = lab[1]
    service.fail_write = failure
    assert execute(lab, monkeypatch) == 1
    assert service.writes == writes
    assert service.memberships == groups
    output = capsys.readouterr().out
    assert "Reconcile before any further write" in output
    assert EVENT["username"] in output and EVENT["event_id"] in output
    assert SECRET not in output and ACCESS_TOKEN not in output


def test_revocation_must_be_verified_before_grant(lab, monkeypatch):
    lab[1].fail_revocation_readback = True
    assert execute(lab, monkeypatch) == 1
    assert lab[1].writes == ["revoke"]


@pytest.mark.parametrize("search_problem", ["duplicate", "count mismatch"])
def test_lab_exception_keeps_identity_search_conflict_checks(lab, monkeypatch, search_problem):
    service = lab[1]
    if search_problem == "duplicate":
        service.search_extra.append({**service.user, "id": "duplicate", "username": "jml.lab.duplicate"})
    else:
        service.count_delta = 1
    assert execute(lab, monkeypatch) == 1
    assert not service.writes
