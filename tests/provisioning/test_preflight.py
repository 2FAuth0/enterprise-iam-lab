import json

import httpx
import pytest

from provisioning import KeycloakClient
from provisioning.preflight import GroupExpectation, PreflightConfig, main, run_preflight

ADMIN = "/admin/realms/northstar-analytics"
TOKEN = "/realms/northstar-analytics/protocol/openid-connect/token"
DEPARTMENT_GROUPS = {
    name: GroupExpectation(name.lower(), name, f"/Departments/{name}")
    for name in ("HR", "Engineering", "Finance", "Operations")
}
CONFIG = PreflightConfig(
    staging_group_id="staging",
    managed_group_id="managed",
    departments=DEPARTMENT_GROUPS,
    disposable_user_id="disposable",
    disposable_username="jml.create.test.synthetic",
    managed_fixture_id="fixture",
    managed_fixture_group_id="managed",
    managed_fixture_group_path="/Provisioning-Managed",
)
GROUPS = {
    "staging": {"id": "staging", "name": "Provisioning-Staging", "path": "/Provisioning-Staging"},
    "managed": {"id": "managed", "name": "Provisioning-Managed", "path": "/Provisioning-Managed"},
    **{
        group.id: {"id": group.id, "name": group.name, "path": group.path}
        for group in DEPARTMENT_GROUPS.values()
    },
}
SECRET = "test-client-secret"
ACCESS_TOKEN = "mock-access-token"
PRIVATE_VALUE = "example-sensitive-user-record-field"


def run_mock_preflight(
    *, verified=False, token_status=200, department_change=None, fixture_count=1,
    disposable_enabled=False, disposable_groups=("staging", "managed"), group_status=200,
):
    calls = []

    def respond(request):
        calls.append((request.method, request.url.path))
        if request.url.path == TOKEN:
            assert request.method == "POST"
            assert request.content == b"grant_type=client_credentials"
            assert request.headers["Authorization"].startswith("Basic ")
            return httpx.Response(token_status, json={
                "access_token": ACCESS_TOKEN, "token_type": "Bearer", "expires_in": 60,
            })

        assert request.method == "GET"
        assert request.headers["Authorization"] == f"Bearer {ACCESS_TOKEN}"
        path = request.url.path.removeprefix(ADMIN)
        if path.startswith("/groups/"):
            group_id = path.split("/")[-1]
            if group_id == "engineering":
                return httpx.Response(group_status, json={**GROUPS[group_id], **(department_change or {})})
            return httpx.Response(200, json=GROUPS[group_id])
        parts = path.split("/")
        user_id = parts[2]
        is_fixture = user_id == "fixture"
        if len(parts) == 3:
            return httpx.Response(200, json={
                "id": user_id,
                "username": "jml.managed.test" if is_fixture else CONFIG.disposable_username,
                "enabled": False if is_fixture else disposable_enabled,
                "private": PRIVATE_VALUE,
            })
        memberships = ("managed",) if is_fixture else disposable_groups
        if path.endswith("/count"):
            return httpx.Response(200, json={"count": fixture_count if is_fixture else len(memberships)})
        page = [GROUPS[group] for group in memberships] if request.url.params["first"] == "0" else []
        return httpx.Response(200, json=page)

    with KeycloakClient(
        "https://keycloak.example", "northstar-analytics", "iam-provisioning-worker", SECRET,
        department_groups={key: group.id for key, group in DEPARTMENT_GROUPS.items()},
        search_visibility_verified=verified, transport=httpx.MockTransport(respond),
    ) as client:
        results = {result.check: result for result in run_preflight(client, CONFIG)}
        assert client.search_visibility_verified is verified
    assert not any(value in str(results) for value in (SECRET, ACCESS_TOKEN, PRIVATE_VALUE))
    return results, calls


def test_preflight_authenticates_and_reads_all_groups_and_both_users():
    results, calls = run_mock_preflight()
    assert len(results) == 10
    assert results["Search visibility flag"].status == "BLOCKED"
    assert "search_visibility_verified=false" in results["Search visibility flag"].detail
    assert sum(result.status == "PASS" for result in results.values()) == 9
    assert calls[0] == ("POST", TOKEN)
    assert all(method == "GET" for method, _ in calls[1:])
    assert {path.rsplit("/", 1)[-1] for _, path in calls if path.startswith(ADMIN + "/groups/")} == set(GROUPS)


def test_reports_existing_true_flag_without_changing_it():
    results, _ = run_mock_preflight(verified=True)
    assert results["Search visibility flag"].status == "PASS"
    assert "operator assertion" in results["Search visibility flag"].detail


def test_authentication_failure_blocks_all_dependent_reads():
    results, calls = run_mock_preflight(token_status=401)
    assert all(result.status == "BLOCKED" for result in results.values())
    assert "AuthenticationError" in results["Service-account authentication"].detail
    assert calls == [("POST", TOKEN)]


@pytest.mark.parametrize("change", [
    {"name": "Other"}, {"path": "/Other/Engineering"}, {"id": "different-id"},
])
def test_department_must_match_approved_id_name_and_path(change):
    results, _ = run_mock_preflight(department_change=change)
    assert results["Engineering department group"].status == "FAIL"
    assert results["Finance department group"].status == "PASS"


def test_group_read_permission_denial_is_blocked():
    results, _ = run_mock_preflight(group_status=403)
    assert results["Engineering department group"].status == "BLOCKED"
    assert "AuthorizationDenied" in results["Engineering department group"].detail


@pytest.mark.parametrize("options", [
    {"disposable_enabled": True}, {"disposable_groups": ("managed",)},
    {"disposable_groups": ("staging",)},
])
def test_disposable_requires_disabled_state_and_both_memberships(options):
    results, _ = run_mock_preflight(**options)
    assert results["Disposable Joiner"].status == "FAIL"


def test_managed_fixture_group_count_mismatch_is_detected():
    results, calls = run_mock_preflight(fixture_count=2)
    result = results["Managed fixture membership visibility"]
    assert result.status == "FAIL"
    assert result.detail == "Membership listing disagrees with the group count."
    assert ("GET", ADMIN + "/users/fixture/groups/count") in calls
    assert results["Disposable Joiner"].status == "PASS"


def test_cli_requires_explicit_live_opt_in(monkeypatch, capsys):
    def forbidden():
        pytest.fail("Configuration was loaded before explicit opt-in.")

    monkeypatch.setattr(PreflightConfig, "from_env", forbidden)
    assert main([]) == 2
    assert capsys.readouterr().out == "BLOCKED Live preflight requires --live.\n"


def test_cli_reports_incomplete_configuration_without_printing_values(monkeypatch, capsys):
    monkeypatch.setenv("IAM_PREFLIGHT_DEPARTMENT_GROUPS", json.dumps({"HR": SECRET}))
    assert main(["--live"]) == 2
    output = capsys.readouterr().out
    assert output.startswith("BLOCKED Configuration")
    assert SECRET not in output


def test_cli_renders_sanitized_results_and_reports_blocked_readiness(monkeypatch, capsys):
    monkeypatch.setenv("IAM_PREFLIGHT_DEPARTMENT_GROUPS", json.dumps({
        name: {"id": group.id, "name": group.name, "path": group.path}
        for name, group in DEPARTMENT_GROUPS.items()
    }))
    for name, value in {
        "IAM_TEST_STAGING_GROUP_ID": CONFIG.staging_group_id,
        "IAM_PREFLIGHT_MANAGED_GROUP_ID": CONFIG.managed_group_id,
        "IAM_PREFLIGHT_DISPOSABLE_USER_ID": CONFIG.disposable_user_id,
        "IAM_PREFLIGHT_DISPOSABLE_USERNAME": CONFIG.disposable_username,
        "IAM_TEST_MANAGED_USER_ID": CONFIG.managed_fixture_id,
        "IAM_TEST_MANAGED_GROUP_ID": CONFIG.managed_fixture_group_id,
        "IAM_TEST_MANAGED_GROUP_PATH": CONFIG.managed_fixture_group_path,
        "KEYCLOAK_BASE_URL": "https://keycloak.example",
        "KEYCLOAK_REALM": "northstar-analytics",
        "KEYCLOAK_CLIENT_ID": "iam-provisioning-worker",
        "KEYCLOAK_CLIENT_SECRET": SECRET,
    }.items():
        monkeypatch.setenv(name, value)

    class ReadClient:
        search_visibility_verified = False

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return None

        def authenticate(self):
            return None

        def department_group_id(self, department):
            return DEPARTMENT_GROUPS[department].id

        def get_group(self, group_id):
            return GROUPS[group_id]

        def get_user(self, user_id):
            return {
                "id": user_id, "enabled": False, "private": PRIVATE_VALUE,
                "username": "jml.managed.test" if user_id == CONFIG.managed_fixture_id else CONFIG.disposable_username,
            }

        def get_user_groups(self, user_id):
            if user_id == CONFIG.managed_fixture_id:
                return [GROUPS["managed"]]
            return [GROUPS["staging"], GROUPS["managed"]]

    def from_env(**kwargs):
        assert kwargs == {
            "department_groups": {name: group.id for name, group in DEPARTMENT_GROUPS.items()},
        }
        return ReadClient()

    monkeypatch.setattr(KeycloakClient, "from_env", from_env)
    assert main(["--live"]) == 2
    output = capsys.readouterr().out
    assert sum(line.startswith("PASS ") for line in output.splitlines()) == 9
    assert "BLOCKED Search visibility flag" in output
    assert all(value not in output for value in (SECRET, PRIVATE_VALUE, CONFIG.disposable_username))
