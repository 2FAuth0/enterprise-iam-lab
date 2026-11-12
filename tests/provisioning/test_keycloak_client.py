import base64
import json
from urllib.parse import parse_qs

import httpx
import pytest

from provisioning import KeycloakClient
from provisioning import keycloak_client
from provisioning.exceptions import (
    AmbiguousIdentity,
    AuthenticationError,
    AuthorizationDenied,
    ConflictError,
    InvalidRequest,
    MalformedJSON,
    ResourceNotFound,
    SearchNoMatch,
    SearchVisibilityUnverified,
    ServiceUnavailable,
    UnexpectedResponse,
)

BASE = "https://keycloak.example"
REALM = "northstar-analytics"
ADMIN = f"/admin/realms/{REALM}"
TOKEN = f"/realms/{REALM}/protocol/openid-connect/token"
CLIENT_ID = "iam-provisioning-worker"
SECRET = "synthetic-private-secret"
BEARER = "synthetic-access-token"
USER = {"id": "person-1", "username": "mara"}
GROUPS = {"HR": "group-hr", "Operations": "group-ops"}
NEW_USER = {
    "username": "mara", "employee_id": "EMP-101", "first_name": "Mara",
    "last_name": "Vale", "email": "mara@example.test",
}


@pytest.fixture
def make_client():
    clients = []

    def create(admin, *, token=None, verified=True, groups=GROUPS):
        calls = []

        def handler(request):
            calls.append(request)
            if request.url.path == TOKEN:
                assert request.method == "POST"
                assert parse_qs(request.content.decode()) == {"grant_type": ["client_credentials"]}
                assert request.headers["Authorization"] == "Basic " + base64.b64encode(
                    f"{CLIENT_ID}:{SECRET}".encode()
                ).decode()
                if token:
                    return token(request)
                return httpx.Response(200, json={
                    "access_token": BEARER, "expires_in": 60, "token_type": "Bearer",
                })
            assert request.url.path.startswith(ADMIN)
            assert request.headers["Authorization"].startswith("Bearer ")
            return admin(request)

        client = KeycloakClient(
            BASE, REALM, CLIENT_ID, SECRET,
            transport=httpx.MockTransport(handler),
            search_visibility_verified=verified,
            department_groups=groups,
        )
        clients.append(client)
        return client, calls

    yield create
    for client in clients:
        client.close()


def test_authenticates_reuses_token_and_gets_user(make_client):
    def admin(request):
        assert request.method == "GET"
        assert request.url.path == ADMIN + "/users/person-1"
        assert request.headers["Authorization"] == "Bearer " + BEARER
        return httpx.Response(200, json=USER)

    client, calls = make_client(admin)
    assert client.get_user("person-1") == USER
    assert client.get_user("person-1") == USER
    assert [request.url.path for request in calls] == [
        TOKEN, ADMIN + "/users/person-1",
        ADMIN + "/users/person-1",
    ]


def test_expired_token_refreshes_before_next_request(make_client, monkeypatch):
    now = 100
    monkeypatch.setattr(keycloak_client.time, "monotonic", lambda: now)
    client, calls = make_client(lambda request: httpx.Response(200, json=USER))
    client.get_user("person-1")
    now += 61
    client.get_user("person-1")
    assert sum(request.url.path == TOKEN for request in calls) == 2


@pytest.mark.parametrize("retry_status", [200, 401])
def test_unauthorized_response_refreshes_once(make_client, retry_status):
    tokens = iter(["first-token", "second-token"])

    def token(_):
        return httpx.Response(200, json={
            "access_token": next(tokens), "expires_in": 60, "token_type": "Bearer",
        })

    def admin(request):
        if request.headers["Authorization"] == "Bearer first-token":
            return httpx.Response(401)
        assert request.headers["Authorization"] == "Bearer second-token"
        return httpx.Response(retry_status, json=USER)

    client, calls = make_client(admin, token=token)
    if retry_status == 401:
        with pytest.raises(AuthenticationError):
            client.get_user("person-1")
    else:
        assert client.get_user("person-1") == USER
    assert [request.url.path for request in calls] == [TOKEN, ADMIN + "/users/person-1"] * 2


@pytest.mark.parametrize(("status", "error"), [
    (403, AuthorizationDenied), (404, ResourceNotFound), (409, ConflictError),
    (429, ServiceUnavailable), (503, ServiceUnavailable), (302, UnexpectedResponse),
])
def test_admin_write_errors_do_not_retry(make_client, status, error):
    def admin(request):
        assert request.method == "PUT"
        return httpx.Response(status, headers={"Location": "https://elsewhere.example/"})

    client, calls = make_client(admin)
    with pytest.raises(error):
        client.set_user_enabled("person-1", False)
    assert len(calls) == 2


@pytest.mark.parametrize("status", [400, 401])
def test_bad_client_credentials(make_client, status):
    client, calls = make_client(
        lambda _: pytest.fail("Admin endpoint must not be called"),
        token=lambda _: httpx.Response(status, text=SECRET),
    )
    with pytest.raises(AuthenticationError) as failure:
        client.get_user("person-1")
    assert SECRET not in str(failure.value)
    assert len(calls) == 1


@pytest.mark.parametrize(("body", "error"), [
    (b"invalid json", MalformedJSON),
    (b"[]", UnexpectedResponse),
    (b'{"expires_in":60,"token_type":"Bearer"}', UnexpectedResponse),
    (b'{"access_token":"","expires_in":60,"token_type":"Bearer"}', UnexpectedResponse),
    (b'{"access_token":"token","expires_in":true,"token_type":"Bearer"}', UnexpectedResponse),
    (b'{"access_token":"token","expires_in":60,"token_type":"Basic"}', UnexpectedResponse),
])
def test_malformed_token_response(make_client, body, error):
    client, calls = make_client(
        lambda _: pytest.fail("Admin endpoint must not be called"),
        token=lambda _: httpx.Response(200, content=body),
    )
    with pytest.raises(error):
        client.get_user("person-1")
    assert len(calls) == 1


def test_exact_username_search_checks_all_pages(make_client):
    def admin(request):
        params = request.url.params
        assert params["username"] == "mara"
        assert params["exact"] == "true"
        results = {"0": [{"id": "wrong", "username": "Mara"}], "1": [USER], "2": []}
        return httpx.Response(200, json=results[params["first"]])

    client, calls = make_client(admin)
    assert client.find_user_by_username("mara") == USER
    assert len(calls) == 4


def test_duplicate_username_is_rejected(make_client):
    client, _ = make_client(lambda _: httpx.Response(200, json=[USER, {**USER, "id": "other"}]))
    with pytest.raises(AmbiguousIdentity):
        client.find_user_by_username("mara")


@pytest.mark.parametrize(("lookup", "value"), [
    ("find_user_by_username", "missing"),
    ("find_user_by_employee_id", "EMP-404"),
    ("find_group_by_name", "missing"),
])
def test_absence_requires_verified_visibility(make_client, lookup, value):
    unverified, calls = make_client(lambda _: httpx.Response(200, json=[]), verified=False)
    with pytest.raises(SearchVisibilityUnverified):
        getattr(unverified, lookup)(value)
    assert not calls

    verified, _ = make_client(lambda _: httpx.Response(200, json=[]))
    with pytest.raises(ResourceNotFound):
        getattr(verified, lookup)(value)


def test_employee_id_duplicate_on_later_page(make_client):
    def admin(request):
        params = request.url.params
        assert "q" not in params
        assert params["briefRepresentation"] == "false"
        return httpx.Response(200, json=[{
            "id": "person-" + params["first"], "attributes": {"employee_id": ["EMP-101"]},
        }])

    client, _ = make_client(admin)
    with pytest.raises(AmbiguousIdentity):
        client.find_user_by_employee_id("EMP-101")


@pytest.mark.parametrize("attribute", ["EMP-101", [], ["EMP-101", "EMP-102"], [101]])
def test_employee_id_must_be_single_managed_attribute_value(make_client, attribute):
    client, _ = make_client(lambda _: httpx.Response(200, json=[
        {**USER, "attributes": {"employee_id": attribute}},
    ]))
    with pytest.raises(UnexpectedResponse):
        client.find_user_by_employee_id("EMP-101")


def test_employee_id_can_match_after_unrelated_users(make_client):
    employee = {**USER, "attributes": {"employee_id": ["EMP-101"]}}
    results = {"0": [{"id": "other"}], "1": [employee], "2": []}
    client, _ = make_client(lambda request: httpx.Response(
        200, json=results[request.url.params["first"]],
    ))
    assert client.find_user_by_employee_id("EMP-101") == employee


@pytest.mark.parametrize("user_id", ["", "  ", "..", "a/b", "%2e%2e", None])
def test_missing_or_invalid_user_id(make_client, user_id):
    client, calls = make_client(lambda _: pytest.fail("Invalid ID reached Keycloak"))
    with pytest.raises(InvalidRequest):
        client.get_user(user_id)
    with pytest.raises(InvalidRequest):
        client.add_user_to_group(user_id, "group-hr")
    assert not calls


def test_get_user_groups(make_client):
    groups = [{"id": "group-hr", "name": "HR"}, {"id": "group-ops", "name": "Operations"}]

    def admin(request):
        if request.url.path == ADMIN + "/users/person-1/groups/count":
            return httpx.Response(200, json={"count": len(groups)})
        assert request.url.path == ADMIN + "/users/person-1/groups"
        offset = int(request.url.params["first"])
        return httpx.Response(200, json=groups[offset:offset + 1])

    client, _ = make_client(admin)
    assert client.get_user_groups("person-1") == groups


def test_filtered_group_listing_fails_closed(make_client):
    def admin(request):
        if request.url.path.endswith("/groups/count"):
            return httpx.Response(200, json={"count": 1})
        return httpx.Response(200, json=[])

    client, _ = make_client(admin)
    with pytest.raises(SearchVisibilityUnverified):
        client.get_user_groups("person-1")


def test_find_group_by_exact_name_without_hierarchy(make_client):
    hr = {"id": "group-hr", "name": "HR"}

    def admin(request):
        assert request.url.path == ADMIN + "/groups"
        assert request.url.params["search"] == "HR"
        assert request.url.params["exact"] == "true"
        assert request.url.params["populateHierarchy"] == "false"
        return httpx.Response(200, json=[hr] if request.url.params["first"] == "0" else [])

    client, _ = make_client(admin)
    assert client.find_group_by_name("HR") == hr


def test_repeated_page_is_not_a_successful_search(make_client):
    client, _ = make_client(lambda _: httpx.Response(200, json=[USER]))
    with pytest.raises(UnexpectedResponse):
        client.find_user_by_username("mara")


@pytest.mark.parametrize("enabled", [True, False])
def test_create_disabled_user(make_client, enabled):
    def admin(request):
        assert request.method == "POST"
        assert request.url.path == ADMIN + "/users"
        assert json.loads(request.content) == {
            "username": "mara", "firstName": "Mara", "lastName": "Vale",
            "email": "mara@example.test", "attributes": {"employee_id": ["EMP-101"]},
            "enabled": False, "emailVerified": False, "groups": ["/Provisioning-Staging"],
        }
        return httpx.Response(201, headers={"Location": BASE + ADMIN + "/users/person-1"})

    client, calls = make_client(admin)
    assert client.create_disabled_user(**NEW_USER, enabled=enabled) == "person-1"
    assert len(calls) == 2


@pytest.mark.parametrize("override", [
    {"groups": ["/HR"]},
    {"groups": ["/Provisioning-Staging", "/Administrators"]},
    {"staging_group_path": "/Administrators"},
    {"emailVerified": True},
    {"realmRoles": ["realm-admin"]},
    {"clientRoles": {}},
    {"credentials": []},
])
def test_create_rejects_caller_overrides(make_client, override):
    client, calls = make_client(lambda _: pytest.fail("Invalid creation reached Keycloak"))
    with pytest.raises(TypeError):
        client.create_disabled_user(**NEW_USER, **override)
    assert not calls


@pytest.mark.parametrize("location", [
    None,
    "http://[invalid",
    ADMIN + "/users/",
    ADMIN + "/users/%2F",
    ADMIN + "/groups/group-hr",
])
def test_create_with_unusable_location_is_not_replayed(make_client, location):
    headers = {} if location is None else {"Location": location}
    client, calls = make_client(lambda _: httpx.Response(201, headers=headers))
    with pytest.raises(UnexpectedResponse, match="Reconcile"):
        client.create_disabled_user(**NEW_USER)
    assert len(calls) == 2


def test_create_denied_is_not_replayed(make_client):
    client, calls = make_client(lambda _: httpx.Response(403))
    with pytest.raises(AuthorizationDenied):
        client.create_disabled_user(**NEW_USER)
    assert len(calls) == 2


def test_create_timeout_is_not_replayed(make_client):
    def admin(request):
        raise httpx.ReadTimeout("Response timed out", request=request)

    client, calls = make_client(admin)
    with pytest.raises(ServiceUnavailable, match="timed out"):
        client.create_disabled_user(**NEW_USER)
    assert len(calls) == 2


def test_profile_update_and_enable_send_only_allowlisted_fields(make_client):
    client, calls = make_client(lambda _: httpx.Response(204))
    client.update_user("person-1", {"firstName": "Mara", "email": "mara@example.test"})
    client.set_user_enabled("person-1", True)
    assert [request.method for request in calls[1:]] == ["PUT", "PUT"]
    assert [json.loads(request.content) for request in calls[1:]] == [
        {"firstName": "Mara", "email": "mara@example.test"}, {"enabled": True},
    ]


@pytest.mark.parametrize("changes", [
    {"employee_id": "EMP-102"},
    {"attributes": {"employee_id": ["EMP-102"]}},
    {"enabled": True},
    {"username": "someone-else"},
    {},
])
def test_forbidden_profile_changes(make_client, changes):
    client, calls = make_client(lambda _: pytest.fail("Forbidden payload reached Keycloak"))
    with pytest.raises(InvalidRequest):
        client.update_user("person-1", changes)
    assert not calls


def test_membership_and_logout_methods(make_client):
    client, calls = make_client(lambda _: httpx.Response(204))
    group_id = client.department_group_id("HR")
    client.add_user_to_group("person-1", group_id)
    client.remove_user_from_group("person-1", group_id)
    client.logout_user("person-1")
    assert [(request.method, request.url.path) for request in calls[1:]] == [
        ("PUT", ADMIN + "/users/person-1/groups/group-hr"),
        ("DELETE", ADMIN + "/users/person-1/groups/group-hr"),
        ("POST", ADMIN + "/users/person-1/logout"),
    ]


def test_unknown_departments_and_groups_are_rejected(make_client):
    with pytest.raises(InvalidRequest):
        make_client(lambda _: httpx.Response(204), groups={"Superusers": "privileged-id"})
    client, calls = make_client(lambda _: pytest.fail("Unauthorized group reached Keycloak"))
    for group_id in ("privileged-id", ""):
        with pytest.raises(InvalidRequest):
            client.add_user_to_group("person-1", group_id)
        with pytest.raises(InvalidRequest):
            client.remove_user_from_group("person-1", group_id)
    for department in ("Unknown", "Finance", ""):
        with pytest.raises(InvalidRequest):
            client.department_group_id(department)
    assert not calls


def test_timeout_does_not_replay_write_or_expose_sensitive_request(make_client, caplog):
    def admin(request):
        raise httpx.ReadTimeout(f"{SECRET} {BEARER}", request=request)

    client, calls = make_client(admin)
    with pytest.raises(ServiceUnavailable, match="timed out") as failure:
        client.set_user_enabled("person-1", False)
    assert len(calls) == 2
    assert failure.value.__context__ is None
    for value in (SECRET, BEARER):
        assert value not in str(failure.value)
        assert value not in repr(failure.value)
        assert value not in caplog.text


def test_error_response_body_is_not_exposed(make_client):
    client, _ = make_client(lambda _: httpx.Response(403, text=f"{SECRET} {BEARER}"))
    with pytest.raises(AuthorizationDenied) as failure:
        client.get_user("person-1")
    assert SECRET not in str(failure.value)
    assert BEARER not in str(failure.value)


def test_rejects_plaintext_remote_endpoint():
    with pytest.raises(InvalidRequest, match="HTTPS"):
        KeycloakClient("http://keycloak.example", REALM, CLIENT_ID, SECRET)


@pytest.mark.parametrize(("operation", "group_path", "method"), [
    ("add_user_to_managed_group", "/Provisioning-Managed", "PUT"),
    ("remove_user_from_staging_group", "/Provisioning-Staging", "DELETE"),
])
def test_narrow_provisioning_membership_checks_group_path(make_client, operation, group_path, method):
    def admin(request):
        if request.method == "GET":
            assert request.url.path == ADMIN + "/groups/group-id"
            return httpx.Response(200, json={"id": "group-id", "path": group_path})
        assert request.method == method
        assert request.url.path == ADMIN + "/users/person-1/groups/group-id"
        return httpx.Response(204)

    client, calls = make_client(admin)
    getattr(client, operation)("person-1", "group-id")
    assert [request.method for request in calls] == ["POST", "GET", method]


@pytest.mark.parametrize("operation", ["add_user_to_managed_group", "remove_user_from_staging_group"])
def test_narrow_membership_rejects_unrelated_group(make_client, operation):
    client, calls = make_client(lambda _: httpx.Response(
        200, json={"id": "group-id", "path": "/Administrators"},
    ))
    with pytest.raises(InvalidRequest):
        getattr(client, operation)("person-1", "group-id")
    assert [request.method for request in calls] == ["POST", "GET"]


def test_search_http_404_is_distinct_from_an_empty_result(make_client):
    missing_endpoint, _ = make_client(lambda _: httpx.Response(404))
    with pytest.raises(ResourceNotFound) as failure:
        missing_endpoint.find_user_by_employee_id("EMP-101")
    assert not isinstance(failure.value, SearchNoMatch)

    empty_results, _ = make_client(lambda _: httpx.Response(200, json=[]))
    with pytest.raises(SearchNoMatch):
        empty_results.find_user_by_employee_id("EMP-101")
