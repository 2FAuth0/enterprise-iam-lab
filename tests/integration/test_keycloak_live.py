"""Controlled live checks. Only Phase B submits an administrative write."""

import os
from uuid import uuid4

import pytest

from provisioning import KeycloakClient
from provisioning.exceptions import AuthorizationDenied
from provisioning.keycloak_client import STAGING_GROUP_PATH

pytestmark = pytest.mark.iam_live


@pytest.fixture(autouse=True)
def require_live_opt_in(request):
    if not request.config.getoption("--iam-live"):
        pytest.skip("Requires --iam-live")
    if request.node.get_closest_marker("iam_create") and os.getenv("IAM_ALLOW_CREATE_TEST") != "1":
        pytest.skip("Requires IAM_ALLOW_CREATE_TEST=1")


def required_env(name):
    value = os.environ.get(name, "")
    if not value.strip():
        pytest.fail(f"Set {name} before running this integration phase.", pytrace=False)
    return value


def check(condition, message):
    if not condition:
        pytest.fail(message, pytrace=False)


def call(operation, action):
    # Avoid rendering response data or exception locals even under --showlocals.
    try:
        return action()
    except Exception as error:
        category = type(error).__name__
    pytest.fail(f"{operation} failed ({category}).", pytrace=False)


@pytest.fixture
def client(require_live_opt_in):
    for name in ("KEYCLOAK_BASE_URL", "KEYCLOAK_REALM", "KEYCLOAK_CLIENT_ID", "KEYCLOAK_CLIENT_SECRET"):
        required_env(name)
    with call("Keycloak client setup", KeycloakClient.from_env) as api:
        yield api


@pytest.fixture
def managed_user_id():
    return required_env("IAM_TEST_MANAGED_USER_ID")


def test_read_managed_user(client, managed_user_id):
    user = call("Managed user read using Client Credentials", lambda: client.get_user(managed_user_id))
    check(user.get("username") == "jml.managed.test", "Managed ID must resolve to jml.managed.test.")
    check(user.get("enabled") is False, "Managed fixture must be disabled.")


def test_read_managed_user_groups(client, managed_user_id):
    expected_id = required_env("IAM_TEST_MANAGED_GROUP_ID")
    user = call("Managed user read", lambda: client.get_user(managed_user_id))
    check(
        user.get("username") == "jml.managed.test" and user.get("enabled") is False,
        "Managed ID must resolve to the disabled jml.managed.test fixture.",
    )
    groups = call("Managed group listing and count", lambda: client.get_user_groups(managed_user_id))
    check(
        any(group["id"] == expected_id for group in groups),
        "Managed user is missing the expected group membership.",
    )


def test_read_unmanaged_user(client):
    user_id = required_env("IAM_TEST_UNMANAGED_USER_ID")
    user = call("Unmanaged user read", lambda: client.get_user(user_id))
    check(user.get("username") == "jml.unauthorized.test", "Unmanaged ID must resolve to jml.unauthorized.test.")
    check(user.get("enabled") is False, "Unmanaged fixture must be disabled.")


def test_known_group_ids_resolve(client):
    managed_id = required_env("IAM_TEST_MANAGED_GROUP_ID")
    managed_path = required_env("IAM_TEST_MANAGED_GROUP_PATH")
    staging_id = required_env("IAM_TEST_STAGING_GROUP_ID")
    actual_managed = call("Managed group read by ID", lambda: client.get_group(managed_id).get("path"))
    check(actual_managed == managed_path, "Managed group ID resolved to an unexpected path.")
    actual_staging = call("Staging group read by ID", lambda: client.get_group(staging_id).get("path"))
    check(actual_staging == STAGING_GROUP_PATH, "Staging group ID must resolve to /Provisioning-Staging.")


@pytest.mark.iam_create
def test_create_disabled_disposable_joiner(client, request):
    staging_id = required_env("IAM_TEST_STAGING_GROUP_ID")
    staging_path = call("Staging group preflight", lambda: client.get_group(staging_id).get("path"))
    check(staging_path == STAGING_GROUP_PATH, "Staging group ID must resolve to /Provisioning-Staging.")

    suffix = uuid4().hex
    username = f"jml.create.test.{suffix}"
    employee_id = f"JML-TEST-{suffix}"
    reporter = request.config.pluginmanager.get_plugin("terminalreporter")
    if reporter is not None:
        reporter.write_line(f"Disposable Joiner username for manual reconciliation or cleanup: {username}")
    try:
        user_id = client.create_disabled_user(
            username=username, employee_id=employee_id,
            first_name="Disposable", last_name="Joiner", email=f"{username}@example.test",
        )
    except AuthorizationDenied:
        failure = "creation rejected (AuthorizationDenied)"
    except Exception as error:
        failure = f"creation outcome unconfirmed ({type(error).__name__})"
    else:
        failure = None
    check(failure is None, f"{username}: {failure}. Reconcile before any new create attempt.")

    incomplete = f"{username}: creation incomplete"
    check(isinstance(user_id, str) and bool(user_id.strip()), f"{incomplete}: missing user ID.")
    user = call(f"{incomplete}: read-back", lambda: client.get_user(user_id))
    check(user.get("username") == username, f"{incomplete}: returned ID resolves to a different username.")
    check(user.get("enabled") is False, f"{incomplete}: enabled was not false.")
    check(user.get("emailVerified") is False, f"{incomplete}: emailVerified was not false.")
    attributes = user.get("attributes")
    check(
        isinstance(attributes, dict) and attributes.get("employee_id") == [employee_id],
        f"{incomplete}: employee_id did not persist exactly.",
    )
    groups = call(f"{incomplete}: group read-back and count", lambda: client.get_user_groups(user_id))
    check(
        any(group["id"] == staging_id and group.get("path") == STAGING_GROUP_PATH for group in groups),
        f"{incomplete}: expected staging membership is missing.",
    )
    check(len(groups) == 1, f"{incomplete}: unexpected group memberships.")
