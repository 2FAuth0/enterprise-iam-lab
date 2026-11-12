import pytest

from provisioning.exceptions import (
    AmbiguousIdentity, AuthorizationDenied, SearchVisibilityUnverified,
    ServiceUnavailable, UnexpectedResponse,
)
from provisioning.leaver import InvalidLeaverEvent, LeaverConflict, LeaverEvent, LeaverOrchestrator
from provisioning.preflight import GroupExpectation

EVENT = {
    "event_id": "leaver-lab-001", "employee_id": "JML-LAB-001", "username": "jml.lab.employee001",
}
DEPARTMENTS = {
    name: GroupExpectation(name.lower(), name, f"/Departments/{name}")
    for name in ("HR", "Engineering", "Finance", "Operations")
}
MANAGED = GroupExpectation("managed", "Provisioning-Managed", "/Provisioning-Managed")
GROUPS = {group.id: group for group in (MANAGED, *DEPARTMENTS.values())}
USER_ID = "lab-user"


class FakeClient:
    search_visibility_verified = True

    def __init__(self):
        self.user = {
            "id": USER_ID, "username": EVENT["username"], "enabled": True,
            "attributes": {"employee_id": [EVENT["employee_id"]]},
        }
        self.memberships = {"managed", "engineering"}
        self.calls = []
        self.writes = []
        self.errors = {}
        self.ignore = set()
        self.user_overrides = {}
        self.group_overrides = {}

    def _read(self, operation):
        self.calls.append(operation)
        if operation in self.errors:
            raise self.errors[operation]

    def _write(self, operation):
        self.writes.append(operation)
        self._read(operation)

    def find_user_by_employee_id(self, employee_id):
        assert employee_id == EVENT["employee_id"]
        self._read("employee search")
        return self.user.copy()

    def find_user_by_username(self, username):
        assert username == EVENT["username"]
        self._read("username search")
        return self.user.copy()

    def get_user(self, user_id):
        assert user_id == USER_ID
        self._read("user read")
        return {**self.user, **self.user_overrides.get(len(self.writes), {})}

    def get_group(self, group_id):
        group = GROUPS[group_id]
        return {
            "id": group.id, "name": group.name, "path": group.path,
            **self.group_overrides.get(group_id, {}),
        }

    def department_group_id(self, department):
        return DEPARTMENTS[department].id

    def get_user_groups(self, user_id):
        assert user_id == USER_ID
        self._read("memberships read")
        return [
            {"id": group, "path": GROUPS[group].path if group in GROUPS else "/Administrators"}
            for group in self.memberships
        ]

    def set_user_enabled(self, user_id, enabled):
        assert user_id == USER_ID and enabled is False
        self._write("disable")
        if "disable" not in self.ignore:
            self.user["enabled"] = False

    def logout_user(self, user_id):
        assert user_id == USER_ID and self.user["enabled"] is False
        self._write("logout")

    def remove_user_from_group(self, user_id, group_id):
        assert user_id == USER_ID and self.user["enabled"] is False and group_id == "engineering"
        self._write("revoke")
        if "revoke" not in self.ignore:
            self.memberships.remove(group_id)


@pytest.fixture
def workflow():
    client = FakeClient()
    return LeaverOrchestrator(client, managed_group_id="managed", department_groups=DEPARTMENTS), client


def test_valid_leaver_event():
    event = LeaverEvent.from_mapping(EVENT)
    assert event.event_type == "LEAVER"
    assert EVENT["employee_id"] not in repr(event)
    assert EVENT["username"] not in repr(event)


@pytest.mark.parametrize("field", EVENT)
def test_missing_event_field_is_rejected(workflow, field):
    leaver, client = workflow
    with pytest.raises(InvalidLeaverEvent):
        leaver.run({key: value for key, value in EVENT.items() if key != field})
    assert not client.calls


@pytest.mark.parametrize("override", [
    {"event_id": ""}, {"employee_id": " "}, {"employee_id": 42},
    {"username": "user name"}, {"username": "invalid\nuser"},
    {"event_type": "MOVER"}, {"enabled": False},
])
def test_invalid_event_rejected_without_http(workflow, override):
    leaver, client = workflow
    with pytest.raises(InvalidLeaverEvent):
        leaver.run({**EVENT, **override})
    assert not client.calls


@pytest.mark.parametrize("identity", [
    {"username": "wrong.user"}, {"attributes": {"employee_id": ["JML-LAB-OTHER"]}},
])
@pytest.mark.parametrize("direct_only", [False, True])
def test_search_and_direct_read_must_agree(workflow, identity, direct_only):
    leaver, client = workflow
    if direct_only:
        client.user_overrides[0] = identity
    else:
        client.user.update(identity)
    result = leaver.run(EVENT)
    assert result.status == "failed"
    assert result.failed_step == ("initial state verification" if direct_only else "identity lookup")
    assert not client.writes


def test_expected_user_id_must_match(workflow):
    leaver, client = workflow
    assert leaver.run(EVENT, expected_user_id="wrong").failed_step == "identity lookup"
    assert not client.writes


@pytest.mark.parametrize("memberships", [
    {"engineering"}, {"managed", "admin"}, {"managed", "engineering", "finance"},
    {"managed", "engineering", "admin"},
])
def test_unmanaged_or_unexpected_groups_rejected(workflow, memberships):
    leaver, client = workflow
    client.memberships = memberships
    assert leaver.run(EVENT).failed_step == "initial state verification"
    assert not client.writes


def test_group_metadata_must_match_approval(workflow):
    leaver, client = workflow
    client.group_overrides["engineering"] = {"path": "/Administrators"}
    assert leaver.run(EVENT).failed_step == "group preflight"
    assert not client.writes


@pytest.mark.parametrize("error", [AmbiguousIdentity, SearchVisibilityUnverified, AuthorizationDenied])
def test_indeterminate_search_stops_without_writes(workflow, error):
    leaver, client = workflow
    client.errors["employee search"] = error()
    result = leaver.run(EVENT)
    assert result.failed_step == "identity lookup"
    assert result.failure_reason == error.__name__
    assert not client.writes


def test_ordinary_workflow_needs_verified_visibility(workflow):
    leaver, client = workflow
    client.search_visibility_verified = False
    assert leaver.run(EVENT).failure_reason == "SearchVisibilityUnverified"
    assert not client.calls


@pytest.mark.parametrize("enabled", [True, False])
@pytest.mark.parametrize("has_department", [True, False])
def test_successful_leaver_orders_writes_and_retains_managed_scope(workflow, enabled, has_department):
    leaver, client = workflow
    client.user["enabled"] = enabled
    if not has_department:
        client.memberships = {"managed"}
    result = leaver.run(EVENT, expected_user_id=USER_ID)
    assert result.status == "completed"
    assert result.disabled_verified and result.final_state_verified
    assert result.disable_changed is enabled
    assert result.logout_status == "accepted"
    assert result.department_status == ("revoked" if has_department else "already_absent")
    assert client.writes == (["disable"] if enabled else []) + ["logout"] + (["revoke"] if has_department else [])
    assert client.memberships == {"managed"}
    assert client.user["enabled"] is False
    if enabled:
        assert "user read" in client.calls[client.calls.index("disable") + 1:client.calls.index("logout")]


@pytest.mark.parametrize("error", [AuthorizationDenied, ServiceUnavailable, UnexpectedResponse])
def test_disable_error_prevents_logout_and_revocation(workflow, error):
    leaver, client = workflow
    client.errors["disable"] = error()
    result = leaver.run(EVENT)
    assert result.status == "failed" and result.failed_step == "disable account"
    assert not result.disabled_verified and result.reconciliation_required
    assert result.logout_status == "not_requested"
    assert client.writes == ["disable"]
    assert leaver.run(EVENT) is result
    assert client.writes == ["disable"]


def test_failed_disable_read_back_blocks_logout(workflow):
    leaver, client = workflow
    client.ignore.add("disable")
    result = leaver.run(EVENT)
    assert result.failed_step == "verify disabled state"
    assert client.writes == ["disable"]


def test_definitive_logout_rejection_continues_verified_revocation(workflow):
    leaver, client = workflow
    client.errors["logout"] = AuthorizationDenied()
    result = leaver.run(EVENT)
    assert result.status == "partial"
    assert result.logout_status == "rejected" and result.logout_error == "AuthorizationDenied"
    assert result.department_status == "revoked" and result.final_state_verified
    assert result.reconciliation_required
    assert client.writes == ["disable", "logout", "revoke"]
    assert client.memberships == {"managed"}
    assert client.user["enabled"] is False


def test_definitive_logout_rejection_stops_if_read_back_changes(workflow):
    leaver, client = workflow
    client.errors["logout"] = AuthorizationDenied()
    client.user_overrides[2] = {"enabled": True}
    result = leaver.run(EVENT)
    assert result.failed_step == "verify state before department revocation"
    assert result.logout_status == "rejected"
    assert client.writes == ["disable", "logout"]


@pytest.mark.parametrize("error", [ServiceUnavailable, UnexpectedResponse])
def test_ambiguous_logout_stops_and_leaves_disabled_account(workflow, error):
    leaver, client = workflow
    client.errors["logout"] = error()
    result = leaver.run(EVENT)
    assert result.status == "partial" and result.logout_status == "unknown"
    assert result.reconciliation_required and not result.final_state_verified
    assert client.writes == ["disable", "logout"]
    assert client.user["enabled"] is False
    assert client.memberships == {"managed", "engineering"}
    with pytest.raises(LeaverConflict, match="reconciliation"):
        leaver.run({**EVENT, "event_id": "new-id"})
    assert leaver.run(EVENT) is result
    assert client.writes == ["disable", "logout"]


@pytest.mark.parametrize("error", [AuthorizationDenied, ServiceUnavailable])
def test_department_failure_is_partial_without_reactivation_or_retry(workflow, error):
    leaver, client = workflow
    client.errors["revoke"] = error()
    result = leaver.run(EVENT)
    assert result.status == "partial" and result.failed_step == "revoke department"
    assert result.logout_status == "accepted" and result.department_status == "unverified"
    assert result.reconciliation_required and client.user["enabled"] is False
    assert client.writes == ["disable", "logout", "revoke"]
    assert leaver.run(EVENT) is result
    assert len(client.writes) == 3


def test_failed_final_membership_verification_reports_partial(workflow):
    leaver, client = workflow
    client.ignore.add("revoke")
    result = leaver.run(EVENT)
    assert result.status == "partial" and result.failed_step == "final verification"
    assert not result.final_state_verified


def test_final_identity_drift_blocks_completion(workflow):
    leaver, client = workflow
    client.user_overrides[3] = {"username": "wrong.user"}
    result = leaver.run(EVENT)
    assert result.status == "partial" and result.failed_step == "final verification"
    assert result.department_status == "revoked" and not result.final_state_verified


def test_completed_repeat_returns_original_result_and_rejects_conflicting_event_id(workflow):
    leaver, client = workflow
    original = leaver.run(EVENT)
    assert leaver.run(EVENT) is original
    with pytest.raises(LeaverConflict, match="different identity"):
        leaver.run({**EVENT, "username": "jml.lab.changed"})
    assert client.writes == ["disable", "logout", "revoke"]


def test_dry_run_makes_zero_client_calls(workflow):
    leaver, client = workflow
    result = leaver.run(EVENT, dry_run=True)
    assert result.status == "dry_run"
    assert "Disable" in result.actions[1]
    assert not client.calls
