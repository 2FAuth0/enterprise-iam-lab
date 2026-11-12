import pytest

from provisioning.exceptions import (
    AmbiguousIdentity, AuthorizationDenied, ResourceNotFound, SearchNoMatch,
    SearchVisibilityUnverified, ServiceUnavailable,
)
from provisioning.joiner import (
    InvalidJoinerEvent, JoinerConflict, JoinerEvent, JoinerFailure, JoinerOrchestrator,
)

EVENT = {
    "event_id": "joiner-demo-001", "employee_id": "EMP-101", "username": "mara.vale",
    "first_name": "Mara", "last_name": "Vale", "email": "mara.vale@example.test",
    "department": "Engineering", "event_type": "JOINER",
}
GROUPS = {
    "staging": "/Provisioning-Staging",
    "managed": "/Provisioning-Managed",
    "engineering": "/Engineering",
}


class FakeClient:
    def __init__(self):
        self.user = None
        self.memberships = set()
        self.calls = []
        self.writes = []
        self.lookup_failure = {}
        self.write_failure = {}
        self.unexpected_group_at = None
        self.enabled_at = None

    def department_group_id(self, department):
        assert department == "Engineering"
        self.calls.append("department mapping")
        return "engineering"

    def get_group(self, group_id):
        self.calls.append(f"group {group_id}")
        return {"id": group_id, "path": GROUPS[group_id]}

    def _lookup(self, key, value):
        self.calls.append(f"lookup {key}")
        if key in self.lookup_failure:
            raise self.lookup_failure[key]
        if self.user and self.user.get(key) == value:
            return self.user.copy()
        if self.user and self.user.get("attributes", {}).get(key) == [value]:
            return self.user.copy()
        raise SearchNoMatch()

    def find_user_by_employee_id(self, employee_id):
        return self._lookup("employee_id", employee_id)

    def find_user_by_username(self, username):
        return self._lookup("username", username)

    def _write(self, operation):
        assert self.user is None or self.user["enabled"] is False
        self.writes.append(operation)
        self.calls.append(operation)
        if operation in self.write_failure:
            raise self.write_failure[operation]

    def create_disabled_user(self, *, username, employee_id, first_name, last_name, email):
        self._write("create")
        assert (first_name, last_name, email) == (EVENT["first_name"], EVENT["last_name"], EVENT["email"])
        self.user = {
            "id": "person-1", "username": username, "attributes": {"employee_id": [employee_id]},
            "enabled": False, "emailVerified": False,
        }
        self.memberships.add("staging")
        return self.user["id"]

    def get_user(self, user_id):
        assert user_id == self.user["id"]
        self.calls.append("read user")
        record = self.user.copy()
        if self.writes[-1] == self.enabled_at:
            record["enabled"] = True
        return record

    def get_user_groups(self, user_id):
        assert user_id == self.user["id"]
        self.calls.append("read memberships")
        groups = [{"id": group, "path": GROUPS[group]} for group in sorted(self.memberships)]
        if self.writes[-1] == self.unexpected_group_at:
            groups.append({"id": "other", "path": "/Other"})
        return groups

    def add_user_to_managed_group(self, user_id, group_id):
        assert user_id == self.user["id"] and group_id == "managed"
        self._write("enroll")
        self.memberships.add(group_id)

    def add_user_to_group(self, user_id, group_id):
        assert user_id == self.user["id"] and group_id == "engineering"
        self._write("assign")
        self.memberships.add(group_id)

    def remove_user_from_staging_group(self, user_id, group_id):
        assert user_id == self.user["id"] and group_id == "staging"
        self._write("remove staging")
        self.memberships.remove(group_id)


@pytest.fixture
def workflow():
    client = FakeClient()
    return JoinerOrchestrator(client, staging_group_id="staging", managed_group_id="managed"), client


def test_valid_joiner_event():
    event = JoinerEvent.from_mapping(EVENT)
    assert event.event_id == EVENT["event_id"]
    assert event.employee_id == EVENT["employee_id"]
    assert EVENT["email"] not in repr(event)


@pytest.mark.parametrize("field", EVENT)
def test_missing_required_fields_fail_before_access(workflow, field):
    joiner, client = workflow
    with pytest.raises(InvalidJoinerEvent, match="missing"):
        joiner.run({key: value for key, value in EVENT.items() if key != field})
    assert not client.calls


@pytest.mark.parametrize("overrides", [
    {"department": "Administrators"}, {"event_type": "MOVER"}, {"employee_id": " "},
    {"username": "contains space"}, {"email": "invalid"}, {"email": 123},
    {"enabled": True},
])
def test_invalid_events_fail_before_access(workflow, overrides):
    joiner, client = workflow
    with pytest.raises(InvalidJoinerEvent):
        joiner.run({**EVENT, **overrides})
    assert not client.calls


def test_successful_joiner_verifies_each_stage_and_remains_disabled(workflow):
    joiner, client = workflow
    result = joiner.run(EVENT)
    assert result.status == "provisioned_disabled"
    assert result.user_id == "person-1"
    assert client.calls == [
        "department mapping", "group staging", "group managed", "group engineering",
        "lookup employee_id", "lookup username",
        "create", "read user", "read memberships",
        "enroll", "read user", "read memberships",
        "assign", "read user", "read memberships",
        "remove staging", "read user", "read memberships",
    ]
    assert client.user["enabled"] is False
    assert client.user["emailVerified"] is False
    assert client.memberships == {"managed", "engineering"}


def test_duplicate_employee_id_aborts(workflow):
    joiner, client = workflow
    client.lookup_failure["employee_id"] = AmbiguousIdentity()
    with pytest.raises(JoinerConflict, match="ambiguous"):
        joiner.run(EVENT)
    assert not client.writes


def test_existing_username_conflict_aborts(workflow):
    joiner, client = workflow
    client.user = {"id": "unrelated", "username": EVENT["username"]}
    with pytest.raises(JoinerConflict, match="username already exists"):
        joiner.run(EVENT)
    assert not client.writes


@pytest.mark.parametrize("error", [SearchVisibilityUnverified, ResourceNotFound, ServiceUnavailable])
def test_indeterminate_search_cannot_authorize_create(workflow, error):
    joiner, client = workflow
    client.lookup_failure["employee_id"] = error()
    with pytest.raises(JoinerFailure) as failure:
        joiner.run(EVENT)
    assert failure.value.step == "identity lookup"
    assert failure.value.reconciliation_required is False
    assert not client.writes


@pytest.mark.parametrize(("operation", "step", "writes"), [
    ("create", "disabled creation", ["create"]),
    ("enroll", "managed enrollment", ["create", "enroll"]),
    ("assign", "department assignment", ["create", "enroll", "assign"]),
    ("remove staging", "staging removal", ["create", "enroll", "assign", "remove staging"]),
])
def test_write_failure_stops_workflow_and_requires_reconciliation(workflow, operation, step, writes):
    joiner, client = workflow
    client.write_failure[operation] = AuthorizationDenied()
    with pytest.raises(JoinerFailure) as failure:
        joiner.run(EVENT)
    assert failure.value.step == step
    assert failure.value.reason == "AuthorizationDenied"
    assert failure.value.reconciliation_required is True
    assert client.writes == writes
    with pytest.raises(JoinerConflict, match="reconciliation"):
        joiner.run(EVENT)
    assert client.writes == writes
    if client.user is not None:
        assert client.user["enabled"] is False
        assert "staging" in client.memberships


@pytest.mark.parametrize(("operation", "step"), [
    ("create", "staging verification"),
    ("enroll", "managed verification"),
    ("assign", "department verification"),
    ("remove staging", "final verification"),
])
def test_unexpected_membership_blocks_next_action(workflow, operation, step):
    joiner, client = workflow
    client.unexpected_group_at = operation
    with pytest.raises(JoinerFailure) as failure:
        joiner.run(EVENT)
    assert failure.value.step == step
    assert failure.value.user_id == "person-1"
    assert client.writes[-1] == operation


def test_enabled_read_back_blocks_managed_enrollment(workflow):
    joiner, client = workflow
    client.enabled_at = "create"
    with pytest.raises(JoinerFailure, match="staging verification"):
        joiner.run(EVENT)
    assert client.writes == ["create"]


def test_ambiguous_create_timeout_blocks_repeat_even_if_no_user_is_visible(workflow):
    joiner, client = workflow
    client.write_failure["create"] = ServiceUnavailable("timed out")
    with pytest.raises(JoinerFailure, match="Reconcile") as failure:
        joiner.run(EVENT)
    assert failure.value.user_id is None
    assert client.user is None
    for replay in (EVENT, {**EVENT, "event_id": "another-event", "username": "different.user"}):
        with pytest.raises(JoinerConflict, match="reconciliation"):
            joiner.run(replay)
    assert client.writes == ["create"]


def test_repeated_event_and_preexisting_staged_account_do_not_write(workflow):
    joiner, client = workflow
    joiner.run(EVENT)
    expected = list(client.writes)
    with pytest.raises(JoinerConflict, match="already completed"):
        joiner.run(EVENT)
    with pytest.raises(JoinerConflict, match="already completed"):
        joiner.run({**EVENT, "employee_id": "EMP-102", "username": "another.user"})
    client.memberships = {"staging"}
    new_instance = JoinerOrchestrator(client, staging_group_id="staging", managed_group_id="managed")
    with pytest.raises(JoinerConflict, match="ownership"):
        new_instance.run(EVENT)
    assert client.writes == expected


def test_group_path_mismatch_aborts_before_creation():
    client = FakeClient()
    joiner = JoinerOrchestrator(client, staging_group_id="staging", managed_group_id="engineering")
    with pytest.raises(JoinerFailure, match="group preflight") as failure:
        joiner.run(EVENT)
    assert failure.value.reconciliation_required is False
    assert not client.writes


def test_dry_run_validates_without_contacting_keycloak(workflow):
    joiner, client = workflow
    plan = joiner.run(EVENT, dry_run=True)
    assert plan.status == "dry_run"
    assert plan.actions[0].startswith("Live check:")
    assert any("Engineering" in action for action in plan.actions)
    assert not client.calls and not client.writes
    with pytest.raises(InvalidJoinerEvent):
        joiner.run({**EVENT, "department": "Administrators"}, dry_run=True)
