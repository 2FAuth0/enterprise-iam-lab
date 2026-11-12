import pytest

from provisioning.exceptions import (
    AmbiguousIdentity, AuthorizationDenied, SearchNoMatch, SearchVisibilityUnverified,
    ServiceUnavailable, UnexpectedResponse,
)
from provisioning.mover import InvalidMoverEvent, MoverConflict, MoverEvent, MoverFailure, MoverOrchestrator
from provisioning.preflight import GroupExpectation

EVENT = {
    "event_id": "move-001", "employee_id": "JML-LAB-001", "username": "jml.lab.employee001",
    "from_department": "Engineering", "to_department": "Finance",
}
DEPARTMENTS = {
    name: GroupExpectation(name.lower(), name, f"/Departments/{name}")
    for name in ("HR", "Engineering", "Finance", "Operations")
}
MANAGED = GroupExpectation("managed", "Provisioning-Managed", "/Provisioning-Managed")
GROUPS = {group.id: group for group in (MANAGED, *DEPARTMENTS.values())}


class FakeClient:
    def __init__(self):
        self.search_visibility_verified = True
        self.user = {
            "id": "known-user", "username": EVENT["username"], "enabled": False,
            "attributes": {"employee_id": [EVENT["employee_id"]]},
        }
        self.memberships = {"managed", "engineering"}
        self.calls = []
        self.writes = []
        self.search_error = None
        self.lookup_override = {}
        self.group_override = {}
        self.write_error = {}
        self.ignore_write = set()
        self.read_error = {}
        self.user_drift = {}

    def _lookup(self, key, value):
        self.calls.append(("lookup", key, value))
        if self.search_error:
            raise self.search_error
        return {**self.user, **self.lookup_override.get(key, {})}

    def find_user_by_employee_id(self, employee_id):
        return self._lookup("employee_id", employee_id)

    def find_user_by_username(self, username):
        return self._lookup("username", username)

    def department_group_id(self, department):
        return DEPARTMENTS[department].id

    def get_group(self, group_id):
        group = GROUPS[group_id]
        return {
            "id": group.id, "name": group.name, "path": group.path,
            **self.group_override.get(group_id, {}),
        }

    def get_user(self, user_id):
        assert user_id == self.user["id"]
        self.calls.append(("read user",))
        return {**self.user, **self.user_drift.get(len(self.writes), {})}

    def get_user_groups(self, user_id):
        assert user_id == self.user["id"]
        self.calls.append(("read groups", frozenset(self.memberships)))
        if len(self.writes) in self.read_error:
            raise self.read_error[len(self.writes)]
        return [
            {"id": group, "path": GROUPS[group].path if group in GROUPS else "/Administrators"}
            for group in self.memberships
        ]

    def _write(self, action, user_id, group_id):
        assert user_id == self.user["id"]
        assert (action, group_id) in {("remove", "engineering"), ("add", "finance")}
        self.writes.append((action, group_id))
        self.calls.append((action, group_id))
        if action in self.write_error:
            raise self.write_error[action]

    def remove_user_from_group(self, user_id, group_id):
        self._write("remove", user_id, group_id)
        if "remove" not in self.ignore_write:
            self.memberships.remove(group_id)

    def add_user_to_group(self, user_id, group_id):
        self._write("add", user_id, group_id)
        if "add" not in self.ignore_write:
            self.memberships.add(group_id)


@pytest.fixture
def workflow():
    client = FakeClient()
    mover = MoverOrchestrator(client, managed_group_id="managed", department_groups=DEPARTMENTS)
    return mover, client


def test_valid_mover_event_defaults_to_mover_and_hides_identifiers():
    event = MoverEvent.from_mapping(EVENT)
    assert event.event_type == "MOVER"
    assert event.from_department == "Engineering"
    assert event.to_department == "Finance"
    assert EVENT["employee_id"] not in repr(event)
    assert EVENT["username"] not in repr(event)


@pytest.mark.parametrize("missing", EVENT)
def test_missing_fields_fail_before_access(workflow, missing):
    mover, client = workflow
    with pytest.raises(InvalidMoverEvent):
        mover.run({key: value for key, value in EVENT.items() if key != missing})
    assert not client.calls


@pytest.mark.parametrize("overrides", [
    {"from_department": "Other"}, {"to_department": "Administrators"},
    {"to_department": "Engineering"}, {"employee_id": " "}, {"username": "invalid username"},
    {"event_id": 42}, {"event_type": "JOINER"}, {"enabled": True},
])
def test_invalid_event_fails_before_access(workflow, overrides):
    mover, client = workflow
    with pytest.raises(InvalidMoverEvent):
        mover.run({**EVENT, **overrides})
    assert not client.calls


@pytest.mark.parametrize("memberships", [
    {"engineering"}, {"managed"}, {"managed", "finance"},
    {"managed", "engineering", "finance"}, {"managed", "engineering", "administrators"},
])
def test_unmanaged_conflicting_and_unexpected_memberships_are_rejected(workflow, memberships):
    mover, client = workflow
    client.memberships = memberships
    with pytest.raises(MoverFailure) as failure:
        mover.run(EVENT)
    assert failure.value.step == "initial state verification"
    assert not failure.value.reconciliation_required
    assert not client.writes


@pytest.mark.parametrize(("lookup", "overrides"), [
    ("employee_id", {"attributes": {"employee_id": ["another"]}}),
    ("employee_id", {"username": "other.user"}),
    ("username", {"id": "another-id"}),
    ("username", {"attributes": {}}),
])
def test_lookups_must_agree_on_exact_identity(workflow, lookup, overrides):
    mover, client = workflow
    client.lookup_override[lookup] = overrides
    with pytest.raises(MoverConflict, match="same identity"):
        mover.run(EVENT)
    assert not client.writes


def test_independently_known_user_id_must_match(workflow):
    mover, client = workflow
    with pytest.raises(MoverConflict, match="same identity"):
        mover.run(EVENT, expected_user_id="different-id")
    assert not client.writes


@pytest.mark.parametrize("error", [SearchNoMatch, AmbiguousIdentity, SearchVisibilityUnverified, AuthorizationDenied])
def test_missing_ambiguous_or_incomplete_identity_stops_before_writes(workflow, error):
    mover, client = workflow
    client.search_error = error()
    with pytest.raises((MoverConflict, MoverFailure)):
        mover.run(EVENT)
    assert not client.writes


def test_unverified_client_is_blocked_before_any_reads(workflow):
    mover, client = workflow
    client.search_visibility_verified = False
    with pytest.raises(MoverFailure, match="SearchVisibilityUnverified"):
        mover.run(EVENT)
    assert not client.calls


@pytest.mark.parametrize(("group", "overrides"), [
    ("managed", {"path": "/Other"}), ("finance", {"name": "Administrators"}),
    ("engineering", {"path": "/Privileged"}), ("operations", {"id": "different"}),
])
def test_group_ids_names_and_paths_must_match_approval(workflow, group, overrides):
    mover, client = workflow
    client.group_override[group] = overrides
    with pytest.raises(MoverFailure, match="group preflight"):
        mover.run(EVENT)
    assert not client.writes


@pytest.mark.parametrize("enabled", [True, False])
def test_transfer_verifies_revoke_before_grant_and_preserves_enabled_state(workflow, enabled):
    mover, client = workflow
    client.user["enabled"] = enabled
    result = mover.run(EVENT, expected_user_id="known-user")
    assert result.status == "transferred"
    assert result.enabled is enabled and client.user["enabled"] is enabled
    assert set(result.previous_groups) == {"/Provisioning-Managed", "/Departments/Engineering"}
    assert set(result.final_groups) == {"/Provisioning-Managed", "/Departments/Finance"}
    assert client.writes == [("remove", "engineering"), ("add", "finance")]
    assert client.calls.index(("remove", "engineering")) < client.calls.index(
        ("read groups", frozenset({"managed"}))
    ) < client.calls.index(("add", "finance"))


@pytest.mark.parametrize(("action", "expected", "source_revoked"), [
    ("remove", [("remove", "engineering")], False),
    ("add", [("remove", "engineering"), ("add", "finance")], True),
])
@pytest.mark.parametrize("error", [AuthorizationDenied, ServiceUnavailable, UnexpectedResponse])
def test_write_failure_stops_and_blocks_replay(workflow, action, expected, source_revoked, error):
    mover, client = workflow
    client.write_error[action] = error()
    with pytest.raises(MoverFailure) as failure:
        mover.run(EVENT)
    assert failure.value.reconciliation_required
    assert failure.value.source_revoked is source_revoked
    assert client.writes == expected
    if source_revoked:
        assert client.memberships == {"managed"}
        assert "Partial" in str(failure.value)
    for event in (EVENT, {**EVENT, "event_id": "another-event"}):
        with pytest.raises(MoverConflict, match="reconciliation"):
            mover.run(event)
    assert client.writes == expected


@pytest.mark.parametrize(("action", "step"), [
    ("remove", "revocation verification"), ("add", "final verification"),
])
def test_success_status_without_membership_change_fails_verification(workflow, action, step):
    mover, client = workflow
    client.ignore_write.add(action)
    with pytest.raises(MoverFailure, match=step):
        mover.run(EVENT)
    assert client.writes[-1][0] == action
    assert len(client.writes) == (1 if action == "remove" else 2)


@pytest.mark.parametrize("drift", [
    {"enabled": True}, {"username": "other.user"}, {"attributes": {"employee_id": ["different"]}},
])
@pytest.mark.parametrize(("write_count", "step"), [(1, "revocation verification"), (2, "final verification")])
def test_identity_and_enabled_state_must_stay_unchanged(workflow, drift, write_count, step):
    mover, client = workflow
    client.user_drift[write_count] = drift
    with pytest.raises(MoverFailure, match=step):
        mover.run(EVENT)
    assert len(client.writes) == write_count


def test_group_visibility_failure_after_revocation_prevents_grant(workflow):
    mover, client = workflow
    client.read_error[1] = SearchVisibilityUnverified()
    with pytest.raises(MoverFailure, match="revocation verification"):
        mover.run(EVENT)
    assert client.writes == [("remove", "engineering")]


def test_completed_or_changed_event_replay_does_not_write(workflow):
    mover, client = workflow
    mover.run(EVENT)
    with pytest.raises(MoverConflict, match="already completed"):
        mover.run(EVENT)
    with pytest.raises(MoverConflict, match="different transfer"):
        mover.run({**EVENT, "to_department": "HR"})
    fresh = MoverOrchestrator(client, managed_group_id="managed", department_groups=DEPARTMENTS)
    with pytest.raises(MoverFailure, match="initial state verification"):
        fresh.run(EVENT)
    assert len(client.writes) == 2


def test_dry_run_validates_and_never_contacts_client(workflow):
    mover, client = workflow
    plan = mover.run(EVENT, dry_run=True)
    assert plan.status == "dry_run"
    assert plan.actions[0].startswith("Live check")
    assert "Revoke Engineering" in plan.actions[2]
    assert "Assign Finance" in plan.actions[3]
    assert not client.calls and not client.writes
    with pytest.raises(InvalidMoverEvent):
        mover.run({**EVENT, "to_department": "Engineering"}, dry_run=True)
