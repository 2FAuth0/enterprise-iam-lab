from dataclasses import replace
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from provisioning.exceptions import AuthorizationDenied, ServiceUnavailable
from provisioning.journal import (
    Checkpoint, Claim, EmployeeBusy, EventConflict, EventRecord, FailureCode,
    JournalUnavailable, Phase, Status, Step, event_fingerprint,
)
from provisioning.journal_leaver import JournalLeaver, LeaverRecovery
from provisioning.leaver import LeaverEvent, LeaverOrchestrator
from provisioning.preflight import GroupExpectation

EVENT = LeaverEvent("leaver-1", "EMP-1", "synthetic.user")
GROUPS = {
    name: GroupExpectation(name.lower(), name, f"/Departments/{name}")
    for name in ("HR", "Engineering", "Finance", "Operations")
}
MANAGED = GroupExpectation("managed", "Provisioning-Managed", "/Provisioning-Managed")
GROUP_BY_ID = {group.id: group for group in (MANAGED, *GROUPS.values())}


class WorkerInterrupted(BaseException):
    pass


class FakeJournal:
    def __init__(self):
        self.records = {}
        self.history = []
        self.fail_on = None
        self.claim_busy = False

    def register(self, event):
        if self.fail_on == "register":
            raise JournalUnavailable()
        if event.event_id in self.records:
            record = self.records[event.event_id]
            if record.event_fingerprint != event_fingerprint(event):
                raise EventConflict()
            return record
        now = datetime.now(UTC)
        record = EventRecord(
            event.event_id, event.event_type, event.employee_id, event_fingerprint(event),
            None, Status.PENDING, Step.REGISTERED, now, now, None, None, False, False,
        )
        self.records[event.event_id] = record
        return record

    def claim(self, event_id):
        if self.claim_busy:
            raise EmployeeBusy()
        self._update(event_id, status=Status.IN_PROGRESS, current_step=Step.CLAIMED)
        return Claim(event_id, uuid4())

    def _update(self, event_id, **changes):
        record = replace(self.records[event_id], **changes)
        self.records[event_id] = record
        return record

    def record_checkpoint(self, claim, step, phase, *, user_id):
        if self.fail_on == (step, phase):
            raise JournalUnavailable()
        entry = Checkpoint(step, phase, datetime.now(UTC))
        self.history.append(entry)
        self._update(
            claim.event_id, current_step=step, keycloak_user_id=user_id,
            write_intent=self.records[claim.event_id].write_intent or phase is Phase.INTENT,
        )
        if self.fail_on == "interrupt after intent" and phase is Phase.INTENT:
            raise WorkerInterrupted()
        return entry

    def complete(self, claim):
        if self.fail_on == "complete":
            raise JournalUnavailable()
        assert self.history[-1].step is Step.VERIFY_FINAL and self.history[-1].phase is Phase.VERIFIED
        return self._update(claim.event_id, status=Status.COMPLETED, completed_at=datetime.now(UTC))

    def fail(self, claim, code):
        return self._update(claim.event_id, status=Status.FAILED, failure_code=code)

    def require_reconciliation(self, claim, code):
        return self._update(
            claim.event_id, status=Status.RECONCILIATION_REQUIRED,
            failure_code=code, requires_reconciliation=True,
        )

    def list_incomplete(self, *, limit, event_type):
        return [
            record for record in self.records.values()
            if record.event_type == event_type and record.status in (
                Status.PENDING, Status.IN_PROGRESS, Status.RECONCILIATION_REQUIRED,
            )
        ][:limit]

    def checkpoints(self, event_id):
        assert event_id == EVENT.event_id
        return list(self.history)


class FakeKeycloak:
    search_visibility_verified = True

    def __init__(self, journal):
        self.journal = journal
        self.enabled = True
        self.memberships = {"managed", "engineering"}
        self.writes = []
        self.reads = 0
        self.errors = {}
        self.interrupt_after_disable = False

    def find_user_by_employee_id(self, employee_id):
        assert employee_id == EVENT.employee_id
        return self.get_user("user-1")

    def find_user_by_username(self, username):
        assert username == EVENT.username
        return self.get_user("user-1")

    def get_user(self, user_id):
        assert user_id == "user-1"
        self.reads += 1
        return {
            "id": user_id, "username": EVENT.username, "enabled": self.enabled,
            "attributes": {"employee_id": [EVENT.employee_id]},
        }

    def get_group(self, group_id):
        group = GROUP_BY_ID[group_id]
        return {"id": group.id, "name": group.name, "path": group.path}

    def department_group_id(self, department):
        return GROUPS[department].id

    def get_user_groups(self, user_id):
        assert user_id == "user-1"
        return [{"id": group, "path": GROUP_BY_ID[group].path} for group in self.memberships]

    def _write(self, step, user_id):
        assert user_id == "user-1"
        assert (self.journal.history[-1].step, self.journal.history[-1].phase) == (step, Phase.INTENT)
        self.writes.append(step)
        if step in self.errors:
            raise self.errors[step]

    def set_user_enabled(self, user_id, enabled):
        assert enabled is False
        self._write(Step.DISABLE_ACCOUNT, user_id)
        self.enabled = False
        if self.interrupt_after_disable:
            raise WorkerInterrupted()

    def logout_user(self, user_id):
        assert self.enabled is False
        self._write(Step.REQUEST_LOGOUT, user_id)

    def remove_user_from_group(self, user_id, group_id):
        assert self.enabled is False and group_id == "engineering"
        self._write(Step.REVOKE_DEPARTMENT, user_id)
        self.memberships.remove(group_id)


@pytest.fixture
def workflow():
    journal = FakeJournal()
    client = FakeKeycloak(journal)
    leaver = LeaverOrchestrator(client, managed_group_id="managed", department_groups=GROUPS)
    return JournalLeaver(journal, leaver), journal, client


def test_success_checkpoints_and_duplicate_delivery(workflow):
    service, journal, client = workflow
    result = service.run(EVENT)
    assert result.status is Status.COMPLETED
    assert result.keycloak_user_id == "user-1"
    assert client.enabled is False and client.memberships == {"managed"}
    assert [(entry.step, entry.phase) for entry in journal.history] == [
        (Step.PREFLIGHT, Phase.VERIFIED),
        (Step.DISABLE_ACCOUNT, Phase.PLANNED),
        (Step.DISABLE_ACCOUNT, Phase.INTENT),
        (Step.DISABLE_ACCOUNT, Phase.ACKNOWLEDGED),
        (Step.VERIFY_DISABLED, Phase.VERIFIED),
        (Step.REQUEST_LOGOUT, Phase.PLANNED),
        (Step.REQUEST_LOGOUT, Phase.INTENT),
        (Step.REQUEST_LOGOUT, Phase.ACKNOWLEDGED),
        (Step.REVOKE_DEPARTMENT, Phase.PLANNED),
        (Step.REVOKE_DEPARTMENT, Phase.INTENT),
        (Step.REVOKE_DEPARTMENT, Phase.ACKNOWLEDGED),
        (Step.VERIFY_FINAL, Phase.VERIFIED),
    ]
    assert service.run(EVENT) == result
    with pytest.raises(EventConflict):
        service.run(replace(EVENT, username="different.user"))
    assert len(client.writes) == 3


def test_claim_rejection_and_unavailable_database_do_not_contact_keycloak(workflow):
    service, journal, client = workflow
    journal.fail_on = "register"
    with pytest.raises(JournalUnavailable):
        service.run(EVENT)
    journal.fail_on = None
    journal.claim_busy = True
    with pytest.raises(EmployeeBusy):
        service.run(EVENT)
    assert not client.reads and not client.writes


@pytest.mark.parametrize("after_write", [False, True])
def test_interrupted_worker_is_not_replayed(workflow, after_write):
    service, journal, client = workflow
    if after_write:
        client.interrupt_after_disable = True
    else:
        journal.fail_on = "interrupt after intent"
    with pytest.raises(WorkerInterrupted):
        service.run(EVENT)
    record = journal.records[EVENT.event_id]
    assert record.status is Status.IN_PROGRESS and record.write_intent
    assert journal.history[-1].phase is Phase.INTENT
    assert client.enabled is not after_write
    assert service.run(EVENT) == record
    assert client.writes == ([Step.DISABLE_ACCOUNT] if after_write else [])


@pytest.mark.parametrize(("failed_checkpoint", "writes"), [
    ((Step.DISABLE_ACCOUNT, Phase.INTENT), []),
    ((Step.DISABLE_ACCOUNT, Phase.ACKNOWLEDGED), [Step.DISABLE_ACCOUNT]),
    ((Step.VERIFY_DISABLED, Phase.VERIFIED), [Step.DISABLE_ACCOUNT]),
    ("complete", [Step.DISABLE_ACCOUNT, Step.REQUEST_LOGOUT, Step.REVOKE_DEPARTMENT]),
])
def test_database_failure_stops_new_writes(workflow, failed_checkpoint, writes):
    service, journal, client = workflow
    journal.fail_on = failed_checkpoint
    with pytest.raises(JournalUnavailable):
        service.run(EVENT)
    assert journal.records[EVENT.event_id].status is Status.IN_PROGRESS
    assert client.writes == writes


@pytest.mark.parametrize(("step", "error", "phase", "code", "revoke"), [
    (Step.REQUEST_LOGOUT, ServiceUnavailable(), Phase.AMBIGUOUS, FailureCode.AMBIGUOUS_WRITE, False),
    (Step.REQUEST_LOGOUT, AuthorizationDenied(), Phase.REJECTED, FailureCode.AUTHORIZATION, True),
    (Step.REVOKE_DEPARTMENT, AuthorizationDenied(), Phase.REJECTED, FailureCode.AUTHORIZATION, True),
])
def test_remote_failures_are_classified_and_require_reconciliation(workflow, step, error, phase, code, revoke):
    service, journal, client = workflow
    client.errors[step] = error
    result = service.run(EVENT)
    assert result.status is Status.RECONCILIATION_REQUIRED and result.failure_code is code
    assert any(entry.step is step and entry.phase is phase for entry in journal.history)
    assert (Step.REVOKE_DEPARTMENT in client.writes) is revoke
    assert client.enabled is False
    if step is Step.REQUEST_LOGOUT and revoke:
        assert result.current_step is Step.VERIFY_FINAL and client.memberships == {"managed"}
    assert service.run(EVENT) == result


def test_recovery_reads_bound_account_and_never_writes(workflow):
    service, journal, client = workflow
    client.errors[Step.REQUEST_LOGOUT] = AuthorizationDenied()
    service.run(EVENT)
    client.enabled = True
    client.memberships.add("engineering")
    before = list(client.writes)
    assessments = LeaverRecovery(journal, client, managed_group_id="managed").assess()
    assert len(assessments) == 1
    result = assessments[0]
    assert result.status is Status.RECONCILIATION_REQUIRED
    assert result.last_phase is Phase.VERIFIED
    assert sum("Discrepancy" in finding for finding in result.findings) == 2
    assert client.writes == before


def test_recovery_does_not_search_for_an_unbound_account(workflow):
    _, journal, client = workflow
    journal.register(EVENT)
    assessment, = LeaverRecovery(journal, client, managed_group_id="managed").assess()
    assert "Account ID is unavailable" in assessment.findings[0]
    assert not client.writes and not client.reads
