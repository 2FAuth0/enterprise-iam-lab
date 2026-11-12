"""Opt-in repository tests using a fresh database on an isolated PostgreSQL server."""

import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Barrier
from uuid import uuid4

import pytest

from provisioning.journal import (
    Claim, EmployeeBusy, EventConflict, FailureCode, InvalidTransition, Phase, Status, Step,
)
from provisioning.leaver import LeaverEvent
from provisioning.mover import MoverEvent

pytestmark = pytest.mark.journal_postgres
MIGRATIONS = Path(__file__).resolve().parents[2] / "provisioning/migrations"


@pytest.fixture(scope="module")
def test_database(request):
    if not request.config.getoption("--journal-postgres"):
        pytest.skip("Requires --journal-postgres.")
    dsn = os.getenv("JML_TEST_POSTGRES_DSN")
    if not dsn:
        pytest.fail("Set JML_TEST_POSTGRES_DSN to the isolated PostgreSQL test server.", pytrace=False)

    import psycopg
    from psycopg import sql
    from psycopg.conninfo import conninfo_to_dict, make_conninfo

    if conninfo_to_dict(dsn).get("dbname") != "jml_journal_test":
        pytest.fail("The test DSN must explicitly target jml_journal_test.", pytrace=False)

    database = "jml_test_" + uuid4().hex
    with psycopg.connect(dsn, autocommit=True) as owner:
        owner.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(database)))
        try:
            temp_dsn = make_conninfo(dsn, dbname=database)
            with psycopg.connect(temp_dsn, autocommit=True) as connection:
                for migration in sorted(MIGRATIONS.glob("*.sql")):
                    connection.execute(migration.read_text(encoding="utf-8"))
            yield temp_dsn
        finally:
            owner.execute(sql.SQL("DROP DATABASE {}").format(sql.Identifier(database)))


@pytest.fixture
def journal(test_database):
    import psycopg

    from provisioning.journal_postgres import PostgresJournal

    with psycopg.connect(test_database) as connection:
        connection.execute("TRUNCATE jml_journal.events, jml_journal.checkpoints")
    return PostgresJournal(test_database)


def event(event_id="evt-1", employee_id="EMP-1"):
    return LeaverEvent(event_id, employee_id, "synthetic.user")


def test_register_duplicate_and_conflict(journal):
    record = journal.register(event())
    assert record.status is Status.PENDING and record.current_step is Step.REGISTERED
    assert record.created_at.tzinfo is not None
    assert record.keycloak_user_id is None
    assert journal.register(event()) == record
    with pytest.raises(EventConflict):
        journal.register(replace(event(), username="different.user"))
    assert journal.get("evt-1") == record
    assert journal.get("missing") is None


def test_progress_completion_and_reconnection(journal, test_database):
    from provisioning.journal_postgres import PostgresJournal

    journal.register(event())
    claim = journal.claim("evt-1")
    restarted = PostgresJournal(test_database)
    assert restarted.get("evt-1").status is Status.IN_PROGRESS
    assert restarted.record_user_id(claim, "kc-user").keycloak_user_id == "kc-user"
    with pytest.raises(InvalidTransition):
        journal.record_user_id(claim, "different-user")
    assert journal.record_step(claim, Step.DISABLE_ACCOUNT).write_intent
    assert journal.record_step(claim, Step.VERIFY_FINAL).write_intent
    complete = restarted.complete(claim)
    assert complete.status is Status.COMPLETED
    assert complete.completed_at is not None
    assert complete.updated_at >= complete.created_at
    assert journal.register(event()) == complete
    assert journal.list_incomplete() == []
    with pytest.raises(InvalidTransition):
        journal.claim("evt-1")


def test_invalid_transition_or_claim_cannot_change_progress(journal):
    journal.register(event())
    with pytest.raises(InvalidTransition):
        journal.claim("missing")
    with pytest.raises(InvalidTransition):
        journal.record_step(Claim("evt-1", uuid4()), Step.PREFLIGHT)
    claim = journal.claim("evt-1")
    with pytest.raises(InvalidTransition):
        journal.claim("evt-1")
    with pytest.raises(InvalidTransition):
        journal.complete(claim)
    with pytest.raises(InvalidTransition):
        journal.record_step(Claim("evt-1", uuid4()), Step.PREFLIGHT)
    assert journal.get("evt-1").current_step is Step.CLAIMED


def test_failure_classification_and_incomplete_listing(journal):
    for event_id in ("failed", "reconcile", "pending"):
        journal.register(event(event_id, "EMP-" + event_id))
    failed = journal.fail(journal.claim("failed"), FailureCode.AUTHORIZATION)
    assert failed.status is Status.FAILED
    assert failed.failure_code is FailureCode.AUTHORIZATION
    assert failed.completed_at is None and not failed.requires_reconciliation
    blocked = journal.require_reconciliation(journal.claim("reconcile"), FailureCode.VERIFICATION_FAILED)
    assert blocked.status is Status.RECONCILIATION_REQUIRED and blocked.requires_reconciliation
    assert [record.event_id for record in journal.list_incomplete()] == ["reconcile", "pending"]
    assert len(journal.list_incomplete(limit=1)) == 1


@pytest.mark.parametrize("step,code", [
    (Step.CREATE_DISABLED, FailureCode.SERVICE_UNAVAILABLE),
    (Step.PREFLIGHT, FailureCode.AMBIGUOUS_WRITE),
])
def test_ambiguous_failure_retains_employee_slot(journal, step, code):
    journal.register(event())
    claim = journal.claim("evt-1")
    journal.record_step(claim, step)
    result = journal.fail(claim, code)
    assert result.status is Status.RECONCILIATION_REQUIRED
    assert result.current_step is step and result.failure_code is code
    journal.register(event("next"))
    with pytest.raises(EmployeeBusy):
        journal.claim("next")


def race(operation, inputs):
    barrier = Barrier(len(inputs))

    def compete(value):
        barrier.wait(timeout=10)
        try:
            return operation(value)
        except (InvalidTransition, EmployeeBusy) as error:
            return type(error)

    with ThreadPoolExecutor(max_workers=len(inputs)) as workers:
        return list(workers.map(compete, inputs))


def test_concurrent_registration_and_same_event_claim(journal):
    registrations = race(journal.register, [event(), event()])
    assert registrations[0] == registrations[1]
    outcomes = race(journal.claim, ["evt-1", "evt-1"])
    assert sum(isinstance(item, Claim) for item in outcomes) == 1
    assert InvalidTransition in outcomes


def test_concurrent_claims_for_different_events_on_same_employee(journal):
    journal.register(event())
    journal.register(MoverEvent("evt-2", "EMP-1", "synthetic.user", "HR", "Engineering"))
    journal.register(event("unrelated", "EMP-2"))
    outcomes = race(journal.claim, ["evt-1", "evt-2"])
    assert EmployeeBusy in outcomes
    active = next(item for item in outcomes if isinstance(item, Claim))
    other = "evt-2" if active.event_id == "evt-1" else "evt-1"
    assert journal.get(other).status is Status.PENDING
    assert journal.claim("unrelated")
    journal.fail(active, FailureCode.IDENTITY_CONFLICT)
    assert journal.claim(other)


def test_crash_restart_quarantines_without_releasing_employee(journal, test_database):
    from provisioning.journal_postgres import PostgresJournal

    journal.register(event())
    claim = journal.claim("evt-1")
    progress = journal.record_step(claim, Step.REVOKE_SOURCE)
    restarted = PostgresJournal(test_database)
    with pytest.raises(InvalidTransition):
        restarted.claim("evt-1")
    with pytest.raises(InvalidTransition):
        restarted.mark_stale("evt-1", stale_before=progress.updated_at - timedelta(seconds=1))
    quarantined = restarted.mark_stale("evt-1", stale_before=datetime.now(UTC))
    assert quarantined.status is Status.RECONCILIATION_REQUIRED
    assert quarantined.failure_code is FailureCode.WORKER_STALE
    assert quarantined.current_step is Step.REVOKE_SOURCE
    with pytest.raises(InvalidTransition):
        journal.record_step(claim, Step.VERIFY_REVOCATION)
    restarted.register(event("later"))
    with pytest.raises(EmployeeBusy):
        restarted.claim("later")


def test_database_never_stores_raw_profile_or_failure_details(journal, test_database):
    import psycopg

    from provisioning.joiner import JoinerEvent

    joiner = JoinerEvent(
        "joiner", "EMP-2", "private.synthetic", "Private", "Synthetic",
        "private@example.test", "HR", "JOINER",
    )
    journal.register(joiner)
    claim = journal.claim("joiner")
    with pytest.raises(ValueError):
        journal.record_step(claim, "Bearer secret-access-token")
    with pytest.raises(ValueError):
        journal.fail(claim, "client_secret=secret-access-token")
    journal.fail(claim, FailureCode.AUTHENTICATION)
    with psycopg.connect(test_database) as connection:
        raw = connection.execute("SELECT to_jsonb(events)::text FROM jml_journal.events").fetchone()[0]
    assert "private.synthetic" not in raw and "private@example.test" not in raw
    assert "secret-access-token" not in raw
    assert '"claim_token": null' in raw


def test_leaver_checkpoint_commit_order_and_completion(journal, test_database):
    from provisioning.journal_postgres import PostgresJournal

    journal.register(event())
    claim = journal.claim("evt-1")
    reader = PostgresJournal(test_database)
    with pytest.raises(InvalidTransition):
        journal.record_checkpoint(claim, Step.DISABLE_ACCOUNT, Phase.INTENT, user_id="kc-1")
    assert not reader.checkpoints("evt-1")
    assert reader.get("evt-1").keycloak_user_id is None

    sequence = [
        (Step.PREFLIGHT, Phase.VERIFIED),
        (Step.DISABLE_ACCOUNT, Phase.PLANNED),
        (Step.DISABLE_ACCOUNT, Phase.INTENT),
        (Step.DISABLE_ACCOUNT, Phase.ACKNOWLEDGED),
        (Step.VERIFY_DISABLED, Phase.VERIFIED),
        (Step.REQUEST_LOGOUT, Phase.PLANNED),
        (Step.REQUEST_LOGOUT, Phase.INTENT),
        (Step.REQUEST_LOGOUT, Phase.ACKNOWLEDGED),
        (Step.VERIFY_FINAL, Phase.VERIFIED),
    ]
    for step, phase in sequence:
        entry = journal.record_checkpoint(claim, step, phase, user_id="kc-1")
        assert reader.checkpoints("evt-1")[-1] == entry
        summary = reader.get("evt-1")
        assert summary.current_step is step and summary.updated_at == entry.recorded_at
        assert summary.keycloak_user_id == "kc-1"
        if phase is Phase.PLANNED and step is Step.DISABLE_ACCOUNT:
            assert not summary.write_intent
            with pytest.raises(InvalidTransition):
                journal.record_checkpoint(claim, step, Phase.INTENT, user_id="wrong")
        if phase is Phase.INTENT:
            assert summary.write_intent
    assert [(entry.step, entry.phase) for entry in reader.checkpoints("evt-1")] == sequence
    assert journal.complete(claim).status is Status.COMPLETED
    with pytest.raises(InvalidTransition):
        journal.record_checkpoint(claim, Step.VERIFY_FINAL, Phase.VERIFIED, user_id="kc-1")


def test_interrupted_leaver_intent_survives_and_keeps_employee_slot(journal, test_database):
    from provisioning.journal_postgres import PostgresJournal

    journal.register(event())
    claim = journal.claim("evt-1")
    journal.record_checkpoint(claim, Step.PREFLIGHT, Phase.VERIFIED, user_id="kc-1")
    journal.record_checkpoint(claim, Step.DISABLE_ACCOUNT, Phase.PLANNED, user_id="kc-1")
    journal.record_checkpoint(claim, Step.DISABLE_ACCOUNT, Phase.INTENT, user_id="kc-1")
    restarted = PostgresJournal(test_database)
    assert restarted.checkpoints("evt-1")[-1].phase is Phase.INTENT
    assert restarted.get("evt-1").status is Status.IN_PROGRESS
    with pytest.raises(InvalidTransition):
        restarted.claim("evt-1")
    restarted.register(event("next"))
    with pytest.raises(EmployeeBusy):
        restarted.claim("next")
    assert restarted.mark_stale("evt-1", stale_before=datetime.now(UTC)).requires_reconciliation
    with pytest.raises(InvalidTransition):
        journal.record_checkpoint(claim, Step.DISABLE_ACCOUNT, Phase.ACKNOWLEDGED, user_id="kc-1")
    assert restarted.checkpoints("evt-1")[-1].phase is Phase.INTENT
    with pytest.raises(EmployeeBusy):
        restarted.claim("next")
