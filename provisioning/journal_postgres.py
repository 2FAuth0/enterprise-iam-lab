"""PostgreSQL repository for JML event state. It performs no Keycloak calls."""

import os
from contextlib import contextmanager
from datetime import datetime
from uuid import uuid4

import psycopg
from psycopg import IsolationLevel
from psycopg.errors import UniqueViolation
from psycopg.rows import dict_row

from .joiner import _valid_text
from .journal import (
    WRITE_STEPS, Checkpoint, Claim, EmployeeBusy, EventConflict, EventRecord, FailureCode,
    InvalidTransition, JMLEvent, JournalUnavailable, Phase, Status, Step, event_fingerprint,
)

_TABLE = "jml_journal.events"
_COLUMNS = """
    event_id, event_type, employee_id, event_fingerprint, keycloak_user_id,
    status, current_step, created_at, updated_at, completed_at, failure_code,
    requires_reconciliation, write_intent
"""
_OWNED = "event_id = %s AND status = 'IN_PROGRESS' AND claim_token = %s"
_CHECKPOINTS = "jml_journal.checkpoints"
_NEXT_CHECKPOINT = {
    None: {(Step.PREFLIGHT, Phase.VERIFIED)},
    (Step.PREFLIGHT, Phase.VERIFIED): {
        (Step.DISABLE_ACCOUNT, Phase.PLANNED), (Step.VERIFY_DISABLED, Phase.VERIFIED),
    },
    (Step.DISABLE_ACCOUNT, Phase.ACKNOWLEDGED): {(Step.VERIFY_DISABLED, Phase.VERIFIED)},
    (Step.VERIFY_DISABLED, Phase.VERIFIED): {(Step.REQUEST_LOGOUT, Phase.PLANNED)},
    (Step.REQUEST_LOGOUT, Phase.ACKNOWLEDGED): {
        (Step.REVOKE_DEPARTMENT, Phase.PLANNED), (Step.VERIFY_FINAL, Phase.VERIFIED),
    },
    (Step.REQUEST_LOGOUT, Phase.REJECTED): {
        (Step.REVOKE_DEPARTMENT, Phase.PLANNED), (Step.VERIFY_FINAL, Phase.VERIFIED),
    },
    (Step.REVOKE_DEPARTMENT, Phase.ACKNOWLEDGED): {(Step.VERIFY_FINAL, Phase.VERIFIED)},
}
for _step in (Step.DISABLE_ACCOUNT, Step.REQUEST_LOGOUT, Step.REVOKE_DEPARTMENT):
    _NEXT_CHECKPOINT[_step, Phase.PLANNED] = {(_step, Phase.INTENT)}
    _NEXT_CHECKPOINT[_step, Phase.INTENT] = {
        (_step, Phase.ACKNOWLEDGED), (_step, Phase.REJECTED), (_step, Phase.AMBIGUOUS),
    }


def _record(row: dict) -> EventRecord:
    row["status"] = Status(row["status"])
    row["current_step"] = Step(row["current_step"])
    if row["failure_code"] is not None:
        row["failure_code"] = FailureCode(row["failure_code"])
    return EventRecord(**row)


def _identifier(value: str) -> str:
    if not _valid_text(value):
        raise ValueError("Journal identifiers must be nonempty text without surrounding whitespace or control characters.")
    return value


class PostgresJournal:
    """Use one short transaction per call. Commit write intent before a REST write."""

    def __init__(self, dsn: str) -> None:
        if not isinstance(dsn, str) or not dsn.strip():
            raise ValueError("Set JML_JOURNAL_DSN to the dedicated journal database connection string.")
        self._dsn = dsn

    @classmethod
    def from_env(cls) -> "PostgresJournal":
        return cls(os.getenv("JML_JOURNAL_DSN", ""))

    @contextmanager
    def _transaction(self):
        try:
            with psycopg.connect(self._dsn, connect_timeout=5, row_factory=dict_row) as connection:
                connection.isolation_level = IsolationLevel.READ_COMMITTED
                yield connection
            return
        except UniqueViolation as error:
            employee_busy = error.diag.constraint_name == "jml_one_active_event_per_employee"
        except psycopg.Error:
            employee_busy = False
        # Driver diagnostics can contain connection details and row values.
        if employee_busy:
            raise EmployeeBusy("Another event is in progress or requires reconciliation for this employee.")
        raise JournalUnavailable("Journal database operation failed. Inspect durable state before retrying.")

    def register(self, event: JMLEvent) -> EventRecord:
        fingerprint = event_fingerprint(event)
        with self._transaction() as db:
            row = db.execute(
                f"""
                INSERT INTO {_TABLE} (event_id, event_type, employee_id, event_fingerprint)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (event_id) DO NOTHING
                RETURNING {_COLUMNS}
                """,
                (event.event_id, event.event_type, event.employee_id, fingerprint),
            ).fetchone()
            if row is None:
                # Read in a new statement snapshot after any competing insert commits.
                row = db.execute(
                    f"SELECT {_COLUMNS} FROM {_TABLE} WHERE event_id = %s", (event.event_id,),
                ).fetchone()
                if row is None:
                    raise JournalUnavailable("Registered event disappeared before it could be read.")
                if row["event_fingerprint"] != fingerprint:
                    raise EventConflict("Event ID is already bound to a different validated event.")
            return _record(row)

    def get(self, event_id: str) -> EventRecord | None:
        with self._transaction() as db:
            row = db.execute(
                f"SELECT {_COLUMNS} FROM {_TABLE} WHERE event_id = %s", (_identifier(event_id),),
            ).fetchone()
            return _record(row) if row is not None else None

    def claim(self, event_id: str) -> Claim:
        token = uuid4()
        with self._transaction() as db:
            row = db.execute(
                f"""
                UPDATE {_TABLE}
                SET status = 'IN_PROGRESS', current_step = 'CLAIMED',
                    claim_token = %s, updated_at = clock_timestamp()
                WHERE event_id = %s AND status = 'PENDING'
                RETURNING event_id
                """,
                (token, _identifier(event_id)),
            ).fetchone()
            if row is None:
                raise InvalidTransition("Only a pending event can be claimed.")
        return Claim(event_id, token)

    def _update(self, claim: Claim, assignments: str, values: tuple = (), condition: str = "") -> EventRecord:
        if not isinstance(claim, Claim):
            raise ValueError("An active journal claim is required.")
        with self._transaction() as db:
            # SQL fragments are internal literals. All event data is bound separately.
            row = db.execute(
                f"""
                UPDATE {_TABLE}
                SET {assignments}, updated_at = clock_timestamp()
                WHERE {_OWNED} {condition}
                RETURNING {_COLUMNS}
                """,
                (*values, claim.event_id, claim.token),
            ).fetchone()
            if row is None:
                raise InvalidTransition("The event status, claim, or recorded state does not permit this operation.")
            return _record(row)

    def record_step(self, claim: Claim, step: Step) -> EventRecord:
        if not isinstance(step, Step) or step in (Step.REGISTERED, Step.CLAIMED):
            raise ValueError("Select a workflow step from the journal vocabulary.")
        return self._update(
            claim, "current_step = %s, write_intent = write_intent OR %s",
            (step, step in WRITE_STEPS),
        )

    def record_user_id(self, claim: Claim, user_id: str) -> EventRecord:
        user_id = _identifier(user_id)
        with self._transaction() as db:
            if not isinstance(claim, Claim):
                raise ValueError("An active journal claim is required.")
            row = db.execute(
                f"""
                UPDATE {_TABLE}
                SET keycloak_user_id = %s, updated_at = clock_timestamp()
                WHERE {_OWNED} AND (keycloak_user_id IS NULL OR keycloak_user_id = %s)
                RETURNING {_COLUMNS}
                """,
                (user_id, claim.event_id, claim.token, user_id),
            ).fetchone()
            if row is None:
                raise InvalidTransition("An active claim can associate only one Keycloak user ID.")
            return _record(row)

    def record_checkpoint(self, claim: Claim, step: Step, phase: Phase, *, user_id: str) -> Checkpoint:
        """Append a Leaver checkpoint and update its event summary in one transaction."""
        if not isinstance(claim, Claim) or not isinstance(step, Step) or not isinstance(phase, Phase):
            raise ValueError("A claim, journal step, and checkpoint phase are required.")
        user_id = _identifier(user_id)
        with self._transaction() as db:
            owned = db.execute(
                f"""
                SELECT event_id FROM {_TABLE}
                WHERE {_OWNED} AND event_type = 'LEAVER'
                    AND (keycloak_user_id IS NULL OR keycloak_user_id = %s)
                FOR UPDATE
                """,
                (claim.event_id, claim.token, user_id),
            ).fetchone()
            if owned is None:
                raise InvalidTransition("An active Leaver claim with the same account ID is required.")
            previous = db.execute(
                f"""
                SELECT ordinal, step, phase FROM {_CHECKPOINTS}
                WHERE event_id = %s ORDER BY ordinal DESC LIMIT 1
                """,
                (claim.event_id,),
            ).fetchone()
            previous_phase = (previous["step"], previous["phase"]) if previous else None
            if (step, phase) not in _NEXT_CHECKPOINT.get(previous_phase, ()):
                raise InvalidTransition("The recorded checkpoint does not permit this transition.")
            row = db.execute(
                f"""
                INSERT INTO {_CHECKPOINTS} (event_id, ordinal, step, phase)
                VALUES (%s, %s, %s, %s) RETURNING recorded_at
                """,
                (claim.event_id, previous["ordinal"] + 1 if previous else 1, step, phase),
            ).fetchone()
            db.execute(
                f"""
                UPDATE {_TABLE} SET keycloak_user_id = %s, current_step = %s,
                    updated_at = %s, write_intent = write_intent OR %s
                WHERE {_OWNED}
                """,
                (user_id, step, row["recorded_at"], phase is Phase.INTENT, claim.event_id, claim.token),
            )
            return Checkpoint(step, phase, row["recorded_at"])

    def checkpoints(self, event_id: str) -> list[Checkpoint]:
        with self._transaction() as db:
            rows = db.execute(
                f"""
                SELECT step, phase, recorded_at FROM {_CHECKPOINTS}
                WHERE event_id = %s ORDER BY ordinal
                """,
                (_identifier(event_id),),
            ).fetchall()
            return [Checkpoint(Step(row["step"]), Phase(row["phase"]), row["recorded_at"]) for row in rows]

    def complete(self, claim: Claim) -> EventRecord:
        return self._update(
            claim, "status = 'COMPLETED', completed_at = clock_timestamp(), claim_token = NULL",
            condition="AND keycloak_user_id IS NOT NULL AND current_step = 'VERIFY_FINAL'",
        )

    def fail(self, claim: Claim, code: FailureCode) -> EventRecord:
        """A failure after write intent always retains the employee slot."""
        return self._record_failure(claim, code, force_reconciliation=False)

    def require_reconciliation(self, claim: Claim, code: FailureCode) -> EventRecord:
        return self._record_failure(claim, code, force_reconciliation=True)

    def _record_failure(self, claim: Claim, code: FailureCode, *, force_reconciliation: bool) -> EventRecord:
        if not isinstance(code, FailureCode) or code is FailureCode.WORKER_STALE:
            raise ValueError("Select a sanitized workflow failure code from the journal vocabulary.")
        reconcile = force_reconciliation or code is FailureCode.AMBIGUOUS_WRITE
        return self._update(
            claim,
            """
            status = CASE WHEN write_intent OR %s THEN 'RECONCILIATION_REQUIRED' ELSE 'FAILED' END,
            requires_reconciliation = write_intent OR %s,
            failure_code = %s, claim_token = NULL
            """,
            (reconcile, reconcile, code),
        )

    def mark_stale(self, event_id: str, *, stale_before: datetime) -> EventRecord:
        """Quarantine an abandoned claim. Stop the worker before calling this."""
        if not isinstance(stale_before, datetime) or stale_before.utcoffset() is None:
            raise ValueError("Stale cutoff must be a timezone-aware timestamp.")
        with self._transaction() as db:
            row = db.execute(
                f"""
                UPDATE {_TABLE}
                SET status = 'RECONCILIATION_REQUIRED', requires_reconciliation = true,
                    failure_code = 'WORKER_STALE', claim_token = NULL, updated_at = clock_timestamp()
                WHERE event_id = %s AND status = 'IN_PROGRESS'
                    AND updated_at < %s AND %s <= clock_timestamp()
                RETURNING {_COLUMNS}
                """,
                (_identifier(event_id), stale_before, stale_before),
            ).fetchone()
            if row is None:
                raise InvalidTransition("Only an in-progress event older than the past cutoff can be quarantined.")
            return _record(row)

    def list_incomplete(self, *, limit: int = 100, event_type: str | None = None) -> list[EventRecord]:
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("Incomplete event limit must be between 1 and 1000.")
        if event_type not in (None, "JOINER", "MOVER", "LEAVER"):
            raise ValueError("Unknown JML event type.")
        with self._transaction() as db:
            rows = db.execute(
                f"""
                SELECT {_COLUMNS} FROM {_TABLE}
                WHERE status IN ('PENDING', 'IN_PROGRESS', 'RECONCILIATION_REQUIRED')
                    AND (%s::text IS NULL OR event_type = %s)
                ORDER BY created_at, event_id LIMIT %s
                """,
                (event_type, event_type, limit),
            ).fetchall()
            return [_record(row) for row in rows]
