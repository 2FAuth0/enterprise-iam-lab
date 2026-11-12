"""Validated event fingerprints and types for the durable JML journal."""

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import StrEnum
from uuid import UUID

from .joiner import JoinerEvent
from .leaver import LeaverEvent
from .mover import MoverEvent

type JMLEvent = JoinerEvent | MoverEvent | LeaverEvent


class JournalError(RuntimeError):
    """Base error for sanitized journal failures."""


class EventConflict(JournalError):
    """An event ID is already bound to a different payload."""


class InvalidTransition(JournalError):
    """The current status or claim does not authorize the operation."""


class EmployeeBusy(JournalError):
    """Another event owns this employee's processing slot."""


class JournalUnavailable(JournalError):
    """The database operation failed or its commit outcome is unknown."""


class Status(StrEnum):
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    RECONCILIATION_REQUIRED = "RECONCILIATION_REQUIRED"


class Step(StrEnum):
    REGISTERED = "REGISTERED"
    CLAIMED = "CLAIMED"
    PREFLIGHT = "PREFLIGHT"
    CREATE_DISABLED = "CREATE_DISABLED"
    VERIFY_STAGING = "VERIFY_STAGING"
    ADD_MANAGED = "ADD_MANAGED"
    ASSIGN_DEPARTMENT = "ASSIGN_DEPARTMENT"
    REMOVE_STAGING = "REMOVE_STAGING"
    REVOKE_SOURCE = "REVOKE_SOURCE"
    VERIFY_REVOCATION = "VERIFY_REVOCATION"
    DISABLE_ACCOUNT = "DISABLE_ACCOUNT"
    VERIFY_DISABLED = "VERIFY_DISABLED"
    REQUEST_LOGOUT = "REQUEST_LOGOUT"
    REVOKE_DEPARTMENT = "REVOKE_DEPARTMENT"
    VERIFY_FINAL = "VERIFY_FINAL"


WRITE_STEPS = frozenset({
    Step.CREATE_DISABLED, Step.ADD_MANAGED, Step.ASSIGN_DEPARTMENT, Step.REMOVE_STAGING,
    Step.REVOKE_SOURCE, Step.DISABLE_ACCOUNT, Step.REQUEST_LOGOUT, Step.REVOKE_DEPARTMENT,
})


class FailureCode(StrEnum):
    AUTHENTICATION = "AUTHENTICATION"
    AUTHORIZATION = "AUTHORIZATION"
    IDENTITY_CONFLICT = "IDENTITY_CONFLICT"
    INVALID_STATE = "INVALID_STATE"
    SEARCH_VISIBILITY = "SEARCH_VISIBILITY"
    SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"
    AMBIGUOUS_WRITE = "AMBIGUOUS_WRITE"
    VERIFICATION_FAILED = "VERIFICATION_FAILED"
    WORKER_STALE = "WORKER_STALE"


class Phase(StrEnum):
    PLANNED = "PLANNED"
    INTENT = "INTENT"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"
    AMBIGUOUS = "AMBIGUOUS"


@dataclass(frozen=True)
class Checkpoint:
    step: Step
    phase: Phase
    recorded_at: datetime


@dataclass(frozen=True)
class EventRecord:
    event_id: str
    event_type: str
    employee_id: str = field(repr=False)
    event_fingerprint: str = field(repr=False)
    keycloak_user_id: str | None = field(repr=False)
    status: Status
    current_step: Step
    created_at: datetime
    updated_at: datetime
    completed_at: datetime | None
    failure_code: FailureCode | None
    requires_reconciliation: bool
    write_intent: bool


@dataclass(frozen=True)
class Claim:
    event_id: str
    token: UUID = field(repr=False)


def event_fingerprint(event: JMLEvent) -> str:
    """Fingerprint all normalized event fields without storing the payload."""
    if type(event) not in (JoinerEvent, MoverEvent, LeaverEvent):
        raise ValueError("Register a validated Joiner, Mover, or Leaver event.")
    payload = asdict(event)
    type(event).from_mapping(payload)
    canonical = json.dumps(
        {"version": 1, "event": payload}, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    )
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()
