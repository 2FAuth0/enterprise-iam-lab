"""Explicit journal-backed Leaver execution and read-only recovery assessment."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .exceptions import KeycloakError
from .joiner import _valid_text
from .journal import EventRecord, FailureCode, Phase, Status, Step
from .keycloak_client import MANAGED_GROUP_PATH, KeycloakClient
from .leaver import LeaverConflict, LeaverEvent, LeaverOrchestrator

if TYPE_CHECKING:
    from .journal_postgres import PostgresJournal

_FAILURE_CODES = {
    "AuthenticationError": FailureCode.AUTHENTICATION,
    "AuthorizationDenied": FailureCode.AUTHORIZATION,
    "AmbiguousIdentity": FailureCode.IDENTITY_CONFLICT,
    "SearchNoMatch": FailureCode.IDENTITY_CONFLICT,
    "SearchVisibilityUnverified": FailureCode.SEARCH_VISIBILITY,
    "ServiceUnavailable": FailureCode.SERVICE_UNAVAILABLE,
    "UnexpectedResponse": FailureCode.VERIFICATION_FAILED,
}


class JournalLeaver:
    """Opt-in adapter. Database errors propagate and stop further remote writes."""

    def __init__(self, journal: PostgresJournal, leaver: LeaverOrchestrator) -> None:
        self._journal = journal
        self._leaver = leaver

    def run(
        self, event: LeaverEvent | Mapping[str, object], *, expected_user_id: str | None = None,
    ) -> EventRecord:
        if not isinstance(event, LeaverEvent):
            event = LeaverEvent.from_mapping(event)
        if expected_user_id is not None and not _valid_text(expected_user_id):
            raise ValueError("Expected user ID must be a nonempty string.")

        journal = self._journal
        existing = journal.register(event)
        if existing.status is not Status.PENDING:
            return existing
        claim = journal.claim(event.event_id)
        last_phase = None

        def checkpoint(step: str, phase: str, user_id: str) -> None:
            nonlocal last_phase
            recorded_phase = Phase(phase)
            journal.record_checkpoint(claim, Step(step), recorded_phase, user_id=user_id)
            last_phase = recorded_phase

        try:
            result = self._leaver.run(event, expected_user_id=expected_user_id, checkpoint=checkpoint)
        except LeaverConflict:
            return journal.fail(claim, FailureCode.IDENTITY_CONFLICT)

        if result.status == "completed" and result.final_state_verified:
            return journal.complete(claim)
        code = (
            FailureCode.AMBIGUOUS_WRITE if last_phase is Phase.AMBIGUOUS else
            _FAILURE_CODES.get(result.failure_reason, FailureCode.INVALID_STATE)
        )
        if result.reconciliation_required:
            return journal.require_reconciliation(claim, code)
        return journal.fail(claim, code)


@dataclass(frozen=True)
class RecoveryAssessment:
    event_id: str
    status: Status
    current_step: Step
    last_phase: Phase | None
    findings: tuple[str, ...]


class LeaverRecovery:
    """Inspect a recorded account by ID and employee attribute, without writes."""

    def __init__(self, journal: PostgresJournal, client: KeycloakClient, *, managed_group_id: str) -> None:
        if not _valid_text(managed_group_id):
            raise ValueError("A trusted managed group ID is required.")
        self._journal = journal
        self._client = client
        self._managed_group_id = managed_group_id

    def assess(self, *, limit: int = 100) -> list[RecoveryAssessment]:
        return [
            self._assess_record(record)
            for record in self._journal.list_incomplete(limit=limit, event_type="LEAVER")
        ]

    def _assess_record(self, record: EventRecord) -> RecoveryAssessment:
        history = self._journal.checkpoints(record.event_id)
        phases = {(entry.step, entry.phase) for entry in history}
        findings = []
        if history and history[-1].phase is Phase.INTENT:
            findings.append("The last write may or may not have reached Keycloak.")
        if history and history[-1].phase is Phase.AMBIGUOUS:
            findings.append("The last write returned an ambiguous outcome.")
        if (Step.REQUEST_LOGOUT, Phase.ACKNOWLEDGED) in phases:
            findings.append("Logout was acknowledged. Session and token outcomes remain unverified.")
        findings.extend(self._inspect_account(record, phases))
        return RecoveryAssessment(
            record.event_id, record.status, record.current_step,
            history[-1].phase if history else None, tuple(findings),
        )

    def _inspect_account(self, record: EventRecord, phases: set[tuple[Step, Phase]]) -> tuple[str, ...]:
        user_id = record.keycloak_user_id
        if user_id is None:
            return ("Account ID is unavailable. Verify identity independently before any correction.",)
        try:
            user = self._client.get_user(user_id)
            attributes = user.get("attributes")
            if (
                user.get("id") != user_id or not isinstance(attributes, dict)
                or attributes.get("employee_id") != [record.employee_id]
                or type(user.get("enabled")) is not bool
            ):
                return ("Direct read did not confirm the recorded identity and enabled state.",)
            groups = self._client.get_user_groups(user_id)
        except KeycloakError as error:
            return (f"Account or membership read blocked ({type(error).__name__}).",)

        findings = [
            "Account is currently enabled." if user["enabled"] else "Account is currently disabled.",
            "Compare the username against the original trusted event during reconciliation.",
        ]
        if user["enabled"] and (Step.VERIFY_DISABLED, Phase.VERIFIED) in phases:
            findings.append("Discrepancy: a previous checkpoint verified the account was disabled.")
        memberships = {(group["id"], group.get("path")) for group in groups}
        managed = (self._managed_group_id, MANAGED_GROUP_PATH)
        if managed not in memberships:
            findings.append("Discrepancy: managed membership is missing.")
        elif memberships != {managed}:
            findings.append("Additional direct memberships remain.")
            if (Step.VERIFY_FINAL, Phase.VERIFIED) in phases:
                findings.append("Discrepancy: final verification previously found only managed membership.")
        else:
            findings.append("Managed membership is the only direct membership observed.")
        return tuple(findings)
