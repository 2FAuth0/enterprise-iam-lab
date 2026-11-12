"""Disable and offboard verified managed accounts from trusted HR events."""

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from threading import Lock
from typing import Literal

from .exceptions import (
    AuthenticationError, AuthorizationDenied, InvalidRequest, KeycloakError,
    ResourceNotFound, SearchVisibilityUnverified, UnexpectedResponse,
)
from .joiner import _valid_text
from .keycloak_client import DEPARTMENTS, MANAGED_GROUP_PATH, STAGING_GROUP_PATH, KeycloakClient
from .preflight import GroupExpectation

LogoutStatus = Literal["not_requested", "accepted", "rejected", "unknown"]
DepartmentStatus = Literal["unverified", "already_absent", "revoked"]
LeaverCheckpoint = Callable[[str, str, str], None]
_REJECTED_WRITE = (AuthenticationError, AuthorizationDenied, ResourceNotFound, InvalidRequest)


class InvalidLeaverEvent(ValueError):
    """The event does not conform to the Leaver schema."""


class LeaverConflict(RuntimeError):
    """An existing attempt prevents replay."""


@dataclass(frozen=True)
class LeaverEvent:
    event_id: str
    employee_id: str = field(repr=False)
    username: str = field(repr=False)
    event_type: str = "LEAVER"

    def __post_init__(self) -> None:
        for name in ("event_id", "employee_id", "username"):
            if not _valid_text(getattr(self, name)):
                raise InvalidLeaverEvent(f"{name} must be a nonempty string without surrounding whitespace or control characters.")
        if any(char.isspace() for char in self.username):
            raise InvalidLeaverEvent("username must not contain whitespace.")
        if not isinstance(self.event_type, str) or self.event_type != "LEAVER":
            raise InvalidLeaverEvent("event_type must be LEAVER.")

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> "LeaverEvent":
        if not isinstance(data, Mapping):
            raise InvalidLeaverEvent("Leaver event must be a mapping.")
        try:
            return cls(**dict(data))
        except TypeError:
            pass
        raise InvalidLeaverEvent("Leaver event contains missing or unexpected fields.")


@dataclass(frozen=True)
class LeaverPlan:
    event_id: str
    actions: tuple[str, ...]
    status: str = field(default="dry_run", init=False)


@dataclass(frozen=True)
class LeaverResult:
    event_id: str
    status: Literal["completed", "partial", "failed"]
    user_id: str | None = field(repr=False)
    disabled_verified: bool
    disable_changed: bool | None
    logout_status: LogoutStatus
    logout_error: str | None
    department_status: DepartmentStatus
    final_state_verified: bool
    failed_step: str | None
    failure_reason: str | None
    reconciliation_required: bool


class LeaverOrchestrator:
    def __init__(
        self, client: KeycloakClient, *, managed_group_id: str,
        department_groups: Mapping[str, GroupExpectation],
    ) -> None:
        departments = dict(department_groups)
        if not _valid_text(managed_group_id) or departments.keys() != DEPARTMENTS:
            raise ValueError("Configure the managed group ID and all four approved departments.")
        for group in departments.values():
            if (
                not isinstance(group, GroupExpectation)
                or not all(_valid_text(value) for value in (group.id, group.name, group.path))
                or not group.path.startswith("/")
            ):
                raise ValueError("Each department requires a trusted group ID, name, and absolute path.")
        ids = {managed_group_id, *(group.id for group in departments.values())}
        paths = {MANAGED_GROUP_PATH, STAGING_GROUP_PATH, *(group.path for group in departments.values())}
        if len(ids) != 5 or len(paths) != 6:
            raise ValueError("Provisioning and department groups must have distinct IDs and paths.")
        self._client = client
        self._managed = GroupExpectation(managed_group_id, "Provisioning-Managed", MANAGED_GROUP_PATH)
        self._departments = departments
        self._lock = Lock()
        self._events: dict[str, tuple[LeaverEvent, str | None]] = {}
        self._results: dict[str, LeaverResult] = {}
        self._unresolved: set[tuple[str, str]] = set()

    def run(
        self, event: LeaverEvent | Mapping[str, object], *, dry_run: bool = False,
        expected_user_id: str | None = None,
        checkpoint: LeaverCheckpoint | None = None,
    ) -> LeaverPlan | LeaverResult:
        if not isinstance(event, LeaverEvent):
            event = LeaverEvent.from_mapping(event)
        if type(dry_run) is not bool:
            raise ValueError("dry_run must be a boolean.")
        if expected_user_id is not None and not _valid_text(expected_user_id):
            raise ValueError("Expected user ID must be a nonempty string.")
        if dry_run:
            return self.plan(event)

        keys = {("employee", event.employee_id), ("username", event.username.casefold())}
        with self._lock:
            intent = (event, expected_user_id)
            if self._events.setdefault(event.event_id, intent) != intent:
                raise LeaverConflict("This event ID was already used for a different identity.")
            if event.event_id in self._results:
                if checkpoint is not None:
                    raise LeaverConflict("A historical result cannot satisfy a checkpointed execution.")
                return self._results[event.event_id]
            if self._unresolved & keys:
                raise LeaverConflict("A prior termination attempt requires reconciliation.")
            result = self._terminate(event, expected_user_id, keys, checkpoint)
            if result.status == "completed" or result.reconciliation_required:
                self._results[event.event_id] = result
            return result

    @staticmethod
    def plan(event: LeaverEvent) -> LeaverPlan:
        return LeaverPlan(event.event_id, (
            "Live check: verify exact identity, managed scope, and approved direct memberships.",
            "Disable the account if enabled and verify that it is disabled.",
            "Request session termination and record the response.",
            "Revoke any approved department membership and verify final identity and group state.",
        ))

    def _require_search_visibility(self, expected_user_id: str | None) -> None:
        if not self._client.search_visibility_verified:
            raise SearchVisibilityUnverified("Leaver requires verified search visibility.")

    @staticmethod
    def _matches(event: LeaverEvent, user: dict) -> bool:
        attributes = user.get("attributes")
        return (
            user.get("username") == event.username and isinstance(attributes, dict)
            and attributes.get("employee_id") == [event.employee_id]
        )

    def _read_enabled(self, event: LeaverEvent, user_id: str) -> bool:
        user = self._client.get_user(user_id)
        enabled = user.get("enabled")
        if user.get("id") != user_id or not self._matches(event, user) or type(enabled) is not bool:
            raise UnexpectedResponse("Direct read did not confirm the expected identity and enabled state.")
        return enabled

    def _require_disabled(self, event: LeaverEvent, user_id: str) -> None:
        if self._read_enabled(event, user_id):
            raise UnexpectedResponse("Direct read did not confirm the account is disabled.")

    def _current_department(self, user_id: str) -> GroupExpectation | None:
        groups = self._client.get_user_groups(user_id)
        paths = {group["id"]: group.get("path") for group in groups}
        if len(paths) != len(groups) or paths.pop(self._managed.id, None) != self._managed.path:
            raise UnexpectedResponse("Direct memberships did not confirm managed scope.")
        if not paths:
            return None
        for group in self._departments.values():
            if paths == {group.id: group.path}:
                return group
        raise UnexpectedResponse("Account has unexpected or conflicting direct memberships.")

    def _terminate(
        self, event: LeaverEvent, expected_user_id: str | None, keys: set[tuple[str, str]],
        checkpoint: LeaverCheckpoint | None,
    ) -> LeaverResult:
        client = self._client
        user_id = None
        write_started = disabled_verified = final_state_verified = False
        disable_changed = None
        logout_status: LogoutStatus = "not_requested"
        logout_error = None
        department_status: DepartmentStatus = "unverified"
        step = "identity lookup"
        reason = None

        def record(operation: str, phase: str) -> None:
            if checkpoint is not None:
                checkpoint(operation, phase, user_id)

        def write(operation: str, action: Callable[[], None]) -> None:
            record(operation, "PLANNED")
            record(operation, "INTENT")
            try:
                action()
            except _REJECTED_WRITE:
                record(operation, "REJECTED")
                raise
            except KeycloakError:
                record(operation, "AMBIGUOUS")
                raise
            record(operation, "ACKNOWLEDGED")

        try:
            self._require_search_visibility(expected_user_id)
            employee = client.find_user_by_employee_id(event.employee_id)
            username = client.find_user_by_username(event.username)
            matched_id = employee.get("id")
            if (
                not _valid_text(matched_id) or username.get("id") != matched_id
                or (expected_user_id is not None and matched_id != expected_user_id)
                or not self._matches(event, employee) or not self._matches(event, username)
            ):
                raise UnexpectedResponse("Searches did not confirm the same expected identity.")
            user_id = matched_id
            keys.add(("user", user_id))
            if self._unresolved & keys:
                raise LeaverConflict("A prior termination attempt for this account requires reconciliation.")

            step = "group preflight"
            for group in (self._managed, *self._departments.values()):
                actual = client.get_group(group.id)
                if (actual.get("id"), actual.get("name"), actual.get("path")) != (group.id, group.name, group.path):
                    raise UnexpectedResponse("Group differs from approved ID, name, or path.")
            for department, group in self._departments.items():
                if client.department_group_id(department) != group.id:
                    raise UnexpectedResponse("Approved group differs from the client department mapping.")

            step = "initial state verification"
            was_enabled = self._read_enabled(event, user_id)
            department = self._current_department(user_id)
            record("PREFLIGHT", "VERIFIED")

            self._unresolved.update(keys)
            write_started = True
            if was_enabled:
                step = "disable account"
                write("DISABLE_ACCOUNT", lambda: client.set_user_enabled(user_id, False))
                step = "verify disabled state"
                self._require_disabled(event, user_id)
            disable_changed = was_enabled
            disabled_verified = True
            record("VERIFY_DISABLED", "VERIFIED")

            step = "request session termination"
            try:
                write("REQUEST_LOGOUT", lambda: client.logout_user(user_id))
            except _REJECTED_WRITE as error:
                logout_status = "rejected"
                logout_error = type(error).__name__
            except KeycloakError as error:
                logout_status = "unknown"
                logout_error = type(error).__name__
                raise
            else:
                logout_status = "accepted"

            step = "verify state before department revocation"
            self._require_disabled(event, user_id)
            if self._current_department(user_id) != department:
                raise UnexpectedResponse("Direct memberships changed during termination.")

            if department is not None:
                step = "revoke department"
                write("REVOKE_DEPARTMENT", lambda: client.remove_user_from_group(user_id, department.id))

            step = "final verification"
            if self._current_department(user_id) is not None:
                raise UnexpectedResponse("Department membership remains.")
            department_status = "revoked" if department is not None else "already_absent"
            self._require_disabled(event, user_id)
            final_state_verified = True
            record("VERIFY_FINAL", "VERIFIED")
        except KeycloakError as error:
            reason = type(error).__name__
        else:
            step = "request session termination" if logout_error else None
            reason = logout_error

        if reason is None:
            self._unresolved.difference_update(keys)
            status = "completed"
        else:
            status = "partial" if disabled_verified else "failed"
        return LeaverResult(
            event_id=event.event_id,
            status=status,
            user_id=user_id,
            disabled_verified=disabled_verified,
            disable_changed=disable_changed,
            logout_status=logout_status,
            logout_error=logout_error,
            department_status=department_status,
            final_state_verified=final_state_verified,
            failed_step=step,
            failure_reason=reason,
            reconciliation_required=write_started and reason is not None,
        )
