"""Revoke-first department transfers for managed identities from trusted HR callers."""

from collections.abc import Mapping
from dataclasses import dataclass, field
from threading import Lock

from .exceptions import (
    AmbiguousIdentity, KeycloakError, SearchNoMatch, SearchVisibilityUnverified, UnexpectedResponse,
)
from .joiner import _valid_text
from .keycloak_client import DEPARTMENTS, MANAGED_GROUP_PATH, STAGING_GROUP_PATH, KeycloakClient
from .preflight import GroupExpectation


class InvalidMoverEvent(ValueError):
    """The event does not conform to the Mover schema."""


class MoverConflict(RuntimeError):
    """The identity, current state, or replay history prevents a transfer."""


class MoverFailure(RuntimeError):
    """A transfer stopped. A write attempt requires independent reconciliation."""

    def __init__(
        self, step: str, reason: str, *, reconciliation_required: bool,
        source_revoked: bool, user_id: str | None, previous_groups: tuple[str, ...],
    ) -> None:
        self.step = step
        self.reason = reason
        self.reconciliation_required = reconciliation_required
        self.source_revoked = source_revoked
        self.user_id = user_id
        self.previous_groups = previous_groups
        outcome = " Partial or unverified transition: source revocation was verified." if source_revoked else ""
        action = " Reconcile before any further write." if reconciliation_required else ""
        super().__init__(f"Mover failed during {step} ({reason}).{outcome}{action}")


@dataclass(frozen=True)
class MoverEvent:
    event_id: str
    employee_id: str = field(repr=False)
    username: str = field(repr=False)
    from_department: str
    to_department: str
    event_type: str = "MOVER"

    def __post_init__(self) -> None:
        for name in ("event_id", "employee_id", "username"):
            if not _valid_text(getattr(self, name)):
                raise InvalidMoverEvent(f"{name} must be a nonempty string without surrounding whitespace or control characters.")
        if any(char.isspace() for char in self.username):
            raise InvalidMoverEvent("username must not contain whitespace.")
        for department in (self.from_department, self.to_department):
            if not isinstance(department, str) or department not in DEPARTMENTS:
                raise InvalidMoverEvent("Both departments must be approved Northstar departments.")
        if self.from_department == self.to_department:
            raise InvalidMoverEvent("Source and destination departments must differ.")
        if not isinstance(self.event_type, str) or self.event_type != "MOVER":
            raise InvalidMoverEvent("event_type must be MOVER.")

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> "MoverEvent":
        if not isinstance(data, Mapping):
            raise InvalidMoverEvent("Mover event must be a mapping.")
        try:
            return cls(**dict(data))
        except TypeError:
            pass
        raise InvalidMoverEvent("Mover event contains missing or unexpected fields.")


@dataclass(frozen=True)
class MoverPlan:
    event_id: str
    actions: tuple[str, ...]
    status: str = field(default="dry_run", init=False)


@dataclass(frozen=True)
class MoverResult:
    event_id: str
    user_id: str = field(repr=False)
    enabled: bool
    previous_groups: tuple[str, ...]
    final_groups: tuple[str, ...]
    status: str = field(default="transferred", init=False)


class MoverOrchestrator:
    """Transfer only verified managed accounts using trusted group expectations."""

    def __init__(
        self, client: KeycloakClient, *, managed_group_id: str,
        department_groups: Mapping[str, GroupExpectation],
    ) -> None:
        groups = dict(department_groups)
        if not _valid_text(managed_group_id) or groups.keys() != DEPARTMENTS:
            raise ValueError("Configure the managed group ID and all four approved department groups.")
        for group in groups.values():
            if (
                not isinstance(group, GroupExpectation)
                or not all(_valid_text(value) for value in (group.id, group.name, group.path))
                or not group.path.startswith("/")
            ):
                raise ValueError("Each department requires a trusted group ID, name, and absolute path.")
        ids = {managed_group_id, *(group.id for group in groups.values())}
        paths = {MANAGED_GROUP_PATH, STAGING_GROUP_PATH, *(group.path for group in groups.values())}
        if len(ids) != 5 or len(paths) != 6:
            raise ValueError("Provisioning and department groups must have distinct IDs and paths.")
        self._client = client
        self._managed = GroupExpectation(managed_group_id, "Provisioning-Managed", MANAGED_GROUP_PATH)
        self._departments = groups
        self._lock = Lock()
        self._events: dict[str, tuple[MoverEvent, str | None]] = {}
        self._completed: set[str] = set()
        self._unresolved: set[tuple[str, str]] = set()

    def run(
        self, event: MoverEvent | Mapping[str, object], *, dry_run: bool = False,
        expected_user_id: str | None = None,
    ) -> MoverPlan | MoverResult:
        if not isinstance(event, MoverEvent):
            event = MoverEvent.from_mapping(event)
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
                raise MoverConflict("This event ID was already used with a different transfer or identity.")
            if event.event_id in self._completed:
                raise MoverConflict("This event ID already completed in this orchestrator instance.")
            if self._unresolved & keys:
                raise MoverConflict("A previous transfer attempt requires reconciliation.")
            return self._transfer(event, expected_user_id, keys)

    @staticmethod
    def plan(event: MoverEvent) -> MoverPlan:
        return MoverPlan(event.event_id, (
            "Live check: verify search visibility, exact identity, approved groups, and current account state.",
            f"Require /Provisioning-Managed and {event.from_department} as the only direct memberships.",
            f"Revoke {event.from_department} and verify the source is absent before granting access.",
            f"Assign {event.to_department} and verify final memberships, identity, and original enabled state.",
        ))

    def _transfer(
        self, event: MoverEvent, expected_user_id: str | None, keys: set[tuple[str, str]],
    ) -> MoverResult:
        client = self._client
        source = self._departments[event.from_department]
        destination = self._departments[event.to_department]
        managed = self._managed
        user_id = None
        previous_groups = ()
        write_started = source_revoked = False
        step = "identity lookup"
        try:
            self._require_search_visibility(expected_user_id)
            user_id = self._find_identity(event, expected_user_id)

            step = "group preflight"
            for group in (managed, *self._departments.values()):
                record = client.get_group(group.id)
                if (record.get("id"), record.get("name"), record.get("path")) != (group.id, group.name, group.path):
                    raise UnexpectedResponse("Group ID, name, or path differs from approved configuration.")
            for department, group in self._departments.items():
                if client.department_group_id(department) != group.id:
                    raise UnexpectedResponse("Approved group differs from the client department mapping.")

            step = "initial state verification"
            enabled = self._verify_identity(event, user_id)
            previous_groups = self._verify_groups(user_id, managed, source)

            step = "source revocation"
            self._unresolved.update(keys | {("user", user_id)})
            write_started = True
            client.remove_user_from_group(user_id, source.id)

            step = "revocation verification"
            self._verify_groups(user_id, managed)
            source_revoked = True
            self._verify_identity(event, user_id, enabled)

            step = "destination assignment"
            client.add_user_to_group(user_id, destination.id)

            step = "final verification"
            final_groups = self._verify_groups(user_id, managed, destination)
            self._verify_identity(event, user_id, enabled)
        except KeycloakError as error:
            reason = type(error).__name__
        else:
            self._unresolved.difference_update(keys | {("user", user_id)})
            self._completed.add(event.event_id)
            return MoverResult(event.event_id, user_id, enabled, previous_groups, final_groups)
        raise MoverFailure(
            step, reason, reconciliation_required=write_started, source_revoked=source_revoked,
            user_id=user_id, previous_groups=previous_groups,
        )

    def _require_search_visibility(self, expected_user_id: str | None) -> None:
        if not self._client.search_visibility_verified:
            raise SearchVisibilityUnverified("Mover requires verified search visibility.")

    def _find_identity(self, event: MoverEvent, expected_user_id: str | None) -> str:
        try:
            employee = self._client.find_user_by_employee_id(event.employee_id)
            username = self._client.find_user_by_username(event.username)
        except (AmbiguousIdentity, SearchNoMatch):
            pass
        else:
            user_id = employee.get("id")
            if (
                _valid_text(user_id) and username.get("id") == user_id
                and (expected_user_id is None or user_id == expected_user_id)
                and self._matches(event, employee) and self._matches(event, username)
            ):
                if ("user", user_id) in self._unresolved:
                    raise MoverConflict("A previous transfer attempt for this account requires reconciliation.")
                return user_id
            raise MoverConflict("Employee ID, username, and expected account must resolve to the same identity.")
        raise MoverConflict("Identity search found no match or an ambiguous match.")

    @staticmethod
    def _matches(event: MoverEvent, user: dict) -> bool:
        attributes = user.get("attributes")
        return (
            user.get("username") == event.username and isinstance(attributes, dict)
            and attributes.get("employee_id") == [event.employee_id]
        )

    def _verify_identity(self, event: MoverEvent, user_id: str, enabled: bool | None = None) -> bool:
        user = self._client.get_user(user_id)
        actual_enabled = user.get("enabled")
        if (
            user.get("id") != user_id or not self._matches(event, user)
            or type(actual_enabled) is not bool or (enabled is not None and actual_enabled is not enabled)
        ):
            raise UnexpectedResponse("Read-back did not match the expected identity or enabled state.")
        return actual_enabled

    def _verify_groups(self, user_id: str, *expected: GroupExpectation) -> tuple[str, ...]:
        groups = self._client.get_user_groups(user_id)
        actual = {group["id"]: group.get("path") for group in groups}
        if len(groups) != len(expected) or actual != {group.id: group.path for group in expected}:
            raise UnexpectedResponse("Direct memberships differ from the expected Mover state.")
        return tuple(sorted(actual.values()))
