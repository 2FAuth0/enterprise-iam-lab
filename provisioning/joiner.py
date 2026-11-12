"""Disabled Joiner workflow for events from an already trusted caller."""

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from threading import Lock

from .exceptions import AmbiguousIdentity, KeycloakError, SearchNoMatch, UnexpectedResponse
from .keycloak_client import DEPARTMENTS, MANAGED_GROUP_PATH, STAGING_GROUP_PATH, KeycloakClient

EMAIL = re.compile(r"[^@\s]+@[^@\s]+")


class InvalidJoinerEvent(ValueError):
    """The input does not conform to the Joiner event schema."""


class JoinerConflict(RuntimeError):
    """An existing or ambiguous identity blocks automatic provisioning."""


class JoinerFailure(RuntimeError):
    """A workflow step failed. Write-phase failures require reconciliation."""

    def __init__(
        self, step: str, reason: str, *, reconciliation_required: bool, user_id: str | None,
    ) -> None:
        self.step = step
        self.reason = reason
        self.reconciliation_required = reconciliation_required
        self.user_id = user_id
        action = " Reconcile before retrying." if reconciliation_required else ""
        super().__init__(f"Joiner failed during {step} ({reason}).{action}")


def _valid_text(value: object) -> bool:
    return (
        isinstance(value, str) and bool(value) and value == value.strip()
        and value.isprintable()
    )


@dataclass(frozen=True)
class JoinerEvent:
    event_id: str
    employee_id: str = field(repr=False)
    username: str = field(repr=False)
    first_name: str = field(repr=False)
    last_name: str = field(repr=False)
    email: str = field(repr=False)
    department: str
    event_type: str

    def __post_init__(self) -> None:
        for name in ("event_id", "employee_id", "username", "first_name", "last_name", "email"):
            if not _valid_text(getattr(self, name)):
                raise InvalidJoinerEvent(f"{name} must be a nonempty string without surrounding whitespace or control characters.")
        if any(char.isspace() for char in self.username):
            raise InvalidJoinerEvent("username must not contain whitespace.")
        if not EMAIL.fullmatch(self.email):
            raise InvalidJoinerEvent("email must be an address with a local part and domain.")
        if not isinstance(self.department, str) or self.department not in DEPARTMENTS:
            raise InvalidJoinerEvent("department must be HR, Engineering, Finance, or Operations.")
        if not isinstance(self.event_type, str) or self.event_type != "JOINER":
            raise InvalidJoinerEvent("event_type must be JOINER.")

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> "JoinerEvent":
        if not isinstance(data, Mapping):
            raise InvalidJoinerEvent("Joiner event must be a mapping.")
        try:
            return cls(**dict(data))
        except TypeError:
            pass
        raise InvalidJoinerEvent("Joiner event contains missing or unexpected fields.")


@dataclass(frozen=True)
class JoinerPlan:
    event_id: str
    department: str
    actions: tuple[str, ...]
    status: str = field(default="dry_run", init=False)


@dataclass(frozen=True)
class JoinerResult:
    event_id: str
    user_id: str = field(repr=False)
    status: str = field(default="provisioned_disabled", init=False)


class JoinerOrchestrator:
    """Provision only accounts created and verified in the current run.

    Group IDs and the department mapping come from trusted operator configuration.
    """

    def __init__(
        self, client: KeycloakClient, *, staging_group_id: str, managed_group_id: str,
    ) -> None:
        if (
            not _valid_text(staging_group_id) or not _valid_text(managed_group_id)
            or staging_group_id == managed_group_id
        ):
            raise ValueError("Staging and managed group IDs must be distinct nonempty strings.")
        self._client = client
        self._staging = staging_group_id
        self._managed = managed_group_id
        self._lock = Lock()
        self._unresolved: set[tuple[str, str]] = set()
        self._completed_events: set[str] = set()

    def run(
        self, event: JoinerEvent | Mapping[str, object], *, dry_run: bool = False,
    ) -> JoinerPlan | JoinerResult:
        if not isinstance(event, JoinerEvent):
            event = JoinerEvent.from_mapping(event)
        if type(dry_run) is not bool:
            raise ValueError("dry_run must be a boolean.")
        if dry_run:
            return self.plan(event)

        keys = {
            ("event", event.event_id), ("employee", event.employee_id),
            ("username", event.username.casefold()),
        }
        with self._lock:
            if event.event_id in self._completed_events:
                raise JoinerConflict("This event ID already completed in this orchestrator instance.")
            if self._unresolved & keys:
                raise JoinerConflict("A previous attempt requires reconciliation before provisioning.")
            return self._provision(event, keys)

    @staticmethod
    def plan(event: JoinerEvent) -> JoinerPlan:
        return JoinerPlan(event.event_id, event.department, (
            "Live check: verify group IDs and search for employee ID and username.",
            "If both searches complete without a match, create a disabled, unverified user in /Provisioning-Staging.",
            "Live check: read back identity and confirm staging is the only direct membership.",
            "Add /Provisioning-Managed and verify identity and exact memberships.",
            f"Assign the approved {event.department} group and verify identity and exact memberships.",
            "Remove /Provisioning-Staging and verify final memberships and disabled state.",
        ))

    def _provision(self, event: JoinerEvent, keys: set[tuple[str, str]]) -> JoinerResult:
        client = self._client
        user_id = None
        step = "group preflight"
        write_started = False
        try:
            department = client.department_group_id(event.department)
            if department in {self._staging, self._managed}:
                raise UnexpectedResponse("Department and provisioning groups must be distinct.")
            if (
                client.get_group(self._staging).get("path") != STAGING_GROUP_PATH
                or client.get_group(self._managed).get("path") != MANAGED_GROUP_PATH
            ):
                raise UnexpectedResponse("Configured provisioning group IDs have unexpected paths.")
            # Confirm the approved department ID is resolvable before creating an account.
            department_path = client.get_group(department).get("path")
            if not isinstance(department_path, str) or not department_path.startswith("/") or (
                department_path in {STAGING_GROUP_PATH, MANAGED_GROUP_PATH}
            ):
                raise UnexpectedResponse("Configured department group has an invalid path.")

            step = "identity lookup"
            identity_exists = False
            for lookup, value in (
                (client.find_user_by_employee_id, event.employee_id),
                (client.find_user_by_username, event.username),
            ):
                try:
                    lookup(value)
                except SearchNoMatch:
                    continue
                except AmbiguousIdentity:
                    raise JoinerConflict("Identity lookup is ambiguous. Reconcile before provisioning.") from None
                identity_exists = True
            if identity_exists:
                raise JoinerConflict("An employee ID or username already exists. Reconcile ownership before provisioning.")

            step = "disabled creation"
            self._unresolved.update(keys)
            write_started = True
            user_id = client.create_disabled_user(
                username=event.username, employee_id=event.employee_id,
                first_name=event.first_name, last_name=event.last_name, email=event.email,
            )

            step = "staging verification"
            self._verify(event, user_id, {self._staging: STAGING_GROUP_PATH})

            step = "managed enrollment"
            client.add_user_to_managed_group(user_id, self._managed)
            step = "managed verification"
            self._verify(event, user_id, {
                self._staging: STAGING_GROUP_PATH, self._managed: MANAGED_GROUP_PATH,
            })

            step = "department assignment"
            client.add_user_to_group(user_id, department)
            step = "department verification"
            self._verify(event, user_id, {
                self._staging: STAGING_GROUP_PATH, self._managed: MANAGED_GROUP_PATH,
                department: department_path,
            })

            step = "staging removal"
            client.remove_user_from_staging_group(user_id, self._staging)
            step = "final verification"
            self._verify(event, user_id, {
                self._managed: MANAGED_GROUP_PATH, department: department_path,
            })
        except KeycloakError as error:
            reason = type(error).__name__
        else:
            self._unresolved.difference_update(keys)
            self._completed_events.add(event.event_id)
            return JoinerResult(event.event_id, user_id)
        raise JoinerFailure(step, reason, reconciliation_required=write_started, user_id=user_id)

    def _verify(self, event: JoinerEvent, user_id: str, expected_groups: dict[str, str]) -> None:
        if not _valid_text(user_id):
            raise UnexpectedResponse("Creation did not return a usable user ID.")
        user = self._client.get_user(user_id)
        attributes = user.get("attributes")
        if (
            user.get("id") != user_id or user.get("username") != event.username
            or user.get("enabled") is not False or user.get("emailVerified") is not False
            or not isinstance(attributes, dict) or attributes.get("employee_id") != [event.employee_id]
        ):
            raise UnexpectedResponse("User read-back did not match the expected disabled identity.")
        groups = self._client.get_user_groups(user_id)
        actual_groups = {group["id"]: group.get("path") for group in groups}
        if len(groups) != len(expected_groups) or actual_groups != expected_groups:
            raise UnexpectedResponse("User read-back did not match the expected direct memberships.")
