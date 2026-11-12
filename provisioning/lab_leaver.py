"""Offboard a known synthetic employee in the loopback-only Northstar lab."""

import argparse
import json
import os
from pathlib import Path

from .exceptions import InvalidRequest, KeycloakError, SearchVisibilityUnverified
from .keycloak_client import _segment
from .lab_joiner import LAB_EMPLOYEE_ID, LAB_USERNAME, _LabKeycloakClient
from .leaver import InvalidLeaverEvent, LeaverConflict, LeaverEvent, LeaverOrchestrator
from .preflight import load_joiner_groups


class _LabLeaverOrchestrator(LeaverOrchestrator):
    def _require_search_visibility(self, expected_user_id: str | None) -> None:
        if (
            expected_user_id is None
            or os.getenv("IAM_LAB_MODE") != "1"
            or not isinstance(self._client, _LabKeycloakClient)
        ):
            raise SearchVisibilityUnverified("Leaver lab searches require a bound lab account.")


def load_lab_event(path: Path) -> LeaverEvent:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError):
        pass
    else:
        event = LeaverEvent.from_mapping(data)
        if not LAB_USERNAME.fullmatch(event.username):
            raise InvalidLeaverEvent("Lab username must start with jml.lab. and use lowercase synthetic characters.")
        if not LAB_EMPLOYEE_ID.fullmatch(event.employee_id):
            raise InvalidLeaverEvent("Lab employee ID must start with JML-LAB-.")
        return event
    raise InvalidLeaverEvent("Unable to read the lab event as a local JSON fixture.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--event", type=Path, required=True, help="Path to a local synthetic Leaver JSON event.")
    parser.add_argument("--expected-user-id", required=True, help="Independently verified Keycloak user ID.")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true", help="Validate and print a plan without HTTP.")
    mode.add_argument("--execute", action="store_true", help="Explicitly authorize live lab writes.")
    args = parser.parse_args(argv)

    if args.execute and os.getenv("IAM_LAB_MODE") != "1":
        print("BLOCKED Live execution requires IAM_LAB_MODE=1 and --execute.")
        return 2

    try:
        event = load_lab_event(args.event)
        _segment(args.expected_user_id, "Expected user ID")
    except (InvalidLeaverEvent, InvalidRequest) as error:
        print(f"BLOCKED {error}")
        return 2

    identity = f"event_id={event.event_id} username={event.username}"
    print(identity, flush=True)
    if args.dry_run:
        print("DRY RUN. No termination performed.")
        for action in LeaverOrchestrator.plan(event).actions:
            print(action)
        return 0

    print("Lab scope only. Search results can be permission-filtered and cannot establish global uniqueness.", flush=True)
    try:
        _, managed_id, departments = load_joiner_groups()
        with _LabKeycloakClient.from_env(
            department_groups={name: group.id for name, group in departments.items()},
        ) as client:
            leaver = _LabLeaverOrchestrator(
                client, managed_group_id=managed_id, department_groups=departments,
            )
            result = leaver.run(event, expected_user_id=args.expected_user_id)
    except (ValueError, KeycloakError) as error:
        print(f"BLOCKED Lab configuration ({type(error).__name__}). {identity}")
        return 2
    except LeaverConflict as error:
        print(f"FAIL {error} {identity}")
        return 1

    print(
        f"{result.status.upper()} {identity} disabled_verified={str(result.disabled_verified).lower()} "
        f"logout_request={result.logout_status} department={result.department_status} "
        f"final_state_verified={str(result.final_state_verified).lower()}"
    )
    if result.failed_step is not None:
        print(f"Stopped or incomplete at {result.failed_step} ({result.failure_reason}).")
    if result.logout_error is not None:
        print(f"Logout request {result.logout_status} ({result.logout_error}).")
    if result.reconciliation_required:
        print("Reconcile actual account, session, and membership state before any further write.")
    return 0 if result.status == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
