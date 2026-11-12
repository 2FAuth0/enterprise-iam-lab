"""Transfer a known synthetic employee in the loopback-only Northstar lab."""

import argparse
import json
import os
from pathlib import Path

from .exceptions import InvalidRequest, KeycloakError, SearchVisibilityUnverified
from .keycloak_client import _segment
from .lab_joiner import LAB_EMPLOYEE_ID, LAB_USERNAME, _LabKeycloakClient
from .mover import InvalidMoverEvent, MoverConflict, MoverEvent, MoverFailure, MoverOrchestrator
from .preflight import load_joiner_groups


class _LabMoverOrchestrator(MoverOrchestrator):
    """Permit the scoped user searches only for a bound lab account."""

    def _require_search_visibility(self, expected_user_id: str | None) -> None:
        if (
            expected_user_id is None
            or os.getenv("IAM_LAB_MODE") != "1"
            or not isinstance(self._client, _LabKeycloakClient)
        ):
            raise SearchVisibilityUnverified("Mover lab searches require a bound lab account.")


def load_lab_event(path: Path) -> MoverEvent:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError):
        pass
    else:
        event = MoverEvent.from_mapping(data)
        if not LAB_USERNAME.fullmatch(event.username):
            raise InvalidMoverEvent("Lab username must start with jml.lab. and use lowercase synthetic characters.")
        if not LAB_EMPLOYEE_ID.fullmatch(event.employee_id):
            raise InvalidMoverEvent("Lab employee ID must start with JML-LAB-.")
        return event
    raise InvalidMoverEvent("Unable to read the lab event as a local JSON fixture.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--event", type=Path, required=True, help="Path to a local synthetic Mover JSON event.")
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
    except (InvalidMoverEvent, InvalidRequest) as error:
        print(f"BLOCKED {error}")
        return 2

    identity = f"event_id={event.event_id} username={event.username}"
    print(identity, flush=True)
    print("Lab scope only. Search results can be permission-filtered and cannot establish global uniqueness.", flush=True)
    if args.dry_run:
        print("DRY RUN")
        for action in MoverOrchestrator.plan(event).actions:
            print(action)
        return 0

    try:
        _, managed_id, departments = load_joiner_groups()
        with _LabKeycloakClient.from_env(
            department_groups={name: group.id for name, group in departments.items()},
        ) as client:
            mover = _LabMoverOrchestrator(
                client, managed_group_id=managed_id, department_groups=departments,
            )
            result = mover.run(event, expected_user_id=args.expected_user_id)
    except (ValueError, KeycloakError) as error:
        print(f"BLOCKED Lab configuration ({type(error).__name__}). {identity}")
        return 2
    except (MoverConflict, MoverFailure) as error:
        print(f"FAIL {error} {identity}")
        return 1

    print(f"PASS {result.status}. Enabled state preserved ({str(result.enabled).lower()}). {identity}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
