"""Run a synthetic Joiner fixture in the loopback-only Northstar lab."""

import argparse
import json
import os
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx

from .exceptions import InvalidRequest, KeycloakError, UnexpectedResponse
from .joiner import InvalidJoinerEvent, JoinerConflict, JoinerEvent, JoinerFailure, JoinerOrchestrator
from .keycloak_client import KeycloakClient, _base_url, _is_loopback, _json
from .preflight import load_joiner_groups

LAB_REALM = "northstar-analytics"
LAB_CLIENT_ID = "iam-provisioning-worker"
LAB_USERNAME = re.compile(r"jml\.lab\.[a-z0-9][a-z0-9._-]*")
LAB_EMPLOYEE_ID = re.compile(r"JML-LAB-[A-Za-z0-9][A-Za-z0-9_-]*")
VISIBILITY_NOTICE = (
    "Lab scope only. The absence of visible matches is not proof of global uniqueness."
)


class _LabKeycloakClient(KeycloakClient):
    """Keep the audit flag false while allowing checked user searches in the lab."""

    def __init__(self, base_url: str, realm: str, client_id: str, client_secret: str, **kwargs: Any):
        if os.getenv("IAM_LAB_MODE") != "1":
            raise InvalidRequest("The lab client requires IAM_LAB_MODE=1.")
        base_url = _base_url(base_url)
        if not _is_loopback(httpx.URL(base_url).host):
            raise InvalidRequest("Lab Keycloak URL must use localhost or a loopback address.")
        if realm != LAB_REALM or client_id != LAB_CLIENT_ID:
            raise InvalidRequest("Lab mode requires the Northstar realm and provisioning worker client.")
        super().__init__(base_url, realm, client_id, client_secret, **kwargs)

    def _require_search_visibility(self, *, user_search: bool = False) -> None:
        if not user_search:
            super()._require_search_visibility()

    def _pages(self, path: str, **params: str) -> Iterator[dict[str, Any]]:
        if path != "/users":
            yield from super()._pages(path, **params)
            return

        count_params = {name: value for name, value in params.items() if name != "briefRepresentation"}
        count = _json(self._admin_request("GET", "/users/count", 200, params=count_params))
        if type(count) is not int or count < 0:
            raise UnexpectedResponse("Keycloak returned an invalid user search count.")

        seen = 0
        for user in super()._pages(path, **params):
            username = user.get("username")
            seen += 1
            if (
                not isinstance(username, str) or not username.strip()
                or ("username" in params and username != params["username"])
                or seen > count
            ):
                raise UnexpectedResponse("Keycloak returned an inconsistent user search result.")
            yield user
        if seen != count:
            raise UnexpectedResponse("Keycloak user search listing and count disagree.")


def load_lab_event(path: Path) -> JoinerEvent:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError):
        pass
    else:
        event = JoinerEvent.from_mapping(data)
        if not LAB_USERNAME.fullmatch(event.username):
            raise InvalidJoinerEvent("Lab username must start with jml.lab. and use lowercase synthetic characters.")
        if not LAB_EMPLOYEE_ID.fullmatch(event.employee_id):
            raise InvalidJoinerEvent("Lab employee ID must start with JML-LAB-.")
        if not event.email.rsplit("@", 1)[-1].lower().endswith(".test"):
            raise InvalidJoinerEvent("Lab email must use a .test domain.")
        return event
    raise InvalidJoinerEvent("Unable to read the lab event as a local JSON fixture.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--event", type=Path, required=True, help="Path to a local synthetic JSON event.")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true", help="Validate and print a plan without HTTP.")
    mode.add_argument("--execute", action="store_true", help="Explicitly authorize live lab writes.")
    args = parser.parse_args(argv)

    if args.execute and os.getenv("IAM_LAB_MODE") != "1":
        print("BLOCKED Live execution requires IAM_LAB_MODE=1 and --execute.")
        return 2

    try:
        event = load_lab_event(args.event)
    except InvalidJoinerEvent as error:
        print(f"BLOCKED {error}")
        return 2

    identity = f"event_id={event.event_id} username={event.username}"
    print(identity, flush=True)
    print(VISIBILITY_NOTICE, flush=True)
    if args.dry_run:
        print("DRY RUN")
        for action in JoinerOrchestrator.plan(event).actions:
            print(action)
        return 0

    try:
        staging_id, managed_id, departments = load_joiner_groups()
        with _LabKeycloakClient.from_env(
            department_groups={name: group.id for name, group in departments.items()},
        ) as client:
            expected = departments[event.department]
            group = client.get_group(expected.id)
            if (group.get("name"), group.get("path")) != (expected.name, expected.path):
                raise InvalidRequest("Department group does not match its approved name and path.")
            result = JoinerOrchestrator(
                client, staging_group_id=staging_id, managed_group_id=managed_id,
            ).run(event)
    except (ValueError, KeycloakError) as error:
        print(f"BLOCKED Lab configuration or preflight ({type(error).__name__}). {identity}")
        return 2
    except JoinerConflict as error:
        print(f"FAIL {error} {identity}")
        return 1
    except JoinerFailure as error:
        print(f"FAIL {error} {identity}")
        return 1

    print(f"PASS {result.status}. {identity}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
