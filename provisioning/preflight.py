"""Read-only Joiner preflight for the Northstar Keycloak lab."""

import argparse
import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal

from .exceptions import (
    AuthenticationError, AuthorizationDenied, KeycloakError,
    SearchVisibilityUnverified, ServiceUnavailable,
)
from .keycloak_client import DEPARTMENTS, MANAGED_GROUP_PATH, STAGING_GROUP_PATH, KeycloakClient

Status = Literal["PASS", "FAIL", "BLOCKED"]


@dataclass(frozen=True)
class CheckResult:
    status: Status
    check: str
    detail: str

    def __str__(self) -> str:
        return f"{self.status} {self.check} — {self.detail}"


@dataclass(frozen=True)
class GroupExpectation:
    id: str
    name: str
    path: str


@dataclass(frozen=True)
class PreflightConfig:
    staging_group_id: str
    managed_group_id: str
    departments: Mapping[str, GroupExpectation]
    disposable_user_id: str
    disposable_username: str
    managed_fixture_id: str
    managed_fixture_group_id: str
    managed_fixture_group_path: str

    @classmethod
    def from_env(cls) -> "PreflightConfig":
        staging_id, managed_id, groups = load_joiner_groups()
        config = cls(
            staging_group_id=staging_id,
            managed_group_id=managed_id,
            departments=groups,
            disposable_user_id=_required_env("IAM_PREFLIGHT_DISPOSABLE_USER_ID"),
            disposable_username=_required_env("IAM_PREFLIGHT_DISPOSABLE_USERNAME"),
            managed_fixture_id=_required_env("IAM_TEST_MANAGED_USER_ID"),
            managed_fixture_group_id=_required_env("IAM_TEST_MANAGED_GROUP_ID"),
            managed_fixture_group_path=_required_env("IAM_TEST_MANAGED_GROUP_PATH"),
        )
        if config.disposable_user_id == config.managed_fixture_id:
            raise ValueError("The disposable Joiner and managed fixture must have different IDs.")
        return config


def _required_env(name: str) -> str:
    value = os.environ.get(name, "")
    if not value.strip() or value != value.strip():
        raise ValueError(f"Set {name} to a nonempty value without surrounding whitespace.")
    return value


def load_joiner_groups() -> tuple[str, str, dict[str, GroupExpectation]]:
    try:
        departments = json.loads(os.environ.get("IAM_PREFLIGHT_DEPARTMENT_GROUPS", ""))
    except ValueError:
        departments = None
    if not isinstance(departments, dict) or departments.keys() != DEPARTMENTS:
        raise ValueError("IAM_PREFLIGHT_DEPARTMENT_GROUPS must define HR, Engineering, Finance, and Operations.")
    groups = {}
    for department, group in departments.items():
        if (
            not isinstance(group, dict) or group.keys() != {"id", "name", "path"}
            or not all(isinstance(value, str) and value.strip() for value in group.values())
            or not group["path"].startswith("/")
        ):
            raise ValueError(f"{department} requires an approved group ID, name, and absolute path.")
        groups[department] = GroupExpectation(**group)

    staging_id = _required_env("IAM_TEST_STAGING_GROUP_ID")
    managed_id = _required_env("IAM_PREFLIGHT_MANAGED_GROUP_ID")
    ids = [staging_id, managed_id, *(group.id for group in groups.values())]
    paths = [STAGING_GROUP_PATH, MANAGED_GROUP_PATH, *(group.path for group in groups.values())]
    if len(set(ids)) != len(ids) or len(set(paths)) != len(paths):
        raise ValueError("Provisioning and department groups must have distinct IDs and paths.")
    return staging_id, managed_id, groups


def _run_check(label, verify, success, mismatch) -> CheckResult:
    try:
        matched = verify()
    except SearchVisibilityUnverified:
        return CheckResult("FAIL", label, "Membership listing disagrees with the group count.")
    except (AuthenticationError, AuthorizationDenied, ServiceUnavailable) as error:
        return CheckResult("BLOCKED", label, f"Keycloak check unavailable ({type(error).__name__}).")
    except KeycloakError as error:
        return CheckResult("FAIL", label, f"Keycloak check failed ({type(error).__name__}).")
    return CheckResult("PASS", label, success) if matched else CheckResult("FAIL", label, mismatch)


def run_preflight(client: KeycloakClient, config: PreflightConfig) -> tuple[CheckResult, ...]:
    """Check known IDs through authenticated reads and report the current search flag."""

    def matches_group(expected: GroupExpectation) -> bool:
        group = client.get_group(expected.id)
        return (group.get("id"), group.get("name"), group.get("path")) == (
            expected.id, expected.name, expected.path,
        )

    def matches_department(department: str, expected: GroupExpectation) -> bool:
        return client.department_group_id(department) == expected.id and matches_group(expected)

    def has_memberships(user_id: str, username: str, expected: set[tuple[str, str]]) -> bool:
        user = client.get_user(user_id)
        if user.get("id") != user_id or user.get("username") != username or user.get("enabled") is not False:
            return False
        groups = client.get_user_groups(user_id)
        return expected <= {(group["id"], group.get("path")) for group in groups}

    checks = [
        ("Provisioning staging group",
         lambda: matches_group(GroupExpectation(config.staging_group_id, "Provisioning-Staging", STAGING_GROUP_PATH)),
         "Expected ID, name, and path verified.", "Staging group ID, name, or path differs."),
        ("Provisioning managed group",
         lambda: matches_group(GroupExpectation(config.managed_group_id, "Provisioning-Managed", MANAGED_GROUP_PATH)),
         "Expected ID, name, and path verified.", "Managed group ID, name, or path differs."),
    ]
    for department in sorted(DEPARTMENTS):
        expected = config.departments[department]
        checks.append((
            f"{department} department group",
            lambda department=department, expected=expected: matches_department(department, expected),
            "Approved ID, name, and path verified.", "Department mapping, group name, or path differs.",
        ))
    checks.extend([
        ("Disposable Joiner",
         lambda: has_memberships(config.disposable_user_id, config.disposable_username, {
             (config.staging_group_id, STAGING_GROUP_PATH), (config.managed_group_id, MANAGED_GROUP_PATH),
         }),
         "Disabled with both staging and managed memberships.",
         "Expected disposable identity, disabled state, or provisioning membership is missing."),
        ("Managed fixture membership visibility",
         lambda: has_memberships(config.managed_fixture_id, "jml.managed.test", {
             (config.managed_fixture_group_id, config.managed_fixture_group_path),
         }),
         "Expected direct membership visible and listing agrees with count.",
         "Expected disabled managed fixture or direct membership is missing."),
    ])
    auth = _run_check(
        "Service-account authentication", lambda: client.authenticate() is None,
        "Client Credentials token acquired.", "Client Credentials authentication failed.",
    )
    results = [auth]
    if auth.status == "PASS":
        results.extend(_run_check(*check) for check in checks)
    else:
        results.extend(CheckResult("BLOCKED", label, "Service-account authentication did not pass.")
                       for label, *_ in checks)

    if client.search_visibility_verified:
        results.append(CheckResult("PASS", "Search visibility flag", "search_visibility_verified=true (operator assertion)."))
    else:
        results.append(CheckResult(
            "BLOCKED", "Search visibility flag",
            "search_visibility_verified=false. Verify realm search coverage before live Joiner creation.",
        ))
    return tuple(results)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true", help="Opt in to live read-only Keycloak calls.")
    if not parser.parse_args(argv).live:
        print("BLOCKED Live preflight requires --live.")
        return 2

    try:
        config = PreflightConfig.from_env()
        for name in ("KEYCLOAK_BASE_URL", "KEYCLOAK_REALM", "KEYCLOAK_CLIENT_ID", "KEYCLOAK_CLIENT_SECRET"):
            _required_env(name)
    except ValueError as error:
        # Configuration errors above contain only fixed messages and approved labels.
        print(f"BLOCKED Configuration — {error}")
        return 2

    try:
        with KeycloakClient.from_env(
            department_groups={name: group.id for name, group in config.departments.items()},
        ) as client:
            results = run_preflight(client, config)
    except KeycloakError as error:
        print(f"BLOCKED Client configuration — {type(error).__name__}.")
        return 2

    for result in results:
        print(result)
    if any(result.status == "FAIL" for result in results):
        return 1
    return 2 if any(result.status == "BLOCKED" for result in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
