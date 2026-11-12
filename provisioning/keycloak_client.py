"""Restricted Keycloak Admin REST API client for Northstar provisioning."""

import math
import os
import re
import time
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from ipaddress import ip_address
from threading import Lock
from typing import Any, Self
from urllib.parse import quote, unquote

import httpx

from .exceptions import (
    AmbiguousIdentity,
    AuthenticationError,
    AuthorizationDenied,
    ConflictError,
    InvalidRequest,
    MalformedJSON,
    ResourceNotFound,
    SearchNoMatch,
    SearchVisibilityUnverified,
    ServiceUnavailable,
    UnexpectedResponse,
)

DEPARTMENTS = frozenset({"HR", "Engineering", "Finance", "Operations"})
PROFILE_FIELDS = frozenset({"firstName", "lastName", "email"})
STAGING_GROUP_PATH = "/Provisioning-Staging"
MANAGED_GROUP_PATH = "/Provisioning-Managed"
PAGE_SIZE = 100
MAX_PAGES = 10_000
BEARER_TOKEN = re.compile(r"[A-Za-z0-9._~+/-]+=*")


@dataclass(frozen=True)
class _AccessToken:
    value: str = field(repr=False)
    refresh_at: float


def _required(value: object, label: str) -> str:
    if (
        not isinstance(value, str) or not value.strip() or value.strip() != value
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise InvalidRequest(f"{label} must be a non-empty string without surrounding whitespace or control characters.")
    try:
        value.encode("utf-8")
    except UnicodeError:
        pass
    else:
        return value
    raise InvalidRequest(f"{label} contains invalid Unicode.")


def _segment(value: object, label: str) -> str:
    value = _required(value, label)
    if value in {".", ".."} or any(char in value for char in "/\\%"):
        raise InvalidRequest(f"{label} must be a single unescaped path segment.")
    return quote(value, safe="")


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ip_address(host).is_loopback
    except ValueError:
        return False


def _base_url(value: str) -> str:
    try:
        url = httpx.URL(_required(value, "Base URL"))
    except (httpx.InvalidURL, UnicodeError, ValueError):
        url = None
    if (
        url is None or not url.host or url.userinfo or url.query or url.fragment
        or (
            url.scheme != "https"
            and (url.scheme != "http" or not _is_loopback(url.host))
        )
    ):
        raise InvalidRequest("Use a Keycloak HTTPS base URL, or HTTP on loopback, without credentials, query, or fragment.")
    return str(url).rstrip("/")


def _json(response: httpx.Response) -> Any:
    try:
        return response.json()
    except (ValueError, UnicodeError, RecursionError):
        pass
    raise MalformedJSON("Keycloak returned malformed JSON.")


def _representation_id(item: object) -> str:
    if isinstance(item, dict):
        try:
            _segment(item.get("id"), "Resource ID")
            return item["id"]
        except InvalidRequest:
            pass
    raise UnexpectedResponse("Keycloak returned a representation without a valid resource ID.")


class KeycloakClient:
    """Synchronous client. Use as a context manager or call close() after use.

    search_visibility_verified is an operator assertion covering all relevant
    users, their managed employee_id attributes, and groups for this account.
    department_groups maps trusted department names to approved Keycloak IDs.
    """

    def __init__(
        self,
        base_url: str,
        realm: str,
        client_id: str,
        client_secret: str,
        *,
        timeout: float = 5.0,
        department_groups: Mapping[str, str] | None = None,
        search_visibility_verified: bool = False,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        base = _base_url(base_url)
        realm_path = _segment(realm, "Realm")
        self._client_id = _required(client_id, "OAuth client ID")
        self._client_secret = _required(client_secret, "OAuth client secret")
        if ":" in self._client_id:
            raise InvalidRequest("OAuth client ID cannot contain a colon with HTTP Basic authentication.")
        if type(timeout) not in (int, float) or not 0 < timeout < math.inf:
            raise InvalidRequest("HTTP timeout must be a positive finite number.")
        if type(search_visibility_verified) is not bool:
            raise InvalidRequest("Search visibility verification must be a boolean.")

        groups = {} if department_groups is None else dict(department_groups)
        if groups.keys() - DEPARTMENTS:
            raise InvalidRequest("Department group configuration contains an unauthorized department.")
        for group_id in groups.values():
            _segment(group_id, "Department group ID")
        if len(set(groups.values())) != len(groups):
            raise InvalidRequest("Each configured department must have a distinct group ID.")
        self._department_groups = groups
        self._search_visibility_verified = search_visibility_verified
        self._admin = f"{base}/admin/realms/{realm_path}"
        self._token_url = f"{base}/realms/{realm_path}/protocol/openid-connect/token"
        self._http = httpx.Client(
            timeout=timeout, transport=transport, trust_env=False, follow_redirects=False,
        )
        self._access_token: _AccessToken | None = None
        self._token_lock = Lock()

    @classmethod
    def from_env(
        cls,
        *,
        department_groups: Mapping[str, str] | None = None,
        search_visibility_verified: bool = False,
    ) -> Self:
        try:
            timeout = float(os.getenv("KEYCLOAK_HTTP_TIMEOUT", "5"))
        except ValueError:
            timeout = None
        if timeout is None:
            raise InvalidRequest("KEYCLOAK_HTTP_TIMEOUT must be a positive finite number.")
        return cls(
            os.getenv("KEYCLOAK_BASE_URL", ""),
            os.getenv("KEYCLOAK_REALM", ""),
            os.getenv("KEYCLOAK_CLIENT_ID", ""),
            os.getenv("KEYCLOAK_CLIENT_SECRET", ""),
            timeout=timeout,
            department_groups=department_groups,
            search_visibility_verified=search_visibility_verified,
        )

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        with self._token_lock:
            self._access_token = None
            self._http.close()

    @property
    def search_visibility_verified(self) -> bool:
        return self._search_visibility_verified

    def authenticate(self) -> None:
        """Ensure a Client Credentials token is available without exposing it."""
        self._token()

    def _send(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        try:
            return self._http.request(method, url, **kwargs)
        except httpx.TimeoutException:
            failure = "Keycloak request timed out."
        except httpx.RequestError:
            failure = "Keycloak request failed in transit."
        # Transport exceptions can retain requests with Authorization headers.
        raise ServiceUnavailable(failure)

    def _token(self, rejected: _AccessToken | None = None) -> _AccessToken:
        with self._token_lock:
            cached = self._access_token
            started = time.monotonic()
            if cached is not None and cached is not rejected and started < cached.refresh_at:
                return cached

            self._access_token = None
            response = self._send(
                "POST", self._token_url,
                auth=(self._client_id, self._client_secret),
                data={"grant_type": "client_credentials"},
            )
            if response.status_code in {400, 401}:
                raise AuthenticationError("Keycloak rejected the client credentials request.")
            self._expect(response, 200)
            body = _json(response)
            if not isinstance(body, dict):
                raise UnexpectedResponse("Keycloak returned an invalid client credentials response.")
            value = body.get("access_token")
            token_type = body.get("token_type")
            lifetime = body.get("expires_in")
            if (
                not isinstance(value, str) or not BEARER_TOKEN.fullmatch(value)
                or not isinstance(token_type, str) or token_type.lower() != "bearer"
                or type(lifetime) not in (int, float) or not 0 < lifetime < math.inf
            ):
                raise UnexpectedResponse("Keycloak returned an invalid client credentials response.")
            if time.monotonic() >= started + lifetime:
                raise AuthenticationError("The Keycloak access token expired during acquisition.")
            refresh_at = started + lifetime - min(5, lifetime / 10)
            self._access_token = _AccessToken(value, refresh_at)
            return self._access_token

    @staticmethod
    def _expect(response: httpx.Response, expected: int) -> None:
        status = response.status_code
        if status == expected:
            return
        if status == 401:
            raise AuthenticationError("Keycloak rejected authentication for the request.")
        if status == 403:
            raise AuthorizationDenied("Keycloak denied permission for the request.")
        if status == 404:
            raise ResourceNotFound("Keycloak could not find the requested resource.")
        if status in {400, 422}:
            raise InvalidRequest("Keycloak rejected the request parameters or payload.")
        if status == 409:
            raise ConflictError("The Keycloak request conflicts with existing state.")
        if status in {408, 429} or 500 <= status < 600:
            raise ServiceUnavailable(f"Keycloak could not process the request (HTTP {status}).")
        raise UnexpectedResponse(f"Keycloak returned HTTP {status}; expected {expected}.")

    def _admin_request(
        self, method: str, path: str, expected: int, **kwargs: Any,
    ) -> httpx.Response:
        token = self._token()
        url = self._admin + path
        response = self._send(method, url, headers={"Authorization": f"Bearer {token.value}"}, **kwargs)
        if response.status_code == 401:
            token = self._token(rejected=token)
            response = self._send(method, url, headers={"Authorization": f"Bearer {token.value}"}, **kwargs)
            if response.status_code == 401:
                with self._token_lock:
                    if self._access_token is token:
                        self._access_token = None
        self._expect(response, expected)
        return response

    @staticmethod
    def _user_path(user_id: str) -> str:
        return "/users/" + _segment(user_id, "User ID")

    def get_user(self, user_id: str) -> dict[str, Any]:
        response = self._admin_request("GET", self._user_path(user_id), 200)
        user = _json(response)
        if _representation_id(user) != user_id:
            raise UnexpectedResponse("Keycloak returned a different user ID.")
        return user

    def get_group(self, group_id: str) -> dict[str, Any]:
        path = "/groups/" + _segment(group_id, "Group ID")
        group = _json(self._admin_request("GET", path, 200))
        if _representation_id(group) != group_id:
            raise UnexpectedResponse("Keycloak returned a different group ID.")
        return group

    def _pages(self, path: str, **params: str) -> Iterator[dict[str, Any]]:
        offset = 0
        seen = set()
        for _ in range(MAX_PAGES):
            response = self._admin_request(
                "GET", path, 200, params={**params, "first": offset, "max": PAGE_SIZE},
            )
            page = _json(response)
            if not isinstance(page, list) or len(page) > PAGE_SIZE:
                raise UnexpectedResponse("Keycloak returned an invalid results page.")
            if not page:
                return
            for item in page:
                item_id = _representation_id(item)
                if item_id in seen:
                    raise UnexpectedResponse("Keycloak repeated a resource while paginating.")
                seen.add(item_id)
                yield item
            offset += len(page)
        raise UnexpectedResponse("Keycloak pagination exceeded its safety limit.")

    def _require_search_visibility(self, *, user_search: bool = False) -> None:
        if not self._search_visibility_verified:
            raise SearchVisibilityUnverified(
                "Verify the service account's search and attribute visibility before relying on lookups."
            )

    @staticmethod
    def _one(matches: Iterator[dict[str, Any]], label: str) -> dict[str, Any]:
        match = next(matches, None)
        if match is None:
            raise SearchNoMatch(f"No matching {label} was found.")
        if next(matches, None) is not None:
            raise AmbiguousIdentity(f"Multiple results match the requested {label}.")
        return match

    @staticmethod
    def _named_matches(
        results: Iterator[dict[str, Any]], field_name: str, name: str,
    ) -> Iterator[dict[str, Any]]:
        for item in results:
            value = item.get(field_name)
            if not isinstance(value, str) or not value.strip():
                raise UnexpectedResponse("Keycloak returned a search result with no valid name.")
            if value == name:
                yield item

    def find_user_by_username(self, username: str) -> dict[str, Any]:
        username = _required(username, "Username")
        self._require_search_visibility(user_search=True)
        users = self._pages("/users", username=username, exact="true", briefRepresentation="false")
        return self._one(self._named_matches(users, "username", username), "username")

    def find_user_by_employee_id(self, employee_id: str) -> dict[str, Any]:
        employee_id = _required(employee_id, "Employee ID")
        self._require_search_visibility(user_search=True)

        def matches() -> Iterator[dict[str, Any]]:
            # A custom-attribute search can miss a duplicate across storage providers.
            for user in self._pages("/users", briefRepresentation="false"):
                attributes = user.get("attributes", {})
                if not isinstance(attributes, dict):
                    raise UnexpectedResponse("Keycloak returned invalid user attributes.")
                if "employee_id" not in attributes:
                    continue
                values = attributes["employee_id"]
                if (
                    not isinstance(values, list) or len(values) != 1
                    or not isinstance(values[0], str) or not values[0].strip()
                    or values[0].strip() != values[0]
                ):
                    raise UnexpectedResponse("Keycloak employee_id must contain exactly one non-empty string.")
                if values[0] == employee_id:
                    yield user

        return self._one(matches(), "employee ID")

    def get_user_groups(self, user_id: str) -> list[dict[str, Any]]:
        path = self._user_path(user_id) + "/groups"
        groups = list(self._pages(path))
        count = _json(self._admin_request("GET", path + "/count", 200))
        if not isinstance(count, dict) or type(count.get("count")) is not int or count["count"] < 0:
            raise UnexpectedResponse("Keycloak returned an invalid user group count.")
        if len(groups) != count["count"]:
            raise SearchVisibilityUnverified(
                "User group listing disagrees with the membership count. Check visibility or concurrent changes."
            )
        return groups

    def find_group_by_name(self, name: str) -> dict[str, Any]:
        name = _required(name, "Group name")
        self._require_search_visibility()
        groups = self._pages("/groups", search=name, exact="true", populateHierarchy="false")
        return self._one(self._named_matches(groups, "name", name), "group name")

    def create_disabled_user(
        self,
        *,
        username: str,
        employee_id: str,
        first_name: str,
        last_name: str,
        email: str,
        enabled: bool = False,
    ) -> str:
        """Request disabled creation in staging and return the ID from Location.

        The enabled input is ignored. Verify persisted state separately.
        """
        payload = {
            "username": _required(username, "Username"),
            "attributes": {"employee_id": [_required(employee_id, "Employee ID")]},
            "firstName": _required(first_name, "First name"),
            "lastName": _required(last_name, "Last name"),
            "email": _required(email, "Email"),
            "enabled": False,
            "emailVerified": False,
            "groups": [STAGING_GROUP_PATH],
        }
        response = self._admin_request("POST", "/users", 201, json=payload)
        location = response.headers.get("location", "")
        try:
            path = httpx.URL(location).raw_path.decode("ascii")
            collection = httpx.URL(self._admin + "/users/").raw_path.decode("ascii")
            if path.startswith(collection):
                user_id = unquote(path[len(collection):], errors="strict")
                _segment(user_id, "Created user ID")
                if "?" not in path:
                    return user_id
        except (httpx.InvalidURL, UnicodeError, InvalidRequest):
            pass
        raise UnexpectedResponse("Keycloak reported creation without a usable user Location. Reconcile before retrying.")

    def update_user(self, user_id: str, changes: Mapping[str, str]) -> None:
        path = self._user_path(user_id)
        fields = dict(changes) if isinstance(changes, Mapping) else {}
        if not fields or fields.keys() - PROFILE_FIELDS:
            raise InvalidRequest("User updates are limited to firstName, lastName, and email.")
        payload = {field_name: _required(value, field_name) for field_name, value in fields.items()}
        self._admin_request("PUT", path, 204, json=payload)

    def set_user_enabled(self, user_id: str, enabled: bool) -> None:
        path = self._user_path(user_id)
        if type(enabled) is not bool:
            raise InvalidRequest("Enabled must be a boolean.")
        self._admin_request("PUT", path, 204, json={"enabled": enabled})

    def department_group_id(self, department: str) -> str:
        name = _required(department, "Department")
        if name not in self._department_groups:
            raise InvalidRequest("Department has no approved group configured.")
        return self._department_groups[name]

    def _membership(self, method: str, user_id: str, group_id: str) -> None:
        path = self._user_path(user_id) + "/groups/" + _segment(group_id, "Group ID")
        self._admin_request(method, path, 204)

    def _require_department_group(self, group_id: str) -> None:
        _segment(group_id, "Group ID")
        if group_id not in self._department_groups.values():
            raise InvalidRequest("Group ID is outside the approved department allowlist.")

    def add_user_to_group(self, user_id: str, group_id: str) -> None:
        self._require_department_group(group_id)
        self._membership("PUT", user_id, group_id)

    def remove_user_from_group(self, user_id: str, group_id: str) -> None:
        self._require_department_group(group_id)
        self._membership("DELETE", user_id, group_id)

    def add_user_to_managed_group(self, user_id: str, group_id: str) -> None:
        _segment(user_id, "User ID")
        if self.get_group(group_id).get("path") != MANAGED_GROUP_PATH:
            raise InvalidRequest("Group ID must resolve to the provisioning managed group.")
        self._membership("PUT", user_id, group_id)

    def remove_user_from_staging_group(self, user_id: str, group_id: str) -> None:
        _segment(user_id, "User ID")
        if self.get_group(group_id).get("path") != STAGING_GROUP_PATH:
            raise InvalidRequest("Group ID must resolve to the provisioning staging group.")
        self._membership("DELETE", user_id, group_id)

    def logout_user(self, user_id: str) -> None:
        self._admin_request("POST", self._user_path(user_id) + "/logout", 204)
