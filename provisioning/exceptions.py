"""Sanitized failure types for the provisioning client."""


class KeycloakError(Exception):
    """Base class for provisioning API failures."""


class AuthenticationError(KeycloakError):
    """Client authentication or an authenticated request was rejected."""


class AuthorizationDenied(KeycloakError):
    """Keycloak denied the operation."""


class ResourceNotFound(KeycloakError):
    """A requested resource could not be found."""


class SearchNoMatch(ResourceNotFound):
    """A completed search found no matching record."""


class AmbiguousIdentity(KeycloakError):
    """More than one result matched a lookup key."""


class SearchVisibilityUnverified(KeycloakError):
    """Search results cannot establish absence or uniqueness."""


class InvalidRequest(KeycloakError):
    """Input failed local validation or Keycloak rejected the request."""


class ConflictError(KeycloakError):
    """Keycloak reported a conflict with existing state."""


class ServiceUnavailable(KeycloakError):
    """A transport failure, throttling, or a server error blocked the request."""


class UnexpectedResponse(KeycloakError):
    """The response did not satisfy the endpoint contract."""


class MalformedJSON(UnexpectedResponse):
    """The endpoint returned invalid JSON."""
