# Enterprise IAM Lab -- Northstar Analytics

A hands-on Identity and Access Management (IAM) engineering project that simulates the identity infrastructure of a ficitional enterprise, Northstar Analytics.

This project focuses on designing and implementing secure authentication, role-based authorization, multi-factor authentication (MFA), and automated identity provisioning.

This lab was built using open-source technologies and synthetic employee identities. Its purpose is to demostrate practical IAM engineering skills, including system deployment, identity lifecycle management, security policy enforcement, troubleshooting, and automated testing.

### Technology Stack
|Technology|Purpose|
|----------|-------|
|Keycloak  |Identity provider, authentication, users, groups, and roles|
|PostgreSQL|Presistent identity-provider database|
|Docker Compose|Containerized lab infrastucture|
|Python| OIDC testing and planned provisioning automation|

### Current Implementation

#### Identity Infrastructure
A containerized Keycloak and PostgreSQL environment has been deployed for the fictional Northstar Analytics organization.

The identity environment includes:
- a dedicated northstar-analytics realm
- Synthetic employee identities.
- Departmental groups for HR, Engineering, Finance, and Operations.
- Application-specific client roles and composite role inferitance.
- Confidential OIDC clietns for HR, Operations, and isolated authentication testings.
- Authorization Code Flow with PKCE S256
- Locally bound development services

#### Authentication and MFA
The lab includes a custom Keycloak authentication flow supporting two authentication assurance contests:
|Authentication Context|Assurance Level|Authentication|
|----------------------|---------------|--------------|
|northstar-basic|LoA 1|Password|
|northstar-mfa|LoA 2|Password and TOTP|

Interactive testing has demostrated:
- Successful basic OIDC authentication.
- Successful TOTP MFA authentication.
- Rejection of incorrect TOTP codes.
- Successful processing of OIDC authorization-code callbacks.
- Validation of returned authentication assurance claims against application policy.

The lab includes a dedicated localhost FastAPI authentication harness and two separate business portals.

#### OIDC Test Harness

A Python OIDC test harness has been developed to examine and validate authentication behavior.

Implemented components include:
- OIDC discovery metadata retrieval and validation.
- Cryptographically secure PKCE verifier generation
- S256 code-challenge generation.
- Authorization-request construction.
- State and nonce generation.
- Interactive authentication with Keycloak through Authlib.
- Authentication assurance evaluation.

The automated test suite currently includes eight passing tests covering PKCE and authorization-request construction.

These tests validate local behavior. Interactive Keycloak authentication and MFA behavior have been verified separately through manual testing.

### Business Applications

- **HR Portal** serves fictional employee records and lets HR editors update job titles.
- **Operations Portal** serves sample metrics. Configuration changes require an Operations admin role, verified MFA assurance, and an active approval. The approval provider is a student milestone.

See the [portal run instructions](apps/README.md).

### Planned Identity Lifecycle Automation

A Python provisioning service will automate identity lifecycle operations against Keycloack's Admin REST API.

**Joiner**: Create synthetic employee identities and assign appropriate initial access.

**Mover**: Recalculate access after department or role changes, revoke obsolete entitlements, and assign new authorized permissions.

**Leaver**: Disable accounts, restrict continued application access, and record termination-related actions.

The implementation will emphasize idempotency, least privilege, failure recovery, reconciliation, and auditability.