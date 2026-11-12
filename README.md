# Enterprise IAM Lab -- Northstar Analytics

A hands-on Identity and Access Management (IAM) engineering project that simulates the identity infrastructure of a fictional enterprise, Northstar Analytics.

This project focuses on designing and implementing secure authentication, role-based authorization, multi-factor authentication (MFA), and automated identity provisioning.

This lab was built using open-source technologies and synthetic employee identities. Its purpose is to demonstrate practical IAM engineering skills, including system deployment, identity lifecycle management, security policy enforcement, troubleshooting, and automated testing.

### Technology Stack

| Technology | Purpose |
|------------|---------|
| Keycloak | Identity provider, authentication, users, groups, and roles |
| PostgreSQL | Persistent identity-provider database and JML event journal |
| Docker Compose | Containerized lab infrastructure |
| Python | OIDC testing, identity provisioning, and lifecycle automation |
| FastAPI | Authentication test harness and business applications |
| Authlib | OIDC authentication integration |
| HTTPX | Keycloak Admin REST API integration |
| pytest | Automated unit and integration testing |

### Current Implementation

#### Identity Infrastructure

A containerized Keycloak and PostgreSQL environment has been deployed for the fictional Northstar Analytics organization.

The identity environment includes:

- A dedicated `northstar-analytics` realm.
- Synthetic employee identities.
- Departmental groups for HR, Engineering, Finance, and Operations.
- Application-specific client roles and composite role inheritance.
- Confidential OIDC clients for HR, Operations, and isolated authentication testing.
- Authorization Code Flow with PKCE S256.
- Locally bound development services.
- A dedicated provisioning service account with fine-grained administrative permissions.

#### Authentication and MFA

The lab includes a custom Keycloak authentication flow supporting two authentication assurance contexts:

| Authentication Context | Assurance Level | Authentication |
|------------------------|-----------------|----------------|
| `northstar-basic` | LoA 1 | Password |
| `northstar-mfa` | LoA 2 | Password and TOTP |

Interactive testing has demonstrated:

- Successful basic OIDC authentication.
- Successful TOTP MFA authentication.
- Rejection of incorrect TOTP codes.
- Successful processing of OIDC authorization-code callbacks.
- Validation of returned authentication assurance claims against application policy.
- Enforcement of role-based access restrictions and MFA requirements.

The lab includes a dedicated localhost FastAPI authentication harness and two separate business portals.

#### OIDC Test Harness

A Python OIDC test harness has been developed to examine and validate authentication behavior.

Implemented components include:

- OIDC discovery metadata retrieval and validation.
- Cryptographically secure PKCE verifier generation.
- S256 code-challenge generation.
- Authorization-request construction.
- State and nonce generation.
- Interactive authentication with Keycloak through Authlib.
- Authentication assurance evaluation.

The dedicated OIDC test harness includes eight passing automated tests covering PKCE and authorization-request construction.

These tests validate local behavior. Interactive Keycloak authentication and MFA behavior have been verified separately through manual testing.

### Business Applications

- **HR Portal** serves fictional employee records and allows authorized HR editors to update job titles.
- **Operations Portal** serves sample metrics. Configuration changes require an Operations administrator role, verified MFA assurance, and an active approval. The approval provider remains a planned milestone, and protected changes fail closed without approval.

See the [portal run instructions](apps/README.md).

### Automated Identity Lifecycle Management

A Python provisioning service has been implemented to automate employee identity lifecycle operations against Keycloak's Admin REST API.

The system uses a dedicated `iam-provisioning-worker` service account with restricted administrative permissions. Employee lifecycle events are represented by validated synthetic HR records.

Three lifecycle operations have been implemented and successfully demonstrated against the live Keycloak environment.

**Joiner:** Creates disabled synthetic employee identities in `/Provisioning-Staging`, verifies their attributes, enrolls them into `/Provisioning-Managed`, assigns an approved department, and removes staging membership.

**Mover:** Handles department transfers by revoking the previous department membership before granting the new department membership. The workflow verifies each change and preserves the account's existing enabled state.

**Leaver:** Disables employee accounts when necessary, requests session termination, removes department memberships, and verifies the final disabled state.

A complete synthetic employee lifecycle has been demonstrated:

- Joiner: Employee created and assigned to Engineering.
- Mover: Employee transferred from Engineering to Finance.
- Leaver: Finance access revoked, logout requested, and disabled state verified.

Each workflow includes identity validation, authorization checks, and post-operation state verification.

New employee accounts remain disabled until a separate account activation and credential enrollment process is implemented.

#### Fine-Grained Provisioning Permissions

The provisioning service uses Keycloak fine-grained administrative permissions to separate employee lifecycle management from privileged identity administration.

The authorization model includes:

- `/Provisioning-Staging` for initial employee creation.
- `/Provisioning-Managed` for identities authorized for lifecycle administration.
- Approved department groups for HR, Engineering, Finance, and Operations.
- Separate IAM administration of privileged accounts and service identities.

Security testing has demonstrated that the provisioning worker can enroll an authorized staged identity into the managed group while rejecting direct and indirect enrollment attempts against a selected unauthorized identity.

The provisioning client also restricts administrative operations and handles authentication, authorization, and unexpected API responses.

Comprehensive search-visibility auditing remains deferred for the lab. Controlled synthetic demonstrations use an explicitly enabled lab mode rather than claiming production-level identity uniqueness.

#### Persistent Event Journal

A separate PostgreSQL database has been implemented to support durable identity lifecycle records and failure investigation.

Implemented capabilities include:

- Persistent JML event registration.
- Duplicate-event detection using event fingerprints.
- Employee-level concurrency controls.
- Event processing claims and status tracking.
- Administrative operation checkpoints.
- Failure classification and reconciliation states.
- Read-only recovery assessment.

The journal records operation states such as `PLANNED`, `INTENT`, `ACKNOWLEDGED`, `REJECTED`, `AMBIGUOUS`, and `VERIFIED`.

A journal-integrated Leaver adapter has been implemented and tested. Joiner and Mover journal integration remains planned.

The journal database uses a restricted PostgreSQL worker account. Database permission testing confirmed that the worker can access required records but cannot delete event history.

The persistent database, migrations, and Python journal connection have been successfully configured and verified.

### Testing and Validation

The project includes automated unit tests, integration tests, and manual security validation.

Current testing results include:

- 343 passing tests in the latest reported default offline suite.
- 12 passing isolated PostgreSQL integration tests.
- Successful live Joiner, Mover, and Leaver demonstrations.
- Successful controlled Keycloak provisioning integration tests.
- Negative authorization testing for selected unmanaged identities.
- Verification of restricted PostgreSQL database permissions.

Automated tests cover authentication behavior, identity validation, API interactions, lifecycle operations, authorization checks, state verification, and failure handling.

Live integration tests are separated from the default test suite and require explicit execution.

### Planned Features

#### Identity Lifecycle Improvements

- Integrate Joiner and Mover workflows with the persistent event journal.
- Validate journal-integrated Leaver execution against the live lab.
- Implement operator-controlled reconciliation and recovery for interrupted provisioning events.
- Define automated account activation, initial credential enrollment, and MFA registration.
- Expand privileged-account authorization and security testing.

#### IAM Operations Dashboard

Develop an administrative dashboard for monitoring identity lifecycle operations.

Planned capabilities include:

- View Joiner, Mover, and Leaver event history.
- Monitor successful, failed, and incomplete provisioning operations.
- Review events requiring reconciliation.
- Inspect administrative operation checkpoints.
- Display identity lifecycle activity and basic operational metrics.

The initial dashboard will provide read-only monitoring.

#### Reproducibility and Deployment

Improve the project's reproducibility so that the IAM environment can be deployed and tested consistently on another machine.

Planned improvements include:

- Documented prerequisites and installation instructions.
- Standardized Docker Compose deployment procedures.
- Automated Keycloak realm and client configuration where practical.
- Reproducible creation of synthetic employee identities, groups, and roles.
- Environment configuration templates without embedded credentials.
- Database initialization and migration procedures.
- Automated environment validation and smoke tests.
- A deployment guide covering setup, testing, troubleshooting, and cleanup.

The objective is to allow another developer or security engineer to recreate the Northstar Analytics IAM lab without manually reproducing every configuration decision.

### Project Scope

Northstar Analytics is a fictional enterprise created for educational and portfolio purposes.

The project uses synthetic identities and locally hosted services to demonstrate enterprise IAM engineering concepts.

It is not intended to manage real employee identities or serve as a production-ready IAM platform.

Detailed provisioning documentation is available in [provisioning/README.md](provisioning/README.md).