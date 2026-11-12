# Provisioning Policy
- HR employee ID is the immutable external identity identifier.
- Department is authoritative from the synthetic HR source.
- An unknown department must not receive default access.
- A Joiner must not receive privileged application roles automatically.
- Existing employees must not be duplicated when the same event is processed again.
- Department changes must remove obsolete group memberships before granting new ones.
- Terminated employees must not retain access to protected business operations.
- Every provisioning action must generate an auditable outcome.

### Idempotency and Failure Recovery

The provisioning worker must process repeated HR events without creating duplicate identities, duplicate entitlements, or unintended state changes.

Each event must have a unique identifier and idempotency key. The worker must record processing state and prevent concurrent execution of conflicting operations on the same employee.

Database transactions should protect local provisioning records. However, Keycloak API operations cannot be assumed to participate in the same atomic transaction.

Before applying changes, the worker must inspect the current identity state in Keycloak. After applying changes, it must verify the resulting state.

If a workflow is interrupted or partially completed, the worker must record the failure and support safe retries and reconciliation.

Recovery must prioritize least privilege. The worker must not automatically restore obsolete access merely to reverse a partially completed transfer.

For Joiner events, accounts should remain disabled or pending until required onboarding conditions are satisfied. For Leaver events, disabling access takes priority over noncritical cleanup.