BEGIN;

CREATE SCHEMA jml_journal;

CREATE TABLE jml_journal.events (
    event_id text PRIMARY KEY CHECK (event_id <> ''),
    event_type text NOT NULL CHECK (event_type IN ('JOINER', 'MOVER', 'LEAVER')),
    employee_id text NOT NULL CHECK (employee_id <> ''),
    event_fingerprint text NOT NULL CHECK (event_fingerprint ~ '^[0-9a-f]{64}$'),
    keycloak_user_id text CHECK (keycloak_user_id <> ''),
    status text NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'IN_PROGRESS', 'COMPLETED', 'FAILED', 'RECONCILIATION_REQUIRED')),
    current_step text NOT NULL DEFAULT 'REGISTERED' CHECK (current_step IN (
        'REGISTERED', 'CLAIMED', 'PREFLIGHT', 'CREATE_DISABLED', 'VERIFY_STAGING',
        'ADD_MANAGED', 'ASSIGN_DEPARTMENT', 'REMOVE_STAGING', 'REVOKE_SOURCE',
        'VERIFY_REVOCATION', 'DISABLE_ACCOUNT', 'VERIFY_DISABLED', 'REQUEST_LOGOUT',
        'REVOKE_DEPARTMENT', 'VERIFY_FINAL'
    )),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    completed_at timestamptz,
    failure_code text CHECK (failure_code IN (
        'AUTHENTICATION', 'AUTHORIZATION', 'IDENTITY_CONFLICT', 'INVALID_STATE',
        'SEARCH_VISIBILITY', 'SERVICE_UNAVAILABLE', 'AMBIGUOUS_WRITE',
        'VERIFICATION_FAILED', 'WORKER_STALE'
    )),
    requires_reconciliation boolean NOT NULL DEFAULT false,
    write_intent boolean NOT NULL DEFAULT false,
    claim_token uuid,
    CHECK ((status = 'IN_PROGRESS') = (claim_token IS NOT NULL)),
    CHECK ((status = 'COMPLETED') = (completed_at IS NOT NULL)),
    CHECK (status <> 'COMPLETED' OR (keycloak_user_id IS NOT NULL AND current_step = 'VERIFY_FINAL')),
    CHECK ((status IN ('FAILED', 'RECONCILIATION_REQUIRED')) = (failure_code IS NOT NULL)),
    CHECK ((status = 'RECONCILIATION_REQUIRED') = requires_reconciliation),
    CHECK (status <> 'FAILED' OR NOT write_intent)
);

CREATE UNIQUE INDEX jml_one_active_event_per_employee
    ON jml_journal.events (employee_id)
    WHERE status IN ('IN_PROGRESS', 'RECONCILIATION_REQUIRED');

CREATE INDEX jml_incomplete_events
    ON jml_journal.events (created_at, event_id)
    WHERE status IN ('PENDING', 'IN_PROGRESS', 'RECONCILIATION_REQUIRED');

COMMIT;
