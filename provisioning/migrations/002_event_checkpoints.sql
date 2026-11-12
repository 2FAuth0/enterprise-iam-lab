BEGIN;

CREATE TABLE jml_journal.checkpoints (
    event_id text NOT NULL REFERENCES jml_journal.events(event_id) ON DELETE CASCADE,
    ordinal integer NOT NULL CHECK (ordinal > 0),
    step text NOT NULL CHECK (step IN (
        'PREFLIGHT', 'DISABLE_ACCOUNT', 'VERIFY_DISABLED', 'REQUEST_LOGOUT',
        'REVOKE_DEPARTMENT', 'VERIFY_FINAL'
    )),
    phase text NOT NULL CHECK (phase IN (
        'PLANNED', 'INTENT', 'ACKNOWLEDGED', 'VERIFIED', 'REJECTED', 'AMBIGUOUS'
    )),
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (event_id, ordinal),
    UNIQUE (event_id, step, phase)
);

COMMIT;
