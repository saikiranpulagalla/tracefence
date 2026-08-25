"""Frozen Phase 2C-A DDL additions owned by migration v24."""

V24_ACTION_AUTHORITY_BINDING_DDL = """
CREATE TABLE action_authority_bindings (
    run_id VARCHAR(36) NOT NULL,
    action_id VARCHAR(36) NOT NULL,
    scope_id VARCHAR(36) NOT NULL,
    bound_version INTEGER NOT NULL,
    CONSTRAINT pk_action_authority_binding PRIMARY KEY (action_id, scope_id),
    CONSTRAINT fk_action_authority_binding_action
      FOREIGN KEY(run_id, action_id) REFERENCES action_attempts (run_id, id)
      ON DELETE CASCADE,
    CONSTRAINT fk_action_authority_binding_scope
      FOREIGN KEY(run_id, scope_id) REFERENCES control_scopes (run_id, id)
      ON DELETE RESTRICT,
    CONSTRAINT ck_action_authority_binding_version CHECK (bound_version >= 1)
);
"""
V24_ACTION_AUTHORITY_BINDING_INDEX_DDL = (
    "CREATE INDEX ix_action_authority_bindings_scope "
    "ON action_authority_bindings (scope_id)",
)

V24_SCHEMA_INTEGRITY_TRIGGER_DDL = {
    "trg_action_attempts_lifecycle_identity_immutable": """
        CREATE TRIGGER IF NOT EXISTS trg_action_attempts_lifecycle_identity_immutable
        BEFORE UPDATE OF lifecycle_version, worker_instance_id, worker_incarnation,
          authority_vector_digest, authorization_proof_revision ON action_attempts
        WHEN NEW.lifecycle_version IS NOT OLD.lifecycle_version
          OR NEW.worker_instance_id IS NOT OLD.worker_instance_id
          OR NEW.worker_incarnation IS NOT OLD.worker_incarnation
          OR NEW.authority_vector_digest IS NOT OLD.authority_vector_digest
          OR NEW.authorization_proof_revision IS NOT OLD.authorization_proof_revision
        BEGIN
            SELECT RAISE(ABORT, 'ACTION_LIFECYCLE_IDENTITY_IMMUTABLE');
        END
    """,
    "trg_action_attempts_lifecycle_state_transition": """
        CREATE TRIGGER IF NOT EXISTS trg_action_attempts_lifecycle_state_transition
        BEFORE UPDATE OF execution_state ON action_attempts
        WHEN NEW.execution_state IS NOT OLD.execution_state
         AND NOT (
            (OLD.execution_state = 'AUTHORIZED' AND NEW.execution_state IN ('DISPATCHED','FAILED','STALE'))
            OR (OLD.execution_state = 'DISPATCHED' AND NEW.execution_state IN ('SUCCEEDED','FAILED','STALE','AMBIGUOUS'))
            OR (OLD.execution_state = 'AMBIGUOUS' AND NEW.execution_state IN ('SUCCEEDED','FAILED','STALE'))
         )
        BEGIN
            SELECT RAISE(ABORT, 'ACTION_LIFECYCLE_STATE_TRANSITION_INVALID');
        END
    """,
    "trg_action_attempts_v2_worker_binding": """
        CREATE TRIGGER IF NOT EXISTS trg_action_attempts_v2_worker_binding
        BEFORE INSERT ON action_attempts
        WHEN NEW.lifecycle_version = 1
         AND (SELECT execution_protocol_version FROM runs WHERE id = NEW.run_id) = 2
         AND NOT EXISTS (
            SELECT 1 FROM worker_instances
            WHERE id = NEW.worker_instance_id
              AND node_id = NEW.node_id
              AND incarnation = NEW.worker_incarnation
         )
        BEGIN
            SELECT RAISE(ABORT, 'ACTION_V2_WORKER_BINDING_INVALID');
        END
    """,
    "trg_action_authority_bindings_immutable": """
        CREATE TRIGGER IF NOT EXISTS trg_action_authority_bindings_immutable
        BEFORE UPDATE ON action_authority_bindings
        BEGIN
            SELECT RAISE(ABORT, 'ACTION_AUTHORITY_BINDING_IMMUTABLE');
        END
    """,
}
