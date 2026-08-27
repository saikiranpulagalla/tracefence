"""Frozen Phase 2C-C1 DDL additions owned by migration v25."""

V25_EXTERNAL_OPERATION_BINDING_DDL = """
CREATE TABLE action_external_operation_bindings (
    run_id VARCHAR(36) NOT NULL,
    action_id VARCHAR(36) NOT NULL,
    provider_adapter_id VARCHAR(100) NOT NULL,
    provider_config_ref VARCHAR(160) NOT NULL,
    provider_scope_ref VARCHAR(160) NOT NULL,
    tool_reconciliation_version VARCHAR(64) NOT NULL,
    operation_key VARCHAR(160) NOT NULL,
    provider_handle VARCHAR(200),
    created_at DATETIME NOT NULL,
    provider_handle_bound_at DATETIME,
    CONSTRAINT pk_action_external_operation_binding PRIMARY KEY (action_id),
    CONSTRAINT uq_action_external_operation_binding_run_action UNIQUE (run_id, action_id),
    CONSTRAINT uq_action_external_operation_binding_provider_key UNIQUE (provider_adapter_id, provider_config_ref, provider_scope_ref, operation_key),
    CONSTRAINT fk_action_external_operation_binding_action FOREIGN KEY(run_id, action_id)
      REFERENCES action_attempts (run_id, id) ON DELETE CASCADE,
    CONSTRAINT ck_action_external_operation_binding_handle_shape CHECK
      ((provider_handle IS NULL AND provider_handle_bound_at IS NULL) OR
       (provider_handle IS NOT NULL AND provider_handle_bound_at IS NOT NULL))
);
"""

V25_RECONCILIATION_EVIDENCE_DDL = """
CREATE TABLE action_reconciliation_evidence (
    id VARCHAR(36) NOT NULL,
    run_id VARCHAR(36) NOT NULL,
    action_id VARCHAR(36) NOT NULL,
    observation_kind VARCHAR(24) NOT NULL,
    outcome_class VARCHAR(24) NOT NULL,
    payload_json JSON NOT NULL,
    payload_digest VARCHAR(64) NOT NULL,
    provider_evidence_ref VARCHAR(240),
    provider_evidence_digest VARCHAR(64),
    evidence_digest VARCHAR(64) NOT NULL,
    observed_at DATETIME NOT NULL,
    recorded_at DATETIME NOT NULL,
    CONSTRAINT pk_action_reconciliation_evidence PRIMARY KEY (id),
    CONSTRAINT uq_action_reconciliation_evidence_digest UNIQUE (action_id, evidence_digest),
    CONSTRAINT fk_action_reconciliation_evidence_binding FOREIGN KEY(run_id, action_id)
      REFERENCES action_external_operation_bindings (run_id, action_id) ON DELETE CASCADE,
    CONSTRAINT ck_action_reconciliation_evidence_kind CHECK
      (observation_kind IN ('SUCCEEDED','FAILED','NONEXECUTION','CONFLICT')),
    CONSTRAINT ck_action_reconciliation_evidence_outcome CHECK
      (outcome_class IN ('SUCCESS','FAILURE','NONEXECUTED','CONFLICT')),
    CONSTRAINT ck_action_reconciliation_evidence_shape CHECK
      ((observation_kind = 'SUCCEEDED' AND outcome_class = 'SUCCESS') OR
       (observation_kind = 'FAILED' AND outcome_class = 'FAILURE') OR
       (observation_kind = 'NONEXECUTION' AND outcome_class = 'NONEXECUTED') OR
       (observation_kind = 'CONFLICT' AND outcome_class = 'CONFLICT')),
    CONSTRAINT ck_action_reconciliation_evidence_provider_ref_shape CHECK
      ((provider_evidence_ref IS NULL AND provider_evidence_digest IS NULL) OR
       (provider_evidence_ref IS NOT NULL AND provider_evidence_digest IS NOT NULL))
);
"""

V25_RECONCILIATION_INDEX_DDL = (
    "CREATE INDEX ix_action_reconciliation_evidence_action ON action_reconciliation_evidence (action_id)",
)

V25_SCHEMA_INTEGRITY_TRIGGER_DDL = {
    "trg_action_external_operation_binding_pre_dispatch": """
        CREATE TRIGGER IF NOT EXISTS trg_action_external_operation_binding_pre_dispatch
        BEFORE INSERT ON action_external_operation_bindings
        WHEN NOT EXISTS (
            SELECT 1 FROM action_attempts
            WHERE id = NEW.action_id AND run_id = NEW.run_id
              AND lifecycle_version = 1 AND execution_state = 'AUTHORIZED'
        )
        BEGIN
            SELECT RAISE(ABORT, 'ACTION_EXTERNAL_BINDING_MUST_PRECEDE_DISPATCH');
        END
    """,
    "trg_action_external_operation_binding_immutable": """
        CREATE TRIGGER IF NOT EXISTS trg_action_external_operation_binding_immutable
        BEFORE UPDATE ON action_external_operation_bindings
        WHEN NEW.run_id IS NOT OLD.run_id
          OR NEW.action_id IS NOT OLD.action_id
          OR NEW.provider_adapter_id IS NOT OLD.provider_adapter_id
          OR NEW.provider_config_ref IS NOT OLD.provider_config_ref
          OR NEW.provider_scope_ref IS NOT OLD.provider_scope_ref
          OR NEW.tool_reconciliation_version IS NOT OLD.tool_reconciliation_version
          OR NEW.operation_key IS NOT OLD.operation_key
          OR (OLD.provider_handle IS NOT NULL AND
              (NEW.provider_handle IS NOT OLD.provider_handle OR
               NEW.provider_handle_bound_at IS NOT OLD.provider_handle_bound_at))
          OR (OLD.provider_handle IS NULL AND NEW.provider_handle IS NULL)
          OR (OLD.provider_handle IS NULL AND NEW.provider_handle IS NOT NULL
              AND NEW.provider_handle_bound_at IS NULL)
        BEGIN
            SELECT RAISE(ABORT, 'ACTION_EXTERNAL_BINDING_IMMUTABLE');
        END
    """,
    "trg_action_reconciliation_evidence_immutable": """
        CREATE TRIGGER IF NOT EXISTS trg_action_reconciliation_evidence_immutable
        BEFORE UPDATE ON action_reconciliation_evidence
        BEGIN
            SELECT RAISE(ABORT, 'ACTION_RECONCILIATION_EVIDENCE_IMMUTABLE');
        END
    """,
}
