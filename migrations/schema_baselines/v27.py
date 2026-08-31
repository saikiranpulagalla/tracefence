"""Frozen Phase 3A-1 DDL additions owned by migration v27."""

V27_PROVIDER_EXECUTION_INTENT_DDL = """
CREATE TABLE provider_execution_intents (
    id VARCHAR(36) NOT NULL,
    run_id VARCHAR(36) NOT NULL,
    action_id VARCHAR(36) NOT NULL,
    provider_idempotency_key VARCHAR(96) NOT NULL,
    provider_dispatch_contract_version VARCHAR(64) NOT NULL,
    provider_request_json JSON NOT NULL,
    provider_request_digest VARCHAR(64) NOT NULL,
    delivery_status VARCHAR(24) NOT NULL,
    claim_token VARCHAR(36),
    claim_expires_at DATETIME,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    next_delivery_at DATETIME,
    last_error_class VARCHAR(80),
    last_attempt_at DATETIME,
    observation_attempt_count INTEGER NOT NULL DEFAULT 0,
    next_observation_at DATETIME,
    last_observation_error_class VARCHAR(80),
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    CONSTRAINT pk_provider_execution_intent PRIMARY KEY (id),
    CONSTRAINT uq_provider_execution_intent_action UNIQUE (run_id, action_id),
    CONSTRAINT uq_provider_execution_intent_idempotency_key UNIQUE (provider_idempotency_key),
    CONSTRAINT fk_provider_execution_intent_binding FOREIGN KEY(run_id, action_id)
      REFERENCES action_external_operation_bindings (run_id, action_id) ON DELETE CASCADE,
    CONSTRAINT ck_provider_execution_intent_delivery_status CHECK
      (delivery_status IN ('PENDING','CLAIMED','HANDED_OFF')),
    CONSTRAINT ck_provider_execution_intent_claim_shape CHECK
      ((delivery_status = 'CLAIMED' AND claim_token IS NOT NULL AND claim_expires_at IS NOT NULL) OR
       (delivery_status != 'CLAIMED' AND claim_token IS NULL AND claim_expires_at IS NULL)),
    CONSTRAINT ck_provider_execution_intent_attempt_count CHECK (attempt_count >= 0),
    CONSTRAINT ck_provider_execution_intent_observation_attempt_count CHECK
      (observation_attempt_count >= 0)
);
"""

V27_PROVIDER_HANDLE_UNIQUE_INDEX_DDL = """
CREATE UNIQUE INDEX IF NOT EXISTS uq_action_external_operation_binding_provider_handle
ON action_external_operation_bindings
  (provider_adapter_id, provider_config_ref, provider_scope_ref, provider_handle)
WHERE provider_handle IS NOT NULL
"""

V27_SCHEMA_INTEGRITY_TRIGGER_DDL = {
    "trg_provider_execution_intent_immutable": """
        CREATE TRIGGER IF NOT EXISTS trg_provider_execution_intent_immutable
        BEFORE UPDATE ON provider_execution_intents
        WHEN NEW.id IS NOT OLD.id
          OR NEW.run_id IS NOT OLD.run_id
          OR NEW.action_id IS NOT OLD.action_id
          OR NEW.provider_idempotency_key IS NOT OLD.provider_idempotency_key
          OR NEW.provider_dispatch_contract_version IS NOT OLD.provider_dispatch_contract_version
          OR NEW.provider_request_json IS NOT OLD.provider_request_json
          OR NEW.provider_request_digest IS NOT OLD.provider_request_digest
        BEGIN
            SELECT RAISE(ABORT, 'PROVIDER_EXECUTION_INTENT_IMMUTABLE');
        END
    """,
    "trg_provider_execution_intent_no_delete": """
        CREATE TRIGGER IF NOT EXISTS trg_provider_execution_intent_no_delete
        BEFORE DELETE ON provider_execution_intents
        BEGIN
            SELECT RAISE(ABORT, 'PROVIDER_EXECUTION_INTENT_NO_DELETE');
        END
    """,
}
