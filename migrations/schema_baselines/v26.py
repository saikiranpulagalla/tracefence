"""Frozen Phase 2C-C3 DDL additions owned by migration v26."""

V26_RECOVERY_LINK_DDL = """
CREATE TABLE action_recovery_links (
    source_run_id VARCHAR(36) NOT NULL,
    source_action_id VARCHAR(36) NOT NULL,
    recovery_run_id VARCHAR(36) NOT NULL,
    recovery_action_id VARCHAR(36) NOT NULL,
    basis_evidence_id VARCHAR(36) NOT NULL,
    recovery_policy_version VARCHAR(96) NOT NULL,
    recovery_request_digest VARCHAR(64) NOT NULL,
    created_at DATETIME NOT NULL,
    CONSTRAINT pk_action_recovery_link PRIMARY KEY (source_run_id, source_action_id),
    CONSTRAINT uq_action_recovery_link_child UNIQUE (recovery_run_id, recovery_action_id),
    CONSTRAINT fk_action_recovery_link_source FOREIGN KEY(source_run_id, source_action_id)
      REFERENCES action_attempts (run_id, id) ON DELETE RESTRICT,
    CONSTRAINT fk_action_recovery_link_recovery FOREIGN KEY(recovery_run_id, recovery_action_id)
      REFERENCES action_attempts (run_id, id) ON DELETE RESTRICT,
    CONSTRAINT fk_action_recovery_link_basis FOREIGN KEY(basis_evidence_id)
      REFERENCES action_reconciliation_evidence (id) ON DELETE RESTRICT,
    CONSTRAINT ck_action_recovery_link_distinct_actions CHECK
      (source_action_id <> recovery_action_id)
);
"""

V26_SCHEMA_INTEGRITY_TRIGGER_DDL = {
    "trg_action_recovery_link_basis_matches_source": """
        CREATE TRIGGER IF NOT EXISTS trg_action_recovery_link_basis_matches_source
        BEFORE INSERT ON action_recovery_links
        WHEN NOT EXISTS (
            SELECT 1
            FROM action_reconciliation_evidence evidence
            JOIN action_external_operation_bindings binding
              ON binding.run_id = evidence.run_id AND binding.action_id = evidence.action_id
            WHERE evidence.id = NEW.basis_evidence_id
              AND evidence.run_id = NEW.source_run_id
              AND evidence.action_id = NEW.source_action_id
              AND binding.run_id = NEW.source_run_id
              AND binding.action_id = NEW.source_action_id
        )
        BEGIN
            SELECT RAISE(ABORT, 'ACTION_RECOVERY_BASIS_SOURCE_MISMATCH');
        END
    """,
    "trg_action_recovery_link_immutable": """
        CREATE TRIGGER IF NOT EXISTS trg_action_recovery_link_immutable
        BEFORE UPDATE ON action_recovery_links
        BEGIN
            SELECT RAISE(ABORT, 'ACTION_RECOVERY_LINK_IMMUTABLE');
        END
    """,
    "trg_action_recovery_link_no_delete": """
        CREATE TRIGGER IF NOT EXISTS trg_action_recovery_link_no_delete
        BEFORE DELETE ON action_recovery_links
        BEGIN
            SELECT RAISE(ABORT, 'ACTION_RECOVERY_LINK_NO_DELETE');
        END
    """,
}
