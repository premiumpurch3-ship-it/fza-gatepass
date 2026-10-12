-- Least-privilege roles. Executed by `python -m app.cli apply-grants` (owner connection). Idempotent.
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'gatepass_app') THEN CREATE ROLE gatepass_app LOGIN; END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'gatepass_backup') THEN CREATE ROLE gatepass_backup LOGIN; END IF;
END $$;
GRANT USAGE ON SCHEMA public TO gatepass_app, gatepass_backup;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO gatepass_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO gatepass_app;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO gatepass_app;
-- Append-only business/audit tables: the application role can only INSERT and SELECT (a trigger blocks it too).
REVOKE UPDATE, DELETE, TRUNCATE ON audit_logs, audit_chain_checks, gate_pass_status_history, gate_pass_approvals, gate_pass_revisions,
                                   gate_pass_gate_events, gate_pass_verifications, returnable_transactions FROM gatepass_app;
REVOKE TRUNCATE ON ALL TABLES IN SCHEMA public FROM gatepass_app;
REVOKE DELETE ON users, gate_passes, form_versions, returnable_records, returnable_items, number_sequences FROM gatepass_app;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO gatepass_backup;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO gatepass_backup;
