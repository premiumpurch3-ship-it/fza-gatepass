-- FZA-GatePass-MTJ schema v1 (implements Phase 2 data model + master-prompt adjustments; see docs/CONSISTENCY.md)
CREATE EXTENSION IF NOT EXISTS citext;
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE OR REPLACE FUNCTION set_updated_at() RETURNS trigger AS $$
BEGIN NEW.updated_at := now(); RETURN NEW; END $$ LANGUAGE plpgsql;

-- ============ MASTER DATA ============
CREATE TABLE departments (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  code citext NOT NULL UNIQUE, name text NOT NULL,
  head_user_id uuid, is_active boolean NOT NULL DEFAULT true, sort_order integer NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE locations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  code citext NOT NULL UNIQUE, name text NOT NULL,
  location_type text NOT NULL DEFAULT 'EXTERNAL' CONSTRAINT ck_locations__type CHECK (location_type IN ('INTERNAL','EXTERNAL')),
  address text, city text, contact_person text, contact_phone text,
  is_active boolean NOT NULL DEFAULT true, sort_order integer NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX ix_locations__active_name ON locations (is_active, name);
CREATE TABLE gates (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  code citext NOT NULL UNIQUE, name text NOT NULL,
  location_id uuid REFERENCES locations(id), is_active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE units_of_measure (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  code citext NOT NULL UNIQUE, name text NOT NULL,
  decimal_places smallint NOT NULL DEFAULT 0 CONSTRAINT ck_uom__dp CHECK (decimal_places BETWEEN 0 AND 3),
  is_active boolean NOT NULL DEFAULT true, sort_order integer NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE lookup_lists (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  code citext NOT NULL UNIQUE, name text NOT NULL, description text, is_system boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE lookup_options (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  list_id uuid NOT NULL REFERENCES lookup_lists(id),
  value text NOT NULL CONSTRAINT ck_lookup__value CHECK (value ~ '^[A-Z0-9_]{1,40}$'),
  label text NOT NULL, sort_order integer NOT NULL DEFAULT 0, is_active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_lookup_options__list_value UNIQUE (list_id, value));
CREATE TABLE item_catalog (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  item_code citext NOT NULL UNIQUE, description text NOT NULL,
  default_unit_id uuid REFERENCES units_of_measure(id), default_returnable boolean NOT NULL DEFAULT false,
  is_active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE system_settings (
  key text PRIMARY KEY, value jsonb NOT NULL,
  value_type text NOT NULL DEFAULT 'json' CONSTRAINT ck_settings__type CHECK (value_type IN ('string','int','bool','json','list')),
  category text NOT NULL DEFAULT 'general', description text,
  is_secret boolean NOT NULL DEFAULT false, is_public boolean NOT NULL DEFAULT false,
  version integer NOT NULL DEFAULT 1, updated_by uuid, updated_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE number_sequences (
  scope_key text PRIMARY KEY, last_value bigint NOT NULL DEFAULT 0 CONSTRAINT ck_numseq__nonneg CHECK (last_value >= 0),
  updated_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE gate_pass_types (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  code citext NOT NULL UNIQUE, name text NOT NULL,
  direction text NOT NULL CONSTRAINT ck_gpt__dir CHECK (direction IN ('OUT','IN')),
  approval_levels smallint NOT NULL CONSTRAINT ck_gpt__levels CHECK (approval_levels BETWEEN 0 AND 2),
  requires_gate_event boolean NOT NULL DEFAULT true, tracks_returns boolean NOT NULL DEFAULT true,
  min_photos smallint NOT NULL DEFAULT 0, max_photos smallint NOT NULL DEFAULT 20,
  settings jsonb NOT NULL DEFAULT '{}', is_active boolean NOT NULL DEFAULT true, sort_order integer NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT ck_gpt__photos CHECK (min_photos <= max_photos));

-- ============ IDENTITY & ACCESS ============
CREATE TABLE users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  username citext NOT NULL UNIQUE CONSTRAINT ck_users__username CHECK (username ~ '^[a-z0-9._-]{3,50}$'),
  email citext UNIQUE, full_name text NOT NULL, employee_code text UNIQUE,
  password_hash text NOT NULL, password_changed_at timestamptz NOT NULL DEFAULT now(),
  must_change_password boolean NOT NULL DEFAULT true,
  is_master_admin boolean NOT NULL DEFAULT false, authz_version integer NOT NULL DEFAULT 1,
  is_active boolean NOT NULL DEFAULT true,
  department_id uuid REFERENCES departments(id), phone text,
  failed_login_count integer NOT NULL DEFAULT 0, locked_until timestamptz, last_login_at timestamptz,
  mfa_enabled boolean NOT NULL DEFAULT false, mfa_secret_enc text, mfa_recovery_hashes jsonb,
  created_by uuid REFERENCES users(id), deactivated_at timestamptz, deactivated_by uuid REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT ck_users__master_active CHECK (is_master_admin = false OR is_active = true));
CREATE UNIQUE INDEX uq_users__single_master ON users (is_master_admin) WHERE is_master_admin;
CREATE INDEX ix_users__department ON users (department_id);
CREATE INDEX ix_users__name_trgm ON users USING gin (full_name gin_trgm_ops);
ALTER TABLE departments ADD CONSTRAINT fk_departments__head FOREIGN KEY (head_user_id) REFERENCES users(id) DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE system_settings ADD CONSTRAINT fk_settings__user FOREIGN KEY (updated_by) REFERENCES users(id);
CREATE FUNCTION trg_users_guard() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'users cannot be deleted'; END IF;
  IF NEW.is_master_admin IS DISTINCT FROM OLD.is_master_admin THEN RAISE EXCEPTION 'is_master_admin is immutable'; END IF;
  IF OLD.is_master_admin AND NEW.is_active = false THEN RAISE EXCEPTION 'master admin cannot be deactivated'; END IF;
  RETURN NEW; END $$ LANGUAGE plpgsql;
CREATE TRIGGER trg_users_guard BEFORE UPDATE OR DELETE ON users FOR EACH ROW EXECUTE FUNCTION trg_users_guard();
CREATE TRIGGER trg_users_updated BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE roles (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  code citext NOT NULL UNIQUE, name text NOT NULL, description text,
  is_system boolean NOT NULL DEFAULT false, is_active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE permissions (
  code text PRIMARY KEY, module text NOT NULL, description text NOT NULL,
  is_approval boolean NOT NULL DEFAULT false, sort_order smallint NOT NULL DEFAULT 0);
CREATE TABLE role_permissions (
  role_id uuid NOT NULL REFERENCES roles(id), permission_code text NOT NULL REFERENCES permissions(code) ON UPDATE CASCADE,
  PRIMARY KEY (role_id, permission_code));
CREATE INDEX ix_role_permissions__code ON role_permissions (permission_code);
CREATE TABLE user_roles (
  user_id uuid NOT NULL REFERENCES users(id), role_id uuid NOT NULL REFERENCES roles(id),
  assigned_by uuid REFERENCES users(id), assigned_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, role_id));
CREATE INDEX ix_user_roles__role ON user_roles (role_id);
CREATE TABLE user_permissions (
  user_id uuid NOT NULL REFERENCES users(id), permission_code text NOT NULL REFERENCES permissions(code) ON UPDATE CASCADE,
  effect text NOT NULL CONSTRAINT ck_userperm__effect CHECK (effect IN ('GRANT','DENY')),
  granted_by uuid REFERENCES users(id), granted_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, permission_code));
CREATE INDEX ix_user_permissions__code ON user_permissions (permission_code, effect);
-- Future data scoping (D-09/D-10). Created now, not enforced in Phase 1.
CREATE TABLE user_data_scopes (
  user_id uuid NOT NULL REFERENCES users(id),
  scope_type text NOT NULL CONSTRAINT ck_scope__type CHECK (scope_type IN ('DEPARTMENT','LOCATION','GATE')),
  scope_id uuid NOT NULL, PRIMARY KEY (user_id, scope_type, scope_id));
CREATE TABLE user_password_history (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id uuid NOT NULL REFERENCES users(id),
  password_hash text NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX ix_pwhist__user ON user_password_history (user_id, created_at DESC);
CREATE TABLE auth_sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id uuid NOT NULL REFERENCES users(id),
  family_id uuid NOT NULL, parent_session_id uuid REFERENCES auth_sessions(id),
  refresh_token_hash text NOT NULL UNIQUE,
  platform text NOT NULL CONSTRAINT ck_sess__platform CHECK (platform IN ('web','electron','android','ios')),
  device_label text, client_version text, ip inet, user_agent text,
  scope text NOT NULL DEFAULT 'full',
  last_used_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL,
  rotated_at timestamptz, revoked_at timestamptz, revoked_reason text,
  created_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX ix_sess__live ON auth_sessions (user_id) WHERE revoked_at IS NULL AND rotated_at IS NULL;
CREATE INDEX ix_sess__family ON auth_sessions (family_id);
CREATE TABLE login_attempts (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, username_attempted text NOT NULL,
  user_id uuid REFERENCES users(id), ip inet, success boolean NOT NULL, failure_reason text, platform text,
  occurred_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX ix_login__user ON login_attempts (lower(username_attempted), occurred_at DESC);
CREATE INDEX ix_login__ip ON login_attempts (ip, occurred_at DESC);

-- ============ DYNAMIC FORMS ============
CREATE TABLE form_field_registry (
  field_key text PRIMARY KEY CONSTRAINT ck_registry__key CHECK (field_key ~ '^[a-z][a-z0-9_]{1,48}$'),
  field_type text NOT NULL CONSTRAINT ck_registry__type CHECK (field_type IN
    ('TEXT','LONGTEXT','INTEGER','DECIMAL','DATE','TIME','DATETIME','YESNO','DROPDOWN','MULTISELECT',
     'USER','LOCATION','ATTACHMENT','IMAGE','CAMERA')),
  storage_class text NOT NULL CONSTRAINT ck_registry__class CHECK (storage_class IN ('SYSTEM','CORE','CUSTOM')),
  core_column text, created_by uuid REFERENCES users(id),
  first_published_at timestamptz, retired_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT ck_registry__core_col CHECK ((storage_class = 'CUSTOM') = (core_column IS NULL)));
CREATE FUNCTION trg_registry_guard() RETURNS trigger AS $$
BEGIN
  IF OLD.first_published_at IS NOT NULL AND (NEW.field_type <> OLD.field_type OR NEW.storage_class <> OLD.storage_class
     OR NEW.core_column IS DISTINCT FROM OLD.core_column) THEN
    RAISE EXCEPTION 'field % is published: type/class/column are frozen', OLD.field_key; END IF;
  RETURN NEW; END $$ LANGUAGE plpgsql;
CREATE TRIGGER trg_registry_guard BEFORE UPDATE ON form_field_registry FOR EACH ROW EXECUTE FUNCTION trg_registry_guard();

CREATE TABLE form_definitions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  gate_pass_type_id uuid NOT NULL UNIQUE REFERENCES gate_pass_types(id), name text NOT NULL,
  current_version_id uuid,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE form_versions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  form_definition_id uuid NOT NULL REFERENCES form_definitions(id),
  version_no integer NOT NULL CONSTRAINT ck_fv__no CHECK (version_no > 0),
  status text NOT NULL DEFAULT 'DRAFT' CONSTRAINT ck_fv__status CHECK (status IN ('DRAFT','PUBLISHED','ARCHIVED')),
  change_note text, base_version_id uuid REFERENCES form_versions(id),
  snapshot jsonb, schema_hash text,
  created_by uuid REFERENCES users(id), published_by uuid REFERENCES users(id),
  published_at timestamptz, archived_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_fv__def_no UNIQUE (form_definition_id, version_no),
  CONSTRAINT ck_fv__published_complete CHECK (status = 'DRAFT' OR (snapshot IS NOT NULL AND schema_hash IS NOT NULL
    AND published_at IS NOT NULL AND change_note IS NOT NULL)));
CREATE UNIQUE INDEX uq_fv__one_draft ON form_versions (form_definition_id) WHERE status = 'DRAFT';
CREATE UNIQUE INDEX uq_fv__one_published ON form_versions (form_definition_id) WHERE status = 'PUBLISHED';
ALTER TABLE form_definitions ADD CONSTRAINT fk_fd__current FOREIGN KEY (current_version_id) REFERENCES form_versions(id) DEFERRABLE INITIALLY DEFERRED;
CREATE FUNCTION trg_form_version_guard() RETURNS trigger AS $$
BEGIN
  IF OLD.status = 'DRAFT' THEN RETURN CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END; END IF;
  IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'published form versions cannot be deleted'; END IF;
  IF OLD.status = 'PUBLISHED' AND NEW.status = 'ARCHIVED' AND NEW.snapshot IS NOT DISTINCT FROM OLD.snapshot
     AND NEW.schema_hash IS NOT DISTINCT FROM OLD.schema_hash AND NEW.version_no = OLD.version_no THEN RETURN NEW; END IF;
  RAISE EXCEPTION 'form version % is immutable (status %)', OLD.version_no, OLD.status; END $$ LANGUAGE plpgsql;
CREATE TRIGGER trg_form_version_guard BEFORE UPDATE OR DELETE ON form_versions FOR EACH ROW EXECUTE FUNCTION trg_form_version_guard();

CREATE TABLE form_sections (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  form_version_id uuid NOT NULL REFERENCES form_versions(id) ON DELETE CASCADE,
  section_key text NOT NULL, title text NOT NULL,
  scope text NOT NULL CONSTRAINT ck_fs__scope CHECK (scope IN ('HEADER','ITEM','EVIDENCE','SYSTEM')),
  display_order integer NOT NULL, is_collapsible boolean NOT NULL DEFAULT false,
  CONSTRAINT uq_fs__ver_key UNIQUE (form_version_id, section_key));
CREATE TABLE form_fields (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  form_version_id uuid NOT NULL REFERENCES form_versions(id) ON DELETE CASCADE,
  section_id uuid NOT NULL REFERENCES form_sections(id) ON DELETE CASCADE,
  field_key text NOT NULL REFERENCES form_field_registry(field_key),
  scope text NOT NULL CONSTRAINT ck_ff__scope CHECK (scope IN ('HEADER','ITEM')),
  label text NOT NULL CONSTRAINT ck_ff__label CHECK (length(label) BETWEEN 1 AND 80),
  field_type text NOT NULL, storage_class text NOT NULL, core_column text,
  is_required boolean NOT NULL DEFAULT false, is_active boolean NOT NULL DEFAULT true, is_locked boolean NOT NULL DEFAULT false,
  display_order integer NOT NULL, default_value jsonb, placeholder text, help_text text,
  validation jsonb NOT NULL DEFAULT '{}',
  options_source text NOT NULL DEFAULT 'NONE' CONSTRAINT ck_ff__src CHECK (options_source IN
    ('NONE','INLINE','LOOKUP','MASTER_LOCATIONS','MASTER_DEPARTMENTS','MASTER_USERS','MASTER_UNITS')),
  lookup_list_id uuid REFERENCES lookup_lists(id), visibility_rule jsonb,
  show_in_list boolean NOT NULL DEFAULT false, show_in_pdf boolean NOT NULL DEFAULT true, is_searchable boolean NOT NULL DEFAULT false,
  ui jsonb NOT NULL DEFAULT '{}',
  CONSTRAINT uq_ff__ver_key UNIQUE (form_version_id, field_key),
  CONSTRAINT ck_ff__lookup CHECK (options_source <> 'LOOKUP' OR lookup_list_id IS NOT NULL),
  CONSTRAINT ck_ff__locked CHECK (NOT is_locked OR (is_active AND storage_class = 'SYSTEM')),
  CONSTRAINT ck_ff__json CHECK (jsonb_typeof(validation) = 'object' AND jsonb_typeof(ui) = 'object'));
CREATE INDEX ix_ff__order ON form_fields (form_version_id, section_id, display_order);
CREATE INDEX ix_ff__key ON form_fields (field_key);
CREATE TABLE form_field_options (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  form_field_id uuid NOT NULL REFERENCES form_fields(id) ON DELETE CASCADE,
  value text NOT NULL CONSTRAINT ck_ffo__value CHECK (value ~ '^[A-Z0-9_]{1,40}$'),
  label text NOT NULL, sort_order integer NOT NULL DEFAULT 0, is_active boolean NOT NULL DEFAULT true, is_default boolean NOT NULL DEFAULT false,
  CONSTRAINT uq_ffo__field_value UNIQUE (form_field_id, value));
CREATE UNIQUE INDEX uq_ffo__one_default ON form_field_options (form_field_id) WHERE is_default;
CREATE FUNCTION trg_form_children_guard() RETURNS trigger AS $$
DECLARE vid uuid; st text; rec record;
BEGIN
  rec := CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;
  IF TG_TABLE_NAME = 'form_field_options' THEN
    SELECT form_version_id INTO vid FROM form_fields WHERE id = rec.form_field_id;
  ELSE vid := rec.form_version_id; END IF;
  SELECT status INTO st FROM form_versions WHERE id = vid;
  IF st IS NOT NULL AND st <> 'DRAFT' THEN RAISE EXCEPTION 'form version is not a draft; structure is immutable'; END IF;
  RETURN rec; END $$ LANGUAGE plpgsql;
CREATE TRIGGER trg_fs_guard BEFORE INSERT OR UPDATE OR DELETE ON form_sections FOR EACH ROW EXECUTE FUNCTION trg_form_children_guard();
CREATE TRIGGER trg_ff_guard BEFORE INSERT OR UPDATE OR DELETE ON form_fields FOR EACH ROW EXECUTE FUNCTION trg_form_children_guard();
CREATE TRIGGER trg_ffo_guard BEFORE INSERT OR UPDATE OR DELETE ON form_field_options FOR EACH ROW EXECUTE FUNCTION trg_form_children_guard();
CREATE FUNCTION trg_ff_matches_registry() RETURNS trigger AS $$
DECLARE r form_field_registry%ROWTYPE;
BEGIN
  SELECT * INTO r FROM form_field_registry WHERE field_key = NEW.field_key;
  IF r.field_type <> NEW.field_type OR r.storage_class <> NEW.storage_class OR r.core_column IS DISTINCT FROM NEW.core_column THEN
    RAISE EXCEPTION 'field % does not match its registry identity', NEW.field_key; END IF;
  RETURN NEW; END $$ LANGUAGE plpgsql;
CREATE TRIGGER trg_ff_registry BEFORE INSERT OR UPDATE ON form_fields FOR EACH ROW EXECUTE FUNCTION trg_ff_matches_registry();

-- ============ GATE PASSES ============
CREATE TABLE gate_passes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  gate_pass_no text UNIQUE,
  type_id uuid NOT NULL REFERENCES gate_pass_types(id),
  form_version_id uuid NOT NULL REFERENCES form_versions(id),
  status text NOT NULL DEFAULT 'DRAFT' CONSTRAINT ck_gp__status CHECK (status IN
    ('DRAFT','SUBMITTED','PENDING_L1','L1_APPROVED','PENDING_L2','APPROVED','REJECTED','GATE_OUT','GATE_IN',
     'PENDING_RETURN','PARTIALLY_RETURNED','COMPLETED','CLOSED','CANCELLED')),
  status_changed_at timestamptz NOT NULL DEFAULT now(),
  row_version integer NOT NULL DEFAULT 1, revision_no integer NOT NULL DEFAULT 0, round_no integer NOT NULL DEFAULT 0,
  required_approval_levels smallint CONSTRAINT ck_gp__levels CHECK (required_approval_levels BETWEEN 0 AND 2),
  client_request_id uuid,
  reference_no text, vehicle_no text,
  vehicle_no_normalized text GENERATED ALWAYS AS (upper(regexp_replace(vehicle_no, '[^A-Za-z0-9]', '', 'g'))) STORED,
  seal_no text, planned_datetime timestamptz,
  location_id uuid REFERENCES locations(id), department_id uuid REFERENCES departments(id),
  responsible_user_id uuid REFERENCES users(id), responsible_name text,
  purpose_value text, category_value text, received_by_name text,
  inward_kind text CONSTRAINT ck_gp__inward_kind CHECK (inward_kind IN ('RETURN_AGAINST_OUTWARD','FRESH_INWARD')),
  expected_return_date date, remarks text CONSTRAINT ck_gp__remarks CHECK (length(remarks) <= 2000),
  has_returnable boolean NOT NULL DEFAULT false,
  custom_data jsonb NOT NULL DEFAULT '{}' CONSTRAINT ck_gp__custom CHECK (jsonb_typeof(custom_data) = 'object'),
  created_by uuid NOT NULL REFERENCES users(id),
  submitted_at timestamptz, submitted_by uuid REFERENCES users(id), approved_at timestamptz, completed_at timestamptz,
  closed_at timestamptz, closed_by uuid REFERENCES users(id), close_reason text,
  cancelled_at timestamptz, cancelled_by uuid REFERENCES users(id), cancel_reason text,
  last_rejected_at timestamptz, last_rejected_by uuid REFERENCES users(id), last_rejection_reason text,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT ck_gp__number CHECK (status = 'DRAFT' OR gate_pass_no IS NOT NULL),
  CONSTRAINT ck_gp__cancel CHECK ((status = 'CANCELLED') = (cancelled_at IS NOT NULL AND cancel_reason IS NOT NULL)),
  CONSTRAINT ck_gp__closed CHECK (status <> 'CLOSED' OR closed_at IS NOT NULL),
  CONSTRAINT ck_gp__return_date CHECK (status = 'DRAFT' OR NOT has_returnable OR expected_return_date IS NOT NULL));
CREATE UNIQUE INDEX uq_gp__client_req ON gate_passes (created_by, client_request_id) WHERE client_request_id IS NOT NULL;
CREATE INDEX ix_gp__type_status ON gate_passes (type_id, status);
CREATE INDEX ix_gp__status_created ON gate_passes (status, created_at DESC);
CREATE INDEX ix_gp__creator ON gate_passes (created_by, created_at DESC);
CREATE INDEX ix_gp__formver ON gate_passes (form_version_id);
CREATE INDEX ix_gp__location ON gate_passes (location_id);
CREATE INDEX ix_gp__department ON gate_passes (department_id);
CREATE INDEX ix_gp__responsible ON gate_passes (responsible_user_id);
CREATE INDEX ix_gp__submitted ON gate_passes (submitted_at DESC);
CREATE INDEX ix_gp__returnable_due ON gate_passes (expected_return_date) WHERE has_returnable;
CREATE INDEX ix_gp__pending_approval ON gate_passes (status, submitted_at) WHERE status IN ('PENDING_L1','PENDING_L2');
CREATE INDEX ix_gp__approved ON gate_passes (status, approved_at) WHERE status = 'APPROVED';
CREATE INDEX ix_gp__ref_trgm ON gate_passes USING gin (reference_no gin_trgm_ops);
CREATE INDEX ix_gp__veh_trgm ON gate_passes USING gin (vehicle_no_normalized gin_trgm_ops);
CREATE INDEX ix_gp__no_trgm ON gate_passes USING gin (gate_pass_no gin_trgm_ops);
CREATE INDEX ix_gp__seal_trgm ON gate_passes USING gin (seal_no gin_trgm_ops);
CREATE INDEX ix_gp__custom ON gate_passes USING gin (custom_data jsonb_path_ops);
CREATE TRIGGER trg_gp_updated BEFORE UPDATE ON gate_passes FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE gate_pass_items (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  gate_pass_id uuid NOT NULL REFERENCES gate_passes(id),
  line_no integer NOT NULL CONSTRAINT ck_gpi__line CHECK (line_no > 0),
  item_catalog_id uuid REFERENCES item_catalog(id), item_code text,
  description text NOT NULL CONSTRAINT ck_gpi__desc CHECK (length(description) BETWEEN 1 AND 300),
  quantity numeric(14,3) NOT NULL CONSTRAINT ck_gpi__qty CHECK (quantity > 0),
  unit_id uuid NOT NULL REFERENCES units_of_measure(id),
  cartons integer CONSTRAINT ck_gpi__cartons CHECK (cartons >= 0), pieces integer CONSTRAINT ck_gpi__pieces CHECK (pieces >= 0),
  is_returnable boolean NOT NULL DEFAULT false, condition_value text,
  verified_quantity numeric(14,3) CONSTRAINT ck_gpi__vqty CHECK (verified_quantity >= 0), verified_condition_value text,
  source_outward_item_id uuid REFERENCES gate_pass_items(id), remarks text,
  custom_data jsonb NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_gpi__line UNIQUE (gate_pass_id, line_no),
  CONSTRAINT ck_gpi__notself CHECK (source_outward_item_id IS NULL OR source_outward_item_id <> id));
CREATE INDEX ix_gpi__pass ON gate_pass_items (gate_pass_id);
CREATE INDEX ix_gpi__source ON gate_pass_items (source_outward_item_id) WHERE source_outward_item_id IS NOT NULL;
CREATE INDEX ix_gpi__code ON gate_pass_items (item_code);
CREATE INDEX ix_gpi__desc_trgm ON gate_pass_items USING gin (description gin_trgm_ops);
CREATE TRIGGER trg_gpi_updated BEFORE UPDATE ON gate_pass_items FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE FUNCTION trg_items_immutable() RETURNS trigger AS $$
DECLARE st text;
BEGIN
  SELECT status INTO st FROM gate_passes WHERE id = COALESCE(NEW.gate_pass_id, OLD.gate_pass_id);
  IF st IN ('DRAFT','REJECTED') THEN RETURN CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END; END IF;
  IF TG_OP = 'UPDATE' AND (to_jsonb(NEW) - 'verified_quantity' - 'verified_condition_value' - 'updated_at')
       = (to_jsonb(OLD) - 'verified_quantity' - 'verified_condition_value' - 'updated_at') THEN RETURN NEW; END IF;
  RAISE EXCEPTION 'items of a submitted gate pass are immutable (status %)', st; END $$ LANGUAGE plpgsql;
CREATE TRIGGER trg_items_immutable BEFORE INSERT OR UPDATE OR DELETE ON gate_pass_items FOR EACH ROW EXECUTE FUNCTION trg_items_immutable();

CREATE TABLE gate_pass_revisions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), gate_pass_id uuid NOT NULL REFERENCES gate_passes(id),
  revision_no integer NOT NULL, reason text NOT NULL CONSTRAINT ck_rev__reason CHECK (reason IN ('SUBMIT','RESUBMIT','ADMIN_EDIT')),
  snapshot jsonb NOT NULL, snapshot_hash text NOT NULL, created_by uuid NOT NULL REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now(), CONSTRAINT uq_rev__pass_no UNIQUE (gate_pass_id, revision_no));

CREATE TABLE gate_pass_attachments (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  gate_pass_id uuid NOT NULL REFERENCES gate_passes(id),
  gate_pass_item_id uuid REFERENCES gate_pass_items(id),
  form_field_key text REFERENCES form_field_registry(field_key),
  kind text NOT NULL CONSTRAINT ck_att__kind CHECK (kind IN ('PHOTO_CAPTURE','PHOTO_UPLOAD','VIDEO','DOCUMENT')),
  stage text NOT NULL CONSTRAINT ck_att__stage CHECK (stage IN ('CREATION','GATE_OUT','GATE_IN','RETURN','ADMIN')),
  sequence_no integer NOT NULL, original_filename text NOT NULL, storage_key text NOT NULL UNIQUE,
  declared_mime text, detected_mime text, extension text NOT NULL,
  size_bytes bigint CONSTRAINT ck_att__size CHECK (size_bytes > 0), sha256 text,
  width integer, height integer, duration_seconds integer, thumbnail_key text,
  status text NOT NULL DEFAULT 'PENDING_UPLOAD' CONSTRAINT ck_att__status CHECK (status IN ('PENDING_UPLOAD','UPLOADED','READY','QUARANTINED','DELETED')),
  multipart_upload_id text, capture_meta jsonb NOT NULL DEFAULT '{}',
  uploaded_by uuid NOT NULL REFERENCES users(id), uploaded_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz, deleted_by uuid REFERENCES users(id), delete_reason text,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT ck_att__ready CHECK (status <> 'READY' OR (detected_mime IS NOT NULL AND size_bytes IS NOT NULL)),
  CONSTRAINT ck_att__deleted CHECK ((status = 'DELETED') = (deleted_at IS NOT NULL AND delete_reason IS NOT NULL)),
  CONSTRAINT uq_att__pass_seq UNIQUE (gate_pass_id, sequence_no));
CREATE INDEX ix_att__pass_status ON gate_pass_attachments (gate_pass_id, status);
CREATE INDEX ix_att__pending ON gate_pass_attachments (status, created_at) WHERE status = 'PENDING_UPLOAD';
CREATE INDEX ix_att__sha ON gate_pass_attachments (sha256);
CREATE TRIGGER trg_att_updated BEFORE UPDATE ON gate_pass_attachments FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE gate_pass_approvals (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), gate_pass_id uuid NOT NULL REFERENCES gate_passes(id),
  round_no integer NOT NULL CONSTRAINT ck_appr__round CHECK (round_no > 0), revision_no integer NOT NULL,
  level smallint NOT NULL CONSTRAINT ck_appr__level CHECK (level IN (1,2)),
  approver_id uuid NOT NULL REFERENCES users(id), approver_name text NOT NULL,
  approver_was_master_admin boolean NOT NULL DEFAULT false,
  decision text NOT NULL CONSTRAINT ck_appr__decision CHECK (decision IN ('APPROVED','REJECTED')),
  comments text, decided_at timestamptz NOT NULL DEFAULT now(),
  ip inet, user_agent text, platform text, client_version text, device_info jsonb,
  CONSTRAINT ck_appr__reject_reason CHECK (decision = 'APPROVED' OR length(btrim(coalesce(comments,''))) > 0),
  CONSTRAINT uq_appr__level UNIQUE (gate_pass_id, round_no, level));
CREATE INDEX ix_appr__approver ON gate_pass_approvals (approver_id, decided_at DESC);

CREATE TABLE gate_pass_status_history (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, gate_pass_id uuid NOT NULL REFERENCES gate_passes(id),
  from_status text, to_status text NOT NULL, actor_id uuid REFERENCES users(id), reason text,
  revision_no integer, round_no integer, metadata jsonb NOT NULL DEFAULT '{}', occurred_at timestamptz NOT NULL DEFAULT clock_timestamp());
CREATE INDEX ix_hist__pass ON gate_pass_status_history (gate_pass_id, occurred_at, id);

CREATE TABLE gate_pass_gate_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), gate_pass_id uuid NOT NULL REFERENCES gate_passes(id),
  event_type text NOT NULL CONSTRAINT ck_ge__type CHECK (event_type IN ('GATE_OUT','GATE_IN')),
  gate_id uuid NOT NULL REFERENCES gates(id),
  occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(), recorded_by uuid NOT NULL REFERENCES users(id),
  vehicle_no_verified text, seal_no_verified text, seal_intact boolean, driver_name text, remarks text,
  has_discrepancy boolean NOT NULL DEFAULT false, ip inet, platform text, device_info jsonb,
  CONSTRAINT uq_ge__pass_type UNIQUE (gate_pass_id, event_type));
CREATE INDEX ix_ge__user ON gate_pass_gate_events (recorded_by, occurred_at DESC);
CREATE INDEX ix_ge__time ON gate_pass_gate_events (occurred_at DESC);

CREATE FUNCTION trg_items_source_valid() RETURNS trigger AS $$
DECLARE ok boolean;
BEGIN
  IF NEW.source_outward_item_id IS NULL THEN RETURN NEW; END IF;
  SELECT (t.direction = 'OUT' AND i.is_returnable AND EXISTS (SELECT 1 FROM gate_pass_gate_events e WHERE e.gate_pass_id = i.gate_pass_id AND e.event_type = 'GATE_OUT'))
    INTO ok FROM gate_pass_items i JOIN gate_passes p ON p.id = i.gate_pass_id JOIN gate_pass_types t ON t.id = p.type_id
    WHERE i.id = NEW.source_outward_item_id;
  IF ok IS NOT TRUE THEN RAISE EXCEPTION 'source line must be a returnable line of a gated-out outward pass'; END IF;
  RETURN NEW; END $$ LANGUAGE plpgsql;
CREATE TRIGGER trg_items_source_valid BEFORE INSERT OR UPDATE OF source_outward_item_id ON gate_pass_items FOR EACH ROW EXECUTE FUNCTION trg_items_source_valid();

CREATE TABLE gate_pass_verifications (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), gate_pass_id uuid NOT NULL REFERENCES gate_passes(id),
  verification_type text NOT NULL CONSTRAINT ck_ver__type CHECK (verification_type IN ('ADMIN_AUDIT')),
  result text NOT NULL CONSTRAINT ck_ver__result CHECK (result IN ('VERIFIED','DISCREPANCY')), notes text,
  verified_by uuid NOT NULL REFERENCES users(id), verified_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT ck_ver__notes CHECK (result = 'VERIFIED' OR length(btrim(coalesce(notes,''))) > 0));
CREATE INDEX ix_ver__pass ON gate_pass_verifications (gate_pass_id, verified_at DESC);

-- status transition guard + history consistency
CREATE FUNCTION trg_gp_status_transition() RETURNS trigger AS $$
DECLARE ok boolean;
BEGIN
  IF NEW.status = OLD.status THEN RETURN NEW; END IF;
  SELECT EXISTS (SELECT 1 FROM (VALUES
   ('DRAFT','SUBMITTED'),('DRAFT','CANCELLED'),('SUBMITTED','PENDING_L1'),('SUBMITTED','APPROVED'),
   ('PENDING_L1','L1_APPROVED'),('PENDING_L1','REJECTED'),('PENDING_L1','DRAFT'),('PENDING_L1','CANCELLED'),
   ('L1_APPROVED','PENDING_L2'),('L1_APPROVED','APPROVED'),('PENDING_L2','APPROVED'),('PENDING_L2','REJECTED'),('PENDING_L2','CANCELLED'),
   ('REJECTED','SUBMITTED'),('REJECTED','CANCELLED'),('APPROVED','GATE_OUT'),('APPROVED','GATE_IN'),('APPROVED','CANCELLED'),
   ('GATE_OUT','PENDING_RETURN'),('GATE_OUT','COMPLETED'),('GATE_IN','COMPLETED'),
   ('PENDING_RETURN','PARTIALLY_RETURNED'),('PENDING_RETURN','COMPLETED'),
   ('PARTIALLY_RETURNED','COMPLETED'),('PARTIALLY_RETURNED','PENDING_RETURN'),
   ('COMPLETED','CLOSED'),('COMPLETED','PARTIALLY_RETURNED'),('COMPLETED','PENDING_RETURN'),
   ('CLOSED','PARTIALLY_RETURNED'),('CLOSED','PENDING_RETURN')) AS t(f,t2) WHERE f = OLD.status AND t2 = NEW.status) INTO ok;
  IF NOT ok THEN RAISE EXCEPTION 'invalid gate pass status transition % -> %', OLD.status, NEW.status; END IF;
  RETURN NEW; END $$ LANGUAGE plpgsql;
CREATE TRIGGER trg_gp_status_transition BEFORE UPDATE OF status ON gate_passes FOR EACH ROW EXECUTE FUNCTION trg_gp_status_transition();
CREATE FUNCTION trg_gp_status_history() RETURNS trigger AS $$
DECLARE last_to text; cur text;
BEGIN
  -- deferred: compare the *final* state of the row with the latest history row (several steps may occur in one transaction)
  SELECT status INTO cur FROM gate_passes WHERE id = NEW.id;
  SELECT to_status INTO last_to FROM gate_pass_status_history WHERE gate_pass_id = NEW.id ORDER BY id DESC LIMIT 1;
  IF last_to IS DISTINCT FROM cur THEN RAISE EXCEPTION 'status change of % lacks a history row', NEW.id; END IF;
  RETURN NULL; END $$ LANGUAGE plpgsql;
CREATE CONSTRAINT TRIGGER trg_gp_status_history AFTER INSERT OR UPDATE OF status ON gate_passes
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION trg_gp_status_history();

-- ============ RETURNABLES ============
CREATE TABLE returnable_records (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  source_gate_pass_id uuid NOT NULL UNIQUE REFERENCES gate_passes(id),
  origin_direction text NOT NULL DEFAULT 'OUT' CONSTRAINT ck_rr__dir CHECK (origin_direction = 'OUT'),
  status text NOT NULL DEFAULT 'OPEN' CONSTRAINT ck_rr__status CHECK (status IN ('OPEN','PARTIALLY_RETURNED','COMPLETED','CLOSED_ADJUSTED')),
  expected_return_date date NOT NULL, opened_at timestamptz NOT NULL,
  completed_at timestamptz, closed_at timestamptz, closed_by uuid REFERENCES users(id), close_reason text,
  last_reminder_at timestamptz, reminder_count integer NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT ck_rr__completed CHECK (status <> 'COMPLETED' OR completed_at IS NOT NULL),
  CONSTRAINT ck_rr__closed CHECK (status <> 'CLOSED_ADJUSTED' OR (closed_at IS NOT NULL AND closed_by IS NOT NULL AND length(btrim(coalesce(close_reason,''))) > 0)));
CREATE INDEX ix_rr__open ON returnable_records (status, expected_return_date) WHERE status IN ('OPEN','PARTIALLY_RETURNED');
CREATE TRIGGER trg_rr_updated BEFORE UPDATE ON returnable_records FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TABLE returnable_items (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  record_id uuid NOT NULL REFERENCES returnable_records(id),
  source_item_id uuid NOT NULL UNIQUE REFERENCES gate_pass_items(id),
  unit_id uuid NOT NULL REFERENCES units_of_measure(id),
  qty_out numeric(14,3) NOT NULL CONSTRAINT ck_ri__out CHECK (qty_out > 0),
  qty_returned numeric(14,3) NOT NULL DEFAULT 0 CONSTRAINT ck_ri__ret CHECK (qty_returned >= 0),
  qty_adjusted numeric(14,3) NOT NULL DEFAULT 0 CONSTRAINT ck_ri__adj CHECK (qty_adjusted >= 0),
  qty_pending numeric(14,3) GENERATED ALWAYS AS (qty_out - qty_returned - qty_adjusted) STORED,
  status text GENERATED ALWAYS AS (CASE WHEN qty_returned + qty_adjusted = 0 THEN 'PENDING'
      WHEN qty_out - qty_returned - qty_adjusted > 0 THEN 'PARTIAL' WHEN qty_adjusted = 0 THEN 'RETURNED' ELSE 'ADJUSTED' END) STORED,
  row_version integer NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT ck_ri__no_overreturn CHECK (qty_returned + qty_adjusted <= qty_out));
CREATE INDEX ix_ri__record ON returnable_items (record_id);
CREATE INDEX ix_ri__pending ON returnable_items (qty_pending) WHERE qty_pending > 0;
CREATE TRIGGER trg_ri_updated BEFORE UPDATE ON returnable_items FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TABLE returnable_transactions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  returnable_item_id uuid NOT NULL REFERENCES returnable_items(id),
  txn_type text NOT NULL CONSTRAINT ck_rt__type CHECK (txn_type IN ('RETURN','ADJUSTMENT','REVERSAL')),
  quantity numeric(14,3) NOT NULL CONSTRAINT ck_rt__qty CHECK (quantity > 0),
  inward_gate_pass_id uuid REFERENCES gate_passes(id), inward_item_id uuid REFERENCES gate_pass_items(id),
  condition_value text, reason text, reverses_txn_id uuid UNIQUE REFERENCES returnable_transactions(id),
  recorded_by uuid NOT NULL REFERENCES users(id), recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT ck_rt__return CHECK (txn_type <> 'RETURN' OR (inward_gate_pass_id IS NOT NULL AND inward_item_id IS NOT NULL AND reverses_txn_id IS NULL)),
  CONSTRAINT ck_rt__adjustment CHECK (txn_type <> 'ADJUSTMENT' OR (length(btrim(coalesce(reason,''))) > 0 AND inward_item_id IS NULL AND reverses_txn_id IS NULL)),
  CONSTRAINT ck_rt__reversal CHECK (txn_type <> 'REVERSAL' OR (reverses_txn_id IS NOT NULL AND length(btrim(coalesce(reason,''))) > 0)));
CREATE UNIQUE INDEX uq_rt__inward_item ON returnable_transactions (inward_item_id) WHERE txn_type = 'RETURN';
CREATE INDEX ix_rt__item ON returnable_transactions (returnable_item_id, recorded_at);
CREATE INDEX ix_rt__inward ON returnable_transactions (inward_gate_pass_id);

-- ============ AUDIT / CROSS-CUTTING ============
CREATE TABLE audit_logs (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  actor_user_id uuid REFERENCES users(id), actor_username text, action text NOT NULL, entity_type text NOT NULL, entity_id text,
  gate_pass_id uuid REFERENCES gate_passes(id),
  severity text NOT NULL DEFAULT 'INFO' CONSTRAINT ck_audit__sev CHECK (severity IN ('INFO','WARN','SECURITY')),
  summary text NOT NULL, before jsonb, after jsonb, ip inet, user_agent text, platform text, client_version text,
  request_id uuid, session_id uuid, prev_hash bytea NOT NULL, row_hash bytea NOT NULL UNIQUE);
CREATE INDEX ix_audit__time ON audit_logs (occurred_at DESC);
CREATE INDEX ix_audit__entity ON audit_logs (entity_type, entity_id);
CREATE INDEX ix_audit__pass ON audit_logs (gate_pass_id, occurred_at);
CREATE INDEX ix_audit__actor ON audit_logs (actor_user_id, occurred_at DESC);
CREATE INDEX ix_audit__action ON audit_logs (action, occurred_at DESC);
CREATE FUNCTION audit_canonical(r audit_logs) RETURNS text AS $$
  SELECT concat_ws('|', r.id::text, to_char(r.occurred_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US'),
    coalesce(r.actor_user_id::text,''), r.action, r.entity_type, coalesce(r.entity_id,''), coalesce(r.gate_pass_id::text,''),
    r.severity, r.summary, coalesce(r.before::text,''), coalesce(r.after::text,'')) $$ LANGUAGE sql IMMUTABLE;
CREATE FUNCTION trg_audit_chain() RETURNS trigger AS $$
DECLARE prev bytea;
BEGIN
  PERFORM pg_advisory_xact_lock(7283001);
  SELECT row_hash INTO prev FROM audit_logs ORDER BY id DESC LIMIT 1;
  NEW.prev_hash := coalesce(prev, decode(repeat('00',32),'hex'));
  NEW.row_hash := digest(NEW.prev_hash || convert_to(audit_canonical(NEW),'UTF8'), 'sha256');
  RETURN NEW; END $$ LANGUAGE plpgsql;
CREATE TRIGGER trg_audit_chain BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION trg_audit_chain();
CREATE FUNCTION audit_verify_chain(from_id bigint DEFAULT 0, OUT rows_checked bigint, OUT first_bad bigint) AS $$
DECLARE r audit_logs; prev bytea; expected bytea;
BEGIN
  rows_checked := 0; first_bad := NULL;
  SELECT row_hash INTO prev FROM audit_logs WHERE id < from_id ORDER BY id DESC LIMIT 1;
  prev := coalesce(prev, decode(repeat('00',32),'hex'));
  FOR r IN SELECT * FROM audit_logs WHERE id >= from_id ORDER BY id LOOP
    expected := digest(prev || convert_to(audit_canonical(r),'UTF8'), 'sha256');
    IF r.prev_hash <> prev OR r.row_hash <> expected THEN first_bad := r.id; RETURN; END IF;
    prev := r.row_hash; rows_checked := rows_checked + 1;
  END LOOP; END $$ LANGUAGE plpgsql;
CREATE TABLE audit_chain_checks (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, checked_at timestamptz NOT NULL DEFAULT now(),
  up_to_audit_id bigint, rows_checked bigint NOT NULL, ok boolean NOT NULL, first_bad_audit_id bigint, details text);

CREATE FUNCTION trg_append_only() RETURNS trigger AS $$
BEGIN RAISE EXCEPTION '% is append-only', TG_TABLE_NAME; END $$ LANGUAGE plpgsql;
DO $$ DECLARE t text; BEGIN
  FOREACH t IN ARRAY ARRAY['audit_logs','audit_chain_checks','gate_pass_status_history','gate_pass_approvals','gate_pass_revisions',
                           'gate_pass_gate_events','gate_pass_verifications','returnable_transactions'] LOOP
    EXECUTE format('CREATE TRIGGER trg_append_only BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION trg_append_only()', t);
    EXECUTE format('CREATE TRIGGER trg_append_only_trunc BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION trg_append_only()', t);
  END LOOP; END $$;

CREATE TABLE notifications (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), recipient_user_id uuid NOT NULL REFERENCES users(id),
  channel text NOT NULL CONSTRAINT ck_notif__channel CHECK (channel IN ('IN_APP','EMAIL','WHATSAPP','SMS')),
  event_type text NOT NULL, gate_pass_id uuid REFERENCES gate_passes(id), title text NOT NULL, body text,
  payload jsonb NOT NULL DEFAULT '{}',
  status text NOT NULL DEFAULT 'PENDING' CONSTRAINT ck_notif__status CHECK (status IN ('PENDING','SENT','FAILED','READ','CANCELLED')),
  attempts integer NOT NULL DEFAULT 0, next_attempt_at timestamptz, sent_at timestamptz, read_at timestamptz, last_error text,
  dedupe_key text NOT NULL UNIQUE, created_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX ix_notif__pending ON notifications (status, next_attempt_at) WHERE status = 'PENDING';
CREATE INDEX ix_notif__inbox ON notifications (recipient_user_id, created_at DESC) WHERE channel = 'IN_APP';
CREATE TABLE notification_preferences (
  user_id uuid NOT NULL REFERENCES users(id), event_type text NOT NULL, channel text NOT NULL, enabled boolean NOT NULL DEFAULT true,
  PRIMARY KEY (user_id, event_type, channel));
CREATE TABLE idempotency_keys (
  user_id uuid NOT NULL REFERENCES users(id), key text NOT NULL, endpoint text NOT NULL, request_hash text NOT NULL,
  response_status integer, response_body jsonb, created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL,
  PRIMARY KEY (user_id, key));
CREATE INDEX ix_idem__exp ON idempotency_keys (expires_at);
CREATE TABLE export_jobs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), requested_by uuid NOT NULL REFERENCES users(id), report_code text NOT NULL,
  format text NOT NULL CONSTRAINT ck_exp__fmt CHECK (format IN ('XLSX','CSV','PDF')), filters jsonb NOT NULL DEFAULT '{}',
  status text NOT NULL DEFAULT 'QUEUED' CONSTRAINT ck_exp__status CHECK (status IN ('QUEUED','RUNNING','DONE','FAILED','EXPIRED')),
  object_key text, row_count integer, error text, started_at timestamptz, finished_at timestamptz, expires_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE background_jobs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), job_type text NOT NULL, payload jsonb NOT NULL DEFAULT '{}',
  status text NOT NULL DEFAULT 'PENDING' CONSTRAINT ck_job__status CHECK (status IN ('PENDING','RUNNING','DONE','FAILED','DEAD')),
  run_at timestamptz NOT NULL DEFAULT now(), attempts integer NOT NULL DEFAULT 0, max_attempts integer NOT NULL DEFAULT 5,
  locked_at timestamptz, locked_by text, last_error text, dedupe_key text UNIQUE, finished_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX ix_job__run ON background_jobs (run_at) WHERE status = 'PENDING';
