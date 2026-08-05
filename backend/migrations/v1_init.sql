-- Fraud APP Analysis Platform
-- Initial schema (idempotent)

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

CREATE TABLE IF NOT EXISTS users (
  id VARCHAR(36) PRIMARY KEY,
  username VARCHAR(64) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  role ENUM('admin', 'user') NOT NULL DEFAULT 'user',
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uk_users_username (username),
  KEY idx_users_role (role)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS tasks (
  id VARCHAR(36) PRIMARY KEY,
  batch_id VARCHAR(36) NULL,
  task_description VARCHAR(255) NULL,
  priority INT NOT NULL DEFAULT 1,
  source_type ENUM('apk_upload', 'url_download') NOT NULL,
  source_name VARCHAR(512) NOT NULL,
  user_id VARCHAR(36) NULL,
  file_md5 VARCHAR(32) NULL,
  file_size BIGINT NULL,
  status ENUM(
    'downloading',
    'download_failed',
    'static_analyzing',
    'static_failed',
    'waiting_device',
    'dynamic_tracing',
    'dynamic_failed',
    'completed'
  ) NOT NULL,
  error_message TEXT NULL,
  apk_path VARCHAR(512) NULL,
  pcap_path VARCHAR(512) NULL,
  report_path VARCHAR(512) NULL,
  run_log_path VARCHAR(512) NULL,
  device_id VARCHAR(36) NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  KEY idx_tasks_md5 (file_md5),
  KEY idx_tasks_status (status),
  KEY idx_tasks_created_at (created_at),
  KEY idx_tasks_user_id (user_id),
  KEY idx_tasks_batch_id (batch_id),
  KEY idx_tasks_priority (priority)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS devices (
  id VARCHAR(36) PRIMARY KEY,
  name VARCHAR(128) NULL,
  serial VARCHAR(128) NOT NULL,
  android_version VARCHAR(32) NULL,
  model VARCHAR(128) NULL,
  resolution VARCHAR(32) NULL,
  status ENUM('online', 'offline', 'busy', 'quarantined') NOT NULL DEFAULT 'online',
  current_task_id VARCHAR(36) NULL,
  last_heartbeat_at DATETIME NULL,
  quarantine_reason TEXT NULL,
  quarantined_at DATETIME NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uk_devices_serial (serial),
  KEY idx_devices_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS static_results (
  task_id VARCHAR(36) PRIMARY KEY,
  app_name VARCHAR(256) NULL,
  package_name VARCHAR(256) NULL,
  version_name VARCHAR(64) NULL,
  version_code VARCHAR(32) NULL,
  icon_path VARCHAR(512) NULL,
  cert_md5 VARCHAR(128) NULL,
  cert_sha1 VARCHAR(128) NULL,
  cert_sha256 VARCHAR(128) NULL,
  cert_info JSON NULL,
  permissions JSON NULL,
  activities JSON NULL,
  services JSON NULL,
  providers JSON NULL,
  receivers JSON NULL,
  so_files JSON NULL,
  component_string LONGTEXT NULL,
  component_md5 VARCHAR(32) NULL,
  KEY idx_static_results_package (package_name),
  CONSTRAINT fk_static_results_task_id
    FOREIGN KEY (task_id) REFERENCES tasks(id)
    ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS sdk_results (
  id VARCHAR(36) PRIMARY KEY,
  task_id VARCHAR(36) NOT NULL,
  sdk_id VARCHAR(128) NOT NULL,
  sdk_name VARCHAR(256) NULL,
  sdk_type VARCHAR(128) NULL,
  vendor VARCHAR(256) NULL,
  package_prefix VARCHAR(256) NULL,
  source_file VARCHAR(1024) NULL,
  evidence TEXT NULL,
  param_name VARCHAR(128) NULL,
  param_value TEXT NULL,
  credential_source_file VARCHAR(1024) NULL,
  credential_line INT NULL,
  credential_evidence TEXT NULL,
  raw_finding JSON NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uk_sdk_results_task_sdk (task_id, sdk_id),
  KEY idx_sdk_results_task (task_id),
  KEY idx_sdk_results_sdk_id (sdk_id),
  CONSTRAINT fk_sdk_results_task_id
    FOREIGN KEY (task_id) REFERENCES tasks(id)
    ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS dynamic_results (
  id VARCHAR(36) PRIMARY KEY,
  task_id VARCHAR(36) NOT NULL,
  seq INT NOT NULL,
  action VARCHAR(256) NOT NULL,
  action_result VARCHAR(512) NULL,
  action_time DATETIME NULL,
  screenshot_before VARCHAR(512) NULL,
  screenshot_after VARCHAR(512) NULL,
  is_success TINYINT(1) NOT NULL DEFAULT 1,
  UNIQUE KEY uk_dynamic_results_task_seq (task_id, seq),
  KEY idx_dynamic_results_task (task_id),
  CONSTRAINT fk_dynamic_results_task_id
    FOREIGN KEY (task_id) REFERENCES tasks(id)
    ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS traffic_logs (
  id VARCHAR(36) PRIMARY KEY,
  task_id VARCHAR(36) NOT NULL,
  dynamic_result_id VARCHAR(36) NULL,
  seq INT NOT NULL,
  src_ip VARCHAR(45) NOT NULL,
  dst_ip VARCHAR(45) NOT NULL,
  src_port SMALLINT UNSIGNED NULL,
  dst_port SMALLINT UNSIGNED NULL,
  protocol VARCHAR(32) NOT NULL,
  domain VARCHAR(512) NULL,
  url TEXT NULL,
  resolved_ip VARCHAR(45) NULL,
  ip_country VARCHAR(128) NULL,
  is_up TINYINT(1) NOT NULL DEFAULT 0,
  is_real_controller TINYINT(1) NOT NULL DEFAULT 0,
  KEY idx_traffic_logs_task (task_id),
  KEY idx_traffic_logs_dynamic_result_id (dynamic_result_id),
  CONSTRAINT fk_traffic_logs_task_id
    FOREIGN KEY (task_id) REFERENCES tasks(id)
    ON DELETE CASCADE,
  CONSTRAINT fk_traffic_logs_dynamic_result_id
    FOREIGN KEY (dynamic_result_id) REFERENCES dynamic_results(id)
    ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS frida_logs (
  id VARCHAR(36) PRIMARY KEY,
  task_id VARCHAR(36) NOT NULL,
  dynamic_result_id VARCHAR(36) NULL,
  seq INT NOT NULL,
  event_time DATETIME NULL,
  rule_id VARCHAR(128) NULL,
  class_name VARCHAR(256) NULL,
  method_name VARCHAR(128) NULL,
  signature VARCHAR(512) NULL,
  arg_index INT NULL,
  arg_value TEXT NULL,
  retval TEXT NULL,
  KEY idx_frida_logs_task (task_id),
  KEY idx_frida_logs_dynamic_result_id (dynamic_result_id),
  CONSTRAINT fk_frida_logs_task_id
    FOREIGN KEY (task_id) REFERENCES tasks(id)
    ON DELETE CASCADE,
  CONSTRAINT fk_frida_logs_dynamic_result_id
    FOREIGN KEY (dynamic_result_id) REFERENCES dynamic_results(id)
    ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Backward-compatible device quarantine state for existing tables.
SET @devices_status_needs_quarantined := (
  SELECT COUNT(*) FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'devices'
    AND column_name = 'status'
    AND LOCATE('''quarantined''', column_type) = 0
);
SET @sql_devices_status_needs_quarantined := IF(
  @devices_status_needs_quarantined > 0,
  'ALTER TABLE devices MODIFY COLUMN status ENUM(''online'', ''offline'', ''busy'', ''quarantined'') NOT NULL DEFAULT ''online''',
  'SELECT 1'
);
PREPARE stmt_devices_status_needs_quarantined FROM @sql_devices_status_needs_quarantined;
EXECUTE stmt_devices_status_needs_quarantined;
DEALLOCATE PREPARE stmt_devices_status_needs_quarantined;

SET @devices_quarantine_reason_col := (
  SELECT COUNT(*) FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'devices'
    AND column_name = 'quarantine_reason'
);
SET @sql_devices_quarantine_reason_col := IF(
  @devices_quarantine_reason_col = 0,
  'ALTER TABLE devices ADD COLUMN quarantine_reason TEXT NULL AFTER last_heartbeat_at',
  'SELECT 1'
);
PREPARE stmt_devices_quarantine_reason_col FROM @sql_devices_quarantine_reason_col;
EXECUTE stmt_devices_quarantine_reason_col;
DEALLOCATE PREPARE stmt_devices_quarantine_reason_col;

SET @devices_quarantined_at_col := (
  SELECT COUNT(*) FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'devices'
    AND column_name = 'quarantined_at'
);
SET @sql_devices_quarantined_at_col := IF(
  @devices_quarantined_at_col = 0,
  'ALTER TABLE devices ADD COLUMN quarantined_at DATETIME NULL AFTER quarantine_reason',
  'SELECT 1'
);
PREPARE stmt_devices_quarantined_at_col FROM @sql_devices_quarantined_at_col;
EXECUTE stmt_devices_quarantined_at_col;
DEALLOCATE PREPARE stmt_devices_quarantined_at_col;

-- Add foreign keys that create a circular reference, in an idempotent way.
SET @fk_tasks_device := (
  SELECT COUNT(*) FROM information_schema.table_constraints
  WHERE constraint_schema = DATABASE()
    AND table_name = 'tasks'
    AND constraint_name = 'fk_tasks_device_id'
    AND constraint_type = 'FOREIGN KEY'
);
SET @sql_tasks_device := IF(
  @fk_tasks_device = 0,
  'ALTER TABLE tasks ADD CONSTRAINT fk_tasks_device_id FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE SET NULL',
  'SELECT 1'
);
PREPARE stmt_tasks_device FROM @sql_tasks_device;
EXECUTE stmt_tasks_device;
DEALLOCATE PREPARE stmt_tasks_device;

SET @fk_tasks_user := (
  SELECT COUNT(*) FROM information_schema.table_constraints
  WHERE constraint_schema = DATABASE()
    AND table_name = 'tasks'
    AND constraint_name = 'fk_tasks_user_id'
    AND constraint_type = 'FOREIGN KEY'
);
SET @sql_tasks_user := IF(
  @fk_tasks_user = 0,
  'ALTER TABLE tasks ADD CONSTRAINT fk_tasks_user_id FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL',
  'SELECT 1'
);
PREPARE stmt_tasks_user FROM @sql_tasks_user;
EXECUTE stmt_tasks_user;
DEALLOCATE PREPARE stmt_tasks_user;

SET @fk_devices_task := (
  SELECT COUNT(*) FROM information_schema.table_constraints
  WHERE constraint_schema = DATABASE()
    AND table_name = 'devices'
    AND constraint_name = 'fk_devices_current_task_id'
    AND constraint_type = 'FOREIGN KEY'
);
SET @sql_devices_task := IF(
  @fk_devices_task = 0,
  'ALTER TABLE devices ADD CONSTRAINT fk_devices_current_task_id FOREIGN KEY (current_task_id) REFERENCES tasks(id) ON DELETE SET NULL',
  'SELECT 1'
);
PREPARE stmt_devices_task FROM @sql_devices_task;
EXECUTE stmt_devices_task;
DEALLOCATE PREPARE stmt_devices_task;

-- Backward-compatible traffic_logs.dynamic_result_id upgrade for existing tables.
SET @traffic_logs_dynamic_result_col := (
  SELECT COUNT(*) FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'traffic_logs'
    AND column_name = 'dynamic_result_id'
);
SET @sql_traffic_logs_dynamic_result_col := IF(
  @traffic_logs_dynamic_result_col = 0,
  'ALTER TABLE traffic_logs ADD COLUMN dynamic_result_id VARCHAR(36) NULL AFTER task_id',
  'SELECT 1'
);
PREPARE stmt_traffic_logs_dynamic_result_col FROM @sql_traffic_logs_dynamic_result_col;
EXECUTE stmt_traffic_logs_dynamic_result_col;
DEALLOCATE PREPARE stmt_traffic_logs_dynamic_result_col;

-- Backfill mapping using task_id + seq where possible.
UPDATE traffic_logs tl
INNER JOIN dynamic_results dr
  ON dr.task_id = tl.task_id
 AND dr.seq = tl.seq
SET tl.dynamic_result_id = dr.id
WHERE tl.dynamic_result_id IS NULL;

SET @traffic_logs_dynamic_result_idx := (
  SELECT COUNT(*) FROM information_schema.statistics
  WHERE table_schema = DATABASE()
    AND table_name = 'traffic_logs'
    AND index_name = 'idx_traffic_logs_dynamic_result_id'
);
SET @sql_traffic_logs_dynamic_result_idx := IF(
  @traffic_logs_dynamic_result_idx = 0,
  'ALTER TABLE traffic_logs ADD KEY idx_traffic_logs_dynamic_result_id (dynamic_result_id)',
  'SELECT 1'
);
PREPARE stmt_traffic_logs_dynamic_result_idx FROM @sql_traffic_logs_dynamic_result_idx;
EXECUTE stmt_traffic_logs_dynamic_result_idx;
DEALLOCATE PREPARE stmt_traffic_logs_dynamic_result_idx;

SET @fk_traffic_logs_dynamic_result := (
  SELECT COUNT(*) FROM information_schema.table_constraints
  WHERE constraint_schema = DATABASE()
    AND table_name = 'traffic_logs'
    AND constraint_name = 'fk_traffic_logs_dynamic_result_id'
    AND constraint_type = 'FOREIGN KEY'
);
SET @sql_fk_traffic_logs_dynamic_result := IF(
  @fk_traffic_logs_dynamic_result = 0,
  'ALTER TABLE traffic_logs ADD CONSTRAINT fk_traffic_logs_dynamic_result_id FOREIGN KEY (dynamic_result_id) REFERENCES dynamic_results(id) ON DELETE CASCADE',
  'SELECT 1'
);
PREPARE stmt_fk_traffic_logs_dynamic_result FROM @sql_fk_traffic_logs_dynamic_result;
EXECUTE stmt_fk_traffic_logs_dynamic_result;
DEALLOCATE PREPARE stmt_fk_traffic_logs_dynamic_result;

-- Backward-compatible traffic_logs IP country column.
SET @traffic_logs_ip_country_col := (
  SELECT COUNT(*) FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'traffic_logs'
    AND column_name = 'ip_country'
);
SET @sql_traffic_logs_ip_country_col := IF(
  @traffic_logs_ip_country_col = 0,
  'ALTER TABLE traffic_logs ADD COLUMN ip_country VARCHAR(128) NULL AFTER resolved_ip',
  'SELECT 1'
);
PREPARE stmt_traffic_logs_ip_country_col FROM @sql_traffic_logs_ip_country_col;
EXECUTE stmt_traffic_logs_ip_country_col;
DEALLOCATE PREPARE stmt_traffic_logs_ip_country_col;

-- Backward-compatible traffic_logs real-controller tagging column.
SET @traffic_logs_is_up_col := (
  SELECT COUNT(*) FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'traffic_logs'
    AND column_name = 'is_up'
);
SET @sql_traffic_logs_is_up_col := IF(
  @traffic_logs_is_up_col = 0,
  'ALTER TABLE traffic_logs ADD COLUMN is_up TINYINT(1) NOT NULL DEFAULT 0 AFTER ip_country',
  'SELECT 1'
);
PREPARE stmt_traffic_logs_is_up_col FROM @sql_traffic_logs_is_up_col;
EXECUTE stmt_traffic_logs_is_up_col;
DEALLOCATE PREPARE stmt_traffic_logs_is_up_col;

-- Backward-compatible traffic_logs real-controller tagging column.
SET @traffic_logs_real_controller_col := (
  SELECT COUNT(*) FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'traffic_logs'
    AND column_name = 'is_real_controller'
);
SET @sql_traffic_logs_real_controller_col := IF(
  @traffic_logs_real_controller_col = 0,
  'ALTER TABLE traffic_logs ADD COLUMN is_real_controller TINYINT(1) NOT NULL DEFAULT 0 AFTER ip_country',
  'SELECT 1'
);
PREPARE stmt_traffic_logs_real_controller_col FROM @sql_traffic_logs_real_controller_col;
EXECUTE stmt_traffic_logs_real_controller_col;
DEALLOCATE PREPARE stmt_traffic_logs_real_controller_col;

-- Backward-compatible users.role upgrade for existing tables.
SET @users_role_col := (
  SELECT COUNT(*) FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'users'
    AND column_name = 'role'
);
SET @sql_users_role_col := IF(
  @users_role_col = 0,
  'ALTER TABLE users ADD COLUMN role ENUM(''admin'', ''user'') NOT NULL DEFAULT ''user'' AFTER password_hash',
  'SELECT 1'
);
PREPARE stmt_users_role_col FROM @sql_users_role_col;
EXECUTE stmt_users_role_col;
DEALLOCATE PREPARE stmt_users_role_col;

SET @users_role_idx := (
  SELECT COUNT(*) FROM information_schema.statistics
  WHERE table_schema = DATABASE()
    AND table_name = 'users'
    AND index_name = 'idx_users_role'
);
SET @sql_users_role_idx := IF(
  @users_role_idx = 0,
  'ALTER TABLE users ADD KEY idx_users_role (role)',
  'SELECT 1'
);
PREPARE stmt_users_role_idx FROM @sql_users_role_idx;
EXECUTE stmt_users_role_idx;
DEALLOCATE PREPARE stmt_users_role_idx;

-- Backward-compatible tasks.batch_id upgrade for existing tables.
SET @tasks_batch_id_col := (
  SELECT COUNT(*) FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'tasks'
    AND column_name = 'batch_id'
);
SET @sql_tasks_batch_id_col := IF(
  @tasks_batch_id_col = 0,
  'ALTER TABLE tasks ADD COLUMN batch_id VARCHAR(36) NULL AFTER id',
  'SELECT 1'
);
PREPARE stmt_tasks_batch_id_col FROM @sql_tasks_batch_id_col;
EXECUTE stmt_tasks_batch_id_col;
DEALLOCATE PREPARE stmt_tasks_batch_id_col;

SET @tasks_desc_col := (
  SELECT COUNT(*) FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'tasks'
    AND column_name = 'task_description'
);
SET @sql_tasks_desc_col := IF(
  @tasks_desc_col = 0,
  'ALTER TABLE tasks ADD COLUMN task_description VARCHAR(255) NULL AFTER batch_id',
  'SELECT 1'
);
PREPARE stmt_tasks_desc_col FROM @sql_tasks_desc_col;
EXECUTE stmt_tasks_desc_col;
DEALLOCATE PREPARE stmt_tasks_desc_col;

SET @tasks_batch_id_idx := (
  SELECT COUNT(*) FROM information_schema.statistics
  WHERE table_schema = DATABASE()
    AND table_name = 'tasks'
    AND index_name = 'idx_tasks_batch_id'
);
SET @sql_tasks_batch_id_idx := IF(
  @tasks_batch_id_idx = 0,
  'ALTER TABLE tasks ADD KEY idx_tasks_batch_id (batch_id)',
  'SELECT 1'
);
PREPARE stmt_tasks_batch_id_idx FROM @sql_tasks_batch_id_idx;
EXECUTE stmt_tasks_batch_id_idx;
DEALLOCATE PREPARE stmt_tasks_batch_id_idx;

SET @tasks_priority_col := (
  SELECT COUNT(*) FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'tasks'
    AND column_name = 'priority'
);
SET @sql_tasks_priority_col := IF(
  @tasks_priority_col = 0,
  'ALTER TABLE tasks ADD COLUMN priority INT NOT NULL DEFAULT 1 AFTER task_description',
  'SELECT 1'
);
PREPARE stmt_tasks_priority_col FROM @sql_tasks_priority_col;
EXECUTE stmt_tasks_priority_col;
DEALLOCATE PREPARE stmt_tasks_priority_col;

SET @tasks_priority_idx := (
  SELECT COUNT(*) FROM information_schema.statistics
  WHERE table_schema = DATABASE()
    AND table_name = 'tasks'
    AND index_name = 'idx_tasks_priority'
);
SET @sql_tasks_priority_idx := IF(
  @tasks_priority_idx = 0,
  'ALTER TABLE tasks ADD KEY idx_tasks_priority (priority)',
  'SELECT 1'
);
PREPARE stmt_tasks_priority_idx FROM @sql_tasks_priority_idx;
EXECUTE stmt_tasks_priority_idx;
DEALLOCATE PREPARE stmt_tasks_priority_idx;

-- Backward-compatible static_results component fingerprint columns.
SET @static_results_component_string_col := (
  SELECT COUNT(*) FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'component_string'
);
SET @sql_static_results_component_string_col := IF(
  @static_results_component_string_col = 0,
  'ALTER TABLE static_results ADD COLUMN component_string LONGTEXT NULL AFTER so_files',
  'SELECT 1'
);
PREPARE stmt_static_results_component_string_col FROM @sql_static_results_component_string_col;
EXECUTE stmt_static_results_component_string_col;
DEALLOCATE PREPARE stmt_static_results_component_string_col;

SET @static_results_component_md5_col := (
  SELECT COUNT(*) FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'component_md5'
);
SET @sql_static_results_component_md5_col := IF(
  @static_results_component_md5_col = 0,
  'ALTER TABLE static_results ADD COLUMN component_md5 VARCHAR(32) NULL AFTER component_string',
  'SELECT 1'
);
PREPARE stmt_static_results_component_md5_col FROM @sql_static_results_component_md5_col;
EXECUTE stmt_static_results_component_md5_col;
DEALLOCATE PREPARE stmt_static_results_component_md5_col;

-- BroadcastReceiver components.
SET @static_results_receivers_col := (
  SELECT COUNT(*) FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'receivers'
);
SET @sql_static_results_receivers_col := IF(
  @static_results_receivers_col = 0,
  'ALTER TABLE static_results ADD COLUMN receivers JSON NULL AFTER providers',
  'SELECT 1'
);
PREPARE stmt_static_results_receivers_col FROM @sql_static_results_receivers_col;
EXECUTE stmt_static_results_receivers_col;
DEALLOCATE PREPARE stmt_static_results_receivers_col;

-- Full signing certificate info (JSON).
SET @static_results_cert_info_col := (
  SELECT COUNT(*) FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'cert_info'
);
SET @sql_static_results_cert_info_col := IF(
  @static_results_cert_info_col = 0,
  'ALTER TABLE static_results ADD COLUMN cert_info JSON NULL AFTER cert_sha256',
  'SELECT 1'
);
PREPARE stmt_static_results_cert_info_col FROM @sql_static_results_cert_info_col;
EXECUTE stmt_static_results_cert_info_col;
DEALLOCATE PREPARE stmt_static_results_cert_info_col;

-- Static analysis development framework detection fields.
SET @static_results_framework_name_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'framework_name'
);
SET @sql_static_results_framework_name_col := IF(
  @static_results_framework_name_col = 0,
  'ALTER TABLE static_results ADD COLUMN framework_name VARCHAR(128) NULL AFTER component_md5',
  'SELECT 1'
);
PREPARE stmt_static_results_framework_name_col FROM @sql_static_results_framework_name_col;
EXECUTE stmt_static_results_framework_name_col;
DEALLOCATE PREPARE stmt_static_results_framework_name_col;

SET @static_results_framework_matches_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'framework_matches'
);
SET @sql_static_results_framework_matches_col := IF(
  @static_results_framework_matches_col = 0,
  'ALTER TABLE static_results ADD COLUMN framework_matches JSON NULL AFTER framework_name',
  'SELECT 1'
);
PREPARE stmt_static_results_framework_matches_col FROM @sql_static_results_framework_matches_col;
EXECUTE stmt_static_results_framework_matches_col;
DEALLOCATE PREPARE stmt_static_results_framework_matches_col;

-- Static analysis hardening / obfuscation detection and unpack result fields.
SET @static_results_is_packed_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'is_packed'
);
SET @sql_static_results_is_packed_col := IF(
  @static_results_is_packed_col = 0,
  'ALTER TABLE static_results ADD COLUMN is_packed TINYINT(1) NOT NULL DEFAULT 0 AFTER component_md5',
  'SELECT 1'
);
PREPARE stmt_static_results_is_packed_col FROM @sql_static_results_is_packed_col;
EXECUTE stmt_static_results_is_packed_col;
DEALLOCATE PREPARE stmt_static_results_is_packed_col;

SET @static_results_packer_vendor_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'packer_vendor'
);
SET @sql_static_results_packer_vendor_col := IF(
  @static_results_packer_vendor_col = 0,
  'ALTER TABLE static_results ADD COLUMN packer_vendor VARCHAR(512) NULL AFTER is_packed',
  'SELECT 1'
);
PREPARE stmt_static_results_packer_vendor_col FROM @sql_static_results_packer_vendor_col;
EXECUTE stmt_static_results_packer_vendor_col;
DEALLOCATE PREPARE stmt_static_results_packer_vendor_col;

SET @static_results_packer_vendors_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'packer_vendors'
);
SET @sql_static_results_packer_vendors_col := IF(
  @static_results_packer_vendors_col = 0,
  'ALTER TABLE static_results ADD COLUMN packer_vendors JSON NULL AFTER packer_vendor',
  'SELECT 1'
);
PREPARE stmt_static_results_packer_vendors_col FROM @sql_static_results_packer_vendors_col;
EXECUTE stmt_static_results_packer_vendors_col;
DEALLOCATE PREPARE stmt_static_results_packer_vendors_col;

SET @static_results_packer_details_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'packer_details'
);
SET @sql_static_results_packer_details_col := IF(
  @static_results_packer_details_col = 0,
  'ALTER TABLE static_results ADD COLUMN packer_details JSON NULL AFTER packer_vendors',
  'SELECT 1'
);
PREPARE stmt_static_results_packer_details_col FROM @sql_static_results_packer_details_col;
EXECUTE stmt_static_results_packer_details_col;
DEALLOCATE PREPARE stmt_static_results_packer_details_col;

SET @static_results_is_obfuscated_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'is_obfuscated'
);
SET @sql_static_results_is_obfuscated_col := IF(
  @static_results_is_obfuscated_col = 0,
  'ALTER TABLE static_results ADD COLUMN is_obfuscated TINYINT(1) NOT NULL DEFAULT 0 AFTER packer_details',
  'SELECT 1'
);
PREPARE stmt_static_results_is_obfuscated_col FROM @sql_static_results_is_obfuscated_col;
EXECUTE stmt_static_results_is_obfuscated_col;
DEALLOCATE PREPARE stmt_static_results_is_obfuscated_col;

SET @static_results_obfuscation_vendor_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'obfuscation_vendor'
);
SET @sql_static_results_obfuscation_vendor_col := IF(
  @static_results_obfuscation_vendor_col = 0,
  'ALTER TABLE static_results ADD COLUMN obfuscation_vendor VARCHAR(512) NULL AFTER is_obfuscated',
  'SELECT 1'
);
PREPARE stmt_static_results_obfuscation_vendor_col FROM @sql_static_results_obfuscation_vendor_col;
EXECUTE stmt_static_results_obfuscation_vendor_col;
DEALLOCATE PREPARE stmt_static_results_obfuscation_vendor_col;

SET @static_results_obfuscation_vendors_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'obfuscation_vendors'
);
SET @sql_static_results_obfuscation_vendors_col := IF(
  @static_results_obfuscation_vendors_col = 0,
  'ALTER TABLE static_results ADD COLUMN obfuscation_vendors JSON NULL AFTER obfuscation_vendor',
  'SELECT 1'
);
PREPARE stmt_static_results_obfuscation_vendors_col FROM @sql_static_results_obfuscation_vendors_col;
EXECUTE stmt_static_results_obfuscation_vendors_col;
DEALLOCATE PREPARE stmt_static_results_obfuscation_vendors_col;

SET @static_results_obfuscator_details_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'obfuscator_details'
);
SET @sql_static_results_obfuscator_details_col := IF(
  @static_results_obfuscator_details_col = 0,
  'ALTER TABLE static_results ADD COLUMN obfuscator_details JSON NULL AFTER obfuscation_vendors',
  'SELECT 1'
);
PREPARE stmt_static_results_obfuscator_details_col FROM @sql_static_results_obfuscator_details_col;
EXECUTE stmt_static_results_obfuscator_details_col;
DEALLOCATE PREPARE stmt_static_results_obfuscator_details_col;

SET @static_results_protection_detect_error_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'protection_detect_error'
);
SET @sql_static_results_protection_detect_error_col := IF(
  @static_results_protection_detect_error_col = 0,
  'ALTER TABLE static_results ADD COLUMN protection_detect_error TEXT NULL AFTER obfuscator_details',
  'SELECT 1'
);
PREPARE stmt_static_results_protection_detect_error_col FROM @sql_static_results_protection_detect_error_col;
EXECUTE stmt_static_results_protection_detect_error_col;
DEALLOCATE PREPARE stmt_static_results_protection_detect_error_col;

SET @static_results_unpack_archive_path_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'unpack_archive_path'
);
SET @sql_static_results_unpack_archive_path_col := IF(
  @static_results_unpack_archive_path_col = 0,
  'ALTER TABLE static_results ADD COLUMN unpack_archive_path VARCHAR(512) NULL AFTER protection_detect_error',
  'SELECT 1'
);
PREPARE stmt_static_results_unpack_archive_path_col FROM @sql_static_results_unpack_archive_path_col;
EXECUTE stmt_static_results_unpack_archive_path_col;
DEALLOCATE PREPARE stmt_static_results_unpack_archive_path_col;

SET @static_results_unpack_error_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'unpack_error'
);
SET @sql_static_results_unpack_error_col := IF(
  @static_results_unpack_error_col = 0,
  'ALTER TABLE static_results ADD COLUMN unpack_error TEXT NULL AFTER unpack_archive_path',
  'SELECT 1'
);
PREPARE stmt_static_results_unpack_error_col FROM @sql_static_results_unpack_error_col;
EXECUTE stmt_static_results_unpack_error_col;
DEALLOCATE PREPARE stmt_static_results_unpack_error_col;

-- Source IOC extraction fields for phone/email/url found in APK source assets/code.
SET @static_results_source_phones_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'source_phones'
);
SET @sql_static_results_source_phones_col := IF(
  @static_results_source_phones_col = 0,
  'ALTER TABLE static_results ADD COLUMN source_phones JSON NULL AFTER unpack_error',
  'SELECT 1'
);
PREPARE stmt_static_results_source_phones_col FROM @sql_static_results_source_phones_col;
EXECUTE stmt_static_results_source_phones_col;
DEALLOCATE PREPARE stmt_static_results_source_phones_col;

SET @static_results_source_emails_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'source_emails'
);
SET @sql_static_results_source_emails_col := IF(
  @static_results_source_emails_col = 0,
  'ALTER TABLE static_results ADD COLUMN source_emails JSON NULL AFTER source_phones',
  'SELECT 1'
);
PREPARE stmt_static_results_source_emails_col FROM @sql_static_results_source_emails_col;
EXECUTE stmt_static_results_source_emails_col;
DEALLOCATE PREPARE stmt_static_results_source_emails_col;

SET @static_results_source_urls_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'source_urls'
);
SET @sql_static_results_source_urls_col := IF(
  @static_results_source_urls_col = 0,
  'ALTER TABLE static_results ADD COLUMN source_urls JSON NULL AFTER source_emails',
  'SELECT 1'
);
PREPARE stmt_static_results_source_urls_col FROM @sql_static_results_source_urls_col;
EXECUTE stmt_static_results_source_urls_col;
DEALLOCATE PREPARE stmt_static_results_source_urls_col;

-- DCloud/uni-app and Flutter details are stored as queryable columns, not aggregate JSON blobs.
SET @static_results_dcloud_tech_type_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'dcloud_tech_type'
);
SET @sql_static_results_dcloud_tech_type_col := IF(
  @static_results_dcloud_tech_type_col = 0,
  'ALTER TABLE static_results ADD COLUMN dcloud_tech_type VARCHAR(64) NULL AFTER source_urls',
  'SELECT 1'
);
PREPARE stmt_static_results_dcloud_tech_type_col FROM @sql_static_results_dcloud_tech_type_col;
EXECUTE stmt_static_results_dcloud_tech_type_col;
DEALLOCATE PREPARE stmt_static_results_dcloud_tech_type_col;

SET @static_results_dcloud_appids_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'dcloud_appids'
);
SET @sql_static_results_dcloud_appids_col := IF(
  @static_results_dcloud_appids_col = 0,
  'ALTER TABLE static_results ADD COLUMN dcloud_appids JSON NULL AFTER dcloud_tech_type',
  'SELECT 1'
);
PREPARE stmt_static_results_dcloud_appids_col FROM @sql_static_results_dcloud_appids_col;
EXECUTE stmt_static_results_dcloud_appids_col;
DEALLOCATE PREPARE stmt_static_results_dcloud_appids_col;

SET @static_results_dcloud_pages_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'dcloud_pages'
);
SET @sql_static_results_dcloud_pages_col := IF(
  @static_results_dcloud_pages_col = 0,
  'ALTER TABLE static_results ADD COLUMN dcloud_pages JSON NULL AFTER dcloud_appids',
  'SELECT 1'
);
PREPARE stmt_static_results_dcloud_pages_col FROM @sql_static_results_dcloud_pages_col;
EXECUTE stmt_static_results_dcloud_pages_col;
DEALLOCATE PREPARE stmt_static_results_dcloud_pages_col;

SET @static_results_dcloud_api_routes_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'dcloud_api_routes'
);
SET @sql_static_results_dcloud_api_routes_col := IF(
  @static_results_dcloud_api_routes_col = 0,
  'ALTER TABLE static_results ADD COLUMN dcloud_api_routes JSON NULL AFTER dcloud_pages',
  'SELECT 1'
);
PREPARE stmt_static_results_dcloud_api_routes_col FROM @sql_static_results_dcloud_api_routes_col;
EXECUTE stmt_static_results_dcloud_api_routes_col;
DEALLOCATE PREPARE stmt_static_results_dcloud_api_routes_col;

SET @static_results_dcloud_remote_service_urls_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'dcloud_remote_service_urls'
);
SET @sql_static_results_dcloud_remote_service_urls_col := IF(
  @static_results_dcloud_remote_service_urls_col = 0,
  'ALTER TABLE static_results ADD COLUMN dcloud_remote_service_urls JSON NULL AFTER dcloud_api_routes',
  'SELECT 1'
);
PREPARE stmt_static_results_dcloud_remote_service_urls_col FROM @sql_static_results_dcloud_remote_service_urls_col;
EXECUTE stmt_static_results_dcloud_remote_service_urls_col;
DEALLOCATE PREPARE stmt_static_results_dcloud_remote_service_urls_col;

SET @static_results_dcloud_remote_service_domains_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'dcloud_remote_service_domains'
);
SET @sql_static_results_dcloud_remote_service_domains_col := IF(
  @static_results_dcloud_remote_service_domains_col = 0,
  'ALTER TABLE static_results ADD COLUMN dcloud_remote_service_domains JSON NULL AFTER dcloud_remote_service_urls',
  'SELECT 1'
);
PREPARE stmt_static_results_dcloud_remote_service_domains_col FROM @sql_static_results_dcloud_remote_service_domains_col;
EXECUTE stmt_static_results_dcloud_remote_service_domains_col;
DEALLOCATE PREPARE stmt_static_results_dcloud_remote_service_domains_col;

SET @static_results_dcloud_is_confused_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'dcloud_is_confused'
);
SET @sql_static_results_dcloud_is_confused_col := IF(
  @static_results_dcloud_is_confused_col = 0,
  'ALTER TABLE static_results ADD COLUMN dcloud_is_confused TINYINT(1) NULL AFTER dcloud_remote_service_domains',
  'SELECT 1'
);
PREPARE stmt_static_results_dcloud_is_confused_col FROM @sql_static_results_dcloud_is_confused_col;
EXECUTE stmt_static_results_dcloud_is_confused_col;
DEALLOCATE PREPARE stmt_static_results_dcloud_is_confused_col;

SET @static_results_flutter_primary_package_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'flutter_primary_package'
);
SET @sql_static_results_flutter_primary_package_col := IF(
  @static_results_flutter_primary_package_col = 0,
  'ALTER TABLE static_results ADD COLUMN flutter_primary_package VARCHAR(256) NULL AFTER dcloud_is_confused',
  'SELECT 1'
);
PREPARE stmt_static_results_flutter_primary_package_col FROM @sql_static_results_flutter_primary_package_col;
EXECUTE stmt_static_results_flutter_primary_package_col;
DEALLOCATE PREPARE stmt_static_results_flutter_primary_package_col;

SET @static_results_flutter_primary_entry_uri_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'flutter_primary_entry_uri'
);
SET @sql_static_results_flutter_primary_entry_uri_col := IF(
  @static_results_flutter_primary_entry_uri_col = 0,
  'ALTER TABLE static_results ADD COLUMN flutter_primary_entry_uri VARCHAR(1024) NULL AFTER flutter_primary_package',
  'SELECT 1'
);
PREPARE stmt_static_results_flutter_primary_entry_uri_col FROM @sql_static_results_flutter_primary_entry_uri_col;
EXECUTE stmt_static_results_flutter_primary_entry_uri_col;
DEALLOCATE PREPARE stmt_static_results_flutter_primary_entry_uri_col;

SET @static_results_flutter_library_uris_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'flutter_library_uris'
);
SET @sql_static_results_flutter_library_uris_col := IF(
  @static_results_flutter_library_uris_col = 0,
  'ALTER TABLE static_results ADD COLUMN flutter_library_uris JSON NULL AFTER flutter_primary_entry_uri',
  'SELECT 1'
);
PREPARE stmt_static_results_flutter_library_uris_col FROM @sql_static_results_flutter_library_uris_col;
EXECUTE stmt_static_results_flutter_library_uris_col;
DEALLOCATE PREPARE stmt_static_results_flutter_library_uris_col;

SET @static_results_flutter_primary_package_classes_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'flutter_primary_package_classes'
);
SET @sql_static_results_flutter_primary_package_classes_col := IF(
  @static_results_flutter_primary_package_classes_col = 0,
  'ALTER TABLE static_results ADD COLUMN flutter_primary_package_classes JSON NULL AFTER flutter_library_uris',
  'SELECT 1'
);
PREPARE stmt_static_results_flutter_primary_package_classes_col FROM @sql_static_results_flutter_primary_package_classes_col;
EXECUTE stmt_static_results_flutter_primary_package_classes_col;
DEALLOCATE PREPARE stmt_static_results_flutter_primary_package_classes_col;

SET @static_results_flutter_remote_service_urls_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'flutter_remote_service_urls'
);
SET @sql_static_results_flutter_remote_service_urls_col := IF(
  @static_results_flutter_remote_service_urls_col = 0,
  'ALTER TABLE static_results ADD COLUMN flutter_remote_service_urls JSON NULL AFTER flutter_primary_package_classes',
  'SELECT 1'
);
PREPARE stmt_static_results_flutter_remote_service_urls_col FROM @sql_static_results_flutter_remote_service_urls_col;
EXECUTE stmt_static_results_flutter_remote_service_urls_col;
DEALLOCATE PREPARE stmt_static_results_flutter_remote_service_urls_col;

SET @static_results_flutter_remote_service_domains_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'flutter_remote_service_domains'
);
SET @sql_static_results_flutter_remote_service_domains_col := IF(
  @static_results_flutter_remote_service_domains_col = 0,
  'ALTER TABLE static_results ADD COLUMN flutter_remote_service_domains JSON NULL AFTER flutter_remote_service_urls',
  'SELECT 1'
);
PREPARE stmt_static_results_flutter_remote_service_domains_col FROM @sql_static_results_flutter_remote_service_domains_col;
EXECUTE stmt_static_results_flutter_remote_service_domains_col;
DEALLOCATE PREPARE stmt_static_results_flutter_remote_service_domains_col;

SET @static_results_flutter_primary_remote_service_urls_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'flutter_primary_remote_service_urls'
);
SET @sql_static_results_flutter_primary_remote_service_urls_col := IF(
  @static_results_flutter_primary_remote_service_urls_col = 0,
  'ALTER TABLE static_results ADD COLUMN flutter_primary_remote_service_urls JSON NULL AFTER flutter_remote_service_domains',
  'SELECT 1'
);
PREPARE stmt_static_results_flutter_primary_remote_service_urls_col FROM @sql_static_results_flutter_primary_remote_service_urls_col;
EXECUTE stmt_static_results_flutter_primary_remote_service_urls_col;
DEALLOCATE PREPARE stmt_static_results_flutter_primary_remote_service_urls_col;

SET @static_results_flutter_primary_remote_service_domains_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'flutter_primary_remote_service_domains'
);
SET @sql_static_results_flutter_primary_remote_service_domains_col := IF(
  @static_results_flutter_primary_remote_service_domains_col = 0,
  'ALTER TABLE static_results ADD COLUMN flutter_primary_remote_service_domains JSON NULL AFTER flutter_primary_remote_service_urls',
  'SELECT 1'
);
PREPARE stmt_static_results_flutter_primary_remote_service_domains_col FROM @sql_static_results_flutter_primary_remote_service_domains_col;
EXECUTE stmt_static_results_flutter_primary_remote_service_domains_col;
DEALLOCATE PREPARE stmt_static_results_flutter_primary_remote_service_domains_col;

SET @static_results_flutter_dart_version_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'flutter_dart_version'
);
SET @sql_static_results_flutter_dart_version_col := IF(
  @static_results_flutter_dart_version_col = 0,
  'ALTER TABLE static_results ADD COLUMN flutter_dart_version VARCHAR(64) NULL AFTER flutter_primary_remote_service_domains',
  'SELECT 1'
);
PREPARE stmt_static_results_flutter_dart_version_col FROM @sql_static_results_flutter_dart_version_col;
EXECUTE stmt_static_results_flutter_dart_version_col;
DEALLOCATE PREPARE stmt_static_results_flutter_dart_version_col;

SET @static_results_flutter_blutter_backend_version_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'flutter_blutter_backend_version'
);
SET @sql_static_results_flutter_blutter_backend_version_col := IF(
  @static_results_flutter_blutter_backend_version_col = 0,
  'ALTER TABLE static_results ADD COLUMN flutter_blutter_backend_version VARCHAR(64) NULL AFTER flutter_dart_version',
  'SELECT 1'
);
PREPARE stmt_static_results_flutter_blutter_backend_version_col FROM @sql_static_results_flutter_blutter_backend_version_col;
EXECUTE stmt_static_results_flutter_blutter_backend_version_col;
DEALLOCATE PREPARE stmt_static_results_flutter_blutter_backend_version_col;

-- Backfill split columns from legacy aggregate JSON blobs before dropping them.
SET @static_results_flutter_remote_service_ips_drop_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'flutter_remote_service_ips'
);
SET @sql_static_results_flutter_remote_service_ips_drop_col := IF(
  @static_results_flutter_remote_service_ips_drop_col = 1,
  'ALTER TABLE static_results DROP COLUMN flutter_remote_service_ips',
  'SELECT 1'
);
PREPARE stmt_static_results_flutter_remote_service_ips_drop_col FROM @sql_static_results_flutter_remote_service_ips_drop_col;
EXECUTE stmt_static_results_flutter_remote_service_ips_drop_col;
DEALLOCATE PREPARE stmt_static_results_flutter_remote_service_ips_drop_col;

SET @static_results_flutter_primary_remote_service_ips_drop_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'flutter_primary_remote_service_ips'
);
SET @sql_static_results_flutter_primary_remote_service_ips_drop_col := IF(
  @static_results_flutter_primary_remote_service_ips_drop_col = 1,
  'ALTER TABLE static_results DROP COLUMN flutter_primary_remote_service_ips',
  'SELECT 1'
);
PREPARE stmt_static_results_flutter_primary_remote_service_ips_drop_col FROM @sql_static_results_flutter_primary_remote_service_ips_drop_col;
EXECUTE stmt_static_results_flutter_primary_remote_service_ips_drop_col;
DEALLOCATE PREPARE stmt_static_results_flutter_primary_remote_service_ips_drop_col;

SET @static_results_dcloud_info_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'dcloud_info'
);
SET @sql_static_results_dcloud_info_backfill := IF(
  @static_results_dcloud_info_col = 1,
  'UPDATE static_results SET dcloud_tech_type = COALESCE(dcloud_tech_type, JSON_UNQUOTE(JSON_EXTRACT(dcloud_info, ''$.tech_type''))), dcloud_appids = COALESCE(dcloud_appids, JSON_EXTRACT(dcloud_info, ''$.appids'')), dcloud_pages = COALESCE(dcloud_pages, JSON_EXTRACT(dcloud_info, ''$.pages'')), dcloud_api_routes = COALESCE(dcloud_api_routes, JSON_EXTRACT(dcloud_info, ''$.api_routes'')), dcloud_remote_service_urls = COALESCE(dcloud_remote_service_urls, JSON_EXTRACT(dcloud_info, ''$.remote_service_urls'')), dcloud_remote_service_domains = COALESCE(dcloud_remote_service_domains, JSON_EXTRACT(dcloud_info, ''$.remote_service_domains'')), dcloud_is_confused = COALESCE(dcloud_is_confused, CAST(JSON_UNQUOTE(JSON_EXTRACT(dcloud_info, ''$.is_confused'')) AS UNSIGNED)) WHERE dcloud_info IS NOT NULL',
  'SELECT 1'
);
PREPARE stmt_static_results_dcloud_info_backfill FROM @sql_static_results_dcloud_info_backfill;
EXECUTE stmt_static_results_dcloud_info_backfill;
DEALLOCATE PREPARE stmt_static_results_dcloud_info_backfill;

SET @static_results_flutter_info_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'flutter_info'
);
SET @sql_static_results_flutter_info_backfill := IF(
  @static_results_flutter_info_col = 1,
  'UPDATE static_results SET flutter_primary_package = COALESCE(flutter_primary_package, JSON_UNQUOTE(JSON_EXTRACT(flutter_info, ''$.primary_package''))), flutter_primary_entry_uri = COALESCE(flutter_primary_entry_uri, JSON_UNQUOTE(JSON_EXTRACT(flutter_info, ''$.primary_entry_uri''))), flutter_library_uris = COALESCE(flutter_library_uris, JSON_EXTRACT(flutter_info, ''$.library_uris'')), flutter_primary_package_classes = COALESCE(flutter_primary_package_classes, JSON_EXTRACT(flutter_info, ''$.primary_package_classes'')), flutter_dart_version = COALESCE(flutter_dart_version, JSON_UNQUOTE(JSON_EXTRACT(flutter_info, ''$.dart_version''))), flutter_blutter_backend_version = COALESCE(flutter_blutter_backend_version, JSON_UNQUOTE(JSON_EXTRACT(flutter_info, ''$.blutter_backend_version''))) WHERE flutter_info IS NOT NULL',
  'SELECT 1'
);
PREPARE stmt_static_results_flutter_info_backfill FROM @sql_static_results_flutter_info_backfill;
EXECUTE stmt_static_results_flutter_info_backfill;
DEALLOCATE PREPARE stmt_static_results_flutter_info_backfill;

SET @static_results_dcloud_info_drop_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'dcloud_info'
);
SET @sql_static_results_dcloud_info_drop_col := IF(
  @static_results_dcloud_info_drop_col = 1,
  'ALTER TABLE static_results DROP COLUMN dcloud_info',
  'SELECT 1'
);
PREPARE stmt_static_results_dcloud_info_drop_col FROM @sql_static_results_dcloud_info_drop_col;
EXECUTE stmt_static_results_dcloud_info_drop_col;
DEALLOCATE PREPARE stmt_static_results_dcloud_info_drop_col;

SET @static_results_flutter_info_drop_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'flutter_info'
);
SET @sql_static_results_flutter_info_drop_col := IF(
  @static_results_flutter_info_drop_col = 1,
  'ALTER TABLE static_results DROP COLUMN flutter_info',
  'SELECT 1'
);
PREPARE stmt_static_results_flutter_info_drop_col FROM @sql_static_results_flutter_info_drop_col;
EXECUTE stmt_static_results_flutter_info_drop_col;
DEALLOCATE PREPARE stmt_static_results_flutter_info_drop_col;

SET @static_results_dcloud_confusion_details_drop_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'dcloud_confusion_details'
);
SET @sql_static_results_dcloud_confusion_details_drop_col := IF(
  @static_results_dcloud_confusion_details_drop_col = 1,
  'ALTER TABLE static_results DROP COLUMN dcloud_confusion_details',
  'SELECT 1'
);
PREPARE stmt_static_results_dcloud_confusion_details_drop_col FROM @sql_static_results_dcloud_confusion_details_drop_col;
EXECUTE stmt_static_results_dcloud_confusion_details_drop_col;
DEALLOCATE PREPARE stmt_static_results_dcloud_confusion_details_drop_col;

SET @static_results_dcloud_is_obfuscated_drop_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'dcloud_is_obfuscated'
);
SET @sql_static_results_dcloud_is_obfuscated_drop_col := IF(
  @static_results_dcloud_is_obfuscated_drop_col = 1,
  'ALTER TABLE static_results DROP COLUMN dcloud_is_obfuscated',
  'SELECT 1'
);
PREPARE stmt_static_results_dcloud_is_obfuscated_drop_col FROM @sql_static_results_dcloud_is_obfuscated_drop_col;
EXECUTE stmt_static_results_dcloud_is_obfuscated_drop_col;
DEALLOCATE PREPARE stmt_static_results_dcloud_is_obfuscated_drop_col;

SET @static_results_dcloud_error_drop_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'dcloud_error'
);
SET @sql_static_results_dcloud_error_drop_col := IF(
  @static_results_dcloud_error_drop_col = 1,
  'ALTER TABLE static_results DROP COLUMN dcloud_error',
  'SELECT 1'
);
PREPARE stmt_static_results_dcloud_error_drop_col FROM @sql_static_results_dcloud_error_drop_col;
EXECUTE stmt_static_results_dcloud_error_drop_col;
DEALLOCATE PREPARE stmt_static_results_dcloud_error_drop_col;

SET @static_results_flutter_status_drop_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'flutter_status'
);
SET @sql_static_results_flutter_status_drop_col := IF(
  @static_results_flutter_status_drop_col = 1,
  'ALTER TABLE static_results DROP COLUMN flutter_status',
  'SELECT 1'
);
PREPARE stmt_static_results_flutter_status_drop_col FROM @sql_static_results_flutter_status_drop_col;
EXECUTE stmt_static_results_flutter_status_drop_col;
DEALLOCATE PREPARE stmt_static_results_flutter_status_drop_col;

SET @static_results_flutter_asm_dir_drop_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'flutter_asm_dir'
);
SET @sql_static_results_flutter_asm_dir_drop_col := IF(
  @static_results_flutter_asm_dir_drop_col = 1,
  'ALTER TABLE static_results DROP COLUMN flutter_asm_dir',
  'SELECT 1'
);
PREPARE stmt_static_results_flutter_asm_dir_drop_col FROM @sql_static_results_flutter_asm_dir_drop_col;
EXECUTE stmt_static_results_flutter_asm_dir_drop_col;
DEALLOCATE PREPARE stmt_static_results_flutter_asm_dir_drop_col;

SET @static_results_flutter_primary_entry_method_drop_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'flutter_primary_entry_method'
);
SET @sql_static_results_flutter_primary_entry_method_drop_col := IF(
  @static_results_flutter_primary_entry_method_drop_col = 1,
  'ALTER TABLE static_results DROP COLUMN flutter_primary_entry_method',
  'SELECT 1'
);
PREPARE stmt_static_results_flutter_primary_entry_method_drop_col FROM @sql_static_results_flutter_primary_entry_method_drop_col;
EXECUTE stmt_static_results_flutter_primary_entry_method_drop_col;
DEALLOCATE PREPARE stmt_static_results_flutter_primary_entry_method_drop_col;

SET @static_results_flutter_primary_entry_confidence_drop_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'flutter_primary_entry_confidence'
);
SET @sql_static_results_flutter_primary_entry_confidence_drop_col := IF(
  @static_results_flutter_primary_entry_confidence_drop_col = 1,
  'ALTER TABLE static_results DROP COLUMN flutter_primary_entry_confidence',
  'SELECT 1'
);
PREPARE stmt_static_results_flutter_primary_entry_confidence_drop_col FROM @sql_static_results_flutter_primary_entry_confidence_drop_col;
EXECUTE stmt_static_results_flutter_primary_entry_confidence_drop_col;
DEALLOCATE PREPARE stmt_static_results_flutter_primary_entry_confidence_drop_col;

SET @static_results_flutter_root_widget_class_drop_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'flutter_root_widget_class'
);
SET @sql_static_results_flutter_root_widget_class_drop_col := IF(
  @static_results_flutter_root_widget_class_drop_col = 1,
  'ALTER TABLE static_results DROP COLUMN flutter_root_widget_class',
  'SELECT 1'
);
PREPARE stmt_static_results_flutter_root_widget_class_drop_col FROM @sql_static_results_flutter_root_widget_class_drop_col;
EXECUTE stmt_static_results_flutter_root_widget_class_drop_col;
DEALLOCATE PREPARE stmt_static_results_flutter_root_widget_class_drop_col;

SET @static_results_flutter_root_widget_library_uri_drop_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'flutter_root_widget_library_uri'
);
SET @sql_static_results_flutter_root_widget_library_uri_drop_col := IF(
  @static_results_flutter_root_widget_library_uri_drop_col = 1,
  'ALTER TABLE static_results DROP COLUMN flutter_root_widget_library_uri',
  'SELECT 1'
);
PREPARE stmt_static_results_flutter_root_widget_library_uri_drop_col FROM @sql_static_results_flutter_root_widget_library_uri_drop_col;
EXECUTE stmt_static_results_flutter_root_widget_library_uri_drop_col;
DEALLOCATE PREPARE stmt_static_results_flutter_root_widget_library_uri_drop_col;

SET @static_results_flutter_class_count_drop_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'flutter_class_count'
);
SET @sql_static_results_flutter_class_count_drop_col := IF(
  @static_results_flutter_class_count_drop_col = 1,
  'ALTER TABLE static_results DROP COLUMN flutter_class_count',
  'SELECT 1'
);
PREPARE stmt_static_results_flutter_class_count_drop_col FROM @sql_static_results_flutter_class_count_drop_col;
EXECUTE stmt_static_results_flutter_class_count_drop_col;
DEALLOCATE PREPARE stmt_static_results_flutter_class_count_drop_col;

SET @static_results_flutter_error_drop_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'flutter_error'
);
SET @sql_static_results_flutter_error_drop_col := IF(
  @static_results_flutter_error_drop_col = 1,
  'ALTER TABLE static_results DROP COLUMN flutter_error',
  'SELECT 1'
);
PREPARE stmt_static_results_flutter_error_drop_col FROM @sql_static_results_flutter_error_drop_col;
EXECUTE stmt_static_results_flutter_error_drop_col;
DEALLOCATE PREPARE stmt_static_results_flutter_error_drop_col;

SET @static_results_flutter_blutter_status_drop_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'flutter_blutter_status'
);
SET @sql_static_results_flutter_blutter_status_drop_col := IF(
  @static_results_flutter_blutter_status_drop_col = 1,
  'ALTER TABLE static_results DROP COLUMN flutter_blutter_status',
  'SELECT 1'
);
PREPARE stmt_static_results_flutter_blutter_status_drop_col FROM @sql_static_results_flutter_blutter_status_drop_col;
EXECUTE stmt_static_results_flutter_blutter_status_drop_col;
DEALLOCATE PREPARE stmt_static_results_flutter_blutter_status_drop_col;

SET @static_results_flutter_blutter_output_dir_drop_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'flutter_blutter_output_dir'
);
SET @sql_static_results_flutter_blutter_output_dir_drop_col := IF(
  @static_results_flutter_blutter_output_dir_drop_col = 1,
  'ALTER TABLE static_results DROP COLUMN flutter_blutter_output_dir',
  'SELECT 1'
);
PREPARE stmt_static_results_flutter_blutter_output_dir_drop_col FROM @sql_static_results_flutter_blutter_output_dir_drop_col;
EXECUTE stmt_static_results_flutter_blutter_output_dir_drop_col;
DEALLOCATE PREPARE stmt_static_results_flutter_blutter_output_dir_drop_col;

SET @static_results_flutter_blutter_input_dir_drop_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'flutter_blutter_input_dir'
);
SET @sql_static_results_flutter_blutter_input_dir_drop_col := IF(
  @static_results_flutter_blutter_input_dir_drop_col = 1,
  'ALTER TABLE static_results DROP COLUMN flutter_blutter_input_dir',
  'SELECT 1'
);
PREPARE stmt_static_results_flutter_blutter_input_dir_drop_col FROM @sql_static_results_flutter_blutter_input_dir_drop_col;
EXECUTE stmt_static_results_flutter_blutter_input_dir_drop_col;
DEALLOCATE PREPARE stmt_static_results_flutter_blutter_input_dir_drop_col;

SET @static_results_flutter_blutter_log_path_drop_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'flutter_blutter_log_path'
);
SET @sql_static_results_flutter_blutter_log_path_drop_col := IF(
  @static_results_flutter_blutter_log_path_drop_col = 1,
  'ALTER TABLE static_results DROP COLUMN flutter_blutter_log_path',
  'SELECT 1'
);
PREPARE stmt_static_results_flutter_blutter_log_path_drop_col FROM @sql_static_results_flutter_blutter_log_path_drop_col;
EXECUTE stmt_static_results_flutter_blutter_log_path_drop_col;
DEALLOCATE PREPARE stmt_static_results_flutter_blutter_log_path_drop_col;

SET @static_results_flutter_snapshot_hash_drop_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'flutter_snapshot_hash'
);
SET @sql_static_results_flutter_snapshot_hash_drop_col := IF(
  @static_results_flutter_snapshot_hash_drop_col = 1,
  'ALTER TABLE static_results DROP COLUMN flutter_snapshot_hash',
  'SELECT 1'
);
PREPARE stmt_static_results_flutter_snapshot_hash_drop_col FROM @sql_static_results_flutter_snapshot_hash_drop_col;
EXECUTE stmt_static_results_flutter_snapshot_hash_drop_col;
DEALLOCATE PREPARE stmt_static_results_flutter_snapshot_hash_drop_col;

SET @static_results_flutter_target_arch_drop_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'flutter_target_arch'
);
SET @sql_static_results_flutter_target_arch_drop_col := IF(
  @static_results_flutter_target_arch_drop_col = 1,
  'ALTER TABLE static_results DROP COLUMN flutter_target_arch',
  'SELECT 1'
);
PREPARE stmt_static_results_flutter_target_arch_drop_col FROM @sql_static_results_flutter_target_arch_drop_col;
EXECUTE stmt_static_results_flutter_target_arch_drop_col;
DEALLOCATE PREPARE stmt_static_results_flutter_target_arch_drop_col;

SET @static_results_flutter_target_os_drop_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'flutter_target_os'
);
SET @sql_static_results_flutter_target_os_drop_col := IF(
  @static_results_flutter_target_os_drop_col = 1,
  'ALTER TABLE static_results DROP COLUMN flutter_target_os',
  'SELECT 1'
);
PREPARE stmt_static_results_flutter_target_os_drop_col FROM @sql_static_results_flutter_target_os_drop_col;
EXECUTE stmt_static_results_flutter_target_os_drop_col;
DEALLOCATE PREPARE stmt_static_results_flutter_target_os_drop_col;

SET @static_results_flutter_compressed_pointers_drop_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'flutter_compressed_pointers'
);
SET @sql_static_results_flutter_compressed_pointers_drop_col := IF(
  @static_results_flutter_compressed_pointers_drop_col = 1,
  'ALTER TABLE static_results DROP COLUMN flutter_compressed_pointers',
  'SELECT 1'
);
PREPARE stmt_static_results_flutter_compressed_pointers_drop_col FROM @sql_static_results_flutter_compressed_pointers_drop_col;
EXECUTE stmt_static_results_flutter_compressed_pointers_drop_col;
DEALLOCATE PREPARE stmt_static_results_flutter_compressed_pointers_drop_col;

SET @static_results_flutter_blutter_backend_executable_drop_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'flutter_blutter_backend_executable'
);
SET @sql_static_results_flutter_blutter_backend_executable_drop_col := IF(
  @static_results_flutter_blutter_backend_executable_drop_col = 1,
  'ALTER TABLE static_results DROP COLUMN flutter_blutter_backend_executable',
  'SELECT 1'
);
PREPARE stmt_static_results_flutter_blutter_backend_executable_drop_col FROM @sql_static_results_flutter_blutter_backend_executable_drop_col;
EXECUTE stmt_static_results_flutter_blutter_backend_executable_drop_col;
DEALLOCATE PREPARE stmt_static_results_flutter_blutter_backend_executable_drop_col;

SET @static_results_flutter_blutter_backend_match_drop_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'flutter_blutter_backend_match'
);
SET @sql_static_results_flutter_blutter_backend_match_drop_col := IF(
  @static_results_flutter_blutter_backend_match_drop_col = 1,
  'ALTER TABLE static_results DROP COLUMN flutter_blutter_backend_match',
  'SELECT 1'
);
PREPARE stmt_static_results_flutter_blutter_backend_match_drop_col FROM @sql_static_results_flutter_blutter_backend_match_drop_col;
EXECUTE stmt_static_results_flutter_blutter_backend_match_drop_col;
DEALLOCATE PREPARE stmt_static_results_flutter_blutter_backend_match_drop_col;

SET @static_results_flutter_blutter_error_drop_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'flutter_blutter_error'
);
SET @sql_static_results_flutter_blutter_error_drop_col := IF(
  @static_results_flutter_blutter_error_drop_col = 1,
  'ALTER TABLE static_results DROP COLUMN flutter_blutter_error',
  'SELECT 1'
);
PREPARE stmt_static_results_flutter_blutter_error_drop_col FROM @sql_static_results_flutter_blutter_error_drop_col;
EXECUTE stmt_static_results_flutter_blutter_error_drop_col;
DEALLOCATE PREPARE stmt_static_results_flutter_blutter_error_drop_col;
-- Preserve the complete detector output for later traceability.
SET @sdk_results_raw_finding_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'sdk_results'
    AND column_name = 'raw_finding'
);
SET @sql_sdk_results_raw_finding_col := IF(
  @sdk_results_raw_finding_col = 0,
  'ALTER TABLE sdk_results ADD COLUMN raw_finding JSON NULL AFTER credential_evidence',
  'SELECT 1'
);
PREPARE stmt_sdk_results_raw_finding_col FROM @sql_sdk_results_raw_finding_col;
EXECUTE stmt_sdk_results_raw_finding_col;
DEALLOCATE PREPARE stmt_sdk_results_raw_finding_col;

-- SDK results are stored in sdk_results. Remove legacy aggregate/error columns.
SET @static_results_sdk_findings_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'sdk_findings'
);
SET @sql_static_results_sdk_findings_col := IF(
  @static_results_sdk_findings_col = 1,
  'ALTER TABLE static_results DROP COLUMN sdk_findings',
  'SELECT 1'
);
PREPARE stmt_static_results_sdk_findings_col FROM @sql_static_results_sdk_findings_col;
EXECUTE stmt_static_results_sdk_findings_col;
DEALLOCATE PREPARE stmt_static_results_sdk_findings_col;

SET @static_results_sdk_detect_error_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'sdk_detect_error'
);
SET @sql_static_results_sdk_detect_error_col := IF(
  @static_results_sdk_detect_error_col = 1,
  'ALTER TABLE static_results DROP COLUMN sdk_detect_error',
  'SELECT 1'
);
PREPARE stmt_static_results_sdk_detect_error_col FROM @sql_static_results_sdk_detect_error_col;
EXECUTE stmt_static_results_sdk_detect_error_col;
DEALLOCATE PREPARE stmt_static_results_sdk_detect_error_col;

-- Drop legacy aggregate/error IOC columns. Split phone/email/url fields are authoritative.
SET @static_results_source_iocs_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'source_iocs'
);
SET @sql_static_results_source_iocs_col := IF(
  @static_results_source_iocs_col = 1,
  'ALTER TABLE static_results DROP COLUMN source_iocs',
  'SELECT 1'
);
PREPARE stmt_static_results_source_iocs_col FROM @sql_static_results_source_iocs_col;
EXECUTE stmt_static_results_source_iocs_col;
DEALLOCATE PREPARE stmt_static_results_source_iocs_col;

SET @static_results_source_ioc_error_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'source_ioc_error'
);
SET @sql_static_results_source_ioc_error_col := IF(
  @static_results_source_ioc_error_col = 1,
  'ALTER TABLE static_results DROP COLUMN source_ioc_error',
  'SELECT 1'
);
PREPARE stmt_static_results_source_ioc_error_col FROM @sql_static_results_source_ioc_error_col;
EXECUTE stmt_static_results_source_ioc_error_col;
DEALLOCATE PREPARE stmt_static_results_source_ioc_error_col;

SET @static_results_source_iocs_error_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'source_iocs_error'
);
SET @sql_static_results_source_iocs_error_col := IF(
  @static_results_source_iocs_error_col = 1,
  'ALTER TABLE static_results DROP COLUMN source_iocs_error',
  'SELECT 1'
);
PREPARE stmt_static_results_source_iocs_error_col FROM @sql_static_results_source_iocs_error_col;
EXECUTE stmt_static_results_source_iocs_error_col;
DEALLOCATE PREPARE stmt_static_results_source_iocs_error_col;

SET FOREIGN_KEY_CHECKS = 1;
