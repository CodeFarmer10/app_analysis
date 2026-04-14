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
  priority INT NOT NULL DEFAULT 100,
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
  status ENUM('online', 'offline', 'busy') NOT NULL DEFAULT 'online',
  current_task_id VARCHAR(36) NULL,
  last_heartbeat_at DATETIME NULL,
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
  permissions JSON NULL,
  activities JSON NULL,
  services JSON NULL,
  providers JSON NULL,
  so_files JSON NULL,
  KEY idx_static_results_package (package_name),
  CONSTRAINT fk_static_results_task_id
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

-- Backward-compatible traffic_logs real-controller tagging columns.
SET @traffic_logs_real_controller_col := (
  SELECT COUNT(*) FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'traffic_logs'
    AND column_name = 'is_real_controller'
);
SET @sql_traffic_logs_real_controller_col := IF(
  @traffic_logs_real_controller_col = 0,
  'ALTER TABLE traffic_logs ADD COLUMN is_real_controller TINYINT(1) NOT NULL DEFAULT 0 AFTER resolved_ip',
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
  'ALTER TABLE tasks ADD COLUMN priority INT NOT NULL DEFAULT 100 AFTER task_description',
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

SET FOREIGN_KEY_CHECKS = 1;
