-- Fraud APP Analysis Platform
-- Initial schema (idempotent)

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

CREATE TABLE IF NOT EXISTS users (
  id VARCHAR(36) PRIMARY KEY,
  username VARCHAR(64) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uk_users_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS tasks (
  id VARCHAR(36) PRIMARY KEY,
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
  KEY idx_tasks_user_id (user_id)
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
  seq INT NOT NULL,
  src_ip VARCHAR(45) NOT NULL,
  dst_ip VARCHAR(45) NOT NULL,
  src_port SMALLINT UNSIGNED NULL,
  dst_port SMALLINT UNSIGNED NULL,
  protocol VARCHAR(32) NOT NULL,
  domain VARCHAR(512) NULL,
  url TEXT NULL,
  resolved_ip VARCHAR(45) NULL,
  KEY idx_traffic_logs_task (task_id),
  CONSTRAINT fk_traffic_logs_task_id
    FOREIGN KEY (task_id) REFERENCES tasks(id)
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

SET FOREIGN_KEY_CHECKS = 1;
