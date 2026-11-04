-- Apply to existing MySQL 5.7+ databases after v1_init.sql.
-- Add only indexes used by task-list owner/status filters and recent-first ordering.

SET @idx_tasks_user_created_exists := (
  SELECT COUNT(*) FROM information_schema.statistics
  WHERE table_schema = DATABASE() AND table_name = 'tasks'
    AND index_name = 'idx_tasks_user_created_id'
);
SET @sql_tasks_user_created := IF(
  @idx_tasks_user_created_exists = 0,
  'ALTER TABLE tasks ADD KEY idx_tasks_user_created_id (user_id, created_at, id)',
  'SELECT 1'
);
PREPARE stmt_tasks_user_created FROM @sql_tasks_user_created;
EXECUTE stmt_tasks_user_created;
DEALLOCATE PREPARE stmt_tasks_user_created;

SET @idx_tasks_user_status_created_exists := (
  SELECT COUNT(*) FROM information_schema.statistics
  WHERE table_schema = DATABASE() AND table_name = 'tasks'
    AND index_name = 'idx_tasks_user_status_created_id'
);
SET @sql_tasks_user_status_created := IF(
  @idx_tasks_user_status_created_exists = 0,
  'ALTER TABLE tasks ADD KEY idx_tasks_user_status_created_id (user_id, status, created_at, id)',
  'SELECT 1'
);
PREPARE stmt_tasks_user_status_created FROM @sql_tasks_user_status_created;
EXECUTE stmt_tasks_user_status_created;
DEALLOCATE PREPARE stmt_tasks_user_status_created;

SET @idx_tasks_status_created_exists := (
  SELECT COUNT(*) FROM information_schema.statistics
  WHERE table_schema = DATABASE() AND table_name = 'tasks'
    AND index_name = 'idx_tasks_status_created_id'
);
SET @sql_tasks_status_created := IF(
  @idx_tasks_status_created_exists = 0,
  'ALTER TABLE tasks ADD KEY idx_tasks_status_created_id (status, created_at, id)',
  'SELECT 1'
);
PREPARE stmt_tasks_status_created FROM @sql_tasks_status_created;
EXECUTE stmt_tasks_status_created;
DEALLOCATE PREPARE stmt_tasks_status_created;
