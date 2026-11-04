SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS family_recommendations (
  id VARCHAR(36) PRIMARY KEY,
  batch_id VARCHAR(36) NOT NULL,
  family_key VARCHAR(64) NOT NULL,
  framework_name VARCHAR(128) NOT NULL,
  cluster_strategy VARCHAR(64) NOT NULL,
  cluster_stage VARCHAR(64) NOT NULL,
  member_count INT NOT NULL,
  representative_task_id VARCHAR(36) NULL,
  min_pair_similarity DOUBLE NULL,
  fingerprints_json LONGTEXT NOT NULL,
  rule_expression LONGTEXT NOT NULL,
  model_name VARCHAR(255) NULL,
  family_description VARCHAR(500) NULL,
  model_type_code VARCHAR(64) NULL,
  model_type_name VARCHAR(128) NULL,
  confidence DOUBLE NULL,
  status VARCHAR(24) NOT NULL DEFAULT 'pending',
  failure_reason TEXT NULL,
  model_id VARCHAR(36) NULL,
  reviewed_by VARCHAR(36) NULL,
  reviewed_at DATETIME NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uk_family_recommendations_key (family_key),
  KEY idx_family_recommendations_status (status),
  KEY idx_family_recommendations_batch (batch_id),
  KEY idx_family_recommendations_model (model_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

SET @family_recommendation_id_exists := (
  SELECT COUNT(*) FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND column_name = 'family_recommendation_id'
);
SET @family_recommendation_id_sql := IF(
  @family_recommendation_id_exists = 0,
  'ALTER TABLE static_results ADD COLUMN family_recommendation_id VARCHAR(36) NULL AFTER model_type_name',
  'SELECT 1'
);
PREPARE family_recommendation_id_stmt FROM @family_recommendation_id_sql;
EXECUTE family_recommendation_id_stmt;
DEALLOCATE PREPARE family_recommendation_id_stmt;

SET @family_recommendation_idx_exists := (
  SELECT COUNT(*) FROM information_schema.statistics
  WHERE table_schema = DATABASE()
    AND table_name = 'static_results'
    AND index_name = 'idx_static_results_family_recommendation_id'
);
SET @family_recommendation_idx_sql := IF(
  @family_recommendation_idx_exists = 0,
  'ALTER TABLE static_results ADD KEY idx_static_results_family_recommendation_id (family_recommendation_id)',
  'SELECT 1'
);
PREPARE family_recommendation_idx_stmt FROM @family_recommendation_idx_sql;
EXECUTE family_recommendation_idx_stmt;
DEALLOCATE PREPARE family_recommendation_idx_stmt;
