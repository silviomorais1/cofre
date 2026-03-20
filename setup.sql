-- ═══════════════════════════════════════════════════════════════
-- VAULT v5.1 — Setup MySQL
-- ═══════════════════════════════════════════════════════════════

CREATE DATABASE IF NOT EXISTS vault_db
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE vault_db;

-- Criar utilizador dedicado
-- IMPORTANTE: muda 'MUDA_ESTA_SENHA' para uma senha forte!
CREATE USER IF NOT EXISTS 'vault_user'@'localhost' IDENTIFIED BY 'Padre551';
GRANT SELECT, INSERT, UPDATE, DELETE ON vault_db.* TO 'vault_user'@'localhost';
FLUSH PRIVILEGES;

-- TABELA: users
CREATE TABLE IF NOT EXISTS users (
  id               INT UNSIGNED     AUTO_INCREMENT PRIMARY KEY,
  email            VARCHAR(254)     NOT NULL UNIQUE,
  username         VARCHAR(50)      NOT NULL UNIQUE,
  password_hash    VARCHAR(255)     NOT NULL,
  enc_salt         VARCHAR(64)      NOT NULL,
  recovery_hashes  JSON             DEFAULT NULL,
  used_recovery    JSON             DEFAULT NULL,
  logins           INT UNSIGNED     DEFAULT 0,
  session_timeout  SMALLINT UNSIGNED DEFAULT 600,
  last_login       DATETIME         NULL,
  created_at       DATETIME         DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- TABELA: vault_items
CREATE TABLE IF NOT EXISTS vault_items (
  id               INT UNSIGNED     AUTO_INCREMENT PRIMARY KEY,
  user_id          INT UNSIGNED     NOT NULL,
  item_type        VARCHAR(30)      NOT NULL,
  title            VARCHAR(120)     NOT NULL,
  encrypted_data   LONGTEXT         NOT NULL,
  preview          VARCHAR(80)      DEFAULT NULL,
  created_at       DATETIME         DEFAULT CURRENT_TIMESTAMP,
  updated_at       DATETIME         NULL ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_user_created (user_id, created_at DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- TABELA: login_attempts
CREATE TABLE IF NOT EXISTS login_attempts (
  id           INT UNSIGNED    AUTO_INCREMENT PRIMARY KEY,
  email        VARCHAR(254)    DEFAULT NULL,
  ip_address   VARCHAR(45)     NOT NULL,
  success      TINYINT(1)      DEFAULT 0,
  attempted_at DATETIME        DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_ip_time (ip_address, attempted_at),
  INDEX idx_email_time (email, attempted_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

SELECT 'Base de dados VAULT criada com sucesso!' AS status;
SHOW TABLES;
