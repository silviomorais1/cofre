-- ============================================
-- VelorumSafe — Limpar utilizadores antigos
-- (hash incompatível com versão anterior)
-- ============================================
USE vault_db;

-- Apagar todos os dados antigos (incompatíveis)
DELETE FROM vault_items;
DELETE FROM login_attempts;
DELETE FROM users;

-- Resetar auto-increment
ALTER TABLE users AUTO_INCREMENT = 1;
ALTER TABLE vault_items AUTO_INCREMENT = 1;

-- Criar tabela de bloqueios por email (se não existir)
CREATE TABLE IF NOT EXISTS email_lockouts (
  id           INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  email        VARCHAR(254) NOT NULL,
  attempts     INT DEFAULT 0,
  locked_until DATETIME DEFAULT NULL,
  last_attempt DATETIME DEFAULT NULL,
  INDEX idx_email (email)
);

SELECT 'Utilizadores antigos removidos. Podes criar conta nova.' AS status;
