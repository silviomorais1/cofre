USE vault_db;

ALTER TABLE users ADD COLUMN otp_code VARCHAR(6) DEFAULT NULL;
ALTER TABLE users ADD COLUMN otp_expiry DATETIME DEFAULT NULL;
ALTER TABLE users ADD COLUMN last_login DATETIME DEFAULT NULL;
ALTER TABLE users ADD COLUMN recovery_codes TEXT DEFAULT NULL;

-- Criar tabela de bloqueios por email se não existir
CREATE TABLE IF NOT EXISTS email_lockouts (
  id           INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  email        VARCHAR(254) NOT NULL,
  attempts     INT DEFAULT 0,
  locked_until DATETIME DEFAULT NULL,
  last_attempt DATETIME DEFAULT NULL,
  INDEX idx_email (email)
);

SELECT 'Colunas adicionadas com sucesso!' AS status;
