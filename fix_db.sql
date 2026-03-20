USE vault_db;

-- Corrigir coluna enc_salt para ter valor padrão vazio
ALTER TABLE users MODIFY COLUMN enc_salt VARCHAR(64) NOT NULL DEFAULT '';

SELECT 'Corrigido!' AS status;
