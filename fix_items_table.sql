USE vault_db;

ALTER TABLE vault_items
  ADD COLUMN title VARCHAR(120) DEFAULT NULL,
  ADD COLUMN preview VARCHAR(80) DEFAULT NULL;

SELECT 'Colunas adicionadas!' AS status;
