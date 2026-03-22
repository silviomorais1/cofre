USE railway;

ALTER TABLE users ADD COLUMN security_question TEXT DEFAULT NULL;
ALTER TABLE users ADD COLUMN security_answer_hash VARCHAR(255) DEFAULT NULL;

SELECT 'Colunas de recuperação adicionadas!' AS status;
SHOW COLUMNS FROM users;
