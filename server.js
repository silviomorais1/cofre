/**
 * VelorumSafe Server v3.0
 * + Registo de actividade (audit log)
 * + JWT blacklist (logout seguro)
 * + Validação reforçada
 * + Ordenação de itens
 */
require('dotenv').config();
const express    = require('express');
const mysql      = require('mysql2/promise');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const helmet     = require('helmet');
const cors       = require('cors');

const app = express();
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: '*', methods: ['GET','POST','PUT','DELETE','OPTIONS'], allowedHeaders: ['Content-Type','Authorization'] }));
app.use(express.json({ limit: '10mb' }));

const pool = mysql.createPool({
  host:     process.env.DB_HOST || 'localhost',
  user:     process.env.DB_USER || 'vault_user',
  password: process.env.DB_PASS || '',
  database: process.env.DB_NAME || 'vault_db',
  waitForConnections: true,
  connectionLimit: 10,
});

// JWT Blacklist
const tokenBlacklist = new Set();
setInterval(() => {
  const now = Math.floor(Date.now() / 1000);
  for (const token of tokenBlacklist) {
    try { const d = jwt.decode(token); if (d && d.exp < now) tokenBlacklist.delete(token); }
    catch { tokenBlacklist.delete(token); }
  }
}, 3600000);

// Email
const transporter = nodemailer.createTransport({
  service: process.env.MAIL_SERVICE || 'gmail',
  auth: { user: process.env.MAIL_USER, pass: process.env.MAIL_PASS },
});

async function sendOTPEmail(to, username, otp) {
  await transporter.sendMail({
    from: process.env.MAIL_FROM || `VelorumSafe <${process.env.MAIL_USER}>`,
    to,
    subject: `${otp} — Código de verificação VelorumSafe`,
    html: `<!DOCTYPE html><html><body style="margin:0;padding:0;background:#080e1a;font-family:'Segoe UI',sans-serif"><div style="max-width:480px;margin:40px auto;background:#0d1525;border-radius:16px;overflow:hidden;border:1px solid #1e3050"><div style="padding:32px;text-align:center"><div style="font-size:2rem;margin-bottom:8px">🔒</div><h1 style="margin:0;font-size:1.4rem;color:#fff"><span style="color:#fff">Velorum</span><span style="color:#00d4ff">Safe</span></h1><p style="color:#8ba8c4;font-size:12px;letter-spacing:2px;text-transform:uppercase;margin:4px 0 24px">Cofre Digital Seguro</p><p style="color:#e8f4f8;margin-bottom:4px">Olá <strong>${username}</strong>,</p><p style="color:#8ba8c4;font-size:14px;margin-bottom:24px">O teu código de verificação é:</p><div style="background:#111d30;border-radius:12px;padding:24px;margin:0 auto 24px;display:inline-block;min-width:200px"><span style="font-size:2.2rem;font-weight:700;letter-spacing:12px;color:#00d4ff;font-family:'Courier New',monospace">${otp}</span></div><p style="color:#8ba8c4;font-size:13px">Válido por <strong style="color:#fff">10 minutos</strong>.</p><p style="color:#4a6580;font-size:12px;margin-top:16px">Se não foste tu, ignora este email.</p></div></div></body></html>`,
  });
}

// Auth middleware
function authMiddleware(req, res, next) {
  const h = req.headers.authorization;
  if (!h || !h.startsWith('Bearer ')) return res.status(401).json({ error: 'Não autenticado' });
  const token = h.slice(7);
  if (tokenBlacklist.has(token)) return res.status(401).json({ error: 'Sessão inválida' });
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = payload.userId; req.userEmail = payload.email; req.token = token;
    next();
  } catch { res.status(401).json({ error: 'Sessão expirada' }); }
}

// Audit log
async function log(userId, action, detail, ip) {
  try {
    await pool.execute(
      'INSERT INTO audit_log (user_id, action, detail, ip_address) VALUES (?,?,?,?)',
      [userId, action, (detail||'').substring(0,255), ip||'']
    );
  } catch(e) { console.error('[log]', e.message); }
}

// Rate limiting
const MAX_ATTEMPTS = 5, LOCKOUT_MINS = 15;

async function checkEmailLockout(email) {
  const [rows] = await pool.execute('SELECT attempts, locked_until FROM email_lockouts WHERE email=?', [email]);
  if (!rows.length) return { blocked: false, remaining: MAX_ATTEMPTS };
  const row = rows[0];
  if (row.locked_until && new Date(row.locked_until) > new Date()) {
    return { blocked: true, mins: Math.ceil((new Date(row.locked_until) - new Date()) / 60000) };
  }
  if (row.locked_until) await pool.execute('UPDATE email_lockouts SET attempts=0, locked_until=NULL WHERE email=?', [email]);
  return { blocked: false, remaining: MAX_ATTEMPTS - (row.locked_until ? 0 : row.attempts) };
}

async function recordFailedAttempt(email) {
  const [rows] = await pool.execute('SELECT attempts FROM email_lockouts WHERE email=?', [email]);
  if (!rows.length) { await pool.execute('INSERT INTO email_lockouts (email,attempts,last_attempt) VALUES (?,1,NOW())', [email]); return { attempts:1, locked:false }; }
  const n = (rows[0].attempts||0) + 1;
  if (n >= MAX_ATTEMPTS) {
    const until = new Date(Date.now() + LOCKOUT_MINS*60000);
    await pool.execute('UPDATE email_lockouts SET attempts=?,locked_until=?,last_attempt=NOW() WHERE email=?', [n, until, email]);
    return { attempts:n, locked:true };
  }
  await pool.execute('UPDATE email_lockouts SET attempts=?,last_attempt=NOW() WHERE email=?', [n, email]);
  return { attempts:n, locked:false };
}

async function clearFailedAttempts(email) {
  await pool.execute('UPDATE email_lockouts SET attempts=0, locked_until=NULL WHERE email=?', [email]);
}

// Setup DB — cria tabela audit_log se não existir
async function setupDB() {
  await pool.execute(`
    CREATE TABLE IF NOT EXISTS audit_log (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NOT NULL,
      action VARCHAR(64) NOT NULL,
      detail VARCHAR(255) DEFAULT '',
      ip_address VARCHAR(64) DEFAULT '',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_user (user_id),
      INDEX idx_time (created_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
  `);
  // Adicionar updated_at a vault_items se não existir
  try {
    await pool.execute('ALTER TABLE vault_items ADD COLUMN updated_at TIMESTAMP NULL DEFAULT NULL');
  } catch(e) { /* já existe */ }
}

// ── ROTAS ──

app.get('/api/health', (req, res) => res.json({ ok:true, version:'3.0' }));

app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, passwordHash } = req.body;
    if (!username||!email||!passwordHash) return res.status(400).json({ error:'Campos obrigatórios em falta' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error:'Email inválido' });
    const [exists] = await pool.execute('SELECT id FROM users WHERE email=?', [email]);
    if (exists.length) return res.status(409).json({ error:'Este email já está registado' });
    const serverHash = await bcrypt.hash(passwordHash, 12);
    const recoveryCodes = Array.from({length:8}, () =>
      Math.random().toString(36).substring(2,6).toUpperCase()+'-'+Math.random().toString(36).substring(2,6).toUpperCase()
    );
    const hashedCodes = await Promise.all(recoveryCodes.map(c => bcrypt.hash(c, 8)));
    const [result] = await pool.execute(
      'INSERT INTO users (email,username,password_hash,recovery_codes) VALUES (?,?,?,?)',
      [email, username, serverHash, JSON.stringify(hashedCodes)]
    );
    await log(result.insertId, 'register', `Conta criada: ${email}`, req.ip);
    res.json({ ok:true, recoveryCodes });
  } catch(e) { console.error('Register:', e); res.status(500).json({ error:'Erro interno' }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, passwordHash } = req.body;
    if (!email||!passwordHash) return res.status(400).json({ error:'Campos obrigatórios em falta' });
    const lockout = await checkEmailLockout(email);
    if (lockout.blocked) return res.status(429).json({ error:`Conta bloqueada por ${lockout.mins} min.`, blocked:true, mins:lockout.mins });
    const [rows] = await pool.execute('SELECT * FROM users WHERE email=?', [email]);
    if (!rows.length) { await recordFailedAttempt(email); return res.status(401).json({ error:'Credenciais inválidas' }); }
    const valid = await bcrypt.compare(passwordHash, rows[0].password_hash);
    if (!valid) {
      const r = await recordFailedAttempt(email);
      if (r.locked) { await log(rows[0].id,'login_blocked','Conta bloqueada',req.ip); return res.status(429).json({ error:`Conta bloqueada por ${LOCKOUT_MINS} min.`, blocked:true, mins:LOCKOUT_MINS }); }
      await log(rows[0].id,'login_failed',`${MAX_ATTEMPTS-r.attempts} tentativas restantes`,req.ip);
      return res.status(401).json({ error:`Credenciais inválidas. ${MAX_ATTEMPTS-r.attempts} tentativa(s) restante(s).`, remaining:MAX_ATTEMPTS-r.attempts });
    }
    await clearFailedAttempts(email);
    const otp = String(Math.floor(100000 + Math.random()*900000));
    await pool.execute('UPDATE users SET otp_code=?,otp_expiry=? WHERE id=?', [otp, new Date(Date.now()+600000), rows[0].id]);
    await sendOTPEmail(email, rows[0].username, otp);
    await log(rows[0].id,'login_otp_sent',`OTP enviado`,req.ip);
    res.json({ ok:true });
  } catch(e) { console.error('Login:', e); res.status(500).json({ error:'Erro interno' }); }
});

app.post('/api/auth/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    if (!email||!otp) return res.status(400).json({ error:'Dados em falta' });
    const [rows] = await pool.execute('SELECT * FROM users WHERE email=?', [email]);
    if (!rows.length) return res.status(401).json({ error:'Utilizador não encontrado' });
    const user = rows[0];
    if (!user.otp_code || user.otp_code !== String(otp).trim()) { await log(user.id,'otp_failed','Código inválido',req.ip); return res.status(401).json({ error:'Código inválido' }); }
    if (new Date(user.otp_expiry) < new Date()) return res.status(401).json({ error:'Código expirado. Faz login novamente.' });
    await pool.execute('UPDATE users SET otp_code=NULL,otp_expiry=NULL,last_login=NOW() WHERE id=?', [user.id]);
    await log(user.id,'login_success','Login bem-sucedido',req.ip);
    const token = jwt.sign({ userId:user.id, email:user.email }, process.env.JWT_SECRET, { expiresIn:'8h' });
    res.json({ ok:true, token, user:{ id:user.id, username:user.username, email:user.email } });
  } catch(e) { console.error('OTP:', e); res.status(500).json({ error:'Erro interno' }); }
});

app.post('/api/auth/resend-otp', async (req, res) => {
  try {
    const { email } = req.body;
    const [rows] = await pool.execute('SELECT * FROM users WHERE email=?', [email]);
    if (!rows.length) return res.status(404).json({ error:'Utilizador não encontrado' });
    const otp = String(Math.floor(100000 + Math.random()*900000));
    await pool.execute('UPDATE users SET otp_code=?,otp_expiry=? WHERE id=?', [otp, new Date(Date.now()+600000), rows[0].id]);
    await sendOTPEmail(email, rows[0].username, otp);
    res.json({ ok:true });
  } catch(e) { res.status(500).json({ error:'Erro ao reenviar' }); }
});

app.post('/api/auth/logout', authMiddleware, async (req, res) => {
  tokenBlacklist.add(req.token);
  await log(req.userId, 'logout', 'Sessão encerrada', req.ip);
  res.json({ ok:true });
});

app.get('/api/items', authMiddleware, async (req, res) => {
  try {
    const orderMap = { newest:'created_at DESC', oldest:'created_at ASC', az:'title ASC', za:'title DESC', updated:'COALESCE(updated_at,created_at) DESC' };
    const order = orderMap[req.query.sort] || 'created_at DESC';
    const [items] = await pool.execute(
      `SELECT id, encrypted_data, item_type, title, created_at, updated_at FROM vault_items WHERE user_id=? ORDER BY ${order}`,
      [req.userId]
    );
    res.json({ items });
  } catch(e) { res.status(500).json({ error:'Erro ao carregar itens' }); }
});

app.post('/api/items', authMiddleware, async (req, res) => {
  try {
    const encryptedData = req.body.encryptedData || req.body.encryptedBlob;
    const itemType = req.body.itemType;
    const title = req.body.title || '';
    if (!encryptedData||!itemType) return res.status(400).json({ error:'Dados em falta' });
    if (encryptedData.length > 100000) return res.status(400).json({ error:'Dados demasiado grandes' });
    const validTypes = ['password','note','secret','file'];
    const safeType = validTypes.includes(itemType) ? itemType : 'note';
    const [result] = await pool.execute(
      'INSERT INTO vault_items (user_id,encrypted_data,item_type,title) VALUES (?,?,?,?)',
      [req.userId, encryptedData, safeType, title]
    );
    await log(req.userId, 'item_created', `"${title}" (${safeType})`, req.ip);
    res.json({ ok:true, id:result.insertId });
  } catch(e) { console.error('[POST /items]', e.message); res.status(500).json({ error:e.message }); }
});

app.put('/api/items/:id', authMiddleware, async (req, res) => {
  try {
    const encryptedData = req.body.encryptedData || req.body.encryptedBlob;
    const itemType = req.body.itemType;
    const title = req.body.title || '';
    const validTypes = ['password','note','secret','file'];
    const safeType = validTypes.includes(itemType) ? itemType : 'note';
    await pool.execute(
      'UPDATE vault_items SET encrypted_data=?,item_type=?,title=?,updated_at=NOW() WHERE id=? AND user_id=?',
      [encryptedData, safeType, title, req.params.id, req.userId]
    );
    await log(req.userId, 'item_updated', `"${title}"`, req.ip);
    res.json({ ok:true });
  } catch(e) { console.error('[PUT /items]', e.message); res.status(500).json({ error:e.message }); }
});

app.delete('/api/items/:id', authMiddleware, async (req, res) => {
  try {
    const [rows] = await pool.execute('SELECT title FROM vault_items WHERE id=? AND user_id=?', [req.params.id, req.userId]);
    const title = rows[0]?.title || '?';
    await pool.execute('DELETE FROM vault_items WHERE id=? AND user_id=?', [req.params.id, req.userId]);
    await log(req.userId, 'item_deleted', `"${title}"`, req.ip);
    res.json({ ok:true });
  } catch(e) { res.status(500).json({ error:'Erro ao eliminar' }); }
});

app.get('/api/audit', authMiddleware, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit)||100, 500);
    const [rows] = await pool.execute(
      `SELECT id,action,detail,ip_address,created_at FROM audit_log WHERE user_id=? ORDER BY created_at DESC LIMIT ${limit}`,
      [req.userId]
    );
    res.json({ logs:rows });
  } catch(e) { 
    console.error('[audit]', e.message);
    res.status(500).json({ error:'Erro ao carregar registo' }); 
  }
});

app.get('/api/user/me', authMiddleware, async (req, res) => {
  try {
    const [rows] = await pool.execute('SELECT id,username,email,created_at FROM users WHERE id=?', [req.userId]);
    if (!rows.length) return res.status(404).json({ error:'Utilizador não encontrado' });
    res.json({ user:rows[0] });
  } catch(e) { res.status(500).json({ error:'Erro' }); }
});

app.put('/api/user/password', authMiddleware, async (req, res) => {
  try {
    const { oldHash, newHash, reencryptedItems } = req.body;
    const [rows] = await pool.execute('SELECT password_hash FROM users WHERE id=?', [req.userId]);
    if (!rows.length) return res.status(404).json({ error:'Utilizador não encontrado' });
    if (!await bcrypt.compare(oldHash, rows[0].password_hash)) return res.status(401).json({ error:'Senha actual incorreta' });
    await pool.execute('UPDATE users SET password_hash=? WHERE id=?', [await bcrypt.hash(newHash, 12), req.userId]);
    if (reencryptedItems?.length) {
      for (const item of reencryptedItems) {
        await pool.execute('UPDATE vault_items SET encrypted_data=?,item_type=? WHERE id=? AND user_id=?', [item.blob, item.type, item.id, req.userId]);
      }
    }
    await log(req.userId, 'password_changed', 'Senha mestre alterada', req.ip);
    res.json({ ok:true });
  } catch(e) { res.status(500).json({ error:'Erro ao alterar senha' }); }
});

app.get('/api/user/export', authMiddleware, async (req, res) => {
  try {
    const [items] = await pool.execute('SELECT id,encrypted_data,item_type,title,created_at FROM vault_items WHERE user_id=?', [req.userId]);
    await log(req.userId, 'vault_exported', `${items.length} itens exportados`, req.ip);
    res.json({ exportedAt:new Date(), items });
  } catch(e) { res.status(500).json({ error:'Erro ao exportar' }); }
});

const PORT = process.env.PORT || 3001;
pool.getConnection().then(async conn => {
  conn.release();
  await setupDB();
  app.listen(PORT, () => {
    console.log(`\n✅ MySQL conectado.\n`);
    console.log(`🔐 VelorumSafe Server v3.0`);
    console.log(`   Porta      : ${PORT}`);
    console.log(`   Email      : ${process.env.MAIL_USER}`);
    console.log(`   Segurança  : JWT blacklist + Audit log + AES-256-GCM`);
    console.log(`   Rate limit : ${MAX_ATTEMPTS} tentativas → ${LOCKOUT_MINS} min bloqueio\n`);
  });
}).catch(err => { console.error('❌ MySQL:', err.message); process.exit(1); });
