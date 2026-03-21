/**
 * VelorumSafe Server v2.1
 * Rate limiting por email: 5 tentativas → bloqueio 15 min
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
app.use(cors({
  origin: ['https://silviomorais1.github.io', 'http://localhost:3000', 'http://127.0.0.1'],
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization'],
  credentials: true
}));
// ── Pool MySQL ──────────────────────────────────────────
const pool = mysql.createPool({
  host:     process.env.DB_HOST     || 'localhost',
  port:     parseInt(process.env.DB_PORT || '3306'),
  user:     process.env.DB_USER     || 'vault_user',
  password: process.env.DB_PASS     || '',
  database: process.env.DB_NAME     || 'vault_db',
  waitForConnections: true,
  connectionLimit: 10,
});

// ── Email ───────────────────────────────────────────────
const transporter = nodemailer.createTransport({
  service: process.env.MAIL_SERVICE || 'gmail',
  auth: {
    user: process.env.MAIL_USER,
    pass: process.env.MAIL_PASS,
  },
});

async function sendOTPEmail(to, username, otp) {
  await transporter.sendMail({
    from: process.env.MAIL_FROM || `VelorumSafe <${process.env.MAIL_USER}>`,
    to,
    subject: `${otp} — Código de verificação VelorumSafe`,
    html: `
<!DOCTYPE html>
<html>
<body style="margin:0;padding:0;background:#080e1a;font-family:'Segoe UI',sans-serif">
<div style="max-width:480px;margin:40px auto;background:#0d1525;border-radius:16px;overflow:hidden;border:1px solid #1e3050">
  <div style="padding:32px;text-align:center">
    <div style="font-size:2rem;margin-bottom:8px">🔒</div>
    <h1 style="margin:0;font-size:1.4rem;color:#fff">
      <span style="color:#fff">Velorum</span><span style="color:#00d4ff">Safe</span>
    </h1>
    <p style="color:#8ba8c4;font-size:12px;letter-spacing:2px;text-transform:uppercase;margin:4px 0 24px">Cofre Digital Seguro</p>
    <p style="color:#e8f4f8;margin-bottom:4px">Olá <strong>${username}</strong>,</p>
    <p style="color:#8ba8c4;font-size:14px;margin-bottom:24px">O teu código de verificação é:</p>
    <div style="background:#111d30;border-radius:12px;padding:24px;margin:0 auto 24px;display:inline-block;min-width:200px">
      <span style="font-size:2.2rem;font-weight:700;letter-spacing:12px;color:#00d4ff;font-family:'Courier New',monospace">${otp}</span>
    </div>
    <p style="color:#8ba8c4;font-size:13px">Válido por <strong style="color:#fff">10 minutos</strong>.</p>
    <p style="color:#4a6580;font-size:12px;margin-top:16px">Se não foste tu, ignora este email.</p>
  </div>
</div>
</body>
</html>`,
  });
}

// ── Auth middleware ─────────────────────────────────────
function authMiddleware(req, res, next) {
  const h = req.headers.authorization;
  if (!h || !h.startsWith('Bearer ')) return res.status(401).json({ error: 'Não autenticado' });
  try {
    const payload = jwt.verify(h.slice(7), process.env.JWT_SECRET);
    req.userId    = payload.userId;
    req.userEmail = payload.email;
    next();
  } catch { res.status(401).json({ error: 'Sessão expirada' }); }
}

// ── Rate limiting POR EMAIL ─────────────────────────────
const MAX_ATTEMPTS  = 5;
const LOCKOUT_MINS  = 15;

async function checkEmailLockout(email) {
  const [rows] = await pool.execute(
    'SELECT attempts, locked_until FROM email_lockouts WHERE email = ?', [email]
  );
  if (!rows.length) return { blocked: false, remaining: MAX_ATTEMPTS };

  const row = rows[0];
  if (row.locked_until) {
    const until = new Date(row.locked_until);
    if (until > new Date()) {
      const mins = Math.ceil((until - new Date()) / 60000);
      return { blocked: true, mins };
    }
    // Bloqueio expirou — resetar
    await pool.execute('UPDATE email_lockouts SET attempts=0, locked_until=NULL WHERE email=?', [email]);
    return { blocked: false, remaining: MAX_ATTEMPTS };
  }
  const remaining = MAX_ATTEMPTS - row.attempts;
  return { blocked: false, remaining: remaining > 0 ? remaining : 0 };
}

async function recordFailedAttempt(email) {
  const [rows] = await pool.execute('SELECT attempts FROM email_lockouts WHERE email=?', [email]);
  if (!rows.length) {
    await pool.execute(
      'INSERT INTO email_lockouts (email, attempts, last_attempt) VALUES (?,1,NOW())', [email]
    );
    return { attempts: 1, locked: false };
  }
  const newAttempts = (rows[0].attempts || 0) + 1;
  if (newAttempts >= MAX_ATTEMPTS) {
    const lockedUntil = new Date(Date.now() + LOCKOUT_MINS * 60000);
    await pool.execute(
      'UPDATE email_lockouts SET attempts=?, locked_until=?, last_attempt=NOW() WHERE email=?',
      [newAttempts, lockedUntil, email]
    );
    return { attempts: newAttempts, locked: true, until: lockedUntil };
  }
  await pool.execute(
    'UPDATE email_lockouts SET attempts=?, last_attempt=NOW() WHERE email=?',
    [newAttempts, email]
  );
  return { attempts: newAttempts, locked: false };
}

async function clearFailedAttempts(email) {
  await pool.execute('UPDATE email_lockouts SET attempts=0, locked_until=NULL WHERE email=?', [email]);
}

// ── ROTAS ───────────────────────────────────────────────

// Health check
app.get('/api/health', (req, res) => res.json({ ok: true, version: '2.1' }));

// Registo
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, passwordHash } = req.body;
    if (!username || !email || !passwordHash) return res.status(400).json({ error: 'Campos obrigatórios em falta' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Email inválido' });

    const [exists] = await pool.execute('SELECT id FROM users WHERE email=?', [email]);
    if (exists.length) return res.status(409).json({ error: 'Este email já está registado' });

    const serverHash = await bcrypt.hash(passwordHash, 12);

    // Gerar códigos de recuperação
    const recoveryCodes = Array.from({length:8}, () =>
      Math.random().toString(36).substring(2,6).toUpperCase() + '-' +
      Math.random().toString(36).substring(2,6).toUpperCase()
    );
    const hashedCodes = await Promise.all(recoveryCodes.map(c => bcrypt.hash(c, 8)));

    await pool.execute(
      'INSERT INTO users (email, username, password_hash, recovery_codes) VALUES (?,?,?,?)',
      [email, username, serverHash, JSON.stringify(hashedCodes)]
    );

    res.json({ ok: true, recoveryCodes });
  } catch(e) {
    console.error('Register error:', e);
    res.status(500).json({ error: 'Erro interno no servidor' });
  }
});

// Login — com rate limiting por email
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, passwordHash } = req.body;
    if (!email || !passwordHash) return res.status(400).json({ error: 'Campos obrigatórios em falta' });

    // Verificar bloqueio deste email
    const lockout = await checkEmailLockout(email);
    if (lockout.blocked) {
      return res.status(429).json({
        error: `Conta bloqueada por ${lockout.mins} minuto(s). Tenta mais tarde.`,
        blocked: true,
        mins: lockout.mins
      });
    }

    const [rows] = await pool.execute('SELECT * FROM users WHERE email=?', [email]);
    if (!rows.length) {
      // Não revelar se email existe — registar tentativa
      await recordFailedAttempt(email);
      const check = await checkEmailLockout(email);
      const remaining = MAX_ATTEMPTS - (check.remaining !== undefined ? MAX_ATTEMPTS - check.remaining : 0);
      return res.status(401).json({ error: 'Credenciais inválidas' });
    }

    const valid = await bcrypt.compare(passwordHash, rows[0].password_hash);
    if (!valid) {
      const result = await recordFailedAttempt(email);
      if (result.locked) {
        return res.status(429).json({
          error: `Muitas tentativas falhadas. Conta bloqueada por ${LOCKOUT_MINS} minutos.`,
          blocked: true,
          mins: LOCKOUT_MINS
        });
      }
      const remaining = MAX_ATTEMPTS - result.attempts;
      return res.status(401).json({
        error: `Credenciais inválidas. ${remaining} tentativa(s) restante(s).`,
        remaining
      });
    }

    // Login correto — limpar tentativas falhadas
    await clearFailedAttempts(email);

    // Gerar OTP
    const otp = String(Math.floor(100000 + Math.random() * 900000));
    const otpExpiry = new Date(Date.now() + 10 * 60000);

    await pool.execute(
      'UPDATE users SET otp_code=?, otp_expiry=? WHERE id=?',
      [otp, otpExpiry, rows[0].id]
    );

    // Enviar email
    await sendOTPEmail(email, rows[0].username, otp);

    await pool.execute(
      'INSERT INTO login_attempts (email, ip_address, success) VALUES (?,?,0)',
      [email, req.ip]
    );

    res.json({ ok: true, message: 'Código enviado para o email' });
  } catch(e) {
    console.error('Login error:', e);
    res.status(500).json({ error: 'Erro interno no servidor' });
  }
});

// Verificar OTP
app.post('/api/auth/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    if (!email || !otp) return res.status(400).json({ error: 'Dados em falta' });

    const [rows] = await pool.execute('SELECT * FROM users WHERE email=?', [email]);
    if (!rows.length) return res.status(401).json({ error: 'Utilizador não encontrado' });

    const user = rows[0];
    if (!user.otp_code || user.otp_code !== String(otp).trim()) {
      return res.status(401).json({ error: 'Código inválido' });
    }
    if (new Date(user.otp_expiry) < new Date()) {
      return res.status(401).json({ error: 'Código expirado. Faz login novamente.' });
    }

    // Limpar OTP
    await pool.execute('UPDATE users SET otp_code=NULL, otp_expiry=NULL, last_login=NOW() WHERE id=?', [user.id]);
    await pool.execute('UPDATE login_attempts SET success=1 WHERE email=? ORDER BY id DESC LIMIT 1', [email]);

    const token = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '2h' }
    );

    res.json({ ok: true, token, user: { id: user.id, username: user.username, email: user.email } });
  } catch(e) {
    console.error('OTP error:', e);
    res.status(500).json({ error: 'Erro interno no servidor' });
  }
});

// Reenviar OTP
app.post('/api/auth/resend-otp', async (req, res) => {
  try {
    const { email } = req.body;
    const [rows] = await pool.execute('SELECT * FROM users WHERE email=?', [email]);
    if (!rows.length) return res.status(404).json({ error: 'Utilizador não encontrado' });

    const otp = String(Math.floor(100000 + Math.random() * 900000));
    const otpExpiry = new Date(Date.now() + 10 * 60000);
    await pool.execute('UPDATE users SET otp_code=?, otp_expiry=? WHERE id=?', [otp, otpExpiry, rows[0].id]);
    await sendOTPEmail(email, rows[0].username, otp);

    res.json({ ok: true });
  } catch(e) {
    res.status(500).json({ error: 'Erro ao reenviar código' });
  }
});

// ── Items ────────────────────────────────────────────────

app.get('/api/items', authMiddleware, async (req, res) => {
  try {
    const [items] = await pool.execute(
      'SELECT id, encrypted_data, item_type, created_at FROM vault_items WHERE user_id=? ORDER BY created_at DESC',
      [req.userId]
    );
    res.json({ items });
  } catch(e) { res.status(500).json({ error: 'Erro ao carregar itens' }); }
});

app.post('/api/items', authMiddleware, async (req, res) => {
  try {
    const { encryptedBlob, itemType } = req.body;
    if (!encryptedBlob || !itemType) return res.status(400).json({ error: 'Dados em falta' });
    const [result] = await pool.execute(
      'INSERT INTO vault_items (user_id, encrypted_data, item_type) VALUES (?,?,?)',
      [req.userId, encryptedBlob, itemType]
    );
    res.json({ ok: true, id: result.insertId });
  } catch(e) { res.status(500).json({ error: 'Erro ao guardar item' }); }
});

app.put('/api/items/:id', authMiddleware, async (req, res) => {
  try {
    const { encryptedBlob, itemType } = req.body;
    await pool.execute(
      'UPDATE vault_items SET encrypted_data=?, item_type=? WHERE id=? AND user_id=?',
      [encryptedBlob, itemType, req.params.id, req.userId]
    );
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: 'Erro ao actualizar item' }); }
});

app.delete('/api/items/:id', authMiddleware, async (req, res) => {
  try {
    await pool.execute('DELETE FROM vault_items WHERE id=? AND user_id=?', [req.params.id, req.userId]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: 'Erro ao eliminar item' }); }
});

// ── User ─────────────────────────────────────────────────

app.get('/api/user/me', authMiddleware, async (req, res) => {
  try {
    const [rows] = await pool.execute('SELECT id, username, email, created_at FROM users WHERE id=?', [req.userId]);
    if (!rows.length) return res.status(404).json({ error: 'Utilizador não encontrado' });
    res.json({ user: rows[0] });
  } catch(e) { res.status(500).json({ error: 'Erro' }); }
});

app.put('/api/user/password', authMiddleware, async (req, res) => {
  try {
    const { oldHash, newHash, reencryptedItems } = req.body;
    const [rows] = await pool.execute('SELECT password_hash FROM users WHERE id=?', [req.userId]);
    if (!rows.length) return res.status(404).json({ error: 'Utilizador não encontrado' });

    const valid = await bcrypt.compare(oldHash, rows[0].password_hash);
    if (!valid) return res.status(401).json({ error: 'Senha actual incorreta' });

    const serverHash = await bcrypt.hash(newHash, 12);
    await pool.execute('UPDATE users SET password_hash=? WHERE id=?', [serverHash, req.userId]);

    if (reencryptedItems && reencryptedItems.length) {
      for (const item of reencryptedItems) {
        await pool.execute(
          'UPDATE vault_items SET encrypted_data=?, item_type=? WHERE id=? AND user_id=?',
          [item.blob, item.type, item.id, req.userId]
        );
      }
    }
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: 'Erro ao alterar senha' }); }
});

app.get('/api/user/export', authMiddleware, async (req, res) => {
  try {
    const [items] = await pool.execute(
      'SELECT id, encrypted_data, item_type, created_at FROM vault_items WHERE user_id=?',
      [req.userId]
    );
    res.json({ exportedAt: new Date(), items });
  } catch(e) { res.status(500).json({ error: 'Erro ao exportar' }); }
});

// ── Start ────────────────────────────────────────────────
const PORT = process.env.PORT || 3001;
pool.getConnection().then(conn => {
  conn.release();
  app.listen(PORT, () => {
    console.log(`\n✅ MySQL conectado.\n`);
    console.log(`🔐 VelorumSafe Server v2.1`);
    console.log(`   Porta      : ${PORT}`);
    console.log(`   Email      : ${process.env.MAIL_USER}`);
    console.log(`   Rate limit : ${MAX_ATTEMPTS} tentativas por email → ${LOCKOUT_MINS} min bloqueio`);
    console.log(`   Encriptação: AES-256-GCM (cliente) + bcrypt (servidor)\n`);
  });
}).catch(err => {
  console.error('❌ Erro ao conectar MySQL:', err.message);
  process.exit(1);
});
