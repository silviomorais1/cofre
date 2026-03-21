/**
 * VelorumSafe — Backend Node.js + MySQL
 * 2FA via Email OTP (Nodemailer)
 * ==========================================
 * Instalar dependências:
 *   npm install express mysql2 bcrypt jsonwebtoken nodemailer
 *               express-rate-limit helmet cors dotenv express-validator
 *
 * Arrancar:
 *   node server.js
 */

require('dotenv').config();
const express     = require('express');
const mysql       = require('mysql2/promise');
const bcrypt      = require('bcryptjs');
const jwt         = require('jsonwebtoken');
const nodemailer  = require('nodemailer');
const rateLimit   = require('express-rate-limit');
const helmet      = require('helmet');
const cors        = require('cors');
const { body, validationResult } = require('express-validator');

const app  = express();
const PORT = process.env.PORT || 3001;

// ─────────────────────────────────────────
//  MIDDLEWARES GLOBAIS
// ─────────────────────────────────────────
app.use(helmet());
app.use(cors({
  origin: '*',
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization']
}));
app.use(express.json({ limit: '10mb' }));

// ─────────────────────────────────────────
//  POOL MySQL
// ─────────────────────────────────────────
const pool = mysql.createPool({
  host:     process.env.DB_HOST || 'localhost',
  user:     process.env.DB_USER || 'vault_user',
  password: process.env.DB_PASS || '',
  database: process.env.DB_NAME || 'vault_db',
  waitForConnections: true,
  connectionLimit: 10,
});

// ─────────────────────────────────────────
//  EMAIL (Nodemailer)
// ─────────────────────────────────────────
const transporter = nodemailer.createTransport({
  host: process.env.MAIL_HOST || 'smtp-relay.brevo.com',
  port: 587,
  secure: false,
  auth: {
    user: process.env.MAIL_USER,
    pass: process.env.MAIL_PASS,
  },
});

async function sendOTPEmail(toEmail, username, otp) {
  const mailOptions = {
    from: process.env.MAIL_FROM || `VelorumSafe <${process.env.MAIL_USER}>`,
    to:   toEmail,
    subject: `${otp} — Código de verificação VelorumSafe`,
    html: `
      <div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;background:#0d1520;color:#e8f4ff;padding:32px;border-radius:16px;border:1px solid rgba(0,210,255,0.2);">
        <h2 style="color:#00d2ff;margin-bottom:8px;">🔐 VelorumSafe</h2>
        <p style="color:#7a9bb8;margin-bottom:24px;">Cofre Digital Seguro</p>
        <p>Olá <strong>${username}</strong>,</p>
        <p style="margin:16px 0;">O teu código de verificação é:</p>
        <div style="background:#080d14;border:1px solid rgba(0,210,255,0.3);border-radius:12px;padding:24px;text-align:center;margin:20px 0;">
          <span style="font-size:36px;font-weight:bold;letter-spacing:12px;color:#00d2ff;font-family:monospace;">${otp}</span>
        </div>
        <p style="color:#7a9bb8;font-size:13px;">Válido por <strong style="color:#e8f4ff;">10 minutos</strong>.</p>
        <p style="color:#7a9bb8;font-size:13px;">Se não foste tu, ignora este email.</p>
        <hr style="border-color:rgba(0,210,255,0.1);margin:24px 0;">
        <p style="color:#4a6a85;font-size:11px;">VelorumSafe — Os teus dados estão encriptados com AES-256-GCM</p>
      </div>
    `,
  };
  await transporter.sendMail(mailOptions);
}

// ─────────────────────────────────────────
//  RATE LIMITING
// ─────────────────────────────────────────
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: 'Demasiadas tentativas. Tenta em 15 minutos.' },
});

const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  message: { error: 'Demasiados registos deste IP.' },
});

const otpLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 10,
  message: { error: 'Demasiadas tentativas de OTP.' },
});

// ─────────────────────────────────────────
//  MIDDLEWARE AUTH (JWT)
// ─────────────────────────────────────────
function authMiddleware(req, res, next) {
  const header = req.headers['authorization'];
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token em falta' });
  }
  const token = header.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'dev_secret_muda_isto');
    req.userId    = decoded.userId;
    req.userEmail = decoded.email;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Token inválido ou expirado' });
  }
}

// ─────────────────────────────────────────
//  HELPERS
// ─────────────────────────────────────────
function generateOTP() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

// ─────────────────────────────────────────
//  ROTAS — AUTH
// ─────────────────────────────────────────

// POST /api/auth/register
app.post('/api/auth/register', registerLimiter,
  async (req, res) => {
    const { email, username, passwordHash, recoveryCodes } = req.body;
    if (!email || !username || !passwordHash) {
      return res.status(400).json({ error: 'Campos obrigatórios em falta' });
    }
    try {
      // Verificar se já existe
      const [existing] = await pool.execute(
        'SELECT id FROM users WHERE email = ?', [email]
      );
      if (existing.length) return res.status(409).json({ error: 'Email já registado' });

      // Hash duplo: cliente fez PBKDF2, servidor faz bcrypt por cima
      const serverHash = await bcrypt.hash(passwordHash, 12);

      // Guardar códigos de recuperação (já vêm com hash SHA-256 do cliente)
      const codesJSON = JSON.stringify(recoveryCodes || []);

      await pool.execute(
        'INSERT INTO users (email, username, password_hash, recovery_codes) VALUES (?, ?, ?, ?)',
        [email, username, serverHash, codesJSON]
      );

      // Log
      await pool.execute(
        'INSERT INTO login_attempts (email, ip_address, success) VALUES (?, ?, ?)',
        [email, req.ip, 1]
      );

      res.json({ ok: true, message: 'Conta criada com sucesso' });
    } catch (err) {
      console.error('Register error:', err);
      res.status(500).json({ error: 'Erro interno no servidor' });
    }
  }
);

// POST /api/auth/login  — gera e envia OTP
app.post('/api/auth/login', loginLimiter,
  async (req, res) => {
    const { email, passwordHash } = req.body;
    if (!email || !passwordHash) {
      return res.status(400).json({ error: 'Email e senha obrigatórios' });
    }
    try {
      const [rows] = await pool.execute(
        'SELECT id, username, password_hash FROM users WHERE email = ?', [email]
      );

      // Resposta genérica para não revelar se o email existe
      if (!rows.length) {
        await pool.execute(
          'INSERT INTO login_attempts (email, ip_address, success) VALUES (?, ?, ?)',
          [email, req.ip, 0]
        );
        return res.status(401).json({ error: 'Credenciais inválidas' });
      }

      const user = rows[0];
      const valid = await bcrypt.compare(passwordHash, user.password_hash);
      if (!valid) {
        await pool.execute(
          'INSERT INTO login_attempts (email, ip_address, success) VALUES (?, ?, ?)',
          [email, req.ip, 0]
        );
        return res.status(401).json({ error: 'Credenciais inválidas' });
      }

      // Gerar OTP
      const otp     = generateOTP();
      const expires = new Date(Date.now() + 10 * 60 * 1000); // 10 min

      // Guardar OTP na BD (limpa o anterior primeiro)
      await pool.execute(
        'DELETE FROM otp_codes WHERE user_id = ?', [user.id]
      );
      await pool.execute(
        'INSERT INTO otp_codes (user_id, code, expires_at) VALUES (?, ?, ?)',
        [user.id, otp, expires]
      );

      // Enviar email
      await sendOTPEmail(email, user.username, otp);

      res.json({ ok: true, message: 'Código OTP enviado para o teu email' });
    } catch (err) {
      console.error('Login error:', err);
      res.status(500).json({ error: 'Erro ao enviar email. Verifica as configurações.' });
    }
  }
);

// POST /api/auth/verify-otp — verifica OTP e devolve JWT
app.post('/api/auth/verify-otp', otpLimiter,
  async (req, res) => {
    const { email, otp } = req.body;
    if (!email || !otp) {
      return res.status(400).json({ error: 'Email e código obrigatórios' });
    }
    try {
      const [userRows] = await pool.execute(
        'SELECT id, username, email FROM users WHERE email = ?', [email]
      );
      if (!userRows.length) return res.status(401).json({ error: 'Utilizador não encontrado' });

      const user = userRows[0];
      const [otpRows] = await pool.execute(
        'SELECT * FROM otp_codes WHERE user_id = ? AND code = ? AND expires_at > NOW()',
        [user.id, otp]
      );

      if (!otpRows.length) return res.status(401).json({ error: 'Código inválido ou expirado' });

      // Apagar OTP usado
      await pool.execute('DELETE FROM otp_codes WHERE user_id = ?', [user.id]);

      // Actualizar last_login
      await pool.execute(
        'UPDATE users SET last_login = NOW() WHERE id = ?', [user.id]
      );

      // Emitir JWT (30 minutos)
      const token = jwt.sign(
        { userId: user.id, email: user.email },
        process.env.JWT_SECRET || 'dev_secret_muda_isto',
        { expiresIn: '30m' }
      );

      res.json({
        ok: true,
        token,
        user: { id: user.id, username: user.username, email: user.email }
      });
    } catch (err) {
      console.error('OTP verify error:', err);
      res.status(500).json({ error: 'Erro interno no servidor' });
    }
  }
);

// POST /api/auth/resend-otp — reenviar OTP
app.post('/api/auth/resend-otp', otpLimiter, async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email em falta' });
  try {
    const [rows] = await pool.execute(
      'SELECT id, username FROM users WHERE email = ?', [email]
    );
    if (!rows.length) return res.json({ ok: true }); // não revelar

    const user   = rows[0];
    const otp    = generateOTP();
    const expires = new Date(Date.now() + 10 * 60 * 1000);

    await pool.execute('DELETE FROM otp_codes WHERE user_id = ?', [user.id]);
    await pool.execute(
      'INSERT INTO otp_codes (user_id, code, expires_at) VALUES (?, ?, ?)',
      [user.id, otp, expires]
    );
    await sendOTPEmail(email, user.username, otp);

    res.json({ ok: true });
  } catch (err) {
    console.error('Resend OTP error:', err);
    res.status(500).json({ error: 'Erro ao reenviar código' });
  }
});

// ─────────────────────────────────────────
//  ROTAS — ITENS DO COFRE
// ─────────────────────────────────────────

// GET /api/items — listar itens do utilizador
app.get('/api/items', authMiddleware, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      'SELECT id, encrypted_data, item_type, created_at FROM vault_items WHERE user_id = ? ORDER BY created_at DESC',
      [req.userId]
    );
    res.json({ items: rows });
  } catch (err) {
    console.error('Get items error:', err);
    res.status(500).json({ error: 'Erro ao carregar itens' });
  }
});

// POST /api/items — guardar novo item
app.post('/api/items', authMiddleware,
  async (req, res) => {
    const { encryptedData, item_type } = req.body;
    if (!encryptedData || !item_type) {
      return res.status(400).json({ error: 'Dados do item em falta' });
    }
    try {
      const [result] = await pool.execute(
        'INSERT INTO vault_items (user_id, encrypted_data, item_type) VALUES (?, ?, ?)',
        [req.userId, encryptedData, item_type]
      );
      res.json({ ok: true, id: result.insertId });
    } catch (err) {
      console.error('Save item error:', err);
      res.status(500).json({ error: 'Erro ao guardar item' });
    }
  }
);

// DELETE /api/items/:id — eliminar item
app.delete('/api/items/:id', authMiddleware, async (req, res) => {
  try {
    const [result] = await pool.execute(
      'DELETE FROM vault_items WHERE id = ? AND user_id = ?',
      [req.params.id, req.userId]
    );
    if (result.affectedRows === 0) return res.status(404).json({ error: 'Item não encontrado' });
    res.json({ ok: true });
  } catch (err) {
    console.error('Delete item error:', err);
    res.status(500).json({ error: 'Erro ao eliminar item' });
  }
});

// ─────────────────────────────────────────
//  ROTAS — UTILIZADOR
// ─────────────────────────────────────────

// GET /api/user/me
app.get('/api/user/me', authMiddleware, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      'SELECT id, username, email, created_at, last_login FROM users WHERE id = ?',
      [req.userId]
    );
    if (!rows.length) return res.status(404).json({ error: 'Utilizador não encontrado' });
    res.json({ user: rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'Erro interno' });
  }
});

// GET /api/user/export — exportar cofre (blobs encriptados)
app.get('/api/user/export', authMiddleware, async (req, res) => {
  try {
    const [items] = await pool.execute(
      'SELECT id, encrypted_data, item_type, created_at FROM vault_items WHERE user_id = ?',
      [req.userId]
    );
    const [user]  = await pool.execute(
      'SELECT username, email FROM users WHERE id = ?', [req.userId]
    );
    res.json({
      exported_at: new Date().toISOString(),
      user: user[0],
      items,
      note: 'Dados encriptados com AES-256-GCM. Apenas o dono pode desencriptar.'
    });
  } catch (err) {
    res.status(500).json({ error: 'Erro ao exportar' });
  }
});

// ─────────────────────────────────────────
//  ROTA DE SAÚDE
// ─────────────────────────────────────────
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', version: '2.0', time: new Date().toISOString() });
});

// ─────────────────────────────────────────
//  ARRANQUE
// ─────────────────────────────────────────
async function start() {
  try {
    const conn = await pool.getConnection();
    conn.release();
    console.log('\n\x1b[32m✅ MySQL conectado.\x1b[0m');
  } catch (err) {
    console.error('\x1b[31m❌ Erro ao conectar ao MySQL:\x1b[0m', err.message);
    console.error('   Verifica se o MySQL está a correr e as credenciais no .env');
    process.exit(1);
  }

  app.listen(PORT, () => {
    console.log(`
\x1b[36m🔐 VelorumSafe Server v2.0\x1b[0m
   Porta      : \x1b[33m${PORT}\x1b[0m
   2FA        : Email OTP (10 min)
   Email      : \x1b[33m${process.env.MAIL_USER || 'não configurado'}\x1b[0m
   Ambiente   : \x1b[33m${process.env.NODE_ENV || 'development'}\x1b[0m
   Encriptação: AES-256-GCM (cliente) + bcrypt (servidor)

\x1b[90m   Ctrl+C para parar\x1b[0m
`);
  });
}

start();
