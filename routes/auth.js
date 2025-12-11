const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { query } = require('../db');

const router = express.Router();

router.post('/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body ?? {};
    if (!name || !email || !password) return res.status(400).json({ ok: false, error: 'INVALID_INPUT' });
    if (!/^\S+@\S+\.\S+$/.test(String(email).trim())) return res.status(400).json({ ok: false, error: 'INVALID_EMAIL' });
    if (String(password).length < 8) return res.status(400).json({ ok: false, error: 'WEAK_PASSWORD' });

    const emailNorm = String(email).trim();
    const existed = await query('SELECT id FROM users WHERE lower(email)=lower($1) LIMIT 1', [emailNorm]);
    if (existed.rowCount) return res.status(409).json({ ok: false, error: 'EMAIL_TAKEN' });

    const hash = await bcrypt.hash(String(password), Number(process.env.BCRYPT_SALT_ROUNDS || 10));
    const ins = await query(
      `INSERT INTO users (email, password_hash, name, role)
       VALUES ($1,$2,$3,'user')
       RETURNING id, email, name, role, created_at`,
      [emailNorm, hash, String(name).trim()]
    );
    const user = ins.rows[0];

    const token = jwt.sign({ sub: user.user_no, role: user.role }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({ ok: true, token, user });
  } catch (e) {
    if (e?.code === '23505') return res.status(409).json({ ok: false, error: 'EMAIL_TAKEN' });
    console.error('[signup]', e);
    res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
  }
});

router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body ?? {};
    if (!email || !password) return res.status(400).json({ ok: false, error: 'INVALID_INPUT' });

    const r = await query(
      `SELECT id, email, name, role, is_active, password_hash
       FROM users WHERE lower(email)=lower($1) LIMIT 1`,
      [String(email).trim()]
    );
    if (!r.rowCount) return res.status(401).json({ ok: false, error: 'INVALID_CREDENTIALS' });

    const user = r.rows[0];
    const ok = user.password_hash
      ? await bcrypt.compare(String(password), user.password_hash)
      : false;
    if (!ok) return res.status(401).json({ ok: false, error: 'INVALID_CREDENTIALS' });
    if (user.is_active === false) return res.status(403).json({ ok: false, error: 'INACTIVE_USER' });

    const token = jwt.sign({ sub: user.user_no, role: user.role }, process.env.JWT_SECRET, { expiresIn: '7d' });
    delete user.password_hash;
    res.json({ ok: true, token, user });
  } catch (e) {
    console.error('[login]', e);
    res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
  }
});

module.exports = router;
