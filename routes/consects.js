const express = require('express');
const { query } = require('../db');

const router = express.Router();

/**
 * POST /consents
 * body: {
 *   userId: string,
 *   items: [{ type: 'privacy'|'tos'|'marketing', version?: string, accepted: boolean, payload?: any }]
 * }
 */
router.post('/', async (req, res) => {
  try {
    const { userId, items } = req.body ?? {};
    if (!userId || !Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ ok: false, error: 'INVALID_INPUT' });
    }

    const values = [];
    const rows = items.map((it, i) => {
      const idx = i * 5;
      values.push(
        userId,
        String(it.type),
        String(it.version || 'v1'),
        !!it.accepted,
        JSON.stringify(it.payload || {})
      );
      return `($${idx + 1}, $${idx + 2}, $${idx + 3}, $${idx + 4}, $${idx + 5})`;
    });

    await query(
      `INSERT INTO consents (user_id, type, version, accepted, payload) VALUES ${rows.join(',')}`,
      values
    );

    res.status(201).json({ ok: true });
  } catch (e) {
    console.error('[consents]', e);
    res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
  }
});

module.exports = router;
