const { Pool } = require('pg');

const isProd = process.env.NODE_ENV === 'production';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: isProd ? { rejectUnauthorized: false } : false,
});

async function ping() {
  const r = await pool.query('select 1 as ok');
  return r.rows[0]?.ok === 1;
}

function query(text, params) {
  return pool.query(text, params);
}

module.exports = { pool, query, ping };
