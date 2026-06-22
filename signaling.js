// server/signaling.js
import 'dotenv/config';
import http from 'http';
import express from 'express';
import morgan from 'morgan';
import { WebSocketServer } from 'ws';
import { Pool } from 'pg';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

dotenv.config({ path: '../.env' });

const PORT = Number(process.env.SIGNAL_PORT || process.env.PORT || 8082);

// ✅ [2026-02-24] NEW: Ahri API proxy settings (apiKey는 서버에서만 보관/주입)
const AHRIRAG_API_BASE = String(process.env.AHRIRAG_API_BASE || 'https://api.ahrirag.com').replace(/\/+$/, '');
const AHRIRAG_API_KEY = String(process.env.AHRIRAG_API_KEY || '').trim();
const AHRIRAG_MODEL_FAMILY = String(process.env.AHRIRAG_MODEL_FAMILY || '').trim();

// ─────────────────────────────────────────────────────────
// PostgreSQL
// ─────────────────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});
const query = (sql, params) => pool.query(sql, params);
async function ping() {
  const r = await query('select 1 as ok');
  return r.rows[0]?.ok === 1;
}

// ─────────────────────────────────────────────────────────
// ✅ JWT 토큰 파싱 유틸 (⚠️ 아래 라우트들에서 먼저 쓰이므로 위로 올림)  ✅ [2026-02-25] FIX
// ─────────────────────────────────────────────────────────
function verifyTokenFromReq(req) {
  try {
    const h = req.headers.authorization || req.headers.Authorization || '';
    const [typ, tk] = String(h).split(' ');
    if (typ?.toLowerCase() !== 'bearer' || !tk) return null;
    return jwt.verify(tk, process.env.JWT_SECRET);
  } catch {
    return null;
  }
}

// ─────────────────────────────────────────────────────────
// Helpers (validation/policy)
// ─────────────────────────────────────────────────────────
const onlyDigits = (s = '') => String(s).replace(/\D/g, '');
const isEmail = (v = '') => /^\S+@\S+\.\S+$/.test(String(v).trim());

// DB 제약과 맞춤(가입/저장): 숫자 10~11자리
const isPhone10or11 = (s = '') => /^[0-9]{10,11}$/.test(onlyDigits(s));

// 아이디찾기용(보다 엄격): 010으로 시작 11자리
const isPhone010 = (s = '') => /^010\d{8}$/.test(onlyDigits(s));

// 비번 정책(클라와 동일: ASCII 0x21~0x7E, 영문/숫자/특수, 8자↑)
const passwordStrong = (pw = '') => {
  const str = String(pw);
  return (
    str.length >= 8 &&
    /^[\x21-\x7E]+$/.test(str) &&
    /[A-Za-z]/.test(str) &&
    /\d/.test(str) &&
    /[^A-Za-z0-9]/.test(str)
  );
};

// 이메일 마스킹(아이디 찾기 힌트용)
const maskEmail = (email = '') => {
  const [local, domain] = String(email).split('@');
  if (!domain) return '***';
  const dparts = domain.split('.');
  const dname = dparts.slice(0, -1).join('.') || domain;
  const tld = dparts.slice(-1)[0] || '';
  const mLocal = local.length <= 2 ? (local[0] || '*') + '***' : local.slice(0, 2) + '***';
  const mDom = dname.length <= 2 ? (dname[0] || '*') + '***' : dname.slice(0, 2) + '***';
  return `${mLocal}@${mDom}${tld ? '.' + tld : ''}`;
};

// ✅ [2026-02-12] NEW: 담당고객 상한(기본 200명). 과금 확장 시 env로 올릴 수 있게.
const CUSTOMER_LIMIT_PER_PLANNER = Number(process.env.CUSTOMER_LIMIT_PER_PLANNER || 200);

// ✅ [2026-02-12] NEW: 고객 기본 저장용량(MB). DB default가 있으면 이 값은 무시해도 됨(하지만 안전하게 세팅).
const DEFAULT_USER_FILE_MB = Number(process.env.DEFAULT_USER_FILE_MB || 10);

// ✅ [2026-02-12] NEW: plannerNo(=users.user_no of planner)에 대한 담당 고객 수 제한 체크 (트랜잭션 + 잠금)
// - 동시성에서 200명 초과 삽입이 발생하지 않도록 planner row를 FOR UPDATE로 잠금
async function enforcePlannerCustomerLimitTx(client, plannerNoInt, limit = CUSTOMER_LIMIT_PER_PLANNER) {
  const rLock = await client.query(
    `SELECT id, user_no, role FROM users WHERE role='planner' AND user_no=$1 LIMIT 1 FOR UPDATE`,
    [plannerNoInt],
  );
  if (!rLock.rowCount) {
    const err = new Error('INVALID_PLANNER_NO');
    err.code = 'INVALID_PLANNER_NO';
    throw err;
  }

  const rCount = await client.query(`SELECT COUNT(*)::int AS cnt FROM users WHERE role='user' AND planner_no=$1`, [
    plannerNoInt,
  ]);

  const cnt = Number(rCount.rows[0]?.cnt ?? 0);
  if (cnt >= limit) {
    const err = new Error('CUSTOMER_LIMIT_EXCEEDED');
    err.code = 'CUSTOMER_LIMIT_EXCEEDED';
    err.detail = { cnt, limit };
    throw err;
  }
}

// ─────────────────────────────────────────────────────────
// HTTP (REST + POP 큐)
// ─────────────────────────────────────────────────────────
const app = express();
app.use(express.json());
app.use(morgan('dev'));

// CORS (개발 기본)
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  // ✅ [2026-02-10] FIX: credentials 포함 요청(preflight) 호환
  res.setHeader('Access-Control-Allow-Credentials', 'true');

  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// 헬스 체크
app.get('/health', async (_req, res) => {
  try {
    res.json({ ok: await ping(), time: new Date().toISOString() });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

// ✅ [2026-02-24] NEW: Ahri init 프록시
app.post('/auth/ahri', async (req, res) => {
  try {
    if (!AHRIRAG_API_KEY) {
      return res.status(500).json({ ok: false, error: 'AHRIRAG_API_KEY_missing' });
    }

    const _fetch = globalThis.fetch;
    if (typeof _fetch !== 'function') {
      return res
        .status(500)
        .json({ ok: false, error: 'FETCH_NOT_AVAILABLE(Node18+ required or add node-fetch)' });
    }

    const body = req.body ?? {};
    let finalUserId = String(body.userId || '').trim();

    const payload = verifyTokenFromReq(req);
    if (payload?.sub) {
      const meRes = await query(`SELECT id, role, user_no FROM users WHERE id = $1 LIMIT 1`, [payload.sub]);
      if (meRes.rowCount) {
        const me = meRes.rows[0];
        if (me.role === 'user') finalUserId = `ahrisure_customer_${me.user_no}`;
        else if (me.role === 'manager') finalUserId = `ahrisure_manager_${me.user_no}`;
        else if (me.role === 'planner') finalUserId = `ahrisure_planner_${me.user_no}`;
        else finalUserId = `ahrisure_${me.role}_${me.user_no}`;
      }
    }

    if (!finalUserId) return res.status(400).json({ ok: false, error: 'userId_required' });

    const url = `${AHRIRAG_API_BASE}/init/ahri`;

    const forward1 = {
      ...body,
      userId: finalUserId,
      apiKey: AHRIRAG_API_KEY,
      modelFamily: AHRIRAG_MODEL_FAMILY || String(body.modelFamily || ''),
    };

    const r1 = await _fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(forward1),
    });

    if (r1.status === 422) {
      const forward2 = { userId: finalUserId };
      const r2 = await _fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(forward2),
      });

      const t2 = await r2.text();
      res.status(r2.status);
      const ct2 = r2.headers.get('content-type');
      if (ct2) res.setHeader('content-type', ct2);
      return res.send(t2);
    }

    const t1 = await r1.text();
    res.status(r1.status);
    const ct1 = r1.headers.get('content-type');
    if (ct1) res.setHeader('content-type', ct1);
    return res.send(t1);
  } catch (e) {
    console.error('[auth/ahri]', e);
    return res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
  }
});

// ✅ [2026-02-24] NEW: Ahri update 프록시
app.post('/auth/ahri/update', async (req, res) => {
  try {
    if (!AHRIRAG_API_KEY) {
      return res.status(500).json({ ok: false, error: 'AHRIRAG_API_KEY_missing' });
    }

    const _fetch = globalThis.fetch;
    if (typeof _fetch !== 'function') {
      return res
        .status(500)
        .json({ ok: false, error: 'FETCH_NOT_AVAILABLE(Node18+ required or add node-fetch)' });
    }

    const body = req.body ?? {};
    let finalUserId = String(body.userId || '').trim();

    const payload = verifyTokenFromReq(req);
    if (payload?.sub) {
      const meRes = await query(`SELECT id, role, user_no FROM users WHERE id = $1 LIMIT 1`, [payload.sub]);
      if (meRes.rowCount) {
        const me = meRes.rows[0];
        if (me.role === 'user') finalUserId = `ahrisure_customer_${me.user_no}`;
        else if (me.role === 'manager') finalUserId = `ahrisure_manager_${me.user_no}`;
        else if (me.role === 'planner') finalUserId = `ahrisure_planner_${me.user_no}`;
        else finalUserId = `ahrisure_${me.role}_${me.user_no}`;
      }
    }

    if (!finalUserId) return res.status(400).json({ ok: false, error: 'userId_required' });

    const url = `${AHRIRAG_API_BASE}/update/ahri`;

    const forward = {
      ...body,
      userId: finalUserId,
      apiKey: AHRIRAG_API_KEY,
      modelFamily: AHRIRAG_MODEL_FAMILY || String(body.modelFamily || ''),
    };

    const r = await _fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(forward),
    });

    const t = await r.text();
    res.status(r.status);
    const ct = r.headers.get('content-type');
    if (ct) res.setHeader('content-type', ct);
    return res.send(t);
  } catch (e) {
    console.error('[auth/ahri/update]', e);
    return res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
  }
});

// 인메모리 큐
const messages = new Map();
app.post('/auth/messages', (req, res) => {
  const { roomId, to, msg } = req.body || {};
  if (!roomId || !to || !msg || !msg.text) {
    return res.status(400).json({ ok: false, error: 'roomId/to/msg.text required' });
  }
  if (!messages.has(roomId)) messages.set(roomId, { toUser: [], toManager: [] });
  const box = messages.get(roomId);
  if (to === 'user') box.toUser.push(msg);
  else if (to === 'manager') box.toManager.push(msg);
  else return res.status(400).json({ ok: false, error: 'to must be user|manager' });
  return res.json({ ok: true });
});
app.get('/auth/messages', (req, res) => {
  const { roomId, for: forWho } = req.query;
  if (!roomId || !forWho) return res.status(400).json({ ok: false, error: 'roomId & for required' });
  if (!messages.has(roomId)) return res.json({ ok: true, messages: [] });
  const box = messages.get(roomId);
  const list = forWho === 'user' ? box.toUser : box.toManager;
  const out = list.splice(0, list.length);
  return res.json({ ok: true, messages: out });
});
app.get('/auth/debug/messages', (req, res) => {
  const { roomId } = req.query;
  const box = messages.get(roomId) || { toUser: [], toManager: [] };
  res.json({ ok: true, debug: { roomId, toUser: box.toUser, toManager: box.toManager } });
});

// ─────────────────────────────────────────────────────────
// Quota: 업로드/삭제 used_bytes 조정
// ─────────────────────────────────────────────────────────

// 파일 업로드 전 용량 체크 + used_bytes 증가
app.post('/auth/files/upload', async (req, res) => {
  try {
    const payload = verifyTokenFromReq(req);
    if (!payload?.sub) return res.status(401).json({ ok: false, error: 'UNAUTHORIZED' });

    const { sizeBytes, targetUserNo } = req.body ?? {};
    if (!sizeBytes) return res.status(400).json({ ok: false, error: 'INVALID_INPUT' });

    let deltaMB = Number(sizeBytes) / (1024 ** 2);
    if (deltaMB < 0.001) deltaMB = 0.001;
    const delta = Number(deltaMB.toFixed(3));

    const tNoRaw = targetUserNo !== undefined && targetUserNo !== null ? Number(String(targetUserNo).trim()) : NaN;
    const hasTargetUserNo = Number.isFinite(tNoRaw) && tNoRaw > 0;

    const meRes = await query(`SELECT id, role, user_no FROM users WHERE id = $1 LIMIT 1`, [payload.sub]);
    if (!meRes.rowCount) return res.status(404).json({ ok: false, error: 'ME_NOT_FOUND' });
    const me = meRes.rows[0];

    let r;
    if (!hasTargetUserNo) {
      r = await query(
        `
        UPDATE users
        SET used_bytes = COALESCE(used_bytes, 0) + $2
        WHERE id = $1
          AND COALESCE(used_bytes, 0) + $2 <= COALESCE(file_bytes, 0)
        RETURNING id, used_bytes, file_bytes
        `,
        [payload.sub, delta],
      );
    } else {
      if (me.role === 'planner') {
        r = await query(
          `
          UPDATE users
          SET used_bytes = COALESCE(used_bytes, 0) + $2
          WHERE role = 'user'
            AND user_no = $1
            AND planner_no = $3
            AND COALESCE(used_bytes, 0) + $2 <= COALESCE(file_bytes, 0)
          RETURNING id, used_bytes, file_bytes
          `,
          [tNoRaw, delta, me.user_no],
        );
      } else if (me.role === 'admin' || me.role === 'manager') {
        r = await query(
          `
          UPDATE users
          SET used_bytes = COALESCE(used_bytes, 0) + $2
          WHERE role = 'user'
            AND user_no = $1
            AND COALESCE(used_bytes, 0) + $2 <= COALESCE(file_bytes, 0)
          RETURNING id, used_bytes, file_bytes
          `,
          [tNoRaw, delta],
        );
      } else {
        return res.status(403).json({ ok: false, error: 'FORBIDDEN_ROLE' });
      }
    }

    if (!r.rowCount) return res.status(400).json({ ok: false, error: 'QUOTA_EXCEEDED' });
    return res.json({ ok: true });
  } catch (e) {
    console.error('[files/upload]', e);
    return res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
  }
});

/**
 * ✅ [2026-02-25] NEW: 삭제 시 used_bytes 감소(차감)
 * - body: { sizeBytes }
 */
app.post('/auth/files/delete', async (req, res) => {
  try {
    const payload = verifyTokenFromReq(req);
    if (!payload?.sub) return res.status(401).json({ ok: false, error: 'UNAUTHORIZED' });

    const { sizeBytes } = req.body ?? {};
    const b = Number(sizeBytes ?? 0);
    if (!Number.isFinite(b) || b <= 0) return res.status(400).json({ ok: false, error: 'INVALID_INPUT' });

    let deltaMB = b / (1024 ** 2);
    if (deltaMB < 0.001) deltaMB = 0.001;
    const delta = Number(deltaMB.toFixed(3));

    const r = await query(
      `
      UPDATE users
      SET used_bytes = GREATEST(0, COALESCE(used_bytes, 0) - $2)
      WHERE id = $1
      RETURNING id, user_no, file_bytes, used_bytes
      `,
      [payload.sub, delta],
    );

    if (!r.rowCount) return res.status(404).json({ ok: false, error: 'ME_NOT_FOUND' });
    return res.json({ ok: true, me: r.rows[0] });
  } catch (e) {
    console.error('[files/delete]', e);
    return res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
  }
});

/**
 * ✅ [2026-02-25] NEW: 업로드 파일 메타데이터 기록(삭제 시 sizeBytes 조회용)
 *
 * 프론트(api.tsx)의 recordFilesAfterUpload()는
 * POST /auth/files/record-upload  body: { files: [ ... ] }
 * 형태로 보내므로, 서버도 그 형태를 그대로 받도록 수정함.  ✅ [2026-02-25] FIX
 *
 * DB: user_files 테이블 필요 (PK/UNIQUE: owner_user_id + collection_name + category_path + content_name)
 */
app.post('/auth/files/record-upload', async (req, res) => {
  try {
    const payload = verifyTokenFromReq(req);
    if (!payload?.sub) return res.status(401).json({ ok: false, error: 'UNAUTHORIZED' });

    const body = req.body ?? {};
    const filesRaw = Array.isArray(body.files)
      ? body.files
      : Array.isArray(body.items)
        ? body.items
        : body.collectionName && body.contentName
          ? [body] // 단건 호환
          : [];

    if (!filesRaw.length) {
      return res.status(400).json({ ok: false, error: 'INVALID_INPUT' });
    }

    const meRes = await query(`SELECT id, role, user_no FROM users WHERE id=$1 LIMIT 1`, [payload.sub]);
    if (!meRes.rowCount) return res.status(404).json({ ok: false, error: 'ME_NOT_FOUND' });
    const me = meRes.rows[0];

    // ✅ [2026-03-20] 공통 targetUserNo (body 최상단에 있는 경우)
    const bodyTargetUserNo = body.targetUserNo != null ? Number(body.targetUserNo) : NaN;

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      let okCount = 0;
      const bad = [];

      for (let i = 0; i < filesRaw.length; i += 1) {
        const f = filesRaw[i] ?? {};
        const collectionName = String(f.collectionName ?? '').trim();
        const categoryPath = String(f.categoryPath ?? '').trim(); // common은 '' 가능
        const contentName = String(f.contentName ?? '').trim();
        const mimeType = f.mimeType != null && String(f.mimeType).trim() !== '' ? String(f.mimeType).trim() : null;

        const size = Number(f.sizeBytes ?? 0);
        const sizeBytes = Number.isFinite(size) && size >= 0 ? Math.trunc(size) : null;

        if (!collectionName || !contentName || sizeBytes == null) {
          bad.push({ index: i, collectionName, categoryPath, contentName, sizeBytes: f.sizeBytes });
          continue;
        }

        // ✅ [2026-03-20] targetUserNo 처리:
        //   - 파일별 f.targetUserNo 우선, 없으면 body.targetUserNo, 없으면 요청자(me) 사용
        //   - ahrisure_customer_M_N 컬렉션: 프론트가 고객 user_no를 targetUserNo로 전달
        //   - ahrisure_manager_N 컬렉션: targetUserNo 미전달 → me(플래너 본인)로 기록
        const itemTargetNo = f.targetUserNo != null ? Number(f.targetUserNo) : NaN;
        const targetNo = Number.isFinite(itemTargetNo) && itemTargetNo > 0 ? itemTargetNo
                       : Number.isFinite(bodyTargetUserNo) && bodyTargetUserNo > 0 ? bodyTargetUserNo
                       : NaN;

        let owner = me;
        if (Number.isFinite(targetNo) && targetNo > 0 && targetNo !== me.user_no) {
          const targetRes = await client.query(
            `SELECT id, role, user_no FROM users WHERE user_no=$1 LIMIT 1`,
            [targetNo],
          );
          if (targetRes.rowCount) {
            owner = targetRes.rows[0];
          }
          // targetUserNo 지정됐지만 못 찾으면 me로 fallback (에러 대신 계속 진행)
        }

        await client.query(
          `
          INSERT INTO user_files
            (owner_user_id, owner_user_no, owner_role, collection_name, category_path, content_name,
             size_bytes, mime_type, uploaded_at, is_deleted, deleted_at)
          VALUES
            ($1,$2,$3,$4,$5,$6,$7,$8,now(),false,NULL)
          ON CONFLICT (owner_user_id, collection_name, category_path, content_name)
          DO UPDATE SET
            size_bytes = EXCLUDED.size_bytes,
            mime_type = EXCLUDED.mime_type,
            uploaded_at = now(),
            is_deleted = false,
            deleted_at = NULL
          `,
          [owner.id, owner.user_no, owner.role, collectionName, categoryPath, contentName, sizeBytes, mimeType],
        );

        okCount += 1;
      }

      await client.query('COMMIT');

      if (okCount === 0) {
        return res.status(400).json({ ok: false, error: 'INVALID_INPUT', bad });
      }

      return res.json({ ok: true, count: okCount, bad });
    } catch (e) {
      await client.query('ROLLBACK').catch(() => {});
      throw e;
    } finally {
      client.release();
    }
  } catch (e) {
    console.error('[record-upload]', e);
    return res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
  }
});

// GET /auth/files/record?collectionName=...&categoryPath=...&contentName=...
app.get('/auth/files/record', async (req, res) => {
  try {
    const payload = verifyTokenFromReq(req);
    if (!payload?.sub) return res.status(401).json({ ok: false, error: 'UNAUTHORIZED' });

    const collectionName = String(req.query.collectionName ?? '').trim();
    const categoryPath = String(req.query.categoryPath ?? '').trim();
    const contentName = String(req.query.contentName ?? '').trim();

    if (!collectionName || !contentName) return res.status(400).json({ ok: false, error: 'INVALID_INPUT' });

    const r = await query(
      `
      SELECT id, collection_name, category_path, content_name, size_bytes, mime_type, uploaded_at, is_deleted, deleted_at
      FROM user_files
      WHERE owner_user_id=$1
        AND collection_name=$2
        AND category_path=$3
        AND content_name=$4
      LIMIT 1
      `,
      [payload.sub, collectionName, categoryPath, contentName],
    );

    if (!r.rowCount) return res.status(404).json({ ok: false, error: 'NOT_FOUND' });
    return res.json({ ok: true, file: r.rows[0] });
  } catch (e) {
    console.error('[record-get]', e);
    return res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
  }
});

// POST /auth/files/record-delete  { collectionName, categoryPath, contentName, userNo? }
app.post('/auth/files/record-delete', async (req, res) => {
  try {
    const payload = verifyTokenFromReq(req);
    if (!payload?.sub) return res.status(401).json({ ok: false, error: 'UNAUTHORIZED' });

    const { collectionName, categoryPath, contentName, userNo, targetUserNo } = req.body ?? {};
    if (!collectionName || !contentName) return res.status(400).json({ ok: false, error: 'INVALID_INPUT' });

    const col = String(collectionName).trim();
    const cat = String(categoryPath ?? '').trim();
    const name = String(contentName).trim();

    // ✅ [2026-03-20] userNo(또는 targetUserNo) 제공 시 해당 사용자의 owner_user_id로 삭제
    //   - ahrisure_customer_M_N: 프론트가 고객 user_no 전달
    //   - ahrisure_manager_N: userNo 미전달 → JWT sub(플래너 본인)로 처리
    const requestedNo = userNo != null ? Number(userNo) : targetUserNo != null ? Number(targetUserNo) : NaN;
    let ownerUserId = payload.sub;

    if (Number.isFinite(requestedNo) && requestedNo > 0) {
      const targetRes = await query(
        `SELECT id FROM users WHERE user_no=$1 LIMIT 1`,
        [requestedNo],
      );
      if (targetRes.rowCount) {
        ownerUserId = targetRes.rows[0].id;
      }
      // 못 찾으면 JWT sub로 fallback
    }

    const r = await query(
      `
      UPDATE user_files
      SET is_deleted=true, deleted_at=now()
      WHERE owner_user_id=$1
        AND collection_name=$2
        AND category_path=$3
        AND content_name=$4
      RETURNING id, size_bytes
      `,
      [ownerUserId, col, cat, name],
    );

    if (!r.rowCount) return res.status(404).json({ ok: false, error: 'NOT_FOUND' });
    return res.json({ ok: true, sizeBytes: Number(r.rows[0]?.size_bytes ?? 0) });
  } catch (e) {
    console.error('[record-delete]', e);
    return res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
  }
});

// ─────────────────────────────────────────────────────────
// Auth API
// ─────────────────────────────────────────────────────────

// POST /auth/signup { name, email, password, phone, plannerNo? }
app.post('/auth/signup', async (req, res) => {
  try {
    const { name, email, password, phone, plannerNo } = req.body ?? {};

    if (!name || !email || !password) return res.status(400).json({ ok: false, error: 'INVALID_INPUT' });
    if (!isEmail(email)) return res.status(400).json({ ok: false, error: 'INVALID_EMAIL' });
    if (!passwordStrong(password)) return res.status(400).json({ ok: false, error: 'WEAK_PASSWORD' });

    const phoneDigits = onlyDigits(phone || '');
    if (!isPhone10or11(phoneDigits)) return res.status(400).json({ ok: false, error: 'INVALID_PHONE' });

    let plannerRow = null;
    let plannerNoInt = null;
    if (plannerNo !== undefined && plannerNo !== null && String(plannerNo).trim() !== '') {
      const pn = onlyDigits(String(plannerNo));
      if (!pn) return res.status(400).json({ ok: false, error: 'INVALID_PLANNER_NO' });
      plannerNoInt = Number(pn);

      const rPlanner = await query(`SELECT id, role FROM users WHERE user_no = $1 LIMIT 1`, [plannerNoInt]);
      if (!rPlanner.rowCount) return res.status(400).json({ ok: false, error: 'INVALID_PLANNER_NO' });
      plannerRow = rPlanner.rows[0];
      if (plannerRow.role !== 'planner') return res.status(400).json({ ok: false, error: 'PLANNER_NO_NOT_PLANNER' });
    }

    const emailNorm = String(email).trim();
    const existed = await query('SELECT id FROM users WHERE lower(email)=lower($1) LIMIT 1', [emailNorm]);
    if (existed.rowCount) return res.status(409).json({ ok: false, error: 'EMAIL_TAKEN' });

    const hash = await bcrypt.hash(String(password), Number(process.env.BCRYPT_SALT_ROUNDS || 10));

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      let ins;
      if (plannerRow) {
        await enforcePlannerCustomerLimitTx(client, plannerNoInt);

        ins = await client.query(
          `INSERT INTO users (email, password_hash, name, role, phone, planner_no, used_bytes, file_bytes)
           VALUES ($1,$2,$3,'user',$4,$5,0,$6)
           RETURNING id, email, name, role, phone, user_no, planner_no, file_bytes, used_bytes, created_at`,
          [emailNorm, hash, String(name).trim(), phoneDigits, plannerNoInt, DEFAULT_USER_FILE_MB],
        );
      } else {
        ins = await client.query(
          `INSERT INTO users (email, password_hash, name, role, phone, used_bytes, file_bytes)
           VALUES ($1,$2,$3,'user',$4,0,$5)
           RETURNING id, email, name, role, phone, user_no, file_bytes, used_bytes, created_at`,
          [emailNorm, hash, String(name).trim(), phoneDigits, DEFAULT_USER_FILE_MB],
        );
      }

      const user = ins.rows[0];

      if (plannerRow) {
        try {
          await client.query(
            `INSERT INTO planner_assignments (user_id, planner_id, is_primary)
             VALUES ($1,$2,true)
             ON CONFLICT (user_id, planner_id) DO NOTHING`,
            [user.id, plannerRow.id],
          );
        } catch (e) {
          console.warn('[signup] planner_assignments insert failed', e?.code || e?.message || e);
        }
      }

      await client.query('COMMIT');

      const token = jwt.sign({ sub: user.id, role: user.role, user_no: user.user_no }, process.env.JWT_SECRET, {
        expiresIn: '7d',
      });

      return res.status(201).json({ ok: true, token, user });
    } catch (e) {
      await client.query('ROLLBACK').catch(() => {});
      if (e?.code === 'CUSTOMER_LIMIT_EXCEEDED') {
        return res.status(403).json({ ok: false, error: 'CUSTOMER_LIMIT_EXCEEDED', detail: e?.detail || null });
      }
      if (e?.code === 'INVALID_PLANNER_NO') return res.status(400).json({ ok: false, error: 'INVALID_PLANNER_NO' });
      throw e;
    } finally {
      client.release();
    }
  } catch (e) {
    if (e?.code === '23505') return res.status(409).json({ ok: false, error: 'EMAIL_TAKEN' });
    console.error('[signup]', e);
    return res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
  }
});

// POST /auth/login { email, password }
app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body ?? {};
    if (!email || !password) return res.status(400).json({ ok: false, error: 'INVALID_INPUT' });

    const r = await query(
      `SELECT 
         id,
         email,
         name,
         role,
         is_active,
         password_hash,
         user_no,
         planner_no,
         file_bytes,
         used_bytes,
         intro_text,
         created_at,
         updated_at
       FROM users
       WHERE lower(email)=lower($1)
       LIMIT 1`,
      [String(email).trim()],
    );

    if (!r.rowCount) return res.status(401).json({ ok: false, error: 'INVALID_CREDENTIALS' });

    const user = r.rows[0];
    const ok = user.password_hash ? await bcrypt.compare(String(password), user.password_hash) : false;
    if (!ok) return res.status(401).json({ ok: false, error: 'INVALID_CREDENTIALS' });
    if (user.is_active === false) return res.status(403).json({ ok: false, error: 'INACTIVE_USER' });

    const token = jwt.sign({ sub: user.id, role: user.role, user_no: user.user_no }, process.env.JWT_SECRET, {
      expiresIn: '7d',
    });

    delete user.password_hash;
    return res.json({ ok: true, token, user });
  } catch (e) {
    console.error('[login]', e);
    return res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
  }
});

// GET /auth/check-email?email=...
app.get('/auth/check-email', async (req, res) => {
  try {
    const email = String(req.query.email || '').trim();
    if (!email || !isEmail(email)) return res.json({ ok: true, available: false });

    const r = await query('SELECT 1 FROM users WHERE lower(email)=lower($1) LIMIT 1', [email]);
    return res.json({ ok: true, available: r.rowCount === 0 });
  } catch (e) {
    console.error('[check-email]', e);
    return res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
  }
});

// POST /auth/find-id { name, phone }
app.post('/auth/find-id', async (req, res) => {
  try {
    const nmRaw = String(req.body?.name || '').trim();
    const ph = String(req.body?.phone || '').replace(/\D/g, '');

    const nameOk = /^[가-힣a-zA-Z\s]{2,}$/.test(nmRaw);
    const phoneOk = /^[0-9]{10,11}$/.test(ph);
    if (!nameOk || !phoneOk) return res.status(400).json({ ok: false, error: 'INVALID_INPUT' });

    const q = `
      SELECT email
      FROM users
      WHERE replace(lower(name), ' ', '') = replace(lower($1), ' ', '')
        AND phone = $2
      LIMIT 1
    `;
    const r = await query(q, [nmRaw, ph]);
    if (!r.rowCount) return res.status(404).json({ ok: false, error: 'NOT_FOUND' });

    return res.json({ ok: true, email: r.rows[0].email });
  } catch (e) {
    console.error('[find-id]', e);
    return res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
  }
});

// 간단 1회용 티켓 소모(서버 재기동 시 초기화)
const usedTickets = new Set();

// POST /auth/verify-owner { email, phone }
app.post('/auth/verify-owner', async (req, res) => {
  try {
    const email = String(req.body?.email || '').trim().toLowerCase();
    const phone = onlyDigits(String(req.body?.phone || ''));
    if (!isEmail(email) || !/^[0-9]{10,11}$/.test(phone)) return res.status(400).json({ ok: false, error: 'INVALID_INPUT' });

    const q = `
      SELECT id
      FROM users
      WHERE lower(email)=lower($1) AND phone=$2
      ORDER BY created_at DESC
      LIMIT 1
    `;
    const r = await query(q, [email, phone]);
    if (!r.rowCount) return res.status(404).json({ ok: false, error: 'NOT_FOUND' });

    const userId = r.rows[0].id;
    const ticket = jwt.sign({ typ: 'pwd_reset', sub: userId, eml: email }, process.env.JWT_SECRET, { expiresIn: '10m' });
    return res.json({ ok: true, ticket });
  } catch (e) {
    console.error('[verify-owner]', e);
    return res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
  }
});

// POST /auth/reset { ticket, newPassword }
app.post('/auth/reset', async (req, res) => {
  try {
    const { ticket, newPassword } = req.body ?? {};
    if (!ticket || !newPassword) return res.status(400).json({ ok: false, error: 'INVALID_INPUT' });
    if (!passwordStrong(String(newPassword))) return res.status(400).json({ ok: false, error: 'WEAK_PASSWORD' });

    let payload;
    try {
      payload = jwt.verify(ticket, process.env.JWT_SECRET);
    } catch {
      return res.status(400).json({ ok: false, error: 'BAD_TICKET' });
    }
    if (payload?.typ !== 'pwd_reset' || !payload?.sub) return res.status(400).json({ ok: false, error: 'BAD_TICKET' });
    if (usedTickets.has(ticket)) return res.status(400).json({ ok: false, error: 'BAD_TICKET' });

    const hash = await bcrypt.hash(String(newPassword), Number(process.env.BCRYPT_SALT_ROUNDS || 10));
    await query(`UPDATE users SET password_hash=$1 WHERE id=$2`, [hash, payload.sub]);

    usedTickets.add(ticket);
    return res.json({ ok: true });
  } catch (e) {
    console.error('[reset]', e);
    return res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
  }
});

// ★★★ GET /auth/me - 토큰 기준 현재 로그인한 유저 정보 반환
app.get('/auth/me', async (req, res) => {
  console.log('[/auth/me] hit', new Date().toISOString(), 'pid=', process.pid);
  console.log('[/auth/me] host=', req.headers.host, 'origin=', req.headers.origin);
  try {
    const payload = verifyTokenFromReq(req);
    if (!payload?.sub) return res.status(401).json({ ok: false, error: 'UNAUTHORIZED' });

    const r = await query(
      `
      SELECT
        u.id,
        u.email,
        u.name,
        u.role,
        u.phone,
        u.is_active,
        u.user_no,
        u.planner_no,
        u.file_bytes,
        u.used_bytes,
        u.intro_text,
        u.created_at,
        u.updated_at,
        p.name AS planner_name
      FROM users AS u
      LEFT JOIN users AS p
        ON p.user_no = u.planner_no
       AND p.role   = 'planner'
      WHERE u.id = $1
      LIMIT 1
      `,
      [payload.sub],
    );

    if (!r.rowCount) return res.status(404).json({ ok: false, error: 'NOT_FOUND' });

    const user = r.rows[0];
    return res.json({ ok: true, user });
  } catch (e) {
    console.error('[me]', e);
    return res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
  }
});

// ★★★ PUT /auth/me
app.put('/auth/me', async (req, res) => {
  try {
    const payload = verifyTokenFromReq(req);
    if (!payload?.sub) return res.status(401).json({ ok: false, error: 'UNAUTHORIZED' });

    const { email, phone, intro_text, password } = req.body ?? {};

    const updates = [];
    const params = [];
    let idx = 1;

    if (email !== undefined) {
      if (!isEmail(email)) return res.status(400).json({ ok: false, error: 'INVALID_EMAIL' });
      updates.push(`email = $${idx++}`);
      params.push(String(email).trim());
    }

    if (phone !== undefined) {
      const phoneDigits = onlyDigits(String(phone));
      if (!isPhone10or11(phoneDigits)) return res.status(400).json({ ok: false, error: 'INVALID_PHONE' });
      updates.push(`phone = $${idx++}`);
      params.push(phoneDigits);
    }

    if (intro_text !== undefined) {
      updates.push(`intro_text = $${idx++}`);
      params.push(String(intro_text));
    }

    if (password !== undefined && String(password).trim() !== '') {
      if (!passwordStrong(password)) return res.status(400).json({ ok: false, error: 'WEAK_PASSWORD' });
      const hash = await bcrypt.hash(String(password), Number(process.env.BCRYPT_SALT_ROUNDS || 10));
      updates.push(`password_hash = $${idx++}`);
      params.push(hash);
    }

    if (updates.length === 0) return res.json({ ok: true });

    params.push(payload.sub);
    const q = `
      UPDATE users
         SET ${updates.join(', ')},
             updated_at = now()
       WHERE id = $${idx}
       RETURNING id, email, name, role, phone, user_no, planner_no
    `;

    const r = await query(q, params);
    if (!r.rowCount) return res.status(404).json({ ok: false, error: 'NOT_FOUND' });

    return res.json({ ok: true, user: r.rows[0] });
  } catch (e) {
    console.error('[me:PUT]', e);
    return res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
  }
});

// ─────────────────────────────────────────────────────────
// WebSocket (Signaling)
// ─────────────────────────────────────────────────────────
const server = http.createServer(app);
const ws = new WebSocketServer({ server, path: '/signal' });

const rooms = new Map();
const wsMeta = new WeakMap();

const MAX_ROOM_SIZE = Number(process.env.MAX_ROOM_SIZE || 2);
const HEARTBEAT_INTERVAL_MS = Number(process.env.HEARTBEAT_INTERVAL_MS || 30_000);
const CLIENT_TIMEOUT_MS = Number(process.env.CLIENT_TIMEOUT_MS || 90_000);

function safeSend(sock, obj) {
  try {
    sock.send(JSON.stringify(obj));
  } catch {}
}

function notifyPeers(roomId, payload, except = null) {
  const set = rooms.get(roomId);
  if (!set) return;
  for (const peer of set) {
    if (peer !== except && peer.readyState === 1) safeSend(peer, payload);
  }
}

function join(sock, roomId) {
  if (!roomId) return safeSend(sock, { type: 'error', error: 'roomId_required' });

  if (!rooms.has(roomId)) rooms.set(roomId, new Set());
  const set = rooms.get(roomId);
  if (set.size >= MAX_ROOM_SIZE) return safeSend(sock, { type: 'room-full', roomId });

  set.add(sock);
  sock._rooms ??= new Set();
  sock._rooms.add(roomId);

  safeSend(sock, { type: 'joined', roomId, peers: set.size });
  notifyPeers(roomId, { type: 'peer-join', roomId, peers: set.size }, sock);

  console.log(`[WS] joined room=${roomId} peers=${set.size}`);
}

function leaveAll(sock) {
  for (const roomId of sock._rooms || []) {
    const set = rooms.get(roomId);
    if (!set) continue;
    set.delete(sock);
    if (set.size === 0) {
      rooms.delete(roomId);
      console.log(`room empty -> deleted room=${roomId}`);
    } else {
      notifyPeers(roomId, { type: 'peer-left', roomId, peers: set.size });
      console.log(`[WS] left room=${roomId} peers=${set.size}`);
    }
  }
}

function relay(sock, roomId, payload) {
  const set = rooms.get(roomId);
  if (!set) return;
  for (const peer of set) {
    if (peer !== sock && peer.readyState === 1) safeSend(peer, payload);
  }
}

function isSignalWithRoom(msg) {
  return msg && typeof msg === 'object' && typeof msg.roomId === 'string';
}

const heartbeatTimer = setInterval(() => {
  ws.clients.forEach((sock) => {
    const meta = wsMeta.get(sock);
    if (!meta) return;
    const now = Date.now();

    if (sock.readyState === 1) {
      try {
        sock.ping();
      } catch {}
    }

    if (now - meta.lastPongAt > CLIENT_TIMEOUT_MS) {
      console.warn('[WS] terminate stale client');
      try {
        sock.terminate();
      } catch {}
    }
  });
}, HEARTBEAT_INTERVAL_MS);

ws.on('connection', (sock, req) => {
  wsMeta.set(sock, { rooms: new Set(), lastPongAt: Date.now() });

  const ip = req.headers['x-forwarded-for']?.toString().split(',')[0].trim() || req.socket.remoteAddress;
  console.log('[WS] connection from', ip);

  sock.on('pong', () => {
    const meta = wsMeta.get(sock);
    if (meta) meta.lastPongAt = Date.now();
  });

  sock.on('message', (raw) => {
    let msg;
    try {
      msg = JSON.parse(raw.toString());
    } catch {
      console.warn('[WS] non-JSON message ignored');
      return;
    }

    if (msg?.type === 'ping') {
      safeSend(sock, { type: 'pong', t: Date.now() });
      return;
    }

    if (msg?.type === 'join') return join(sock, msg.roomId);

    if (['offer', 'answer', 'ice'].includes(msg?.type)) {
      if (!isSignalWithRoom(msg)) return safeSend(sock, { type: 'error', error: 'roomId_required' });
      relay(sock, msg.roomId, msg);
      return;
    }

    safeSend(sock, { type: 'error', error: 'unknown_type', raw: msg?.type });
  });

  sock.on('close', () => leaveAll(sock));
  sock.on('error', (err) => console.warn('[WS] error', err?.message || err));
});

// 디버그: 현재 방/피어 상태 조회
app.get('/auth/rooms', (_req, res) => {
  const out = [];
  for (const [roomId, set] of rooms.entries()) out.push({ roomId, peers: set.size });
  res.json({ ok: true, rooms: out });
});

// 서버 종료 시 타이머 정리
process.on('SIGINT', () => {
  clearInterval(heartbeatTimer);
  process.exit(0);
});
process.on('SIGTERM', () => {
  clearInterval(heartbeatTimer);
  process.exit(0);
});

// ★★★ [추가] 설계사 회원가입: POST /auth/signup-planner
app.post('/auth/signup-planner', async (req, res) => {
  try {
    const { name, email, password, phone } = req.body ?? {};

    if (!name || !email || !password) return res.status(400).json({ ok: false, error: 'INVALID_INPUT' });
    if (!isEmail(email)) return res.status(400).json({ ok: false, error: 'INVALID_EMAIL' });
    if (!passwordStrong(password)) return res.status(400).json({ ok: false, error: 'WEAK_PASSWORD' });

    const phoneDigits = onlyDigits(phone || '');
    if (!isPhone10or11(phoneDigits)) return res.status(400).json({ ok: false, error: 'INVALID_PHONE' });

    const existed = await query('SELECT id FROM users WHERE lower(email)=lower($1) LIMIT 1', [String(email).trim()]);
    if (existed.rowCount) return res.status(409).json({ ok: false, error: 'EMAIL_TAKEN' });

    const hash = await bcrypt.hash(String(password), Number(process.env.BCRYPT_SALT_ROUNDS || 10));
    const ins = await query(
      `INSERT INTO users (email, password_hash, name, role, phone)
       VALUES ($1,$2,$3,'planner',$4)
       RETURNING id, email, name, role, phone, user_no, created_at`,
      [String(email).trim(), hash, String(name).trim(), phoneDigits],
    );
    const user = ins.rows[0];

    const token = jwt.sign({ sub: user.id, role: user.role, user_no: user.user_no }, process.env.JWT_SECRET, {
      expiresIn: '7d',
    });

    return res.status(201).json({ ok: true, token, user });
  } catch (e) {
    if (e?.code === '23505') return res.status(409).json({ ok: false, error: 'EMAIL_TAKEN' });
    console.error('[signup-planner]', e);
    return res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
  }
});

// ─────────────────────────────────────────────────────────
// 내 고객 목록 / quota 변경 / by-user-no / customers CRUD / usedbytes/add
// (아래는 사용자가 준 코드 그대로 유지)
// ─────────────────────────────────────────────────────────

// ★★★ GET /customers/mine
app.get('/customers/mine', async (req, res) => {
  try {
    const payload = verifyTokenFromReq(req);
    if (!payload?.sub) return res.status(401).json({ ok: false, error: 'UNAUTHORIZED' });

    const meRes = await query(`SELECT id, role, user_no FROM users WHERE id = $1 LIMIT 1`, [payload.sub]);
    if (!meRes.rowCount) return res.status(404).json({ ok: false, error: 'NOT_FOUND' });

    const me = meRes.rows[0];

    if (me.role === 'planner') {
      const q = `
        SELECT 
          id,
          user_no,
          name,
          email,
          phone,
          created_at,
          file_bytes,
          used_bytes,
          is_active
        FROM users
        WHERE role = 'user'
          AND planner_no = $1
        ORDER BY created_at DESC
      `;
      const r = await query(q, [me.user_no]);
      const customers = r.rows.map((u) => ({
        id: u.id,
        name: u.name,
        email: u.email,
        phone: u.phone,
        user_no: u.user_no,
        created_at: u.created_at,
        file_bytes: u.file_bytes,
        used_bytes: u.used_bytes,
        is_active: u.is_active,
      }));
      return res.json({ ok: true, customers });
    }

    if (me.role === 'admin' || me.role === 'manager') {
      const plannerUserNo = req.query.plannerUserNo ? Number(req.query.plannerUserNo) : null;

      if (plannerUserNo) {
        const q = `
          SELECT 
            id,
            user_no,
            name,
            email,
            phone,
            created_at,
            file_bytes,
            used_bytes,
            is_active
          FROM users
          WHERE role = 'user'
            AND planner_no = $1
          ORDER BY created_at DESC
        `;
        const r = await query(q, [plannerUserNo]);
        const customers = r.rows.map((u) => ({
          id: u.id,
          name: u.name,
          email: u.email,
          phone: u.phone,
          user_no: u.user_no,
          created_at: u.created_at,
          file_bytes: u.file_bytes,
          used_bytes: u.used_bytes,
          is_active: u.is_active,
        }));
        return res.json({ ok: true, customers });
      } else {
        const q = `
          SELECT 
            id,
            user_no,
            name,
            email,
            phone,
            created_at,
            file_bytes,
            used_bytes,
            is_active
          FROM users
          WHERE role = 'user'
          ORDER BY created_at DESC
        `;
        const r = await query(q);
        const customers = r.rows.map((u) => ({
          id: u.id,
          name: u.name,
          email: u.email,
          phone: u.phone,
          user_no: u.user_no,
          created_at: u.created_at,
          file_bytes: u.file_bytes,
          used_bytes: u.used_bytes,
          is_active: u.is_active,
        }));
        return res.json({ ok: true, customers });
      }
    }

    return res.status(403).json({ ok: false, error: 'FORBIDDEN' });
  } catch (e) {
    console.error('[customers/mine]', e);
    return res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
  }
});

// ★★★ 설계사가 담당 고객의 저장 용량(MB)을 변경
app.put('/customers/filequota', async (req, res) => {
  try {
    const payload = verifyTokenFromReq(req);
    if (!payload?.sub) return res.status(401).json({ ok: false, error: 'UNAUTHORIZED' });

    const { customerUserNo, fileBytes } = req.body ?? {};
    const userNo = Number(customerUserNo);
    const fileBytesNum = Number(fileBytes);

    if (!Number.isFinite(userNo) || !Number.isFinite(fileBytesNum)) {
      return res.status(400).json({ ok: false, error: 'INVALID_INPUT' });
    }
    if (![10, 30, 50].includes(fileBytesNum)) {
      return res.status(400).json({ ok: false, error: 'INVALID_QUOTA' });
    }

    const meRes = await query(`SELECT id, role, user_no FROM users WHERE id = $1 LIMIT 1`, [payload.sub]);
    if (!meRes.rowCount) return res.status(404).json({ ok: false, error: 'ME_NOT_FOUND' });
    const me = meRes.rows[0];

    if (me.role !== 'planner' && me.role !== 'admin' && me.role !== 'manager') {
      return res.status(403).json({ ok: false, error: 'FORBIDDEN_ROLE' });
    }

    let r;
    if (me.role === 'planner') {
      r = await query(
        `
        UPDATE users
        SET file_bytes = $2
        WHERE user_no = $1
          AND role = 'user'
          AND planner_no = $3
        RETURNING id, user_no, file_bytes, used_bytes
        `,
        [userNo, fileBytesNum, me.user_no],
      );
    } else {
      r = await query(
        `
        UPDATE users
        SET file_bytes = $2
        WHERE user_no = $1
          AND role = 'user'
        RETURNING id, user_no, file_bytes, used_bytes
        `,
        [userNo, fileBytesNum],
      );
    }

    if (!r.rowCount) {
      return res.status(404).json({ ok: false, error: 'USER_NOT_FOUND_OR_NO_PERMISSION' });
    }

    const updated = r.rows[0];
    return res.json({
      ok: true,
      customer: { id: updated.id, user_no: updated.user_no, file_bytes: updated.file_bytes, used_bytes: updated.used_bytes },
    });
  } catch (e) {
    console.error('[customers/filequota]', e);
    return res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
  }
});

// ★★★ GET /auth/by-user-no (full columns)
app.get('/auth/by-user-no', async (req, res) => {
  try {
    const userNoRaw = req.query.userNo;
    const plannerNoRaw = req.query.plannerNo;

    const userNo = userNoRaw ? onlyDigits(String(userNoRaw)) : '';
    const plannerNo = plannerNoRaw ? onlyDigits(String(plannerNoRaw)) : '';

    if (!userNo && !plannerNo) {
      return res.status(400).json({ ok: false, error: 'userNo or plannerNo required' });
    }

    let plannerNoFinal = plannerNo || null;

    if (!plannerNoFinal && userNo) {
      const rUser = await query(
        `
        SELECT planner_no
        FROM users
        WHERE user_no = $1
          AND role = 'user'
        LIMIT 1
        `,
        [Number(userNo)],
      );

      if (!rUser.rowCount || !rUser.rows[0].planner_no) {
        return res.status(404).json({ ok: false, error: 'PLANNER_NOT_ASSIGNED' });
      }

      plannerNoFinal = String(rUser.rows[0].planner_no);
    }

    if (!plannerNoFinal) return res.status(404).json({ ok: false, error: 'PLANNER_NOT_FOUND' });

    const rPlanner = await query(
      `
      SELECT
        id,
        email,
        password_hash,
        name,
        phone,
        role,
        is_active,
        user_no,
        planner_no,
        file_bytes,
        used_bytes,
        intro_text,
        created_at,
        updated_at
      FROM users
      WHERE user_no = $1
        AND role = 'planner'
      LIMIT 1
      `,
      [Number(plannerNoFinal)],
    );

    if (!rPlanner.rowCount) return res.status(404).json({ ok: false, error: 'PLANNER_NOT_FOUND' });

    const p = rPlanner.rows[0];
    delete p.password_hash;
    return res.json({ ok: true, planner: p });
  } catch (e) {
    console.error('[/auth/by-user-no]', e);
    return res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
  }
});

// 권한 유틸: admin/manager/planner 허용 + planner는 내 고객만 처리하도록 me 정보 리턴
async function requireStaff(req, res) {
  const payload = verifyTokenFromReq(req);
  if (!payload?.sub) {
    res.status(401).json({ ok: false, error: 'UNAUTHORIZED' });
    return null;
  }

  const meRes = await query(`SELECT id, role, user_no FROM users WHERE id=$1 LIMIT 1`, [payload.sub]);
  if (!meRes.rowCount) {
    res.status(404).json({ ok: false, error: 'ME_NOT_FOUND' });
    return null;
  }

  const me = meRes.rows[0];
  if (me.role !== 'admin' && me.role !== 'manager' && me.role !== 'planner') {
    res.status(403).json({ ok: false, error: 'FORBIDDEN' });
    return null;
  }
  return me;
}

// (A) 고객 계정 추가
app.post('/customers', async (req, res) => {
  try {
    const me = await requireStaff(req, res);
    if (!me) return;

    const { name, email, phone, plannerNo, password } = req.body ?? {};

    if (!name || !email || !phone) return res.status(400).json({ ok: false, error: 'INVALID_INPUT' });
    if (!isEmail(email)) return res.status(400).json({ ok: false, error: 'INVALID_EMAIL' });

    const phoneDigits = onlyDigits(phone || '');
    if (!isPhone10or11(phoneDigits)) return res.status(400).json({ ok: false, error: 'INVALID_PHONE' });

    if (!password || !passwordStrong(password)) return res.status(400).json({ ok: false, error: 'WEAK_PASSWORD' });

    const existed = await query('SELECT id FROM users WHERE lower(email)=lower($1) LIMIT 1', [String(email).trim()]);
    if (existed.rowCount) return res.status(409).json({ ok: false, error: 'EMAIL_TAKEN' });

    let plannerNoInt = null;
    if (me.role === 'planner') {
      plannerNoInt = me.user_no;
    } else if (plannerNo !== undefined && plannerNo !== null && String(plannerNo).trim() !== '') {
      const pn = Number(onlyDigits(String(plannerNo)));
      if (!Number.isFinite(pn) || pn <= 0) return res.status(400).json({ ok: false, error: 'INVALID_PLANNER_NO' });
      plannerNoInt = pn;
    }

    const hash = await bcrypt.hash(String(password), Number(process.env.BCRYPT_SALT_ROUNDS || 10));

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      if (plannerNoInt != null) await enforcePlannerCustomerLimitTx(client, plannerNoInt);

      const ins = await client.query(
        `INSERT INTO users (email, password_hash, name, role, phone, planner_no, is_active, used_bytes, file_bytes)
         VALUES ($1,$2,$3,'user',$4,$5,false,0,$6)
         RETURNING id, user_no, name, email, phone, planner_no, is_active, created_at, file_bytes, used_bytes`,
        [String(email).trim(), hash, String(name).trim(), phoneDigits, plannerNoInt, DEFAULT_USER_FILE_MB],
      );

      await client.query('COMMIT');
      return res.status(201).json({ ok: true, customer: ins.rows[0] });
    } catch (e) {
      await client.query('ROLLBACK').catch(() => {});
      if (e?.code === 'CUSTOMER_LIMIT_EXCEEDED') {
        return res.status(403).json({ ok: false, error: 'CUSTOMER_LIMIT_EXCEEDED', detail: e?.detail || null });
      }
      if (e?.code === 'INVALID_PLANNER_NO') return res.status(400).json({ ok: false, error: 'INVALID_PLANNER_NO' });
      throw e;
    } finally {
      client.release();
    }
  } catch (e) {
    console.error('[customers:POST]', e);
    return res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
  }
});

// (B) 고객 수정
app.put('/customers/:userNo', async (req, res) => {
  try {
    const me = await requireStaff(req, res);
    if (!me) return;

    const userNo = Number(req.params.userNo);
    if (!Number.isFinite(userNo)) return res.status(400).json({ ok: false, error: 'INVALID_USER_NO' });

    const { name, email, phone, plannerNo, is_active, password } = req.body ?? {};

    const updates = [];
    const params = [];
    let idx = 1;

    if (name !== undefined) {
      updates.push(`name=$${idx++}`);
      params.push(String(name).trim());
    }

    if (email !== undefined) {
      if (!isEmail(email)) return res.status(400).json({ ok: false, error: 'INVALID_EMAIL' });
      updates.push(`email=$${idx++}`);
      params.push(String(email).trim());
    }

    if (phone !== undefined) {
      const phoneDigits = onlyDigits(String(phone));
      if (!isPhone10or11(phoneDigits)) return res.status(400).json({ ok: false, error: 'INVALID_PHONE' });
      updates.push(`phone=$${idx++}`);
      params.push(phoneDigits);
    }

    if (password !== undefined && String(password).trim() !== '') {
      if (!passwordStrong(password)) return res.status(400).json({ ok: false, error: 'WEAK_PASSWORD' });
      const hash = await bcrypt.hash(String(password), Number(process.env.BCRYPT_SALT_ROUNDS || 10));
      updates.push(`password_hash=$${idx++}`);
      params.push(hash);
    }

    if (plannerNo !== undefined && me.role !== 'planner') {
      const pnRaw = String(plannerNo).trim();
      const pn = pnRaw === '' ? null : Number(onlyDigits(pnRaw));
      if (pnRaw !== '' && (!Number.isFinite(pn) || pn <= 0)) {
        return res.status(400).json({ ok: false, error: 'INVALID_PLANNER_NO' });
      }
      updates.push(`planner_no=$${idx++}`);
      params.push(pnRaw === '' ? null : pn);
    }

    if (is_active !== undefined) {
      updates.push(`is_active=$${idx++}`);
      params.push(Boolean(is_active));
    }

    if (updates.length === 0) return res.json({ ok: true });

    let where = `role='user' AND user_no=$${idx}`;
    params.push(userNo);
    idx += 1;

    if (me.role === 'planner') {
      where += ` AND planner_no=$${idx}`;
      params.push(me.user_no);
      idx += 1;
    }

    const r = await query(
      `UPDATE users
          SET ${updates.join(', ')}, updated_at=now()
        WHERE ${where}
        RETURNING id, user_no, name, email, phone, planner_no, is_active, created_at`,
      params,
    );

    if (!r.rowCount) return res.status(404).json({ ok: false, error: 'USER_NOT_FOUND_OR_NO_PERMISSION' });
    return res.json({ ok: true, customer: r.rows[0] });
  } catch (e) {
    console.error('[customers:PUT]', e);
    return res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
  }
});

// (C) 고객 삭제(soft delete)
app.delete('/customers/:userNo', async (req, res) => {
  try {
    const me = await requireStaff(req, res);
    if (!me) return;

    const userNo = Number(req.params.userNo);
    if (!Number.isFinite(userNo)) return res.status(400).json({ ok: false, error: 'INVALID_USER_NO' });

    const params = [userNo];
    let q = `
      UPDATE users
         SET is_active=false, updated_at=now()
       WHERE role='user' AND user_no=$1
    `;
    if (me.role === 'planner') {
      q += ` AND planner_no=$2`;
      params.push(me.user_no);
    }
    q += ` RETURNING user_no`;

    const r = await query(q, params);
    if (!r.rowCount) return res.status(404).json({ ok: false, error: 'USER_NOT_FOUND_OR_NO_PERMISSION' });

    return res.json({ ok: true, user_no: r.rows[0].user_no });
  } catch (e) {
    console.error('[customers:DELETE]', e);
    return res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
  }
});

// (D) 가입 승인
app.put('/customers/:userNo/approve', async (req, res) => {
  try {
    const me = await requireStaff(req, res);
    if (!me) return;

    const userNo = Number(req.params.userNo);
    if (!Number.isFinite(userNo)) return res.status(400).json({ ok: false, error: 'INVALID_USER_NO' });

    const params = [userNo];
    let q = `
      UPDATE users
         SET is_active=true, updated_at=now()
       WHERE role='user' AND user_no=$1
    `;
    if (me.role === 'planner') {
      q += ` AND planner_no=$2`;
      params.push(me.user_no);
    }
    q += ` RETURNING id, user_no, is_active`;

    const r = await query(q, params);
    if (!r.rowCount) return res.status(404).json({ ok: false, error: 'USER_NOT_FOUND_OR_NO_PERMISSION' });

    return res.json({ ok: true, customer: r.rows[0] });
  } catch (e) {
    console.error('[customers:APPROVE]', e);
    return res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
  }
});

// (E) 활성/비활성 토글
app.put('/customers/:userNo/active', async (req, res) => {
  try {
    const me = await requireStaff(req, res);
    if (!me) return;

    const userNo = Number(req.params.userNo);
    if (!Number.isFinite(userNo)) return res.status(400).json({ ok: false, error: 'INVALID_USER_NO' });

    const nextActive = !!req.body?.is_active;

    const params = [userNo, nextActive];
    let q = `
      UPDATE users
         SET is_active=$2, updated_at=now()
       WHERE role='user' AND user_no=$1
    `;
    if (me.role === 'planner') {
      q += ` AND planner_no=$3`;
      params.push(me.user_no);
    }
    q += ` RETURNING id, user_no, is_active`;

    const r = await query(q, params);
    if (!r.rowCount) return res.status(404).json({ ok: false, error: 'USER_NOT_FOUND_OR_NO_PERMISSION' });

    return res.json({ ok: true, customer: r.rows[0] });
  } catch (e) {
    console.error('[customers:ACTIVE]', e);
    return res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
  }
});

// customer 정보 가져오기
app.get('/customers/me', async (req, res) => {
  try {
    const payload = verifyTokenFromReq(req);
    if (!payload?.sub) return res.status(401).json({ ok: false, error: 'UNAUTHORIZED' });

    const r = await query(
      `
      SELECT
        id,
        user_no,
        planner_no,
        name,
        email,
        phone,
        role,
        created_at,
        file_bytes,
        used_bytes
      FROM users
      WHERE id = $1
      LIMIT 1
      `,
      [payload.sub],
    );

    if (!r.rowCount) return res.status(404).json({ ok: false, error: 'NOT_FOUND' });

    const me = r.rows[0];
    if (me.role !== 'user') return res.status(403).json({ ok: false, error: 'FORBIDDEN' });

    return res.json({ ok: true, customer: me });
  } catch (e) {
    console.error('[customers/me]', e);
    return res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
  }
});

// ✅ usedbytes/add (기존 유지)
async function handleUsedBytesAdd(req, res) {
  try {
    const payload = verifyTokenFromReq(req);
    if (!payload?.sub) return res.status(401).json({ ok: false, error: 'UNAUTHORIZED' });

    const { addMb } = req.body ?? {};
    const addMbNum = Number(addMb);
    if (!Number.isFinite(addMbNum) || addMbNum <= 0) return res.status(400).json({ ok: false, error: 'INVALID_INPUT' });

    const meRes = await query(`SELECT id, role, user_no FROM users WHERE id = $1 LIMIT 1`, [payload.sub]);
    if (!meRes.rowCount) return res.status(404).json({ ok: false, error: 'ME_NOT_FOUND' });
    const me = meRes.rows[0];

    if (me.role !== 'planner' && me.role !== 'admin' && me.role !== 'manager') {
      return res.status(403).json({ ok: false, error: 'FORBIDDEN_ROLE' });
    }

    const r = await query(
      `
      UPDATE users
      SET used_bytes = COALESCE(used_bytes, 0) + $2
      WHERE id = $1
      RETURNING id, user_no, file_bytes, used_bytes
      `,
      [me.id, addMbNum],
    );

    if (!r.rowCount) return res.status(404).json({ ok: false, error: 'ME_NOT_FOUND' });

    const updated = r.rows[0];
    return res.json({
      ok: true,
      customer: { id: updated.id, user_no: updated.user_no, file_bytes: updated.file_bytes, used_bytes: updated.used_bytes },
    });
  } catch (e) {
    console.error('[usedbytes/add]', e);
    return res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
  }
}
app.post('/customers/usedbytes/add', handleUsedBytesAdd);
app.post('/auth/usedbytes/add', handleUsedBytesAdd);

// ✅ [2026-02-25] FIX: server.listen은 "모든 라우트 등록 후" 파일 맨 아래에서 실행
server.listen(PORT, () => {
  console.log(`HTTP+WS signaling up: http://0.0.0.0:${PORT}`);
});