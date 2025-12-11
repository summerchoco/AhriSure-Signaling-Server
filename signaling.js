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

dotenv.config({path: '../.env'});

const PORT = Number(process.env.SIGNAL_PORT || process.env.PORT || 8082);

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

// 인메모리 큐
const messages = new Map();
app.post('/messages', (req, res) => {
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
app.get('/messages', (req, res) => {
  const { roomId, for: forWho } = req.query;
  if (!roomId || !forWho) return res.status(400).json({ ok: false, error: 'roomId & for required' });
  if (!messages.has(roomId)) return res.json({ ok: true, messages: [] });
  const box = messages.get(roomId);
  const list = forWho === 'user' ? box.toUser : box.toManager;
  const out = list.splice(0, list.length);
  return res.json({ ok: true, messages: out });
});
app.get('/debug/messages', (req, res) => {
  const { roomId } = req.query;
  const box = messages.get(roomId) || { toUser: [], toManager: [] };
  res.json({ ok: true, debug: { roomId, toUser: box.toUser, toManager: box.toManager } });
});

// sizeBytes: 실제 파일 크기(바이트 단위)
// userId: 이 용량을 차지할 "사용자"의 users.id
// 파일 업로드 전 용량 체크 + used_bytes 증가
app.post('/files/upload', async (req, res) => {
  try {
    const payload = verifyTokenFromReq(req);
    if (!payload?.sub) {
      return res.status(401).json({ ok: false, error: 'UNAUTHORIZED' });
    }

    const { sizeBytes } = req.body ?? {};
    if (!sizeBytes) {
      return res.status(400).json({ ok: false, error: 'INVALID_INPUT' });
    }

    // 1) 바이트 → GB (실수)
    let deltaGB = sizeBytes / (1024 ** 3);  // 예: 4KB → 0.0000037...

    // 2) 0.001GB 미만은 0.001로 클램프
    if (deltaGB < 0.001) {
      deltaGB = 0.001;
    }

    // 3) 소수점 3자리까지로 잘라서 넘기기 (DB는 numeric(12,3))
    const delta = Number(deltaGB.toFixed(3)); // 0.001, 1.234, 9.876 등

    const r = await query(
      `
      UPDATE users
      SET used_bytes = used_bytes + $2
      WHERE id = $1
        AND used_bytes + $2 <= file_bytes
      RETURNING id, used_bytes, file_bytes
      `,
      [payload.sub, delta]
    );

    if (!r.rowCount) {
      return res.status(400).json({ ok: false, error: 'QUOTA_EXCEEDED' });
    }

    return res.json({ ok: true });
  } catch (e) {
    console.error('[files/upload]', e);
    return res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
  }
});

// ─────────────────────────────────────────────────────────
// Auth API
// ─────────────────────────────────────────────────────────

// POST /auth/signup { name, email, password, phone, plannerNo? }
app.post('/auth/signup', async (req, res) => {
  try {
    const { name, email, password, phone, plannerNo } = req.body ?? {}; // ★★★ 추가: plannerNo 수신

    if (!name || !email || !password) {
      return res.status(400).json({ ok: false, error: 'INVALID_INPUT' });
    }
    if (!isEmail(email)) {
      return res.status(400).json({ ok: false, error: 'INVALID_EMAIL' });
    }
    if (!passwordStrong(password)) {
      return res.status(400).json({ ok: false, error: 'WEAK_PASSWORD' });
    }

    // 전화번호 숫자만 + 10~11자리
    const phoneDigits = onlyDigits(phone || '');
    if (!isPhone10or11(phoneDigits)) {
      return res.status(400).json({ ok: false, error: 'INVALID_PHONE' });
    }

    // ★★★ 추가: plannerNo 유효성(선택 입력)
    let plannerRow = null; // { id, role } | null
    let plannerNoInt = null;
    if (plannerNo !== undefined && plannerNo !== null && String(plannerNo).trim() !== '') {
      const pn = onlyDigits(String(plannerNo));
      if (!pn) {
        return res.status(400).json({ ok: false, error: 'INVALID_PLANNER_NO' });
      }
      plannerNoInt = Number(pn);

      // user_no로 설계사 존재/역할 확인
      const rPlanner = await query(
        `SELECT id, role FROM users WHERE user_no = $1 LIMIT 1`,
        [plannerNoInt]
      );
      if (!rPlanner.rowCount) {
        return res.status(400).json({ ok: false, error: 'INVALID_PLANNER_NO' });
      }
      plannerRow = rPlanner.rows[0];
      if (plannerRow.role !== 'planner') {
        return res.status(400).json({ ok: false, error: 'PLANNER_NO_NOT_PLANNER' });
      }
    }

    const emailNorm = String(email).trim();

    // 이메일 중복
    const existed = await query(
      'SELECT id FROM users WHERE lower(email)=lower($1) LIMIT 1',
      [emailNorm]
    );
    if (existed.rowCount) {
      return res.status(409).json({ ok: false, error: 'EMAIL_TAKEN' });
    }

    // 저장 (phone 포함) + ★★★ 추가: planner_no 선택적 반영
    const hash = await bcrypt.hash(String(password), Number(process.env.BCRYPT_SALT_ROUNDS || 10));
    let ins;
    if (plannerRow) {
      // ★★★ 변경: planner_no 포함 INSERT + user_no도 RETURNING
      ins = await query(
        `INSERT INTO users (email, password_hash, name, role, phone, planner_no)
         VALUES ($1,$2,$3,'user',$4,$5)
         RETURNING id, email, name, role, phone, user_no, planner_no, created_at`,
        [emailNorm, hash, String(name).trim(), phoneDigits, plannerNoInt]
      );
    } else {
      // 기존 경로 유지 + ★★★ user_no도 RETURNING
      ins = await query(
        `INSERT INTO users (email, password_hash, name, role, phone)
         VALUES ($1,$2,$3,'user',$4)
         RETURNING id, email, name, role, phone, user_no, created_at`,
        [emailNorm, hash, String(name).trim(), phoneDigits]
      );
    }
    const user = ins.rows[0];

    // ★★★ 추가: 설계사 번호가 유효했다면 기본 배정 레코드 생성 (중복시 무시)
    if (plannerRow) {
      try {
        await query(
          `INSERT INTO planner_assignments (user_id, planner_id, is_primary)
           VALUES ($1,$2,true)
           ON CONFLICT (user_id, planner_id) DO NOTHING`,
          [user.id, plannerRow.id]
        );
      } catch (e) {
        // 배정 실패는 가입 자체를 막지 않음(로그만 남김)
        console.warn('[signup] planner_assignments insert failed', e?.code || e?.message || e);
      }
    }

    // ★★★ 토큰 sub: 이제 user_no 를 확실히 사용할 수 있음
    const token = jwt.sign(
      { sub: user.user_no, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.status(201).json({ ok: true, token, user });
  } catch (e) {
    if (e?.code === '23505') return res.status(409).json({ ok: false, error: 'EMAIL_TAKEN' });
    console.error('[signup]', e);
    res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
  }
});

// POST /auth/login { email, password }
app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body ?? {};
    if (!email || !password) {
      return res.status(400).json({ ok: false, error: 'INVALID_INPUT' });
    }

    const r = await query(
      `SELECT 
         id,
         email,
         name,
         role,
         is_active,
         password_hash,
         user_no,      
         planner_no    
       FROM users
       WHERE lower(email)=lower($1)
       LIMIT 1`,
      [String(email).trim()]
    );

    if (!r.rowCount) {
      return res.status(401).json({ ok: false, error: 'INVALID_CREDENTIALS' });
    }

    const user = r.rows[0];

    const ok = user.password_hash
      ? await bcrypt.compare(String(password), user.password_hash)
      : false;
    if (!ok) {
      return res.status(401).json({ ok: false, error: 'INVALID_CREDENTIALS' });
    }
    if (user.is_active === false) {
      return res.status(403).json({ ok: false, error: 'INACTIVE_USER' });
    }

    const token = jwt.sign(
      { sub: user.id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    delete user.password_hash;

    // ★★★ 여기서 user 객체에는 user_no, planner_no 가 그대로 포함됨
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
    if (!email || !isEmail(email)) {
      // invalid 형식도 ok:true로 응답하되 사용불가 처리
      return res.json({ ok: true, available: false });
    }
    const r = await query('SELECT 1 FROM users WHERE lower(email)=lower($1) LIMIT 1', [email]);
    const available = r.rowCount === 0;
    res.json({ ok: true, available });
  } catch (e) {
    console.error('[check-email]', e);
    res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
  }
});

// POST /auth/find-id { name, phone }
app.post('/auth/find-id', async (req, res) => {
  try {
    const nmRaw = String(req.body?.name || '').trim();
    const ph = String(req.body?.phone || '').replace(/\D/g, '');

    const nameOk = /^[가-힣a-zA-Z\s]{2,}$/.test(nmRaw);
    const phoneOk = /^[0-9]{10,11}$/.test(ph);
    if (!nameOk || !phoneOk) {
      return res.status(400).json({ ok: false, error: 'INVALID_INPUT' });
    }

    const q = `
      SELECT email
      FROM users
      WHERE replace(lower(name), ' ', '') = replace(lower($1), ' ', '')
        AND phone = $2
      LIMIT 1
    `;
    const r = await query(q, [nmRaw, ph]);

    if (!r.rowCount) return res.status(404).json({ ok: false, error: 'NOT_FOUND' });

    // ✅ 마스킹 없이 전체 이메일 반환
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
    if (!isEmail(email) || !/^[0-9]{10,11}$/.test(phone)) {
      return res.status(400).json({ ok: false, error: 'INVALID_INPUT' });
    }

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

    const ticket = jwt.sign(
      { typ: 'pwd_reset', sub: userId, eml: email },
      process.env.JWT_SECRET,
      { expiresIn: '10m' }
    );

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
    if (!ticket || !newPassword) {
      return res.status(400).json({ ok: false, error: 'INVALID_INPUT' });
    }
    if (!passwordStrong(String(newPassword))) {
      return res.status(400).json({ ok: false, error: 'WEAK_PASSWORD' });
    }

    let payload;
    try {
      payload = jwt.verify(ticket, process.env.JWT_SECRET);
    } catch {
      return res.status(400).json({ ok: false, error: 'BAD_TICKET' });
    }
    if (payload?.typ !== 'pwd_reset' || !payload?.sub) {
      return res.status(400).json({ ok: false, error: 'BAD_TICKET' });
    }

    if (usedTickets.has(ticket)) {
      return res.status(400).json({ ok: false, error: 'BAD_TICKET' });
    }

    const hash = await bcrypt.hash(String(newPassword), Number(process.env.BCRYPT_SALT_ROUNDS || 10));
    await query(`UPDATE users SET password_hash=$1 WHERE id=$2`, [hash, payload.sub]);

    usedTickets.add(ticket);
    return res.json({ ok: true });
  } catch (e) {
    console.error('[reset]', e);
    return res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
  }
});

// ★★★ GET /me - 토큰 기준 현재 로그인한 유저 정보 반환
app.get('/me', async (req, res) => {
  try {
    const payload = verifyTokenFromReq(req);
    if (!payload?.sub) {
      return res.status(401).json({ ok: false, error: 'UNAUTHORIZED' });
    }

    const r = await query(
      `
      SELECT
        u.id,
        u.email,
        u.name,
        u.role,
        u.phone,
        u.user_no,
        u.planner_no,
        u.created_at,
        p.name AS planner_name
      FROM users AS u
      LEFT JOIN users AS p
        ON p.user_no = u.planner_no
       AND p.role   = 'planner'
      WHERE u.id = $1
      LIMIT 1
      `,
      [payload.sub]
    );

    if (!r.rowCount) {
      return res.status(404).json({ ok: false, error: 'NOT_FOUND' });
    }

    const user = r.rows[0];
    return res.json({ ok: true, user });
  } catch (e) {
    console.error('[me]', e);
    return res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
  }
});

// ★★★ PUT /me - 현재 로그인한 유저 정보 수정(이메일/전화/비밀번호/소개문구)
app.put('/me', async (req, res) => {
  try {
    const payload = verifyTokenFromReq(req);
    if (!payload?.sub) {
      return res.status(401).json({ ok: false, error: 'UNAUTHORIZED' });
    }

    const { email, phone, intro_text, password } = req.body ?? {};

    const updates = [];
    const params = [];
    let idx = 1;

    // 이메일 변경
    if (email !== undefined) {
      if (!isEmail(email)) {
        return res.status(400).json({ ok: false, error: 'INVALID_EMAIL' });
      }
      updates.push(`email = $${idx++}`);
      params.push(String(email).trim());
    }

    // 전화번호 변경
    if (phone !== undefined) {
      const phoneDigits = onlyDigits(String(phone));
      if (!isPhone10or11(phoneDigits)) {
        return res.status(400).json({ ok: false, error: 'INVALID_PHONE' });
      }
      updates.push(`phone = $${idx++}`);
      params.push(phoneDigits);
    }

    // 소개 문구 변경 (users 테이블에 intro_text 컬럼이 있어야 함!)
    if (intro_text !== undefined) {
      updates.push(`intro_text = $${idx++}`);
      params.push(String(intro_text));
    }

    // 비밀번호 변경
    if (password !== undefined && String(password).trim() !== '') {
      if (!passwordStrong(password)) {
        return res.status(400).json({ ok: false, error: 'WEAK_PASSWORD' });
      }

      const hash = await bcrypt.hash(
        String(password),
        Number(process.env.BCRYPT_SALT_ROUNDS || 10)
      );
      updates.push(`password_hash = $${idx++}`);
      params.push(hash);
    }

    if (updates.length === 0) {
      // 변경할 게 없으면 그냥 OK
      return res.json({ ok: true });
    }

    // 실제 업데이트
    params.push(payload.sub); // where id = $idx
    const q = `
      UPDATE users
         SET ${updates.join(', ')},
             updated_at = now()
       WHERE id = $${idx}
       RETURNING id, email, name, role, phone, user_no, planner_no
    `;

    const r = await query(q, params);
    if (!r.rowCount) {
      return res.status(404).json({ ok: false, error: 'NOT_FOUND' });
    }

    const user = r.rows[0];
    return res.json({ ok: true, user });
  } catch (e) {
    console.error('[me:PUT]', e);
    return res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
  }
});

// ─────────────────────────────────────────────────────────
// WebSocket (Signaling) — 강화판
// ─────────────────────────────────────────────────────────
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

// 방 관리: roomId -> Set<ws>
const rooms = new Map();

// 소켓 메타(생존/방목록/마지막 pong 등) 추적
const wsMeta = new WeakMap();

// 환경설정
const MAX_ROOM_SIZE = Number(process.env.MAX_ROOM_SIZE || 2);
const HEARTBEAT_INTERVAL_MS = Number(process.env.HEARTBEAT_INTERVAL_MS || 30_000);
const CLIENT_TIMEOUT_MS = Number(process.env.CLIENT_TIMEOUT_MS || 90_000);

// 유틸: 안전 전송
function safeSend(ws, obj) {
  try { ws.send(JSON.stringify(obj)); } catch {}
}

function notifyPeers(roomId, payload, except=null) {
  const set = rooms.get(roomId);
  if (!set) return;
  for (const peer of set) {
    if (peer !== except && peer.readyState === 1) safeSend(peer, payload);
  }
}

function join(ws, roomId) {
  if (!roomId) return safeSend(ws, { type: 'error', error: 'roomId_required' });

  if (!rooms.has(roomId)) rooms.set(roomId, new Set());
  const set = rooms.get(roomId);
  if (set.size >= 2) return safeSend(ws, { type: 'room-full', roomId });

  set.add(ws);
  ws._rooms ??= new Set();
  ws._rooms.add(roomId);

  // 나에게 현재 인원 알려주기
  safeSend(ws, { type: 'joined', roomId, peers: set.size });

  // ✅ 기존 참가자에게 "새 피어 들어옴" 알림
  notifyPeers(roomId, { type: 'peer-join', roomId, peers: set.size }, ws);

  console.log(`[WS] joined room=${roomId} peers=${set.size}`);
}

function leaveAll(ws) {
  for (const roomId of ws._rooms || []) {
    const set = rooms.get(roomId);
    if (!set) continue;
    set.delete(ws);
    if (set.size === 0) {
      rooms.delete(roomId);
      console.log(`room empty -> deleted room=${roomId}`);
    } else {
      // ✅ 남아있는 참가자에게 "피어 떠남" 알림
      notifyPeers(roomId, { type: 'peer-left', roomId, peers: set.size });
      console.log(`[WS] left room=${roomId} peers=${set.size}`);
    }
  }
}

// 유틸: 같은 방 피어에게 릴레이
function relay(ws, roomId, payload) {
  const set = rooms.get(roomId);
  if (!set) return;
  for (const peer of set) {
    if (peer !== ws && peer.readyState === 1) {
      safeSend(peer, payload);
    }
  }
}

// 메시지 스키마 간단 검증
function isSignalWithRoom(msg) {
  return msg && typeof msg === 'object' && typeof msg.roomId === 'string';
}

// 하트비트: 서버→클라 ping, 클라 pong 확인
const heartbeatTimer = setInterval(() => {
  wss.clients.forEach((ws) => {
    const meta = wsMeta.get(ws);
    if (!meta) return;
    const now = Date.now();

    // 클라가 ping을 보내는 경우도 있지만, 서버 주도로 ping을 보냄
    if (ws.readyState === 1) {
      try { ws.ping(); } catch {}
    }

    // 마지막 pong으로부터 너무 오래되면 종료
    if (now - meta.lastPongAt > CLIENT_TIMEOUT_MS) {
      console.warn('[WS] terminate stale client');
      try { ws.terminate(); } catch {}
    }
  });
}, HEARTBEAT_INTERVAL_MS);

wss.on('connection', (ws, req) => {
  console.log(`[WS] connection from ${req.socket.remoteAddress}`);

  wsMeta.set(ws, {
    rooms: new Set(),
    lastPongAt: Date.now(),
  });

  const ip =
    req.headers['x-forwarded-for']?.toString().split(',')[0].trim() ||
    req.socket.remoteAddress;
  console.log('[WS] connection from', ip);

  // 기본 이벤트
  ws.on('pong', () => {
    const meta = wsMeta.get(ws);
    if (meta) meta.lastPongAt = Date.now();
  });

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw.toString()); }
    catch {
      console.warn('[WS] non-JSON message ignored');
      return;
    }
    console.log('[WS] recv type=%s room=%s', msg?.type, msg?.roomId)

    // 디버그: 모든 타입 로깅
    const room = msg?.roomId ?? '-';
    console.log(`[WS] recv type=${msg?.type} room=${room}`);

    // 클라 ping 대응
    if (msg?.type === 'ping') {
      safeSend(ws, { type: 'pong', t: Date.now() });
      return;
    }

    if (msg?.type === 'join') {
      console.log(`[WS] join requested room=${msg.roomId}`);
      return join(ws, msg.roomId);
    }

    if (['offer', 'answer', 'ice'].includes(msg?.type)) {
      if (!isSignalWithRoom(msg)) {
        console.warn(`[WS] invalid signal without roomId type=${msg?.type}`);
        return safeSend(ws, { type: 'error', error: 'roomId_required' });
      }
      // 필수 필드 체크 로그
      if (msg.type === 'offer' && !msg.sdp) console.warn('[WS] offer without sdp');
      if (msg.type === 'answer' && !msg.sdp) console.warn('[WS] answer without sdp');
      if (msg.type === 'ice' && !msg.candidate) console.warn('[WS] ice without candidate');

      console.log(`[WS] relay type=${msg.type} room=${msg.roomId}`);
      relay(ws, msg.roomId, msg);
      return;
    }

    safeSend(ws, { type: 'error', error: 'unknown_type', raw: msg?.type });
  });

  ws.on('close', () => {
    leaveAll(ws);
  });

  ws.on('error', (err) => {
    console.warn('[WS] error', err?.message || err);
  });
});

// 디버그: 현재 방/피어 상태 조회
app.get('/debug/rooms', (_req, res) => {
  const out = [];
  for (const [roomId, set] of rooms.entries()) {
    out.push({ roomId, peers: set.size });
  }
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

server.listen(PORT, () => {
  console.log(`HTTP+WS signaling up: http://0.0.0.0:${PORT}`);
});

// ------------------------

// ★★★ [추가] 설계사 회원가입: POST /auth/signup-planner
app.post('/auth/signup-planner', async (req, res) => {
  try {
    const { name, email, password, phone } = req.body ?? {};

    // 기본 검증 (일반 가입과 동일 정책)
    if (!name || !email || !password) {
      return res.status(400).json({ ok: false, error: 'INVALID_INPUT' });
    }
    if (!isEmail(email)) {
      return res.status(400).json({ ok: false, error: 'INVALID_EMAIL' });
    }
    if (!passwordStrong(password)) {
      return res.status(400).json({ ok: false, error: 'WEAK_PASSWORD' });
    }

    const phoneDigits = onlyDigits(phone || '');
    if (!isPhone10or11(phoneDigits)) {
      return res.status(400).json({ ok: false, error: 'INVALID_PHONE' });
    }

    // 이메일 중복
    const existed = await query(
      'SELECT id FROM users WHERE lower(email)=lower($1) LIMIT 1',
      [String(email).trim()]
    );
    if (existed.rowCount) {
      return res.status(409).json({ ok: false, error: 'EMAIL_TAKEN' });
    }

    // ★★★ 핵심: role='planner'로 저장 (planner_no는 NULL이어야 함)
    // DB 트리거가 자동으로 planner 시퀀스(user_no_planner_seq)에서 user_no를 부여
    const hash = await bcrypt.hash(String(password), Number(process.env.BCRYPT_SALT_ROUNDS || 10));
    const ins = await query(
      `INSERT INTO users (email, password_hash, name, role, phone)
       VALUES ($1,$2,$3,'planner',$4)
       RETURNING id, email, name, role, phone, user_no, created_at`,
      [String(email).trim(), hash, String(name).trim(), phoneDigits]
    );
    const user = ins.rows[0];

    // 토큰 발급(관리 콘솔에서 바로 로그인하게 하려면 유지)
    const token = jwt.sign({ sub: user.user_no, role: user.role }, process.env.JWT_SECRET, { expiresIn: '7d' });

    // ★★★ user_no가 설계사 번호
    return res.status(201).json({ ok: true, token, user });
  } catch (e) {
    if (e?.code === '23505') return res.status(409).json({ ok: false, error: 'EMAIL_TAKEN' });
    console.error('[signup-planner]', e);
    return res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
  }
});

// ─────────────────────────────────────────────────────────
// (signaling.js 상단 import 아래, helpers 근처에 없으면 추가)
// ─────────────────────────────────────────────────────────

// ★★★ JWT 토큰 파싱 유틸 (없으면 추가)
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
// (Auth API들 바로 아래쯤에 추가) 내 고객 목록
// ─────────────────────────────────────────────────────────

// ★★★ GET /customers/mine
// - planner: 본인에게 배정된 고객(users.role='user') 목록만 반환
// - admin  : 전체 고객 목록 반환 (원하면 ?plannerId=...로 특정 설계사 필터 가능)
app.get('/customers/mine', async (req, res) => {
  try {
    const payload = verifyTokenFromReq(req);
    if (!payload?.sub) return res.status(401).json({ ok: false, error: 'UNAUTHORIZED' });

    // 나(접속자) 정보 조회: role, user_no 필요
    const meRes = await query(
      `SELECT id, role, user_no FROM users WHERE id = $1 LIMIT 1`,
      [payload.sub]
    );
    if (!meRes.rowCount) return res.status(404).json({ ok: false, error: 'NOT_FOUND' });

    const me = meRes.rows[0];

    // 플래너: 내 user_no를 고객의 planner_no와 매칭
    if (me.role === 'planner') {
      const q = `
        SELECT 
          id,
          user_no,
          name,
          email,
          phone,
          created_at,
          file_bytes,   -- ★ 추가
          used_bytes    -- ★ 추가
        FROM users
        WHERE role = 'user'
          AND planner_no = $1
        ORDER BY created_at DESC
      `;
      const r = await query(q, [me.user_no]);
      const customers = r.rows.map(u => ({
        id: u.id,
        name: u.name,
        email: u.email,
        phone: u.phone,
        user_no: u.user_no,
        created_at: u.created_at,
        file_bytes: u.file_bytes,   // ★ 추가
        used_bytes: u.used_bytes,   // ★ 추가
      }));
      return res.json({ ok: true, customers });
    }

    // 관리자: 전체 고객 or 특정 플래너의 고객(쿼리로 필터)
    if (me.role === 'admin') {
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
            file_bytes,   -- ★ 추가
            used_bytes    -- ★ 추가
          FROM users
          WHERE role = 'user'
            AND planner_no = $1
          ORDER BY created_at DESC
        `;
        const r = await query(q, [plannerUserNo]);
        const customers = r.rows.map(u => ({
          id: u.id,
          name: u.name,
          email: u.email,
          phone: u.phone,
          user_no: u.user_no,
          created_at: u.created_at,
          file_bytes: u.file_bytes,   // ★ 추가
          used_bytes: u.used_bytes,   // ★ 추가
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
            file_bytes,   -- ★ 추가
            used_bytes    -- ★ 추가
          FROM users
          WHERE role = 'user'
          ORDER BY created_at DESC
        `;
        const r = await query(q);
        const customers = r.rows.map(u => ({
          id: u.id,
          name: u.name,
          email: u.email,
          phone: u.phone,
          user_no: u.user_no,
          created_at: u.created_at,
          file_bytes: u.file_bytes,   // ★ 추가
          used_bytes: u.used_bytes,   // ★ 추가
        }));
        return res.json({ ok: true, customers });
      }
    }

    // 일반 사용자는 접근 불가
    return res.status(403).json({ ok: false, error: 'FORBIDDEN' });
  } catch (e) {
    console.error('[customers/mine]', e);
    return res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
  }
});

// ★★★ 설계사가 담당 고객의 저장 용량(GB)을 변경
app.put('/customers/filequota', async (req, res) => {
  try {
    const payload = verifyTokenFromReq(req);
    if (!payload?.sub) {
      return res.status(401).json({ ok: false, error: 'UNAUTHORIZED' });
    }

    // ✅ 프론트에서 오는 이름에 맞춰준다.
    const { customerUserNo, fileBytes } = req.body ?? {};
    // fileBytes: 10, 30, 50 (GB 단위)

    // 문자열로 와도 숫자로 변환
    const userNo = Number(customerUserNo);
    const fileBytesNum = Number(fileBytes);

    // ✅ 숫자 여부 검사
    if (!Number.isFinite(userNo) || !Number.isFinite(fileBytesNum)) {
      return res.status(400).json({ ok: false, error: 'INVALID_INPUT' });
    }

    if (![10, 30, 50].includes(fileBytesNum)) {
      return res.status(400).json({ ok: false, error: 'INVALID_QUOTA' });
    }

    // 나(설계사) 정보 가져오기
    const meRes = await query(
      `SELECT id, role, user_no FROM users WHERE id = $1 LIMIT 1`,
      [payload.sub]
    );
    if (!meRes.rowCount) {
      return res.status(404).json({ ok: false, error: 'ME_NOT_FOUND' });
    }
    const me = meRes.rows[0];

    // manager/admin/planner 만 변경 허용
    if (
      me.role !== 'planner' &&
      me.role !== 'admin' &&
      me.role !== 'manager'
    ) {
      return res.status(403).json({ ok: false, error: 'FORBIDDEN_ROLE' });
    }

    let r;
    if (me.role === 'planner') {
      // 설계사는 "내 고객"만 변경 가능
      r = await query(
        `
        UPDATE users
        SET file_bytes = $2
        WHERE user_no = $1
          AND role = 'user'
          AND planner_no = $3
        RETURNING id, user_no, file_bytes, used_bytes
        `,
        [userNo, fileBytesNum, me.user_no]
      );
    } else {
      // admin / manager 는 전체 고객 변경 가능
      r = await query(
        `
        UPDATE users
        SET file_bytes = $2
        WHERE user_no = $1
          AND role = 'user'
        RETURNING id, user_no, file_bytes, used_bytes
        `,
        [userNo, fileBytesNum]
      );
    }

    if (!r.rowCount) {
      return res.status(404).json({
        ok: false,
        error: 'USER_NOT_FOUND_OR_NO_PERMISSION',
      });
    }

    const updated = r.rows[0];

    // ✅ 프론트에서 j.customer 로 읽도록 맞춰서 보낸다.
    return res.json({
      ok: true,
      customer: {
        id: updated.id,
        user_no: updated.user_no,
        file_bytes: updated.file_bytes,
        used_bytes: updated.used_bytes,
      },
    });
  } catch (e) {
    console.error('[customers/filequota]', e);
    return res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
  }
});

// ★★★ GET /planners/by-user-no
// - 쿼리: ?userNo=1002 (또는 ?plannerNo=2002 로 직접 설계사 번호 넘겨도 됨)
// - 리턴: { ok: true, planner: { id, user_no, name, email, phone, ... } }
app.get('/planners/by-user-no', async (req, res) => {
  try {
    const userNoRaw = req.query.userNo;
    const plannerNoRaw = req.query.plannerNo;

    // 숫자만 추출
    const userNo = userNoRaw ? onlyDigits(String(userNoRaw)) : '';
    const plannerNo = plannerNoRaw ? onlyDigits(String(plannerNoRaw)) : '';

    if (!userNo && !plannerNo) {
      return res
        .status(400)
        .json({ ok: false, error: 'userNo or plannerNo required' });
    }

    let plannerNoFinal = plannerNo || null;

    // ★★★ 1) userNo만 넘어오면: 그 사용자의 planner_no를 먼저 찾는다
    if (!plannerNoFinal && userNo) {
      const rUser = await query(
        `
        SELECT planner_no
        FROM users
        WHERE user_no = $1
          AND role = 'user'
        LIMIT 1
        `,
        [Number(userNo)]
      );

      if (!rUser.rowCount || !rUser.rows[0].planner_no) {
        return res.status(404).json({
          ok: false,
          error: 'PLANNER_NOT_ASSIGNED',
        });
      }

      plannerNoFinal = String(rUser.rows[0].planner_no);
    }

    if (!plannerNoFinal) {
      return res
        .status(404)
        .json({ ok: false, error: 'PLANNER_NOT_FOUND' });
    }

    // ★★★ 2) planner_no 기준으로 설계사(users.role='planner') 조회
    const rPlanner = await query(
      `
      SELECT
        id,
        user_no,
        name,
        email,
        phone,
        role,
        created_at
      FROM users
      WHERE user_no = $1
        AND role = 'planner'
      LIMIT 1
      `,
      [Number(plannerNoFinal)]
    );

    if (!rPlanner.rowCount) {
      return res
        .status(404)
        .json({ ok: false, error: 'PLANNER_NOT_FOUND' });
    }

    const p = rPlanner.rows[0];

    // ★★★ 응답 스키마 — 프론트에서 그대로 planner.* 로 사용
    const planner = {
      id: p.id,
      user_no: p.user_no,
      name: p.name,
      email: p.email,
      phone: p.phone,
      role: p.role,
      created_at: p.created_at,
      // ★★★ 여기에 branch 같은 컬럼 있으면 추가
      // branch: p.branch_name ?? null,
    };

    return res.json({ ok: true, planner });
  } catch (e) {
    console.error('[planners/by-user-no]', e);
    return res
      .status(500)
      .json({ ok: false, error: 'SERVER_ERROR' });
  }
});