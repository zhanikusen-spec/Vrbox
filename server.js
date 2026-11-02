'use strict';
/* VR Box · Quest — сервер: раздаёт игру, аккаунты (/api/*), онлайн-комнаты и голос (WebSocket) */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const zlib = require('zlib');
const { WebSocketServer } = require('ws');

const PORT = +process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const MAX_ROOM = Math.min(250, +process.env.MAX_PLAYERS || 30); // игроков в одной комнате (id игрока — 1 байт)
const ROOMS = 4;                                               // server #1 … #4 в игре
const VOICE_R = +process.env.VOICE_RADIUS || 14;               // метров, дальше голос не пересылаем
const NICK_RE = /^[A-Za-z0-9_\-А-Яа-яЁё]{3,16}$/;

/* ---------- статика ---------- */
const INDEX = fs.readFileSync(path.join(__dirname, 'public', 'index.html'));
const INDEX_GZ = zlib.gzipSync(INDEX, { level: 6 });
const ETAG = '"' + crypto.createHash('sha1').update(INDEX).digest('hex').slice(0, 16) + '"';

/* ---------- пользователи ---------- */
fs.mkdirSync(DATA_DIR, { recursive: true });
const DB_FILE = path.join(DATA_DIR, 'users.json');
let users = {};                 // ключ — ник в нижнем регистре
try { users = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch (e) { users = {}; }
const tokenIdx = new Map();     // sha256(token) -> ключ пользователя
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
for (const k in users) for (const h of users[k].tokens || []) tokenIdx.set(h, k);

let saveT = null;
function persist() {
  if (saveT) return;
  saveT = setTimeout(() => {
    saveT = null;
    const tmp = DB_FILE + '.tmp';
    fs.writeFile(tmp, JSON.stringify(users), err => { if (!err) fs.rename(tmp, DB_FILE, () => {}); });
  }, 800);
}
const scrypt = (pass, salt) => new Promise((res, rej) => crypto.scrypt(pass, salt, 32, (e, k) => e ? rej(e) : res(k)));
function newToken(key) {
  const t = crypto.randomBytes(32).toString('hex'), u = users[key];
  u.tokens = (u.tokens || []).slice(-4);       // не больше 5 устройств
  const h = sha(t); u.tokens.push(h); tokenIdx.set(h, key);
  return t;
}
const userByToken = t => {
  if (typeof t !== 'string' || t.length < 16 || t.length > 128) return null;
  const k = tokenIdx.get(sha(t)); return k && users[k] ? { key: k, u: users[k] } : null;
};
function cleanData(d) {
  if (!d || typeof d !== 'object' || Array.isArray(d)) return {};
  return JSON.stringify(d).length <= 60000 ? d : null;
}

/* ---------- простой лимит запросов ---------- */
const hits = new Map();
function limited(ip, max) {
  const now = Date.now(), h = (hits.get(ip) || []).filter(t => now - t < 60000);
  h.push(now); hits.set(ip, h); return h.length > max;
}
setInterval(() => { const now = Date.now(); for (const [k, v] of hits) if (!v.some(t => now - t < 60000)) hits.delete(k); }, 60000).unref();

/* ---------- HTTP ---------- */
const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type'
};
function json(res, code, obj) {
  res.writeHead(code, Object.assign({ 'Content-Type': 'application/json; charset=utf-8' }, CORS));
  res.end(JSON.stringify(obj));
}
function readBody(req) {
  return new Promise((res, rej) => {
    let n = 0; const ch = [];
    req.on('data', c => { n += c.length; if (n > 200000) { rej(new Error('big')); req.destroy(); } else ch.push(c); });
    req.on('end', () => { try { res(JSON.parse(Buffer.concat(ch).toString('utf8') || '{}')); } catch (e) { rej(new Error('bad json')); } });
    req.on('error', rej);
  });
}

const API = {
  async register(b, ip) {
    if (limited(ip, 10)) throw httpErr(429, 'Слишком много попыток, подожди минуту');
    const nick = String(b.nick || '').trim(), pass = String(b.pass || '');
    if (!NICK_RE.test(nick)) throw httpErr(400, 'Ник: 3–16 символов — буквы, цифры, _ и -');
    if (pass.length < 4 || pass.length > 64) throw httpErr(400, 'Пароль — от 4 до 64 символов');
    const key = nick.toLowerCase();
    if (users[key]) throw httpErr(409, 'Этот ник уже занят');
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = (await scrypt(pass, salt)).toString('hex');
    if (users[key]) throw httpErr(409, 'Этот ник уже занят');
    const data = cleanData(b.data) || {};
    users[key] = { nick, salt, hash, data, tokens: [], created: Date.now() };
    const token = newToken(key); persist();
    return { nick, token, data };
  },
  async login(b, ip) {
    if (limited(ip, 20)) throw httpErr(429, 'Слишком много попыток, подожди минуту');
    const key = String(b.nick || '').trim().toLowerCase(), u = users[key];
    if (!u) throw httpErr(401, 'Неверный ник или пароль');
    const hash = await scrypt(String(b.pass || ''), u.salt);
    const ok = hash.length === 32 && crypto.timingSafeEqual(hash, Buffer.from(u.hash, 'hex'));
    if (!ok) throw httpErr(401, 'Неверный ник или пароль');
    const token = newToken(key); persist();
    return { nick: u.nick, token, data: u.data || {} };
  },
  async me(b) {
    const r = userByToken(b.token);
    if (!r) throw httpErr(401, 'Сессия устарела');
    return { nick: r.u.nick, data: r.u.data || {} };
  },
  async save(b) {
    const r = userByToken(b.token);
    if (!r) throw httpErr(401, 'Сессия устарела');
    const d = cleanData(b.data);
    if (d === null) throw httpErr(413, 'Слишком большие данные');
    r.u.data = d; persist();
    return { ok: true };
  }
};
const httpErr = (code, msg) => Object.assign(new Error(msg), { http: code });

const server = http.createServer(async (req, res) => {
  const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').toString().split(',')[0].trim();
  const url = (req.url || '/').split('?')[0];
  if (req.method === 'OPTIONS') { res.writeHead(204, CORS); return res.end(); }

  if (url.startsWith('/api/')) {
    const name = url.slice(5);
    if (name === 'health') return json(res, 200, { ok: true, online: wss ? wss.clients.size : 0 });
    if (req.method !== 'POST' || !Object.prototype.hasOwnProperty.call(API, name)) return json(res, 404, { error: 'Не найдено' });
    try { json(res, 200, await API[name](await readBody(req), ip)); }
    catch (e) { json(res, e.http || 400, { error: e.http ? e.message : 'Некорректный запрос' }); }
    return;
  }

  if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405); return res.end(); }
  if (url === '/' || url === '/index.html') {
    if (req.headers['if-none-match'] === ETAG) { res.writeHead(304, { ETag: ETAG }); return res.end(); }
    const gz = /\bgzip\b/.test(req.headers['accept-encoding'] || ''), body = gz ? INDEX_GZ : INDEX;
    const h = { 'Content-Type': 'text/html; charset=utf-8', 'Content-Length': body.length, ETag: ETAG, 'Cache-Control': 'no-cache' };
    if (gz) h['Content-Encoding'] = 'gzip';
    res.writeHead(200, h);
    return res.end(req.method === 'HEAD' ? undefined : body);
  }
  if (url === '/health') { res.writeHead(200, { 'Content-Type': 'text/plain' }); return res.end('ok'); }
  res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); res.end('Не найдено');
});

/* ---------- WebSocket: комнаты, позиции, голос ---------- */
const rooms = {};                                   // номер -> Map(id -> клиент)
const wss = new WebSocketServer({ server, maxPayload: 16384 });
const num = (v, lim) => (typeof v === 'number' && isFinite(v) ? Math.max(-lim, Math.min(lim, v)) : 0);
const send = (ws, o) => { if (ws.readyState === 1) ws.send(JSON.stringify(o)); };

function leave(ws) {
  if (!ws.room) return;
  const r = rooms[ws.room]; if (r) { r.delete(ws.id); if (!r.size) delete rooms[ws.room]; }
  ws.room = 0;
}

wss.on('connection', ws => {
  ws.isAlive = true; ws.room = 0; ws.id = 0; ws.key = null;
  ws.p = { x: 0, y: 0, z: 0, r: 0, h: '', m: 0 };
  ws.voiceBytes = 0; ws.voiceT = Date.now();
  const joinTimer = setTimeout(() => { if (!ws.room) ws.close(); }, 10000);

  ws.on('pong', () => { ws.isAlive = true; });
  ws.on('message', (data, isBinary) => {
    ws.isAlive = true;
    if (isBinary) return voice(ws, data);
    let m; try { m = JSON.parse(data.toString()); } catch (e) { return; }
    if (!m || typeof m !== 'object') return;

    if (m.t === 'join' && !ws.room) {
      const au = userByToken(m.token);
      if (!au) { send(ws, { t: 'auth' }); return ws.close(); }
      const rn = Math.min(ROOMS, Math.max(1, parseInt(m.room, 10) || 1));
      const r = rooms[rn] || (rooms[rn] = new Map());
      if (r.size >= MAX_ROOM) { send(ws, { t: 'full' }); return ws.close(); }
      for (const rr of Object.values(rooms)) for (const o of rr.values())      // один аккаунт — одно устройство
        if (o.key === au.key && o !== ws) { send(o, { t: 'kick' }); o.close(); leave(o); }
      let id = 1; while (r.has(id)) id++;
      ws.id = id; ws.room = rn; ws.key = au.key; ws.nick = au.u.nick; r.set(id, ws);
      clearTimeout(joinTimer);
      send(ws, { t: 'hello', id });
    } else if (m.t === 'pos' && ws.room) {
      const p = ws.p;
      p.x = num(m.x, 500); p.y = num(m.y, 200); p.z = num(m.z, 500); p.r = num(m.r, 10);
      p.h = typeof m.h === 'string' ? m.h.slice(0, 24) : ''; p.m = m.m ? 1 : 0;
    }
  });
  ws.on('close', () => { clearTimeout(joinTimer); leave(ws); });
  ws.on('error', () => {});
});

/* голос: PCM 8 кГц от клиента -> [id отправителя][PCM] только ближним игрокам комнаты */
function voice(ws, buf) {
  if (!ws.room || buf.length < 4 || buf.length > 8192) return;
  const now = Date.now();
  if (now - ws.voiceT > 1000) { ws.voiceT = now; ws.voiceBytes = 0; }
  if ((ws.voiceBytes += buf.length) > 48000) return;                // ~3× от нормы, защита от флуда
  const out = Buffer.concat([Buffer.from([ws.id]), buf]), a = ws.p;
  for (const o of rooms[ws.room].values()) {
    if (o === ws || o.readyState !== 1) continue;
    if (Math.hypot(o.p.x - a.x, o.p.y - a.y, o.p.z - a.z) <= VOICE_R) o.send(out, { binary: true });
  }
}

/* состояние комнат 10 раз в секунду */
setInterval(() => {
  for (const rn in rooms) {
    const r = rooms[rn], all = [];
    for (const o of r.values()) all.push({ i: o.id, u: o.nick, x: o.p.x, y: o.p.y, z: o.p.z, r: o.p.r, h: o.p.h, m: o.p.m });
    for (const o of r.values()) send(o, { t: 'state', n: r.size, p: all.filter(e => e.i !== o.id) });
  }
}, 100);

/* выкидываем «мёртвые» соединения */
setInterval(() => {
  for (const ws of wss.clients) { if (!ws.isAlive) { ws.terminate(); continue; } ws.isAlive = false; try { ws.ping(); } catch (e) {} }
}, 30000).unref();

server.listen(PORT, () => console.log('VR Box сервер запущен: http://localhost:' + PORT));
process.on('SIGTERM', () => { try { fs.writeFileSync(DB_FILE, JSON.stringify(users)); } catch (e) {} process.exit(0); });
