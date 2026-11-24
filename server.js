'use strict';
/**
 * TiviOne – serveur Node.js (aucune dépendance)
 *  - sert l’application (index.html, icônes…)
 *  - GET /proxy?u=<lien>&k=<code VIP> : relais pour les flux bloqués (CORS, http, etc.)
 *  - GET /health : indique que le relais est disponible
 * Sécurité : code VIP vérifié via Google Sheet, adresses privées bloquées, pages web refusées,
 * limites par code (flux simultanés, volume par jour).
 */
const http = require('http'), fs = require('fs'), path = require('path'), net = require('net'), dns = require('dns').promises;
const {Readable} = require('stream');

const PORT = process.env.PORT || 3000;
const API = process.env.API_URL || 'https://script.google.com/macros/s/AKfycbyhr-XKy6_A_6-Z1JzAKXq_FuwGl5kT6kxZpMq_GOcAiqv5nBpaHIIqo_JtPnqHbVEU/exec';
const DAILY = Number(process.env.DAILY_MB || 3000) * 1e6;       // volume maximum par code et par jour
const MAX_STREAMS = Number(process.env.MAX_STREAMS || 8);       // flux simultanés par code
const ORIGINS = (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
const UA = 'Mozilla/5.0 (Linux; Android 12) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36';
const FILES = {
  'index.html': 'text/html; charset=utf-8',
  'sw.js': 'text/javascript; charset=utf-8',
  'manifest.json': 'application/manifest+json',
  'icon-192.png': 'image/png',
  'icon-512.png': 'image/png',
  'icon-180.png': 'image/png',
  'favicon-32.png': 'image/png'
};

const send = (res, code, msg) => {
  res.writeHead(code, {'Content-Type': 'text/plain; charset=utf-8', 'Access-Control-Allow-Origin': '*'});
  res.end(msg);
};

/* ---------- Contrôle d’accès : code VIP ---------- */
const okCache = new Map(), badCache = new Map(), fails = new Map(), usage = new Map(), active = new Map();
const day = () => new Date().toISOString().slice(0, 10);
const used = c => { const u = usage.get(c); return u && u.d === day() ? u.b : 0; };
function addUsed(c, n) {
  const d = day();
  let u = usage.get(c);
  if (!u || u.d !== d) { u = {d, b: 0}; usage.set(c, u); }
  u.b += n;
}
setInterval(() => {
  const n = Date.now();
  [okCache, badCache].forEach(m => m.forEach((v, k) => { if (v < n) m.delete(k); }));
  fails.forEach((v, k) => { if (n - v.t > 600e3) fails.delete(k); });
}, 600e3).unref();

async function verify(code, ip) {
  code = String(code || '').trim().toUpperCase();
  if (!code || code.length > 64) return false;
  const ok = okCache.get(code); if (ok && ok > Date.now()) return true;
  const bad = badCache.get(code); if (bad && bad > Date.now()) return false;
  const f = fails.get(ip) || {n: 0, t: Date.now()};
  if (Date.now() - f.t > 600e3) { f.n = 0; f.t = Date.now(); }
  if (f.n >= 15) return false;
  try {
    const r = await fetch(API, {
      method: 'POST',
      headers: {'Content-Type': 'text/plain'},
      body: JSON.stringify({a: 'login', code})
    });
    const j = await r.json();
    if (j && j.ok) {
      okCache.set(code, Math.min(Date.now() + 300e3, Number(j.exp) || (Date.now() + 300e3)));
      return true;
    }
  } catch (e) { return false; }
  badCache.set(code, Date.now() + 60e3);
  f.n++;
  fails.set(ip, f);
  return false;
}

/* ---------- Protection contre l’accès au réseau interne ---------- */
function isPrivate(ip) {
  if (net.isIPv4(ip)) {
    const p = ip.split('.').map(Number);
    return p[0] === 0 || p[0] === 10 || p[0] === 127 ||
      (p[0] === 169 && p[1] === 254) ||
      (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
      (p[0] === 192 && p[1] === 168) ||
      (p[0] === 100 && p[1] >= 64 && p[1] <= 127) ||
      p[0] >= 224;
  }
  if (net.isIPv6(ip)) {
    const s = ip.toLowerCase();
    if (s.startsWith('::ffff:')) return isPrivate(s.slice(7));
    return s === '::1' || s === '::' || s.startsWith('fc') || s.startsWith('fd') ||
      s.startsWith('fe8') || s.startsWith('fe9') || s.startsWith('fea') || s.startsWith('feb');
  }
  return true;
}

async function safeUrl(u) {
  let x; try { x = new URL(u); } catch (e) { return null; }
  if (!/^https?:$/.test(x.protocol) || x.username || x.password) return null;
  const h = x.hostname.replace(/^\[|\]$/g, '');
  if (net.isIP(h)) return isPrivate(h) ? null : x;
  if (h === 'localhost' || h.endsWith('.local') || h.endsWith('.internal')) return null;
  try {
    const a = await dns.lookup(h, {all: true});
    if (!a.length || a.some(r => isPrivate(r.address))) return null;
  } catch (e) { return null; }
  return x;
}

async function upstream(u, req, signal) {
  let url = u;
  for (let i = 0; i < 5; i++) {
    const x = await safeUrl(url);
    if (!x) throw Object.assign(new Error('bloqué'), {status: 403});
    const headers = {'User-Agent': UA, 'Accept': '*/*'};
    if (req.headers.range) headers.Range = req.headers.range;
    const r = await fetch(x, {headers, redirect: 'manual', signal});
    const loc = r.headers.get('location');
    if (r.status >= 300 && r.status < 400 && loc) { url = new URL(loc, x).href; continue; }
    return {r, url: x.href};
  }
  throw Object.assign(new Error('trop de redirections'), {status: 508});
}

/* ---------- Réécriture des playlists HLS : tout repasse par /proxy ---------- */
function rewrite(text, base, t) {
  const px = u => {
    try {
      return '/proxy?u=' + encodeURIComponent(new URL(u, base).href) + '&k=' + encodeURIComponent(t);
    } catch (e) { return u; }
  };
  return text.split(/\r?\n/).map(l => {
    if (!l.trim()) return l;
    if (l[0] === '#') return l.replace(/URI="([^"]+)"/g, (m, u) => /^data:/i.test(u) ? m : 'URI="' + px(u) + '"');
    return px(l.trim());
  }).join('\n');
}

const isHls = t => /#EXT-X-(TARGETDURATION|STREAM-INF|MEDIA-SEQUENCE|MEDIA:|VERSION|PLAYLIST-TYPE|ENDLIST|MAP)/.test(t);

const cors = (req, res) => {
  const o = req.headers.origin;
  if (!ORIGINS.length) {
    res.setHeader('Access-Control-Allow-Origin', '*');
  } else if (o && ORIGINS.includes(o)) {
    res.setHeader('Access-Control-Allow-Origin', o);
    res.setHeader('Vary', 'Origin');
  }
};

async function proxy(req, res, q, ip) {
  const u = q.get('u'), t = String(q.get('k') || '').trim().toUpperCase();
  if (!u || u.length > 2000) return send(res, 400, 'Lien manquant');
  if (!(await verify(t, ip))) return send(res, 401, 'Code VIP invalide ou expiré');
  if (used(t) >= DAILY) return send(res, 429, 'Limite quotidienne atteinte');
  if ((active.get(t) || 0) >= MAX_STREAMS) return send(res, 429, 'Trop de flux simultanés');

  const ac = new AbortController();
  res.on('close', () => ac.abort());
  const timer = setTimeout(() => ac.abort(), 20000);

  try {
    const {r, url} = await upstream(u, req, ac.signal);
    clearTimeout(timer);
    const ct = r.headers.get('content-type') || '';
    if (/text\/html/i.test(ct)) return send(res, 415, 'Ce lien n’est pas un flux vidéo');
    if (!r.ok && r.status !== 206) return send(res, r.status === 404 ? 404 : 502, 'Flux inaccessible');

    cors(req, res);

    if (/mpegurl|text\/plain/i.test(ct) || /\.m3u8?(\?|$)/i.test(url)) {
      if (Number(r.headers.get('content-length') || 0) > 30e6) return send(res, 413, 'Fichier trop grand');
      const text = await r.text();
      if (text.length > 30e6) return send(res, 413, 'Fichier trop grand');
      if (isHls(text)) {
        res.writeHead(200, {'Content-Type': 'application/vnd.apple.mpegurl', 'Cache-Control': 'no-store'});
        return res.end(rewrite(text, url, t));
      }
      res.writeHead(200, {'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store'});
      return res.end(text);
    }

    const h = {'Content-Type': ct || 'application/octet-stream', 'Cache-Control': 'no-store'};
    if (!r.headers.get('content-encoding')) {
      ['content-length', 'content-range', 'accept-ranges'].forEach(k => {
        const v = r.headers.get(k);
        if (v) h[k] = v;
      });
    }
    res.writeHead(r.status, h);
    if (!r.body) return res.end();

    active.set(t, (active.get(t) || 0) + 1);
    let released = false;
    const release = () => {
      if (released) return;
      released = true;
      active.set(t, Math.max(0, (active.get(t) || 1) - 1));
    };
    res.on('close', release);
    res.on('finish', release);

    Readable.fromWeb(r.body)
      .on('data', c => addUsed(t, c.length))
      .on('error', () => { release(); res.destroy(); })
      .on('end', release)
      .pipe(res);
  } catch (e) {
    clearTimeout(timer);
    if (!res.headersSent) send(res, e.status || 502, 'Flux inaccessible');
    else res.destroy();
  }
}

function serve(req, res, p) {
  const name = p === '/' ? 'index.html' : p.slice(1), type = FILES[name];
  if (!type) return send(res, 404, 'Introuvable');
  fs.readFile(path.join(__dirname, name), (e, d) => {
    if (e) return send(res, 404, 'Introuvable');
    res.writeHead(200, {
      'Content-Type': type,
      'X-Content-Type-Options': 'nosniff',
      'Cache-Control': name === 'index.html' || name === 'sw.js' ? 'no-cache' : 'public, max-age=86400'
    });
    res.end(d);
  });
}

const server = http.createServer(async (req, res) => {
  try {
    const u = new URL(req.url, 'http://x');
    const ip = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
    if (req.method === 'OPTIONS') {
      cors(req, res);
      res.writeHead(204, {
        'Access-Control-Allow-Methods': 'GET, OPTIONS',
        'Access-Control-Allow-Headers': 'Range, Content-Type',
        'Access-Control-Max-Age': '86400'
      });
      return res.end();
    }
    if (req.method !== 'GET') return send(res, 405, 'Méthode non autorisée');
    if (u.pathname === '/health') {
      res.writeHead(200, {'Content-Type': 'text/plain', 'Cache-Control': 'no-store', 'Access-Control-Allow-Origin': '*'});
      return res.end('tivione-proxy-ok');
    }
    if (u.pathname === '/proxy') return await proxy(req, res, u.searchParams, ip);
    return serve(req, res, u.pathname);
  } catch (e) {
    if (!res.headersSent) send(res, 500, 'Erreur serveur');
    else res.destroy();
  }
});

if (require.main === module) server.listen(PORT, () => console.log('TiviOne : serveur démarré sur le port ' + PORT));
module.exports = {rewrite, isPrivate, safeUrl, isHls, server};
