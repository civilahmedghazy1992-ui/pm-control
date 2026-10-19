/* Project Monitor Control - core (crypto, control file, GitHub gist)
   Created by Planner Ahmed Ghazy
   The control file format is the one of pm_auth.ps1:
     PMCTRL 1 / status= / message= / until= / issued= / dkey= / dissued= / dsig= / user=name|role|active|salt|hash|until / sig=
   The phone signs with its own RSA key (RSASSA-PKCS1-v1_5, SHA-256); the administrator PC signs the phone key once
   (dsig over "PMDKEY|" + dissued + "|" + dkey), so every installation of the tool accepts the phone's files. */
(function (root) {
  'use strict';
  const C = (root.crypto && root.crypto.subtle) ? root.crypto : require('crypto').webcrypto;
  const S = C.subtle;
  const enc = new TextEncoder(), dec = new TextDecoder();
  const FILE = 'ProjectMonitor_control.txt';

  // ---------------------------------------------------------------- bytes
  function b64(bytes) {
    bytes = new Uint8Array(bytes);
    let s = '';
    for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    return btoa(s);
  }
  function unb64(t) {
    const s = atob(String(t).trim());
    const b = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) b[i] = s.charCodeAt(i);
    return b;
  }
  function urlToStd(u) { u = u.replace(/-/g, '+').replace(/_/g, '/'); while (u.length % 4) u += '='; return u; }
  function stdToUrl(s) { return s.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
  function rnd(n) { const b = new Uint8Array(n); C.getRandomValues(b); return b; }

  // ---------------------------------------------------------------- dates (local time, as the PC writes them)
  function pad(n) { return (n < 10 ? '0' : '') + n; }
  function fmt(d) {
    return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + 'T' + pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
  }
  // 'yyyy-MM-ddTHH:mm[:ss]' / 'yyyy-MM-dd HH:mm' / 'yyyy-MM-dd' (= end of the day) -> Date | null
  function parseUntil(t) {
    t = String(t || '').trim();
    let m = t.match(/^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2}))?$/);
    if (m) return new Date(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +(m[6] || 0));
    m = t.match(/^(\d{4})-(\d{2})-(\d{2})$/);
    if (m) return new Date(+m[1], +m[2] - 1, +m[3], 23, 59, 59);
    return null;
  }
  function expired(t, now) { const d = parseUntil(t); return !!d && (now || new Date()) > d; }
  function addDays(days, from) { const d = new Date((from || new Date()).getTime() + days * 86400000); return fmt(d); }

  // ---------------------------------------------------------------- the phone key
  const ALG = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
  async function newKey() {
    const kp = await S.generateKey(Object.assign({ modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) }, ALG), true, ['sign', 'verify']);
    const pkcs8 = b64(await S.exportKey('pkcs8', kp.privateKey));
    const jwk = await S.exportKey('jwk', kp.publicKey);
    return { priv: pkcs8, pub: urlToStd(jwk.n) + '|' + urlToStd(jwk.e) };
  }
  async function importPriv(pkcs8) { return S.importKey('pkcs8', unb64(pkcs8), ALG, false, ['sign']); }
  async function importPub(pubText) {
    const p = String(pubText).split('|');
    return S.importKey('jwk', { kty: 'RSA', n: stdToUrl(p[0]), e: stdToUrl(p[1]), alg: 'RS256', ext: true }, ALG, false, ['verify']);
  }
  async function sign(key, text) { return b64(await S.sign(ALG, key, enc.encode(text))); }
  async function verify(pubText, text, sig) {
    try { return await S.verify(ALG, await importPub(pubText), unb64(sig), enc.encode(text)); } catch (e) { return false; }
  }
  function pairingCode(pub) { return 'PMPHONE1|' + pub; }

  // ---------------------------------------------------------------- the encrypted vault on the phone (key + GitHub token)
  async function vaultKey(password, salt) {
    const base = await S.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
    return S.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt: salt, iterations: 310000 }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }
  async function seal(obj, password) {
    const salt = rnd(16), iv = rnd(12);
    const ct = await S.encrypt({ name: 'AES-GCM', iv: iv }, await vaultKey(password, salt), enc.encode(JSON.stringify(obj)));
    return JSON.stringify({ v: 1, salt: b64(salt), iv: b64(iv), ct: b64(ct) });
  }
  async function unseal(text, password) {
    const o = JSON.parse(text);
    const pt = await S.decrypt({ name: 'AES-GCM', iv: unb64(o.iv) }, await vaultKey(password, unb64(o.salt)), unb64(o.ct));
    return JSON.parse(dec.decode(pt));
  }

  // ---------------------------------------------------------------- users' passwords (same as pm_auth.ps1: PBKDF2-SHA1, 20000, 32 bytes)
  function newSalt() { return b64(rnd(16)); }
  async function hashPwd(pwd, saltB64) {
    const base = await S.importKey('raw', enc.encode(pwd), 'PBKDF2', false, ['deriveBits']);
    return b64(await S.deriveBits({ name: 'PBKDF2', hash: 'SHA-1', salt: unb64(saltB64), iterations: 20000 }, base, 256));
  }

  // ---------------------------------------------------------------- control file
  function parseControl(raw) {
    const c = { ok: false, status: 'enabled', message: '', until: '', src: '', issued: '', dkey: '', dissued: '', dsig: '', users: [], sig: '', body: '', why: '' };
    raw = String(raw || '').replace(/^﻿/, '');
    const body = [];
    raw.split('\n').forEach(function (l) {
      l = l.replace(/\r$/, '');
      if (l.indexOf('sig=') === 0) c.sig = l.substring(4).trim(); else if (l.length > 0) body.push(l);
    });
    if (!body.length || body[0] !== 'PMCTRL 1') { c.why = 'ليس ملف تحكم'; return c; }
    body.forEach(function (l) {
      const i = l.indexOf('='); if (i < 1) return;
      const k = l.substring(0, i), v = l.substring(i + 1);
      if (k === 'user') {
        const p = v.split('|');
        if (p.length >= 5) c.users.push({ name: p[0], role: p[1], active: p[2] === '1', salt: p[3], hash: p[4], until: p.length >= 6 ? p[5] : '' });
      } else if (k in c && k !== 'users') c[k] = v;
    });
    c.body = body.join('\n');
    c.ok = true;
    return c;
  }
  function clean(t) { return String(t || '').replace(/[\r\n]+/g, ' ').trim(); }
  // the phone writes the file: issued always moves forward (never older than the file it replaces)
  async function buildControl(c, privKey, now) {
    now = now || new Date();
    const prev = parseUntil(c.issued);
    if (prev && prev >= now) now = new Date(prev.getTime() + 1000);
    const L = ['PMCTRL 1', 'status=' + (c.status === 'disabled' ? 'disabled' : 'enabled'), 'message=' + clean(c.message)];
    if (c.until) L.push('until=' + c.until);
    if (c.src) L.push('src=' + c.src);
    L.push('issued=' + fmt(now));
    if (c.dkey && c.dsig) { L.push('dkey=' + c.dkey); L.push('dissued=' + c.dissued); L.push('dsig=' + c.dsig); }
    c.users.forEach(function (u) {
      L.push('user=' + clean(u.name).replace(/\|/g, ' ') + '|' + u.role + '|' + (u.active ? '1' : '0') + '|' + u.salt + '|' + u.hash + '|' + (u.until || ''));
    });
    const text = L.join('\n');
    return text + '\nsig=' + (await sign(privKey, text)) + '\n';
  }
  // the file is accepted by the tool only when it is signed by the paired phone, and the phone key is the one paired
  async function checkPhoneFile(c, pub) {
    if (!c.dkey) return 'not-paired';
    if (c.dkey !== pub) return 'other-phone';
    return 'ok';
  }

  // ---------------------------------------------------------------- GitHub gist
  async function gist(method, id, token, body) {
    const r = await fetch('https://api.github.com/gists' + (id ? '/' + id : ''), {
      method: method,
      headers: { 'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github+json', 'Content-Type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined,
      cache: 'no-store'
    });
    if (!r.ok) {
      let t = ''; try { t = (await r.json()).message || ''; } catch (e) { }
      const err = new Error('GitHub ' + r.status + (t ? ': ' + t : ''));
      err.status = r.status; throw err;
    }
    return r.json();
  }
  async function readGist(id, token) {
    const g = await gist('GET', id, token);
    const f = g.files && g.files[FILE];
    if (!f) throw new Error('الملف ' + FILE + ' غير موجود في هذا الـ Gist');
    let content = f.content;
    if (f.truncated && f.raw_url) content = await (await fetch(f.raw_url, { cache: 'no-store' })).text();
    return content;
  }
  async function writeGist(id, token, raw) {
    const files = {}; files[FILE] = { content: raw };
    return gist('PATCH', id, token, { files: files });
  }

  const PMCore = { b64, unb64, fmt, parseUntil, expired, addDays, newKey, importPriv, importPub, sign, verify, pairingCode,
    seal, unseal, newSalt, hashPwd, parseControl, buildControl, checkPhoneFile, readGist, writeGist, FILE };
  if (typeof module !== 'undefined' && module.exports) module.exports = PMCore; else root.PMCore = PMCore;
})(typeof self !== 'undefined' ? self : globalThis);
