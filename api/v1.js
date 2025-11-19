// api/v1.js
/**
 * v1 unified API (with improved DB error messages and parent_id handling)
 * Make sure environment variables:
 * SUPABASE_URL
 * SUPABASE_SERVICE_KEY  (preferred) OR SUPABASE_KEY
 * JWT_SECRET
 * SMTP_* if you use email OTP
 *
 * This file returns more informative DB error reasons during development.
 */

import nodemailer from 'nodemailer';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { createClient } from '@supabase/supabase-js';
import fetch from 'node-fetch';

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_KEY;

if (!SUPABASE_URL || !SUPABASE_KEY) {
  console.warn('Warning: SUPABASE_URL or SUPABASE_SERVICE_KEY (or SUPABASE_KEY) missing. API will return an explanatory error.');
}

const supabase = createClient(SUPABASE_URL || '', SUPABASE_KEY || '');

function pickRandomSmtp() {
  const count = parseInt(process.env.SMTP_COUNT || '1', 10) || 1;
  const i = Math.floor(Math.random() * count) + 1;
  return {
    host: process.env[`SMTP_${i}_HOST`],
    port: parseInt(process.env[`SMTP_${i}_PORT`] || '587', 10),
    user: process.env[`SMTP_${i}_USER`],
    pass: process.env[`SMTP_${i}_PASS`],
    secure: (process.env[`SMTP_${i}_SECURE`] === 'true')
  };
}

function signJwt(payload, opts = {}) {
  const secret = process.env.JWT_SECRET || 'dev-secret';
  return jwt.sign(payload, secret, { expiresIn: opts.expiresIn || '7d' });
}
function verifyJwt(token) {
  try { const secret = process.env.JWT_SECRET || 'dev-secret'; return jwt.verify(token, secret); } catch (e) { return null; }
}
async function hashOtp(plain) { const salt = await bcrypt.genSalt(10); return bcrypt.hash(plain, salt); }

function cookieSerialize(name, val, options = {}) {
  const parts = []; const encoded = encodeURIComponent(val || ''); parts.push(`${name}=${encoded}`);
  if (options.maxAge) parts.push(`Max-Age=${options.maxAge}`);
  if (options.expires) parts.push(`Expires=${new Date(options.expires).toUTCString()}`);
  if (options.httpOnly !== false) parts.push('HttpOnly');
  if (options.secure) parts.push('Secure');
  if (options.sameSite) parts.push(`SameSite=${options.sameSite}`);
  if (options.path) parts.push(`Path=${options.path}`);
  if (options.domain) parts.push(`Domain=${options.domain}`);
  return parts.join('; ');
}

function corsHeaders(req) {
  const origin = req.headers.origin || '';
  const headers = {
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type,Authorization'
  };
  headers['Access-Control-Allow-Origin'] = origin || '*';
  return headers;
}
function parseCookie(cookieHeader = '') {
  const obj = {}; cookieHeader.split(';').forEach(pair => {
    const [k, ...rest] = pair.trim().split('='); if (!k) return; obj[k] = decodeURIComponent(rest.join('=') || '');
  }); return obj;
}

function jsonResponse(res, status, body) { res.statusCode = status; res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify(body)); }
function getTokenFromReq(req) {
  const cookies = parseCookie(req.headers.cookie || '');
  if (cookies.token) return cookies.token;
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) return req.headers.authorization.slice(7);
  return null;
}
async function getJson(req) {
  return new Promise(resolve => {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try { resolve(body ? JSON.parse(body) : {}); } catch (e) { resolve({}); }
    });
  });
}

export default async function handler(req, res) {
  if (req.method === 'OPTIONS') { const headers = corsHeaders(req); res.writeHead(204, headers); return res.end(); }
  const headers = corsHeaders(req); Object.entries(headers).forEach(([k,v])=>res.setHeader(k,v));

  const url = new URL(req.url, 'http://x');
  const parts = url.pathname.split('/').filter(Boolean);
  const route = parts.slice(2).join('/') || (url.searchParams.get('action') || '');

  try {
    if (req.method === 'POST' && (route === 'send-otp' || route === 'send_otp')) return handleSendOtp(req,res);
    if (req.method === 'POST' && (route === 'verify-otp' || route === 'verify_otp')) return handleVerifyOtp(req,res);
    if (req.method === 'POST' && (route === 'login-password' || route === 'login_password')) return handleLoginPassword(req,res);
    if (req.method === 'POST' && route === 'set-password') return handleSetPassword(req,res);
    if (req.method === 'POST' && route === 'reset-password') return handleResetPassword(req,res);
    if (req.method === 'POST' && route === 'guest-create') return handleGuestCreate(req,res);
    if (req.method === 'GET' && route === 'me') return handleMe(req,res);
    if (req.method === 'POST' && route === 'logout') return handleLogout(req,res);
    if (req.method === 'GET' && route === 'messages') return handleGetMessages(req,res);
    if (req.method === 'POST' && route === 'messages') return handlePostMessage(req,res);
    if (req.method === 'PUT' && route === 'messages') return handleMessageAction(req,res);
    if (req.method === 'POST' && route === 'bind-qq') return handleBindQQ(req,res);
    if (req.method === 'POST' && route === 'unbind-qq') return handleUnbindQQ(req,res);
    if (req.method === 'POST' && route === 'update-profile') return handleUpdateProfile(req,res);
    if (route.startsWith('admin/')) {
      const sub = route.replace(/^admin\//,'');
      if (req.method === 'GET' && sub === 'users') return adminListUsers(req,res);
      if (req.method === 'POST' && sub === 'users') return adminModifyUser(req,res);
    }
    return jsonResponse(res,404,{ error:'not found', route });
  } catch (err) {
    console.error('v1 top handler err', err);
    return jsonResponse(res,500,{ error:'server error', reason: (err && err.message) ? err.message : String(err) });
  }
}

/* ----------------- handlers ----------------- */

async function handleSendOtp(req,res) {
  if (req.method !== 'POST') return jsonResponse(res,405,{ error:'method' });
  const body = await getJson(req); const email = (body && body.email) || '';
  if (!email) return jsonResponse(res,400,{ error:'missing email' });
  const otp = (Math.floor(100000 + Math.random()*900000)).toString();
  const otpExpiresMin = parseInt(process.env.OTP_EXPIRES_MINUTES || '10',10);
  const expiresAt = new Date(Date.now() + otpExpiresMin*60*1000).toISOString();
  const otpHash = await hashOtp(otp);
  const { error } = await supabase.from('otps').insert([{ email, otp_hash: otpHash, purpose:'login', expires_at: expiresAt }]);
  if (error) { console.error('insert otp err', error); return jsonResponse(res,500,{ error:'db error', reason: error.message || error }); }
  const smtp = pickRandomSmtp();
  if (!smtp || !smtp.host || !smtp.user || !smtp.pass) { console.warn('smtp incomplete', smtp); console.log('OTP (dev):', otp); return jsonResponse(res,200,{ ok:true, note:'smtp missing, otp printed to server logs' }); }
  const transporter = nodemailer.createTransport({ host:smtp.host, port:smtp.port||587, secure: !!smtp.secure, auth:{user:smtp.user, pass:smtp.pass} });
  const mailOptions = { from: smtp.user, to: email, subject:'【留言板】验证码', text:`你的验证码：${otp}，有效 ${otpExpiresMin} 分钟。`, html:`<p>你的验证码：<strong>${otp}</strong></p>` };
  try { await transporter.sendMail(mailOptions); return jsonResponse(res,200,{ ok:true }); } catch (err) { console.error('sendMail err', err); return jsonResponse(res,500,{ error:'send failed', reason: err.message || String(err) }); }
}

async function handleVerifyOtp(req,res) {
  if (req.method !== 'POST') return jsonResponse(res,405,{ error:'method' });
  const body = await getJson(req); const email = body && body.email; const otp = body && body.otp;
  if (!email || !otp) return jsonResponse(res,400,{ error:'missing' });
  const now = new Date().toISOString();
  const { data, error } = await supabase.from('otps').select('*').eq('email', email).eq('used', false).gt('expires_at', now).order('created_at',{ascending:false}).limit(10);
  if (error) { console.error('otps select err', error); return jsonResponse(res,500,{ error:'db error', reason: error.message || error }); }
  if (!data || data.length === 0) return jsonResponse(res,400,{ error:'no valid otp' });
  let matched = null;
  for (const row of data) { if (await bcrypt.compare(otp, row.otp_hash)) { matched = row; break; } }
  if (!matched) return jsonResponse(res,400,{ error:'invalid otp' });
  await supabase.from('otps').update({ used:true }).eq('id', matched.id);
  const { data: udata } = await supabase.from('users').select('*').eq('email', email).limit(1);
  let user = udata && udata[0];
  if (!user) { const { data: ins, error: insErr } = await supabase.from('users').insert([{ email }]).select().single(); if (insErr) { console.error('create user err', insErr); return jsonResponse(res,500,{ error:'db error', reason: insErr.message || insErr }); } user = ins; }
  const token = signJwt({ user_id: user.id, email: user.email });
  const isProd = (process.env.NODE_ENV === 'production');
  const cookie = cookieSerialize('token', token, { maxAge:7*24*3600, httpOnly:true, secure:isProd, sameSite:'None', path:'/' });
  res.setHeader('Set-Cookie', cookie);
  return jsonResponse(res,200,{ ok:true, email: user.email });
}

async function handleLoginPassword(req,res) {
  if (req.method !== 'POST') return jsonResponse(res,405,{ error:'method' });
  const body = await getJson(req); const email = body && body.email; const password = body && body.password;
  if (!email || !password) return jsonResponse(res,400,{ error:'missing' });
  const { data } = await supabase.from('users').select('id,email,password_hash,is_banned').eq('email', email).limit(1);
  if (!data || data.length === 0) return jsonResponse(res,401,{ error:'invalid credentials' });
  const user = data[0]; if (user.is_banned) return jsonResponse(res,403,{ error:'banned' });
  if (!user.password_hash) return jsonResponse(res,400,{ error:'password not set' });
  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return jsonResponse(res,401,{ error:'invalid credentials' });
  const token = signJwt({ user_id: user.id, email: user.email });
  const isProd = (process.env.NODE_ENV === 'production');
  const cookie = cookieSerialize('token', token, { maxAge:7*24*3600, httpOnly:true, secure:isProd, sameSite:'None', path:'/' });
  res.setHeader('Set-Cookie', cookie);
  return jsonResponse(res,200,{ ok:true });
}

async function handleSetPassword(req,res) {
  if (req.method !== 'POST') return jsonResponse(res,405,{ error:'method' });
  const body = await getJson(req);
  const token = getTokenFromReq(req); if (!token) return jsonResponse(res,401,{ error:'not authenticated' });
  const payload = verifyJwt(token); if (!payload) return jsonResponse(res,401,{ error:'invalid token' });
  const { oldPassword, newPassword } = body || {};
  if (!newPassword || newPassword.length < 6) return jsonResponse(res,400,{ error:'password too short' });
  if (!/^[A-Za-z0-9]{6,}$/.test(newPassword)) return jsonResponse(res,400,{ error:'password invalid (letters+digits only, min 6)' });
  const { data } = await supabase.from('users').select('password_hash').eq('id', payload.user_id).limit(1);
  const user = data && data[0];
  if (user && user.password_hash) {
    if (!oldPassword) return jsonResponse(res,400,{ error:'old password required' });
    const ok = await bcrypt.compare(oldPassword, user.password_hash);
    if (!ok) return jsonResponse(res,401,{ error:'old password wrong' });
  }
  const newHash = await bcrypt.hash(newPassword, 10);
  const { error } = await supabase.from('users').update({ password_hash: newHash }).eq('id', payload.user_id);
  if (error) { console.error('set-password update err', error); return jsonResponse(res,500,{ error:'db error', reason: error.message || error }); }
  return jsonResponse(res,200,{ ok:true });
}

async function handleResetPassword(req,res) {
  if (req.method !== 'POST') return jsonResponse(res,405,{ error:'method' });
  const body = await getJson(req);
  const { email, otp, newPassword } = body || {};
  if (!email || !otp || !newPassword) return jsonResponse(res,400,{ error:'missing' });
  if (!/^[A-Za-z0-9]{6,}$/.test(newPassword)) return jsonResponse(res,400,{ error:'password invalid (letters+digits, >=6)' });
  const now = new Date().toISOString();
  const { data, error } = await supabase.from('otps').select('*').eq('email', email).eq('used', false).gt('expires_at', now).order('created_at',{ascending:false}).limit(10);
  if (error) return jsonResponse(res,500,{ error:'db error', reason: error.message || error });
  let matched = null;
  for (const row of data) { if (await bcrypt.compare(otp, row.otp_hash)) { matched = row; break; } }
  if (!matched) return jsonResponse(res,400,{ error:'invalid otp' });
  await supabase.from('otps').update({ used:true }).eq('id', matched.id);
  let { data: udata } = await supabase.from('users').select('*').eq('email', email).limit(1);
  let user = udata && udata[0];
  if (!user) { const { data: ins, error: insErr } = await supabase.from('users').insert([{ email }]).select().single(); if (insErr) return jsonResponse(res,500,{ error:'db error', reason: insErr.message || insErr }); user = ins; }
  const hash = await bcrypt.hash(newPassword, 10);
  await supabase.from('users').update({ password_hash: hash }).eq('id', user.id);
  return jsonResponse(res,200,{ ok:true });
}

async function handleGuestCreate(req,res) {
  if (req.method !== 'POST') return jsonResponse(res,405,{ error:'method' });
  const crypto = await import('crypto');
  const guestKey = 'guest_' + crypto.randomBytes(8).toString('hex');
  const cookie = cookieSerialize('guest_id', guestKey, { maxAge:24*3600, httpOnly:false, secure: process.env.NODE_ENV === 'production', sameSite:'Lax', path:'/' });
  res.setHeader('Set-Cookie', cookie);
  try { await supabase.from('guest_posts').insert([{ guest_key: guestKey }]); } catch(e){}
  return jsonResponse(res,200,{ ok:true, guest_id: guestKey });
}

async function handleMe(req,res) {
  if (req.method !== 'GET') return jsonResponse(res,405,{ error:'method' });
  const token = getTokenFromReq(req); if (!token) return jsonResponse(res,401,{ error:'not authenticated' });
  const payload = verifyJwt(token); if (!payload) return jsonResponse(res,401,{ error:'invalid token' });
  const { data } = await supabase.from('users').select('id,email,display_name,qq_id,qq_name,qq_avatar,role,is_banned').eq('id', payload.user_id).limit(1);
  if (!data || data.length === 0) return jsonResponse(res,200,{ email: payload.email });
  const u = data[0];
  return jsonResponse(res,200,{ id:u.id,email:u.email,display_name:u.display_name,qq_id:u.qq_id,qq_name:u.qq_name,qq_avatar:u.qq_avatar,role:u.role,is_banned:u.is_banned });
}

async function handleLogout(req,res) {
  const cookie = cookieSerialize('token','',{ maxAge:0, httpOnly:true, secure: process.env.NODE_ENV === 'production', sameSite:'None', path:'/' });
  res.setHeader('Set-Cookie', cookie);
  return jsonResponse(res,200,{ ok:true });
}

async function handleGetMessages(req,res) {
  if (req.method !== 'GET') return jsonResponse(res,405,{ error:'method' });
  const url = new URL(req.url, 'http://x');
  const limit = parseInt(url.searchParams.get('limit') || '50', 10);
  try {
    const { data, error } = await supabase.from('messages').select('*').order('created_at',{ascending:false}).limit(limit);
    if (error) { console.error('messages get error', error); return jsonResponse(res,500,{ error:'db error', reason: error.message || error }); }
    const enriched = await Promise.all((data||[]).map(async m => {
      if (m.user_id) {
        const { data: ud } = await supabase.from('users').select('qq_id,qq_name,qq_avatar,display_name').eq('id', m.user_id).limit(1);
        if (ud && ud[0]) return { ...m, qq_id: ud[0].qq_id, qq_name: ud[0].qq_name, qq_avatar: ud[0].qq_avatar, display_name: ud[0].display_name };
      }
      return m;
    }));
    return jsonResponse(res,200,enriched);
  } catch (e) { console.error('messages get err', e); return jsonResponse(res,500,{ error:'server error', reason: e.message || String(e) }); }
}

async function handlePostMessage(req,res) {
  if (req.method !== 'POST') return jsonResponse(res,405,{ error:'method' });
  const body = await getJson(req);
  const content = (body && (body.content || body.text || '')).toString().trim();
  // normalize parent_id: empty string -> null; ensure integer if present
  let parent_id = (body && body.parent_id) || null;
  if (parent_id === '' || parent_id === 'null') parent_id = null;
  if (parent_id !== null) {
    const n = parseInt(parent_id, 10);
    parent_id = Number.isNaN(n) ? null : n;
  }
  const device_model = (body && body.device_model) || null;
  const network = (body && body.network) || null;
  if (!content) return jsonResponse(res,400,{ error:'content required' });

  const cookieHeader = req.headers.cookie || '';
  const cookies = parseCookie(cookieHeader);
  let userId = null, email = null, isGuest = false, guestKey = null;
  const token = cookies.token || (req.headers.authorization && req.headers.authorization.startsWith('Bearer ') ? req.headers.authorization.slice(7) : null);
  if (token) {
    const payload = verifyJwt(token);
    if (!payload) return jsonResponse(res,401,{ error:'invalid token' });
    userId = payload.user_id; email = payload.email;
    try { const { data: u } = await supabase.from('users').select('is_banned').eq('id', userId).limit(1).single(); if (u && u.is_banned) return jsonResponse(res,403,{ error:'banned' }); } catch(e){}
  } else {
    guestKey = cookies.guest_id || req.headers['x-guest-key'] || null;
    if (!guestKey) return jsonResponse(res,401,{ error:'guest not initialized' });
    isGuest = true;
    try {
      const todayStart = new Date(); todayStart.setHours(0,0,0,0);
      const { count, error } = await supabase.from('messages').select('id',{ count: 'exact' }).eq('is_guest', true).eq('email', guestKey).gte('created_at', todayStart.toISOString());
      const limit = parseInt(process.env.GUEST_DAILY_LIMIT || '5', 10);
      if (error) console.warn('guest count err', error);
      if (typeof count === 'number' && count >= limit) return jsonResponse(res,403,{ error:'guest limit reached' });
    } catch(e) {}
  }

  const ip = (req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || req.socket.remoteAddress || '').split(',')[0].trim();
  const ua = req.headers['user-agent'] || '';
  let ip_location = '';
  try {
    if (ip && ip !== '::1' && !ip.startsWith('127.')) {
      const geoRes = await fetch(`http://ip-api.com/json/${ip}?fields=status,country,regionName,city`);
      const geo = await geoRes.json();
      if (geo && geo.status === 'success') ip_location = `${geo.country||''} ${geo.regionName||''} ${geo.city||''}`.trim();
    }
  } catch (e) { console.warn('geo error', e); }

  const insertObj = {
    content, parent_id,
    user_id: userId,
    email: userId ? email : guestKey,
    is_guest: isGuest,
    ip, ip_location, device: device_model, network
  };

  try {
    const { data, error } = await supabase.from('messages').insert([insertObj]).select().single();
    if (error) { console.error('messages insert err', error); return jsonResponse(res,500,{ error:'db error', reason: error.message || error }); }
    try { await supabase.from('message_audit').insert([{ message_id: data.id, action:'created', actor_user_id: userId }]); } catch(e){}
    return jsonResponse(res,200,{ ok:true, message: data });
  } catch (err) { console.error('messages post err', err); return jsonResponse(res,500,{ error:'server error', reason: err.message || String(err) }); }
}

async function handleMessageAction(req,res) {
  if (req.method !== 'PUT') return jsonResponse(res,405,{ error:'method' });
  const url = new URL(req.url, 'http://x'); const action = url.searchParams.get('action'); const id = url.searchParams.get('id');
  if (!id) return jsonResponse(res,400,{ error:'missing id' });
  const token = getTokenFromReq(req); const payload = token ? verifyJwt(token) : null;
  try {
    const { data: msg } = await supabase.from('messages').select('*').eq('id', id).limit(1).single();
    if (!msg) return jsonResponse(res,404,{ error:'message not found' });
    const isAuthor = payload && payload.user_id && msg.user_id === payload.user_id;
    let isAdmin = false;
    if (payload) { const { data: u } = await supabase.from('users').select('role').eq('id', payload.user_id).limit(1).single(); isAdmin = u && u.role === 'admin'; }
    if (action === 'undo') {
      const canUndo = isAdmin || (isAuthor && (new Date() - new Date(msg.created_at) <= 30*60*1000));
      if (!canUndo) return jsonResponse(res,403,{ error:'forbidden' });
      const { error } = await supabase.from('messages').update({ deleted:true, deleted_at:new Date().toISOString(), deleted_by: payload ? payload.user_id : null }).eq('id', id);
      if (error) return jsonResponse(res,500,{ error:'db error', reason: error.message || error });
      return jsonResponse(res,200,{ ok:true });
    } else if (action === 'restore') {
      const canRestore = isAdmin || isAuthor;
      if (!canRestore) return jsonResponse(res,403,{ error:'forbidden' });
      const { error } = await supabase.from('messages').update({ deleted:false, restored:true, deleted_at:null, deleted_by:null }).eq('id', id);
      if (error) return jsonResponse(res,500,{ error:'db error', reason: error.message || error });
      return jsonResponse(res,200,{ ok:true });
    } else {
      return jsonResponse(res,400,{ error:'unknown action' });
    }
  } catch (err) { console.error(err); return jsonResponse(res,500,{ error:'server error', reason: err.message || String(err) }); }
}

async function handleBindQQ(req,res) {
  if (req.method !== 'POST') return jsonResponse(res,405,{ error:'method' });
  const token = getTokenFromReq(req); if (!token) return jsonResponse(res,401,{ error:'not authenticated' });
  const payload = verifyJwt(token); if (!payload) return jsonResponse(res,401,{ error:'invalid token' });
  const body = await getJson(req); const qq = body && (body.qq || body.qq_id || body.qqId);
  if (!qq) return jsonResponse(res,400,{ error:'missing qq' });
  try {
    const endpoint = `https://r.qzone.qq.com/fcg-bin/cgi_get_portrait.fcg?uins=${qq}`;
    const r = await fetch(endpoint); const txt = await r.text();
    let nickname = '';
    try { const s = txt.indexOf('('); const e = txt.lastIndexOf(')'); const inner = txt.substring(s+1,e); const obj = JSON.parse(inner); const key = Object.keys(obj)[0]; const arr = obj[key]; nickname = Array.isArray(arr) && arr.length>0 ? (arr[6] || arr[0] || '') : ''; } catch(e) { nickname=''; }
    const avatar = `https://q1.qlogo.cn/g?b=qq&nk=${qq}&s=640`;
    const { error } = await supabase.from('users').update({ qq_id: qq, qq_name: nickname, qq_avatar: avatar }).eq('id', payload.user_id);
    if (error) return jsonResponse(res,500,{ error:'db error', reason: error.message || error });
    return jsonResponse(res,200,{ ok:true, qq, qq_name: nickname, qq_avatar: avatar });
  } catch (err) { console.error(err); return jsonResponse(res,500,{ error:'server error', reason: err.message || String(err) }); }
}

async function handleUnbindQQ(req,res) {
  if (req.method !== 'POST') return jsonResponse(res,405,{ error:'method' });
  const token = getTokenFromReq(req); if (!token) return jsonResponse(res,401,{ error:'not authenticated' });
  const payload = verifyJwt(token); if (!payload) return jsonResponse(res,401,{ error:'invalid token' });
  try { const { error } = await supabase.from('users').update({ qq_id: null, qq_name: null, qq_avatar: null }).eq('id', payload.user_id); if (error) return jsonResponse(res,500,{ error:'db error', reason: error.message || error }); return jsonResponse(res,200,{ ok:true }); } catch (e) { console.error(e); return jsonResponse(res,500,{ error:'server error', reason: e.message || String(e) }); }
}

async function handleUpdateProfile(req,res) {
  if (req.method !== 'POST') return jsonResponse(res,405,{ error:'method' });
  const token = getTokenFromReq(req); if (!token) return jsonResponse(res,401,{ error:'not authenticated' });
  const payload = verifyJwt(token); if (!payload) return jsonResponse(res,401,{ error:'invalid token' });
  const body = await getJson(req); const update = {};
  if (typeof body.display_name !== 'undefined') update.display_name = body.display_name || null;
  if (typeof body.email !== 'undefined') update.email = body.email || null;
  try { const { error } = await supabase.from('users').update(update).eq('id', payload.user_id); if (error) return jsonResponse(res,500,{ error:'db error', reason: error.message || error }); return jsonResponse(res,200,{ ok:true }); } catch(e) { console.error(e); return jsonResponse(res,500,{ error:'server error', reason: e.message || String(e) }); }
}

/* admin handlers omitted for brevity (unchanged) — keep the earlier admin functions from your previous v1.js if you had them */
async function adminListUsers(req,res) {
  const token = getTokenFromReq(req); if (!token) return jsonResponse(res,401,{ error:'not authenticated' });
  const me = verifyJwt(token); if (!me) return jsonResponse(res,401,{ error:'invalid token' });
  const { data: u } = await supabase.from('users').select('role').eq('id', me.user_id).limit(1).single();
  if (!u || u.role !== 'admin') return jsonResponse(res,403,{ error:'admin only' });
  const { data, error } = await supabase.from('users').select('id,email,qq_id,qq_name,qq_avatar,role,is_banned,created_at').order('created_at',{ascending:false}).limit(200);
  if (error) return jsonResponse(res,500,{ error:'db error', reason: error.message || error });
  return jsonResponse(res,200,data);
}

async function adminModifyUser(req,res) {
  const token = getTokenFromReq(req); if (!token) return jsonResponse(res,401,{ error:'not authenticated' });
  const me = verifyJwt(token); if (!me) return jsonResponse(res,401,{ error:'invalid token' });
  const { data: u } = await supabase.from('users').select('role').eq('id', me.user_id).limit(1).single();
  if (!u || u.role !== 'admin') return jsonResponse(res,403,{ error:'admin only' });
  const body = await getJson(req); const { action } = body || {}; let user_id = body.user_id || null;
  if (!user_id && body.lookup_email) { const { data } = await supabase.from('users').select('id').eq('email', body.lookup_email).limit(1); if (data && data[0]) user_id = data[0].id; }
  if (!user_id && body.lookup_qq) { const { data } = await supabase.from('users').select('id').eq('qq_id', body.lookup_qq).limit(1); if (data && data[0]) user_id = data[0].id; }
  if (!action || !user_id) return jsonResponse(res,400,{ error:'missing' });
  if (action === 'ban') { const { error } = await supabase.from('users').update({ is_banned:true }).eq('id', user_id); if (error) return jsonResponse(res,500,{ error:'db error', reason: error.message || error }); return jsonResponse(res,200,{ ok:true }); }
  else if (action === 'unban') { const { error } = await supabase.from('users').update({ is_banned:false }).eq('id', user_id); if (error) return jsonResponse(res,500,{ error:'db error', reason: error.message || error }); return jsonResponse(res,200,{ ok:true }); }
  else if (action === 'set-admin') { const make_admin = !!body.make_admin; const { error } = await supabase.from('users').update({ role: make_admin ? 'admin' : 'user' }).eq('id', user_id); if (error) return jsonResponse(res,500,{ error:'db error', reason: error.message || error }); return jsonResponse(res,200,{ ok:true }); }
  else return jsonResponse(res,400,{ error:'unknown action' });
}
