const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { URL } = require('node:url');

const PORT = Number(process.env.PORT || 3000);
const ROOT = __dirname;
const PUBLIC = path.join(ROOT, 'public');
const DATA_DIR = path.join(ROOT, 'data');
const DATA_FILE = process.env.DATA_FILE || path.join(DATA_DIR, 'db.json');
const SESSION_DAYS = 30;
const appSecret = process.env.APP_SECRET || 'troque-esta-chave-antes-de-publicar';
const encryptionKey = crypto.scryptSync(process.env.APP_ENCRYPTION_KEY || appSecret, 'conversa-crm-v1', 32);

function initialDb() {
  return { users: [], tenants: [], sessions: [], integrations: [], contacts: [], messages: [], auditLog: [] };
}

function loadDb() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(DATA_FILE)) return initialDb();
  try { return { ...initialDb(), ...JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')) }; }
  catch { throw new Error('O banco local nao pode ser lido. Restaure data/db.json a partir de um backup.'); }
}

let db = loadDb();
function saveDb() {
  const temporary = `${DATA_FILE}.tmp`;
  fs.writeFileSync(temporary, JSON.stringify(db, null, 2), { mode: 0o600 });
  fs.renameSync(temporary, DATA_FILE);
}
function ensurePlatformAdmin() {
  const email = safeText(process.env.PLATFORM_ADMIN_EMAIL, 180).toLowerCase();
  const password = String(process.env.PLATFORM_ADMIN_PASSWORD || '');
  if (!email || password.length < 8) return;
  const existing = db.users.find(item => item.email === email);
  if (existing) { if (existing.role !== 'platform_admin') { existing.role = 'platform_admin'; existing.tenantId = null; saveDb(); } return; }
  db.users.push({ id: id('user'), tenantId: null, name: safeText(process.env.PLATFORM_ADMIN_NAME, 120) || 'Administrador da plataforma', email, passwordHash: hashPassword(password), role: 'platform_admin', createdAt: now() });
  saveDb();
}
function id(prefix) { return `${prefix}_${crypto.randomBytes(12).toString('hex')}`; }
function now() { return new Date().toISOString(); }
function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  return `${salt}:${crypto.scryptSync(password, salt, 64).toString('hex')}`;
}
ensurePlatformAdmin();
function passwordMatches(password, stored) {
  const [salt, key] = String(stored).split(':');
  if (!salt || !key) return false;
  const calculated = crypto.scryptSync(password, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(key, 'hex'), Buffer.from(calculated, 'hex'));
}
function encrypt(value) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey, iv);
  const encrypted = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
  return [iv.toString('base64url'), cipher.getAuthTag().toString('base64url'), encrypted.toString('base64url')].join('.');
}
function decrypt(value) {
  if (!value) return {};
  const [ivText, tagText, encryptedText] = String(value).split('.');
  const decipher = crypto.createDecipheriv('aes-256-gcm', encryptionKey, Buffer.from(ivText, 'base64url'));
  decipher.setAuthTag(Buffer.from(tagText, 'base64url'));
  return JSON.parse(Buffer.concat([decipher.update(Buffer.from(encryptedText, 'base64url')), decipher.final()]).toString('utf8'));
}
function metaSignatureIsValid(raw, signature) {
  const appSecret = process.env.META_APP_SECRET;
  if (!appSecret) return true;
  const expected = `sha256=${crypto.createHmac('sha256', appSecret).update(raw).digest('hex')}`;
  if (!signature || signature.length !== expected.length) return false;
  return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
}
function safeSignatureMatch(expected, supplied) {
  if (!supplied || supplied.length !== expected.length) return false;
  return crypto.timingSafeEqual(Buffer.from(supplied), Buffer.from(expected));
}
function twilioSignatureIsValid(req, body, integration) {
  const publicUrl = process.env.PUBLIC_URL;
  if (!publicUrl) return true;
  const token = decrypt(integration.secrets).authToken;
  const signedUrl = `${publicUrl.replace(/\/$/, '')}${req.url}`;
  const values = Object.keys(body).sort().map(key => `${key}${body[key]}`).join('');
  const expected = crypto.createHmac('sha1', token).update(`${signedUrl}${values}`).digest('base64');
  return safeSignatureMatch(expected, req.headers['x-twilio-signature']);
}
function resendSignatureIsValid(raw, headers, webhookSecret) {
  if (!webhookSecret) return true;
  const messageId = headers['svix-id']; const timestamp = headers['svix-timestamp']; const signed = headers['svix-signature'];
  if (!messageId || !timestamp || !signed || Math.abs(Date.now() / 1000 - Number(timestamp)) > 300) return false;
  const secret = String(webhookSecret).replace(/^whsec_/, '');
  let key; try { key = Buffer.from(secret, 'base64'); } catch { return false; }
  const expected = crypto.createHmac('sha256', key).update(`${messageId}.${timestamp}.${raw}`).digest('base64');
  return String(signed).split(' ').some(part => { const [, value] = part.split(','); return value ? safeSignatureMatch(expected, value) : false; });
}
function cookies(req) {
  return Object.fromEntries(String(req.headers.cookie || '').split(';').map(part => {
    const cut = part.indexOf('=');
    return cut < 0 ? [] : [part.slice(0, cut).trim(), decodeURIComponent(part.slice(cut + 1).trim())];
  }).filter(pair => pair.length));
}
function send(res, status, data, headers = {}) {
  const body = typeof data === 'string' || Buffer.isBuffer(data) ? data : JSON.stringify(data);
  res.writeHead(status, { 'content-type': typeof data === 'string' || Buffer.isBuffer(data) ? 'text/plain; charset=utf-8' : 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers });
  res.end(body);
}
function json(res, status, data, headers) { send(res, status, data, headers); }
function bad(res, message, status = 400) { json(res, status, { error: message }); }
function safeText(value, max = 5000) { return String(value || '').trim().slice(0, max); }
async function readBody(req) {
  const chunks = []; let size = 0;
  for await (const chunk of req) { size += chunk.length; if (size > 1024 * 1024) throw new Error('Solicitacao muito grande.'); chunks.push(chunk); }
  const raw = Buffer.concat(chunks).toString('utf8');
  if (!raw) return {};
  let body;
  if ((req.headers['content-type'] || '').includes('application/x-www-form-urlencoded')) body = Object.fromEntries(new URLSearchParams(raw));
  else { try { body = JSON.parse(raw); } catch { throw new Error('JSON invalido.'); } }
  if (!body || typeof body !== 'object') throw new Error('O corpo da solicitacao deve ser um objeto JSON.');
  Object.defineProperty(body, '_rawBody', { value: raw, enumerable: false });
  return body;
}
function sessionFor(req) {
  const sessionId = cookies(req).conversa_session;
  const session = db.sessions.find(item => item.id === sessionId && new Date(item.expiresAt) > new Date());
  if (!session) return null;
  const user = db.users.find(item => item.id === session.userId);
  if (user?.role === 'platform_admin') return { session, user, admin: true };
  const tenant = user && db.tenants.find(item => item.id === user.tenantId);
  return user && tenant ? { session, user, tenant } : null;
}
function requireSession(req, res) {
  const active = sessionFor(req);
  if (!active) { bad(res, 'Sua sessao expirou. Entre novamente.', 401); return null; }
  if (active.admin) { bad(res, 'Esta area e exclusiva para contas de cliente.', 403); return null; }
  if (active.tenant.status && active.tenant.status !== 'active') { bad(res, 'O acesso desta empresa esta suspenso. Fale com o administrador da plataforma.', 403); return null; }
  return active;
}
function requirePlatformAdmin(req, res) {
  const active = sessionFor(req);
  if (!active?.admin) { bad(res, 'Acesso restrito ao administrador da plataforma.', 403); return null; }
  return active;
}
function createSession(res, user) {
  const session = { id: id('sess'), userId: user.id, expiresAt: new Date(Date.now() + SESSION_DAYS * 86400000).toISOString(), createdAt: now() };
  db.sessions = db.sessions.filter(item => item.userId !== user.id || new Date(item.expiresAt) > new Date());
  db.sessions.push(session); saveDb();
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  return { 'set-cookie': `conversa_session=${session.id}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_DAYS * 86400}${secure}` };
}
function endSession(req) {
  const sessionId = cookies(req).conversa_session;
  db.sessions = db.sessions.filter(item => item.id !== sessionId); saveDb();
}
function safeIntegration(item) {
  const { secrets, ...publicData } = item;
  return { ...publicData, connected: Boolean(item.connectedAt), credentialConfigured: Boolean(secrets) };
}
function tenantIntegrations(tenantId) { return db.integrations.filter(item => item.tenantId === tenantId); }
function getIntegration(tenantId, type) { return tenantIntegrations(tenantId).find(item => item.type === type && item.enabled); }
function seedWelcome(tenantId) {
  if (db.contacts.some(item => item.tenantId === tenantId)) return;
  const contact = { id: id('contact'), tenantId, name: 'Mariana Costa', phone: '+5511999184027', email: 'mariana@example.com', tags: ['Lead quente'], createdAt: now() };
  db.contacts.push(contact);
  db.messages.push({ id: id('msg'), tenantId, contactId: contact.id, direction: 'inbound', channel: 'whatsapp', content: 'Olá! Queria entender os planos disponíveis.', status: 'received', createdAt: now() });
  saveDb();
}
function overview(tenantId) {
  seedWelcome(tenantId);
  const messages = db.messages.filter(item => item.tenantId === tenantId).sort((a, b) => a.createdAt.localeCompare(b.createdAt));
  const contacts = db.contacts.filter(item => item.tenantId === tenantId);
  return { contacts, messages: messages.slice(-100), integrations: tenantIntegrations(tenantId).map(safeIntegration), metrics: { openConversations: Math.max(1, contacts.length), contacts: contacts.length, sentToday: messages.filter(item => item.direction === 'outbound' && item.createdAt.slice(0, 10) === now().slice(0, 10)).length } };
}
function adminTenantList() {
  return db.tenants.map(tenant => {
    const owner = db.users.find(user => user.tenantId === tenant.id && user.role === 'owner');
    const integrations = tenantIntegrations(tenant.id);
    const messages = db.messages.filter(message => message.tenantId === tenant.id);
    return { id: tenant.id, name: tenant.name, status: tenant.status || 'active', createdAt: tenant.createdAt, suspendedAt: tenant.suspendedAt || null, suspensionReason: tenant.suspensionReason || null, owner: owner ? { name: owner.name, email: owner.email } : null, channels: integrations.map(channel => channel.type), contacts: db.contacts.filter(contact => contact.tenantId === tenant.id).length, messages: messages.length, lastActivityAt: messages.at(-1)?.createdAt || null };
  }).sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}
function audit(actorId, action, tenantId, details = {}) {
  db.auditLog.push({ id: id('audit'), actorId, action, tenantId, details, createdAt: now() });
  db.auditLog = db.auditLog.slice(-1000);
}
async function sendWhatsapp(integration, recipient, content) {
  const secret = decrypt(integration.secrets);
  if (!secret.accessToken || !integration.phoneNumberId) throw new Error('Informe o token permanente e o ID do numero do WhatsApp.');
  const version = integration.graphVersion || 'v23.0';
  const response = await fetch(`https://graph.facebook.com/${version}/${encodeURIComponent(integration.phoneNumberId)}/messages`, { method: 'POST', headers: { authorization: `Bearer ${secret.accessToken}`, 'content-type': 'application/json' }, body: JSON.stringify({ messaging_product: 'whatsapp', to: recipient.replace(/\D/g, ''), type: 'text', text: { body: content } }) });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload?.error?.message || 'A Meta recusou o envio da mensagem.');
  return payload;
}
async function sendEmail(integration, recipient, content, subject) {
  const secret = decrypt(integration.secrets);
  if (!secret.apiKey || !integration.fromEmail) throw new Error('Informe a chave da Resend e o e-mail remetente.');
  const response = await fetch('https://api.resend.com/emails', { method: 'POST', headers: { authorization: `Bearer ${secret.apiKey}`, 'content-type': 'application/json' }, body: JSON.stringify({ from: integration.fromEmail, to: [recipient], subject: subject || 'Nova mensagem', text: content }) });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload?.message || 'O provedor de e-mail recusou o envio.');
  return payload;
}
async function sendSms(integration, recipient, content) {
  const secret = decrypt(integration.secrets);
  if (!secret.accountSid || !secret.authToken || !integration.fromNumber) throw new Error('Informe Account SID, Auth Token e numero remetente da Twilio.');
  const basic = Buffer.from(`${secret.accountSid}:${secret.authToken}`).toString('base64');
  const response = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${encodeURIComponent(secret.accountSid)}/Messages.json`, { method: 'POST', headers: { authorization: `Basic ${basic}`, 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ To: recipient, From: integration.fromNumber, Body: content }).toString() });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload?.message || 'A Twilio recusou o envio.');
  return payload;
}
function findOrCreateContact(tenantId, fields) {
  const phone = safeText(fields.phone, 32); const email = safeText(fields.email, 180).toLowerCase();
  let contact = db.contacts.find(item => item.tenantId === tenantId && ((phone && item.phone === phone) || (email && item.email === email)));
  if (contact) return contact;
  contact = { id: id('contact'), tenantId, name: safeText(fields.name, 120) || phone || email || 'Novo contato', phone, email, tags: [], createdAt: now() };
  db.contacts.push(contact); return contact;
}
function saveInbound(tenantId, channel, fields) {
  if (fields.providerId) { const duplicate = db.messages.find(item => item.tenantId === tenantId && item.providerId === fields.providerId); if (duplicate) return duplicate; }
  const contact = findOrCreateContact(tenantId, fields);
  const message = { id: id('msg'), tenantId, contactId: contact.id, direction: 'inbound', channel, content: safeText(fields.content), subject: safeText(fields.subject, 180), providerId: safeText(fields.providerId, 180), status: 'received', createdAt: now() };
  db.messages.push(message); saveDb(); return message;
}
function contentType(file) { return file.endsWith('.html') ? 'text/html; charset=utf-8' : file.endsWith('.js') ? 'text/javascript; charset=utf-8' : file.endsWith('.css') ? 'text/css; charset=utf-8' : 'application/octet-stream'; }
function staticFile(res, pathname) {
  const requested = pathname === '/' ? '/index.html' : pathname;
  const file = path.normalize(path.join(PUBLIC, requested));
  if (!file.startsWith(PUBLIC) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) return false;
  res.writeHead(200, { 'content-type': contentType(file), 'cache-control': requested.endsWith('.html') ? 'no-store' : 'public, max-age=3600' });
  fs.createReadStream(file).pipe(res); return true;
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = url.pathname;
  try {
    if (req.method === 'GET' && pathname === '/health') return json(res, 200, { ok: true, time: now() });
    if (req.method === 'POST' && pathname === '/api/auth/register') {
      const body = await readBody(req); const name = safeText(body.name, 120); const company = safeText(body.company, 120); const email = safeText(body.email, 180).toLowerCase(); const password = String(body.password || '');
      if (!name || !company || !/^\S+@\S+\.\S+$/.test(email) || password.length < 8) return bad(res, 'Preencha nome, empresa, e-mail valido e uma senha de pelo menos 8 caracteres.');
      if (db.users.some(item => item.email === email)) return bad(res, 'Este e-mail ja possui uma conta. Entre para continuar.', 409);
      const tenant = { id: id('tenant'), name: company, status: 'active', createdAt: now() }; const user = { id: id('user'), tenantId: tenant.id, name, email, passwordHash: hashPassword(password), role: 'owner', createdAt: now() };
      db.tenants.push(tenant); db.users.push(user); saveDb();
      return json(res, 201, { user: { name: user.name, email: user.email }, tenant: { name: tenant.name } }, createSession(res, user));
    }
    if (req.method === 'POST' && pathname === '/api/auth/login') {
      const body = await readBody(req); const email = safeText(body.email, 180).toLowerCase(); const user = db.users.find(item => item.email === email);
      if (!user || !passwordMatches(String(body.password || ''), user.passwordHash)) return bad(res, 'E-mail ou senha incorretos.', 401);
      if (user.role === 'platform_admin') return json(res, 200, { user: { name: user.name, email: user.email, role: user.role }, admin: true }, createSession(res, user));
      const tenant = db.tenants.find(item => item.id === user.tenantId); if (!tenant) return bad(res, 'Conta sem empresa vinculada. Contate o suporte.', 403); if (tenant.status && tenant.status !== 'active') return bad(res, 'O acesso desta empresa esta suspenso. Fale com o administrador da plataforma.', 403); return json(res, 200, { user: { name: user.name, email: user.email, role: user.role }, tenant: { name: tenant.name }, admin: false }, createSession(res, user));
    }
    if (req.method === 'POST' && pathname === '/api/auth/logout') { endSession(req); return json(res, 200, { ok: true }, { 'set-cookie': 'conversa_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0' }); }
    if (req.method === 'GET' && pathname === '/api/session') { const active = sessionFor(req); if (!active) return json(res, 401, { error: 'Nao autenticado.' }); if (active.admin) return json(res, 200, { user: { name: active.user.name, email: active.user.email, role: active.user.role }, admin: true }); return json(res, 200, { user: { name: active.user.name, email: active.user.email, role: active.user.role }, tenant: { name: active.tenant.name, status: active.tenant.status || 'active' }, admin: false }); }
    if (req.method === 'GET' && pathname === '/api/admin/tenants') { const admin = requirePlatformAdmin(req, res); if (!admin) return; return json(res, 200, { tenants: adminTenantList(), audit: db.auditLog.slice(-20).reverse() }); }
    const adminStatusMatch = pathname.match(/^\/api\/admin\/tenants\/([^/]+)\/status$/);
    if (req.method === 'POST' && adminStatusMatch) { const admin = requirePlatformAdmin(req, res); if (!admin) return; const body = await readBody(req); const status = safeText(body.status, 20); if (!['active', 'suspended'].includes(status)) return bad(res, 'Status invalido.'); const tenant = db.tenants.find(item => item.id === adminStatusMatch[1]); if (!tenant) return bad(res, 'Empresa nao encontrada.', 404); tenant.status = status; tenant.suspendedAt = status === 'suspended' ? now() : null; tenant.suspensionReason = status === 'suspended' ? safeText(body.reason, 180) || 'Inadimplencia' : null; if (status === 'suspended') { const tenantUsers = new Set(db.users.filter(user => user.tenantId === tenant.id).map(user => user.id)); db.sessions = db.sessions.filter(session => !tenantUsers.has(session.userId)); } audit(admin.user.id, status === 'suspended' ? 'tenant_suspended' : 'tenant_reactivated', tenant.id, { reason: tenant.suspensionReason }); saveDb(); return json(res, 200, adminTenantList().find(item => item.id === tenant.id)); }
    if (req.method === 'GET' && pathname === '/api/overview') { const active = requireSession(req, res); if (!active) return; return json(res, 200, overview(active.tenant.id)); }
    if (pathname === '/api/integrations' && req.method === 'GET') { const active = requireSession(req, res); if (!active) return; return json(res, 200, tenantIntegrations(active.tenant.id).map(safeIntegration)); }
    if (pathname === '/api/integrations' && req.method === 'POST') {
      const active = requireSession(req, res); if (!active) return; const body = await readBody(req); const type = safeText(body.type, 20); if (!['whatsapp', 'email', 'sms'].includes(type)) return bad(res, 'Canal invalido.');
      const existing = db.integrations.find(item => item.tenantId === active.tenant.id && item.type === type); const integration = existing || { id: id('channel'), tenantId: active.tenant.id, type, createdAt: now() };
      const publicFields = type === 'whatsapp' ? { displayName: safeText(body.displayName, 100), phoneNumberId: safeText(body.phoneNumberId, 80), businessAccountId: safeText(body.businessAccountId, 80), graphVersion: safeText(body.graphVersion, 16) || 'v23.0' } : type === 'email' ? { provider: 'resend', displayName: safeText(body.displayName, 100), fromEmail: safeText(body.fromEmail, 180), inboundAddress: safeText(body.inboundAddress, 180).toLowerCase() } : { provider: 'twilio', displayName: safeText(body.displayName, 100), fromNumber: safeText(body.fromNumber, 32) };
      const secretFields = type === 'whatsapp' ? { accessToken: safeText(body.accessToken, 2000), verifyToken: safeText(body.verifyToken, 300) } : type === 'email' ? { apiKey: safeText(body.apiKey, 1000), webhookSecret: safeText(body.webhookSecret, 300) } : { accountSid: safeText(body.accountSid, 100), authToken: safeText(body.authToken, 300) };
      if (Object.values(publicFields).some(value => !value) || Object.values(secretFields).some(value => !value)) return bad(res, 'Preencha todos os dados da conexao.');
      Object.assign(integration, publicFields, { secrets: encrypt(JSON.stringify(secretFields)), enabled: true, connectedAt: now(), updatedAt: now() }); if (!existing) db.integrations.push(integration); saveDb(); return json(res, 200, safeIntegration(integration));
    }
    if (pathname === '/api/messages' && req.method === 'POST') {
      const active = requireSession(req, res); if (!active) return; const body = await readBody(req); const channel = safeText(body.channel, 20); const recipient = safeText(body.recipient, 180); const content = safeText(body.content); const subject = safeText(body.subject, 180);
      if (!['whatsapp', 'email', 'sms'].includes(channel) || !recipient || !content) return bad(res, 'Informe canal, destinatario e mensagem.');
      const integration = getIntegration(active.tenant.id, channel); if (!integration) return bad(res, `Conecte o canal de ${channel} antes de enviar.`, 422);
      const contact = findOrCreateContact(active.tenant.id, { name: safeText(body.name, 120), phone: channel === 'email' ? '' : recipient, email: channel === 'email' ? recipient : '' });
      const message = { id: id('msg'), tenantId: active.tenant.id, contactId: contact.id, direction: 'outbound', channel, content, subject, status: 'sending', createdAt: now() }; db.messages.push(message); saveDb();
      try { const result = channel === 'whatsapp' ? await sendWhatsapp(integration, recipient, content) : channel === 'email' ? await sendEmail(integration, recipient, content, subject) : await sendSms(integration, recipient, content); message.status = 'sent'; message.providerId = result?.messages?.[0]?.id || result?.id || result?.sid || null; saveDb(); return json(res, 201, message); }
      catch (error) { message.status = 'failed'; message.error = error.message; saveDb(); return bad(res, error.message, 502); }
    }
    if (pathname === '/webhooks/whatsapp' && req.method === 'GET') {
      const token = url.searchParams.get('hub.verify_token'); const integration = db.integrations.find(item => item.type === 'whatsapp' && item.enabled && decrypt(item.secrets).verifyToken === token);
      if (url.searchParams.get('hub.mode') === 'subscribe' && integration) return send(res, 200, url.searchParams.get('hub.challenge') || ''); return send(res, 403, 'verification failed');
    }
    if (pathname === '/webhooks/whatsapp' && req.method === 'POST') {
      const body = await readBody(req); if (!metaSignatureIsValid(body._rawBody, req.headers['x-hub-signature-256'])) return bad(res, 'Assinatura do webhook da Meta invalida.', 401); for (const entry of body.entry || []) for (const change of entry.changes || []) { const value = change.value || {}; const phoneNumberId = value.metadata?.phone_number_id; const integration = db.integrations.find(item => item.type === 'whatsapp' && item.enabled && item.phoneNumberId === phoneNumberId); if (!integration) continue; const names = Object.fromEntries((value.contacts || []).map(item => [item.wa_id, item.profile?.name])); for (const incoming of value.messages || []) { const content = incoming.text?.body || incoming.button?.text || `[${incoming.type || 'mensagem'}]`; saveInbound(integration.tenantId, 'whatsapp', { name: names[incoming.from], phone: `+${incoming.from}`, content }); } } return json(res, 200, { ok: true });
    }
    if (pathname === '/webhooks/sms' && req.method === 'POST') { const body = await readBody(req); const integration = db.integrations.find(item => item.type === 'sms' && item.enabled && item.fromNumber === body.To); if (integration && !twilioSignatureIsValid(req, body, integration)) return bad(res, 'Assinatura da Twilio invalida.', 401); if (integration) saveInbound(integration.tenantId, 'sms', { name: body.From, phone: body.From, content: body.Body, providerId: body.MessageSid }); return send(res, 200, '<Response></Response>', { 'content-type': 'text/xml' }); }
    if (pathname === '/webhooks/email' && req.method === 'POST') { const body = await readBody(req); const event = body.data || {}; const recipients = Array.isArray(event.to) ? event.to : [body.to]; const integration = db.integrations.find(item => item.type === 'email' && item.enabled && recipients.filter(Boolean).some(address => String(address).toLowerCase() === item.inboundAddress)); if (!integration) return json(res, 200, { ok: true }); const secret = decrypt(integration.secrets); if (!resendSignatureIsValid(body._rawBody, req.headers, secret.webhookSecret)) return bad(res, 'Assinatura da Resend invalida.', 401); if (body.type !== 'email.received') return json(res, 200, { ok: true }); let content = event.subject || 'Novo e-mail recebido'; try { const received = await fetch(`https://api.resend.com/emails/receiving/${encodeURIComponent(event.email_id)}`, { headers: { authorization: `Bearer ${secret.apiKey}` } }); const email = await received.json(); if (received.ok) content = email.text || String(email.html || '').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim() || content; } catch {} saveInbound(integration.tenantId, 'email', { name: event.from, email: event.from, content, subject: event.subject, providerId: event.email_id }); return json(res, 200, { ok: true }); }
    if (req.method === 'GET' && staticFile(res, pathname)) return;
    return bad(res, 'Rota nao encontrada.', 404);
  } catch (error) { console.error(error); return bad(res, error.message || 'Erro inesperado.', 500); }
});

server.listen(PORT, () => console.log(`Conversa CRM em http://localhost:${PORT}`));
