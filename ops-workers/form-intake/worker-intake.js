export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === 'POST' && (url.pathname === '/contact' || url.pathname === '/join')) {
      return handleForm(request, env, url.pathname.slice(1));
    }
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: cors(env, request.headers.get('Origin')) });
    }
    return new Response('not found', { status: 404 });
  }
};

async function handleForm(request, env, form) {
  const origin = request.headers.get('Origin') || '';
  const corsHeaders = cors(env, origin);
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: 'invalid_json' }, 400, corsHeaders);
  }
  const sanitized = sanitize(body);
  if (!sanitized) return json({ error: 'invalid_payload' }, 400, corsHeaders);
  const text = JSON.stringify({ form, data: sanitized });
  const { ciphertext, iv } = await encrypt(env, text);
  const key = `${form}:${Date.now()}:${crypto.randomUUID()}`;
  await env.FORM_DATA.put(
    key,
    JSON.stringify({ iv: bufferToBase64(iv), data: bufferToBase64(ciphertext) })
  );
  if (env.TRANSIT_URL) {
    await fetch(env.TRANSIT_URL, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ form, iv: bufferToBase64(iv), data: bufferToBase64(ciphertext) })
    });
  }
  return json({ status: 'stored' }, 202, corsHeaders);
}

function sanitize(obj) {
  const out = {};
  for (const [k, v] of Object.entries(obj || {})) {
    if (typeof v === 'string') {
      if (/<script|on\w+=|javascript:/i.test(v)) return null;
      out[k] = v.replace(/[<>]/g, '');
    }
  }
  return out;
}

async function encrypt(env, text) {
  const keyData = base64ToBytes(env.DATA_KEY || '');
  const cryptoKey = await crypto.subtle.importKey('raw', keyData, 'AES-GCM', false, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = new TextEncoder().encode(text);
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, cryptoKey, data);
  return { ciphertext: new Uint8Array(encrypted), iv };
}

function bufferToBase64(buf) {
  let binary = '';
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

function base64ToBytes(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function cors(env, origin) {
  const headers = { 'content-type': 'application/json', 'cache-control': 'no-store' };
  if (origin && isAllowedOrigin(env, origin)) {
    headers['Access-Control-Allow-Origin'] = origin;
    headers['Vary'] = 'Origin';
    headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS';
    headers['Access-Control-Allow-Headers'] = 'content-type';
  }
  return headers;
}

function isAllowedOrigin(env, origin) {
  const list = String(env.ALLOWED_ORIGINS || '')
    .split(',')
    .map(s => s.trim())
    .filter(Boolean);
  return list.includes(origin);
}

function json(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...headers, 'content-type': 'application/json' }
  });
}
