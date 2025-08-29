/* =========================================
TRANSIT BROKER — Sandwich Worker
Asset ID: ops-transit-broker
Version: 0.2.0
Purpose: Decrypt inbound payloads, validate integrity, re‑encrypt and
forward to the Contact or Join workers.
========================================= */

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get('Origin') || '';
    const corsHeaders = cors(env, origin);

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: { ...corsHeaders, 'Access-Control-Max-Age': '600' } });
    }

    if (request.method === 'GET' && url.pathname === '/.well-known/health') {
      return json({ ok: true, service: env.ASSET_ID || 'ops-transit-broker', version: '0.2.0' }, 200, corsHeaders);
    }

    if (request.method === 'POST' && url.pathname === '/core') {
      let input;
      try { input = await request.json(); } catch { return json({ error: 'invalid_json' }, 400, corsHeaders); }

      const { form, payload, signature } = input || {};
      if (!form || typeof payload !== 'object') return json({ error: 'invalid_payload' }, 400, corsHeaders);

      const aesKey = await importAesKey(env.DATA_KEY);
      const clear = {};
      for (const [field, blob] of Object.entries(payload)) {
        clear[field] = await decryptField(aesKey, blob);
        if (!isClean(clear[field])) return json({ error: 'malicious_input' }, 400, corsHeaders);
      }

      const canonical = canonicalize(clear);
      const validSig = await verifySignature(env.CLIENT_PUB_PEM, canonical, signature);
      if (!validSig) return json({ error: 'bad_signature' }, 401, corsHeaders);

      const reEncrypted = {};
      for (const [field, value] of Object.entries(clear)) {
        reEncrypted[field] = await encryptField(aesKey, value);
      }

      const targetWrapped = form === 'contact' ? env.CONTACT_URL_WRAPPED : env.JOIN_URL_WRAPPED;
      if (!targetWrapped) return json({ error: 'unknown_form' }, 400, corsHeaders);
      const targetUrl = await unwrapUrl(targetWrapped, env.URL_WRAP_KEY);

      const upstreamResp = await fetch(targetUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${env.UPSTREAM_TOKEN || ''}`,
          'x-asset-id': env.ASSET_ID,
        },
        body: JSON.stringify({ payload: reEncrypted })
      });

      if (!upstreamResp.ok) return json({ error: 'upstream_error' }, 502, corsHeaders);
      return json({ status: 'forwarded', form }, 202, corsHeaders);
    }

    return json({ error: 'not_found' }, 404, corsHeaders);
  }
};

/* ---- helpers ---- */
function json(body, status, headers) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...headers, 'content-type': 'application/json', 'cache-control': 'no-store' }
  });
}

function cors(env, origin) {
  const h = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
  };
  if (isAllowedOrigin(env, origin)) {
    h['Access-Control-Allow-Origin'] = origin;
    h['Vary'] = 'Origin';
    h['Access-Control-Allow-Methods'] = 'POST, OPTIONS, GET';
    h['Access-Control-Allow-Headers'] = 'content-type, x-asset-id';
  }
  return h;
}

function isAllowedOrigin(env, origin) {
  const list = String(env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
  return origin && list.includes(origin);
}

function isClean(str) {
  return !( /<\s*script/i.test(str) || /javascript:/i.test(str) || /--/g.test(str) );
}

function canonicalize(obj) {
  return JSON.stringify(Object.keys(obj).sort().reduce((acc, k) => (acc[k] = obj[k], acc), {}));
}

function base64ToArray(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function arrayToBase64(arr) {
  return btoa(String.fromCharCode(...new Uint8Array(arr)));
}

async function importAesKey(b64) {
  const raw = base64ToArray(b64);
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

async function decryptField(key, blob) {
  const { ciphertext, iv } = blob;
  const data = base64ToArray(ciphertext);
  const ivBytes = base64ToArray(iv);
  const dec = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ivBytes }, key, data);
  return new TextDecoder().decode(dec);
}

async function encryptField(key, value) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(value));
  return { ciphertext: arrayToBase64(enc), iv: arrayToBase64(iv) };
}

async function verifySignature(pem, data, sigB64) {
  if (!pem || !sigB64) return false;
  const key = await crypto.subtle.importKey(
    'spki',
    pemToArray(pem),
    { name: 'ECDSA', namedCurve: 'P-384' },
    false,
    ['verify']
  );
  const sig = base64ToArray(sigB64);
  return crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-384' }, key, sig, new TextEncoder().encode(data));
}

function pemToArray(pem) {
  const b64 = pem.replace(/-----(BEGIN|END) PUBLIC KEY-----|\n/g, '');
  return base64ToArray(b64);
}

async function unwrapUrl(wrappedB64, wrapKeyB64) {
  const wrapKey = await crypto.subtle.importKey('raw', base64ToArray(wrapKeyB64), 'AES-KW', false, ['unwrapKey']);
  const wrapped = base64ToArray(wrappedB64);
  const key = await crypto.subtle.unwrapKey('raw', wrapped, wrapKey, 'AES-KW', 'raw', true, ['encrypt']);
  const urlBytes = await crypto.subtle.exportKey('raw', key);
  return new TextDecoder().decode(urlBytes);
}
