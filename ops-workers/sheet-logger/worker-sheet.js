/* =========================================
GOOGLE SHEET LOGGER — Cloudflare Worker
Asset ID: ops-sheet-logger
Version: 0.1.0
Purpose: Accept JSON from trusted clients and append to Google Sheet using OAuth.
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
      return json({ ok: true, service: env.ASSET_ID || 'ops-sheet-logger', version: '0.1.0' }, 200, corsHeaders);
    }

    if (request.method === 'POST' && url.pathname === '/log') {
      const auth = request.headers.get('Authorization') || '';
      if (auth !== `Bearer ${env.API_TOKEN}`) {
        return json({ error: 'unauthorized' }, 401, corsHeaders);
      }

      let payload;
      try {
        payload = await request.json();
      } catch {
        return json({ error: 'bad_json' }, 400, corsHeaders);
      }

      try {
        await appendToSheet(env, payload);
        return json({ ok: true }, 200, corsHeaders);
      } catch (err) {
        return json({ error: 'sheet_error' }, 500, corsHeaders);
      }
    }

    return json({ error: 'not_found' }, 404, corsHeaders);
  }
};

async function appendToSheet(env, data) {
  const token = await getAccessToken(env);
  const url = `https://sheets.googleapis.com/v4/spreadsheets/${env.SHEET_ID}/values/A1:append?valueInputOption=RAW`;
  const body = {
    values: [[ new Date().toISOString(), JSON.stringify(data) ]]
  };
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(body)
  });
  if (!res.ok) throw new Error('append_failed');
}

async function getAccessToken(env) {
  const header = { alg: 'RS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const claim = {
    iss: env.SA_EMAIL,
    scope: 'https://www.googleapis.com/auth/spreadsheets',
    aud: 'https://oauth2.googleapis.com/token',
    exp: now + 3600,
    iat: now
  };
  const enc = str => new TextEncoder().encode(str);
  const b64url = buf => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/=+$/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  const unsigned = `${b64url(enc(JSON.stringify(header)))}.${b64url(enc(JSON.stringify(claim)))}`;
  const key = await crypto.subtle.importKey(
    'pkcs8',
    str2ab(env.SA_PRIVATE_KEY),
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, enc(unsigned));
  const jwt = `${unsigned}.${b64url(signature)}`;
  const res = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`
  });
  const jsonResp = await res.json();
  if (!res.ok) throw new Error('token_error');
  return jsonResp.access_token;
}

function str2ab(pem) {
  const b64 = pem.replace(/-----\w+ PRIVATE KEY-----/g, '').replace(/\s+/g, '');
  const binary = atob(b64);
  const len = binary.length;
  const buf = new ArrayBuffer(len);
  const view = new Uint8Array(buf);
  for (let i = 0; i < len; i++) view[i] = binary.charCodeAt(i);
  return buf;
}

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
    h['Access-Control-Allow-Headers'] = 'content-type, authorization';
  }
  return h;
}
function isAllowedOrigin(env, origin) {
  const list = String(env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
  return origin && list.includes(origin);
}
