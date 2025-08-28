/* =========================================
TRANSIT BROKER — Bootstrap (no secrets)
Asset ID: ops-transit-broker
Version: 0.1.0
Purpose: Accept validated envelopes from Contact/Join and ACK.
========================================= */

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get('Origin') || '';
    const corsHeaders = cors(env, origin);

    if (request.method === 'OPTIONS')
      return new Response(null, { status: 204, headers: { ...corsHeaders, 'Access-Control-Max-Age': '600' } });

    if (request.method === 'GET' && url.pathname === '/.well-known/health')
      return json({ ok: true, service: env.ASSET_ID || 'ops-transit-broker', version: '0.1.0' }, 200, corsHeaders);

    if (request.method === 'POST' && url.pathname === '/core') {
      // Note: In the bootstrap we don’t verify signatures or decrypt.
      // We just sanity-check shape and ACK with 202.
      let bodyText = '';
      try { bodyText = await request.text(); } catch { return json({ error: 'read_error' }, 400, corsHeaders); }
      let input;
      try { input = JSON.parse(bodyText || '{}'); } catch { return json({ error: 'invalid_json' }, 400, corsHeaders); }

      if (!input || typeof input !== 'object') return json({ error: 'invalid_payload' }, 400, corsHeaders);
      const form = input.form;
      if (!form || (form !== 'contact' && form !== 'join'))
        return json({ error: 'unknown_form' }, 400, corsHeaders);

      // Minimal ACK
      return json({ status: 'ack', form, received_at: new Date().toISOString() }, 202, corsHeaders);
    }

    return json({ error: 'not_found' }, 404, corsHeaders);
  }
};

/* ---- helpers ---- */
function json(body, status, headers) {
  return new Response(JSON.stringify(body), {
    status, headers: { ...headers, 'content-type': 'application/json', 'cache-control': 'no-store' }
  });
}
function cors(env, origin) {
  const h = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
  };
  // Transit can be called from other workers (no browser CORS needed),
  // but we still reflect allowed origins if you hit it from a page.
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

