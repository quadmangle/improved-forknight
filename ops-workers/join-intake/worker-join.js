/* =========================================
JOIN INTAKE — Bootstrap (no secrets)
Asset ID: ops-join-intake
Version: 0.1.0
========================================= */

const JOIN_SCHEMA = {
  fields: [
    { name: 'Name', type: 'string', required: true, min: 1, max: 200 },
    { name: 'Email', type: 'email', required: true },
    { name: 'Phone', type: 'phone', required: false, min: 0, max: 40 },
    { name: 'Skills', type: 'strArrayCapped', required: false },
    { name: 'Education', type: 'strArrayCapped', required: false },
    { name: 'Certification', type: 'strArrayCapped', required: false },
    { name: 'Hobbies', type: 'strArrayCapped', required: false },
    { name: 'What are you interested in?', type: 'enum', required: true,
      options: ['Business Operations', 'Contact Center', 'IT Support', 'Professionals'] },
    { name: 'Continued Education', type: 'strArrayCapped', required: false },
    { name: 'Experience', type: 'strArrayCapped', required: false },
    { name: 'Tell us about yourself', type: 'string', required: false, min: 0, max: 5000 },
  ]
};

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get('Origin') || '';
    const corsHeaders = cors(env, origin);

    if (request.method === 'OPTIONS')
      return new Response(null, { status: 204, headers: { ...corsHeaders, 'Access-Control-Max-Age': '600' } });

    if (request.method === 'GET' && url.pathname === '/.well-known/health')
      return json({ ok: true, service: env.ASSET_ID || 'ops-join-intake', version: '0.1.0' }, 200, corsHeaders);

    if (request.method === 'POST' && url.pathname === '/ingress/join') {
      if (!isAllowedOrigin(env, origin)) return json({ error: 'forbidden_origin' }, 403, corsHeaders);

      let bodyText = '';
      try { bodyText = await request.text(); } catch { return json({ error: 'read_error' }, 400, corsHeaders); }
      if (byteLen(bodyText) > toInt(env.MAX_BODY_BYTES || '256000')) return json({ error: 'payload_too_large' }, 413, corsHeaders);

      let input; try { input = JSON.parse(bodyText || '{}'); } catch { return json({ error: 'invalid_json' }, 400, corsHeaders); }
      const shape = (input && typeof input === 'object' && 'form' in input) ? input.fields : input;
      if (!shape || typeof shape !== 'object') return json({ error: 'invalid_payload' }, 400, corsHeaders);

      let fields;
      try {
        fields = validateAgainstSchema('join', JOIN_SCHEMA, sanitizeValue(shape));
        enforceByteLimits(fields, toInt(env.MAX_FIELD_BYTES || '5000'));
      } catch (e) {
        return json({ error: 'validation_error', message: String(e.message || e) }, 400, corsHeaders);
      }

      const envelope = {
        schema: 'ops.v1',
        submitted_at: new Date().toISOString(),
        asset_id: env.ASSET_ID || 'ops-join-intake',
        form: 'join',
        fields
      };

      try {
        if (env.TRANSIT && typeof env.TRANSIT.fetch === 'function') {
          const r = await env.TRANSIT.fetch('https://transit.internal/core', {
            method: 'POST',
            headers: { 'content-type': 'application/json', 'X-Asset-ID': envelope.asset_id },
            body: JSON.stringify(envelope)
          });
          if (r.ok) return json({ status: 'accepted_by_transit' }, 202, corsHeaders);
          return json({ status: 'transit_rejected', code: r.status }, r.status, corsHeaders);
        } else if (env.TRANSIT_URL) {
          const r = await fetch(new URL('/core', env.TRANSIT_URL).toString(), {
            method: 'POST',
            headers: { 'content-type': 'application/json', 'X-Asset-ID': envelope.asset_id },
            body: JSON.stringify(envelope)
          });
          if (r.ok) return json({ status: 'accepted_by_transit' }, 202, corsHeaders);
          return json({ status: 'transit_rejected', code: r.status }, r.status, corsHeaders);
        }
      } catch (_) {}

      return json({ status: 'validated_only', message: 'Transit not configured' }, 200, corsHeaders);
    }

    return json({ error: 'not_found' }, 404, corsHeaders);
  }
};

/* ---- shared helpers ---- */
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
  if (isAllowedOrigin(env, origin)) {
    h['Access-Control-Allow-Origin'] = origin;
    h['Vary'] = 'Origin';
    h['Access-Control-Allow-Methods'] = 'POST, OPTIONS, GET';
    h['Access-Control-Allow-Headers'] = 'content-type';
  }
  return h;
}
function isAllowedOrigin(env, origin) {
  const list = String(env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
  return origin && list.includes(origin);
}
function toInt(s) { return parseInt(String(s), 10) || 0; }
function byteLen(s) { return new TextEncoder().encode(String(s || '')).length; }

function validateAgainstSchema(formName, schema, fields) {
  if (formName !== 'join') throw new Error('wrong_form');
  const allowed = new Set(schema.fields.map(f => f.name));
  for (const k of Object.keys(fields)) if (!allowed.has(k)) throw new Error(`unexpected field: ${k}`);

  const out = {};
  for (const f of schema.fields) {
    const v = fields[f.name];
    if (f.required && (v === undefined || v === null || v === '')) throw new Error(`missing: ${f.name}`);
    if (v === undefined || v === null || v === '') { out[f.name] = (f.type === 'strArrayCapped' ? [] : ''); continue; }
    switch (f.type) {
      case 'string': out[f.name] = mustStr(v, f.min || 0, f.max || 5000, f.name); break;
      case 'email': out[f.name] = mustEmail(v, f.name); break;
      case 'phone': out[f.name] = mustPhone(v, f.name, f.max || 40); break;
      case 'enum':  out[f.name] = mustEnum(v, f.options, f.name); break;
      case 'strArrayCapped': out[f.name] = strArrayCapped(v, f.name); break;
      default: throw new Error(`unknown type: ${f.type}`);
    }
  }
  return out;
}
const RE_CTRL = /[\u0000-\u001F\u007F]/g;
const RE_BIDI  = /[\u200E\u200F\u202A-\u202E\u2066-\u2069]/g;
function sanitizeValue(v) {
  if (v == null) return v;
  if (typeof v === 'string') {
    let s = v.normalize('NFKC').replace(RE_CTRL, ' ').replace(RE_BIDI, '');
    s = s.replace(/<[^>]*?>/g, '');
    s = s.replace(/\bon\w+\s*=/gi, '');
    s = s.replace(/javascript\s*:/gi, '');
    return s.trim();
  }
  if (Array.isArray(v)) return v.map(sanitizeValue);
  if (typeof v === 'object') { const o = {}; for (const k of Object.keys(v)) o[k] = sanitizeValue(v[k]); return o; }
  return v;
}
function mustStr(v, min, max, field) {
  if (typeof v !== 'string') throw new Error(`invalid ${field}`);
  const t = sanitizeValue(v);
  if (t.length < min) throw new Error(`${field} too short`);
  if (t.length > max) throw new Error(`${field} too long`);
  return t;
}
function mustEmail(v, field) {
  const s = mustStr(String(v), 3, 254, field);
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s)) throw new Error(`invalid ${field}`);
  return s;
}
function mustPhone(v, field, max) {
  const s = mustStr(String(v), 0, max, field);
  if (s && !/^[+()\-\d\s\.]{4,}$/.test(s)) throw new Error(`invalid ${field}`);
  return s;
}
function mustEnum(v, options, field) {
  const s = mustStr(String(v), 1, 200, field);
  if (!options.includes(s)) throw new Error(`invalid ${field}`);
  return s;
}
function strArrayCapped(v, field, { maxItems = 50, maxItemBytes = 5000, maxTotalBytes = 20000 } = {}) {
  if (!v) return [];
  if (!Array.isArray(v)) throw new Error(`invalid ${field}`);
  const enc = new TextEncoder();
  let total = 0;
  if (v.length > maxItems) throw new Error(`${field} has too many items`);
  return v.map((x, i) => {
    const s = mustStr(String(x), 0, maxItemBytes, `${field}[${i}]`);
    const n = enc.encode(s).length;
    if (n > maxItemBytes) throw new Error(`${field}[${i}] too large`);
    total += n;
    if (total > maxTotalBytes) throw new Error(`${field} total size too large`);
    return s;
  });
}
function enforceByteLimits(obj, maxBytesPerField) {
  const enc = new TextEncoder();
  const walk = (v) => {
    if (typeof v === 'string') {
      const n = enc.encode(v).length;
      if (n > maxBytesPerField) throw new Error(`field exceeds ${maxBytesPerField} bytes`);
    } else if (Array.isArray(v)) v.forEach(walk);
    else if (v && typeof v === 'object') Object.values(v).forEach(walk);
  };
  walk(obj);
}
