export default {
  async fetch(request, env) {
    if (request.method !== 'POST') {
      return new Response('Method Not Allowed', { status: 405 });
    }

    if (request.headers.get('x-asset-id') !== env.UPSTREAM_ASSET_ID) {
      return new Response('Forbidden', { status: 403 });
    }

    let body;
    try {
      body = await request.json();
    } catch {
      return new Response('Bad Request', { status: 400 });
    }

    const aesKey = await importAesKey(env.DATA_KEY);
    const clear = {};
    for (const [field, blob] of Object.entries(body.payload || {})) {
      clear[field] = await decryptField(aesKey, blob);
      if (!isClean(clear[field])) return new Response('Bad Request', { status: 400 });
    }

    const key = `join:${Date.now()}:${crypto.randomUUID()}`;
    if (env.JOIN_KV) {
      // Store sanitized plaintext for Apps Script to pull and handle.
      await env.JOIN_KV.put(key, JSON.stringify(clear));
    }

    return new Response(
      JSON.stringify({ status: 'received', kvLink: key }),
      {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }
    );
  },
};

function isClean(str) {
  return !( /<\s*script/i.test(str) || /javascript:/i.test(str) || /--/g.test(str) );
}

function base64ToArray(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

async function importAesKey(b64) {
  const raw = base64ToArray(b64);
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['decrypt']);
}

async function decryptField(key, blob) {
  const { ciphertext, iv } = blob;
  const data = base64ToArray(ciphertext);
  const ivBytes = base64ToArray(iv);
  const dec = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ivBytes }, key, data);
  return new TextDecoder().decode(dec);
}

