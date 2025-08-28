export default {
  async fetch(request, env) {
    if (request.method !== 'POST') {
      return new Response('Method Not Allowed', { status: 405 });
    }

    const auth = request.headers.get('Authorization');
    if (!auth || !auth.startsWith('Bearer ')) {
      return new Response('Unauthorized', { status: 401 });
    }

    let body;
    try {
      body = await request.json();
    } catch {
      return new Response('Bad Request', { status: 400 });
    }

    // Persist the encrypted payload for later processing.
    const key = `join:${Date.now()}:${crypto.randomUUID()}`;
    if (env.JOIN_KV) {
      await env.JOIN_KV.put(key, JSON.stringify(body));
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
