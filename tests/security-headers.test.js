const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');

const app = require('../server');

test('server sets core security headers', async () => {
  const server = http.createServer(app);
  await new Promise(resolve => server.listen(0, resolve));
  const port = server.address().port;
  const res = await fetch(`http://localhost:${port}/`);
  server.close();

  assert.equal(
    res.headers.get('strict-transport-security'),
    'max-age=31536000; includeSubDomains; preload'
  );
  assert.equal(
    res.headers.get('referrer-policy'),
    'strict-origin-when-cross-origin'
  );
  assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
  const csp = res.headers.get('content-security-policy') || '';
  assert.ok(csp.includes("default-src 'none'"));
});
