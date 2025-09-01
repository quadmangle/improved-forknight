const test = require('node:test');
const assert = require('node:assert');
const request = require('supertest');

// Set a default environment for tests
process.env.NODE_ENV = 'test';

const app = require('../server.js');

test.describe('API Tests', () => {
    test.describe('CSRF Protection', () => {
      let agent;

    test.beforeEach(async () => {
      agent = request.agent(app);
      await agent.post('/api/session').expect(204);
    });

    test('should get a CSRF token', async () => {
      const response = await agent.get('/api/csrf-token').expect(200);
      assert(response.body.token, 'Response should contain a CSRF token');
    });

    test('should accept a valid CSRF token', async () => {
      const tokenRes = await agent.get('/api/csrf-token').expect(200);
      const token = tokenRes.body.token;

      const res = await agent
        .post('/api/contact')
        .send({ csrfToken: token, name: 'Test User', email: 'test@opsonlinesupport.com', message: 'hello' })
        .expect(200);

      assert(res.body.ok === true, 'Response should indicate success');
    });

    test('should reject an invalid CSRF token', async () => {
      // Get a valid token first to make sure the session is initialized
      await agent.get('/api/csrf-token').expect(200);

      const res = await agent
        .post('/api/contact')
        .send({ csrfToken: 'invalid-token', name: 'Test User', email: 'test@opsonlinesupport.com', message: 'hello' })
        .expect(403);

      assert(res.body.error === 'Invalid CSRF token', 'Response should contain an error message');
    });

    test('should reject a request with no CSRF token', async () => {
      // Get a valid token first to make sure the session is initialized
      await agent.get('/api/csrf-token').expect(200);

      const res = await agent.post('/api/contact').send({ name: 'Test User', email: 'test@opsonlinesupport.com', message: 'hello' }).expect(403);
      assert(res.body.error === 'Invalid CSRF token', 'Response should contain an error message');
    });
  });

  test.describe('Secure Cookie Flag', () => {
    let originalNodeEnv;

    test.before(() => {
      originalNodeEnv = process.env.NODE_ENV;
    });

    test.after(() => {
      process.env.NODE_ENV = originalNodeEnv;
      delete require.cache[require.resolve('../server.js')]; // Invalidate cache so it reloads with original env
    });

    test('should set Secure flag on session cookie in production', async () => {
      process.env.NODE_ENV = 'production';
      process.env.SESSION_SECRET = 'test-secret-for-production-env';
      delete require.cache[require.resolve('../server.js')]; // Invalidate cache to reload with new env
      const appProd = require('../server.js');

      const agent = request.agent(appProd);
      const response = await agent
        .post('/api/session')
        .set('X-Forwarded-Proto', 'https')
        .expect(204);
      const cookieHeader = response.headers['set-cookie'];

      assert(cookieHeader, 'Set-Cookie header should be present');
      assert(cookieHeader.some(c => c.includes('Secure')), 'Secure flag should be set on the cookie');
    });

    test('should NOT set Secure flag on session cookie in development', async () => {
      process.env.NODE_ENV = 'development';
      delete require.cache[require.resolve('../server.js')]; // Invalidate cache to reload with new env
      const appDev = require('../server.js');

      const agent = request.agent(appDev);
      const response = await agent.post('/api/session').expect(204);
      const cookieHeader = response.headers['set-cookie'];

      assert(cookieHeader, 'Set-Cookie header should be present');
      assert(!cookieHeader.some(c => c.includes('Secure')), 'Secure flag should NOT be set on the cookie');
    });
  });
});
