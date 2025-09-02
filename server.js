// server.js — Clean, consolidated, and OPS-aligned
// - Express + Helmet hardened
// - Session cookies (Strict, HttpOnly, Secure in production)
// - Nonce rotation middleware for /api/*
// - CSRF token issue/rotate on use
// - Rate limiting on /api/*
// - Minimal, explicit JSON body size limit
// - Safe defaults for production

'use strict';

const express = require('express');
const session = require('express-session');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const cookie = require('cookie');

const app = express();

// ---------- Security Headers ----------
app.use(
  helmet({
    // Content-Security-Policy is best delivered via reverse proxy or meta with nonces;
    // keep HSTS here as a baseline.
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true,
    },
    // Disable X-Powered-By, etc.
    hidePoweredBy: true,
  })
);

// ---------- Core settings ----------
const isProduction = process.env.NODE_ENV === 'production';
const sessionSecret = process.env.SESSION_SECRET;

// Trust reverse proxy (needed for correct secure cookies & IPs in k8s/CF/proxy)
if (isProduction) {
  app.set('trust proxy', 1);
}

// Fail hard if production has no real secret
if (isProduction && (!sessionSecret || sessionSecret === 'dev-secret')) {
  // eslint-disable-next-line no-console
  console.error('FATAL ERROR: SESSION_SECRET is not set in production.');
  process.exit(1);
}

// ---------- Body parsing (limit size) ----------
app.use(express.json({ limit: '128kb' }));

// ---------- Sessions ----------
app.use(
  session({
    secret: sessionSecret || 'dev-secret',
    resave: false,
    saveUninitialized: false,
    name: 'sid', // optional: short cookie name
    cookie: {
      httpOnly: true,
      sameSite: 'strict',
      secure: isProduction,
      maxAge: 30 * 60 * 1000, // 30 minutes absolute max for session cookie
    },
  })
);

// ---------- Helpers ----------
function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

function generateNonce() {
  // Node has crypto.webcrypto, but randomBytes is simpler & portable.
  return crypto.randomBytes(16).toString('hex'); // 128-bit nonce
}

// Require a valid rotating nonce for /api/* (after /api/session initializes it)
function requireNonce(req, res, next) {
  const cookies = cookie.parse(req.headers.cookie || '');
  const clientNonce = cookies.nonce;
  const sessionNonce = req.session.nonce;

  if (
    !clientNonce ||
    !sessionNonce ||
    clientNonce !== sessionNonce.value ||
    Date.now() > sessionNonce.expires
  ) {
    return res.status(403).json({ error: 'Invalid nonce' });
  }

  // Rotate nonce on each validated request
  const newNonce = generateNonce();
  req.session.nonce = { value: newNonce, expires: Date.now() + 10 * 60 * 1000 };
  res.cookie('nonce', newNonce, {
    httpOnly: true,
    sameSite: 'strict',
    secure: isProduction,
  });

  next();
}

// ---------- Rate limiting for API ----------
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,                 // 100 requests/IP/window
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api/', apiLimiter);

// ---------- Routes ----------

// Initialize a fresh nonce (client must call this before other /api endpoints)
app.post('/api/session', (req, res) => {
  const nonce = generateNonce();
  req.session.nonce = { value: nonce, expires: Date.now() + 10 * 60 * 1000 };
  res.cookie('nonce', nonce, {
    httpOnly: true,
    sameSite: 'strict',
    secure: isProduction,
  });
  return res.status(204).end();
});

// All routes below this line require a valid nonce (rotated on each request)
app.use('/api/', requireNonce);

// Issue a CSRF token (separate from nonce). Client should send it back in body.
app.get('/api/csrf-token', (req, res) => {
  const token = generateToken();
  req.session.csrfToken = { value: token, expires: Date.now() + 10 * 60 * 1000 };
  return res.json({ token });
});

// Example validated form: Contact
const contactValidation = [
  body('name').trim().isLength({ min: 1 }).escape(),
  body('email').isEmail().normalizeEmail(),
  body('message').trim().isLength({ min: 1 }).escape(),
  body('csrfToken').isString().isLength({ min: 1 }),
];

app.post('/api/contact', contactValidation, (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { csrfToken } = req.body;
  const sessionToken = req.session.csrfToken;

  if (
    !csrfToken ||
    !sessionToken ||
    sessionToken.value !== csrfToken ||
    Date.now() > sessionToken.expires
  ) {
    return res.status(403).json({ error: 'Invalid CSRF token' });
  }

  // Rotate CSRF token after successful use
  const newToken = generateToken();
  req.session.csrfToken = { value: newToken, expires: Date.now() + 10 * 60 * 1000 };
  res.set('X-CSRF-Token', newToken);

  // TODO: process the contact payload safely here (enqueue, worker, etc.)
  return res.json({ ok: true });
});

// Chat flows: per-session chatNonce to guard replay within the chat thread
app.post('/api/chat/reset', (req, res) => {
  req.session.chatNonce = null;
  return res.json({ ok: true });
});

app.post('/api/chat', (req, res) => {
  const { message, nonce } = req.body || {};
  if (!nonce || typeof nonce !== 'string') {
    return res.status(400).json({ error: 'Missing nonce' });
  }

  const now = Date.now();
  const sessionNonce = req.session.chatNonce;

  if (!sessionNonce || sessionNonce.expires < now) {
    // First message or expired: accept and set
    req.session.chatNonce = { value: nonce, expires: now + 10 * 60 * 1000 };
  } else if (sessionNonce.value !== nonce) {
    // Reject replay/cross-nonce tampering
    return res.status(403).json({ error: 'Invalid nonce' });
  } else {
    // Refresh expiry on valid message
    req.session.chatNonce.expires = now + 10 * 60 * 1000;
  }

  // Placeholder response; integrate with your chatbot backend here.
  return res.json({ reply: 'ok', echoed: message });
});

// ---------- Health + 404 ----------
app.get('/healthz', (_req, res) => res.status(204).end());

app.use((_req, res) => {
  return res.status(404).json({ error: 'Not Found' });
});

// ---------- Error handler ----------
app.use((err, _req, res, _next) => {
  // eslint-disable-next-line no-console
  console.error('Unhandled error:', err);
  return res.status(500).json({ error: 'Internal Server Error' });
});

module.exports = app;

if (require.main === module) {
  const port = process.env.PORT || 3000;
  app.listen(port, () => {
    // eslint-disable-next-line no-console
    console.log(`Server running on port ${port}`);
  });
}

