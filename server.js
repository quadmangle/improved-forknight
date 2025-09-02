const express = require('express');
const session = require('express-session');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const cookie = require('cookie');

const app = express();

app.use(helmet({ contentSecurityPolicy: false }));
app.use(
  helmet.hsts({
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true,
  })
);
app.use(helmet.referrerPolicy({ policy: 'strict-origin-when-cross-origin' }));
app.use(helmet.crossOriginOpenerPolicy({ policy: 'same-origin' }));
app.use(helmet.crossOriginResourcePolicy({ policy: 'same-origin' }));
app.use((req, res, next) => {
  res.set(
    'Permissions-Policy',
    'geolocation=(), microphone=(), camera=(), payment=(), usb=(), accelerometer=(), gyroscope=(), magnetometer=()'
  );
  res.set('Cache-Control', 'no-store');
  next();
});
app.use(
  helmet.contentSecurityPolicy({
    useDefaults: false,
    directives: {
      defaultSrc: ["'none'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'"],
      imgSrc: ["'self'", 'data:'],
      fontSrc: ["'self'"],
      connectSrc: ["'self'"],
      frameSrc: [],
      frameAncestors: ["'none'"],
      formAction: ["'self'"],
      baseUri: ["'none'"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: []
    }
  })
);
app.use(express.json());
const isProduction = process.env.NODE_ENV === 'production';
const sessionSecret = process.env.SESSION_SECRET;

if (isProduction) {
  app.set('trust proxy', 1); // Trust the first proxy
}

if (isProduction && (!sessionSecret || sessionSecret === 'dev-secret')) {
  console.error('FATAL ERROR: SESSION_SECRET is not set in production.');
  process.exit(1);
}

app.use(
  session({
    secret: sessionSecret || 'dev-secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'strict',
      secure: isProduction,
    },
  })
);

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

function generateNonce() {
  const array = new Uint8Array(16); // 128-bit nonce
  crypto.webcrypto.getRandomValues(array);
  return Buffer.from(array).toString('hex');
}

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

  const newNonce = generateNonce();
  req.session.nonce = { value: newNonce, expires: Date.now() + 10 * 60 * 1000 };
  res.cookie('nonce', newNonce, {
    httpOnly: true,
    sameSite: 'strict',
    secure: isProduction,
  });

  next();
}

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/api/', apiLimiter);

app.post('/api/session', (req, res) => {
  const nonce = generateNonce();
  req.session.nonce = { value: nonce, expires: Date.now() + 10 * 60 * 1000 };
  res.cookie('nonce', nonce, {
    httpOnly: true,
    sameSite: 'strict',
    secure: isProduction,
  });
  res.status(204).end();
});

app.use('/api/', requireNonce);

app.get('/api/csrf-token', (req, res) => {
  const token = generateToken();
  req.session.csrfToken = { value: token, expires: Date.now() + 10 * 60 * 1000 };
  res.json({ token });
});

const contactValidation = [
  body('name').trim().isLength({ min: 1 }).escape(),
  body('email').isEmail().normalizeEmail(),
  body('message').trim().isLength({ min: 1 }).escape(),
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
  const newToken = generateToken();
  req.session.csrfToken = { value: newToken, expires: Date.now() + 10 * 60 * 1000 };
  res.set('X-CSRF-Token', newToken);
  // Process data here (omitted)
  res.json({ ok: true });
});

// Chatbot message handling with nonce validation
app.post('/api/chat/reset', (req, res) => {
  req.session.chatNonce = null;
  res.json({ ok: true });
});

app.post('/api/chat', (req, res) => {
  const { message, nonce } = req.body || {};
  if (!nonce || typeof nonce !== 'string') {
    return res.status(400).json({ error: 'Missing nonce' });
  }

  const now = Date.now();
  const sessionNonce = req.session.chatNonce;
  if (!sessionNonce || sessionNonce.expires < now) {
    req.session.chatNonce = { value: nonce, expires: now + 10 * 60 * 1000 };
  } else if (sessionNonce.value !== nonce) {
    return res.status(403).json({ error: 'Invalid nonce' });
  } else {
    // refresh expiry
    req.session.chatNonce.expires = now + 10 * 60 * 1000;
  }

  // Placeholder response; integrate with chatbot backend here.
  res.json({ reply: 'ok', echoed: message });
});

module.exports = app;

if (require.main === module) {
  const port = process.env.PORT || 3000;
  app.listen(port, () => {
    console.log(`Server running on port ${port}`);
  });
}
