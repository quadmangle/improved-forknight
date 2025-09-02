# Improved Fortnight

This project serves dynamic forms and supporting APIs.

## Environment Variables

- `SESSION_SECRET` – required in production. The server refuses to start if this is missing. Use a strong, random value.

## Session Cookies

Session cookies are configured with the following security flags:

- `HttpOnly`
- `SameSite=Strict`
- `Secure` (enabled automatically in production)

These settings help protect against cross-site scripting and request-forgery attacks.

## Node Version

Development requires Node.js 18 or newer.
