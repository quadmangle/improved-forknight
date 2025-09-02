# OPS Online Support

This repository powers the OPS Online Support site. It includes:

- A **Security and Quality** GitHub Actions workflow that runs CodeQL analysis and `npm audit` on each push and pull request.
- A Cloudflare Worker that injects HTTP security headers for runtime protection. The Worker is deployed at:

  https://winter-csp-pond-0f67.pure-sail-sole.workers.dev/

## Development

Install dependencies and run the test suite:

```bash
npm ci
npm test
```

## Security

The project follows NIST, CISA, and PCI DSS guidance for vulnerability management and secure configuration.
