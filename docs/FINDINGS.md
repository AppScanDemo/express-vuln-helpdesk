# Expected Findings — HelpdeskVuln (Node.js Express)

Intentional vulnerabilities seeded in this repository, for scoring SAST/SCA/
secret-scanning tool coverage during POC.

## SAST — Expected Findings

| # | Location | Vulnerability | CWE | OWASP Top 10 (2021) | ASVS | Severity |
|---|----------|---------------|-----|----------------------|------|----------|
| 1 | `routes/auth.js` (`login`) | NoSQL Injection (operator injection, auth bypass) | CWE-943 | A03: Injection | V5.3.4 | Critical |
| 2 | `routes/tickets.js` (`GET /`) | NoSQL Injection (query-object injection) | CWE-943 | A03 | V5.3.4 | Critical |
| 3 | `routes/search.js` (`GET /`) | NoSQL Injection (`$regex` injection) | CWE-943 | A03 | V5.3.4 | High |
| 4 | `routes/macro.js` (`POST /run`) | Code Injection (`eval()`, Express-specific anti-pattern) | CWE-95 | A03 | V5.2.4 | Critical |
| 5 | `routes/admin.js` (`POST /settings/merge`) | Prototype Pollution (`lodash.merge`, Express-specific anti-pattern) | CWE-1321 | A03/A08 | V5.2.4 | Critical |
| 6 | `routes/search.js` (`POST /import-kb-xml`) | XXE (`libxmljs2` with `noent`/`dtdload`) | CWE-611 | A05: Security Misconfiguration | V5.5.2 | Critical |
| 7 | `routes/search.js` (`GET /kb-proxy`) | SSRF | CWE-918 | A10: SSRF | V12.6 | High |
| 8 | `routes/search.js` (html format) | Reflected XSS | CWE-79 | A03 | V5.3.3 | High |
| 9 | `middleware/weakAuth.js` | Improper JWT verification (`jwt.decode` instead of `jwt.verify`) | CWE-347 | A07: Ident./Auth Failures | V3.5 | Critical |
| 10 | `middleware/weakAuth.js`, `routes/auth.js`, `.env.example` | Hardcoded secrets (JWT key, backdoor admin creds, Mongo credential) | CWE-798 | A07 | V2.10 | Critical |
| 11 | `routes/admin.js` (`GET /users`) | Missing authorization (no auth middleware on route) | CWE-862 | A01: Broken Access Control | V4.1 | Critical |
| 12 | `routes/admin.js` (`promote`) | Privilege escalation | CWE-269 | A01 | V4.1 | Critical |
| 13 | `routes/tickets.js` (`GET /:id`) | IDOR | CWE-639 | A01 | V4.2 | High |
| 14 | `server.js` (`cors()`) | Wildcard CORS with credentials | CWE-942 | A05 | V14.5 | High |
| 15 | `server.js` | Missing security headers (no helmet, no CSP, no HSTS) | CWE-693 | A05 | V14.4 | Low/Medium |
| 16 | `server.js` (error handler) | Verbose error handler returns stack traces to clients | CWE-489 | A05 | V14.3 | Medium |
| 17 | `server.js` (`/files` static route) | Unauthenticated directory listing of uploads | CWE-548 | A01 | V12.3 | Medium |
| 18 | `routes/admin.js` (`GET /debug-env`) | Sensitive environment/secret exposure endpoint | CWE-215, CWE-497 | A05 | V8.3 | Critical |
| 19 | `routes/macro.js` (`GET /hash`) | MD5/SHA1 for integrity hashing | CWE-327, CWE-328 | A02: Cryptographic Failures | V6.2 | High |
| 20 | `routes/macro.js` (`GET /token`) | `Math.random()` for security-relevant token | CWE-338 | A02 | V6.3 | Medium |
| 21 | `models/User.js` | Plaintext password storage | CWE-256 | A02 | V2.4 | Critical |
| 22 | `routes/auth.js`, `middleware/weakAuth.js` | Sensitive data (password, JWT) in logs | CWE-532 | A09: Logging Failures | V7.1 | Medium |
| 23 | `routes/auth.js` (`register`) | Missing password policy | CWE-521 | A07 | V2.1 | Medium |
| 24 | `routes/auth.js` (`login`) | Insecure cookie (no Secure/HttpOnly/SameSite) | CWE-614, CWE-1004 | A05 | V3.4 | Medium |
| 25 | `routes/upload.js` | Unrestricted file upload / path traversal | CWE-434, CWE-22 | A05 | V12.1, V12.4 | Critical |
| 26 | `routes/auth.js` (`register`) | Mass-assignment-adjacent (entire body forwarded into `new User(req.body)`, allows client-set `role`) | CWE-915 | A08 | V5.1.4 | High |

## SCA — Expected Findings

| Dependency | Version pinned | Known issue class | Reachability |
|---|---|---|---|
| `express` | 4.16.0 | Historical Express-line advisories | Reachable (core framework) |
| `lodash` | 4.17.4 | Historical prototype-pollution advisories in `merge`/`mergeWith`/`defaultsDeep` | Reachable (`routes/admin.js`, confirmed functionally by `test/injection.test.js`) |
| `minimist` | 0.0.8 | Historical prototype-pollution advisory in argument parsing | **Unused vulnerable dependency** — never required anywhere in source; reachability = none |
| `axios` | 0.18.0 | Historical SSRF/redirect-handling advisories | Reachable (`routes/search.js` kb-proxy) |
| `jsonwebtoken` | 8.3.0 | Historical algorithm-confusion advisories | Reachable (`middleware/weakAuth.js`, `routes/auth.js`) |
| `multer` | 1.4.1 | Historical advisories in older releases | Reachable (`routes/upload.js`) |
| `libxmljs2` | 0.30.0 | Native XML parser, historical memory-safety advisories, amplifies XXE risk above | Reachable (`routes/search.js`) |

### Typosquatting / malware-name test set
Following the pattern from the Go+Gin repo (`testdata/typosquat-check/`):
recommend an isolated `package.json` fixture under `testdata/typosquat-check/`
with fictional look-alike npm package names (e.g. `expresss`, `lodas`,
`reqests`, `axioss`), excluded from the real `package.json` dependencies.
*(Not yet added to this seed version — flag if you want it included.)*

## Secret Detection — Expected Findings
All in `.env.example`, duplicated inline in `config/db.js` / `middleware/weakAuth.js`
/ `routes/auth.js` for source-code secret-scanning coverage. **All fake.**
- AWS / Azure / GCP credentials
- GitHub PAT / GitLab Token
- Stripe Secret Key / Slack Token / OpenAI API Key / Twilio Auth Token
- OAuth Client Secret / generic Bearer Token
- Fake RSA private key block / fake SSH private key block
- Hardcoded JWT secret (`SuperSecretJWT`)
- Fake MongoDB connection string with embedded credential (`helpdesk`/`Password123`)
- Hardcoded admin backdoor credentials (`admin` / `admin123`) in `routes/auth.js`

## Cryptography Rule Test Coverage
- MD5 / SHA1: `routes/macro.js` (`GET /hash`)
- Weak PRNG: `routes/macro.js` (`GET /token`, `Math.random()`)
- Hardcoded key: `middleware/weakAuth.js`, `routes/auth.js`, `.env.example`

## SBOM Notes
- Recommended: `@cyclonedx/cyclonedx-npm` during POC to emit a CycloneDX
  SBOM from `package.json`. Not wired into this seed version.
- Expect the SBOM to surface all `dependencies`/`devDependencies` entries
  above plus their transitive npm graph.

## License Detection
| Dependency | License |
|---|---|
| express | MIT |
| mongoose | MIT |
| jsonwebtoken | MIT |
| lodash | MIT |
| minimist | MIT |
| axios | MIT |
| multer | MIT |
| body-parser | MIT |
| cors | MIT |
| libxmljs2 | MIT |

This dependency set is MIT-heavy; add a GPL/LGPL npm package in the expanded
version if copyleft-detection testing needs a non-permissive data point.

## Framework-Specific Notes (Express)
This repo specifically targets the two Express-flagged categories from the
benchmark spec:
- **`eval()`** — `routes/macro.js` `POST /run` evaluates a user-supplied
  expression string directly.
- **Prototype Pollution** — `routes/admin.js` `POST /settings/merge` uses
  `lodash.merge()` on an object built directly from the request body,
  functionally confirmed by `test/injection.test.js`.

It also uses a genuine MongoDB backend (rather than a SQL database) so the
NoSQL Injection requirement in the benchmark spec has a real operator-based
injection surface (`$ne`, `$regex`) instead of a purely illustrative one.
