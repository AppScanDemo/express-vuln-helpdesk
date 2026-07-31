# HelpdeskVuln — Node.js Express Intentionally Vulnerable Benchmark App

> ⚠️ **DO NOT DEPLOY. DO NOT USE IN PRODUCTION.**
> Intentionally vulnerable benchmark application (OWASP Benchmark / WebGoat
> style) for evaluating SAST/SCA/Secret-scanning tools during commercial
> product POCs. Every vulnerability is intentional and marked with a
> `// VULN:` comment and CWE ID. Every secret is fake.

## Business Scenario
A fictional IT helpdesk / ticketing system: agents and customers, support
tickets, an admin console, ticket-attachment upload, ticket search, and a
"macro" feature used to demonstrate `eval()`-based code injection.

## Stack
- Node.js 18, Express 4.16.0 (deliberately old — see `docs/FINDINGS.md`)
- MongoDB via Mongoose (enables a genuine NoSQL/operator-injection demo)
- `jsonwebtoken` (old version) for JWT auth

## Running

```bash
cp .env.example .env
docker compose up --build
```

App available at `http://localhost:8085`. MongoDB runs as a companion
`mongo` service in `docker-compose.yml`.

## Default (Intentionally Hardcoded) Accounts
| username | password    | role   |
|----------|-------------|--------|
| admin    | admin123    | admin  |
| agent1   | Password1   | agent  |

See `docs/FINDINGS.md` for the full expected SAST/SCA/Secret-detection
results, CWE/OWASP/ASVS mapping, SBOM, and license notes.

## Layout
```
routes/       auth, tickets, admin, upload, search, macro
models/       User, Ticket (Mongoose schemas)
middleware/   weak JWT auth middleware
config/       MongoDB connection
docs/         Expected findings, CWE/OWASP mapping, SBOM/license notes
.github/workflows/  CI pipeline stub incl. SAST/SCA/secret-scan stages
Jenkinsfile   Jenkins pipeline stub with severity gate
```

## Not Included Yet
Seed version. Planned expansion on request: full CRUD ticket UI, background
job/queue example, GraphQL variant, CycloneDX/SPDX SBOM wired into CI,
typosquat fixture (see `docs/FINDINGS.md` note).
