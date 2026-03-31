# Sentinel

[![Sentinel Grade](https://img.shields.io/badge/Sentinel-A%20(94%25)-brightgreen?style=flat&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIyNCIgaGVpZ2h0PSIyNCIgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJub25lIiBzdHJva2U9IiNmNTllMGIiIHN0cm9rZS13aWR0aD0iMiIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJvdW5kIj48cGF0aCBkPSJNMTIgMjJzOC00IDgtMTBWNWwtOC0zLTggM3Y3YzAgNiA4IDEwIDggMTB6Ii8+PC9zdmc+)](https://sentinel.hitcreate.io)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Security for apps built with AI.** Scan your web app, Supabase database, or server — A–F grade in 30 seconds.

53% of AI-generated code has security vulnerabilities. 83% of Supabase incidents are misconfigured RLS. Sentinel catches the mistakes Cursor, Bolt, Lovable, and Replit leave behind.

**The only scanner that checks your server, web app, AND Supabase in one tool.**

## Quick Start

```bash
git clone https://github.com/hitcreate/sentinel.git
cd sentinel

# Scan any web app
./sentinel scan https://your-app.vercel.app

# Scan your Supabase database
./sentinel scan --supabase https://your-app.vercel.app

# Scan your Linux server
./sentinel scan --server
```

## Demo Output

```
Sentinel Web App Security Scan
══════════════════════════════

  Target: https://your-app.vercel.app
  Status: 200

── Security Headers ──
  ✓ Strict-Transport-Security (HSTS)             PASS
  ✓ Content-Security-Policy (CSP)                PASS
  ✗ X-Content-Type-Options: nosniff              FAIL (medium)
  ✓ X-Frame-Options / frame-ancestors            PASS

── Exposed Secrets & Files ──
  ✓ .env file not accessible                     PASS
  ✓ .git directory not accessible                PASS
  ✗ No API keys in page source                   FAIL (critical)
  ✓ No secrets in NEXT_PUBLIC_ vars              PASS

── Transport & Access ──
  ✓ CORS does not allow all origins              PASS
  ✓ TLS certificate valid (7+ days)              PASS
  ✗ Admin/debug endpoints not exposed            FAIL (high)

  Grade: C (72%)
  13 of 18 checks passed · 2 critical/high · 1 warnings

  Run with --explain to see what's wrong and how to fix it.
```

## Three Scan Types

### Web App Scan (18 checks)

Scans any deployed URL for security misconfigurations.

| Category | What it checks |
|---|---|
| Security Headers (8) | HSTS, CSP, CSP quality, X-Content-Type, X-Frame-Options, Referrer-Policy, Permissions-Policy |
| Exposed Secrets (6) | .env files, .git directory, source maps, debug mode, 15 API key patterns (AWS, Stripe, OpenAI, Anthropic, GitHub, Supabase service_role, Twilio, SendGrid, Mailgun, database URIs, private keys, Firebase), NEXT_PUBLIC_ leaks |
| Transport & Access (4) | CORS wildcard, TLS validity, HTTPS redirect, admin endpoint exposure |

### Supabase Scan (8 checks)

Deep security audit of your Supabase project.

| Category | What it checks |
|---|---|
| RLS & Data Access (3) | Tables protected by RLS, overly permissive policies, anonymous write access |
| Key Exposure (2) | Service role key in frontend code, anon key without RLS protection |
| API Security (3) | Auth signup restrictions, public storage buckets, realtime authentication |

### Server Scan (23 checks)

Linux server hardening assessment.

| Category | What it checks |
|---|---|
| Server Login (4) | Password auth, root login, key-only SSH, brute-force protection |
| Firewall (3) | Active firewall, default-deny, minimal open ports |
| Docker (4) | 0.0.0.0 bindings, no-new-privileges, resource limits, socket exposure |
| HTTPS (2) | Valid TLS, security headers |
| File Safety (3) | SSH key permissions, world-writable files, secret file permissions |
| System (4) | Unattended upgrades, /tmp exec, ASLR, noexec mount |
| Monitoring (3) | File integrity (AIDE), fail2ban, persistent logging |

## Output Modes

```bash
./sentinel scan <url>              # Human-readable (default)
./sentinel scan <url> --explain    # Show what's wrong + how to fix it
./sentinel scan <url> --fix        # Output only fix commands
./sentinel scan <url> --json       # Machine-readable JSON
```

## GitHub Action

Add security scanning to your CI/CD pipeline:

```yaml
# .github/workflows/security.yml
name: Security Scan
on: [push, pull_request]

jobs:
  sentinel:
    runs-on: ubuntu-latest
    steps:
      - name: Sentinel Security Scan
        uses: hitcreate/sentinel@main
        with:
          url: 'https://your-app.vercel.app'
          min-grade: 'C'
```

Supabase scan in CI:

```yaml
      - name: Sentinel Supabase Scan
        uses: hitcreate/sentinel@main
        with:
          scan-type: 'supabase'
          url: 'https://your-app.vercel.app'
          anon-key: ${{ secrets.SUPABASE_ANON_KEY }}
          min-grade: 'C'
```

## Score Badge

After scanning, generate a badge for your README:

```bash
./sentinel scan <url> --json | bash badge.sh
```

Output:
```
[![Sentinel Grade](https://img.shields.io/badge/Sentinel-A%20(94%25)-brightgreen)](https://sentinel.hitcreate.io)
```

## Grading

| Grade | Meaning |
|---|---|
| **A** | Well-secured. No critical issues. |
| **B** | Good shape, minor improvements possible. |
| **C** | Real risks present. Worth fixing soon. |
| **D** | Serious issues. Data may be exposed. |
| **F** | Critical problems. Database likely open to the world. |

Service role key in frontend = automatic F.

## Why This Exists

We got hacked. Twice. Once through exposed Docker ports (Supabase bound to 0.0.0.0), once through an unpatched Next.js vulnerability (CVE GHSA-9qr9-h5gf-34mp). Both times, a 30-second scan would have caught it.

We built the security tool we wish existed when we shipped our first AI-built app.

## How It Compares

| | Sentinel | Lynis | Wazuh | ScanVibe |
|---|---|---|---|---|
| Server scanning | Yes (23 checks) | Yes (304 checks) | Yes (full SIEM) | No |
| Web app scanning | Yes (18 checks) | No | No | Yes |
| Supabase scanning | Yes (8 checks) | No | No | Partial |
| Install time | <1 minute | 2 minutes | Hours | None (SaaS) |
| RAM usage | ~10 MB | ~10 MB | 4-16 GB | 0 (SaaS) |
| Target user | Indie devs | Sysadmins | SOC teams | Vibe coders |
| Price | Free | Free / $3/mo | Free / $571/mo | Free / $9/mo |

Sentinel is the only tool that scans your **server + web app + Supabase** in one command.

## Coming Soon

- **Web UI** — paste a URL, get results (no install needed)
- **Scheduled scans** — daily/weekly with Telegram/Slack alerts
- **More checks** — expanding from 49 to 100+
- **Firebase/Appwrite** — BaaS scanning beyond Supabase

Star this repo to get notified.

## Built By

[HitCreate](https://hitcreate.io) — a small Australian team that builds products with AI.

## License

MIT
