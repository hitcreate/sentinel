# Sentinel

**Security for apps built with AI.** Scan your Supabase database, web app, or server — A–F grade in 30 seconds.

53% of AI-generated code has security vulnerabilities. 83% of Supabase incidents are misconfigured RLS. Sentinel catches the mistakes Cursor, Bolt, Lovable, and Replit leave behind.

## Quick Start

```bash
# Clone and scan any web app (auto-detects Supabase)
git clone https://github.com/hitcreate/sentinel.git
cd sentinel
./sentinel scan https://myapp.vercel.app

# Or scan your Linux server directly
curl -sL sentinel.hitcreate.io/score.sh | bash
```

## Scan Types

### Supabase Security Scan

```bash
./sentinel scan --supabase https://xyz.supabase.co --anon-key eyJ...
```

| Check | Severity | What it finds |
|---|---|---|
| RLS enabled on all tables | Critical | Tables accessible to anyone with your anon key |
| No overly permissive policies | High | Policies that allow reading all rows |
| Anonymous write access blocked | Critical | Tables anyone can INSERT/UPDATE/DELETE |
| No service_role key in frontend | Critical | The key that bypasses ALL security, exposed in JS |
| Anon key + RLS protected | Critical | Anon key in frontend + disabled RLS = open database |
| Auth signup restricted | Medium | Public registration on internal tools |
| No public storage buckets | High | Files downloadable by anyone |
| Realtime requires auth | Medium | Live data changes visible without login |

### Linux Server Scan

```bash
curl -sL sentinel.hitcreate.io/score.sh | bash
```

| Category | Checks | What it looks for |
|---|---|---|
| Server Login | 4 | Password auth, root login, key-only SSH, brute-force protection |
| Firewall | 3 | Active firewall, default-deny, minimal open ports |
| Docker | 4 | 0.0.0.0 bindings, no-new-privileges, resource limits, socket exposure |
| HTTPS | 2 | Valid TLS certificates, security headers |
| File Safety | 3 | SSH key permissions, world-writable files, secret file permissions |
| System | 4 | Unattended upgrades, /tmp exec, ASLR, noexec mount |
| Monitoring | 3 | File integrity (AIDE), fail2ban, persistent logging |

## Output Modes

```bash
# Default: human-readable with pass/fail
./sentinel scan --supabase https://xyz.supabase.co --anon-key eyJ...

# Explain what's wrong and how to fix it
./sentinel scan --supabase https://xyz.supabase.co --anon-key eyJ... --explain

# Get only the fix commands (SQL for Supabase, shell for server)
./sentinel scan --supabase https://xyz.supabase.co --anon-key eyJ... --fix

# Machine-readable JSON
./sentinel scan --supabase https://xyz.supabase.co --anon-key eyJ... --json
```

## Grading

| Grade | Meaning |
|---|---|
| **A** | Well-secured. No critical issues. |
| **B** | Good shape, minor improvements possible. |
| **C** | Real risks present. Worth fixing soon. |
| **D** | Serious issues. Data may be exposed. |
| **F** | Critical problems. Database likely open to the world. |

Service role key in frontend code = automatic F.

## Why This Exists

We got hacked. Twice. Once through exposed Docker ports, once through an unpatched Next.js vulnerability. Both would have been caught by a 30-second scan.

Now we're building the security tool we wish existed when we shipped our first AI-built app.

## Coming Soon

- **Web app scanner** — headers, exposed secrets, CORS, debug endpoints (any URL)
- **GitHub Action** — security grade on every push
- **Sentinel Agent** — continuous monitoring with Telegram/Slack alerts

Star this repo to get notified.

## Built By

[HitCreate](https://hitcreate.io) — a small Australian team that builds products with AI.

## License

MIT
