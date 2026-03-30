# Sentinel

**Is your server hackable?** Know your security grade in 30 seconds.

Sentinel checks 23 things that hackers look for on your server and gives you an A–F grade. Free, open source, nothing leaves your machine.

## Quick Start

```bash
curl -sL sentinel.hitcreate.io/score.sh | bash
```

That's it. One command, 30 seconds, your server's security grade.

## What It Checks

| Category | Checks | What it looks for |
|---|---|---|
| Server Login | 4 | Password auth, root login, key-only SSH, brute-force protection |
| Firewall | 3 | Active firewall, default-deny, minimal open ports |
| Docker | 4 | 0.0.0.0 bindings, no-new-privileges, resource limits, socket exposure |
| HTTPS | 2 | Valid TLS certificates, security headers |
| File Safety | 3 | SSH key permissions, world-writable files, secret file permissions |
| System | 4 | Unattended upgrades, /tmp exec, ASLR, noexec mount |
| Monitoring | 3 | File integrity (AIDE), fail2ban, persistent logging |

## Grading

| Grade | Score | Meaning |
|---|---|---|
| **A** | 90%+ (no critical fails) | Well-hardened. Keep it up. |
| **B** | 80%+ | Good shape, minor improvements possible. |
| **C** | 65%+ | Real risks present. Worth fixing soon. |
| **D** | 50%+ | Serious issues. Attackers could likely get in. |
| **F** | Below 50% | Critical problems. Likely vulnerable now. |

## JSON Output

```bash
curl -sL sentinel.hitcreate.io/score.sh | bash -s -- --json
```

Returns machine-readable JSON for automation and CI pipelines.

## Trust & Transparency

- **Read-only** — looks at settings, changes nothing
- **Private** — zero network calls, no data sent anywhere
- **No install** — runs once and exits, leaves nothing behind
- **Open source** — read every line before you run it

## Why This Exists

We got hacked. Twice. A cryptocurrency miner ran silently on our server for five days. We thought we cleaned it up — they got back in through one misconfigured setting.

After the second hack, we wrote checks for every mistake that let it happen. Then we made them run in 30 seconds, because a security tool you don't use is worthless.

That script became Sentinel.

## Coming Soon: Sentinel Agent

Continuous monitoring that watches your server 24/7 and alerts you on Telegram or Slack if your grade drops. Uses AI to explain findings in plain English.

Star this repo to get notified.

## Built By

[HitCreate](https://hitcreate.io) — a small Australian team that builds products with AI and runs our own servers.

## License

MIT
