# Zonewalk

DNS & Mail Diagnostics for cPanel/Plesk hosting environments.

Originally a Bash tool for 1-grid L3 support engineers. This is a complete Python rewrite — cleaner, extensible, and portable.

## Features

- **Nameserver detection** — identifies 1-grid vs external DNS providers
- **DNS record audit** — A, MX, NS, SOA, TXT, PTR
- **Mail authentication** — SPF, DKIM, DMARC validation
- **PTR consistency** — forward-confirm PTR against A record
- **Email header analysis** — spoofing checks, SPF/DKIM/DMARC auth results, hop-by-hop trace with delays, block reason detection
- **Global propagation check** — queries 10 resolvers worldwide
- **Port scanning** — 17 common service ports
- **IP reputation** — checks 6 blocklists (Spamhaus, SpamCop, SORBS, etc.)
- **Subdomain enumeration** — 25+ common subdomains
- **SSL expiry** — certificate validity check
- **Issue diagnosis** — targeted checks for `mail-send`, `mail-recv`, `web-down`, `dns-fail`, `propagation`, `spam-received`
- **Technician fix guide** — cPanel/Plesk repair steps for each issue

## Quick start

```bash
git clone https://github.com/robertsibanda/zonewalk
cd zonewalk

# Basic check
python3 -m zonewalk example.co.za

# Outbound mail diagnosis
python3 -m zonewalk example.co.za --issue mail-send

# Port scan + reputation
python3 -m zonewalk example.co.za --ports --ip-reputation

# Parse email headers (file or paste)
python3 -m zonewalk example.co.za --headers email.txt
cat email.txt | python3 -m zonewalk example.co.za --headers -
```

## Requirements

- Python 3.10+
- `dig` (dnsutils/bind-utils)
- `curl` (for HTTP checks)
- `whois` (optional, for expiry info)
- `openssl` (optional, for SSL expiry)
- `host` (optional, for PTR lookup)

No pip dependencies — all stdlib.

## Usage

```
usage: zonewalk [-h] [--deep] [--ports] [--ip-reputation] [--skip-propagation]
                [--guide] [--ptr] [--headers [FILE]]
                [--issue {mail-send,mail-recv,web-down,dns-fail,propagation,wrong-domain,spam-received}]
                [domain]
```

## Chain of Trust (diagnostic logic)

```
Is DNS pointing to us?     → Nameserver Check
Is the mail routing right? → MX Record Check
Is Gmail rejecting us?     → Log Analysis (SPF/DKIM/DMARC)
Can the server write mail? → Permissions/Quota (SSH)
```

## Project structure

```
zonewalk/
├── pyproject.toml
├── README.md
└── zonewalk/
    ├── __init__.py
    ├── __main__.py
    ├── cli.py        # CLI entry point (argparse)
    ├── checks.py     # DNS record checks
    ├── network.py    # HTTP, ports, propagation, header analysis
    └── utils.py      # Terminal styling, helpers
```

## License

MIT
