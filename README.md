# 🛡️ Lovable Security Scanner

Defensive audit tool for Lovable.dev projects. Detects exposed credentials, BOLA/IDOR vulnerabilities, missing Supabase RLS policies, and PII leakage across your projects.

## Context

Lovable has a [documented BOLA vulnerability](https://hackerone.com) affecting projects created before November 2025. This scanner helps you identify which of your projects may be affected and what remediation steps to take.

## Features

- **BOLA Detection** — Tests if source code and chat endpoints are accessible without ownership checks
- **16 Secret Patterns** — Supabase, OpenAI, Stripe, AWS, JWT, GitHub, Firebase, and more
- **7 PII Patterns** — Email, LinkedIn, CPF/CNPJ, phone, credit card, Stripe customer IDs
- **Supabase RLS Scanner** — Non-invasive check of Row-Level Security on your tables
- **Risk Scoring** — 0-100 weighted score with Critical/High/Medium/Low/Clean severity
- **Trilingual UI** — 🇺🇸 English (default), 🇧🇷 Português, 🇪🇸 Español
- **Export** — JSON and CSV reports

## Quick Start

```bash
npm install
npm run dev
```

Open `http://localhost:5173`, load demo data to explore, or configure your Lovable token to scan your own projects.

## How to Get Your Token

1. Open [lovable.dev](https://lovable.dev) in your browser
2. Open DevTools (F12) → Network tab
3. Perform any action on the platform
4. Find a request to `api.lovable.dev`
5. Copy the `Authorization: Bearer eyJ...` header value (without "Bearer ")
6. Paste in the Configuration page

## Architecture

```
src/
├── main.ts                    # App: state, rendering, events
├── style.css                  # Dark theme design system
└── lib/
    ├── types.ts               # TypeScript interfaces
    ├── security-rules.ts      # Secret + PII pattern engine
    ├── risk-scorer.ts         # Scoring + severity calculation
    ├── lovable-api-client.ts  # Lovable API HTTP client
    ├── supabase-scanner.ts    # Non-invasive RLS tester
    ├── scanner-engine.ts      # Scan orchestrator
    └── i18n.ts                # Trilingual translations
```

## Disclaimer

This tool is designed for **defensive use only** — to audit your own projects. Tokens are stored exclusively in your browser's localStorage. No data is transmitted to external servers.

## Credits

Created by **[Lucio Amorim](https://linkedin.com/in/lucioamorim)** — Lovable Ambassador

## License

MIT
