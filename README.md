# 🛡️ Lovable Security Scanner

Defensive audit tool for Lovable.dev projects. Detects exposed credentials, BOLA/IDOR vulnerabilities, missing Supabase RLS policies, and PII leakage across your projects.

## Context

Lovable has a [documented BOLA vulnerability](https://hackerone.com) affecting projects created before November 2025. This scanner helps you identify which of your projects may be affected and what remediation steps to take.

## Two Modes

### 🧩 Chrome Extension (recommended)

The extension runs directly in your browser, reads your Lovable session cookie automatically (no manual token copy), and bypasses CORS restrictions natively.

#### Install (Developer Mode)

1. Open Chrome → `chrome://extensions`
2. Enable **Developer mode** (top right toggle)
3. Click **Load unpacked**
4. Select the `extension/` directory from this repo
5. Pin the 🛡️ icon in your toolbar

#### Usage

- **Click the icon** → Quick scan trigger + stats popup
- **Open Dashboard** → Full side panel with results, findings, and export
- The extension reads your `lovable.dev` session automatically — just be logged in

### 🖥️ Web App (development/demo)

The Vite web app provides the same dashboard for development and demo purposes.

```bash
npm install
npm run dev
```

Open `http://localhost:5173`. Note: real scans from the web app require a CORS proxy since browsers block cross-origin requests to `api.lovable.dev`.

## Features

- **BOLA Detection** — Tests if source code and chat endpoints are accessible without ownership checks
- **16 Secret Patterns** — Supabase, OpenAI, Stripe, AWS, JWT, GitHub, Firebase, and more
- **7 PII Patterns** — Email, LinkedIn, CPF/CNPJ, phone, credit card, Stripe customer IDs
- **Supabase RLS Scanner** — Non-invasive check of Row-Level Security on your tables
- **Risk Scoring** — 0-100 weighted score with Critical/High/Medium/Low/Clean severity
- **Trilingual UI** — 🇺🇸 English (default), 🇧🇷 Português, 🇪🇸 Español
- **Export** — JSON and CSV reports

## Architecture

```
├── extension/                     # Chrome Extension (Manifest V3)
│   ├── manifest.json              # Permissions + service worker config
│   ├── background.js              # Service worker — scan orchestrator
│   ├── popup.html                 # Quick-view popup
│   ├── sidepanel.html/js/css      # Full dashboard in side panel
│   ├── icons/                     # Extension icons
│   └── lib/                       # Core modules (plain JS)
│       ├── api-client.js          # Lovable API + chrome.cookies auth
│       ├── scanner-engine.js      # Scan orchestrator
│       ├── security-rules.js      # 16 secret + 7 PII patterns
│       ├── risk-scorer.js         # Scoring + severity
│       └── i18n.js                # Trilingual translations
│
├── src/                           # Web App (Vite + TypeScript)
│   ├── main.ts                    # App: state, rendering, events
│   ├── style.css                  # Dark theme design system
│   └── lib/                       # Core modules (TypeScript)
│       ├── types.ts               # TypeScript interfaces
│       ├── security-rules.ts      # Pattern engine
│       ├── risk-scorer.ts         # Scoring
│       ├── lovable-api-client.ts  # API client (manual token)
│       ├── supabase-scanner.ts    # RLS tester
│       ├── scanner-engine.ts      # Orchestrator
│       └── i18n.ts                # Translations
│
└── package.json
```

## Security Principles

1. **Tokens never leave your browser** — never transmitted to external servers
2. **Response bodies stay local** — only metadata and masked findings are stored
3. **Read-only** — only GET requests, never POST/PUT/DELETE against `api.lovable.dev`
4. **Rate limited** — 1 request/second sustained to avoid overloading the API
5. **User-Agent identified** — requests include `X-Client: NXLV-Scanner/1.0`

## Disclaimer

This tool is designed for **defensive use only** — to audit your own projects. The Chrome Extension operates only on projects belonging to your authenticated Lovable account.

## Credits

Created by **[Lucio Amorim](https://linkedin.com/in/lucioamorim)** — Lovable Ambassador

## License

MIT
