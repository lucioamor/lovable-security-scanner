# Lovable Project Visibility & Hygiene Audit

A self-service audit tool for Lovable.dev users to review their own projects for exposed credentials, misconfigured Supabase RLS policies, and sensitive data left in source code or chat history.

Run it against your own account. Get a clear report. Fix what needs fixing.

## Why this exists

Reports of credential leakage, data breaches, and access vulnerabilities affecting low-code platforms have become more common as these tools gain adoption — and Lovable is no exception to the ecosystem. When developers move fast, it's easy to leave API keys hardcoded, skip RLS configuration, or forget that chat history may be readable beyond its intended scope.

This tool doesn't place blame — it places the solution in your hands. Instead of waiting for a platform to alert you, you audit yourself, find what's exposed, and fix it. That's it.

## What it checks

- **Credentials in source** — 16 patterns including Supabase, OpenAI, Stripe, AWS, JWT, GitHub, Firebase
- **PII in project data** — 7 patterns including email, phone, CPF/CNPJ, credit card, Stripe customer IDs
- **Supabase Row-Level Security** — non-invasive read-only check of RLS configuration on your tables
- **Project access visibility** — flags projects where source or chat endpoints may be accessible beyond your intent
- **Hygiene score** — 0–100 weighted score with Critical / High / Medium / Low / Clean severity levels

## Two ways to run it

### 🧩 Chrome Extension (recommended)

Runs in your browser, reads your own `lovable.dev` session automatically — no manual token handling required.

1. Open Chrome → `chrome://extensions`
2. Enable **Developer mode** (top right toggle)
3. Click **Load unpacked** and select the `extension/` directory from this repo
4. Pin the icon to your toolbar and click to inspect

### 🖥️ Web App (development/demo)

```bash
npm install
npm run dev
```

Opens at `http://localhost:5173`. Real inspections from the web app require a CORS proxy since browsers block cross-origin requests to `api.lovable.dev`. The extension is the recommended path.

## Languages

🇺🇸 English (default) · 🇧🇷 Português · 🇪🇸 Español

## Export

JSON and CSV reports available from the dashboard.

## Architecture

```
├── extension/                     # Chrome Extension (Manifest V3)
│   ├── manifest.json              # Permissions + service worker config
│   ├── background.js              # Service worker — audit orchestrator
│   ├── popup.html                 # Quick-view popup
│   ├── sidepanel.html/js/css      # Full dashboard in side panel
│   ├── icons/                     # Extension icons
│   └── lib/                       # Core modules (plain JS)
│       ├── api-client.js          # Lovable API + chrome.cookies auth
│       ├── audit-engine.js        # Inspection orchestrator
│       ├── data-patterns.js       # 16 credential + 7 PII patterns
│       ├── health-scorer.js       # Scoring algorithms
│       └── i18n.js                # Trilingual translations
│
├── src/                           # Web App (Vite + TypeScript)
│   ├── main.ts                    # App: state, rendering, events
│   ├── style.css                  # Dark theme design system
│   └── lib/                       # Core modules (TypeScript)
│       ├── types.ts               # TypeScript interfaces
│       ├── data-patterns.ts       # Pattern engine
│       ├── health-scorer.ts       # Health scoring
│       ├── lovable-api-client.ts  # API client (manual token)
│       ├── supabase-inspector.ts  # RLS tester
│       ├── audit-engine.ts        # Orchestrator
│       └── i18n.ts                # Translations
│
└── package.json
```

## Principles

1. **Tokens never leave your browser** — never transmitted to external servers
2. **Response bodies stay local** — only metadata and masked findings are retained in the report
3. **Read-only** — only GET requests against `api.lovable.dev`, never POST/PUT/DELETE
4. **Rate limited** — 1 request/second sustained to avoid overloading the API
5. **Identified** — requests include `X-Client: NXLV-Audit/1.0`

## Scope

This tool is for auditing your own account. The Chrome Extension operates only on projects belonging to the authenticated user's session. It is not designed for, and cannot be used for, inspecting projects belonging to other accounts.

## Author

Built by [Lucio Amorim](https://linkedin.com/in/lucioamorim).

## License

MIT
