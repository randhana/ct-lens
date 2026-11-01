# ct-lens web dashboard

A Vite + React + TypeScript front-end for the ct-lens API. It runs a scan, polls
for progress, and renders the ecosystem "report card" (CA market share, lifetime
distribution, issuance over time) plus the security findings — all from the same
core engine the CLI uses.

## Run it

Start the API (from the repo root):

```bash
pip install -e ".[api]"
uvicorn ct_lens.api.app:app --port 8000
```

Then start the dashboard:

```bash
cd web
npm install
npm run dev          # http://localhost:5173
```

The dev server proxies `/api` to `http://127.0.0.1:8000` (override with the
`CT_LENS_API` env var — see `vite.config.ts`).

## Build for production

```bash
npm run build        # outputs to web/dist/
npm run preview      # serve the production build locally
```

## Project layout

```
web/
├── index.html
├── src/
│   ├── main.tsx            # entry point
│   ├── App.tsx             # state machine: idle → running → done/error
│   ├── api.ts              # typed API client + poll-to-completion helper
│   ├── types.ts            # response types mirroring the API
│   ├── styles.css          # light/dark theme via CSS variables
│   └── components/
│       ├── ScanForm.tsx    # target input + anonymise toggle
│       ├── StatCards.tsx   # headline numbers
│       ├── Charts.tsx      # CA share / lifetime / issuance (Recharts)
│       └── Findings.tsx    # severity-ordered findings table
└── vite.config.ts
```
