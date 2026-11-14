# Frontend

React 19 + TypeScript + Vite, plain CSS, no runtime dependencies beyond React.

```bash
npm install
npm run dev      # http://localhost:5173 — expects the API on http://localhost:8000
npm run build    # type-check + production build
npm run lint     # oxlint
```

Set `VITE_API_URL` to point at a deployed backend.

## How it's organized

- **`src/types.ts`** is the API contract. Fields marked *PROPOSED* are optional. The UI
  renders them as soon as the backend returns them.
- **`src/lib/`** holds plain TypeScript with no JSX: joining findings with their verdicts,
  priority scoring, upload preflight, exports, storage and filters.
- **`src/components/`** holds the views.
- **`src/lib/capabilities.ts`** lists which features are live on the server, which run in
  the browser, and which are planned. It drives the in-app Roadmap panel and the
  `PLANNED` tags, so nothing in the UI pretends to work when it doesn't.

Full feature list and backend contract:
[`docs/frontend-feature-roadmap.md`](../../docs/frontend-feature-roadmap.md).
