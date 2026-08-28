# Agentic Vulnerability Validation System

A service that validates scanner findings for reachability and exploitability, so
engineers can focus on what actually matters instead of triaging noise by hand.

Upload a Python codebase, it runs Semgrep, and shows you the real findings. Reachability
and exploitability analysis are designed (see `docs/`) and in progress.

## Status

- **Phase 0 (contracts, self-scan pipeline, UI):** done — real upload → Semgrep scan →
  findings, end to end.
- **Phase 1 (reachability):** design complete, not yet built. See
  [`docs/phase-1-foundations.md`](docs/phase-1-foundations.md) for the full design,
  including hands-on tool evaluation (AppThreat/atom) and why this project is building
  its own reachability engine instead of adopting an external tool.

Full project context, phase roadmap, and working notes: [`CLAUDE.md`](CLAUDE.md).
Design docs: [`docs/`](docs/).

## Running it

Two terminals:

```bash
# Backend
cd src
pip install -r ../requirements.txt -r ../requirements-dev.txt  # one-time
uvicorn api:app --reload --port 8000

# Frontend
cd src/frontend
npm install   # one-time
npm run dev
```

Open `http://localhost:5173`, pick a folder (try `src/sample-apps/todo-list-app`), hit
Scan.

## Tech stack

FastAPI + Uvicorn (backend), React + TypeScript + Vite (frontend), Semgrep (scanning),
pytest (testing). See [`docs/project-design.md`](docs/project-design.md) for the full
reasoning behind each choice.
