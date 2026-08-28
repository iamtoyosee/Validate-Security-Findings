# Project Design: Goals, Scope, and Constraints

This doc explains what the project is for and why it's shaped the way it is — written
for a person trying to understand the design and the reasoning behind its constraints,
not as agent orientation (that's `CLAUDE.md`).

## Goal

A service that takes (1) a codebase and (2) scanner findings against it, and validates
which findings are actually exploitable — so engineers can focus on what matters instead
of triaging a large noisy findings list by hand.

Two distinct claims the system produces, not to be conflated:
- **Reachable** — a claim about the call graph (there is a control-flow path from an
  external entry point to the vulnerable code).
- **Exploited** — a claim backed by evidence (an agent, in a sandbox or reasoning
  statically, actually assessed or triggered the unsafe behavior and produced a written
  judgment or captured proof).

Reachability is the cheap filter that narrows findings down before spending agent/sandbox
budget on exploit attempts. It is not itself an exploitability claim.

## Scope

- **First-party (1P) vulnerabilities only** — code written by the team, found by
  SAST-style tools. Explicitly NOT third-party/dependency (SCA) vulnerabilities.
- **Primary language: Python.** All tooling choices should be evaluated Python-first.
- **Primary scanner in use: Semgrep**, OSS engine, run without a Semgrep login/token.
  Known OSS-engine limitations already discovered: the `lines` and `fingerprint` fields
  in JSON output return `"requires login"` instead of real values — see
  `docs/phase-0-foundations.md`.

## Tech stack

**Backend: FastAPI + Uvicorn.** Decided over Flask/Django (Python's "monolith-capable"
frameworks) and over keeping the web layer in Express (the user's existing fluency,
calling into Python via subprocess) — chosen deliberately as a learning investment, not
just technical fit: the schemas (`NormalizedFinding`, `ReachabilityVerdict`,
`ExploitabilityVerdict`) are already typed dataclasses, and FastAPI serializes/validates
them as API responses directly from those type hints, with an auto-generated `/docs`
page for free. Same architectural role as Express — a JSON API for a separate frontend,
not server-rendered HTML — so the existing mental model (routes, ports, JSON responses)
carries over directly.

**Frontend: React + TypeScript + Vite.** Revised from an initial "plain HTML/JS, no
framework" call — reconsidered once `src/ui/index.html`'s hand-rolled view-switching
(`showView()`, manual `innerHTML` templating, manually wired event listeners) started
showing real seams, exactly what React's declarative rendering and component state
exist to replace. Unlike the backend framework decision, this isn't a learning
investment — the user is already fluent in React, so there's no ramp-up cost, only the
upside of better structure as the UI grows (filtering, an upload form, more detail
views in later phases). TypeScript extends the typed-contract discipline already used
end-to-end (dataclasses, FastAPI's type-hint-driven validation) across the frontend too.

Deliberately **not** Next.js — its bundled backend/routing would duplicate FastAPI,
which already owns that role; Vite gives just the dev server + build step for a plain
SPA, nothing more. Deliberately **no state library or router yet** (plain `useState` for
view switching) — the current UI is a handful of views, and Redux/Zustand/React Router
would be solving a scale problem that doesn't exist yet.

The earlier static mockup (`src/ui/index.html`) validated the drill-down structure and
real-vs-illustrative data split; it has since been replaced by the real React+TS app at
`src/frontend/`, wired to the live `src/api.py` `/api/scan` endpoint.

**Testing: pytest**, already in use since Phase 0.

**Python version: `>=3.11` floor, not an exact pin.** Phase 0 surfaced a real bug from
an undeclared version assumption (`int | None` syntax silently failing on the system's
default Python 3.9.6, since fixed to `Optional[int]` — the code is actually 3.9+
compatible again). `3.11` isn't a technical requirement of any current code; it's a
deliberately chosen modern baseline (meaningfully better performance and error messages
than 3.10), not the exact `3.14` installed locally via Homebrew — a floor should be the
*lowest* reasonable version, not whatever happens to be on one machine, so it stays
correct if this ever runs somewhere else (CI, a teammate's machine, a deploy target)
with an older-but-still-modern Python. Expressed in `pyproject.toml` as
`requires-python = ">=3.11"` once that file exists — not yet added.

**Backend status:** `src/api.py` now exists — a single `POST /api/scan` endpoint that
runs the self-scan pipeline (upload → Semgrep → normalize) and returns findings as JSON,
wired to the real `src/frontend/` React app. Phase 1's reachability output isn't part of
the response yet; the frontend's Reachability/Exploitability sections are placeholders
until that lands.

## Deployment modes

Two distinct ways findings get into the system, both converging on the same
`NormalizedFinding` contract (see `docs/phase-0-foundations.md`):

- **Self-scan mode** — caller supplies a codebase (no findings). The service runs
  Semgrep OSS itself (unauthenticated — no Semgrep login needed — but `--config=auto`
  does require network access and can't run with metrics disabled; reversed from an
  earlier pinned-local-ruleset approach, see `docs/phase-0-foundations.md`) and adapts
  the output. **MVP:
  codebase is a local path/direct upload, not a GitHub URL** — no cloning, no SHA pinning
  needed, since there's no separate fetch step: the code received *is* the code scanned,
  in the same operation. GitHub URL + cloning is a documented future/full-scale design
  (`docs/phase-0-foundations.md`), not built now. Includes a set of pre-loaded
  ground-truth example codebases for zero-setup quick-start (see "Testing/validation
  approach" below).
- **Findings-provided mode** — caller supplies both a codebase and a pre-computed
  findings list, mirroring an enterprise setup where upstream scanners already ran and
  were deduped before reaching this service. Assumes the future git-URL codebase source,
  so practically deferred alongside that.

This project also doubles as a demonstration piece for a potential internal team switch
(TPM → security engineering); self-scan mode exists specifically so it can be shared as
a no-setup, "just try it" demo.

**Access model:** distribution is access-controlled (specific invited people, private
link), not fully public/anonymous. This lowers the abuse-surface stakes of self-scan mode
considerably (not exposing arbitrary code execution to the open internet) — basic sane
limits (repo size cap, clone timeout) are still worth having cheaply, but a heavy public
safety write-up is not urgent. No presentation is planned — this gets shared via a short
email with a live link; the README and the tool's own output need to carry the value on
their own in the first 5-10 minutes of someone's attention.

## Testing/validation approach (applies across phases)

Two unrelated axes, do not conflate:
- **What the product accepts** (input surface) — any codebase a user provides (MVP: local
  path/upload — see "Deployment modes"), never restricted to only the fixed fixture set.
- **How correctness is verified** — requires a small number (2-3) of deliberately
  controlled codebases with known, seeded ground truth (reachable/unreachable), used as
  a private test suite. These fixtures never limit what a real user can point the tool
  at; they exist purely to let us claim "validated against N known cases, correct on M."
  They also double as zero-setup "try this now" quick-start options in the demo itself.

## Target output shape (the funnel)

Locked target for the final report, validated against real prior art (Endor Labs
publishes a similar "8,450 → 1,200 → 329" funnel publicly):

`Scanner found 50 → Reachability narrows to 20 reachable → Exploit-validation confirms
5 as exploited/critical (fix first) → 15 remain reachable-but-unconfirmed (NOT proven
safe, just unconfirmed) → top N critical list surfaced.`

This funnel shape is the actual deliverable users see — output presentation quality
should be treated as part of Phase 1's "done" bar, not deferred to a late phase.

**UI shape (drill-down, not a flat report):** the funnel counts are the top-level view.
Clicking into a stage (e.g. "200 reachable") shows a list of findings with their
reachability reason inline; clicking a specific finding shows the full reachability
detail page (`ReachabilityVerdict` — path, entry point, confidence), which links back to
the underlying finding detail page (`NormalizedFinding` — file, line, message, snippet,
as Semgrep reported it and as we normalized it). Exploitability follows the same pattern
(`ExploitabilityVerdict`), linked the same way. See `docs/phase-0-foundations.md` for the
schemas.
