# Prior Art — Reachability Analysis & Agentic Exploit Validation

Researched before committing to Phase 1 tooling. All verified via live web search, not
pulled from memory alone (these projects rename/move governance frequently).

## Reachability analysis (static, call-graph/CPG-based)

- **Joern** — https://github.com/joernio/joern — CPG-based, supports Python among other
  languages. `reachableByFlows` does backward sink→source traversal across the call
  graph. Mature, actively maintained. OSS.
- **AppThreat/atom** — https://github.com/AppThreat/atom — precomputed source→sink paths,
  framework-tagged entry points. **Governance recently moved to the AboutCode foundation**
  (home of ScanCode/VulnerableCode) — still active, but re-check current maintainership
  before betting the MVP on it. OSS.
- **pyxray** — https://github.com/grgalex/pyxray — Python-specific call-graph builder for
  reachability/dead-code detection. Closest thing to a Python-native version of Phase 1's
  goal.
- **Vulture** — standard Python dead-code scanner. Much shallower than call-graph
  reachability (no call graph), useful only as a baseline comparison.
- **OWASP dep-scan** — https://github.com/owasp-dep-scan/dep-scan — uses atom under the
  hood, but for *dependency* (SCA) reachability, not first-party — out of scope given
  this project's 1P focus, reference only.
- **Endor Labs, Semgrep Assistant, Aikido, Coana** — all publicly describe function-level
  reachability funnels for prioritization (Endor's public "8,450 → 1,200 → 329" funnel
  example is a good story to reuse when explaining this system to engineers later). All
  **proprietary** — architecture reference only, not usable as a base.

## Agentic exploit-validation (LLM agent confirms/exploits a specific finding)

- **AXE** (arXiv 2602.14345, "Grey-Box Exploitability Confirmation for Localized
  Vulnerability Reports") — closest academic match to this project's exact goal:
  multi-agent framework takes a CWE + vulnerable code location (i.e. a scanner finding)
  and attempts real exploitation via plan → explore → execute-and-observe. 30% confirmed
  exploit rate, 3x over black-box baselines. Worth reading even without released code.
- **OpenAnt** (arXiv 2606.19149) — builds a disposable Docker exploit environment per
  finding, runs the attack, tears it down. Closely matches the "sandbox per finding"
  model planned for Phase 4/5. 75.8% reproduction rate on their benchmark.
- **Trail of Bits — Buttercup** — https://github.com/trailofbits/buttercup — AIxCC 2nd
  place, fully open-sourced. Finds *and patches* vulns in real source, not SCA. OSS.
- **Team Atlanta — Atlantis** — https://github.com/Team-Atlanta/aixcc-afc-atlantis —
  AIxCC 1st place. OSS.
- **Theori** — https://github.com/theori-io/aixcc-afc-archive — AIxCC 3rd place, notably
  used a *purely static* validation approach (no live exploit) — useful contrast if a
  non-dynamic fallback path is ever wanted. OSS.
- **Strix** — https://github.com/usestrix/strix — agentic pentest platform with a real
  exploitation toolkit (HTTP manipulation, browser automation, Python runtime). Good
  reference for what tools the Phase 5 agent needs. OSS.
- **PentestGPT** — general autonomous pentest agent, not finding-specific. Architecture
  reference only. OSS.
- **XBOW** — the commercial product is proprietary; what appears open-source under the
  XBOW name is only their benchmark set, not the agent itself.
- **CAI (Cybersecurity AI framework)** — real project, but search turned up unofficial
  mirror repos rather than a clearly canonical upstream — verify the actual source before
  trusting any specific repo.

## Recommended reading order

1. **AXE** and **OpenAnt** papers — both are specifically "take one finding, confirm
   exploitability, produce evidence," i.e. exactly Phase 5.
2. **pyxray** — Python-specific, closest to Phase 1's actual need, worth a first look
   before evaluating Joern/atom.
