# Engineering Standards — Aircraft Ops Coordination Tool

## Project
- **AirOps-Coord-Tool** — Python/Flask web app for tracking aircraft operations during emergencies
- Runs on Raspberry Pi / small servers, fully Dockerized
- Life-safety adjacent: operators depend on this during real incidents. Reliability over cleverness.

## Tech Stack
- **Backend:** Python 3.10, Flask, SQLite, Waitress (WSGI), APScheduler
- **Frontend:** Vanilla JS (ES6 modules), no framework
- **Radio:** Direwolf (AX.25/KISS-TCP), PAT (Winlink), rtl_airband (SAME alerts)
- **Deploy:** Docker multi-platform (amd64, arm64, arm/v7) via `ghcr.io/xmutantson/aircraft_ops_tool`
- **Build:** `wsl docker buildx build --builder multiplatform --platform linux/amd64,linux/arm64,linux/arm/v7 -t ghcr.io/xmutantson/aircraft_ops_tool:latest --push .`
  - WSL must mount X: drive first: `sudo mount -t drvfs X: /mnt/x`

## Core Principles

1. **Research before implementing.** Before fixing any non-trivial problem, use an
   Opus research agent to find prior art or understand the existing codebase patterns.
   Present options. Never guess at database schema, radio protocol, or Winlink fixes.

2. **Fix root causes, not symptoms.** Never adjust timeouts, rate limits, or UI hacks
   to mask a failure. If something is broken, find where it starts — not where it
   surfaces. If three consecutive fix attempts fail, STOP and discuss.

3. **Plan before coding.** For any change touching more than two files: write the plan
   first, explain the rationale, get approval, then implement. Use EnterPlanMode for
   non-trivial features.

4. **Follow existing patterns.** This codebase has established conventions for routes,
   preferences, modals, and copy-to-clipboard. Read the existing implementation before
   adding new code. Key patterns live in:
   - Routes: `modules/routes/` (Flask blueprints)
   - Preferences: `get_preference()` / `set_preference()` in `modules/utils/common.py`
   - Admin toggles: `modules/routes/admin.py` + `templates/admin.html`
   - Copy/paste modals: `templates/inventory_broadcast.html`
   - Winlink message composition: `modules/services/winlink/core.py`

## Systematic Debugging (Four-Phase Framework)

### Phase 1: Root Cause Investigation
- Read error messages and logs thoroughly — every field matters
- Reproduce the issue (use wargame mode for safe testing)
- Trace data flow backward from symptom to original trigger
- Never fix where the error appears — find where it starts

### Phase 2: Pattern Analysis
- Find working examples of similar code in the codebase
- Compare working vs. broken — what specifically differs?
- Understand all dependencies (DB schema, JS event handlers, CSRF)

### Phase 3: Hypothesis & Testing
- One clear hypothesis at a time: "It fails because X"
- Change ONE variable, predict the outcome, test
- If wrong, refine hypothesis — don't shotgun changes

### Phase 4: Implementation
- Implement the minimal fix addressing the root cause
- Verify manually (Docker build + browser test)
- If fix fails: back to Phase 1, do not iterate blindly

## Build & Test

- **Local dev:** `python app.py` or `./entrypoint.sh` → `http://localhost:5150`
- **Docker build + push:** via WSL (see Tech Stack above)
- **Deploy update:** `docker compose pull && docker compose up -d`
- **No formal test suite** — testing is manual and field-based
- **Linting:** Ruff, mypy (Python); ESLint + Prettier (JS) — configs in place

## Key Architecture Notes

- **Single SQLite DB** at `data/aircraft_ops.db` — all state lives here
- **Global preferences** in `preferences` table (name/value TEXT pairs, no per-user scoping)
- **Per-device settings** stored in browser cookies (code_format, mass_unit, etc.)
- **mDNS** advertises as `RampOps.local` (Zeroconf)
- **Wargame mode** provides isolated training — safe for testing without affecting real data
- **Rate limiting** is disabled for LAN due to NAT/IP sharing issues

## Agent Usage & Context Preservation
- **Always use Opus agents.** Cost is not a concern.
- Prefer finding existing patterns in the codebase over inventing new ones.
- **Preserve context above all.** Use sub-agents for any work that would bloat
  the main conversation (file reads, code searches, build output).
- Divide tasks into smaller agent-sized pieces rather than doing everything inline.
  Cost is irrelevant; context loss from compaction is the real cost.

## What NOT to Do
- Don't add frameworks or dependencies for things vanilla JS handles fine
- Don't add per-user scoping to the preferences system (it's single-tenant by design)
- Don't implement without understanding the existing patterns first
- Don't silently change behavior — explain what changed and why
- Don't skip the Docker build — it's the deployment artifact
- Don't create new files when editing existing ones achieves the same goal
- Don't use smart quotes, curly apostrophes, or non-ASCII characters in JavaScript
  code (U+2018/2019/201C/201D, etc.). Browsers reject them as illegal characters.
  Use only straight quotes/apostrophes in code. Emojis and Unicode in HTML text
  content and Jinja comments are fine.
