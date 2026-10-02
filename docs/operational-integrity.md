# Operational integrity changes and verification

These changes target the July 4, 2026 source baseline
`2ebeabc5fe88e01b0c78890c62400b8c5663e12f`. They do not certify a field unit,
radio link, printer, or deployment. No production data repair is included.

## Operator-visible compatibility changes

- Cargo reservations account for other active manifests. An outbound operation
  can now be rejected when the stock is already reserved elsewhere.
- Source ambiguity requires operator input instead of silently merging suppliers.
- Queued pilot acknowledgements made before this change have no manifest-content
  binding. Review and acknowledge those queued flights again before dispatch.
  Historical sent-flight approvals are not bulk rewritten or erased.
- Material draft changes or unapplied cargo edits require a fresh acknowledgement.
  An existing signed PDF is preserved instead of silently rendering a new manifest
  under the old signature.
- Generic Winlink composition waits for PAT's result, up to the existing
  60-second timeout. Success means composed into PAT's outbox, not delivered.
  If PAT succeeded but recording local history failed, the error is logged and
  composition still counts as successful to avoid inviting a duplicate retry.

PDF generation while acknowledging holds a database write reservation to keep
the rendered cargo and approval consistent. Measure its latency and concurrent
operator behavior on the target Pi during staging; PDF rendering is mocked in
the offline regression suite.

## Deployment behavior

- `start.sh` starts the cached configured image without pulling or building.
- `start.sh --update` explicitly pulls first. Invalid Compose configuration or a
  failed pull stops before container startup/recreation.
- Set `AOCT_IMAGE` in the deployment `.env` to a tested registry digest. The
  compatibility default is still `latest`; no untested digest is invented here.
- Only present optional USB/audio/PTT devices enter the generated override.
- `restart: unless-stopped` enables process restart after unexpected exit. It is
  not an application health check or evidence that radio/printing is working.

Offline startup, explicit updates, and failure ordering have regression tests
using a mocked Docker shell function. Real Docker Compose, image builds,
multi-architecture images, and hardware behavior require separate validation.

## Initial 93b71bf offline validation

`python -B -m unittest discover -s tests -v` passes 50 tests: 22 inventory,
12 acknowledgement, 9 Winlink, and 7 deployment cases. These include real
temporary-SQLite concurrency/rollback checks and execution of actual route
functions with external dependencies isolated. Route tests deliberately avoid
importing `app.py`, which initializes live application services.

All 67 Python source/test files parse with Python 3.10 grammar. The two modified
Jinja templates parse, and their 23 inline scripts pass Node syntax checking with
Jinja expressions stubbed. Bash syntax, deployment YAML parsing, and CRLF-aware
Git whitespace checks also pass. Syntax checks do not establish browser behavior.

No application server, Docker build, actual PDF renderer, PAT process, radio,
printer, production data, or live integration was exercised. The test suite is
focused regression coverage, not full end-to-end qualification.

## Release and recovery drill still required

1. Record the running image ID, configured digest, deployment configuration, and
   device identities on a staging unit.
2. In a maintenance window, stop application writes and preserve the full data
   directory, deployment configuration, and `flask_secret` volume. If backing up
   SQLite while it remains open, use SQLite's backup API; copying only the main
   database file can omit WAL transactions.
3. Restore into an isolated spare system with integrations disabled. Confirm
   inventory, manifests, signatures, attachments, and settings agree with the
   source snapshot. Do not connect the spare to operational radio endpoints.
4. Test the candidate image with synthetic inventory and at least three
   operators. Create empty drafts first, then interleave scans and edits. Include
   source selection, the last available unit, deletion, sign-off changes,
   interruption, and restart.
5. Disconnect internet access and demonstrate cached startup. Demonstrate a
   rejected update without disruption to the existing service.
6. Rehearse recovery to the prior image **and matching data snapshot**. A changed
   database schema may make image-only rollback unsafe. No automatic destructive
   rollback or migration reversal is provided.

Retain evidence of this drill with the release digest before field deployment.
The existing AAR's deployment/cleanup checkboxes describe historical conditions;
this implementation does not establish whether those tasks were completed.

## Remaining product and engineering decisions

- A durable Winlink outbox with restart-safe work, retry policy, and definitive
  transmission acknowledgements remains separate from truthful PAT composition
  results. Retrying after an ambiguous timeout needs operator judgment because
  PAT may have accepted the message before the timeout.
- Source allocation must not silently pick a supplier when several have stock.
  A barcode can identify a product without identifying its physical batch.
- Full reproducible dependency locking, versioned published images, a displayed
  build SHA, application health checks, and multi-platform qualification remain
  release work. No dependencies were upgraded speculatively in this change.
- The field unit's real database and hardware have not been inspected or changed.
  Historical stock discrepancies need a separately reviewed reconciliation.

## Independent review follow-up (October 2, 2026)

The review of `93b71bffe7a48de3bea8fe09edc1c1900634bbf2` identified nine
reliability findings. This follow-up implements local fixes for each finding:

| Finding | Implementation and regression evidence |
| --- | --- |
| Duplicate drafts consume one allocation twice | Durable session ownership; retries return the same queued ID; closed sessions cannot be queued or scanned again. Legacy duplicate drafts cannot reverse the owner's allocation. |
| Delete/dispatch race returns shipped stock | Deletion takes `BEGIN IMMEDIATE` before reading the draft or cargo; both transaction orderings are tested. |
| Legacy cargo deletion compensates repeatedly | Persistent source-row deletion records make compensation idempotent under the same write lock. |
| Receipt edit/delete underfunds reservations | Generic corrections validate both affected stock keys and roll back conflicts; session movements must be changed through the manifest. Dispatch independently rechecks committed stock. |
| Stale page signs unseen changes | Queue views carry a saved-revision digest; acknowledgment requires exactly that digest under the write lock. Missing tokens fail closed. |
| Removing cargo loses the cutline | Applied ledger IDs live on the draft, independently of cargo rows. Empty snapshots, same timestamps, later pending commits, and legacy chip removal are covered. |
| Typed PDF weight differs from dispatch | PDF and dispatch use the same typed-weight parser when cargo is not itemized. Remarks are descriptive and cannot override weight. Decimal dispatch weights are retained. |
| Source reversal merges case-distinct origins | Reversals preserve stored source strings exactly. |
| Dispatch accepts a missing signed PDF | Dispatch requires the preserved file; every new acknowledgment creates an artifact even for older clients requesting `build_pdf=no`. |

Signature hardening is static code work with benign unit tests: strict PNG/base64
validation, bounded request/image bytes and decoded pixels, single-frame images,
in-memory PNG normalization, and a PDF fetcher restricted to the validated
signature. No exploit reproduction or network resource fetch is performed.

Schema additions are additive: `queued_flights.snapshot_ledger_ids`,
`manifest_allocations`, and `cargo_deletions`. Legacy snapshots adopt their old
timestamp cutline once; subsequent saves use explicit ledger membership. Legacy
acknowledgments need renewal after the revision format changes. Already-corrupt
historical inventory/snapshots are not automatically repaired. Old clients must
reload updated pages to send the required revision token. Generic edits to
session-linked inventory are rejected to keep signed/saved allocations coherent.

The repository offline suite now has 72 passing tests (the original 50 plus 22
follow-up regressions). Original baseline fixtures now simulate a reviewed
revision and a persisted stub artifact; their invariant assertions are retained.
Three baseline dispatch scenarios explicitly seed stock. PDF rendering remains
stubbed, while the real PDF builder and Jinja template prepare weight totals.

The external independent suite is retained byte-for-byte and rerun separately.
It passes 9 of 13 tests; four tests require review of changed fixture contracts:
its forced nested dispatch now encounters the deletion write lock; its receipt
test ignores the rejected deletion and therefore observes a valid funded flight;
its duplicate-send test directly posts no revision token; and its stale-page test
inherits the updated baseline helper which explicitly reviews the current
revision. Separate repository tests exercise stale/missing tokens directly,
blocked receipt corrections plus legacy corruption, both race orderings, and
one allocation/one dispatch. The external assertions were not edited to obtain
a green result. Treat those four independent results as outstanding independent
review work, not a fully passing external suite.

The D: implementation report records the exact local commit, final test logs,
independent file hash, and remaining validation limits. Actual WeasyPrint,
browser/Flask application integration, Docker builds, Python 3.10/Pi runtime,
hardware, production data, and field concurrency/latency remain unverified.

## Re-review follow-up: shared manifest mutations

The independent review of `e9dc0227b7027025cd72f46c9b3e8bd0cef045e4`
verified the nine original scenarios and accepted the four documented contract
adaptations. It identified four adjacent blockers; this follow-up repairs all
four through shared services in `modules/services/inventory.py`:

- Advanced-panel and legacy row deletion now use `reverse_manifest_entry`.
  Compensation is capped to the remaining allocation, stock-checked, and keyed
  by source table, source row, and manifest. Pending reversal cancellation clears
  only that uncommitted operation's identity. Retries after commit are no-ops.
- Legacy inbound snapshot removal goes through `remove_manifest_item` and
  `insert_entry`, so competing reservations can reject the entire transaction,
  including its pending changes and snapshot deletion.
- Inbound imports require an open session under `BEGIN IMMEDIATE`. Accepted items
  persist `(session_id, import_id, item_id, payload_hash, entry_id)` in
  `manifest_import_items`. Retrying partial success does not replay accepted rows;
  corrected skipped items can be accepted. Changing an already accepted identity
  returns a conflict. An additional deliberate import requires a new import ID.
- `manifest_reversals` replaces the numeric-ID-only deletion lookup. Equal IDs in
  `flight_cargo` and `inventory_entries` are distinct, as are different manifests.
  Legacy calls prefer an existing matching snapshot; ambiguous missing-snapshot
  retries return `source_required` instead of deleting unrelated ledger cargo.
  Clients can disambiguate with `source_table` plus `manifest_id`.

Old ledger tombstones migrate with their retained source row. Legacy direct
flight allocations are backfilled as closed when the terminal guard is installed.
SQLite INSERT/UPDATE/DELETE guards protect terminal session movements against
writers that bypass the Python service. These are application database changes,
not operating-system/security-setting changes. No live migration was executed.

### Mutation-path inventory

| Legitimate path | Shared invariant / disposition |
| --- | --- |
| Manual inventory and barcode additions | `insert_entry` / `adjust_pending`: finite positive items, funding, exact source, open session, write transaction |
| Advanced add/delete/purge/commit | Shared insert, referenced reversal, pending cancellation, and `commit_manifest_session` |
| Scanner/key/nudge removal | `remove_manifest_item`: source/category identity, capped committed reversal, reservation funding; unbacked snapshots require reconciliation |
| Generic receipt edit/delete | Existing guarded correction service; session-linked movements remain immutable through generic inventory controls |
| Bulk category/name/weight propagation | Shared atomic correction checks old/new stock keys after the full batch, rejects session-linked movements, and preserves reservation funding across name casing; exporter format is unchanged |
| Parsed inbound import | Durable per-import/per-item identity and payload equality, with partial validation results |
| Queue creation/save/send | One session owner, guarded pending promotion, saved revision; send transfers approved cargo and closes ownership without appending movements |
| Legacy direct outbound form | Routes into the queue/sign/send workflow instead of dispatching through a separate ledger path |
| Direct inbound / auto-detected arrival | Import, attachment, flight/history writes, and session closure share one transaction; auto-import uses stable `arrival:<flight_id>` identity |
| Whole-draft deletion | Shared atomic ownership-aware net reversal; unbacked legacy snapshot returns are rejected. As before, deleting an inbound draft retains already received stock |
| Explicit finalized-flight cancellation | Stock-checked compensators outside the closed session; flight deletion and allocation state are atomic; repeat deletion is harmless |
| Reconcile insert / pending-commit utility wrappers | Shared insert/commit gates; caller timestamps are preserved for new entries |
| Pending heartbeat and expiration | State checks; expiration removes only pending movements and cancels associated uncommitted reversal records |
| Training seed | Unscoped committed receipt seeding, unchanged; no reservation-reversing operation |
| Explicit incident/training reset | Clears mutation/ownership metadata before ledger rows within the existing reset transaction; no reset was executed in this work |
| Inventory exports / NetOps | Read-only producer shape unchanged: distinct package weights remain distinct rows |

Legacy imports with existing `adv-detect` rows but no durable import identity are
rejected for review rather than guessed/replayed. Already inconsistent or
unattributable historical snapshots are not automatically repaired. Closed
historical pending rows are retained for reconciliation rather than silently
reaped. A pending reversal canceled by Back/expiration can be deliberately retried.

The full offline suite has 96 passing cases, including 24 new mutation tests.
The unchanged independent re-review suite has 21 passing cases (13 original
scenarios and eight adjacent/control tests). Coverage includes competing reversal
and import requests, partial import retry, database failures between ledger and
identity writes, inbound funding rollback, cross-table/session ID collisions,
legacy tombstone migration, pending cancellation/expiry, and actual extracted
arrival routes. Existing tests and external assertions were not weakened.

Limits remain: actual application startup/migrations, browser/CSRF integration,
real PDF rendering, target Python/Pi performance, stress/crash recovery, hardware,
and production data were not exercised. The D: follow-up report identifies the
exact final local commit, final test logs, mutation-path audit, and source hashes.


## Arrival request identity follow-up

Independent verification of `ca6dfad474a664ad0daa5958110d6446fded91a8`
accepted the original nine findings and four follow-up repairs, but found that
retrying an arrival which completed an outbound flight could create another
inbound flight and import the same physical cargo twice.

`modules/services/arrivals.py` persists an `arrival_requests` mapping from request
identity and normalized payload hash to flight, receipt allocation, and saved
response. The route resolves this identity under `BEGIN IMMEDIATE` before
checking a manifest's open state or selecting update versus insert. The mapping,
flight/history writes, receipt import, and allocation closure commit together.
A replay returns the original flight with `action=update_ignored`, without new
cargo, history, outbox changes, or post-commit task effects. Reusing an ID with
changed details returns `arrival_conflict`. A removed flight returns
`arrival_closed`; the mapping is retained rather than reimporting cargo.

The form supplies `arrival_request_id`, retaining it through failed/lost responses
and replacing it after successful form reset. Distinct IDs allow legitimate
separate arrivals with identical tail/time/cargo. The old tail/time-only duplicate
heuristic is removed. Legacy clients omitting an ID receive a stable identity
from the normalized payload. Identical legacy payloads replay indefinitely;
these clients must send a fresh ID to distinguish a separate identical event.
This unavoidable ambiguity is not resolved by guessing a time window or flight ID.
Pre-upgrade arrivals without a stored mapping are not automatically reconstructed.

Nine new offline route tests cover legacy outbound replay, lost responses on both
flight paths, identical distinct events, retry before selection of a later open
leg, explicit closed-manifest retry, changed-payload rejection, identity-write
failure rollback on both paths, concurrent requests, and cancellation/retry.
The full suite is 105 tests. The unchanged independent extra suite is five cases;
its observed arrival blocker now passes along with the four prior controls.
Existing migration and explicit reset paths include the new metadata table;
no live database migration or reset was performed. Export producers are unchanged.

Post-commit task notifications retain their existing best-effort behavior. A crash
between the core transaction and those ancillary actions can leave an action
missing; retries do not replay it. A transactional notification outbox, browser
refresh/draft recovery, real PDF rendering, full application integration, and
field crash/power-loss testing remain outside this offline repair.


## Arrival form recovery follow-up

Independent verification accepted the server identity repair at `4a4173d` but
observed that a rejected POST promise or interrupted JSON body left `rbSubmitting`
and the submit buttons locked. The main form now catches uncertain responses and
restores the guard, buttons, and disabled time controls in `finally`.

Before the first POST, the form retains the destination URL, submit action, and
`FormData` snapshot. A retry resends that same snapshot, preserving the arrival
request ID and every submitted value. It skips mutable-field validation, clock
recalculation, and manifest recommit. Subsequent field edits do not change an
uncertain request; the operator message explains that retry sends the original
details. The snapshot is cleared only after a confirmed result/reset or redirect.
The arrival identity rotates on successful reset, as before. Non-OK or unreadable
responses retain the snapshot; this recovery does not silently treat edited fields
as a new physical arrival.

`tests/arrival_form_retry.cjs` executes the actual handler with inert DOM and
transport adapters. Ten Node cases cover POST loss, JSON parsing interruption,
HTTP rejection, non-JSON/null results, repeated failures, exact-payload retry after
field/action edits, fresh identity for the next successful event, queue/reset,
redirect, and preflight cleanup. A Python unittest wrapper includes this check in
the repository suite when Node is installed. No browser or network is started.

The unchanged independent loss harness additionally asserts that the injected
exception escapes the handler. Recovery now handles it, so that old assertion
fails before the harness reaches its lock checks. The repository tests instead
require the handler to resolve, unlock, retain the original payload/identity, and
successfully retry; no independent file or assertion was edited. Full browser,
CSRF, reload/draft recovery, and external task delivery remain outside this narrow
repair. Server allocation logic and export producers are unchanged.
