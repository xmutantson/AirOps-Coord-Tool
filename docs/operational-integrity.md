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

## Offline validation

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
