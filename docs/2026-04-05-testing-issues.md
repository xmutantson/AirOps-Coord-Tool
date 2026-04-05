# Testing Issues — 2026-04-05

## Labels
1. **Unit labels missing info** — no tail number, no origin/source, no weight value, no unit numbering (1/N)
2. **Summary labels same issue** — missing cargo-specific data (falls through to generic)
3. **Only one label generated** — should be N labels for N units
4. **4x6 shipping labels** — stretched/distorted, same missing data
5. **Address labels** — same issues
6. **Labels dropdown** — only one should be open at a time; opening another should close the first

## Manifest PDF
7. **Notes field** — "Manifest:" lines not fully pruned; showing `blood type on 5 lb x 4 [Kadlec Hospital Richland]` in notes when only the Kennewick entry was pruned
8. **Headers visible** — FIXED (confirmed working)
9. **Origin column** — FIXED (confirmed working)

## Queue Page
10. **Ack button** — links to edit_queued_flight correctly, but user expects inline signature prompt or clearer UX
11. **Send button text** — greyed button should say "Ack first" not just be grey
12. **Send confirmation** — after clicking active Send, should show confirm dialog: "Aircraft has taken off?" with tail number reminder

## Pending Validation
- Delete flight reversal with origin (queue delete path fixed, needs re-test)
- CSV export with origin column
- Waiver flow (pilot/volunteer routing, dark mode)
