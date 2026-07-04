# After-Action Report — Gorge Food-Lift Drill, June 12-13 2026

**Prepared:** July 4 2026, from a forensic snapshot of the field unit's database
(`aircraft_ops.db`, box `adsbexchange`, snapshot `forensic_snapshot_20260704.db`)
cross-checked against the operator report (S. Chlarson email, June 12 2:55 PM)
and the exact code vintage the box was running.

**Build under test:** image built 2026-05-30 (pulled same day, restarted at the
hangar the night of June 10). None of the June 12-13 or later fixes were on this
box — an update was requested but never pulled. Every code defect below is
called out as *fixed on \<date\>* or *fixed in this AAR's follow-up commit*.

---

## 1. Summary

The crew pre-staged a ~2,000 lb Safeway food order on June 12 for a four-plane
lift on June 13. Inventory scan-in went largely correctly (1,994.9 lb recorded —
the operator's "about a ton" estimate was accurate to 0.3%). Manifest building
then failed in ways that made the software untrustworthy, and the crew correctly
fell back to paper manifests for the flight day. The June 13 mission itself
barely touched the system (zero ramp flights recorded), so all findings come
from the June 12 staging session.

Every number in the operator report was verified accurate against the database.
The confusing behavior was real, reproducible, and rooted in three code defects
plus two workflow mismatches.

## 2. What was reported vs. what the data shows

| # | Reported | Finding | Class |
|---|---|---|---|
| 1 | Tablets unusable with USB scanners (no adapters; no on-screen keyboard) | Wedge scanners enumerate as hardware keyboards, so tablets suppress the on-screen keyboard. Separately, outbound panel fields are disabled until category/item/size are chosen, with no visual cue. | Equipment/training + UI papercut |
| 2 | Items scanned in were "not recognized" when scanned for manifests | Two causes: (a) supplier cases carry per-case/lot warehouse stickers that never repeat, and (b) ~1/3 of the mappings captured at intake were damaged (truncated leading characters, a 42-char GS1 dump stored as a barcode, a 9-oz/9-lb unit mixup). | Code/design (fixed June 13: AOT-only scanning) |
| 3 | Outbound scanner bar invisible until toggling inbound and back | This build only rendered the scan field on the Advanced panel's outbound side, refreshed on toggle. | Code (fixed June 13: scanner on both sides) |
| 4 | Two manifests built and saved; afterward **every** draft (all four tails + 26BMAC) showed the same manifest | The five drafts were created empty, leaving `manifest_id` NULL. The edit page rendered that NULL as the literal string **"None"**, which JavaScript accepted as a real session id — so every draft edited that way read and wrote **one shared global session named `None`**. Nothing was ever actually saved to any draft (`flight_cargo` has zero rows); all five were windows onto the same live bucket. | **Code (root cause; fixed in this commit)** |
| 5 | Rebuilt manifest showed ~800 lb when ~400 was expected | The shared session held two build passes at once (761.5 lb on screen). After the operator deleted the first pass, the net came to ~395 lb — the manifest left in the system that evening was actually correct, but the display had already destroyed trust. | Same root cause as #4 |

Also found, not in the report: an 18-minute attempt to receive stock through the
Ramp Boss **inbound** panel (11:34-11:52), typing/scanning barcodes into the
item-name field — 23,061 phantom pounds in (including an inherited 11,082 lb/unit
weight typo), 22,670 clawed back by deletes. Residue of ~25 lb of digit-named
"items" remains in stock and needs cleanup.

## 3. Root causes

**Code (ours):**
1. **The `None` session bug (new, found by this exercise).** Jinja's
   `d.get('manifest_id','')` only uses the default when the key is *missing*,
   not when the value is None — so drafts queued without a manifest rendered
   `value="None"` into the hidden session field, and every JS guard
   (`if (!manifestId.value)`) treated it as a valid session. Fix: render
   `or ''`, normalize `'None'/'null'/'undefined'` client-side, and reject those
   values at every server endpoint that accepts a manifest/session id
   (`clean_mid()` in `modules/utils/common.py`).
2. **No barcode discipline** (per-case stickers accepted as identifiers,
   no canonicalization, capture truncation) — fixed June 13 with AOT-only
   scanning + printed AOT tags (commit 281e69b).
3. **Scanner UI gaps** — outbound-only scan field, silent disabled fields,
   silent bulk-print no-op past 10 labels — fixed June 12-13 (commits 4f19acc,
   281e69b) except the disabled-field affordance, still open.

**Process (untested pattern, not operator error):** the crew queued empty
drafts first and built manifests afterward via edit — a workflow that had never
been tested (developer testing always built the manifest *then* queued). The
untested pattern is exactly where the `None` bug lived. Second mismatch:
warehouse receiving was attempted on the Ramp Boss form, which models cargo
moving on/off an aircraft; stock intake belongs on Inventory → Scan. A steering
banner now points there from the Ramp Boss form.

## 4. Corrective actions

- [x] `None`-session fix, client + server (this commit)
- [x] AOT-only scanning with print-at-intake and create-and-print on ramp inbound (281e69b, June 13)
- [x] Steering banner on Ramp Boss pointing warehouse work at Inventory → Scan (this commit)
- [ ] Update the field box (still on the May 30 image) and run the legacy-mapping
      **Convert to AOT** migration + retag stock
- [ ] Clean drill residue: 2 phantom digit-named items (~25 lb), damaged
      mappings, 5 empty drafts
- [ ] Disabled-field affordance on the Advanced panel
- [ ] Kit: USB-C/Lightning adapters; policy: scanners pair with laptops
      (tablets suppress their keyboards when a scanner is attached)
- [ ] Re-run the drill on the updated build with 2-3 operators building
      manifests simultaneously (operator's recommendation — endorsed)

## 5. Evidence

- DB snapshot: `forensic_snapshot_20260704.db` (on-box) / local analysis copy
- Session reconstruction: shared session literally named `None` contains the
  phantom inbound (11:34-11:52), the manifest rebuild (12:55-13:25), and is
  what every draft's edit view displayed. The one correctly-scoped session
  (`b59e0609…`, 12:36-12:51, 373.8 lb) was never bound to a draft and was
  invisible from every draft view.
- Operator report: S. Chlarson email, June 12 2026 2:55 PM.
