# Field Test Findings — 2026-04-04

## Summary
Full setup and multi-user walkthrough of AirOps Coordination Tool. General feedback was positive — multiple users described the tool as "easy." Several UX issues and one bug were identified.

---

## Issues Found

### 1. Login/Registration Modal Not Scrollable
**Severity:** High — blocks onboarding
**Description:** The login modal (pilot/volunteer registration) scrolls the background page instead of scrolling within the modal. On tablets in landscape mode and on laptops at default zoom, the modal extends beyond the viewport and users cannot reach the bottom fields or submit button. Workarounds required turning tablets to portrait or zooming out the browser — neither is discoverable by untrained users.
**Requirements:**
- Modal content must scroll internally, not the background
- Visible scroll indicator (scroll bar or similar) so users know there's more content
- Touch-compatible scrolling (swipe within modal)
- Mouse scroll wheel must work
- Grabbable scroll bar for mouse users
- Modal must not exceed viewport height; internal content scrolls instead

### 2. Session/Authentication Stability
**Severity:** Medium — needs investigation
**Description:** Users had to re-authenticate multiple times on a laptop. Suspected cause: opening multiple browser tabs/windows of the tool, especially when full-screened (F11) where extra tabs are invisible. May also be related to tabbing away from the app.
**Requirements:**
- Investigate whether switching browser tabs causes session loss
- Investigate whether multiple open tabs/windows invalidate each other's sessions
- If multi-tab is the cause, document it as known behavior or fix the session handling

### 3. Winlink Inbox — Row Clickability
**Severity:** Low — UX polish
**Description:** Only the subject link is clickable to open a message. Users expected to click anywhere on the row.
**Requirements:**
- Make the entire inbox row clickable (navigate to message detail)
- Keep the existing link styling on the subject for visual affordance

### 4. Multiple Tabs/Windows Created by Login Flow
**Severity:** Medium — confusing in fullscreen
**Description:** The login process opens additional tabs. When users are in fullscreen (F11), they can't see the tab bar and don't realize multiple instances are open. This compounds the session issue (#2).
**Requirements:**
- Login flow should not open new tabs
- If a new tab is unavoidable, use `target` naming to reuse the same tab
- Consider detecting fullscreen and warning users

### 5. Airport Code Validation in Callsign Mappings
**Severity:** Medium — data entry error
**Description:** In the Airport-to-Callsign mapping (Preferences), users put ham radio callsigns in the airport code field instead of the callsign field. The fields are not validated, so the error goes unnoticed.
**Requirements:**
- Validate the airport code field against the airports database
- Show a warning (not a hard block) if the entered value doesn't match a known airport code
- Do not prevent saving — just alert the user

### 6. Winlink Settings — Dedicated Page from Radio Tab
**Severity:** Medium — discoverability
**Description:** Winlink airport-to-callsign mappings and CC addresses are buried in the Preferences page. Radio operators couldn't find them easily.
**Requirements:**
- Add a button on the Radio page linking to a dedicated Winlink settings page
- This page contains: airport-to-callsign mappings and CC address configuration
- Remove these settings from the Preferences page to reduce clutter
- Include a "Back to Radio" link on the new page
- If unsaved changes exist when navigating away, warn the user

### 7. Winlink Compose Form (New Feature)
**Severity:** Medium — feature gap
**Description:** No way to compose and send arbitrary Winlink messages from the tool. Only flight-related messages can be sent currently. Operationally, the ability to compose freeform messages is needed.
**Requirements:**
- Add a compose form to the Winlink system
- Require password authentication before access (check against any of the configured Winlink callsign passwords stored in PAT config)
- Display which callsigns are configured on the system
- User authenticates by entering the password for any configured callsign
- Purpose: prevent non-radio personnel from accidentally sending messages

### 8. Inventory Source Tracking (New Feature)
**Severity:** Medium — operational gap
**Description:** No way to track where cargo originated (e.g., which hospital sent blood bags). Source information is not captured or carried through the system.
**Requirements:**
- Add optional "source" field to inventory entries
- Source should persist with the cargo through all movements
- When scanning a barcode, default to the previously entered source (don't re-ask every scan)
- Source should be displayable and editable
- Source travels with the cargo to its destination
**Note:** This is a deep, far-reaching change. Should be implemented last.

### 9. Advanced Cargo Entry — Delete Fails
**Severity:** High — functional bug
**Description:** Deleting an item from the advanced cargo entry (ramp boss) shows "delete failed on server" toast. The inventory system shows reversal entries (negative quantities) from the attempted delete, but the UI item doesn't disappear.
**Requirements:**
- Investigate the server-side error causing the delete failure
- Fix the delete endpoint
- Ensure UI reflects the actual state after delete

---

## Priority Order

### P0 — Must Fix (Blocks Basic Usage)
1. **Login modal scrolling** (#1) — blocks onboarding on tablets and default-zoom laptops
2. **Advanced cargo delete bug** (#9) — functional break in core workflow

### P1 — Should Fix (Significant UX Impact)
3. **Airport code validation** (#5) — prevents common data entry errors
4. **Winlink settings page** (#6) — discoverability for radio operators
5. **Session stability investigation** (#2) — may be non-issue (multi-tab), but needs confirmation
6. **Multiple tabs from login** (#4) — confusing in fullscreen

### P2 — Nice to Have (Polish / New Features)
7. **Winlink inbox row clickability** (#3) — minor UX improvement
8. **Winlink compose form** (#7) — new feature, requires auth gating

### P3 — Future (Large Scope)

---

## Feature Requests (from post-test development)

### 10. Pilot Ack: Keep Send Buttons Available
**Description:** Once a pilot acknowledgement is in the system for a flight, the send state buttons should remain available — showing the send button and view manifest PDF link.
**Status:** Implemented

### 11. Unit-Level Cargo Labels
**Description:** Cargo labels should be generated at the unit level (one label per physical cargo item), numbered per cargo type (e.g., "Blood Bags 1/20", "Blood Bags 2/20"). Labels are meant to be attached to actual cargo items for tracking.
**Status:** Not yet implemented

### 12. Label Sizing Options
**Description:** Label printing should support multiple paper sizes — regular printer (letter/A4) and Dymo-type shipping label printers. Users should be able to choose the format before printing.
**Status:** Implemented (letter, 4x6 shipping, 1.1x3.5 address options in queue Labels dropdown)

### 13. Unified Barcode System with Generated Inventory Tags
**Description:** Two-tier label system using the same barcode:
- **Inventory Tags** (small, address-size): Auto-generated barcode when item enters system without one. Printed immediately after adding items. Contains barcode + item name + weight. Operator sticks on physical items so everything becomes scannable.
- **Shipping Labels** (4x6): Generated when cargo loads onto a flight. Same barcode + flight info + origin + destination + unit numbering.
- System generates Code128 barcodes for items that don't have existing UPC/EAN codes
- "Print inventory tags?" prompt after manual item entry
- Items with existing barcodes (UPC from packaging) keep their original codes
- Printer: Brother QL-820NWB (infrastructure WiFi mode, not WiFi Direct) or USB thermal
**Status:** Not yet implemented — printer being ordered
9. **Inventory source tracking** (#8) — deep change, implement last
