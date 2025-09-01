// static/js/propagate.js
// AOCT Propagation helpers (preview → confirm → apply) with a safe modal
// - ESC / backdrop click / × / Cancel all close the modal
// - High z-index and viewport padding so content never renders off-screen
// - Used by: /inventory/detail, /inventory/stock, /inventory/barcodes

(function () {
  // Use the API routes mounted by modules/routes_inventory/propagate.py
  const API_BASE = '/inventory/api/propagate';

  // ────────────────────────────── Helpers ──────────────────────────────
  function csrf() {
    return document.querySelector('meta[name="csrf-token"]')?.content || '';
  }
  function headers(json = false) {
    const t = csrf();
    const h = { 'X-Requested-With': 'XMLHttpRequest' };
    if (t) { h['X-CSRFToken'] = t; h['X-CSRF-Token'] = t; }
    if (json) h['Content-Type'] = 'application/json';
    return h;
  }
  function toast(msg, type = 'info', ms = 2500) {
    try { window.showToast && window.showToast(msg, type, ms); } catch (_) {}
  }
  function toFixed1(n) {
    const x = parseFloat(n || '0') || 0;
    return (Math.round(x * 10) / 10).toFixed(1);
  }

  // ────────────────────────────── API ──────────────────────────────────
  async function apiPreview(kind, names, opts, oldWpu) {
    // backend expects: { op, names[], match:{sanitized_name?, old_weight_per_unit?} }
    const body = {
      op: kind,
      names: Array.isArray(names) ? names : [],
      match: {
        sanitized_name: (Array.isArray(names) && names.length ? names[0] : undefined),
        old_weight_per_unit: (oldWpu != null ? oldWpu : undefined)
      }
    };
    const r = await fetch(`${API_BASE}/preview`, {
      method: 'POST', headers: headers(true), body: JSON.stringify(body)
    });
    if (!r.ok) throw new Error(`Preview failed (${r.status})`);
    return r.json();
  }

  async function apiApply(kind, names, opts, oldWpu) {
    // backend expects: { op, names[], match:{old_weight_per_unit?}, changes:{...} }
    const body = {
      op: kind,
      names: Array.isArray(names) ? names : [],
      match: (oldWpu != null ? { old_weight_per_unit: oldWpu } : {}),
      changes: Object.assign({}, opts || {})
    };
    const r = await fetch(`${API_BASE}/apply`, {
      method: 'POST', headers: headers(true), body: JSON.stringify(body)
    });
    if (!r.ok) throw new Error(`Apply failed (${r.status})`);
    return r.json();
  }

  // ────────────────────────────── Modal ────────────────────────────────
  // Returns { wait():Promise<{ok:boolean}>, close(ok?), overlay, box }
  function openModal(title, innerHTML, { confirmLabel = 'Apply', cancelLabel = 'Cancel' } = {}) {
    const overlay = document.createElement('div');
    overlay.className = 'aoct-prop-modal';
    Object.assign(overlay.style, {
      position: 'fixed', inset: '0', padding: '4vh 4vw',    // viewport padding to keep content away from edges
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      background: 'rgba(0,0,0,.45)', zIndex: '2147483647'
    });

    const box = document.createElement('div');
    Object.assign(box.style, {
      background: '#fff', borderRadius: '12px',
      width: 'min(92vw, 900px)', maxHeight: '86vh', overflow: 'auto',
      boxShadow: '0 10px 28px rgba(0,0,0,.30)'
    });

    box.innerHTML = `
      <div style="position:sticky;top:0;display:flex;align-items:center;justify-content:space-between;
                  background:#222;color:#fff;padding:10px 14px;border-top-left-radius:12px;border-top-right-radius:12px;">
        <div style="font-weight:600">${title || ''}</div>
        <button type="button" class="pm-x" aria-label="Close"
                style="background:transparent;border:0;color:#fff;font-size:20px;line-height:1;cursor:pointer">×</button>
      </div>
      <div class="pm-content" style="padding:14px 16px;">${innerHTML || ''}</div>
      <div class="pm-actions" style="display:flex;gap:8px;justify-content:flex-end;padding:12px 16px;">
        <button type="button" class="pm-cancel">${cancelLabel}</button>
        <button type="button" class="pm-apply">${confirmLabel}</button>
      </div>
    `;

    overlay.appendChild(box);

    // lock scroll
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    document.body.appendChild(overlay);

    let resolver;
    const wait = () => new Promise(res => (resolver = res));
    const close = (ok) => {
      document.removeEventListener('keydown', onKey);
      document.body.style.overflow = prevOverflow;
      overlay.remove();
      resolver && resolver({ ok: !!ok });
    };

    // close behaviors
    function onKey(e) { if (e.key === 'Escape') close(false); }
    document.addEventListener('keydown', onKey);
    overlay.addEventListener('click', e => { if (e.target === overlay) close(false); });
    box.querySelector('.pm-x').onclick = () => close(false);
    box.querySelector('.pm-cancel').onclick = () => close(false);
    box.querySelector('.pm-apply').onclick = () => close(true);

    return { wait, close, overlay, box };
  }

  function renderSummary(data) {
    // accept either the server's {summary:{groups,totals}} or a flat object
    const s = (data && (data.summary || data)) || {};
    const groups = Array.isArray(s.groups) ? s.groups : [];
    const rows = groups.map(g => `
      <tr>
        <td>${g.category || g.label || ''}</td>
        <td style="text-align:right">${(g.rows ?? g.count ?? 0)}</td>
        <td style="text-align:right">${(g.qty ?? g.quantity ?? 0)}</td>
        <td style="text-align:right">${toFixed1((g.total_lbs ?? g.total_weight ?? g.total) || 0)}</td>
      </tr>`).join('');

    const t = s.totals || s.total || {};
    const totalRows = (t.rows ?? t.count ?? 0);
    const totalQty  = (t.qty  ?? t.quantity ?? 0);
    const totalLbs  = toFixed1((t.total_lbs ?? t.total_weight ?? t.total) || 0);

    return `
      <table class="pm-table" style="width:100%;border-collapse:collapse;margin:0;border-spacing:0;table-layout:auto;">
        <thead>
          <tr style="background:#333;color:#fff;">
            <th style="text-align:left;padding:6px 8px;">Group</th>
            <th style="text-align:right;padding:6px 8px;">Rows</th>
            <th style="text-align:right;padding:6px 8px;">Qty</th>
            <th style="text-align:right;padding:6px 8px;">Total (lbs)</th>
          </tr>
        </thead>
        <tbody>
          ${rows}
          <tr>
            <td style="padding-top:10px;font-weight:700">Total</td>
            <td style="text-align:right;padding-top:10px;font-weight:700">${totalRows}</td>
            <td style="text-align:right;padding-top:10px;font-weight:700">${totalQty}</td>
            <td style="text-align:right;padding-top:10px;font-weight:700">${totalLbs}</td>
          </tr>
        </tbody>
      </table>
    `;
  }

  // Preview → Confirm → Apply
  async function previewBulk(kind, names, opts, oldWpu, onApplied) {
    if (!Array.isArray(names) || !names.length) return;
    try {
      const data = await apiPreview(kind, names, opts, oldWpu);
      const mod = openModal(
        (data && data.title) || `Apply ${kind} change?`,
        renderSummary(data),
        { confirmLabel: (data && data.confirm_label) || 'Apply', cancelLabel: 'Cancel' }
      );
      const res = await mod.wait();
      if (!res.ok) return; // cancelled
      await apiApply(kind, names, opts, oldWpu);
      toast('Updated', 'success');
      typeof onApplied === 'function' && onApplied();
    } catch (e) {
      toast(String(e.message || e), 'error', 4000);
    }
  }

  // ───────────────────── Attachments / Entry points ───────────────────
  // 1) Detail table: enable “Fix/Propagate…” links
  function attachDetailHandlers(container) {
    container = container || document;
    container.addEventListener('click', (e) => {
      const a = e.target.closest('.propagate-link');
      if (!a) return;
      e.preventDefault();

      const tr = a.closest('tr');
      if (!tr) return;
      const name = (tr.dataset.name || '').trim();
      const wpuLbs = parseFloat(tr.dataset.wpuLbs || tr.dataset.wpu || '0') || 0;
      if (!name) return;

      // Quick chooser modal
      const chooserHTML = `
        <div>Choose what to fix for <strong>${name}</strong>:</div>
        <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:10px;">
          <button type="button" class="pm-act" data-k="category">Category</button>
          <button type="button" class="pm-act" data-k="name">Name</button>
          <button type="button" class="pm-act" data-k="weight">Weight</button>
        </div>
      `;
      const mod = openModal('Fix / Propagate', chooserHTML, { confirmLabel: 'Close', cancelLabel: 'Close' });

      // Wire action buttons inside the modal
      mod.box.addEventListener('click', async (ev) => {
        const btn = ev.target.closest('.pm-act');
        if (!btn) return;
        const k = btn.dataset.k;

        if (k === 'category') {
          try {
            const cats = await fetch('/inventory/api/categories', { headers: headers() })
              .then(r => r.json())
              .then(j => j.categories || []);
            const sel = document.createElement('select');
            sel.style.minWidth = '260px';
            sel.innerHTML = cats.map(c => `<option value="${c.id}">${c.display_name}</option>`).join('');
            const inner = `<div>Reassign category for <strong>${name}</strong></div>
                           <label style="display:block;margin-top:.5rem;">Category ${sel.outerHTML}</label>`;
            const m2 = openModal('Choose category', inner, { confirmLabel: 'Preview' });
            const r2 = await m2.wait();
            if (!r2.ok) return;
            const cid = m2.box.querySelector('select').value;
            mod.close(false);
            previewBulk('category', [name], { new_category_id: cid });
          } catch (_) {}
        } else if (k === 'name') {
          const newn = prompt(`Rename '${name}' to:`) || '';
          if (!newn.trim()) return;
          mod.close(false);
          previewBulk('name', [name], { new_name: newn.trim() });
        } else if (k === 'weight') {
          const neww = parseFloat(prompt(`New weight for '${name}'. Current reference size: ${wpuLbs} lbs`) || '0');
          if (!neww || neww <= 0) return;
          mod.close(false);
          previewBulk('weight', [name], { new_weight_per_unit: neww }, wpuLbs);
        }
      });

      // If user just closes, do nothing
      mod.wait().then(() => {});
    });
  }

  // 2) Barcode admin: offer propagation after an inline row save
  async function maybeOfferAfterBarcodeEdit(tr, before, after, reloadCb) {
    try {
      const nameBefore = (before.sanitized || before.name || before.sanitized_name || '').trim();
      const nameAfter  = (after.sanitized_name || after.name || '').trim();
      const catBefore  = parseInt(before.cat || before.category_id || 0, 10) || 0;
      const catAfter   = parseInt(after.category_id || 0, 10) || 0;
      const wBefore    = parseFloat(before.wpu || before.weight_per_unit || '0') || 0;
      const wAfter     = parseFloat(after.weight_per_unit || '0') || 0;

      if (catBefore && catAfter && catAfter !== catBefore && nameBefore) {
        await previewBulk('category', [nameBefore], { new_category_id: catAfter }, null, reloadCb);
      }
      if (nameBefore && nameAfter && nameAfter !== nameBefore) {
        await previewBulk('name', [nameBefore], { new_name: nameAfter }, null, reloadCb);
      }
      if (wBefore && wAfter && Math.abs(wAfter - wBefore) > 1e-9 && nameBefore) {
        await previewBulk('weight', [nameBefore], { new_weight_per_unit: wAfter }, wBefore, reloadCb);
      }
    } catch (_) {}
  }

  // 3) Stock page helpers (optional direct calls from page code)

  // Expose public API
  window.Propagate = Object.assign(window.Propagate || {}, {
    attachDetailHandlers,
    previewBulk,
    maybeOfferAfterBarcodeEdit
  });
})();
