// static/js/flow_triggers.js
(function () {
  // Guard: avoid binding the delete handler twice if script is included more than once
  if (window.__HAS_DELETE_HANDLER__) return;
  window.__HAS_DELETE_HANDLER__ = true;
  const qs = (s, r=document)=>r.querySelector(s);
  const csrf = () => (qs('input[name="csrf_token"]')||{}).value || '';
  function openWaiver(staffId, isPilot) {
    const base = isPilot ? "/docs/waiver/pilot" : "/docs/waiver/volunteer";
    const u = new URL(base, window.location.origin);
    if (staffId) u.searchParams.set("staff_id", staffId);
    u.searchParams.set("return", "roster");
    window.open(u.toString(), "_blank", "noopener");
  }

  function toastWithAction(msg, actionLabel, onClick) {
    // Minimal, dependency-free toast
    const host = document.createElement("div");
    host.style.cssText =
      "position:fixed;right:16px;bottom:16px;z-index:2147483647;font:14px/1.2 system-ui,-apple-system,Segoe UI,Roboto,Arial";
    const card = document.createElement("div");
    card.style.cssText =
      "background:#333;color:#fff;display:flex;gap:12px;align-items:center;border-radius:10px;padding:10px 12px;box-shadow:0 6px 24px rgba(0,0,0,.2)";
    const span = document.createElement("span");
    span.textContent = msg;
    const btn = document.createElement("button");
    btn.textContent = actionLabel;
    btn.style.cssText =
      "border:0;border-radius:8px;padding:6px 10px;background:#fff;color:#111;cursor:pointer;font-weight:600";
    btn.onclick = () => { try { onClick(); } finally { host.remove(); } };
    card.appendChild(span); card.appendChild(btn); host.appendChild(card);
    document.body.appendChild(host);
    setTimeout(() => host.remove(), 12000);
  }

  // ——— Flow trigger A: Duty roster add → ask “Are you a pilot?” → open waiver
  // Tiny modal instead of confirm()
  function choosePilotVolunteer(detail){
    const { staffId, name } = detail || {};
    const overlay = document.createElement('div');
    overlay.style.cssText="position:fixed;inset:0;background:rgba(0,0,0,.45);display:flex;align-items:center;justify-content:center;z-index:99999";
    const card = document.createElement('div');
    card.style.cssText="background:#fff;border:1px solid #ddd;border-radius:12px;min-width:280px;max-width:92vw;padding:14px;box-shadow:0 10px 30px rgba(0,0,0,.25)";
    card.innerHTML = `
      <h3 style="margin:.25rem 0 .5rem 0;">Choose waiver</h3>
      <p class="muted" style="margin:.25rem 0 .75rem 0;">for <strong>${name||'new staffer'}</strong></p>
      <div style="display:flex;gap:.5rem;flex-wrap:wrap;align-items:center;">
        <button type="button" id="w-pilot"   style="padding:.45rem .9rem;">Pilot</button>
        <button type="button" id="w-vol"     style="padding:.45rem .9rem;">Volunteer</button>
        <button type="button" id="w-cancel"  style="margin-left:auto;padding:.45rem .9rem;">Close</button>
      </div>`;
    overlay.appendChild(card); document.body.appendChild(overlay);
    const close = ()=>overlay.remove();
    card.querySelector("#w-pilot").onclick = ()=>{ openWaiver(staffId, true); close(); };
    card.querySelector("#w-vol").onclick   = ()=>{ openWaiver(staffId, false); close(); };
    card.querySelector("#w-cancel").onclick= close;
  }
  window.addEventListener("staff:add:success", (e) => choosePilotVolunteer(e.detail||{}));

  // ——— Flow trigger B: Dashboard sign-in success → same prompt
  window.addEventListener("signin:success", (e) => choosePilotVolunteer(e.detail||{}));

  // ——— Flow trigger C: Ramp / Queue / Edit (labels)
  function openLabels({ flightId, queuedId } = {}) {
    const url = queuedId
      ? `/docs/labels/cargo?queued_id=${encodeURIComponent(queuedId)}&scope=all`
      : (flightId ? `/docs/labels/cargo?flight_id=${encodeURIComponent(flightId)}&scope=all` : null);
    if (!url) return;
    window.open(url, "_blank", "noopener");
  }

  // After “Add to Queue”
  window.addEventListener("flight:queued", (e) => {
    const d = e?.detail || {};
    toastWithAction("Added to Queue.", "Print labels", () => openLabels({ flightId: d.flightId, queuedId: d.queuedId || d.id }));
  });

  // After “Send”
  window.addEventListener("flight:sent", (e) => {
    const d = e?.detail || {};
    toastWithAction("Flight sent.", "Print labels", () => openLabels({ flightId: d.flightId }));
  });

  // Helper you can call from row renderers to inject a persistent “Print Labels” button
  window.attachPrintLabelsButton = function attachPrintLabelsButton(containerEl, flightId, queuedId) {
    if (!containerEl || containerEl.querySelector("[data-role=print-labels]")) return;
    const a = document.createElement("a");
    a.textContent = "Print Labels";
    a.href = queuedId
      ? `/docs/labels/cargo?queued_id=${encodeURIComponent(queuedId)}`
      : `/docs/labels/cargo?flight_id=${encodeURIComponent(flightId)}`;
    a.target = "_blank";
    a.rel = "noopener";
    a.dataset.role = "print-labels";
    a.style.cssText =
      "display:inline-block;margin-left:8px;padding:6px 10px;border:1px solid #444;border-radius:8px;text-decoration:none";
    containerEl.appendChild(a);
  };

  // Optional: call window.renderLabelsColumn(tableEl, rows) from your table code
  window.renderLabelsColumn = function renderLabelsColumn(tableEl) {
    if (!tableEl) return;
    const head = tableEl.tHead?.rows?.[0];
    if (head && ![...head.cells].some(td => td.dataset.col === "labels")) {
      const th = document.createElement("th");
      th.dataset.col = "labels";
      th.textContent = "Labels";
      head.insertBefore(th, head.cells[Math.max(0, head.cells.length - 1)]);
    }
    [...tableEl.tBodies[0].rows].forEach((tr) => {
      if ([...tr.cells].some(td => td.dataset.col === "labels")) return;
      const td = document.createElement("td");
      td.dataset.col = "labels";
      const flightId = tr.dataset.flightId || tr.getAttribute("data-flight-id");
      const queuedId = tr.dataset.queuedId || tr.getAttribute("data-queued-id");
      const a = document.createElement("a");
      a.title = "Print labels";
      a.href = queuedId
        ? `/docs/labels/cargo?queued_id=${encodeURIComponent(queuedId)}`
        : `/docs/labels/cargo?flight_id=${encodeURIComponent(flightId)}`;
      a.target = "_blank"; a.rel = "noopener";
      a.textContent = "📦";
      td.appendChild(a);
      tr.insertBefore(td, tr.cells[Math.max(0, tr.cells.length - 1)]);
    });
  };

  // Roster hard-delete (delegated)
  document.addEventListener('click', async (e) => {
    const btn = e.target.closest('[data-action="delete-staff"][data-id]');
    if (!btn) return;
    e.preventDefault();
    const id = btn.getAttribute('data-id');
    if (!id) return;
    if (!window.confirm('Delete this staff member? This cannot be undone.')) return;
    try {
      const r = await fetch(`/supervisor/staff/${encodeURIComponent(id)}/delete`, {
        method:'POST',
        headers:{'X-Requested-With':'XMLHttpRequest','Content-Type':'application/x-www-form-urlencoded'},
        body:`csrf_token=${encodeURIComponent(csrf())}`
      });
      if (r.ok && window.reloadStaffTable) await window.reloadStaffTable();
      else alert('Delete failed.');
    } catch(_){ alert('Network error.'); }
  });

})();
