(() => {
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  const drawer = $("#reqDrawer");
  const overlay = $("#reqOverlay");
  const fab = $("#fabRequests");
  const badge = $("#fabRequestsBadge");
  const refreshBtn = $("#reqRefresh");
  const closeBtn = $("#reqClose");
  const groups = $("#reqGroups");
  const quickAdd = $("#reqQuickAdd");

  // If this page doesn't include the drawer partial, bail quietly.
  if (!drawer || !overlay || !fab) return;

  // --- tiny toast helper (uses your #toast-container styles if present) ---
  function ensureToastContainer() {
    let tc = document.getElementById("toast-container");
    if (!tc) {
      tc = document.createElement("div");
      tc.id = "toast-container";
      document.body.appendChild(tc);
    }
    return tc;
  }
  function showToast(msg, kind = "info", ms = 2500) {
    const tc = ensureToastContainer();
    const t = document.createElement("div");
    t.className = `toast ${kind}`;
    t.textContent = msg;
    tc.appendChild(t);
    // force reflow then animate
    requestAnimationFrame(() => {
      t.classList.add("show");
      setTimeout(() => {
        t.classList.remove("show");
        t.classList.add("hide");
        setTimeout(() => t.remove(), 300);
      }, ms);
    });
  }

  // --- drawer open/close ---
  function openDrawer() {
    drawer.classList.add("open");
    drawer.setAttribute("aria-hidden", "false");
    overlay.classList.remove("hidden");
    overlay.setAttribute("aria-hidden", "false");
  }
  function closeDrawer() {
    drawer.classList.remove("open");
    drawer.setAttribute("aria-hidden", "true");
    overlay.classList.add("hidden");
    overlay.setAttribute("aria-hidden", "true");
  }

  overlay.addEventListener("click", closeDrawer);
  closeBtn?.addEventListener("click", closeDrawer);
  fab.addEventListener("click", () => {
    openDrawer();
    // lazy refresh on open if we don't have content yet
    if (!groups.dataset.hydrated) {
      fetchSummary().catch(() => {});
    }
  });

  // --- data fetch/render ---
  async function fetchSummary() {
    const res = await fetch("/requests/summary", { credentials: "same-origin" });
    if (!res.ok) throw new Error(`Summary HTTP ${res.status}`);
    const data = await res.json();
    renderSummary(data);
  }

  function number(n) {
    try { return new Intl.NumberFormat().format(n); }
    catch { return String(n); }
  }

  function renderSummary(data) {
    const total = (data?.open_items_total) || 0;
    badge.textContent = total;

    const aps = (data?.airports) || [];
    groups.innerHTML = "";
    groups.dataset.hydrated = "1";

    if (!aps.length) {
      const empty = document.createElement("div");
      empty.className = "req-empty";
      empty.textContent = "No open requests.";
      groups.appendChild(empty);
      return;
    }

    for (const ap of aps) {
      const group = document.createElement("section");
      group.className = "req-group";
      group.dataset.airport = ap.airport;

      // header
      const head = document.createElement("div");
      head.className = "req-group-h";
      const title = document.createElement("div");
      title.className = "req-group-title";
      title.textContent = `${ap.airport} • ${ap.open_items} open`;
      const actions = document.createElement("div");
      actions.className = "req-group-actions";
      const clearBtn = document.createElement("button");
      clearBtn.type = "button";
      clearBtn.className = "button small";
      clearBtn.textContent = "Clear airport";
      clearBtn.addEventListener("click", () => clearAirport(ap.airport));
      actions.appendChild(clearBtn);
      head.appendChild(title);
      head.appendChild(actions);

      // items
      const body = document.createElement("div");
      body.className = "req-items";

      if (!ap.items?.length) {
        const d = document.createElement("div");
        d.className = "req-empty";
        d.textContent = "No lines.";
        body.appendChild(d);
      } else {
        for (const it of ap.items) {
          const row = document.createElement("div");
          row.className = "req-row";

          const left = document.createElement("div");
          left.className = "req-row-name";
          left.textContent = it.name;

          const right = document.createElement("div");
          right.className = "req-row-meta";
          const meta = document.createElement("span");
          meta.textContent = `Req ${number(it.requested_lb)} • Ful ${number(it.fulfilled_lb)} • Out ${number(it.outstanding_lb)}`;
          const rm = document.createElement("button");
          rm.type = "button";
          rm.className = "button small";
          rm.style.marginLeft = ".5rem";
          rm.textContent = "Remove";
          rm.addEventListener("click", () => removeLine(ap.airport, it.name));
          right.appendChild(meta);
          right.appendChild(rm);

          row.appendChild(left);
          row.appendChild(right);
          body.appendChild(row);
        }
      }

      group.appendChild(head);
      group.appendChild(body);
      groups.appendChild(group);
    }
  }

  // --- actions ---
  async function clearAirport(airport) {
    if (!airport) return;
    if (!confirm(`Clear all open request lines for ${airport}?`)) return;
    const res = await fetch("/requests/airport", {
      method: "DELETE",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify({ airport })
    });
    if (!res.ok) {
      showToast(`Failed to clear ${airport}`, "error");
      return;
    }
    showToast(`Cleared ${airport}`, "success");
    await fetchSummary().catch(() => {});
  }

  async function removeLine(airport, name) {
    const res = await fetch("/requests/line", {
      method: "DELETE",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify({ airport, name })
    });
    if (!res.ok) {
      showToast(`Failed to remove ${name}`, "error");
      return;
    }
    showToast(`Removed ${name}`, "success");
    await fetchSummary().catch(() => {});
  }

  quickAdd?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const fd = new FormData(quickAdd);
    const airport = (fd.get("airport") || "").toString().trim().toUpperCase();
    const name = (fd.get("name") || "").toString().trim();
    const w = parseFloat((fd.get("weight_lb") || "").toString());
    if (!airport || !name || !(w > 0)) {
      showToast("Fill airport, item, and positive weight", "warning");
      return;
    }
    const payload = {
      airport,
      items: [{ name, weight_lb: w }]
    };
    const res = await fetch("/requests/intake", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify(payload)
    });
    if (!res.ok) {
      showToast("Add failed", "error");
      return;
    }
    try {
      const j = await res.json();
      const added = j?.added ?? 1;
      showToast(`Added ${added} item${added === 1 ? "" : "s"}`, "success");
    } catch {
      showToast("Added", "success");
    }
    quickAdd.reset();
    await fetchSummary().catch(() => {});
  });

  refreshBtn?.addEventListener("click", () => fetchSummary().catch(() => {}));

  // poll every 30s; keep light
  let pollTimer = null;
  function startPolling() {
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = setInterval(() => {
      // Only poll when drawer is open or the tab is focused (lightweight choice)
      if (drawer.classList.contains("open") || !document.hidden) {
        fetchSummary().catch(() => {});
      }
    }, 30000);
  }
  startPolling();

  // initial lazy fetch after load (keeps idle pages quiet)
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) fetchSummary().catch(() => {});
  }, { passive: true });
})();
