// static/js/barcode_scan.js
(() => {
  const app = document.querySelector('#scan-app'); // container on /inventory/scan and inventory_detail.html
  // NOTE: this script is loaded once; scope everything to #scan-app to avoid collisions
  if (!app) return;
  // scope all lookups to the container to avoid ID collisions
  const $ = (sel) => app.querySelector(sel);

  // Endpoint URLs (can be replaced server-side by setting data-* on #scan-app)
  const URLS = {
    lookup:   app.dataset.urlLookup     || '/inventory/api/lookup_barcode',
    scanPost: app.dataset.urlScanPost || '/inventory/api/scan_barcode',
    saveMap:  app.dataset.urlSaveMap  || '/inventory/api/save_barcode_mapping',
    cats:     app.dataset.urlCategories || '/inventory/api/categories',
    admin:    app.dataset.urlAdmin    || '/inventory/barcodes', // not used in inline flow anymore, but left for reference
  };
  // Optional manifest session (supports /inventory/scan?mid=<session_id>)
  const MANIFEST_ID = app.dataset.manifestId || new URLSearchParams(location.search).get('mid') || '';

  // Prefer linear barcodes only (ignore QR/DataMatrix/PDF417/Aztec)
  const LINEAR_FORMATS = () => {
    const ZX = window.ZXing;
    return [
      ZX.BarcodeFormat.UPC_A, ZX.BarcodeFormat.UPC_E,
      ZX.BarcodeFormat.EAN_13, ZX.BarcodeFormat.EAN_8,
      ZX.BarcodeFormat.CODE_128, ZX.BarcodeFormat.CODE_39,
      ZX.BarcodeFormat.ITF, ZX.BarcodeFormat.CODABAR
    ];
  };

  // CSRF token: read from <meta> or existing form hidden input
  const csrfToken =
    (document.querySelector('meta[name="csrf-token"]')?.content) ||
    (document.querySelector('input[name="csrf_token"]')?.value) || '';
  const jsonHeaders = () => ({
    'Content-Type': 'application/json',
    'X-Requested-With': 'XMLHttpRequest',
    ...(csrfToken ? {'X-CSRFToken': csrfToken} : {})
  });

  const statusEl  = $('#scan-status');
  const kbd       = $('#scan-kbd');
  const submitKbd = $('#scan-kbd-submit');
  const resultEl  = $('#scan-result');
  const createEl  = $('#scan-create');       // inline unknown mapping form
  const photoBtn  = $('#scan-photo-btn');    // native camera via file capture
  const photoInput= $('#scan-photo-input');
  const beep = () => document.getElementById('beep').play().catch(()=>{});
  const RESET_FLAG = 'scan_reset_cleared';
  const clearScanBox = () => { if (kbd) { kbd.value = ''; try { kbd.setAttribute('value',''); } catch(_) {} } };

  // Default focus for “Focus here and scan” field (helps operators land + scan)
  if (kbd) {
    try { kbd.focus({ preventScroll: true }); } catch(_) { kbd.focus(); }
    // If we just came from a Reset-triggered reload, ensure the field is blank
    try { if (sessionStorage.getItem(RESET_FLAG)) { sessionStorage.removeItem(RESET_FLAG); clearScanBox(); } } catch(_){}
  }

  // ── one-shot sticky direction (persists ONLY across our JS reloads) ─────────
  const DIR_STICKY_KEY = 'scan_dir_once';
  const DIR_STICKY_MS  = 90 * 1000; // 90s TTL
  function saveDirOnce(dir) {
    try { sessionStorage.setItem(DIR_STICKY_KEY, JSON.stringify({ dir, ts: Date.now() })); } catch {}
  }
  function consumeDirOnce() {
    try {
      const raw = sessionStorage.getItem(DIR_STICKY_KEY);
      if (!raw) return null;
      sessionStorage.removeItem(DIR_STICKY_KEY);
      const v = JSON.parse(raw);
      if (!v || !v.dir || !v.ts) return null;
      if ((Date.now() - v.ts) > DIR_STICKY_MS) return null;
      return v.dir; // 'IN' | 'OUT'
    } catch {}
    return null;
  }
  // Apply one-shot sticky direction on load (if present)
  (function applySticky() {
    const sticky = consumeDirOnce();
    if (!sticky) return;
    const wantIn = (sticky === 'IN');
    const rIn  = document.getElementById('dir-in');
    const rOut = document.getElementById('dir-out');
    if (rIn && rOut) { rIn.checked = wantIn; rOut.checked = !wantIn; }
  })();
  // one-shot reset (looks like closing the scan UI) — preserve direction for the reload
  const resetAll = () => {
    // Clear the input so browsers don’t restore stale digits on reload
    clearScanBox();
    try { sessionStorage.setItem(RESET_FLAG, '1'); } catch(_){}
    saveDirOnce(getScanDir());
    window.location.reload();
  };

  let lastCode = '', lastTs = 0;            // debounce for repeated reads
  let burstTimer = 0, burstChars = 0;       // USB burst detection

  // Single helper for direction (works on /scan and on inventory detail)
  const getScanDir = () => {
    const v = document.querySelector('input[name="dir"]:checked')?.value
           || document.querySelector('input[name="direction"]:checked')?.value
           || 'IN';
    return (v === 'out' || v === 'OUT') ? 'OUT' : 'IN';
  };
  const setStatus = (msg, cls) => { statusEl.textContent = msg; statusEl.className = 'badge ' + (cls||''); };
  const norm = s => (s||'').toString().trim().replace(/\s+/g,'');

  // Read scanner mode: prefer cookie (updated live), else data-scanner-mode
  function getScanMode(){
    // 1) Source of truth: the checked radio on the page (live toggle)
    const rb = document.querySelector('input[name="scanner_mode_toggle"]:checked');
    if (rb) {
      const v = String(rb.value || '').toLowerCase().trim();
      return (v === 'auto1') ? 'auto1' : 'prompt';
    }
    // 2) Fallbacks for initial/default state (no radio present)
    // Match start or "; " then scanner_mode=...
    const mCookie = (document.cookie.match(/(?:^|;\s*)scanner_mode=([^;]+)/) || [])[1];
    const fromCookie = mCookie ? decodeURIComponent(mCookie) : '';
    const fromData   = (app && app.dataset ? app.dataset.scannerMode : '') || '';
    const v = (fromCookie || fromData || 'prompt').toLowerCase().trim();
    return (v === 'auto1') ? 'auto1' : 'prompt';
  }

  // --- Global redirect of scanner keystrokes when nothing is focused -----------
  function isTypingElement(el){
    if (!el) return false;
    if (el.isContentEditable) return true;
    const tag = el.tagName;
    return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT';
  }
  document.addEventListener('keydown', (e) => {
    if (!kbd) return;
    // If user is already typing in any field/button/etc → don't hijack.
    const ae = document.activeElement;
    if (isTypingElement(ae)) return;
    // Ignore modifiers / navigation keys.
    if (e.ctrlKey || e.metaKey || e.altKey) return;
    const key = e.key || '';
    const printable = key.length === 1; // digits/letters/symbols
    const isEnter   = (key === 'Enter' || key === 'NumpadEnter');
    if (!printable && !isEnter) return;

    // Redirect: focus the scan box and ensure first char is captured.
    kbd.focus();
    if (isEnter) {
      e.preventDefault();
      return handleCode(kbd.value);
    }
    // Swallow this first key and inject it so the burst continues in the field.
    e.preventDefault();
    const start = kbd.selectionStart ?? kbd.value.length;
    const end   = kbd.selectionEnd   ?? kbd.value.length;
    kbd.value = kbd.value.slice(0,start) + key + kbd.value.slice(end);
    kbd.setSelectionRange(start+1, start+1);
    // Kick the existing burst-detection so “idle ≥120ms” triggers lookup.
    burstChars++; clearTimeout(burstTimer);
    burstTimer = setTimeout(() => { if (burstChars >= 5) handleCode(kbd.value); burstChars = 0; }, 120);
  });

  async function postKnownAuto1(code, item){
    const dirWord = (getScanDir() === 'IN') ? 'inbound' : 'outbound';
    const payload = {
      barcode: code,
      qty: 1,
      direction: dirWord,
      commit_now: true,
      manifest_id: MANIFEST_ID || undefined
    };
    const r = await fetch(URLS.scanPost, { method:'POST', headers: jsonHeaders(), body: JSON.stringify(payload) });
    let j = null; try { j = await r.json(); } catch(_){}
    if (!r.ok || !j || j.status !== 'ok') {
      const msg = (j && (j.message || j.error)) || 'Scan failed';
      if (window.showToast) window.showToast(msg, 'error', 3800); else setStatus(msg, 'err');
      return false;
    }
    // success: toast, clear UI, keep focus for the next scan, refresh table if present
    const wpu = Number(j.weight_per_unit ?? item?.weight_per_unit ?? 0).toFixed(1);
    const nm  = j.sanitized_name || item?.sanitized_name || 'item';
    const msg = `Logged ${j.direction} 1 × ${nm} (${wpu} lb)`;
    if (window.showToast) window.showToast(msg, 'success', 3200); else setStatus('Posted ✓','ok');
    if (resultEl) resultEl.innerHTML = '';
    hideLegacyForm(false);
    if (kbd) { kbd.value = ''; kbd.focus(); }
    try { document.getElementById('beep')?.play?.(); } catch(_){}
    if (typeof window.loadInventoryDetail === 'function') { try { window.loadInventoryDetail(); } catch(_){} }
    return true;
  }

  // Add a small “Reset” button into the header row next to the status pill
  (function injectHeaderReset(){
    if (!statusEl) return;
    const row = statusEl.parentElement;
    if (!row || row.querySelector('#scan-reset')) return;
    const btn = document.createElement('button');
    btn.id = 'scan-reset';
    btn.type = 'button';
    btn.textContent = 'Reset';
    btn.addEventListener('click', resetAll);
    row.appendChild(btn);
  })();

  // hide/show the classic inventory form (Inventory Detail page only)
  function hideLegacyForm(hide) {
    const form = document.getElementById('inventory-form');
    if (form) form.style.display = hide ? 'none' : '';
  }

  // Tiny GS1 parser for AIs in (XX) groups. We only care about count (37) and net weight 310x/311x -> grams.
  function parseGS1(s) {
    s = (s || '').replace(/\u001d/g,'');
    const ai = {};
    const re = /\((\d{2,4})\)([^\(]+)/g;
    let m; while ((m = re.exec(s)) !== null) ai[m[1]] = m[2];
    for (let x=0; x<=6; x++) {
      const k = '310' + x; if (ai[k]) ai.net_weight_g = Math.round(parseFloat(ai[k]) / (10**x) * 1000);
    }
    for (let x=0; x<=6; x++) {
      const k = '311' + x; if (ai[k]) ai.net_weight_g = Math.round(parseFloat(ai[k]) / (10**x) * 1000);
    }
    if (ai['37']) ai.count = parseInt(ai['37'],10) || undefined;
    return ai;
  }

  // Prefill the existing Inventory Detail form (if present)
  function prefillInventoryForm(item) {
    const form = document.getElementById('inventory-form');
    if (!form) return; // if we're on /inventory/scan, there's no detail form

    const dirOut = document.getElementById('dir-out')?.checked;
    const categoryEl = document.getElementById('category');
    const nameTxt    = document.getElementById('name');
    const nameSel    = document.getElementById('name-select');
    const weightTxt  = document.getElementById('weight');
    const weightSel  = document.getElementById('weight-select');
    const weightUnit = document.getElementById('weight_unit');
    const qtyFld     = document.getElementById('qty');

    if (categoryEl) {
      categoryEl.value = String(item.category_id);
      categoryEl.dispatchEvent(new Event('change'));
    }
    if (dirOut) {
      // Outbound uses selects; trigger the same code the page already has
      if (nameSel) {
        nameSel.value = item.sanitized_name;
        nameSel.dispatchEvent(new Event('change'));
      }
      // After sizes populate, set weight by value (stored in lbs)
      setTimeout(() => {
        if (weightSel) {
          // Values are raw pounds (as strings)
          weightSel.value = String(item.weight_per_unit);
          weightSel.dispatchEvent(new Event('change'));
        }
        qtyFld && qtyFld.focus();
      }, 0);
    } else {
      // Inbound: free-text + unit toggle
      if (nameTxt) nameTxt.value = item.sanitized_name;
      if (weightTxt) weightTxt.value = String(item.weight_per_unit);
      if (weightUnit) weightUnit.value = 'lbs';
      qtyFld && qtyFld.focus();
    }
  }

  function showKnown(item, code, ai) {
    const qtyDefault = ai?.count; // suggest only; do not preselect
    if (resultEl) resultEl.innerHTML = `
      <div class="card" style="border:1px solid #ddd;border-radius:10px;padding:12px;">
        <div><strong>${item.sanitized_name}</strong></div>
        <div>Category ID: ${item.category_id}</div>
        <div>Unit size: ${item.weight_per_unit} lb</div>
        <label>Quantity
          <select id="qty" required style="padding:6px;">
            <option value="" disabled selected>Qty…</option>
            ${Array.from({length:20}, (_,i)=>`<option value="${i+1}">${i+1}</option>`).join('')}
          </select>
          ${Number.isFinite(qtyDefault) ? `<small style="margin-left:6px;">Suggested: ${qtyDefault}</small>` : ``}
        </label>
        <div style="display:flex;gap:8px;align-items:center;margin-top:8px;flex-wrap:wrap;">
          <button id="postTx">Post ${getScanDir()}</button>
          <button id="scan-reset-card" type="button">Reset</button>
          <small>Scanned: <code>${code}</code></small>
        </div>
      </div>
    `;
    $('#scan-reset-card')?.addEventListener('click', resetAll);
    // Hide the classic form while the quick-post card is active
    hideLegacyForm(true);

    const postBtn = $('#postTx');
    if (postBtn) {
      postBtn.onclick = async () => {
        const qtyVal = $('#qty')?.value || '';
        if (!qtyVal) { setStatus('Choose a quantity','err'); $('#qty')?.focus(); return; }
        const qty = parseInt(qtyVal, 10);
        const dirWord = getScanDir() === 'IN' ? 'inbound' : 'outbound';
        const body = { barcode: code, qty, direction: dirWord, commit_now: true, manifest_id: MANIFEST_ID || undefined };
        const resp = await fetch(URLS.scanPost, { method:'POST', headers: jsonHeaders(), body: JSON.stringify(body) });
        if (resp.ok) {
          setStatus(`Posted ${dirWord} x${qty}`,'ok'); /* no beep on posting */
          // Preserve direction across our own reload
          saveDirOnce(getScanDir());
          // Reset everything so the classic form returns and lists refresh.
          window.location.reload();
        }
        else setStatus('Failed to post transaction','err');
      };
    }
  }

  // Build or reveal the inline "unknown barcode" form.
  async function showUnknownForm(code) {
    // If we were in OUTBOUND, force back to INBOUND before adding a new item.
    (function forceInbound() {
      const rIn  = document.getElementById('dir-in');
      const rOut = document.getElementById('dir-out');
      if (rIn && rOut) {
        if (!rIn.checked) {
          rIn.checked = true;
          rOut.checked = false;
          rIn.dispatchEvent(new Event('change'));
        }
      } else {
        // /inventory/scan radios (name="dir", values IN/OUT)
        const radios = document.querySelectorAll('input[name="dir"]');
        if (radios && radios.length) {
          for (const r of radios) r.checked = (String(r.value).toUpperCase() === 'IN');
          const inRadio = Array.from(radios).find(r => String(r.value).toUpperCase() === 'IN');
          if (inRadio) inRadio.dispatchEvent(new Event('change'));
        }
      }
    })();
    setStatus('Unknown → switched to Inbound','warn');
    // Hide the legacy inventory form while the unknown-item card is up
    hideLegacyForm(true);
    if (!createEl) return;
    // Populate the Category <select> if it has no real options (i.e., only the placeholder).
    // Prefer cloning from the page's main category; otherwise fetch a lightweight list.
    const catSelect = createEl.querySelector('#u_cat');
    if (catSelect) {
      const hasRealOptions = Array.from(catSelect.options)
        .some(o => !o.disabled && String(o.value).trim() !== '');
      if (!hasRealOptions) {
      const mainCat = document.getElementById('category');
      if (mainCat && mainCat.options.length) {
        // Build a cleaned list (skip disabled placeholders) and prepend our own placeholder
        const opts = Array.from(mainCat.options)
                          .filter(o => !o.disabled && String(o.value).trim() !== '');
        catSelect.innerHTML =
          '<option value="" disabled selected>— choose category —</option>' +
          opts.map(o => `<option value="${o.value}">${o.text}</option>`).join('');
      } else {
        try {
          const cats = await fetch(URLS.cats, { headers: {'X-Requested-With':'XMLHttpRequest'} }).then(r => r.json());
          catSelect.innerHTML =
            '<option value="" disabled selected>— choose category —</option>' +
            cats.categories.map(c => `<option value="${c.id}">${c.display_name}</option>`).join('');
          } catch {}
        }
      }
    }
    // Enforce required fields visually too
    if (catSelect) catSelect.required = true;
    const nameEl = createEl.querySelector('#u_name'); if (nameEl) nameEl.required = true;
    const wpuEl  = createEl.querySelector('#u_wpu');  if (wpuEl)  wpuEl.required  = true;
    const unitSel= createEl.querySelector('#u_unit');
    if (unitSel) {
      unitSel.required = true;
      // Ensure a placeholder exists and is selected
      if (!unitSel.querySelector('option[value=""]')) {
        unitSel.insertAdjacentHTML('afterbegin','<option value="" disabled selected>unit</option>');
      }
      unitSel.value = '';
    }
    createEl.hidden = false;
    createEl.querySelector('#u_barcode').value = code;
    createEl.querySelector('#u_name').value = '';
    createEl.querySelector('#u_wpu').value  = '';
    const unitSel2 = createEl.querySelector('#u_unit'); if (unitSel2) unitSel2.value = '';
  }

  async function handleCode(raw, sym='unknown') {
    const code = norm(raw);
    if (!code) return;
    const now = performance.now();
    if (code === lastCode && (now - lastTs) < 1000) return; // debounce
    lastCode = code; lastTs = now;

    setStatus('Looking up…');
    const ai = parseGS1(code);

    // GET or POST lookup; we’ll use POST to keep it simple/consistent
    const resp = await fetch(URLS.lookup, { method:'POST', headers: jsonHeaders(), body: JSON.stringify({ code }) });
    if (resp.ok) {
      const data = await resp.json();
      if (data.item) {
        setStatus('Known ✓','ok');
        beep(); // acknowledge a successful read
        // In single-qty mode, auto-post qty=1 and skip the card entirely.
        if (getScanMode() === 'auto1') {
          const done = await postKnownAuto1(code, data.item);
          if (done) return; // short-circuit; stay in scanning flow
        }
        // Otherwise fall back to the quick-post card (prompt for qty)
        showKnown(data.item, code, ai);
      } else {
        await showUnknownForm(code);
      }
    } else setStatus('Lookup failed','err');
  }

  // ────────────────────────────────────────────────────────────────
  // Photo capture decode (works on HTTP; no camera stream required)
  // ────────────────────────────────────────────────────────────────
  let _zxingReady = null;
  async function loadZXing() {
    if (window.ZXing) return window.ZXing;
    if (_zxingReady) return _zxingReady;
    setStatus('Loading decoder…');
    // Prefer a local vendored UMD build; allow override via data-zxing-url on #scan-app
    const zxingURL = app.dataset.zxingUrl || '/static/js/zxing.min.js';
    _zxingReady = new Promise((resolve, reject) => {
      const s = document.createElement('script');
      // UMD build exposes window.ZXing
      s.src = zxingURL;
      s.async = true;
      s.onload = () => resolve(window.ZXing);
      s.onerror = () => reject(new Error('Failed to load ZXing'));
      document.head.appendChild(s);
    });
    return _zxingReady;
  }

  // ────────────────────────────────────────────────────────────────
  // Image helpers: scale, grayscale+contrast, sharpen, crop, rotate
  // ────────────────────────────────────────────────────────────────
  function drawScaled(img, maxLongEdge = 1800) {
    const w = img.naturalWidth || img.width, h = img.naturalHeight || img.height;
    const scale = Math.min(1, maxLongEdge / Math.max(w, h)); // do not upscale
    const cw = Math.round(w * scale), ch = Math.round(h * scale);
    const c = document.createElement('canvas');
    c.width = cw; c.height = ch;
    const ctx = c.getContext('2d', { willReadFrequently: true });
    ctx.drawImage(img, 0, 0, cw, ch);
    return c;
  }

  function toGrayscaleContrast(canvas) {
    const c = document.createElement('canvas');
    c.width = canvas.width; c.height = canvas.height;
    const ctx = c.getContext('2d', { willReadFrequently: true });
    ctx.drawImage(canvas, 0, 0);
    const img = ctx.getImageData(0, 0, c.width, c.height);
    const d = img.data;
    // luminance histogram for auto-levels (5th–95th percentile)
    const hist = new Uint32Array(256);
    for (let i = 0; i < d.length; i += 4) {
      const y = (d[i]*0.299 + d[i+1]*0.587 + d[i+2]*0.114) | 0;
      hist[y]++; d[i] = d[i+1] = d[i+2] = y;
    }
    let total = (d.length/4)|0, lo = 0, hi = 255, acc = 0;
    const lowCut = total * 0.05, highCut = total * 0.95;
    for (let i=0;i<256;i++){ acc += hist[i]; if (acc >= lowCut){ lo=i; break; } }
    acc = 0;
    for (let i=255;i>=0;i--){ acc += hist[i]; if (acc >= (total - highCut)){ hi=i; break; } }
    const range = Math.max(1, hi - lo);
    for (let i = 0; i < d.length; i += 4) {
      let y = d[i]; y = (255 * (y - lo) / range) | 0;
      if (y < 0) y = 0; else if (y > 255) y = 255;
      d[i] = d[i+1] = d[i+2] = y;
    }
    ctx.putImageData(img, 0, 0);
    return c;
  }

  function lightUnsharp(canvas, amount = 0.45) {
    // simple 3x3 high-pass “unsharp” for soft prints (cardboard)
    const c = document.createElement('canvas');
    c.width = canvas.width; c.height = canvas.height;
    const ctx = c.getContext('2d', { willReadFrequently: true });
    ctx.drawImage(canvas, 0, 0);
    const img = ctx.getImageData(0, 0, c.width, c.height);
    const src = img.data;
    const out = new Uint8ClampedArray(src);
    const w = c.width, h = c.height;
    const idx = (x,y)=>((y*w + x)<<2);
    for (let y=1;y<h-1;y++){
      for (let x=1;x<w-1;x++){
        const i = idx(x,y);
        const center = src[i];
        const e = (
          - src[idx(x-1,y-1)] - src[idx(x,y-1)] - src[idx(x+1,y-1)]
          - src[idx(x-1,y  )] + 8*center       - src[idx(x+1,y  )]
          - src[idx(x-1,y+1)] - src[idx(x,y+1)] - src[idx(x+1,y+1)]
        ) / 8;
        const yv = Math.max(0, Math.min(255, center + amount * e));
        out[i] = out[i+1] = out[i+2] = yv;
      }
    }
    img.data.set(out);
    ctx.putImageData(img, 0, 0);
    return c;
  }

  function rotateCanvas(canvas, deg) {
    if (deg % 360 === 0) return canvas;
    const rad = (deg * Math.PI) / 180;
    const c = document.createElement('canvas');
    const ctx = c.getContext('2d');
    const w = canvas.width, h = canvas.height;
    if (deg === 90 || deg === 270) { c.width = h; c.height = w; }
    else { c.width = w; c.height = h; }
    ctx.translate(c.width/2, c.height/2);
    ctx.rotate(rad);
    ctx.drawImage(canvas, -w/2, -h/2);
    return c;
  }

  function cropCanvas(canvas, x, y, w, h) {
    const c = document.createElement('canvas');
    c.width = w; c.height = h;
    const ctx = c.getContext('2d');
    ctx.drawImage(canvas, x, y, w, h, 0, 0, w, h);
    return c;
  }

  function makeTileVariants(baseCanvas) {
    const W = baseCanvas.width, H = baseCanvas.height;
    const variants = [];
    // Full frame
    variants.push(baseCanvas);
    // Center crop (~70%)
    const cw = Math.round(W * 0.7), ch = Math.round(H * 0.7);
    variants.push(cropCanvas(baseCanvas, Math.round((W-cw)/2), Math.round((H-ch)/2), cw, ch));
    // 4 quadrants (~60%)
    const qw = Math.round(W * 0.6), qh = Math.round(H * 0.6);
    variants.push(cropCanvas(baseCanvas, 0, 0, qw, qh));                           // TL
    variants.push(cropCanvas(baseCanvas, W-qw, 0, qw, qh));                        // TR
    variants.push(cropCanvas(baseCanvas, 0, H-qh, qw, qh));                        // BL
    variants.push(cropCanvas(baseCanvas, W-qw, H-qh, qw, qh));                     // BR
    return variants;
  }

  async function decodeFromVariants(reader, canvases) {
    // Feed supported API: decodeFromImageUrl(dataURL)
    const rotations = [0, 90, 180, 270];
    for (const c of canvases) {
      for (const deg of rotations) {
        const rc = rotateCanvas(c, deg);
        const dataURL = rc.toDataURL('image/png');
        try { return await reader.decodeFromImageUrl(dataURL); }
        catch (_) { /* try next */ }
      }
    }
    throw new Error('no-decode');
  }

  async function decodeWithFallbacks(url) {
    const ZX = await loadZXing(); // may throw if script can’t load
    // Hints: try harder & linear formats only
    const hints = new Map();
    hints.set(ZX.DecodeHintType.TRY_HARDER, true);
    hints.set(ZX.DecodeHintType.POSSIBLE_FORMATS, LINEAR_FORMATS());
    const reader = new ZX.BrowserMultiFormatReader(hints);

    // Quick path: try the original file as-is first.
    try { return await reader.decodeFromImageUrl(url); } catch (_) {}

    // Load once as an <img>, then build canvases for stages & tiles
    const img = await new Promise((res, rej) => {
      const i = new Image();
      i.onload = () => res(i);
      i.onerror = () => rej(new Error('Image load failed'));
      i.src = url;
    });

    const base  = drawScaled(img, 1800);
    const gray  = toGrayscaleContrast(base);
    const sharp = lightUnsharp(gray, 0.45);

    const stages = [
      makeTileVariants(base),
      makeTileVariants(gray),
      makeTileVariants(sharp),
    ];

    for (const tiles of stages) {
      try {
        return await decodeFromVariants(reader, tiles);
      } catch (_) { /* next stage */ }
    }
    throw new Error('no-decode');
  }

  async function handlePhoto(file) {
    if (!file) return;
    const url = URL.createObjectURL(file);
    try {
      let res;
      try {
        res = await decodeWithFallbacks(url);
      } catch (e) {
        // Distinguish load vs decode failures
        if (String(e && e.message || e).toLowerCase().includes('failed to load zxing')
            || String(e).toLowerCase().includes('failed to load')) {
          setStatus('Decoder failed to load','err');
          return;
        }
        setStatus('No barcode found (try closer / more light)','err');
        return;
      }
      const text = res?.text || res?.getText?.();
      if (text) {
        setStatus('Photo decoded ✓','ok');
        await handleCode(text);
      } else {
        setStatus('No barcode found (try closer / more light)','err');
      }
    } finally {
      URL.revokeObjectURL(url);
    }
  }

  if (photoBtn && photoInput) {
    photoBtn.onclick = () => photoInput.click();
    photoInput.addEventListener('change', () => {
      const f = photoInput.files && photoInput.files[0];
      if (f) handlePhoto(f);
      photoInput.value = ''; // allow re-selecting same file
    });
  }

  // USB/manual handlers with "typing burst" detection
  if (submitKbd) submitKbd.onclick = () => handleCode(kbd.value);
  if (kbd) {
    kbd.addEventListener('keydown', e => {
      // Enter submits immediately
      if (e.key === 'Enter') return handleCode(kbd.value);
      // burst detection: >=5 chars with <=120ms between keystrokes, idle >=120ms ends burst
      burstChars++;
      clearTimeout(burstTimer);
      burstTimer = setTimeout(() => {
        if (burstChars >= 5) handleCode(kbd.value);
        burstChars = 0;
      }, 120);
    });
  }

  // Inline unknown form actions (present on both scan page and detail page)
  if (createEl) {
    const saveBtn = createEl.querySelector('#u_save');
    const cancelBtn = createEl.querySelector('#u_cancel');
    if (saveBtn) saveBtn.onclick = async () => {
      const unitEl = createEl.querySelector('#u_unit');
      const unit   = (unitEl && unitEl.value ? unitEl.value : '').toLowerCase();
      const payload = {
        barcode:        createEl.querySelector('#u_barcode').value.trim(),
        category_id:    createEl.querySelector('#u_cat').value,
        name:           createEl.querySelector('#u_name').value.trim(),
        // convert to pounds before sending (DB stores lbs)
        weight_per_unit: (() => {
          const v = parseFloat(createEl.querySelector('#u_wpu').value);
          if (!isFinite(v) || v <= 0) return NaN;
          if (!unit) return NaN;
          return unit === 'oz' ? (v / 16.0) : v;
        })()
      };
      if (!unit) { setStatus('Please choose a unit.','err'); unitEl && unitEl.focus(); return; }
      if (!payload.barcode || !payload.category_id || !payload.name || !isFinite(payload.weight_per_unit) || payload.weight_per_unit <= 0) {
        setStatus('Please complete all required fields.','err');
        if (!payload.category_id) createEl.querySelector('#u_cat')?.focus();
        else if (!payload.name)   createEl.querySelector('#u_name')?.focus();
        else if (!(payload.weight_per_unit>0)) createEl.querySelector('#u_wpu')?.focus();
        return;
      }
      setStatus('Saving…');
      const r = await fetch(URLS.saveMap, { method:'POST', headers: jsonHeaders(), body: JSON.stringify(payload) });
      if (!r.ok) { setStatus('Save failed','err'); return; }
      const data = await r.json();
      createEl.hidden = true;
      setStatus('Mapping saved ✓','ok'); // no beep here; beep only on scan
      if (data.item) showKnown(data.item, payload.barcode, null); // prefill + show quick-post card
    };
    if (cancelBtn) cancelBtn.onclick = resetAll; // cancel = reset the scanner UI
  }

  // Global “Esc” to reset while scanner UI is active
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') resetAll(); });

  // If the legacy Inventory Detail form ever submits normally, keep direction sticky for one reload
  const invForm = document.getElementById('inventory-form');
  if (invForm) {
    invForm.addEventListener('submit', () => { try { saveDirOnce(getScanDir()); } catch {} });
  }
})();
