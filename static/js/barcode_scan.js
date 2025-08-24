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
  const resetAll = () => { saveDirOnce(getScanDir()); window.location.reload(); };

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
    const qtyDefault = ai?.count || 1;
    if (resultEl) resultEl.innerHTML = `
      <div class="card" style="border:1px solid #ddd;border-radius:10px;padding:12px;">
        <div><strong>${item.sanitized_name}</strong></div>
        <div>Category ID: ${item.category_id}</div>
        <div>Unit size: ${item.weight_per_unit} lb</div>
        <label>Quantity
          <input id="qty" type="number" min="1" step="1" value="${qtyDefault}" style="padding:6px;">
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
        const qty = parseInt($('#qty')?.value || '1', 10);
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
    setStatus('Unknown','warn');
    if (!createEl) return;
    // If the category <select> is empty, populate it. Prefer cloning from the page's main category,
    // otherwise fetch a lightweight list.
    const catSelect = createEl.querySelector('#u_cat');
    if (catSelect && !catSelect.options.length) {
      const mainCat = document.getElementById('category');
      if (mainCat && mainCat.options.length) {
        catSelect.innerHTML = mainCat.innerHTML;
        // Drop the disabled placeholder if present
        const first = catSelect.querySelector('option[disabled]');
        if (first) catSelect.removeChild(first);
      } else {
        try {
          const cats = await fetch(URLS.cats, { headers: {'X-Requested-With':'XMLHttpRequest'} }).then(r => r.json());
          catSelect.innerHTML = cats.categories.map(c => `<option value="${c.id}">${c.display_name}</option>`).join('');
        } catch {}
      }
    }
    createEl.hidden = false;
    createEl.querySelector('#u_barcode').value = code;
    createEl.querySelector('#u_name').value = '';
    createEl.querySelector('#u_wpu').value  = '';
    const unitSel = createEl.querySelector('#u_unit'); if (unitSel) unitSel.value = 'lbs';
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
      if (data.item) { setStatus('Known ✓','ok'); beep(); showKnown(data.item, code, ai); }  // beep only on scan success
      else { await showUnknownForm(code); }
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
      const unit = (createEl.querySelector('#u_unit')?.value || 'lbs').toLowerCase();
      const payload = {
        barcode:        createEl.querySelector('#u_barcode').value.trim(),
        category_id:    createEl.querySelector('#u_cat').value,
        name:           createEl.querySelector('#u_name').value.trim(),
        // convert to pounds before sending (DB stores lbs)
        weight_per_unit: (() => {
          const v = parseFloat(createEl.querySelector('#u_wpu').value);
          if (!isFinite(v) || v <= 0) return NaN;
          return unit === 'oz' ? (v / 16.0) : v;
        })()
      };
      if (!payload.barcode || !payload.category_id || !payload.name || !isFinite(payload.weight_per_unit) || payload.weight_per_unit <= 0) {
        setStatus('Please complete all required fields.','err'); return;
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
