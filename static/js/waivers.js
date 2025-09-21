/* WWDART – Waivers: signatures + initials + print gating
   Works against the existing waivers.html markup with no template changes.
   - Click any .sig-field to open a drawing modal; Accept → base64 to hidden input
   - “Tap to initial” buttons fill from Printed Name; buttons then hide
   - window.print() is gated until all initials + both signatures exist
   - Print now opens in a NEW TAB; original page swaps the button to “Continue…”
*/
(function () {
  'use strict';

  // ---------- tiny DOM helpers ----------
  const $  = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  // ---------- detect which section is shown ----------
  const section =
    $('#pilot') ? 'pilot' :
    $('#volunteer') ? 'volunteer' :
    $('#labels') ? 'labels' : '';
  // Print-mode is marked in the template with data-print="1"
  const IS_PRINT_MODE = !!document.querySelector('[data-print="1"]');

  if (!section || section === 'labels') {
    // Labels sheets don’t need this JS.
    return;
  }

  // ---------- initials helpers ----------
  function deriveInitials(name) {
    if (!name) return '';
    const parts = name.trim().split(/\s+/).filter(Boolean);
    if (!parts.length) return '';
    const first = parts[0][0] || '';
    const last  = (parts[parts.length - 1] || '')[0] || '';
    return (first + last).toUpperCase();
  }

  function findPrintedInput() {
    return $('#pilot_printed') || $('#vol_printed') || $('input[name="printed_name"]');
  }

  // Set initials text on the target chip and hide its button
  function applyInitial(btn, chip, fromName) {
    const initials = deriveInitials(fromName) || '✓';
    chip.textContent = initials;
    chip.hidden = false;
    if (btn) btn.remove(); // spec: hide the “Initial” button after setting
    // expose a simple map in case we want to POST it later
    window.__waiverInitialsMap = window.__waiverInitialsMap || {};
    const key = (chip.id || '').replace(/[^\d]/g,'') || chip.id || '';
    if (key) window.__waiverInitialsMap[key] = initials;
    refreshGate();
  }

  // Wire up all “Tap to initial” buttons
  (function bindInitialButtons() {
    const printed = findPrintedInput();

    document.addEventListener('click', (e) => {
      const btn = e.target.closest('.initialize-btn');
      if (!btn) return;
      const id = btn.getAttribute('data-for');
      const chip = document.getElementById(id);
      if (!chip) return;

      const name = printed ? printed.value : '';
      applyInitial(btn, chip, name);
    });

    // If user edits Printed Name before tapping, keep any visible chips in sync
    if (printed) {
      printed.addEventListener('input', () => {
        $$('.initial-chip:not([hidden])').forEach(chip => {
          // Only update chips that look like initials (two latin letters)
          const v = chip.textContent.trim();
          if (/^[A-Z]{1,3}$/.test(v) || v === '✓' || v === '') {
            chip.textContent = deriveInitials(printed.value) || '✓';
          }
        });
        refreshGate();
      });
    }
  })();

  // ---------- signature modal ----------
  const HIDDEN_WRAP_ID = 'waiver-hidden-inputs';
  function ensureHidden(name) {
    let wrap = document.getElementById(HIDDEN_WRAP_ID);
    if (!wrap) {
      wrap = document.createElement('div');
      wrap.id = HIDDEN_WRAP_ID;
      wrap.style.display = 'none';
      document.body.appendChild(wrap);
    }
    let inp = wrap.querySelector(`input[name="${name}"]`);
    if (!inp) {
      inp = document.createElement('input');
      inp.type = 'hidden';
      inp.name = name;
      wrap.appendChild(inp);
    }
    return inp;
  }

  // Create one lazy modal we reuse for both signatures
  let modal, canvas, ctx, clearBtn, acceptBtn, cancelBtn;
  let drawing = false, last = null, currField = null, dpr = window.devicePixelRatio || 1;
  function ensureModal() {
    if (modal) return;

    modal = document.createElement('div');
    Object.assign(modal.style, {
      position: 'fixed', inset: '0', background: 'rgba(0,0,0,.45)',
      display: 'none', alignItems: 'center', justifyContent: 'center',
      zIndex: '99999',
    });

    const sheet = document.createElement('div');
    Object.assign(sheet.style, {
      background: '#fff', border: '1px solid #ccc', borderRadius: '10px',
      width: 'min(720px, 96vw)', padding: '12px', boxShadow: '0 14px 48px rgba(0,0,0,.25)'
    });

    const title = document.createElement('div');
    title.textContent = 'Draw Signature';
    Object.assign(title.style, { fontWeight: '700', margin: '2px 0 8px 2px' });

    canvas = document.createElement('canvas');
    canvas.style.width  = '100%';
    canvas.style.height = '220px';
    canvas.style.border = '1px solid #000';
    canvas.style.touchAction = 'none';

    const row = document.createElement('div');
    Object.assign(row.style, { marginTop: '10px', display: 'flex', gap: '8px', justifyContent: 'flex-end' });

    clearBtn  = document.createElement('button');
    clearBtn.type = 'button';
    clearBtn.textContent = 'Clear';
    acceptBtn = document.createElement('button');
    acceptBtn.type = 'button';
    acceptBtn.textContent = 'Accept';
    cancelBtn = document.createElement('button');
    cancelBtn.type = 'button';
    cancelBtn.textContent = 'Cancel';

    row.appendChild(cancelBtn);
    row.appendChild(clearBtn);
    row.appendChild(acceptBtn);

    sheet.appendChild(title);
    sheet.appendChild(canvas);
    sheet.appendChild(row);
    modal.appendChild(sheet);
    document.body.appendChild(modal);

    // Canvas sizing for DPR
    function resizeCanvas() {
      const rect = canvas.getBoundingClientRect();
      canvas.width  = Math.max(1, Math.round(rect.width * dpr));
      canvas.height = Math.max(1, Math.round(parseFloat(getComputedStyle(canvas).height) * dpr));
      ctx = canvas.getContext('2d');
      ctx.scale(dpr, dpr);
      ctx.lineWidth = 2.5;
      ctx.lineCap = 'round';
      ctx.lineJoin = 'round';
      ctx.strokeStyle = '#000';
      ctx.fillStyle = '#fff';
      // white background to avoid transparent PNG
      ctx.save();
      ctx.setTransform(1,0,0,1,0,0);
      ctx.fillStyle = '#fff';
      ctx.fillRect(0,0,canvas.width,canvas.height);
      ctx.restore();
    }
    new ResizeObserver(resizeCanvas).observe(canvas);
    resizeCanvas();

    // Pointer events
    function pt(e) {
      const r = canvas.getBoundingClientRect();
      return { x: e.clientX - r.left, y: e.clientY - r.top };
    }
    function start(e){
      e.preventDefault();
      drawing = true;
      last = pt(e);
    }
    function move(e){
      if (!drawing) return;
      e.preventDefault();
      const p = pt(e);
      ctx.beginPath();
      ctx.moveTo(last.x, last.y);
      ctx.lineTo(p.x, p.y);
      ctx.stroke();
      last = p;
    }
    function end(){
      drawing = false;
    }
    canvas.addEventListener('pointerdown', start, {passive:false});
    canvas.addEventListener('pointermove', move, {passive:false});
    canvas.addEventListener('pointerup',   end,  {passive:false});
    canvas.addEventListener('pointerleave',end);

    // Buttons
    clearBtn.addEventListener('click', () => {
      ctx.save();
      ctx.setTransform(1,0,0,1,0,0);
      ctx.fillStyle = '#fff';
      ctx.fillRect(0,0,canvas.width,canvas.height);
      ctx.restore();
    });
    cancelBtn.addEventListener('click', () => { modal.style.display = 'none'; currField = null; });
    acceptBtn.addEventListener('click', () => {
      if (!currField) return;

      // Export PNG (opaque)
      const dataURL = canvas.toDataURL('image/png');

      // primary names used by routes
      ensureHidden(currField.hiddenName).value = dataURL;

      // compatibility aliases
      if (currField.hiddenName === 'pilot_signature_b64') {
        ensureHidden('pilot_sig_b64').value = dataURL; // legacy
        ensureHidden('signature_b64').value = dataURL; // generic accepted by routes
      } else if (currField.hiddenName === 'witness_signature_b64') {
        ensureHidden('witness_sig_b64').value = dataURL; // legacy
      }

      // Mirror to <img> preview in the field
      let img = currField.field.querySelector('img.sig-img, img.sig-preview');
      if (!img) {
        img = document.createElement('img');
        img.className = 'sig-img';
        img.style.maxHeight = '52px';
        img.style.maxWidth  = '100%';
        img.style.display   = 'block';
        currField.field.appendChild(img);
      }
      img.src = dataURL;

      modal.style.display = 'none';
      currField = null;
      refreshGate();
    });
  }

  // Make .sig-field clickable → open modal; map to hidden input names
  (function bindSignatureFields(){
    const fields = $$('.sig-field');
    if (!fields.length) return;

    ensureModal();

    fields.forEach((field, idx) => {
      // Names expected by server routes
      const hiddenName = (idx === 0) ? 'pilot_signature_b64' : 'witness_signature_b64';

      // Cue
      const cue = document.createElement('div');
      cue.textContent = 'Click or tap to sign';
      Object.assign(cue.style, {
        position:'absolute', left:'0', right:'0', bottom:'2px',
        fontSize:'.8rem', color:'#666'
      });
      // Only show cue if no image yet
      if (!field.querySelector('img')) field.appendChild(cue);
      field.classList.add('sig-clickable');
      field.style.cursor = 'crosshair';

      field.addEventListener('click', (e) => {
        // Don’t steal clicks from existing buttons inside the field
        if (e.target.closest('button')) return;
        currField = { field, hiddenName };
        // reset canvas to blank
        clearBtn.click();
        modal.style.display = 'flex';
      });

      // If server already rendered an <img>, keep gate satisfied
      const img = field.querySelector('img');
      if (img && img.src && img.src.startsWith('data:')) {
        ensureHidden(hiddenName).value = img.src;
        if (hiddenName === 'pilot_signature_b64') {
          ensureHidden('pilot_sig_b64').value = img.src;
          ensureHidden('signature_b64').value = img.src;
        } else if (hiddenName === 'witness_signature_b64') {
          ensureHidden('witness_sig_b64').value = img.src;
        }
      }
    });
  })();

  // ---------- print gating ----------
  // Counts how many initials *rows* exist and how many chips are filled
  function initialsStatus() {
    const rows = $$('.waiver-table tbody tr');
    const chips = $$('.waiver-table .waiver-initials-col .initial-chip');
    const filled = chips.filter(ch =>
      ch && !ch.hidden && (ch.textContent || '').trim().length > 0
    ).length;
    return { rows: rows.length, filled };
  }

  function signaturesReady() {
    const p = (ensureHidden('pilot_signature_b64').value || ensureHidden('pilot_sig_b64').value);
    const w = (ensureHidden('witness_signature_b64').value || ensureHidden('witness_sig_b64').value);
    // Also accept server-provided <img> without hidden value:
    const hasP = !!p || !!($('#pilot .sig-field img') || $('#volunteer .sig-field img'));
    const hasW = !!w || (function(){
      const imgs = $$('#' + section + ' .sig-field img');
      return imgs.length >= 2; // crude but safe
    })();
    return !!p && !!w || (hasP && hasW);
  }

  function canPrintNow() {
    const { rows, filled } = initialsStatus();
    return (filled >= rows) && signaturesReady();
  }

  // Try to “disable” obvious print triggers until ready; also guard window.print
  const realPrint = window.print ? window.print.bind(window) : null;
  function guardPrint(e) {
    if (IS_PRINT_MODE || canPrintNow()) return true;
    const msg = 'Complete all initials and both signatures before printing.';
    if (window.showToast) window.showToast(msg, 'warning', 2500);
    else alert(msg);
    if (e) { e.preventDefault(); e.stopPropagation(); }
    return false;
  }

  function refreshGate() {
    // Visual affordance on any obvious print buttons
    const triggers = $$('a[href^="javascript:window.print"], .print-button, .btn-primary, button')
      .filter(el => /print/i.test(el.textContent));
    const disabled = !canPrintNow();
    triggers.forEach(el => {
      if (disabled) {
        el.setAttribute('aria-disabled', 'true');
        el.style.opacity = '0.6';
        el.style.pointerEvents = 'auto'; // we still want to intercept click
      } else {
        el.removeAttribute('aria-disabled');
        el.style.opacity = '';
        el.style.pointerEvents = '';
      }
    });
  }

  // Intercept obvious print buttons
  document.addEventListener('click', (e) => {
    const a = e.target.closest('a,button');
    if (!a) return;
    // Our dedicated print submit is handled separately
    if (a.id === 'print-submit') return;
    const isPrinty = (a.tagName === 'A' && (a.getAttribute('href') || '').includes('window.print')) ||
                     /print/i.test(a.textContent);
    if (!isPrinty) return;
    if (!guardPrint(e)) return;
    // If it was the inline JS href, allow default to proceed; otherwise call print
    if (!(a.tagName === 'A' && (a.getAttribute('href') || '').includes('window.print'))) {
      realPrint && realPrint();
    }
  });

  // Guard window.print for any other callers
  if (realPrint && !IS_PRINT_MODE) {
    window.print = function () {
      if (!canPrintNow()) { guardPrint(); return; }
      realPrint();
    };
  }

  // Kick the gate once on load
  refreshGate();

  // -------- server print submit (persists PDF + renders print-mode HTML) -----
  function getHidden(name){ return document.querySelector(`#waiver-hidden-inputs input[name="${name}"]`); }
  function collectInitials(){
    const map = {};
    document.querySelectorAll('.waiver-table .waiver-initials-col .initial-chip').forEach((chip,i)=>{
      const key = (chip.id||'').replace(/[^\d]/g,'') || String(i+1);
      const val = (chip.textContent||'').trim();
      if (val) map[key]=val;
    });
    return map;
  }
  async function submitForServerPrintAndOpenNewTab(){
    if (!canPrintNow()) { guardPrint(); return; }
    const isPilot = !!document.getElementById('pilot');
    const endpoint = isPilot ? '/docs/waiver/pilot/print' : '/docs/waiver/volunteer/print';

    // Build POST body
    const params = new URLSearchParams();
    const q = new URLSearchParams(location.search);
    const csrfToken =
      (window.CSRF_TOKEN) ||
      (document.querySelector('meta[name="csrf-token"]')?.content) ||
      (document.getElementById('csrf_token_value')?.value) ||
      (document.querySelector('input[name="csrf_token"]')?.value) || '';
    if (csrfToken) params.set('csrf_token', csrfToken);
    const printed = (document.getElementById(isPilot?'pilot_printed':'vol_printed')||{}).value || '';
    const date    = (document.getElementById(isPilot?'pilot_date':'vol_date')||{}).value || '';
    if (printed) params.set('printed_name', printed);
    if (date)    params.set('date', date);
    if (q.get('staff_id')) params.set('staff_id', q.get('staff_id'));
    if (q.get('return'))   params.set('return',   q.get('return'));
    const imap = collectInitials();
    Object.keys(imap).forEach(k => params.append(`initials[${k}]`, imap[k]));
    const sig = getHidden('pilot_signature_b64') || getHidden('signature_b64');
    const wit = getHidden('witness_signature_b64') || getHidden('witness_sig_b64');
    if (sig && sig.value) params.set(isPilot?'pilot_signature_b64':'volunteer_signature_b64', sig.value);
    if (wit && wit.value) params.set('witness_signature_b64', wit.value);

    // Request print-mode HTML, then open in a NEW TAB so this page stays put.
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type':'application/x-www-form-urlencoded;charset=UTF-8' },
      body: params.toString()
    });
    const html = await res.text();
    const w = window.open('', '_blank');
    if (w) { w.document.write(html); w.document.close(); }
  }
  // Hook our dedicated button
  document.addEventListener('click', (e)=>{
    const btn = e.target.closest('#print-submit');
    if (!btn) return;
    e.preventDefault();
    // First click: do the print in a new tab
    submitForServerPrintAndOpenNewTab().catch(()=>{});
    // Then transform this button based on which waiver we're on
    try {
      const q = new URLSearchParams(location.search);
      const staffId = q.get('staff_id') || '';
      // Determine section (already computed at top of file)
      const isPilot = (section === 'pilot');
      let nextUrl, nextLabel;
      if (isPilot) {
        nextUrl   = staffId ? (`/aircraft/new?staff_id=${encodeURIComponent(staffId)}`) : '/aircraft';
        nextLabel = 'Continue to Pilot & Aircraft Information';
      } else {
        // volunteers should go back to Duty Roster (match pai_print.html)
        nextUrl   = '/supervisor/staff?window=all';
        nextLabel = 'Return to Duty Roster';
      }

      // If a ?return=/path is present, prefer it (same-origin only, path-absolute)
      const ret = (q.get('return') || '').trim();
      if (ret && ret.startsWith('/')) {
        nextUrl = ret;
      }

      btn.textContent = nextLabel;
      btn.id = 'continue-to-pai';
      btn.classList.remove('btn-primary');
      btn.classList.add('btn-secondary');
      btn.disabled = false;
      btn.onclick = () => { window.location.href = nextUrl; };
    } catch(_) {}
  });
})();
