/* Manual Correction modal: examples + per-type builder + re-parse.
   - Opens automatically when the inbound parse is "allBlank" (client detects).
   - Left: original message (filled from #incoming-form values).
   - Right: tabs with a form for each type + live-composed subject/body.
   - “Insert into Form” fills the inbound form for manual submit.
   - “Build & Re-parse” fills and programmatically submits for a second try.
*/
(function(){
  const modal    = document.getElementById('correction-modal');
  if (!modal) return;

  const tabsWrap = document.getElementById('corr-tabs');

  // Original
  const origSubj = document.getElementById('corr-orig-subject');
  const origBody = document.getElementById('corr-orig-body');

  // Composer preview
  const subjEl   = document.getElementById('corr-subject');
  const bodyEl   = document.getElementById('corr-body');

  const btnCopyS = document.getElementById('corr-copy-subject');
  const btnCopyB = document.getElementById('corr-copy-body');
  const fbS      = document.getElementById('corr-fb-subj');
  const fbB      = document.getElementById('corr-fb-body');
  const btnInsert= document.getElementById('corr-insert');
  const btnReparse=document.getElementById('corr-reparse');
  const btnClose = document.getElementById('corr-close');

  // Forms
  const forms = {
    airops_flight: {
      el: qs('[data-kind="airops_flight"]'),
      get: () => ({
        tail: gv('#af_tail'), from: gv('#af_from'), to: gv('#af_to'),
        dep: gv('#af_dep'), eta: gv('#af_eta'),
        ct: gv('#af_ct'), cw: gv('#af_cw'),
        code: gv('#af_code'), rem: gv('#af_rem')
      }),
      compose(d){
        const hh = normHHMM(d.dep), ee = normHHMM(d.eta);
        const subject =
          `Air Ops: ${d.tail || 'TBD'} | ${d.from || 'TBD'} to ${d.to || 'TBD'} | ` +
          `took off ${hh || '----'} | ETA ${ee || '----'}`;
        const lines = [];
        // mirror the body format used elsewhere in the app
        lines.push("**** TEST MESSAGE ONLY  (if reporting on an actual flight, delete this line). ****");
        lines.push("YOURCALL message number 000.");
        lines.push("");
        lines.push(`Aircraft ${d.tail || 'TBD'}:`);
        lines.push(`  Cargo Type(s) ................. ${d.ct || 'none'}`);
        lines.push(`  Total Weight of the Cargo ..... ${d.cw || 'none'}`);
        lines.push("");
        lines.push("Additional notes/comments:");
        if ((d.code || '').trim()) lines.push(`  Flight Code: ${d.code.trim()}`);
        if ((d.rem || '').trim()) lines.push(`  ${d.rem.trim()}`);
        lines.push("");
        lines.push("{DART Aircraft Takeoff Report, rev. 2024-05-14}");
        return { subject, body: lines.join('\n') };
      }
    },

    aoct_cargo_snapshot: {
      el: qs('[data-kind="aoct_cargo_snapshot"]'),
      get: () => ({
        subject: gv('#acs_subject'),
        airport: gv('#acs_airport'),
        ts:      gv('#acs_ts'),
        units:   gv('#acs_units') || 'pounds',
        payload: gv('#acs_payload')
      }),
      compose(d){
        const head  = `${d.subject || 'AOCT cargo reply'}`;
        const hdr   = `AOCT inventory @ ${(d.airport || '').toUpperCase()} (as of ${d.ts || ''})`;
        const lines = [hdr, `Units: ${d.units || 'pounds'}`, '', (d.payload || '').trim()];
        return { subject: head, body: lines.join('\n') };
      }
    },

    aoct_cargo_query: {
      el: qs('[data-kind="aoct_cargo_query"]'),
      get: () => ({
        airport: gv('#acq_airport'),
        categories: gv('#acq_categories'),
        csv: gv('#acq_csv') || 'YES',
      }),
      compose(d){
        const cats = (d.categories || '').trim();
        const lines = [
          "AOCT cargo query", "",
          `AIRPORT: ${(d.airport || '').toUpperCase()}`,
          `CATEGORIES: ${cats}`,
          `CSV: ${d.csv === 'NO' ? 'NO' : 'YES'}`,
          "", "{AOCT cargo query, rev. 2025-09-01}"
        ];
        return { subject: "AOCT cargo query", body: lines.join('\n') };
      }
    },

    aoct_flight_reply: {
      el: qs('[data-kind="aoct_flight_reply"]'),
      get: () => ({
        tail: gv('#afr_tail'),
        pos:  gv('#afr_pos'),
        track: gv('#afr_track'),
        gs:   gv('#afr_gs'),
        alt:  gv('#afr_alt'),
        ts:   gv('#afr_ts'),
        recv_airport: gv('#afr_airport'),
        recv_call:    gv('#afr_call'),
        source:       gv('#afr_source')
      }),
      compose(d){
        const lines = [
          `TAIL: ${(d.tail || '').toUpperCase()}`,
          `POSITION: ${d.pos || ''}`,
          `TRACK_DEG: ${d.track || ''}`,
          `GROUND_SPEED_KT: ${d.gs || ''}`,
          `ALTITUDE_FT: ${d.alt || ''}`,
          `SAMPLE_TS: ${d.ts || ''}`,
          `RECEIVER_AIRPORT: ${(d.recv_airport || '').toUpperCase()}`,
          `RECEIVER_CALL: ${(d.recv_call || '').toUpperCase()}`,
          `SOURCE: ${d.source || ''}`,
          "{AOCT flight reply, rev. 2025-09-01}"
        ];
        // Match field format (subject + first line include tail; Title Case).
        const subjTail = (d.tail || '').toUpperCase();
        const subject  = `AOCT Flight Reply: ${subjTail}`.trim();
        const bodyTop  = `AOCT Flight Reply: ${subjTail}`;
        return { subject, body: [bodyTop, "", ...lines].join('\n') };
      }
    },

    aoct_flight_query: {
      el: qs('[data-kind="aoct_flight_query"]'),
      get: () => ({
        tail: gv('#afq_tail'),
        from: gv('#afq_from'),
        csv:  gv('#afq_csv') || 'NO'
      }),
      compose(d){
        const lines = [
          "AOCT flight query", "",
          `TAIL: ${(d.tail || '').toUpperCase()}`,
          `FROM_AIRPORT: ${(d.from || '').toUpperCase()}`,
          `CSV: ${d.csv === 'YES' ? 'YES' : 'NO'}`,
          "NOTE: Reply with your last known ADS-B sighting if any.",
          "{AOCT flight query, rev. 2025-09-01}"
        ];
        return { subject: "AOCT flight query", body: lines.join('\n') };
      }
    }
  };

  // Helpers
  function qs(sel){ return document.querySelector(sel); }
  function gv(sel){ const el = qs(sel); return (el && 'value' in el) ? el.value.trim() : ''; }
  function normHHMM(t){
    const d = String(t||'').replace(/[^0-9]/g,''); if (!d) return '';
    return d.padStart(4,'0').slice(-4);
  }
  function copyText(text, fbEl){
    const ok = () => { fbEl.textContent = '✔ Copied!'; fbEl.classList.add('visible'); setTimeout(()=> fbEl.classList.remove('visible'), 1200); };
    if (navigator.clipboard?.writeText) navigator.clipboard.writeText(text).then(ok).catch(fallback);
    else fallback();
    function fallback(){ const ta=document.createElement('textarea'); ta.value=text; ta.style.position='fixed'; ta.style.opacity='0'; document.body.appendChild(ta); ta.select(); try{document.execCommand('copy');}catch(_){ } document.body.removeChild(ta); ok(); }
  }

  // Active tab handling
  let active = 'airops_flight';
  function setActive(kind){
    active = kind in forms ? kind : 'airops_flight';
    tabsWrap.querySelectorAll('.corr-tab').forEach(btn=>{
      const on = btn.dataset.kind === active;
      btn.classList.toggle('btn-yellow', on);
      btn.classList.toggle('yellow', on);
    });
    // show form
    document.querySelectorAll('.corr-form').forEach(p=> p.style.display = (p.dataset.kind === active ? '' : 'none'));
    // compose once from current fields
    composeNow();
  }

  function composeNow(){
    const f = forms[active];
    if (!f) return;
    const d = f.get();
    const r = f.compose(d);
    subjEl.value = r.subject || '';
    bodyEl.value = r.body || '';
  }

  // Wire tab clicks
  tabsWrap.addEventListener('click', (e)=>{
    const btn = e.target.closest('.corr-tab'); if (!btn) return;
    setActive(btn.dataset.kind);
  });

  // Recompose on any input inside forms
  document.querySelector('.corr-forms').addEventListener('input', composeNow);

  // Copy buttons
  btnCopyS.addEventListener('click', ()=> copyText(subjEl.value, fbS));
  btnCopyB.addEventListener('click', ()=> copyText(bodyEl.value, fbB));

  // Insert into Log Incoming form (does not submit)
  btnInsert.addEventListener('click', ()=>{
    const form = document.getElementById('incoming-form');
    const s = form?.querySelector('input[name="subject"]');
    const b = form?.querySelector('textarea[name="body"]');
    if (!form || !s || !b) return alert('Incoming form not found on this page.');
    s.value = subjEl.value;
    b.value = bodyEl.value;
    b.dispatchEvent(new Event('input', { bubbles:true })); // auto-resize
    modal.style.display = 'none';
    form.scrollIntoView({ behavior: 'smooth', block: 'center' });
  });

  // Build & Re-parse (programmatically submit)
  btnReparse.addEventListener('click', ()=>{
    const form = document.getElementById('incoming-form');
    const s = form?.querySelector('input[name="subject"]');
    const b = form?.querySelector('textarea[name="body"]');
    if (!form || !s || !b) return alert('Incoming form not found on this page.');
    s.value = subjEl.value;
    b.value = bodyEl.value;
    b.dispatchEvent(new Event('input', { bubbles:true }));
    // mark that this is a correction re-try; the page script checks this
    window._corrPending = true;
    modal.style.display = 'none';
    // programmatic submit (uses the same AJAX handler already bound)
    form.requestSubmit ? form.requestSubmit() : form.submit();
  });

  // Close
  function close(){ modal.style.display = 'none'; }
  btnClose.addEventListener('click', close);
  modal.addEventListener('click', (ev)=>{ if (ev.target === modal) close(); });
  document.addEventListener('keydown', function onEsc(ev){
    if (ev.key === 'Escape'){ close(); document.removeEventListener('keydown', onEsc); }
  });

  // Global opener used by the page script on parse failure
  function openModal(defaultKind){
    // Fill left pane with the current inbound form contents
    const form = document.getElementById('incoming-form');
    const s = form?.querySelector('input[name="subject"]')?.value || '';
    const b = form?.querySelector('textarea[name="body"]')?.value || '';
    origSubj.value = s;
    origBody.value = b;
    setActive(defaultKind || 'airops_flight');
    modal.style.display = 'flex';
  }
  window.openCorrectionExamples = openModal;

  // Also add a small “Examples” button next to the header for manual access
  (function addTriggerBtn(){
    const header = Array.from(document.querySelectorAll('h3'))
      .find(h => /Log Incoming Winlink Message/i.test(h.textContent || ''));
    if (!header) return;
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'btn btn-secondary';
    btn.textContent = 'Examples / Fix';
    btn.style.marginLeft = '.5rem';
    btn.addEventListener('click', ()=> openModal('airops_flight'));
    header.appendChild(btn);
  })();
})();
