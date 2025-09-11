(function(){
  const btnOpen   = document.getElementById('help-open');
  const panel     = document.getElementById('help-panel');
  const backdrop  = document.getElementById('help-backdrop');
  const btnClose  = document.getElementById('help-close');
  const body      = document.getElementById('help-body');
  const meta      = document.getElementById('help-meta');
  const titleEl   = document.getElementById('help-title');
  const btnEdit   = document.getElementById('help-edit-btn');
  const btnCancel = document.getElementById('help-cancel-btn');
  const btnSave   = document.getElementById('help-save-btn');
  const editWrap  = document.getElementById('help-edit');
  const titleInp  = document.getElementById('help-title-input');
  const mdInp     = document.getElementById('help-md-input');

  let current = null; // {route_prefix,title,body_md,version,updated_at_utc,editable,not_found?}
  let editing = false;

  function openPanel(){ backdrop.style.display='block'; panel.style.display='block'; }
  function closePanel(){ backdrop.style.display='none'; panel.style.display='none'; setEdit(false); }
  function setEdit(on){
    editing = !!on;
    editWrap.style.display = on ? 'block' : 'none';
    body.style.display     = on ? 'none'  : 'block';
    btnEdit.style.display  = (!on && current && current.editable) ? 'inline-block' : 'none';
    btnCancel.style.display= on ? 'inline-block' : 'none';
    btnSave.style.display  = on ? 'inline-block' : 'none';
  }

  async function fetchArticle(){
    const path = window.location.pathname;
    // Ask backend for the article; it returns both Markdown and sanitized HTML.
    const url  = `/help/api/article?path=${encodeURIComponent(path)}`;
    const r    = await fetch(url, {cache:'no-store'});
    if (!r.ok) throw new Error('Failed to load help');
    current = await r.json();
    renderView();
  }

  function escapeHtml(s){ return (s||'').replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])) }

  function renderView(){
    const title = current.title || 'Help';
    // Prefer sanitized server-rendered HTML; fall back to readable Markdown.
    const html  = current.body_html || current.body;
    titleEl.textContent = title;
    if (html) {
      // Insert sanitized HTML fragment from the server
      body.innerHTML = html;
    } else {
      // Fallback: readable Markdown as preformatted text
      body.innerHTML = `<pre style="white-space:pre-wrap;">${escapeHtml(current.body_md || current.raw || '')}</pre>`;
    }
    meta.textContent = (current.updated_at_utc ? `Updated: ${current.updated_at_utc}` : '');
    btnEdit.style.display = current.editable ? 'inline-block' : 'none';
    setEdit(false);
  }

  function beginEdit(){
    titleInp.value = current.title || '';
    // Ensure editor shows raw Markdown (alias supported by backend)
    mdInp.value    = current.body_md || current.raw || '';
    setEdit(true);
  }

  async function saveEdit(){
    const payload = {
      route_prefix: current.route_prefix || window.location.pathname,  // creating new if placeholder
      title: titleInp.value.trim() || 'Help',
      body_md: mdInp.value,
      version: current.version || 0
    };
    const r = await fetch('/help/api/article', {
      method:'PUT',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify(payload)
    });
    if (r.status === 409){
      const j = await r.json();
      window.showToast?.('Someone else edited this doc. Reloading…','warn',3500);
      await fetchArticle(); // reload latest
      return;
    }
    if (!r.ok){
      window.showToast?.('Save failed','error',3000);
      return;
    }
    const j = await r.json();
    window.showToast?.('Saved','success',1800);
    // Immediately reflect saved content without a second fetch when possible
    try {
      current = Object.assign({}, current, {
        title: j.title ?? current.title,
        body_md: j.body_md ?? current.body_md,
        body_html: j.body_html ?? current.body_html,
        raw: j.raw ?? current.raw,
        version: j.version ?? current.version,
        updated_at_utc: j.updated_at_utc ?? current.updated_at_utc
      });
      renderView();
    } catch (_e) {
      // If anything goes odd, fall back to refetching.
      await fetchArticle();
    }
  }

  // Wiring
  if (btnOpen){
    btnOpen.addEventListener('click', async ()=>{
      try{
        await fetchArticle();
        openPanel();
      }catch(e){
        window.showToast?.('Help failed to load','error',3000);
      }
    });
  }
  if (btnClose)  btnClose.addEventListener('click', closePanel);
  if (backdrop)  backdrop.addEventListener('click', closePanel);
  if (btnEdit)   btnEdit.addEventListener('click', beginEdit);
  if (btnCancel) btnCancel.addEventListener('click', ()=>setEdit(false));
  if (btnSave)   btnSave.addEventListener('click', saveEdit);
})();
