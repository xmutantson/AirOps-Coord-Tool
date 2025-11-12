// ... existing code ...

  async function paperworkDone(){
    const plane_id = _state.plane_id;
    if (plane_id == null){ _noSelectionModal(); return; }
    // Open ramp boss paperwork modal
    if (window.WG_UI && typeof window.WG_UI.openRampBossPaperwork === 'function'){
      window.WG_UI.openRampBossPaperwork({
        plane_id,
        onDone: async () => {
          console.log('[PlanePanel] paperworkDone onDone callback triggered');
          console.log('[PlanePanel] _state.el:', _state.el);
          console.log('[PlanePanel] _state.open:', _state.open);
          // Refresh panel to show updated state after paperwork completion
          const {requests, origin} = await fetchRequests().catch((e)=>{console.error('[PlanePanel] fetchRequests error:', e); return {requests:[], origin:'—'};});
          console.log('[PlanePanel] Fetched requests:', requests.length, 'origin:', origin);
          renderRequestsTable(_state.el, requests, origin);
          console.log('[PlanePanel] After renderRequestsTable, calling checkStatus...');
          await checkStatus();
          console.log('[PlanePanel] checkStatus complete');
        }
      });
    } else {
      // Fallback: direct API call without modal
      const payload = {
        plane_id,
        session_id: (window.WG_SESSION_ID ?? 1),
        player_id:  (window.WG_PLAYER_ID ?? null)
      };
      const r = await fetch('/api/wargame/plane/paperwork_complete', {
        method:'POST', credentials:'same-origin',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify(payload)
      });
      const j = await r.json().catch(()=>({}));
      if (!r.ok){ throw j; }
      // Clear manifest area and refresh request list
      renderManifestTable(_state.el, []);
      const {requests, origin} = await fetchRequests().catch(()=>({requests:[], origin:'—'}));
      renderRequestsTable(_state.el, requests, origin);
      await checkStatus();
    }
  }

// ... existing code ...

  // Provide a single entrypoint used by the scene when near a plane
  function initWargamePanel(rootEl){
    // Hook buttons if template provides them
    // Note: Load button's onclick is dynamically set in checkStatus() based on status
    const btnLoad = $('#wgpp-load', rootEl);
    const btnRefresh = $('#wgpp-refresh', rootEl);
    if (btnLoad)    btnLoad.onclick    = ()=>loadPlane().catch(e=>showFriendlyError(e,{action:'load'}));
    if (btnRefresh) btnRefresh.onclick = ()=>checkStatus();
    
    // DEBUG: Add logging to see if this function is called
    console.log('[PlanePanel] initWargamePanel called for plane_id:', _state.plane_id);
  }

// ... existing code ...

  async function checkStatus(){
    if (!_state.open || !_state.el) return;
    const plane_id = _state.plane_id;
    if (plane_id == null){ _noSelectionModal(); return; }
    try{
      // Prefer locked cart implicitly (server may default as well)
      const locked = (typeof window.__WG_getLockedCartUid === 'function') ? window.__WG_getLockedCartUid() : null;
      const url = `/api/wargame/plane/status?plane_id=${encodeURIComponent(plane_id)}${locked?`&cart_id=${encodeURIComponent(locked)}`:''}`;
      console.log('[PlanePanel] checkStatus: fetching from URL:', url);
      const r = await fetch(url, { credentials:'same-origin' });
      const j = await r.json().catch(()=>({}));
      console.log('[PlanePanel] checkStatus: received response:', j);
      _state.lastStatus = j || {};
      setStatusPill(_state.el, _state.lastStatus.status || '—');
      // Render required lines if a request is pinned
      const required = (_state.lastStatus.pin && _state.lastStatus.pin.required) || [];
      renderManifestTable(_state.el, required);
      // Render shortages/excess summary
      renderValidate(_state.el, _state.lastStatus.diff || null);
      // Update button based on status
      const ready = String(_state.lastStatus.status||'').toLowerCase() === 'ready';
      const loaded = String(_state.lastStatus.status||'').toLowerCase() === 'loaded';
      const idle = String(_state.lastStatus.status||'').toLowerCase() === 'idle';
      const loadBtn = $('#wgpp-load', _state.el);
      if (loadBtn) {
        if (loaded) {
          // Cargo already loaded, show "Open Paperwork" button
          loadBtn.textContent = 'Open Paperwork';
          loadBtn.disabled = false;
          loadBtn.className = 'btn'; // Remove primary styling
          loadBtn.onclick = ()=>paperworkDone().catch(e=>showFriendlyError(e,{action:'paperwork'}));
        } else {
          // Cargo not yet loaded, show "Load Cargo" button
          loadBtn.textContent = 'Load Cargo';
          loadBtn.disabled = !ready;
          loadBtn.className = 'btn btn-primary';
          loadBtn.onclick = ()=>loadPlane().catch(e=>showFriendlyError(e,{action:'load'}));
        }
      }
    }catch(e){ 
      console.warn("plane/status failed", e); 
      console.log('[PlanePanel] checkStatus failed with error:', e);
    }
  }

// ... existing code ...
