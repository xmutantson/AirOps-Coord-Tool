// static/wargame/game.js
(function () {
  const DEFAULT_ITEM_KEY = "box";
  const BIN_TO_HUMAN = { S: "small", M: "medium", L: "large", XL: "xl" };
  const HUMAN_TO_BIN = { small: "S", medium: "M", large: "L", xl: "XL" };
  const BIN_TO_LABEL = { S: "S", M: "M", L: "L", XL: "XL" };
  const PLANE_PROX_RADIUS = 64; // player "E" interact threshold to open Plane Panel

  function start() { try { boot(); } catch (e) { console.error(e); showFatal("Boot error — see console."); } }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start); else start();

  function showFatal(msg) {
    const el = document.createElement("div");
    el.style.cssText = "position:fixed;inset:0;display:flex;align-items:center;justify-content:center;background:#0f1115;color:#fff;z-index:99999;font:600 16px/1.4 system-ui,Segoe UI,Roboto";
    el.textContent = msg || "Something went wrong."; document.body.appendChild(el);
  }

  // --------- tiny utils ----------
  function clamp(v, lo, hi){ return Math.max(lo, Math.min(hi, v)); }
  function vecToDir(x,y){
    const a=Math.atan2(y,x), d=(a*180/Math.PI+360)%360;
    if (d>=337.5||d<22.5) return 'E'; if (d<67.5) return 'SE'; if (d<112.5) return 'S';
    if (d<157.5) return 'SW'; if (d<202.5) return 'W'; if (d<247.5) return 'NW';
    if (d<292.5) return 'N'; return 'NE';
  }
  function bodyRect(b){ return { left:b.x, top:b.y, right:b.x+b.width, bottom:b.y+b.height, width:b.width, height:b.height }; }
  function spriteRect(s){ return { left:s.x - s.displayWidth*s.originX, top:s.y - s.displayHeight*s.originY, right:s.x + s.displayWidth*(1-s.originX), bottom:s.y + s.displayHeight*(1-s.originY) }; }
  function distRects(A,B){ const dx=Math.max(0,Math.max(B.left-A.right,A.left-B.right)); const dy=Math.max(0,Math.max(B.top-A.bottom,A.top-B.bottom)); return Math.hypot(dx,dy); }
  function inflateRect(r,dx,dy){ return { left:r.left-dx, top:r.top-dy, right:r.right+dx, bottom:r.bottom+dy, width:r.width+2*dx, height:r.height+2*dy }; }
  function binToHuman(x){ const u=String(x||"").toUpperCase(); return BIN_TO_HUMAN[u] || (["small","medium","large","xl"].includes(String(x).toLowerCase()) ? String(x).toLowerCase() : "medium"); }

  // --------- server time smoothing ----------
  function makeClockSync(){ let skew=0; return {
    tick(serverTime){ if (typeof serverTime!=='number'||!isFinite(serverTime)) return; const now=performance.now()/1000; const s=serverTime-now; const diff=Math.abs(s-skew); const a= diff>0.25?0.5:0.12; skew=(1-a)*skew+a*s; },
    now(){ return performance.now()/1000 + skew; }
  };}

  function makeInterpBuffer(maxSamples){ const buf=[]; let lastSeq=0; const MAX=Math.max(6,maxSamples|0); return {
    push(seq,t,x,y,dir){ if(!seq||seq<=lastSeq) return; lastSeq=seq; buf.push({seq,t,x,y,dir:dir||'S'}); if(buf.length>MAX) buf.splice(0, buf.length-MAX); },
    at(t){ if(!buf.length) return null; if(buf.length===1 || t<=buf[0].t){ const s=buf[0]; return {x:s.x,y:s.y,dir:s.dir}; }
      let i=1; for(; i<buf.length && buf[i].t<t; i++); if(i>=buf.length){ const L=buf[buf.length-1]; return {x:L.x,y:L.y,dir:L.dir}; }
      const A=buf[i-1], B=buf[i]; const span=Math.max(1e-3, B.t-A.t); const u=Math.max(0,Math.min(1,(t-A.t)/span));
      return { x:A.x+(B.x-A.x)*u, y:A.y+(B.y-A.y)*u, dir:u<0.5?A.dir:B.dir };
    }
  };}

  // --------- game ----------
  function boot(){
    // world + visuals
    const VW=1600, VH=900, SPEED=180, BORDER=24;
    const ATLAS_SCALE=0.5, DEPTH={ bg:-20, fence:-10, ui:1000, hint:10000 };
    // Debug HUD toggle (fully hidden when false)
    const SHOW_DEBUG_HUD = false;
    const ALLOW_POINTER_CLICK = false;
    const PLAYER_W=48, PLAYER_H=64, PLAYER_COLL_W=32, PLAYER_COLL_H=28, PLAYER_COLL_YOFF=PLAYER_H-PLAYER_COLL_H;

    // geometry
    const PICK_PAD=10;
    const TERMINAL_RADIUS = 56;

    const STOCKPILE_RECT={ left:580, top:109, right:1165, bottom:211 }; STOCKPILE_RECT.width=STOCKPILE_RECT.right-STOCKPILE_RECT.left; STOCKPILE_RECT.height=STOCKPILE_RECT.bottom-STOCKPILE_RECT.top;
    const SP_INSET=8, BIN_GAP=12, CELL_GAP=2;

    // net timing
    const POS_HZ=8, POLL_MS=110, INTERP_DELAY_MS=80, REMOTE_RENDER_HZ=60, INTERP_MAX_SAMPLES=12;

    // phaser
    const config={ type:Phaser.AUTO, parent:"game-root", backgroundColor:"#0f1115", width:VW, height:VH,
      scale:{ mode:Phaser.Scale.FIT, autoCenter:Phaser.Scale.CENTER_BOTH },
      physics:{ default:"arcade", arcade:{ debug:false } },
      scene:{ preload, create, update } };

    // locals
    let scene, gridLayer, fenceRect;
    let player, nameText, heldBox, hudText;
    let keyW,keyA,keyS,keyD,keyE;
    let propsGroup, colliderRef;
    const ySortSet=new Set();

    // carry
    let carrying=false, heldSize='medium', heldItemKey=null, lastDir='S';
    // NEW (Step 6/7): metadata-aware carrying
    let heldQty=0, heldDisplayName="", heldUnitLb=0;

    // stockpile viewmodel
    const stockpile={ label:null, terminal:null, terminalHitScale:2, fenceGfx:null, wallGroup:null, walls:[], rect:{...STOCKPILE_RECT}, yBase:STOCKPILE_RECT.bottom, geom:{}, bins:{small:[],medium:[],large:[],xl:[]}, hidden:{small:0,medium:0,large:0,xl:0}, badges:{}, sprites:[] };

    // carriers
    const carriers=[], carriersByUid=new Map(); const CART='cart', TRUCK='truck';
    // Step 5: single-cart rule (lock to the *north* cart)
    let LOCKED_CART_UID = null;

    // planes (bodies + wings)
    const planes=[]; // {id, tail, body, wingsBack, wingsFront, facing, cargoRect}
    // plane obstacles (static physics rects)
    let planeObstacleGroup, planeObstacleCollider, planeObstacles = []; // [{rect, plane}]

    // remotes
    const remotes=new Map(); let remoteTimer=null, remoteRenderTimer=null; const clock=makeClockSync();

    // mp
    const netAvailable=!!window.WGNet; let netJoined=false; let myPlayerId=null; let seenClaimId=0; let trucksEpochSeen=0;

    // ui
    let hintContainer,hintBG,hintText, modalEl,modalMsgEl,modalBodyEl,modalOK,modalCancel;
    let nameGate=null, pendingName=null;

    // --- pending-local ops to prevent double-applying our own optimistic changes ---
    const pendingLocalOps = [];
    function addPending(op){
      const token = Object.assign({_id: Math.random().toString(36).slice(2)}, op||{});
      pendingLocalOps.push(token); return token;
    }
    function cancelPending(token){
      const i = pendingLocalOps.indexOf(token);
      if (i >= 0) pendingLocalOps.splice(i,1);
    }
    function consumeMatchingPending(claim){
      if (!claim || claim.player_id !== myPlayerId) return false;
      const act = (claim.action||"").toLowerCase();
      const size = binToHuman(claim.size||"medium");
      for (let i=0;i<pendingLocalOps.length;i++){
        const p = pendingLocalOps[i];
        if ((p.action||"").toLowerCase() !== act) continue;
        if (p.size !== size) continue;
        if (act.startsWith("carrier_")){
          if (String(p.carrier_type) !== String(claim.carrier_type)) continue;
          if (String(p.carrier_uid)  !== String(claim.carrier_uid))  continue;
        }
        pendingLocalOps.splice(i,1);
        return true;
      }
      return false;
    }

    // --- serialize claims (prevents race between pickup→deposit chain) ---
    let _pendingClaim = Promise.resolve();
    function postClaimSerial(payload){
      _pendingClaim = _pendingClaim.then(() => WGNet.postClaim(payload));
      return _pendingClaim;
    }

    // ---------- helpers ----------
    function markForYSort(s,extra){ if(!s) return; s.__yExtra=(typeof extra==='number')?extra:0; ySortSet.add(s); s.setDepth((s.y||0)+s.__yExtra); }
    function ySortTick(){ ySortSet.forEach(s=>{ if(!s||!s.scene||s.destroyed) return; s.setDepth((s.y||0)+(s.__yExtra||0)); }); }
    function drawFence(){ if (fenceRect) fenceRect.destroy(); fenceRect=scene.add.graphics().setDepth(DEPTH.fence); fenceRect.lineStyle(3,0x3a4453,1).strokeRect(BORDER,BORDER,VW-2*BORDER,VH-2*BORDER); }
    function drawGrid(g,w,h,step){ g.clear(); g.lineStyle(1,0x2a3038,1); for(let x=0;x<=w;x+=step) g.lineBetween(x,0,x,h); for(let y=0;y<=h;y+=step) g.lineBetween(0,y,w,h); g.lineStyle(2,0x20242a,1); g.lineBetween(w/2,0,w/2,h); g.lineBetween(0,h/2,w,h/2); }
    function toggleGrid(on){ const want=(typeof on==='boolean')?on:!(gridLayer&&gridLayer.visible); if(!gridLayer){ gridLayer=scene.add.graphics().setDepth(DEPTH.bg); drawGrid(gridLayer,VW,VH,50); } gridLayer.setVisible(want); }

    function ensurePlaceholders(){
      if (scene.textures.exists('ph:player-S')) return;
      if (window.AssetKit && window.AssetKit.ensurePlaceholders) { window.AssetKit.ensurePlaceholders(scene); return; }
      const makeRect=(key,w,h,fill,stroke=0)=>{ if(scene.textures.exists(key)) return; const g=scene.add.graphics(); g.fillStyle(fill,1).fillRect(0,0,w,h); if(stroke) g.lineStyle(2,stroke,1).strokeRect(1,1,w-2,h-2); g.generateTexture(key,w,h); g.destroy(); };
      makeRect('ph:box-small',22,22,0xf6cf65); makeRect('ph:box-medium',28,28,0xe9a948); makeRect('ph:box-large',34,34,0xcc7f2d); makeRect('ph:box-xl',42,42,0xb86b21);
      makeRect('ph:player',48,64,0xff3b30,0x000000);
      makeRect('ph:cart-left',88,48,0x6aa2d9,0x1e3a5f); makeRect('ph:truck-right',128,64,0x708090);
      makeRect('ph:plane-right',140,64,0xcfd8dc,0x90a4ae);
      // NEW placeholders if AssetKit isn't loaded:
      makeRect('ph:plane-body',140,64,0xd9e3e8,0x6f7f89);
      makeRect('ph:plane-wings',160,64,0xbfcad0,0x81929c);
    }
    function texForBox(size){
      try{ if(scene.textures.exists('atlas:boxes')){ const f={small:'box_s',medium:'box_m',large:'box_l',xl:'box_xl'}[size]||'box_m'; return { atlas:'atlas:boxes', frame:f, scale:ATLAS_SCALE }; } }catch(e){}
      const key={small:'ph:box-small',medium:'ph:box-medium',large:'ph:box-large',xl:'ph:box-xl'}[size]||'ph:box-medium'; return { key, scale:1 };
    }
    function measureBox(sz){
      const def={small:{w:22,h:22},medium:{w:28,h:28},large:{w:34,h:34},xl:{w:42,h:42}}[sz]||{w:28,h:28};
      try{ const t=texForBox(sz); const tmp=t.atlas?scene.add.sprite(-9e3,-9e3,t.atlas,t.frame).setScale(t.scale):scene.add.sprite(-9e3,-9e3,t.key); tmp.setOrigin(0.5,1.0); const w=tmp.displayWidth,h=tmp.displayHeight; tmp.destroy(); return (!w||!h)?def:{w,h}; }catch(e){ return def; }
    }
    function ensureTerminalTexture(){ if(scene.textures.exists('ph:terminal')) return; const g=scene.add.graphics(); g.fillStyle(0x1abc9c,1).fillRoundedRect(0,0,22,28,4); g.lineStyle(2,0x0b6b5c,1).strokeRoundedRect(1,1,20,26,4); g.generateTexture('ph:terminal',22,28); g.destroy(); }

    function startNetworking(){
      if(!netAvailable){ enableControls(); return; }
      try{
        // Expose session id so DOM panel posts can include it
        WGNet.init({ sessionId:1, base:"" });
        try { window.WG_SESSION_ID = 1; } catch(_) {}
        WGNet.join(pendingName).then(async info=>{
          myPlayerId = info && info.player_id; netJoined = true; window.PLAYER_NAME = pendingName;
          try { window.WG_PLAYER_ID = myPlayerId; } catch(_) {}
          try {
            // Realtime stream for plane_* topics (and others)
            WGNet.connectEvents({});
            WGNet.onEvent("wg:plane_*", (ev) => {
              if (window.WGPlanePanel && window.WGPlanePanel.isOpenFor && window.WGPlanePanel.isOpenFor(ev.data && ev.data.plane_id)) {
                window.WGPlanePanel.refresh();
              }
            });
          } catch(_) {}
          try{ await bootstrapFromServer(); }catch(e){ console.warn("bootstrap failed", e); }
          enableControls(); schedulePoll();
        }).catch(async ()=>{
          try{ await bootstrapFromServer(); }catch(_){}
          enableControls(); schedulePoll();
        });
      }catch(e){ enableControls(); }
    }

    // ---------- scene ----------
    function preload(){ try{ if (window.AssetKit && window.AssetKit.queueOptional) window.AssetKit.queueOptional(this); }catch(e){} }
    function create(){
      scene=this;
      this.cameras.main.setBounds(0,0,VW,VH);
      this.physics.world.setBounds(BORDER,BORDER,VW-2*BORDER,VH-2*BORDER,true,true,true,true);

      if(this.textures.exists('bg:base')) this.add.image(0,0,'bg:base').setOrigin(0,0).setDisplaySize(VW,VH).setDepth(DEPTH.bg);
      drawFence(); ensurePlaceholders();

      // player
      const startKey = this.textures.exists('ph:player-S')?'ph:player-S':(this.textures.exists('ph:player')?'ph:player':null);
      player = this.physics.add.sprite(VW/2,VH/2,startKey||'ph:player').setOrigin(0.5,1.0).setCollideWorldBounds(true);
      player.setDisplaySize(PLAYER_W,PLAYER_H); player.body.setSize(PLAYER_COLL_W,PLAYER_COLL_H,false); player.body.setOffset((PLAYER_W-PLAYER_COLL_W)/2, PLAYER_COLL_YOFF);
      markForYSort(player, 0);

      // ui label + held box + hud
      nameText = this.add.text(player.x, player.y+8, (window.PLAYER_NAME || 'Guest')+'', {fontSize:'14px', color:'#e6e6e6'}).setOrigin(0.5,0).setDepth(DEPTH.ui);
      heldBox  = this.add.sprite(player.x, player.y, 'ph:box-medium').setOrigin(0.5,1.0).setVisible(false).setDepth(DEPTH.ui+1);
      hudText = null;
      if (SHOW_DEBUG_HUD) { hudText = this.add.text(12,12,"",{fontSize:"12px", color:"#9fb7d9"}).setDepth(DEPTH.ui+100).setScrollFactor(0); }

      // physics group & collider (for props) + plane obstacle group
      propsGroup=this.physics.add.staticGroup(); colliderRef=this.physics.add.collider(player, propsGroup);
      planeObstacleGroup = this.physics.add.staticGroup();
      planeObstacleCollider = this.physics.add.collider(player, planeObstacleGroup);

      // hint + modal
      buildHint(); wireModal();

      // name gate → networking
      mountNameGate();
    }

    // ---------------- name gate / auth ----------------
    function update(){
      if(!keyW) return;
      let vx=0, vy=0; if(keyA.isDown) vx-=1; if(keyD.isDown) vx+=1; if(keyW.isDown) vy-=1; if(keyS.isDown) vy+=1; if(vx&&vy){ vx*=Math.SQRT1_2; vy*=Math.SQRT1_2; }
      player.setVelocity(vx*SPEED, vy*SPEED);

      if(vx||vy){ lastDir=vecToDir(vx,vy); const k='ph:player-'+lastDir; if(scene.textures.exists(k)){ const px=player.x,py=player.y; player.setTexture(k).setDisplaySize(48,64).setOrigin(0.5,1.0).setPosition(px,py);} }
      nameText.setPosition(player.x, player.y+8);

      if (carrying){ const off=holdOffsetPx(heldSize); heldBox.setPosition(player.x, player.y-off); const pDepth=(player.y||0)+(player.__yExtra||0); heldBox.setDepth(Math.max(DEPTH.ui+1, pDepth+1)); }

      renderHeldHudLine();

      ySortTick();
      updateInteractTargetAndHint();

      if (netJoined) WGNet.sendPos(player.x, player.y, lastDir, POS_HZ);
    }

    // ---------- controls ----------
    function enableControls(){
      keyW=scene.input.keyboard.addKey(Phaser.Input.Keyboard.KeyCodes.W);
      keyA=scene.input.keyboard.addKey(Phaser.Input.Keyboard.KeyCodes.A);
      keyS=scene.input.keyboard.addKey(Phaser.Input.Keyboard.KeyCodes.S);
      keyD=scene.input.keyboard.addKey(Phaser.Input.Keyboard.KeyCodes.D);
      keyE=scene.input.keyboard.addKey(Phaser.Input.Keyboard.KeyCodes.E);
      scene.input.keyboard.on('keydown-G', ()=>toggleGrid());
      scene.input.keyboard.on('keydown-E', ()=>attemptInteract());
      if (pendingName) nameText.setText(pendingName);
    }

    function buildHint(){ hintContainer=scene.add.container(0,0).setDepth(DEPTH.hint).setVisible(false); hintBG=scene.add.graphics(); hintBG.fillStyle(0xffffff,1).fillCircle(10,10,10).lineStyle(2,0x000000,1).strokeCircle(10,10,10); hintText=scene.add.text(10,9,'E',{fontSize:'14px', color:'#000'}).setOrigin(0.5,0.6); hintContainer.add([hintBG,hintText]); }
    function wireModal(){
      // Prefer a bounded modal under #modal-root; fall back to document
      const root = document.getElementById('modal-root') || document.body;
      modalEl       = (root.querySelector('#wg-modal') || document.getElementById('wg-modal')) || null;
      modalMsgEl    = (modalEl && modalEl.querySelector('#wg-modal-msg'))    || document.getElementById('wg-modal-msg');
      modalBodyEl   = (modalEl && modalEl.querySelector('#wg-modal-body'))   || document.getElementById('wg-modal-body');
      modalOK       = (modalEl && modalEl.querySelector('#wg-modal-ok'))     || document.getElementById('wg-modal-ok');
      modalCancel   = (modalEl && modalEl.querySelector('#wg-modal-cancel')) || document.getElementById('wg-modal-cancel');
      // If the modal exists but isn't under #modal-root, move it there
      if (modalEl && root && modalEl.parentElement !== root) root.appendChild(modalEl);
    }
    // Minimal modal controller used by WG_UI
    function openModal({ title, bodyHTML, okLabel="OK", onOK, onCancel }){
      if(!modalEl){ if(confirm((title||"").replace(/<[^>]+>/g,''))){ onOK&&onOK(); } else { onCancel&&onCancel(); } return; }
      modalMsgEl && (modalMsgEl.innerHTML = title || "");
      modalBodyEl && (modalBodyEl.innerHTML = bodyHTML || "");
      if (modalOK) modalOK.textContent = okLabel || "OK";
      let escHandler=null, overlayHandler=null;
      const close=()=>{
        modalEl.style.display='none';
        try { window.__wgModalOpen = false; } catch(_) {}
        if (modalOK)     modalOK.onclick = null;
        if (modalCancel) modalCancel.onclick = null;
        if (escHandler)  document.removeEventListener('keydown', escHandler);
        if (overlayHandler) modalEl.removeEventListener('click', overlayHandler);
        if (modalOK) modalOK.textContent="OK";
      };
      if (modalOK)     modalOK.onclick     = ()=>{ close(); onOK && onOK(); };
      if (modalCancel) modalCancel.onclick = ()=>{ close(); onCancel && onCancel(); };
      // ESC to close
      escHandler = (e)=>{ if (e.key==='Escape') { close(); onCancel && onCancel(); } };
      document.addEventListener('keydown', escHandler);
      // Overlay click to close (click outside the card)
      overlayHandler = (e)=>{ if (e.target === modalEl || (e.target && e.target.classList && e.target.classList.contains('backdrop'))) { close(); onCancel && onCancel(); } };
      modalEl.addEventListener('click', overlayHandler);
      try { window.__wgModalOpen = true; } catch(_) {}
      modalEl.style.display='flex';
    }
    // Expose modal controller + helpers so WG_UI can call them
    // (Fixes: "window.openModal is not a function")
    window.openModal = openModal;
    window.postClaimSerial = postClaimSerial;
    window.addPendingLocal = addPending;
    window.cancelPendingLocal = cancelPending;
    // Expose a few helpers for WG_UI optimistic updates (optional)
    window.applyCarrierDelta = applyCarrierDelta;
    window.setHeldBoxTexture = setHeldBoxTexture;
    window.toggleCarry = toggleCarry;
    // NEW: let UI set the carry metadata living in this scene’s closure
    function setHeldMeta({ qty=1, display_name="", unit_lb=0, item_key=DEFAULT_ITEM_KEY, size=null }={}){
      heldQty = Math.max(1, parseInt(qty,10)||1);
      heldDisplayName = display_name||"";
      heldUnitLb = Number(unit_lb)||0;
      heldItemKey = item_key||DEFAULT_ITEM_KEY;
      if (size) setHeldBoxTexture(binToHuman(size));
    }
    window.setHeldMeta = setHeldMeta;

    // Expose a safe snapshot of carriers for UI panels (carts listing, etc.)
    window.__WG_getCarriers = function(){
      try{
        return carriers.map(c => ({
          id: c.uid,
          type: c.type,
          loadSizes: Array.isArray(c.loadSizes) ? c.loadSizes.slice() : []
        }));
      }catch(_){ return []; }
    };

    // Expose the currently locked cart (North Cart) so UI panels can use it
    // without presenting a cart picker.
    window.__WG_getLockedCartUid = function(){
      try { return LOCKED_CART_UID ? String(LOCKED_CART_UID) : null; } catch(_){ return null; }
    };

    function openConfirm(html,onOk,onCancel){ if(!modalEl||!modalMsgEl||!modalOK||!modalCancel){ if(confirm(html.replace(/<[^>]+>/g,''))){ onOk&&onOk(); } else { onCancel&&onCancel(); } return; } modalMsgEl.innerHTML=html; modalBodyEl.innerHTML=''; const close=()=>{ modalEl.style.display='none'; modalOK.onclick=null; modalCancel.onclick=null; }; modalOK.onclick=()=>{ close(); onOk&&onOk(); }; modalCancel.onclick=()=>{ close(); onCancel&&onCancel(); }; modalEl.style.display='flex'; }
    function openSelect(html, options, def, onOk, onCancel){
      options=options||[]; if(!modalEl||!modalMsgEl||!modalBodyEl||!modalOK||!modalCancel){ const v=prompt(html.replace(/<[^>]+>/g,''), def||((options[0]||{}).value||'medium')); if(v){ onOk&&onOk(v); } else { onCancel&&onCancel(); } return; }
      modalMsgEl.innerHTML=html; const opts=options.map(o=>`<option value="${o.value}">${o.label}</option>`).join(''); modalBodyEl.innerHTML=`<label style="display:flex;gap:.5rem;align-items:center;"><span>Size</span><select id="wg-modal-select" style="min-width:10rem;">${opts}</select></label>`;
      const sel=document.getElementById('wg-modal-select'); if(sel&&(def!=null)) sel.value=def; const close=()=>{ modalEl.style.display='none'; modalOK.onclick=null; modalCancel.onclick=null; };
      modalOK.onclick=()=>{ const v=(document.getElementById('wg-modal-select')||{}).value; close(); onOk&&onOk(v); };
      modalCancel.onclick=()=>{ close(); onCancel&&onCancel(); };
      modalEl.style.display='flex';
    }

    // ---------- stockpile ----------
    function initStockpileZone(){
      destroyStockpileZone();
      stockpile.label = scene.add.text((STOCKPILE_RECT.left+STOCKPILE_RECT.right)/2, STOCKPILE_RECT.top-18, "STOCKPILE",{fontSize:"18px", color:"#eaeaea", fontStyle:"bold"}).setOrigin(0.5,1.0).setDepth(DEPTH.ui);
      stockpile.rect = {...STOCKPILE_RECT}; stockpile.yBase=STOCKPILE_RECT.bottom; ensureTerminalTexture();

      stockpile.terminal = scene.add
        .sprite((STOCKPILE_RECT.left+STOCKPILE_RECT.right)/2, STOCKPILE_RECT.bottom + 36, 'ph:terminal')
        .setOrigin(0.5,0.0)
        .setDepth(DEPTH.fence - 1); // behind stockpile contents

      buildStockpileFence(); computeStockpileBins(); stockpile.hidden={small:0,medium:0,large:0,xl:0}; updateBadges();
    }
    function buildStockpileFence(){
      if (stockpile.fenceGfx) stockpile.fenceGfx.destroy();
      stockpile.fenceGfx = scene.add.graphics().setDepth(DEPTH.fence+1).lineStyle(2,0x4f5d6a,1).strokeRect(stockpile.rect.left,stockpile.rect.top, stockpile.rect.width,stockpile.rect.height);
      if (stockpile.wallGroup && !stockpile.wallGroup.destroyed) stockpile.wallGroup.clear(true,true);
      stockpile.wallGroup = scene.physics.add.staticGroup(); const t=8, r=stockpile.rect;
      [[r.left + r.width/2, r.top - t/2, r.width, t],[r.left + r.width/2, r.bottom + t/2, r.width, t],[r.left - t/2, r.top + r.height/2, t, r.height],[r.right + t/2, r.top + r.height/2, t, r.height]].forEach(raw=>{
        const wall=scene.add.rectangle(raw[0],raw[1],raw[2],raw[3],0x4f5d6a,0.15).setStrokeStyle(1,0x5f7285,0.8); scene.physics.add.existing(wall,true); stockpile.wallGroup.add(wall);
      });
      scene.physics.add.collider(player, stockpile.wallGroup);
    }
    function computeStockpileBins(){
      const L=stockpile.rect.left+SP_INSET, R=stockpile.rect.right-SP_INSET, T=stockpile.rect.top+SP_INSET, B=stockpile.rect.bottom-SP_INSET; const W=R-L, H=B-T; const binW=(W-3*BIN_GAP)/4;
      ['small','medium','large','xl'].forEach((sz,i)=>{
        const rect={left:L+i*(binW+BIN_GAP), top:T, right:L+i*(binW+BIN_GAP)+binW, bottom:B}; rect.width=rect.right-rect.left; rect.height=rect.bottom-rect.top;
        const m=measureBox(sz); const cols=Math.max(1,Math.floor((rect.width+CELL_GAP)/(m.w+CELL_GAP))); const rows=Math.max(1,Math.floor((rect.height+CELL_GAP)/(m.h+CELL_GAP)));
        stockpile.geom[sz]={rect,w:m.w,h:m.h,cols,rows,x0:rect.left+m.w/2,yBase:rect.bottom};
      });
    }
    function updateBadges(){
      ['small','medium','large','xl'].forEach(sz=>{
        const hidden=stockpile.hidden[sz]||0;
        if(!stockpile.badges[sz]) stockpile.badges[sz]=scene.add.text(0,0,"",{fontSize:"12px", color:"#ffffff"}).setOrigin(1,0).setDepth(DEPTH.ui+3);
        const b=stockpile.badges[sz], G=stockpile.geom[sz];
        if(hidden>0) b.setText('+'+hidden).setPosition(G.rect.right-4, G.rect.top+4).setVisible(true); else b.setVisible(false);
      });
    }
    function spawnStockpileBox(size){
      const G=stockpile.geom[size]; if(!G) return null;
      const visMax=G.cols*G.rows, cur=stockpile.bins[size].length;
      if(cur>=visMax){ stockpile.hidden[size]=(stockpile.hidden[size]||0)+1; updateBadges(); return null; }
      const t=texForBox(size);
      const s=t.atlas?propsGroup.create(-9999,-9999,t.atlas,t.frame).setScale(t.scale):propsGroup.create(-9999,-9999,t.key);
      s.setOrigin(0.5,1.0);
      const col=cur%G.cols, row=(cur/G.cols)|0;
      s.setPosition(G.x0+col*(G.w+CELL_GAP), G.yBase-row*(G.h+CELL_GAP));
      s.refreshBody();
      // NEW: y-sorted so player appears in front when south of boxes
      markForYSort(s, row*0.01 + col*0.001);
      stockpile.sprites.push(s); stockpile.bins[size].push(s); return s;
    }
    function removeOneFromStockpile(size){
      const list=stockpile.bins[size]; if(list && list.length){ const s=list.pop(); stockpile.sprites=stockpile.sprites.filter(x=>x!==s); s.destroy();
        if((stockpile.hidden[size]||0)>0){ stockpile.hidden[size]--; updateBadges(); spawnStockpileBox(size); } else updateBadges(); return true; }
      if ((stockpile.hidden[size]||0)>0){ stockpile.hidden[size]--; updateBadges(); return true; }
      return false;
    }
    function destroyStockpileZone(){
      stockpile.sprites.forEach(s=>{ if(s&&s.destroy) s.destroy(); }); stockpile.sprites=[]; stockpile.bins={small:[],medium:[],large:[],xl:[]}; stockpile.hidden={small:0,medium:0,large:0,xl:0};
      if(stockpile.label){ stockpile.label.destroy(); stockpile.label=null; } if(stockpile.terminal){ stockpile.terminal.destroy(); stockpile.terminal=null; }
      if(stockpile.fenceGfx){ stockpile.fenceGfx.destroy(); stockpile.fenceGfx=null; } if(stockpile.wallGroup && !stockpile.wallGroup.destroyed) stockpile.wallGroup.clear(true,true);
      stockpile.wallGroup=null; stockpile.walls=[]; ['small','medium','large','xl'].forEach(k=>{ if(stockpile.badges[k]){ stockpile.badges[k].destroy(); stockpile.badges[k]=null; }});
    }
    function totalStockpileCount(){ const ks=['small','medium','large','xl']; let sum=0; for(let i=0;i<ks.length;i++){ const k=ks[i]; sum += (stockpile.bins[k]?stockpile.bins[k].length:0) + (stockpile.hidden[k]||0);} return sum; }

    // ---------- carriers ----------
    function ensureStaticGroup(){ if(!propsGroup||propsGroup.destroyed){ propsGroup=scene.physics.add.staticGroup(); if(colliderRef && !colliderRef.destroyed) colliderRef.destroy(); colliderRef=scene.physics.add.collider(player, propsGroup);} }
    function spawnCarrier(type,opts){ opts=opts||{}; const facing=opts.facing||'right', uid=opts.uid, x=(typeof opts.x==='number')?opts.x:VW/2, y=(typeof opts.y==='number')?opts.y:VH/2;
      ensureStaticGroup(); let base;
      if(type===CART){ base = scene.textures.exists('atlas:cart') ? propsGroup.create(x,y,'atlas:cart','cart_'+facing).setScale(ATLAS_SCALE) : propsGroup.create(x,y,'ph:cart-left'); }
      else { base = scene.textures.exists('atlas:truck') ? propsGroup.create(x,y,'atlas:truck','truck_'+facing).setScale(ATLAS_SCALE) : propsGroup.create(x,y,'ph:truck-right'); }
      // If using placeholder art (ph:*), flip to honor initial facing.
      // ph:cart-left faces LEFT by default → flip when facing === 'right'.
      // ph:truck-right faces RIGHT by default → flip when facing === 'left'.
      const usingAtlas = (type===CART && scene.textures.exists('atlas:cart')) || (type===TRUCK && scene.textures.exists('atlas:truck'));
      if (!usingAtlas) {
        if (type === CART)  base.setFlipX(facing === 'right');
        if (type === TRUCK) base.setFlipX(facing === 'left');
      }
      base.setOrigin(0.5,1.0).refreshBody(); markForYSort(base,-5);
      const entry={ uid, type, base, loadSizes:[], loadSprites:[], facing }; carriers.push(entry); carriersByUid.set(uid, entry); return entry;
    }
    // --- helper: attach popover menu to carriers (truck/cart) ---
    function attachCarrierMenu(entry){
      if (!ALLOW_POINTER_CLICK) return; // ← disable all click-to-interact
      if (!entry || !entry.base) return;
      entry.base.setInteractive({ cursor: 'pointer' });
      entry.base.on('pointerdown', () => {
        const title = (entry.type === TRUCK ? `Truck #${entry.uid}` : 'Cart');
        const items = [];

        // View cargo (truck only)
        if (entry.type === TRUCK && window.WG_UI && typeof window.WG_UI.openTruckCargo === 'function') {
          items.push({
            key: 'view',
            label: 'View cargo…',
            onClick: () => window.WG_UI.openTruckCargo({
              truckId: entry.uid,
              carrierEntry: entry,
              onTaken: ({ qty, size, display_name, unit_lb })=>{
                // Set local carry visuals (matches UI helper)
                const human = (BIN_TO_HUMAN[String(size).toUpperCase()] || size || 'medium');
                setHeldBoxTexture(human);
                heldQty = qty; heldDisplayName = display_name||''; heldUnitLb = unit_lb||0; heldItemKey = 'box';
                toggleCarry(true);
              }
            })
          });
        }

        // Drop carried cargo here (if holding anything)
        if (carrying) {
          items.push({
            key: 'drop',
            label: 'Drop carried cargo here',
            onClick: () => { activeMode = 'depositCarrier'; activeTarget = entry; attemptInteract(); }
          });
        }

        // Ship outbound (only for non-delivery trucks AND when holding)
        if (entry.type === TRUCK && carrying && String(entry.role||'').toLowerCase() !== 'delivery'
            && window.WG_UI && typeof window.WG_UI.openTruckShippingLogging === 'function') {
          items.push({
            key: 'ship',
            label: 'Ship outbound…',
            onClick: () => {
              const sizeBin = (HUMAN_TO_BIN[heldSize] || 'M');
              const disp    = heldDisplayName || (sizeBin + ' box');
              const qty     = Math.max(1, parseInt(heldQty||1,10));
              window.WG_UI.openTruckShippingLogging({
                truckId: entry.uid, carrierEntry: entry,
                qty, display_name: disp, unit_lb: heldUnitLb||0, size: sizeBin,
                onDone: () => { /* WG_UI will toggleCarry(false) via deposit flow */ }
              });
            }
          });
        }

        // Flip facing (truck/cart)
        items.push({
          key: 'flip',
          label: 'Flip facing',
          onClick: () => {
            entry.facing = (entry.facing === 'right' ? 'left' : 'right');
            if (entry.type === TRUCK && scene.textures.exists('atlas:truck')) {
              entry.base.setTexture('atlas:truck', 'truck_'+entry.facing).setScale(ATLAS_SCALE);
            } else if (entry.type === CART && scene.textures.exists('atlas:cart')) {
              entry.base.setTexture('atlas:cart', 'cart_'+entry.facing).setScale(ATLAS_SCALE);
            } else {
              // placeholder: flip sprite if using ph:* texture
              entry.base.setFlipX(entry.facing === 'left');
            }
            entry.base.refreshBody();
            rebuildCarrier(entry);
          }
        });

        // Open the menu at the sprite’s screen position
        if (window.wgUI && typeof window.wgUI.openMenu === 'function') {
          window.wgUI.openMenu({ scene, sprite: entry.base, title, items });
        }
      });
    }
    function rebuildCarrier(entry){
      entry.loadSprites.forEach(s=>{ if(s&&s.destroy) s.destroy(); }); entry.loadSprites=[];
      if(!entry.loadSizes.length) return;
      const m=measureBox(entry.loadSizes[0]); const cols=(entry.type===CART)?3:4, gap=CELL_GAP, rowW=cols*m.w+(cols-1)*gap;
      const startX=entry.base.x - rowW/2 + m.w/2, startY=entry.base.y - 6; const baseDepth=(entry.base.y||0)+(entry.base.__yExtra||0);
      entry.loadSizes.forEach((sz,i)=>{ const t=texForBox(sz); const spr=t.atlas?scene.add.sprite(0,0,t.atlas,t.frame).setScale(t.scale):scene.add.sprite(0,0,t.key);
        spr.setOrigin(0.5,1.0); const col=i%cols, row=(i/cols)|0; spr.setPosition(startX+col*(m.w+gap), startY-row*(m.h+gap)); spr.setDepth(baseDepth+1+row*0.01+col*0.001); spr.__boxSize=sz; entry.loadSprites.push(spr); });
    }
    function applyCarrierDelta(entry, delta){ if(!entry) return; const counts={small:0,medium:0,large:0,xl:0}; entry.loadSizes.forEach(s=>{ counts[s]=(counts[s]||0)+1; });
      ['small','medium','large','xl'].forEach(sz=>{ const net=(delta.add&&delta.add[sz]||0) - (delta.remove&&delta.remove[sz]||0); counts[sz]=Math.max(0,(counts[sz]||0)+net); });
      entry.loadSizes=[]; Object.keys(counts).forEach(sz=>{ for(let i=0;i<counts[sz];i++) entry.loadSizes.push(sz); }); rebuildCarrier(entry);
    }

    // ---------- UI targeting ----------
    let activeMode=null, activeTarget=null;
    function holdOffsetPx(size){ return { small:12, medium:14, large:16, xl:18 }[size] || 14; }
    function setHeldBoxTexture(size){ heldSize=size; const t=texForBox(size); if(t.atlas) heldBox.setTexture(t.atlas,t.frame).setScale(t.scale); else heldBox.setTexture(t.key).setScale(1); heldBox.setOrigin(0.5,1.0); }
    function toggleCarry(force){
      carrying=(typeof force==='boolean')?force:!carrying;
      heldBox.setVisible(carrying);
      if(carrying){
        const off=holdOffsetPx(heldSize);
        heldBox.setPosition(player.x, player.y-off);
        const pDepth=(player.y||0)+(player.__yExtra||0);
        heldBox.setDepth(Math.max(DEPTH.ui+1, pDepth+1));
      } else {
        heldQty=0; heldDisplayName=""; heldUnitLb=0; heldItemKey=null;
      }
    }
    function countBySize(list){ const c={small:0,medium:0,large:0,xl:0}; (list||[]).forEach(s=>{ if(c[s]!=null) c[s]++; }); return c; }
    function sizeOptionsFromCounts(counts){ return [['small','S'],['medium','M'],['large','L'],['xl','XL']].filter(p=>(counts[p[0]]||0)>0).map(p=>({value:p[0], label:p[1]+' — '+counts[p[0]]})); }
    function findNearestCarrier(pRect,pad){ let best=null,dBest=Infinity; carriers.forEach(c=>{ const d=distRects(pRect, spriteRect(c.base)); if(d<= (pad||PICK_PAD) && d<dBest){ dBest=d; best=c; } }); return best; }
    function isNearSouthEdgeOfStockpile(pRect){ const withinX=(pRect.right>stockpile.rect.left-8)&&(pRect.left<stockpile.rect.right+8); const nearY=Math.abs(pRect.bottom-stockpile.rect.bottom)<= (PICK_PAD+8); return withinX&&nearY; }
    function updateInteractTargetAndHint(){
      activeMode=null; activeTarget=null; hintContainer.setVisible(false); const pRect=bodyRect(player.body);

      if (stockpile.terminal) {
        const feetX = player.x, feetY = player.y - 2;
        const tx = stockpile.terminal.x;
        const ty = stockpile.terminal.y + stockpile.terminal.displayHeight / 2;
        const d = Phaser.Math.Distance.Between(feetX, feetY, tx, ty);

        if (carrying && d <= TERMINAL_RADIUS) {
          activeMode='depositTerminal'; activeTarget='terminal';
          hintContainer.setVisible(true).setPosition(player.x, player.y-PLAYER_H-6);
          return;
        }
        if (!carrying && d <= TERMINAL_RADIUS && totalStockpileCount()>0) {
          activeMode='pickupStockpile'; activeTarget=stockpile;
          hintContainer.setVisible(true).setPosition(player.x, player.y-PLAYER_H-6);
          return;
        }
      }

      // carriers
      const nearCarrier=findNearestCarrier(pRect,PICK_PAD);
      if (nearCarrier){
        // Enforce north-cart lock: any non-locked cart is inert (no hint, no action)
        if (nearCarrier.type===CART && LOCKED_CART_UID && String(nearCarrier.uid)!==LOCKED_CART_UID){
          hintContainer.setVisible(false);
          return;
        }
        if(carrying){ activeMode='depositCarrier'; activeTarget=nearCarrier; hintContainer.setVisible(true).setPosition(player.x, player.y-PLAYER_H-6); return; }
        const cnt=countBySize(nearCarrier.loadSizes), any=cnt.small+cnt.medium+cnt.large+cnt.xl;
        // Allow pickup from carts AND from either truck (delivery or retrieval).
        // (Retrieval pickup is for “oops, pull it back” recovery.)
        const allowPickup = (nearCarrier.type===CART) || (nearCarrier.type===TRUCK);
        if(any>0 && allowPickup){ activeMode='pickupCarrier'; activeTarget=nearCarrier; hintContainer.setVisible(true).setPosition(player.x, player.y-PLAYER_H-6); return; }
      }

      // planes (open Plane Panel when near cargo bay)
      const nearPlane = findNearestPlaneCargo(pRect, PLANE_PROX_RADIUS);
      if (nearPlane) {
        activeMode = 'planePanel';
        activeTarget = nearPlane.plane;
        // Ensure downstream code learns the active plane id early
        try {
          const pid = (activeTarget && (activeTarget.id ?? activeTarget.plane_id));
          if (pid != null) window.dispatchEvent(new CustomEvent('wg:set-plane-id', { detail:{ id: Number(pid) } }));
        } catch(_) {}

        hintContainer.setVisible(true).setPosition(player.x, player.y-PLAYER_H-6);
        return;
      }

      // south fence edge pickup fallback
      if (!carrying && isNearSouthEdgeOfStockpile(pRect)){ if(totalStockpileCount()>0){ activeMode='pickupStockpile'; activeTarget=stockpile; hintContainer.setVisible(true).setPosition(player.x, player.y-PLAYER_H-6); return; } }
    }

    // ---------- SKU resolution ----------
    async function resolveTruckSkuForSizeByUid(truckUid,humanSize){
      try{
        const trucks=await WGNet.getTrucks(); const all=[]; (trucks&&trucks.inbound||[]).forEach(t=>all.push(t)); (trucks&&trucks.outbound||[]).forEach(t=>all.push(t));
        const found=all.find(t=>String(t.truck_id)===String(truckUid)); if(!found||!found.manifest) return { item_key:DEFAULT_ITEM_KEY, carrier_uid:truckUid };
        const bin=HUMAN_TO_BIN[humanSize]||'M'; let key=null; for(const k of Object.keys(found.manifest)){ if(((found.manifest[k]||{})[bin]||0)>0){ key=k; break; } }
        if(!key) for(const k of Object.keys(found.manifest)){ const b=found.manifest[k]||{}; if((b.S||0)+(b.M||0)+(b.L||0)+(b.XL||0)>0){ key=k; break; } }
        return { item_key:key||DEFAULT_ITEM_KEY, carrier_uid:truckUid };
      }catch(e){ console.warn('resolveTruckSkuForSizeByUid failed', e); return { item_key:DEFAULT_ITEM_KEY, carrier_uid:truckUid }; }
    }
    async function resolveStockpileSkuForSize(humanSize){
      try{
        const sp=await WGNet.getStockpile(); const bins=(sp&&sp.bins)||{}; const bin=HUMAN_TO_BIN[humanSize]||'M';
        for(const k of Object.keys(bins)){ if(((bins[k]||{})[bin]||0)>0) return k; }
        for(const k of Object.keys(bins)){ const b=bins[k]||{}; if((b.S||0)+(b.M||0)+(b.L||0)+(b.XL||0)>0) return k; }
      }catch(e){ console.warn('resolveStockpileSkuForSize failed', e); }
      return DEFAULT_ITEM_KEY;
    }

    // ---------- planes: helpers ----------
    function spawnPlaneSprites(plane) {
      const pose = (plane && plane.pose) || plane || {};
      const x=(typeof pose.x==='number')?pose.x:(VW/2-100);
      const y=(typeof pose.y==='number')?pose.y:(VH/2-100);
      const facing=pose.facing || 'right';

      // Prefer atlas frames if present; otherwise placeholders.
      let bodyKey='ph:plane-body', wingsKey='ph:plane-wings';
      let bodyFrame=null, wingsFrontFrame=null, wingsBackFrame=null, useAtlas=false;
      if (scene.textures.exists('atlas:plane')) {
        const TX = scene.textures.get('atlas:plane');
        const has = (name)=> !!(TX && TX.has && TX.has(name));
        // Expected atlas frames if you have custom art:
        // body_right / body_left
        // wings_front_right / wings_front_left
        // wings_back_right / wings_back_left
        if (has('body_right') && has('wings_front_right') && has('wings_back_right')) {
          useAtlas = true;
          bodyKey = 'atlas:plane'; wingsKey = 'atlas:plane';
          const suffix = (facing==='left'?'left':'right');
          bodyFrame = 'body_' + suffix;
          wingsFrontFrame = 'wings_front_' + suffix;
          wingsBackFrame  = 'wings_back_'  + suffix;
        }
      }

      const body = scene.add.sprite(x,y,
        useAtlas? bodyKey : 'ph:plane-body',
        useAtlas? bodyFrame : undefined
      ).setOrigin(0.5,1.0);

      if (!useAtlas && facing==='left') body.setScale(-1,1);
      markForYSort(body, -5);

      // Wings: draw as two layers so the player can be sandwiched
      const wingsBack = scene.add.sprite(x,y,
        useAtlas? wingsKey : 'ph:plane-wings',
        useAtlas? wingsBackFrame : undefined
      ).setOrigin(0.5,1.0);
      const wingsFront = scene.add.sprite(x,y,
        useAtlas? wingsKey : 'ph:plane-wings',
        useAtlas? wingsFrontFrame : undefined
      ).setOrigin(0.5,1.0);

      if (!useAtlas && facing==='left') { wingsBack.setScale(-1,1); wingsFront.setScale(-1,1); }

      // vertically position wings around mid-body; adjust y-sort extras so
      // back-wings < player < front-wings when standing under the wing
      const wingOffset = Math.round((body.displayHeight||64) * 0.42);
      wingsBack.y  = body.y - wingOffset;
      wingsFront.y = body.y - wingOffset;

      // Depth sandwich: back wings below, front wings above
      markForYSort(wingsBack,  -wingOffset - 8);
      markForYSort(wingsFront, +wingOffset + 8);

      // Collision pad beneath the belly/boxes area
      const cargoRect = addPlaneCargoObstacleForSprite(body, facing); // (defined later; single canonical impl)
      const record = {
        id: (plane && (plane.id ?? plane.plane_id)) ?? null,
        tail: (plane && plane.tail_number) ?? null,
        body, wingsBack, wingsFront, facing,
        cargoRect
      };
      // Attach back-reference on the newest plane obstacle
      if (cargoRect && planeObstacles.length) {
        const last = planeObstacles[planeObstacles.length-1];
        if (last && last.rect === cargoRect) last.plane = record;
      }
      planes.push(record);
    }

    // ---------- bootstrap ----------
    async function bootstrapFromServer(){
      let nextClaimId=0, initialCarts=[];
      try{
        const s0=await WGNet.getState(0);
        nextClaimId=(s0&&s0.next_claim_id)||0;
        initialCarts=(s0&&s0.carts)||[];
        trucksEpochSeen = (s0 && s0.trucks_epoch) | 0;
      }catch(e){ console.warn("initial state failed", e); }
      seenClaimId=Math.max(0, nextClaimId-1);

      const [trucks, stock, planesData] = await Promise.all([
        WGNet.getTrucks().catch(e=>{ console.warn(e); return { inbound:[], outbound:[] }; }),
        WGNet.getStockpile().catch(e=>{ console.warn(e); return { bins:{} }; }),
        fetch("/api/wargame/planes", { credentials:"same-origin" }).then(r=>r.json()).catch(e=>{ console.warn(e); return { planes:[] }; })
      ]);

      // reset
      clearProps(); initStockpileZone();

      // trucks and carts from server
      layoutTrucksFromServer(trucks);   seedTruckLoadsFromServer(trucks);
      layoutCartsFromServer(initialCarts); seedCartLoadsFromServer(initialCarts);
      // Re-assert single-cart rule after initial seed
      selectNorthCartAndLock();

      // stockpile aggregation → visible sprites
      seedStockpileFromServer(stock);

      // planes (bodies + wings + collision)
      renderPlanes(planesData && planesData.planes || []);
    }

    function clearProps(){
      if (colliderRef && !colliderRef.destroyed) colliderRef.destroy();
      if (propsGroup && !propsGroup.destroyed) propsGroup.clear(true,true);
      propsGroup = scene.physics.add.staticGroup();
      colliderRef = scene.physics.add.collider(player, propsGroup);

      // reset plane obstacles
      if (planeObstacleCollider && !planeObstacleCollider.destroyed) planeObstacleCollider.destroy();
      if (planeObstacleGroup && !planeObstacleGroup.destroyed) planeObstacleGroup.clear(true, true);
      planeObstacleGroup = scene.physics.add.staticGroup();
      planeObstacles.forEach(o => { if (o && o.destroy) o.destroy(); });
      planeObstacles.length = 0; // will be re-populated by renderPlanes
      planeObstacleCollider = scene.physics.add.collider(player, planeObstacleGroup);

      carriers.forEach(c=>c.loadSprites.forEach(s=>{ if(s&&s.destroy) s.destroy(); }));
      carriers.splice(0,carriers.length); carriersByUid.clear();

      destroyStockpileZone();

      planes.forEach(p=>{
        if (p.wingsBack && p.wingsBack.destroy) p.wingsBack.destroy();
        if (p.wingsFront && p.wingsFront.destroy) p.wingsFront.destroy();
        if (p.body && p.body.destroy) p.body.destroy();
      });
      planes.length=0;
    }

    // ---------- name gate ----------
    function mountNameGate(){
      const gate=document.getElementById('wg-name-gate');
      const input=document.getElementById('wg-name-input');
      const btn=document.getElementById('wg-name-commit');
      // If we already have a saved name, auto-join and skip the gate.
      try{
        const saved=(localStorage.getItem('wg_player_name')||'').trim();
        if (input && saved) input.value = saved;
        if (saved){
          pendingName = saved.slice(0,24);
          if (gate) gate.style.display = 'none';
          startNetworking();
          return;
        }
      }catch(_){}
      if(!gate||!input||!btn){ enableControls(); return; }
      nameGate=gate; gate.style.display='flex'; input.focus();
      btn.addEventListener('click', function(){
        const v=(input.value||"").trim(); if (!v) { input.focus(); return; }
        pendingName=v.slice(0,24);
        try{ localStorage.setItem('wg_player_name', pendingName); }catch(_){}
        gate.style.display='none';
        startNetworking();
      });
      input.addEventListener('keydown', function(e){
        if(e.key==='Enter') btn.click();
        e.stopPropagation();
      });
    }

    function layoutTrucksFromServer(trucks){
      const inbound=(trucks&&trucks.inbound)||[], outbound=(trucks&&trucks.outbound)||[];
      const rightX=1600-BORDER-220, baseY=900/2, gapY=180;

      inbound.forEach((t,i)=>{
        const hasPose=t && t.pose && typeof t.pose.x==='number' && typeof t.pose.y==='number';
        const x=hasPose?t.pose.x:rightX, y=hasPose?t.pose.y:(baseY + (i - Math.floor(inbound.length/2))*gapY);
        const facing=(t && t.pose && t.pose.facing) || 'right';
        const entry=spawnCarrier(TRUCK,{ uid:t.truck_id, facing, x, y }); entry.role = (t && t.role) || ""; carriersByUid.set(t.truck_id, entry); if (ALLOW_POINTER_CLICK) attachCarrierMenu(entry);
      });
      const outBaseY = baseY + gapY * (Math.max(inbound.length,1)/2 + 0.7);
      outbound.forEach((t,i)=>{
        const hasPose=t && t.pose && typeof t.pose.x==='number' && typeof t.pose.y==='number';
        const x=hasPose?t.pose.x:(rightX-40), y=hasPose?t.pose.y:(outBaseY + i*gapY);
        const facing=(t && t.pose && t.pose.facing) || 'right';
        const entry=spawnCarrier(TRUCK,{ uid:t.truck_id, facing, x, y }); entry.role = (t && t.role) || ""; carriersByUid.set(t.truck_id, entry); if (ALLOW_POINTER_CLICK) attachCarrierMenu(entry);
      });
    }
    function seedTruckLoadsFromServer(trucks){
      const all=[]; (trucks&&trucks.inbound||[]).forEach(t=>all.push(t)); (trucks&&trucks.outbound||[]).forEach(t=>all.push(t));
      all.forEach(t=>{
        const entry=carriersByUid.get(t.truck_id); if(!entry) return;
        entry.loadSizes=[];
        // Prefer category-aware rendering: one sprite per (display_name, unit_lb, size)
        const lines = Array.isArray(t.lines) ? t.lines : [];
        if (lines.length){
          lines.forEach(ln=>{
            const bin = String(ln.size||'M').toUpperCase();
            const human = BIN_TO_HUMAN[bin] || 'medium';
            // One sprite per category line, regardless of qty
            entry.loadSizes.push(human);
          });
          rebuildCarrier(entry);
          return;
        }
        // Fallback: manifest-only. Cap visible sprites per bin to avoid clutter.
        const perBin={S:0,M:0,L:0,XL:0}; const man=t.manifest||{};
        Object.keys(man).forEach(k=>{
          const b=man[k]||{};
          perBin.S+=b.S||0; perBin.M+=b.M||0; perBin.L+=b.L||0; perBin.XL+=b.XL||0;
        });
        const CAP_PER_BIN = 6; // soft cap per size when lines[] absent
        Object.keys(perBin).forEach(bin=>{
          const human=BIN_TO_HUMAN[bin];
          const n=Math.min(perBin[bin]||0, CAP_PER_BIN);
          for(let i=0;i<n;i++) entry.loadSizes.push(human);
        });
        rebuildCarrier(entry);
      });
    }
    function layoutCartsFromServer(carts){
      (carts||[]).forEach(c=>{
        const pose=c&&c.pose||{}; const x=(typeof pose.x==='number')?pose.x:(VW/2-200); const y=(typeof pose.y==='number')?pose.y:(VH/2); const facing=pose.facing||'left';
        const uid=c.id; const entry=spawnCarrier(CART,{ uid, facing, x, y }); carriersByUid.set(uid, entry); if (ALLOW_POINTER_CLICK) attachCarrierMenu(entry);
      });
      // After carts are placed, enforce single-cart (north) rule
      selectNorthCartAndLock();
    }
    function seedCartLoadsFromServer(carts){
      // New behavior: do NOT auto-spawn legacy boxes from per-unit c.contents.
      // If server provides category lines (c.lines), render one sprite per line;
      // otherwise leave cart visually empty until explicit flows add cargo.
      (carts||[]).forEach(c=>{
        const entry = carriersByUid.get(c.id); if (!entry) return;
        entry.loadSizes = [];
        const lines = Array.isArray(c.lines) ? c.lines : [];
        if (lines.length){
          lines.forEach(ln=>{
            const bin = String(ln.size||'M').toUpperCase();
            const human = BIN_TO_HUMAN[bin] || 'medium';
            entry.loadSizes.push(human);
          });
        }
        rebuildCarrier(entry);
      });
    }
    // Choose the north-most cart and lock selection to it. Others become inert+dim.
    function selectNorthCartAndLock(){
      let best=null, minY=Infinity;
      carriers.forEach(c=>{
        if (c.type!==CART || !c.base) return;
        if (c.base.y < minY){ minY = c.base.y; best = c; }
      });
      LOCKED_CART_UID = best ? String(best.uid) : null;
      carriers.forEach(c=>{
        if (c.type!==CART || !c.base) return;
        // Remove any existing highlight/tween
        if (c._lockBadge && c._lockBadge.destroy) { c._lockBadge.destroy(); c._lockBadge = null; }
        if (c._lockTween && c._lockTween.stop)    { c._lockTween.stop();   c._lockTween = null; }
        if (String(c.uid) === LOCKED_CART_UID){
          c.base.setAlpha(1.0);
          // Non-text visual indicator that this is the chosen “North Cart”
          // Draw a subtle pulsing rounded-rect highlight around the sprite.
          const w = c.base.displayWidth  || 88;
          const h = c.base.displayHeight || 48;
          const pad = 6;
          const gx = c.base.x - w/2 - pad;
          const gy = c.base.y - h   - pad;
          const g = scene.add.graphics().setDepth(DEPTH.ui);
          g.lineStyle(2, 0xffe082, 1).strokeRoundedRect(gx, gy, w + pad*2, h + pad*2, 8);
          g.alpha = 0.9;
          c._lockBadge = g;
          // Gentle pulse so it’s noticeable without any text
          c._lockTween = scene.tweens.add({
            targets: g,
            alpha: { from: 0.55, to: 1.0 },
            duration: 900,
            yoyo: true,
            repeat: -1,
            ease: 'Sine.easeInOut'
          });
        } else {
          c.base.setAlpha(0.35);
        }
      });
    }
    function seedStockpileFromServer(stock){
      // Render one sprite per UNIQUE item (display_name + unit_lb + size) with qty>0.
      const reg = (stock && stock.registry) || {};
      const bySize = { small:[], medium:[], large:[], xl:[] };
      Object.values(reg).forEach(meta=>{
        const q = (meta && meta.qty)|0;
        if (q > 0){
          const bin = String(meta.size||'M').toUpperCase();
          const human = BIN_TO_HUMAN[bin] || 'medium';
          bySize[human].push(meta);
        }
      });
      ['small','medium','large','xl'].forEach(sz=>{
        const G = stockpile.geom[sz];
        const visMax = G ? (G.cols*G.rows) : 0;
        const lines = bySize[sz] || [];
        const visible = lines.slice(0, visMax);
        const hidden = Math.max(0, lines.length - visible.length);
        // reset hidden count for this size
        stockpile.hidden[sz] = hidden;
        // spawn sprites for just the visible categories
        visible.forEach(()=> spawnStockpileBox(sz));
      });
      updateBadges();
    }
    function renderPlanes(list){
      // Pass the full plane object so we can keep its id/tail
      (list||[]).forEach(p=>{ spawnPlaneSprites(p); });
    }

    // ---------- polling ----------
    function schedulePoll(){
      if (remoteTimer) { try{ remoteTimer.remove(false);}catch(e){} remoteTimer=null; }
      remoteTimer = scene.time.addEvent({ delay:POLL_MS, loop:true, callback:function(){
        WGNet.getState(seenClaimId).then(state=>{
          const serverTime=(state && typeof state.server_time==='number') ? state.server_time : null; if(serverTime) clock.tick(serverTime);
          const players=(state&&state.players)||[]; ingestRemotePlayers(players, serverTime); cleanupMissingRemotes(players);
          const claims=(state&&state.claims)||[]; applyClaimsBatched(claims);
          // If trucks_epoch changed, refresh truck loads from server (category view)
          const te = (state && state.trucks_epoch) | 0;
          if (Number.isFinite(te) && te !== trucksEpochSeen){
            trucksEpochSeen = te;
            WGNet.getTrucks()
              .then(tr => { seedTruckLoadsFromServer(tr); })
              .catch(()=>{});
          }
        }).catch(()=>{});
      }});
      if (remoteRenderTimer) { try{ remoteRenderTimer.remove(false);}catch(e){} }
      remoteRenderTimer = scene.time.addEvent({ delay:1000/REMOTE_RENDER_HZ, loop:true, callback: renderRemotesSmoothed });
    }

    function applyClaimsBatched(all){
      if(!Array.isArray(all)||!all.length) return;
      const fresh=all.filter(c=> (c.id||0)>seenClaimId); if(!fresh.length) return;

      let touchedTruck=false;       // trucks need re-seed when touched
      let touchedStockpile=false;   // stockpile needs re-seed when touched
      const carrierDelta=new Map();
      function ensure(uid, type){
        if(!carrierDelta.has(uid)) carrierDelta.set(uid,{add:{},remove:{}, type:type||null});
        const rec = carrierDelta.get(uid); if (type && !rec.type) rec.type = type; return rec;
      }
      function getCarrierByUid(uid, type){
        const asNum = (typeof uid === 'string' && /^\d+$/.test(uid)) ? Number(uid) : uid;
        const asStr = String(uid);
        const pref  = type ? `${String(type)}:${asStr}` : null;
        return carriersByUid.get(uid)
            || carriersByUid.get(asNum)
            || carriersByUid.get(asStr)
            || (pref ? carriersByUid.get(pref) : null)
            || null;
      }

      fresh.forEach(c=>{
        if (consumeMatchingPending(c)) {
          if (typeof c.id==='number' && c.id>seenClaimId) seenClaimId=c.id;
          return;
        }

        const act=(c.action||'').toLowerCase(); const sizeHuman=binToHuman(c.size||'medium');
        if (act==='stockpile_add' || act==='stockpile_remove'){
          touchedStockpile = true;
        } else if (act==='carrier_add' || act==='carrier_remove'){
          const uid=c.carrier_uid; const b=ensure(uid, c.carrier_type);
          const q = Math.max(1, parseInt(c.qty || 1, 10));
          if (act==='carrier_add') b.add[sizeHuman]=(b.add[sizeHuman]||0)+q; else b.remove[sizeHuman]=(b.remove[sizeHuman]||0)+q;
          if (String(c.carrier_type||"").toLowerCase()==='truck'){
            touchedTruck = true;
          }
        }
        if (typeof c.id==='number' && c.id>seenClaimId) seenClaimId=c.id;
      });

      carrierDelta.forEach((d,uid)=>{
        let e = getCarrierByUid(uid, d.type);
        if (e) applyCarrierDelta(e, d);
      });

      // Re-seed stockpile from server so we show one sprite per unique category.
      if (touchedStockpile){
        WGNet.getStockpile()
          .then(sp => { destroyStockpileZone(); initStockpileZone(); seedStockpileFromServer(sp); })
          .catch(()=>{});
      }

      // Re-seed truck loads from server so we show one sprite per category line,
      // not per-unit counts (prevents visual explosion).
      if (touchedTruck){
        WGNet.getTrucks().then(tr => { seedTruckLoadsFromServer(tr); }).catch(()=>{});
      }
    }

    // ---------- remotes ----------
    function ensureRemoteRecord(p){
      let rec=remotes.get(p.id); if(rec) return rec;
      const key= scene.textures.exists('ph:player-S')?'ph:player-S':(scene.textures.exists('ph:player')?'ph:player':'ph:remote');
      if (key==='ph:remote' && !scene.textures.exists('ph:remote')){ const g=scene.add.graphics(); g.fillStyle(0x29b6f6,1).fillRect(0,0,32,32); g.generateTexture('ph:remote',32,32); g.destroy(); }
      const spr=scene.add.sprite(p.x||800, p.y||450, key).setOrigin(0.5,1.0).setDisplaySize(48,64); markForYSort(spr,0);
      const lbl=scene.add.text(spr.x, spr.y+8, (p.name||('P'+p.id))+'', {fontSize:'14px', color:'#cde3ff'}).setOrigin(0.5,0).setDepth(DEPTH.ui);
      rec={ sprite:spr, label:lbl, holdSprite:null, holdingSize:null, buffer:makeInterpBuffer(INTERP_MAX_SAMPLES) }; remotes.set(p.id, rec); return rec;
    }
    function ingestRemotePlayers(arr, serverTime){
      for(let i=0;i<arr.length;i++){
        const p=arr[i]; if(!p || p.id===myPlayerId) continue;
        const rec=ensureRemoteRecord(p);
        const tex='ph:player-'+(p.dir||'S'); if(scene.textures.exists(tex)) rec.sprite.setTexture(tex).setDisplaySize(48,64).setOrigin(0.5,1.0);
        rec.label.setText(p.name || ('P'+p.id));
        const seq=Number(p.pos_seq||0), t=Number(p.last_seen||serverTime||0);
        if(seq&&t) rec.buffer.push(seq,t,p.x||rec.sprite.x, p.y||rec.sprite.y, p.dir||'S');

        const held = p.held;
        if (held && held.size) {
          const human = binToHuman(held.size);
          if (!rec.holdSprite || rec.holdingSize !== human) {
            if (rec.holdSprite) rec.holdSprite.destroy();
            const texBox = texForBox(human);
            rec.holdSprite = texBox.atlas
              ? scene.add.sprite(0, 0, texBox.atlas, texBox.frame).setScale(texBox.scale)
              : scene.add.sprite(0, 0, texBox.key);
            rec.holdSprite.setOrigin(0.5, 1.0);
            rec.holdingSize = human;
          }
        } else {
          if (rec.holdSprite) { rec.holdSprite.destroy(); rec.holdSprite = null; rec.holdingSize = null; }
        }
      }
    }
    function renderRemotesSmoothed(){
      const t=clock.now() - (INTERP_DELAY_MS/1000);
      remotes.forEach(rec=>{
        const pose=rec.buffer.at(t); if(!pose) return; rec.sprite.setPosition(pose.x,pose.y); rec.label.setPosition(pose.x, pose.y+8).setDepth(DEPTH.ui);
        if(rec.holdSprite){ const off=holdOffsetPx(rec.holdingSize||'medium'); rec.holdSprite.setPosition(pose.x,pose.y-off); const rpDepth=(rec.sprite.y||0)+(rec.sprite.__yExtra||0); rec.holdSprite.setDepth(Math.max(DEPTH.ui+1, rpDepth+1)); }
      });
    }
    function cleanupMissingRemotes(players){ const live=new Set(); for(let i=0;i<players.length;i++){ const p=players[i]; if(p && p.id!==myPlayerId) live.add(p.id); }
      remotes.forEach((rec,pid)=>{ if(!live.has(pid)){ if(rec.label&&rec.label.destroy) rec.label.destroy(); if(rec.holdSprite&&rec.holdSprite.destroy) rec.holdSprite.destroy(); if(rec.sprite&&rec.sprite.destroy) rec.sprite.destroy(); remotes.delete(pid); } });
    }

    // ---------- plane helpers ----------
    function addPlaneCargoObstacleForSprite(spr, facing) {
      const w = spr.displayWidth || 140;
      const h = spr.displayHeight || 64;
      const cargoW = Math.max(60, Math.round(w * 0.60));
      const cargoH = Math.max(24, Math.round(h * 0.28));
      const offsetY = Math.round(h * 0.12);
      const offsetX = (facing === 'left' ? -1 : 1) * Math.round(w * 0.05);
      const rx = spr.x + offsetX;
      const ry = spr.y - offsetY;
      const rect = scene.add.rectangle(rx, ry, cargoW, cargoH, 0x00ff00, 0.0).setOrigin(0.5, 1.0);
      scene.physics.add.existing(rect, true);
      planeObstacleGroup.add(rect);
      planeObstacles.push({ rect, plane: null });
      return rect;
    }
    function getBoundsFromRectGO(r){
      // r has origin 0.5,1.0
      const w = r.displayWidth || r.width || 0;
      const h = r.displayHeight || r.height || 0;
      return { left:r.x - w/2, right:r.x + w/2, bottom:r.y, top:r.y - h, width:w, height:h };
    }
    function findNearestPlaneCargo(pRect, pad){
      let best = null, dBest = Infinity;
      for (const o of planeObstacles){
        const r = o && o.rect; if (!r) continue;
        const R = getBoundsFromRectGO(r);
        const d = distRects(pRect, R);
        if (d <= (pad||PLANE_PROX_RADIUS) && d < dBest){ dBest = d; best = o; }
      }
      return best;
    }

    // ---------- interactions ----------
    async function attemptInteract(){
      if (activeMode==='depositTerminal' && carrying){
        // Open Stockpile Logging modal (Step 7)
        window.WG_UI && window.WG_UI.openStockpileLogging({
          qty: heldQty || 1,
          display_name: heldDisplayName || (heldSize.toUpperCase()+" box"),
          unit_lb: heldUnitLb || 0,
          size: HUMAN_TO_BIN[heldSize] || 'M',
          onDone: () => {
            // Clear local carry immediately for responsiveness
            toggleCarry(false);
            hintContainer.setVisible(false);
            // UI will catch up via polling; optionally refresh
            setTimeout(()=>bootstrapFromServer().catch(()=>{}), 150);
          }
        });
        return;
      }

      if (activeMode==='depositCarrier' && carrying && activeTarget){
        const entry=activeTarget;
        // If depositing to the OUTBOUND/“retrieval” truck, open the outbound
        // Shipping modal so the player logs it as outbound before send.
        if (entry.type === TRUCK && String(entry.role||"").toLowerCase() !== 'delivery') {
          const sizeBin = HUMAN_TO_BIN[heldSize] || 'M';
          window.WG_UI && window.WG_UI.openTruckShippingLogging({
            truckId: entry.uid,
            carrierEntry: entry,
            qty: heldQty || 1,
            display_name: heldDisplayName || (sizeBin + " box"),
            unit_lb: heldUnitLb || 0,
            size: sizeBin,
            onDone: () => {
              toggleCarry(false);
              hintContainer.setVisible(false);
              setTimeout(()=>bootstrapFromServer().catch(()=>{}), 150);
            }
          });
          return;
        }
        const q = Math.max(1, parseInt(heldQty||1,10));
        const pend = addPending({ action:'carrier_add', size:heldSize, carrier_type:entry.type, carrier_uid:entry.uid });
        // Optimistic: add full qty to carrier sprite stack
        applyCarrierDelta(entry, { add:{ [heldSize]:q }, remove:{} });
        toggleCarry(false);
        hintContainer.setVisible(false);
        try {
          await _pendingClaim;
          const itemKey = heldItemKey || DEFAULT_ITEM_KEY;
          const sizeBin = HUMAN_TO_BIN[heldSize] || 'M';
          await postClaimSerial({
            action:'carrier_add',
            carrier_type:entry.type,
            carrier_index:-1,
            carrier_uid:entry.uid,
            item_key:itemKey,
            size:sizeBin,
            qty:q,
            // metadata (enables outbound assignment/fulfillment)
            display_name: heldDisplayName || '',
            unit_lb: heldUnitLb || 0
          });
          heldItemKey = null;
        } catch (e) {
          cancelPending(pend);
          applyCarrierDelta(entry, { add:{}, remove:{ [heldSize]:q } });
          setHeldBoxTexture(heldSize);
          toggleCarry(true);
          try { await bootstrapFromServer(); } catch(_) {}
        }
        return;
      }

      if (activeMode==='pickupCarrier' && activeTarget){
        const entry=activeTarget;
        // For ANY TRUCK (delivery or retrieval): open the Truck Cargo modal.
        if (entry.type === TRUCK) {
          window.WG_UI && window.WG_UI.openTruckCargo({
            truckId: entry.uid,
            carrierEntry: entry,
            onTaken: ({ qty, size, display_name, unit_lb })=>{
              const human = (BIN_TO_HUMAN[String(size).toUpperCase()] || size || 'medium');
              setHeldBoxTexture(human);
              heldQty = qty; heldDisplayName = display_name||""; heldUnitLb = unit_lb||0; heldItemKey = DEFAULT_ITEM_KEY;
              toggleCarry(true);
            }
          });
          return;
        }
        // CART: open a cart cargo modal (metadata-aware), like trucks.
        if (window.WG_UI && typeof window.WG_UI.openCartCargo === 'function'){
          window.WG_UI.openCartCargo({
            cartId: entry.uid,
            carrierEntry: entry,
            onTaken: ({ qty, size, display_name, unit_lb })=>{
              const human = (BIN_TO_HUMAN[String(size).toUpperCase()] || size || 'medium');
              setHeldBoxTexture(human);
              heldQty = qty; heldDisplayName = display_name||""; heldUnitLb = unit_lb||0; heldItemKey = DEFAULT_ITEM_KEY;
              toggleCarry(true);
            }
          });
          return;
        }
        // Fallback: legacy size picker if UI module isn't loaded.
        const counts=countBySize(entry.loadSizes), opts=sizeOptionsFromCounts(counts), def=(opts[0]&&opts[0].value)||'medium';
        openSelect('Pick up from '+entry.type.toUpperCase(), opts, def, async (val)=>{
          let resolved={ item_key:DEFAULT_ITEM_KEY, carrier_uid: entry.uid };
          if (entry.type===TRUCK) resolved=await resolveTruckSkuForSizeByUid(entry.uid, val);

          const pend = addPending({ action:'carrier_remove', size:val, carrier_type:entry.type, carrier_uid:resolved.carrier_uid });
          applyCarrierDelta(entry, { add:{}, remove:{ [val]:1 } });
          setHeldBoxTexture(val);
          heldQty = 1; heldDisplayName=""; heldUnitLb=0; toggleCarry(true);

          try {
            await postClaimSerial({ action:'carrier_remove', carrier_type:entry.type, carrier_index:-1, carrier_uid:resolved.carrier_uid, item_key:resolved.item_key, size:val });
            heldItemKey = resolved.item_key;
          } catch (e) {
            cancelPending(pend);
            applyCarrierDelta(entry, { add:{ [val]:1 }, remove:{} });
            toggleCarry(false);
            heldItemKey = null;
            try { await bootstrapFromServer(); } catch(_) {}
          }
        });
        return;
      }

      if (activeMode==='pickupStockpile'){
        // Open Stockpile Inventory modal (category-based, like trucks)
        window.WG_UI && window.WG_UI.openStockpileInventory({
          onTaken: ({ qty, size, display_name, unit_lb })=>{
            const human = (size && BIN_TO_HUMAN[String(size).toUpperCase()]) || size || 'medium';
            // Optimistic local carry + remove one visible sprite of that size
            if (removeOneFromStockpile(human)) { /* visual pop */ }
            setHeldBoxTexture(human);
            heldQty = qty; heldDisplayName = display_name||""; heldUnitLb = unit_lb||0; heldItemKey = DEFAULT_ITEM_KEY;
            toggleCarry(true);
          }
        });
        return;
      }

      if (activeMode==='planePanel' && activeTarget){
        try{
          // Tell the DOM plane panel which plane id is active so pin requests
          // always include a valid plane_id (fixes "missing_manifest").
          try {
            const pid = (activeTarget && (activeTarget.id ?? activeTarget.plane_id)) || null;
            if (pid) {
              window.dispatchEvent(new CustomEvent('wg:set-plane-id', { detail:{ id: Number(pid) } }));
              // Proactively hydrate status for this plane.
              WGNet && WGNet.wgPlaneStatus && WGNet.wgPlaneStatus(Number(pid)).catch(()=>{});
            }
          } catch(_){}
          window.WGPlanePanel && window.WGPlanePanel.open(activeTarget);
        }catch(_) {}
        return;
      }

    }

    // ---------- HUD extra: show "holding" summary ----------
    function renderHeldHudLine(){
      if (!hudText) return;
      const v = player && player.body ? player.body.velocity||{x:0,y:0} : {x:0,y:0};
      const base = `x:${player.x.toFixed(1)}  y:${player.y.toFixed(1)}  vx:${v.x.toFixed(0)}  vy:${v.y.toFixed(0)}`;
      if (!carrying || !heldQty) { hudText.setText(base); return; }
      const sizeLabel = (HUMAN_TO_BIN[heldSize] || 'M');
      const meta = heldDisplayName ? ` × ${heldQty} ${heldDisplayName} (${sizeLabel}, ${heldUnitLb||0} lb)` : ` × ${heldQty} (${sizeLabel})`;
      hudText.setText(base + `\nholding${meta}`);
    }

    // ---------- start phaser ----------
    try{ new Phaser.Game(config); } catch(e){ console.error("Phaser failed", e); showFatal("Phaser failed to start — see console."); }
  }
})();

// ─────────────────────────────────────────────────────────────────────────────
// WG_UI module (Step 6 & 7): dialogs for Truck Cargo + Stockpile Logging
// ─────────────────────────────────────────────────────────────────────────────
(function(){
  if (window.WG_UI) return;
  const BIN_LABEL = { S:'S', M:'M', L:'L', XL:'XL' };
  const BIN_TO_HUMAN = { S:'small', M:'medium', L:'large', XL:'xl', s:'small' }; // fix S → small
  function esc(s){ return String(s==null?"":s).replace(/[&<>"]/g, m=>({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;' }[m])); }

  async function openStockpileInventory({ onTaken }){
    try{
      const sp = await window.WGNet.getStockpile();
      const reg = (sp && sp.registry) || {};
      const lines = Object.values(reg).filter(x => (x && (x.qty|0) > 0));
      if (!lines.length){ alert("Stockpile is empty."); return; }

      const title = `Stockpile Inventory`;
      const header = `
        <table class="wg-table">
          <thead><tr>
            <th style="width:36%">Item</th>
            <th style="width:10%">Size</th>
            <th style="width:12%">Unit (lb)</th>
            <th style="width:12%">Available</th>
            <th>Take</th>
          </tr></thead>
          <tbody id="wg-sp-body"></tbody>
        </table>`;

      function renderBody(){
        const rows = lines.map((ln, idx)=>{
          const size = BIN_LABEL[ln.size] || esc(ln.size||'M');
          const can  = Math.max(0, parseInt(ln.qty||0, 10));
          const disable = (can<=0);
          return `<tr data-row="${idx}">
            <td><strong>${esc(ln.display_name||'item')}</strong></td>
            <td><span class="wg-pill">${size}</span></td>
            <td class="wg-mono">${Number(ln.unit_lb||0).toFixed(0)}</td>
            <td class="wg-mono">${can}</td>
            <td>
              <div class="wg-flex" style="gap:.5rem; align-items:center;">
                <input class="wg-qty" type="number" min="1" max="${can}" value="${Math.min(can,1)}" style="width:5rem;" ${disable?'disabled':''}/>
                <button class="btn btn-primary wg-sp-take" ${disable?'disabled':''}>Take</button>
              </div>
            </td>
          </tr>`;
        }).join('');
        return header.replace('id="wg-sp-body"></tbody>', `id="wg-sp-body">${rows}</tbody>`);
      }

      function hookButtons(){
        const tbody = document.getElementById('wg-sp-body');
        if (!tbody) return;
        tbody.querySelectorAll('button.wg-sp-take').forEach(btn=>{
          btn.addEventListener('click', async (ev)=>{
            const tr = ev.currentTarget.closest('tr');
            const idx = parseInt(tr.getAttribute('data-row'),10);
            const ln  = lines[idx]; if(!ln) return;
            const available = Math.max(0, parseInt(ln.qty||0,10));
            if (available<=0) return;
            const qtyInput = tr.querySelector('input.wg-qty');
            let want = parseInt((qtyInput && qtyInput.value) || '0', 10);
            if (!Number.isFinite(want) || want <= 0) want = 1;
            want = Math.min(available, want);

            // Optimistic table update
            ln.qty = available - want;
            tr.children[3].textContent = String(ln.qty);

            // Mark pending so echoed claim doesn't double-apply locally
            const human = (BIN_TO_HUMAN[ln.size] || 'medium');
            const _tok = window.addPendingLocal && window.addPendingLocal({
              action: 'stockpile_remove',
              size: human
            });

            try{
              const payload = {
                action: 'stockpile_remove',
                item_key: 'box',
                size: ln.size || 'M',
                qty: want,
                display_name: ln.display_name || '',
                unit_lb: ln.unit_lb || 0,
              };
              if (window.postClaimSerial) {
                await window.postClaimSerial(payload);
              } else {
                await window.WGNet.postClaim(payload);
              }
              onTaken && onTaken({ qty: want, size: ln.size, display_name: ln.display_name||'', unit_lb: ln.unit_lb||0 });
              // Close modal after successful take
              document.getElementById('wg-modal-cancel')?.click();
            }catch(e){
              if (window.cancelPendingLocal && _tok) window.cancelPendingLocal(_tok);
              alert("Take failed: "+(e&&e.message?e.message:"error"));
            }
          });
        });
      }

      const bodyHTML = renderBody();
      window.openModal({ title, bodyHTML, okLabel:"Close", onOK:()=>{}, onCancel:()=>{} });
      setTimeout(hookButtons, 0);
    }catch(e){
      alert("Failed to open Stockpile: "+(e&&e.message?e.message:"error"));
    }
  }

  // Outbound Shipping modal (log as OUTBOUND, then load to retrieval truck)
  function openTruckShippingLogging({ qty, display_name, unit_lb, size, truckId, carrierEntry, onDone }){
    const sizeLabel = String(size||'M').toUpperCase();
    const titleBar = `
      <div class="wg-titlebar wg-flex">
        <div>
          You’re holding: <strong>${esc(qty||1)} × ${esc(display_name||'item')}</strong>
          <span class="wg-muted">(${esc(sizeLabel)})</span>,
          <span class="wg-muted">${esc(Number(unit_lb||0).toFixed(0))} lb each</span>
        </div>
        <div class="wg-note">Log it below as <b>Outbound</b>, then click <em>Load cargo to truck</em>.</div>
      </div>`;
    const iframe = `<iframe class="wg-iframe" src="/inventory/detail?dir=outbound&flow=truck&truck_id=${encodeURIComponent(truckId)}" title="Inventory Logging (Outbound)"></iframe>`;
    const bodyHTML = `${titleBar}${iframe}`;

    window.openModal({
      title: "Truck Shipping",
      bodyHTML,
      okLabel: "Load cargo to truck",
      onOK: async ()=>{
        // Optimistic: add to truck stack for visuals
        try{
          if (carrierEntry && window.applyCarrierDelta){
            const human = (BIN_TO_HUMAN[sizeLabel] || 'medium');
            const add = {}; add[human] = Math.max(1, parseInt(qty||1,10));
            window.applyCarrierDelta(carrierEntry, { add, remove:{} });
          }
        }catch(_){}
        // Post claim
        try{
          const payload = {
            action: 'carrier_add',
            carrier_type: 'truck',
            carrier_uid: truckId,
            item_key: 'box',
            size: sizeLabel,
            qty: qty || 1,
            display_name: display_name || '',
            unit_lb: unit_lb || 0
          };
          if (window.postClaimSerial) {
            await window.postClaimSerial(payload);
          } else {
            await window.WGNet.postClaim(payload);
          }
          onDone && onDone();
        }catch(e){
          // Roll back optimistic add on failure
          try{
            if (carrierEntry && window.applyCarrierDelta){
              const human = (BIN_TO_HUMAN[sizeLabel] || 'medium');
              const rem = {}; rem[human] = Math.max(1, parseInt(qty||1,10));
              window.applyCarrierDelta(carrierEntry, { add:{}, remove: rem });
            }
          }catch(_){}
          alert("Load failed: " + (e && e.message ? e.message : "error"));
        }
      },
      onCancel: ()=>{}
    });
  }

  async function openTruckCargo({ truckId, carrierEntry, onTaken }){
    try {
      const t = await window.WGNet.findTruck(truckId);
      if (!t) { alert("Truck not found."); return; }
      const lines = Array.isArray(t.lines) ? t.lines.slice() : [];
      const role = String(t.role||"").toLowerCase();
      const isDelivery = role === 'delivery';
      const title = `Truck Cargo — <span class="wg-muted">${isDelivery ? 'Delivery' : 'Outbound'} #${esc(t.truck_id)}</span>`;
      const header = `
        <table class="wg-table">
          <thead><tr>
            <th style="width:36%">Item</th>
            <th style="width:10%">Size</th>
            <th style="width:12%">Unit (lb)</th>
            <th style="width:12%">Available</th>
            <th>Take</th>
          </tr></thead>
          <tbody id="wg-cargo-body"></tbody>
        </table>`;

      function renderBody(){
        const rows = lines.map((ln, idx)=>{
          const size = BIN_LABEL[ln.size] || esc(ln.size||'M');
          const can = Math.max(0, parseInt(ln.qty||0, 10));
          const disable = (can<=0);
          return `<tr data-row="${idx}">
            <td><strong>${esc(ln.display_name||'item')}</strong></td>
            <td><span class="wg-pill">${size}</span></td>
            <td class="wg-mono">${Number(ln.unit_lb||0).toFixed(0)}</td>
            <td class="wg-mono">${can}</td>
            <td>
              <button class="btn btn-primary wg-qtybtn" data-take="all" ${disable?'disabled':''}>
                Take
              </button>
            </td>
          </tr>`;
        }).join('');
        return header.replace('id="wg-cargo-body"></tbody>', `id="wg-cargo-body">${rows}</tbody>`);
      }

      function hookButtons(){
        const tbody = document.getElementById('wg-cargo-body');
        if (!tbody) return;
        tbody.querySelectorAll('button[data-take]').forEach(btn=>{
          btn.addEventListener('click', async (ev)=>{
            const tr = ev.currentTarget.closest('tr');
            const idx = parseInt(tr.getAttribute('data-row'),10);
            const ln = lines[idx]; if(!ln) return;
            const available = Math.max(0, parseInt(ln.qty||0,10));
            if (available<=0) return;
            const want = available; // always take max
            let _tok = null;
            // Optimistic: reflect immediately
            ln.qty = available - want;
            tr.children[3].textContent = String(ln.qty);
            // Update truck sprite stack visually
            try{
              if (carrierEntry) {
                const human = (BIN_TO_HUMAN[ln.size] || 'medium');
                // Apply N removes
                const remove = {}; remove[human] = want;
                window.applyCarrierDelta && window.applyCarrierDelta(carrierEntry, { add:{}, remove });
              }
            }catch(_){}
            // Set local carry visuals
            try{
              const human = (BIN_TO_HUMAN[ln.size] || 'medium');
              if (window.setHeldBoxTexture) window.setHeldBoxTexture(human);
              window.setHeldMeta && window.setHeldMeta({ qty: want, display_name: ln.display_name||'', unit_lb: ln.unit_lb||0, item_key:'box', size: ln.size });
              window.toggleCarry && window.toggleCarry(true);
            }catch(_){}

            // Server claim (serialize to avoid race with a subsequent deposit)
            try{
              // Mark a pending to suppress the echoed 'carrier_remove' claim
              const human = (BIN_TO_HUMAN[ln.size] || 'medium');
              _tok = window.addPendingLocal && window.addPendingLocal({
                action: 'carrier_remove',
                size: human,
                carrier_type: 'truck',
                carrier_uid: t.truck_id
              });

              // For Delivery truck use 'take'; for Outbound use 'carrier_remove'
              const payload = isDelivery ? {
                action: 'take',
                carrier_type: 'truck',
                carrier_uid: t.truck_id,
                item_key: 'box',
                size: ln.size || 'M',
                qty: want,
                display_name: ln.display_name || '',
                unit_lb: ln.unit_lb || 0,
              } : {
                action: 'carrier_remove',
                carrier_type: 'truck',
                carrier_uid: t.truck_id,
                item_key: 'box',
                size: ln.size || 'M',
                qty: want,
                display_name: ln.display_name || '',
                unit_lb: ln.unit_lb || 0,
              };
              if (window.postClaimSerial) {
                await window.postClaimSerial(payload);
              } else {
                await window.WGNet.postClaim(payload);
              }
              onTaken && onTaken({ qty: want, size: (BIN_TO_HUMAN[ln.size]||'medium'), display_name: ln.display_name||'', unit_lb: ln.unit_lb||0 });
              // Close modal after a successful take
              document.getElementById('wg-modal-cancel')?.click();
            } catch (e) {
              // Revert optimistic table and sprite stack
              try {
                ln.qty = (ln.qty|0) + want;
                tr.children[3].textContent = String(ln.qty);
                if (carrierEntry) {
                  const human = (BIN_TO_HUMAN[ln.size] || 'medium');
                  const add = {}; add[human] = want;
                  window.applyCarrierDelta && window.applyCarrierDelta(carrierEntry, { add, remove:{} });
                }
                // Drop carried box if we set it
                if (window.toggleCarry) window.toggleCarry(false);
              } catch(_){}
              if (window.cancelPendingLocal && _tok) window.cancelPendingLocal(_tok);
              alert("Take failed: " + (e && e.message ? e.message : "error"));
            }
          });
        });
      }

      const bodyHTML = renderBody();
      window.openModal({ title, bodyHTML, okLabel:"Close", onOK:()=>{}, onCancel:()=>{} });
      setTimeout(hookButtons, 0);
    } catch (e) {
      alert("Failed to open Truck Cargo: " + (e && e.message ? e.message : "error"));
    }
  }

  async function openCartCargo({ cartId, carrierEntry, onTaken }){
    // Fallback fetcher: WGNet.findCart() or WGNet.getCarts()
    async function _fetchCart(id){
      if (window.WGNet && typeof window.WGNet.findCart === 'function') return await window.WGNet.findCart(id);
      if (window.WGNet && typeof window.WGNet.getCarts === 'function'){
        const all = await window.WGNet.getCarts(); return (all||[]).find(c=>String(c.id)===String(id));
      }
      // last resort: refresh state
      const s = await window.WGNet.getState(0); return (s&&s.carts||[]).find(c=>String(c.id)===String(id));
    }
    try{
      const c = await _fetchCart(cartId);
      if (!c){ alert("Cart not found."); return; }
      const lines = Array.isArray(c.lines) ? c.lines.slice() : [];
      if (!lines.length){ alert("Cart is empty."); return; }

      const title = `Cart Cargo — <span class="wg-muted">#${String(c.id)}</span>`;
      const header = `
        <table class="wg-table">
          <thead><tr>
            <th style="width:36%">Item</th>
            <th style="width:10%">Size</th>
            <th style="width:12%">Unit (lb)</th>
            <th style="width:12%">Available</th>
            <th>Take</th>
          </tr></thead>
          <tbody id="wg-cart-body"></tbody>
        </table>`;

      function renderBody(){
        const rows = lines.map((ln, idx)=>{
          const size = BIN_LABEL[ln.size] || (ln.size||'M');
          const can  = Math.max(0, parseInt(ln.qty||0,10));
          const dis  = (can<=0) ? 'disabled' : '';
        return `<tr data-row="${idx}">
            <td><strong>${esc(ln.display_name||'item')}</strong></td>
            <td><span class="wg-pill">${esc(size)}</span></td>
            <td class="wg-mono">${Number(ln.unit_lb||0).toFixed(0)}</td>
            <td class="wg-mono">${can}</td>
            <td><button class="btn btn-primary wg-qtybtn" ${dis}>Take</button></td>
          </tr>`;
        }).join('');
        return header.replace('id="wg-cart-body"></tbody>', `id="wg-cart-body">${rows}</tbody>`);
      }

      function hookButtons(){
        const tbody = document.getElementById('wg-cart-body');
        if (!tbody) return;
        tbody.querySelectorAll('button.wg-qtybtn').forEach(btn=>{
          btn.addEventListener('click', async (ev)=>{
            const tr = ev.currentTarget.closest('tr');
            const idx = parseInt(tr.getAttribute('data-row'),10);
            const ln  = lines[idx]; if (!ln) return;
            const want = Math.max(1, parseInt(ln.qty||0,10));
            if (!want) return;

            // optimistic: shrink the cart stack
            ln.qty = Math.max(0, (ln.qty|0) - want);
            tr.children[3].textContent = String(ln.qty);
            try{
              if (carrierEntry && window.applyCarrierDelta){
                const human = (BIN_TO_HUMAN[ln.size] || 'medium');
                const rem = {}; rem[human] = want;
                window.applyCarrierDelta(carrierEntry, { add:{}, remove: rem });
              }
              const human = (BIN_TO_HUMAN[ln.size] || 'medium');
              window.setHeldBoxTexture && window.setHeldBoxTexture(human);
              window.setHeldMeta && window.setHeldMeta({ qty: want, display_name: ln.display_name||'', unit_lb: ln.unit_lb||0, item_key:'box', size: ln.size });
              window.toggleCarry && window.toggleCarry(true);
              // post claim (metadata-aware remove)
              const payload = {
                action: 'carrier_remove',
                carrier_type: 'cart',
                carrier_uid: c.id,
                item_key: 'box',
                size: ln.size || 'M',
                qty: want,
                display_name: ln.display_name || '',
                unit_lb: ln.unit_lb || 0
              };
              if (window.postClaimSerial) await window.postClaimSerial(payload); else await window.WGNet.postClaim(payload);
              onTaken && onTaken({ qty: want, size: ln.size, display_name: ln.display_name||'', unit_lb: ln.unit_lb||0 });
              document.getElementById('wg-modal-cancel')?.click();
            }catch(e){
              // revert optimistic on error
              try{
                ln.qty += want;
                tr.children[3].textContent = String(ln.qty);
                if (carrierEntry && window.applyCarrierDelta){
                  const human = (BIN_TO_HUMAN[ln.size] || 'medium');
                  const add = {}; add[human] = want;
                  window.applyCarrierDelta(carrierEntry, { add, remove: {} });
                }
                if (typeof window.toggleCarry==='function'){ window.toggleCarry(false); }
              }catch(_){}
              alert("Take failed: "+(e&&e.message?e.message:"error"));
            }
          });
        });
      }

      const bodyHTML = renderBody();
      window.openModal({ title, bodyHTML, okLabel:"Close", onOK:()=>{}, onCancel:()=>{} });
      setTimeout(hookButtons, 0);
    }catch(e){
      alert("Failed to open Cart Cargo: "+(e&&e.message?e.message:"error"));
    }
  }

  function openStockpileLogging({ qty, display_name, unit_lb, size, onDone }){
    const humanSize = { S:'small', M:'medium', L:'large', XL:'xl' }[size] || 'medium';
    const titleBar = `
      <div class="wg-titlebar wg-flex">
        <div>
          You’re holding: <strong>${esc(qty)} × ${esc(display_name||'item')}</strong>
          <span class="wg-muted">(${esc(size||'M')})</span>,
          <span class="wg-muted">${esc(Number(unit_lb||0).toFixed(0))} lb each</span>
        </div>
        <div class="wg-note">Log it below, then click <em>Drop cargo at stockpile</em>.</div>
      </div>`;
    const iframe = `<iframe class="wg-iframe" src="/inventory/detail" title="Inventory Logging"></iframe>`;
    const bodyHTML = `${titleBar}${iframe}`;
    window.openModal({
      title: "Stockpile Logging",
      bodyHTML,
      okLabel: "Drop cargo at stockpile",
      onOK: async ()=>{
        try{
          const payload = { action:'stockpile_add', item_key:'box', size, qty, display_name, unit_lb };
          if (window.postClaimSerial) {
            await window.postClaimSerial(payload);
          } else {
            await window.WGNet.claimDropToStockpile(payload);
          }
          onDone && onDone();
        }catch(e){
          alert("Drop failed: "+(e&&e.message?e.message:"error"));
        }
      },
      onCancel: ()=>{}
    });
  }

  window.WG_UI = { openTruckCargo, openCartCargo, openStockpileLogging, openStockpileInventory, openTruckShippingLogging };
})();

// ─────────────────────────────────────────────────────────────────────────────
// WGPlanePanel: Request list → Pin → Validate → Load → Paperwork
// ─────────────────────────────────────────────────────────────────────────────
(function(){
  if (window.WGPlanePanel) return;

  // --- shared mini CSS so tables/columns look right even without base.css ---
  (function ensureWGStyles(){
    if (document.getElementById('wg-ui-inline-style')) return;
    const css = `
      .wg-table{width:100%;border-collapse:collapse}
      .wg-table th,.wg-table td{padding:.5rem .6rem;border-bottom:1px solid #2b3440;text-align:left;vertical-align:middle}
      .wg-table thead th{color:#a9b6c8;font-weight:600}
      .wg-mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace}
      .wg-pill{display:inline-block;padding:.1rem .45rem;border:1px solid #3a4453;border-radius:999px;font:600 12px/1 system-ui}
      .wg-flex{display:flex}
      .wg-iframe{width:100%;height:50vh;border:1px solid #2b3440;border-radius:8px}
      .btn{background:#121821;border:1px solid #2b3440;color:#cbd9ee;padding:.35rem .6rem;border-radius:.5rem;cursor:pointer}
      .btn.btn-primary{background:#1a2230;border-color:#3b4656;color:#dbe7ff}
    `;
    const style = document.createElement('style');
    style.id = 'wg-ui-inline-style';
    style.textContent = css;
    document.head.appendChild(style);
  })();

  // --- strict plane id resolution: dataset only (no title heuristics) ---
  function _toId(x){ const n = Number(x); return Number.isFinite(n) ? n : null; }
  function _resolvePlaneId(scopeEl){
    const root = (scopeEl && scopeEl.closest('#wg-plane-panel')) || document.getElementById('wg-plane-panel');
    if (!root) return null;
    return _toId(root.getAttribute('data-plane-id'));
  }

  const $ = (sel, root=document)=>root.querySelector(sel);
  const $$ = (sel, root=document)=>Array.from(root.querySelectorAll(sel));
  function esc(s){ return String(s==null?"":s).replace(/[&<>"]/g, m=>({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;' }[m])); }
  function _ensureOverlayRoot(){
    let el = document.getElementById('wg-overlay-root');
    if (el) return el;
    el = document.createElement('div');
    el.id = 'wg-overlay-root';
    el.style.cssText = 'position:fixed;inset:0;display:none;z-index:99998;background:rgba(0,0,0,.5)';
    document.body.appendChild(el);
    return el;
  }
  function overlayRoot(){ return document.getElementById('wg-overlay-root') || _ensureOverlayRoot(); }

  let _state = { open:false, plane_id:null, pinnedRequestId:null, selectedCart:null, lastStatus:null, el:null, _statusTimer:null };

  // ---------- Error → Friendly message mapper ----------
  function _errInfo(err){
    try { return (window.WGNet && window.WGNet.parseError) ? window.WGNet.parseError(err) : { code:"unknown", message:String(err&&err.message||"error") }; }
    catch(_) { return { code:"unknown", message:String(err&&err.message||"error") }; }
  }
  // Extra friendly case for plane not selected / NaN id
  function _noSelectionModal(){
    window.openModal && window.openModal({ title:"No Flight Selected", bodyHTML:"<p>Pin a flight for this plane, then try again.</p>", okLabel:"OK", onOK:()=>{}, onCancel:()=>{} });
  }

  function _diffTableHTML(diff){
    const rows = [];
    const add = (kind, arr) => (arr||[]).forEach(x => rows.push({ kind, size: formatSize(x.size||'M'), qty: Number(x.qty||0)|0 }));
    if (diff){ add('shortage', diff.shortages); add('excess', diff.excess); }
    if (!rows.length) return `<div class="wg-muted" style="padding:.6rem">No differences provided.</div>`;
    return `<table class="wg-table"><thead><tr><th>Kind</th><th>Size</th><th>Qty</th></tr></thead><tbody>${
      rows.map(r=>`<tr><td>${esc(r.kind)}</td><td>${esc(r.size)}</td><td class="wg-mono">${esc(r.qty)}</td></tr>`).join("")
    }</tbody></table>`;
  }
  function showFriendlyError(err, ctx){
    const { code, message, data } = _errInfo(err);
    const c = String(code||"").toLowerCase();
    // 1) missing_manifest
    if (c === "missing_manifest"){
      window.openModal && window.openModal({
        title: "No Manifest Lines",
        bodyHTML: `<p>No manifest lines available; choose another flight.</p>`,
        okLabel: "OK",
        onOK: ()=>{},
        onCancel: ()=>{}
      });
      return;
    }
    // 2) already_pinned
    if (c === "already_pinned"){
      const by = (data && (data.owner_name || data.by || data.name)) ? String(data.owner_name || data.by || data.name) : "another user";
      window.openModal && window.openModal({
        title: "Plane Already Pinned",
        bodyHTML: `<p>Plane already pinned by <b>${esc(by)}</b>. Try another request or wait.</p>`,
        okLabel: "OK",
        onOK: ()=>{},
        onCancel: ()=>{}
      });
      return;
    }
    // 2b) no_selection (server couldn't find a pin / NaN id)
    if (c === "no_selection"){
      _noSelectionModal();
      return;
    }
    // 3) mismatch → render diff + disable Load
    if (c === "mismatch"){
      const diff = (data && (data.diff || data.details || data.data && data.data.diff)) || null;
      try {
        const btn = document.getElementById('wgpp-load');
        if (btn) btn.disabled = true;
      } catch(_) {}
      window.openModal && window.openModal({
        title: "Load Mismatch",
        bodyHTML: `<p>The selected cart contents do not match the flight’s requirements.</p>${_diffTableHTML(diff)}<p class="wg-muted" style="margin-top:.5rem">Adjust the cart to resolve shortages/excess, then try again.</p>`,
        okLabel: "OK",
        onOK: ()=>{},
        onCancel: ()=>{}
      });
      return;
    }
    // Default fallback
    window.openModal && window.openModal({
      title: "Request Failed",
      bodyHTML: `<p>${esc(message || "Something went wrong.")}</p>`,
      okLabel: "OK",
      onOK: ()=>{},
      onCancel: ()=>{}
    });
  }

  function mount(node){ const root=overlayRoot(); if(!root) return; root.innerHTML=""; root.appendChild(node); root.style.pointerEvents="auto"; }
  function unmount(){ const root=overlayRoot(); if(!root) return; root.innerHTML=""; root.style.pointerEvents="none"; }

  function formatSize(bin){ return ({S:'S',M:'M',L:'L',XL:'XL'})[String(bin||'M').toUpperCase()] || 'M'; }

  // Requests API shim (fetch; no WGNet dependency) ────────────────
  async function fetchRequests(){
    const r = await fetch('/api/wargame/requests', { credentials:'same-origin' });
    const j = await r.json().catch(()=>({}));
    return Array.isArray(j.requests) ? j.requests : [];
  }
  async function pinRequest(reqId){
    const plane_id = _state.plane_id;
    if (plane_id == null){ _noSelectionModal(); return; }
    const payload = {
      plane_id,
      flight_ref: { request_id: reqId },
      session_id: (window.WG_SESSION_ID ?? 1),
      player_id:  (window.WG_PLAYER_ID ?? null)
    };
    const r = await fetch('/api/wargame/plane/pin', {
      method:'POST', credentials:'same-origin',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify(payload)
    });
    if (!r.ok){
      const err = await r.json().catch(()=>({message:`HTTP ${r.status}`}));
      throw err;
    }
    _state.pinnedRequestId = reqId;
    await Promise.all([
      fetchManifest(reqId).then(lines=>renderManifestTable(_state.el, lines)).catch(()=>renderManifestTable(_state.el, [])),
      checkStatus()
    ]);
  }
  async function fetchManifest(reqId){
    const r = await fetch(`/api/wargame/request/${encodeURIComponent(reqId)}/manifest`, { credentials:'same-origin' });
    const j = await r.json().catch(()=>({}));
    const lines = Array.isArray(j.lines) ? j.lines : (Array.isArray(j.manifest) ? j.manifest : []);
    return lines;
  }

  function cartsFromScene(){
    try {
      // Access carriers from the game scene scope (attached earlier via closures).
      // We can’t access directly; expose a best-effort window hook if present.
      if (window.__WG_getCarriers) return window.__WG_getCarriers();
    } catch(_){}
    // Fallback: ask state snapshot
    return null;
  }

  async function listCarts(){
    const local = cartsFromScene();
    if (Array.isArray(local) && local.length){
      return local.filter(c => c && c.type === 'cart').map(c => ({
        id: c.uid,
        lines: (c.lines||[]),
        loadSizes: Array.isArray(c.loadSizes)?c.loadSizes.slice():[],
      }));
    }
    try {
      const s = await window.WGNet.getState(0);
      const carts = (s && s.carts) || [];
      return carts.map(c => ({ id:c.id, lines:(c.lines||[]), loadSizes:[] }));
    } catch(e){
      console.warn("listCarts fallback failed", e);
      return [];
    }
  }

  // Table: Request list (destination, item_count, requested_weight, Pin)
  function renderRequestsTable(el, requests){
    const tbody = $('#wgpp-requests-body', el) || $('#wgpp-flights-body', el); // fallback to old id if template not updated
    if (!tbody) return;
    tbody.innerHTML = "";
    if (!requests.length){
      tbody.innerHTML = `<tr><td colspan="4" class="wg-muted" style="padding:.6rem">No open requests.</td></tr>`;
      return;
    }
    for (const r of requests){
      const dest   = r.destination || r.airfield_to || r.to || '—';
      const count  = r.item_count  ?? r.lines_count ?? (Array.isArray(r.lines)?r.lines.length:0);
      const weight = r.requested_weight ?? r.total_lb ?? r.weight ?? 0;
      const id     = r.id ?? r.request_id ?? r.req_id;
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${esc(dest)}</td>
        <td class="wg-mono">${esc(count)}</td>
        <td class="wg-mono">${Number(weight||0).toFixed(0)}</td>
        <td style="text-align:right;">
          <button data-id="${esc(id)}" class="btn btn-primary">Pin</button>
        </td>`;
      $('button', tr).onclick = async ()=>{
        try { await pinRequest(id); } catch(e){ showFriendlyError(e, { action:'pin_request' }); }
      };
      tbody.appendChild(tr);
    }
  }

  function renderCarts(el, carts){
    const tbody = $('#wgpp-carts-body', el);
    if (!tbody) return;
    tbody.innerHTML = "";
    if (!carts.length){
      tbody.innerHTML = `<tr><td colspan="3" class="wg-muted" style="padding:.6rem">No carts detected.</td></tr>`;
      return;
    }
    for (const c of carts){
      const linesCount = Array.isArray(c.lines) ? c.lines.length : 0;
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td class="wg-mono">cart:${esc(c.id)}</td>
        <td class="wg-mono">${linesCount}</td>
        <td style="text-align:right;"><button class="btn" data-id="${esc(c.id)}">Use</button></td>`;
      $('button', tr).onclick = async ()=>{
        _state.selectedCart = c.id;
        await checkStatus();
      };
      tbody.appendChild(tr);
    }
  }

  // Manifest table for a pinned request (lines: display_name, size, qty)
  function renderManifestTable(el, lines){
    const tbody = $('#wgpp-manifest-body', el) || $('#wgpp-req-body', el); // fallback to existing section
    if (!tbody) return;
    tbody.innerHTML = "";
    const rows = Array.isArray(lines) ? lines : [];
    if (!rows.length){
      tbody.innerHTML = `<tr><td colspan="3" class="wg-muted" style="padding:.6rem">Pin a request to see its manifest.</td></tr>`;
      return;
    }
    for (const ln of rows){
      const tr = document.createElement('tr');
      tr.innerHTML = `<td>${esc(ln.display_name||ln.name||'item')}</td><td>${formatSize(ln.size||'M')}</td><td class="wg-mono">${esc(ln.qty||0)}</td>`;
      tbody.appendChild(tr);
    }
  }

  function renderValidate(el, diff){
    const tbody = $('#wgpp-val-body', el);
    if (!tbody) return;
    tbody.innerHTML = "";
    const rows = [];
    const add = (kind, arr) => {
      (arr||[]).forEach(x=>{
        rows.push({ kind, size: formatSize(x.size||'M'), qty: Number(x.qty||0)|0 });
      });
    };
    if (diff){
      add('shortage', diff.shortages);
      add('excess', diff.excess);
    }
    if (!rows.length){
      tbody.innerHTML = `<tr><td colspan="3" class="wg-muted" style="padding:.6rem">No differences — looks exact.</td></tr>`;
      return;
    }
    for (const r of rows){
      const tr = document.createElement('tr');
      tr.innerHTML = `<td>${esc(r.kind)}</td><td>${esc(r.size)}</td><td class="wg-mono">${esc(r.qty)}</td>`;
      tbody.appendChild(tr);
    }
  }

  function setStatusPill(el, status){
    const pill = $('#wgpp-status-pill', el);
    if (!pill) return;
    pill.textContent = `status: ${status||'—'}`;
  }

  async function checkStatus(){
    if (!_state.open || !_state.el) return;
    const plane_id = _state.plane_id;
    if (plane_id == null){ _noSelectionModal(); return; }
    try{
      // Prefer locked cart implicitly (server may default as well)
      const locked = (typeof window.__WG_getLockedCartUid === 'function') ? window.__WG_getLockedCartUid() : null;
      const url = `/api/wargame/plane/status?plane_id=${encodeURIComponent(plane_id)}${locked?`&cart_id=${encodeURIComponent(locked)}`:''}`;
      const r = await fetch(url, { credentials:'same-origin' });
      const j = await r.json().catch(()=>({}));
      _state.lastStatus = j || {};
      setStatusPill(_state.el, _state.lastStatus.status || '—');
      // Render required lines if a request is pinned
      const required = (_state.lastStatus.pin && _state.lastStatus.pin.required) || [];
      renderManifestTable(_state.el, required);
      // Render shortages/excess summary
      renderValidate(_state.el, _state.lastStatus.diff || null);
      // Enable/disable buttons
      const ready = String(_state.lastStatus.status||'').toLowerCase() === 'ready';
      const loaded = String(_state.lastStatus.status||'').toLowerCase() === 'loaded';
      const loadBtn = $('#wgpp-load', _state.el);
      const paperBtn = $('#wgpp-paperwork', _state.el);
      if (loadBtn) loadBtn.disabled = !ready;
      if (paperBtn) paperBtn.disabled = !loaded;
    }catch(e){ console.warn("plane/status failed", e); }
  }

  async function loadPlane(){
    const plane_id = _state.plane_id;
    if (plane_id == null){ _noSelectionModal(); return; }
    const locked = (typeof window.__WG_getLockedCartUid === 'function') ? window.__WG_getLockedCartUid() : null;
    const payload = {
      plane_id,
      cart_id: locked || null,
      session_id: (window.WG_SESSION_ID ?? 1),
      player_id:  (window.WG_PLAYER_ID ?? null)
    };
    const r = await fetch('/api/wargame/plane/load', {
      method:'POST', credentials:'same-origin',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify(payload)
    });
    const j = await r.json().catch(()=>({}));
    if (!r.ok){ throw j; }
    await checkStatus();
    // Show paperwork URL (if provided)
    if (j && j.paperwork_url){
      try {
        if (window.WGOverlay && typeof window.WGOverlay.openRampBossPaperwork === 'function'){
          window.WGOverlay.openRampBossPaperwork({ url:j.paperwork_url, planeId: plane_id });
        } else {
          window.openModal && window.openModal({
            title: "Paperwork",
            bodyHTML: `<p><a href="${esc(j.paperwork_url)}" target="_blank" rel="noopener">Open paperwork</a></p>`
          });
        }
      } catch(_){}
    }
  }

  async function paperworkDone(){
    const plane_id = _state.plane_id;
    if (plane_id == null){ _noSelectionModal(); return; }
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
    const reqs = await fetchRequests().catch(()=>[]);
    renderRequestsTable(_state.el, reqs);
    await checkStatus();
  }

  // Provide a single entrypoint used by the scene when near a plane
  function initWargamePanel(rootEl){
    // Hook buttons if template provides them
    const btnLoad = $('#wgpp-load', rootEl);
    const btnPaper = $('#wgpp-paperwork', rootEl);
    const btnRefresh = $('#wgpp-refresh', rootEl);
    if (btnLoad)    btnLoad.onclick    = ()=>loadPlane().catch(e=>showFriendlyError(e,{action:'load'}));
    if (btnPaper)   btnPaper.onclick   = ()=>paperworkDone().catch(e=>showFriendlyError(e,{action:'paperwork'}));
    if (btnRefresh) btnRefresh.onclick = ()=>checkStatus();
  }

  async function open(plane){
    try{
      const tpl = document.getElementById('wg-plane-panel-tpl');
      if (!tpl) { alert("Plane Panel template missing."); return; }
      const el = tpl.content.firstElementChild.cloneNode(true);
      el.id = 'wg-plane-panel';
      // Determine plane id (dataset required)
      const pidInitial = _toId(plane && (plane.id ?? plane.plane_id));
      if (pidInitial != null) el.setAttribute('data-plane-id', String(pidInitial));
      const plane_id = _resolvePlaneId(el);
      if (plane_id == null){ alert("No plane id on panel dataset."); return; }
      // Title
      const _titleId = `Plane ${plane_id}`;
      $('#wgpp-title', el).textContent = `Plane Panel — ${plane.tail || _titleId}`;
      $('#wgpp-close', el).onclick = close;

      mount(el);
      _state = { open:true, plane_id: plane_id, pinnedRequestId:null, selectedCart:null, lastStatus:null, el, _statusTimer:null };
      initWargamePanel(el);

      // Populate left column with requests
      const reqs = await fetchRequests();
      renderRequestsTable(el, reqs);

      // Remove/hide the cart selector section from the template if present.
      // We support a few likely structures; safe no-ops if not found.
      (function hideCartSelector(){
        const elBody = el; // root of panel content
        const cartsTable = elBody.querySelector('#wgpp-carts-body');
        // Try to hide the closest container/section around the carts table
        let section = null;
        if (cartsTable) {
          section = cartsTable.closest('section') || cartsTable.closest('.wg-section') ||
                    cartsTable.closest('table')   || cartsTable.parentElement;
        } else {
          // Alternate markers if your template wraps it differently
          section = elBody.querySelector('#wgpp-carts') ||
                    elBody.querySelector('[data-section="carts"]');
        }
        if (section) {
          // Prefer removing from DOM to avoid any focus traps / tab order
          section.remove();
        }
        // Also ensure the Load button does not depend on manual cart selection
        const loadBtn = elBody.querySelector('#wgpp-load');
        if (loadBtn) loadBtn.disabled = true; // will be enabled by refreshStatus() when ready
      })();

      // Default to the locked (North) cart if available (no UI selection).
      try {
        const locked = (typeof window.__WG_getLockedCartUid === 'function') ? window.__WG_getLockedCartUid() : null;
        if (locked) _state.selectedCart = locked;
      } catch(_) {}

      // Subscribe to realtime plane_* updates while open
      if (window.WGNet && typeof window.WGNet.onEvent==='function'){
        const off = window.WGNet.onEvent('wg:plane_*', async (ev)=>{
          if (ev && ev.data && Number(ev.data.plane_id) === Number(_state.plane_id)) checkStatus();
        });
        _state._off = (typeof off === 'function') ? off : ()=>{};
      }

      // Kick first status check and (optional) tiny polling while focused
      await checkStatus();
      try {
        const T = 3500; // 3.5s while panel visible & tab focused
        _state._statusTimer = window.setInterval(()=>{
          if (!_state.open) return;
          if (document.hidden) return;
          checkStatus();
        }, T);
      } catch(_) {}
    }catch(e){
      console.error(e); alert("Failed to open Plane Panel.");
    }
  }

  function isOpenFor(planeId){ return !!(_state.open && Number(_state.plane_id)===Number(planeId)); }
  async function refresh(){ await checkStatus(); }
  function close(){
    try{ _state._off && _state._off(); }catch(_){}
    if (_state && _state._statusTimer){ try{ clearInterval(_state._statusTimer); }catch(_){} }
    _state = { open:false, plane_id:null, pinnedRequestId:null, selectedCart:null, lastStatus:null, el:null, _statusTimer:null };
    unmount();
  }

  window.WGPlanePanel = { open, close, isOpenFor, refresh };
})();

// ─────────────────────────────────────────────────────────────────────────────
// WGOverlay: arrivals → RampBoss → completion → spawn boxes on Receiving Cart
// ─────────────────────────────────────────────────────────────────────────────
(function(){
  if (window.WGOverlay) return;

  const ROOT_ID = "wg-overlay-root";

  const WGRest = {
    async inboundFlights(){
      const r = await fetch("/api/wargame/inbound_flights", { credentials: "same-origin" });
      const j = await r.json().catch(()=>({}));
      return j.flights || [];
    },
    async getFlight(id){
      const r = await fetch(`/api/wargame/flight/${encodeURIComponent(id)}`, { credentials: "same-origin" });
      const j = await r.json().catch(()=>({}));
      return j.flight || null;
    },
    async getManifest(id){
      const r = await fetch(`/api/wargame/manifest/${encodeURIComponent(id)}`, { credentials: "same-origin" });
      const j = await r.json().catch(()=>({}));
      return j || { lines: [] };
    }
  };

  function ensureRoot(){
    let el = document.getElementById(ROOT_ID);
    if (el) return el;
    el = document.createElement("div");
    el.id = ROOT_ID;
    el.style.cssText = "position:fixed;inset:0;display:none;z-index:99998;background:rgba(0,0,0,.5)";
    document.body.appendChild(el);
    return el;
  }

  let escHandler = null;
  function closeOverlay(){
    const r = ensureRoot();
    r.innerHTML = "";
    r.style.display = "none";
    if (escHandler){
      window.removeEventListener("keydown", escHandler);
      escHandler = null;
    }
  }

  function mount(el){
    const r = ensureRoot();
    r.innerHTML = "";
    r.style.display = "block";
    r.appendChild(el);
    escHandler = ev => { if (ev.key === "Escape") closeOverlay(); };
    window.addEventListener("keydown", escHandler);
  }

  function shell(html){
    const wrap = document.createElement("div");
    wrap.className = "wg-screen";
    wrap.setAttribute("role", "dialog");
    wrap.setAttribute("aria-modal", "true");
    wrap.style.cssText = "position:absolute;inset:5%;background:#0f1115;border:1px solid #2b3440;border-radius:10px;display:flex;flex-direction:column;box-shadow:0 10px 30px rgba(0,0,0,.5)";
    wrap.innerHTML = html;
    return wrap;
  }

  async function showArrivalsPicker(){
    const el = shell(`
      <div class="wg-sticky" style="padding:.75rem 1rem;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid #2b3440">
        <div class="wg-title" style="font:600 16px system-ui;color:#e6eefc">Arrivals — Pick a flight to log</div>
        <button type="button" id="wg-close" class="wg-close" style="padding:.4rem .7rem;border:1px solid #3b4656;border-radius:8px;background:#151a22;color:#dbe7ff;cursor:pointer">Close</button>
      </div>
      <div class="wg-body" style="padding:1rem;overflow:auto;flex:1">
        <table class="wg-table" style="width:100%;border-collapse:collapse">
          <thead>
            <tr style="text-align:left;color:#a9b6c8">
              <th style="padding:.4rem .5rem;border-bottom:1px solid #2b3440">Tail</th>
              <th style="padding:.4rem .5rem;border-bottom:1px solid #2b3440">Pilot</th>
              <th style="padding:.4rem .5rem;border-bottom:1px solid #2b3440">PAX</th>
              <th style="padding:.4rem .5rem;border-bottom:1px solid #2b3440">Origin</th>
              <th style="padding:.4rem .5rem;border-bottom:1px solid #2b3440">ETA</th>
              <th style="padding:.4rem .5rem;border-bottom:1px solid #2b3440"></th>
            </tr>
          </thead>
          <tbody id="wg-arrivals-body"></tbody>
        </table>
      </div>
    `);
    el.querySelector("#wg-close").onclick = closeOverlay;
    mount(el);

    const tbody = el.querySelector("#wg-arrivals-body");
    tbody.innerHTML = `<tr><td colspan="6" style="padding:.8rem;color:#9fb7d9">Loading…</td></tr>`;

    let rows = [];
    try { rows = await WGRest.inboundFlights(); } catch(e){ rows = []; }

    tbody.innerHTML = "";
    if (!rows.length){
      tbody.innerHTML = `<tr><td colspan="6" style="padding:.8rem;color:#9fb7d9">No open inbound flights.</td></tr>`;
      return;
    }
    for (const f of rows){
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td style="padding:.5rem;color:#e6eefc">${f.tail_number || ""}</td>
        <td style="padding:.5rem;color:#cbd9ee">${f.pilot || ""}</td>
        <td style="padding:.5rem;color:#cbd9ee">${f.pax ?? 0}</td>
        <td style="padding:.5rem;color:#cbd9ee">${f.airfield_takeoff || ""}</td>
        <td style="padding:.5rem;color:#cbd9ee">${f.eta || ""}</td>
        <td style="padding:.5rem">
          <button type="button" data-id="${f.id}" style="padding:.35rem .6rem;border:1px solid #3b4656;border-radius:8px;background:#1a2230;color:#dbe7ff;cursor:pointer">Pick</button>
        </td>
      `;
      tr.querySelector("button").onclick = () => openRampBossFor(f);
      tbody.appendChild(tr);
    }
  }

  async function openRampBossFor(flight){
    const el = shell(`
      <div class="wg-sticky" style="padding:.75rem 1rem;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid #2b3440">
        <div class="wg-title" style="font:600 16px system-ui;color:#e6eefc">
          Flight ${String(flight.id)} — ${flight.tail_number || "—"}
          · Pilot: ${flight.pilot || "—"}
          · PAX: ${flight.pax ?? 0}
          · From: ${flight.airfield_takeoff || "—"}
        </div>
        <button type="button" id="wg-close" class="wg-close" style="padding:.4rem .7rem;border:1px solid #3b4656;border-radius:8px;background:#151a22;color:#dbe7ff;cursor:pointer">Close</button>
      </div>
      <div class="wg-body" style="padding:0;overflow:hidden;flex:1;display:flex">
        <iframe id="wg-rb" title="RampBoss" src="/ramp_boss?focus_flight=${encodeURIComponent(flight.id)}" allow="clipboard-write" style="border:0;flex:1;width:100%"></iframe>
      </div>
    `);
    el.querySelector("#wg-close").onclick = closeOverlay;
    mount(el);

    // Fast-path via postMessage (optional if RampBoss implements it)
    const onMsg = async (ev) => {
      if (!ev || !ev.data) return;
      if (ev.data.type === "wargame:flight:complete" && Number(ev.data.flightId) === Number(flight.id)){
        window.removeEventListener("message", onMsg);
        await handleComplete(flight.id);
      }
    };
    window.addEventListener("message", onMsg);

    // Poll completion as a default
    try {
      await pollCompletion(flight.id, 1500, 120); // 1.5s * 120 = 3 minutes
      window.removeEventListener("message", onMsg);
      await handleComplete(flight.id);
    } catch(e){
      // timeout is fine; user can close
    }
  }

  async function pollCompletion(flightId, intervalMs, maxTries){
    let tries = 0;
    while (tries++ < (maxTries || 120)){
      const f = await WGRest.getFlight(flightId).catch(()=>null);
      if (f && f.complete) return true;
      await new Promise(r => setTimeout(r, intervalMs || 1500));
    }
    throw new Error("timeout");
  }

  function groupLines(lines){
    const map = new Map();
    for (const ln of (lines || [])){
      const name = ln.name || "";
      const size = Number(ln.size_lb || 0) || 0;
      const key = `${name}|${size}`;
      if (!map.has(key)) map.set(key, { key, name, size_lb: size, qty: 0 });
      const rec = map.get(key);
      rec.qty += Number(ln.qty || 0) || 0;
    }
    return Array.from(map.values());
  }

  async function handleComplete(flightId){
    const m = await WGRest.getManifest(flightId).catch(()=>({lines:[]}));
    const lines = Array.isArray(m.lines) ? m.lines : [];
    if (lines.length){
      try { window.spawnCartBoxes && window.spawnCartBoxes(lines); } catch(e){}
      try { window.openCartCargoPanel && window.openCartCargoPanel(groupLines(lines)); } catch(e){}
      closeOverlay();
    } else {
      showArrivalsPicker();
    }
  }

  // Public API
  window.WGOverlay = { showArrivalsPicker, openRampBossFor, closeOverlay };

  // Hook to Receiving Cart interaction (call this from your cart click)
  window.onReceivingCartInteract = function(cart){
    try{
      if (cart && typeof cart.hasBoxes === "function" && cart.hasBoxes()){
        const groups = cart.getGroupedCargo ? cart.getGroupedCargo() : null;
        if (groups && window.openCartCargoPanel){ window.openCartCargoPanel(groups); return; }
      }
    }catch(e){}
    showArrivalsPicker();
  };

  // ─────────────────────────────────────────────────────────────
  // §8: RampBoss paperwork modal (open existing /ramp_boss in an iframe)
  // ─────────────────────────────────────────────────────────────
  window.WGOverlay.openRampBossPaperwork = function openRampBossPaperwork(opts){
    const { url, planeId, flightId=null, queueId=null } = (opts||{});
    const root = ensureRoot();
    root.innerHTML = "";
    root.style.display = "block";

    // Build from template if available; otherwise string-build a fallback.
    let wrap = null;
    const tpl = document.getElementById("wg-rampboss-modal-tpl");
    if (tpl && tpl.content && tpl.content.firstElementChild) {
      wrap = tpl.content.firstElementChild.cloneNode(true);
    } else {
      wrap = (function(){
        const div = document.createElement("div");
        div.className = "wg-screen";
        div.setAttribute("role","dialog");
        div.setAttribute("aria-modal","true");
        div.style.cssText = "position:absolute;inset:5%;display:flex;flex-direction:column;background:#0f1115;border:1px solid #2b3440;border-radius:10px;box-shadow:0 10px 30px rgba(0,0,0,.5)";
        div.innerHTML = `
          <div class="wg-sticky" style="display:flex;align-items:center;gap:.75rem;padding:.75rem 1rem;border-bottom:1px solid #2b3440;background:#111;color:#fff;z-index:1;">
            <div class="wg-title" id="wg-rb-title" style="font-weight:600">RampBoss — Paperwork</div>
            <button id="wg-rb-complete" class="wg-close" style="margin-left:auto;background:#2a2a2a;color:#fff;border:1px solid #444;border-radius:.35rem;padding:.35rem .6rem;cursor:pointer">
              Mark Paperwork Complete
            </button>
            <button id="wg-rb-close" class="wg-close" style="background:#2a2a2a;color:#fff;border:1px solid #444;border-radius:.35rem;padding:.35rem .6rem;cursor:pointer">
              Close
            </button>
          </div>
          <div class="wg-body" style="flex:1;min-height:0;overflow:hidden;background:#0f1115;padding:10px;">
            <iframe id="wg-rb-iframe" title="RampBoss" src="about:blank" style="border:1px solid #232833;border-radius:6px;width:100%;height:100%;background:#0b0e13"></iframe>
          </div>`;
        return div;
      })();
    }

    // Wire controls
    const btnClose = wrap.querySelector("#wg-rb-close");
    const btnComplete = wrap.querySelector("#wg-rb-complete");
    const iframe = wrap.querySelector("#wg-rb-iframe");
    const title = wrap.querySelector("#wg-rb-title");

    if (title) {
      const parts = [];
      parts.push("RampBoss — Paperwork");
      if (flightId != null) parts.push(`Flight ${String(flightId)}`);
      title.textContent = parts.join(" · ");
    }
    if (iframe) {
      try { iframe.src = String(url||"/ramp_boss"); } catch(_) { iframe.src="/ramp_boss"; }
    }

    const onClose = ()=>{
      root.innerHTML = "";
      root.style.display = "none";
      try{ window.removeEventListener("keydown", onEsc); }catch(_){}
    };
    const onEsc = (ev)=>{ if (ev.key === "Escape") onClose(); };
    window.addEventListener("keydown", onEsc);

    if (btnClose) btnClose.onclick = onClose;
    if (btnComplete) {
      btnComplete.onclick = async ()=>{
        try{
          btnComplete.disabled = true;
          await window.WGNet.wgPlanePaperworkComplete(planeId, flightId, queueId);
          // Refresh Plane Panel status if it’s open for this plane.
          if (window.WGPlanePanel && typeof window.WGPlanePanel.isOpenFor === 'function' && window.WGPlanePanel.isOpenFor(planeId)) {
            await window.WGPlanePanel.refresh();
          }
          onClose();
        }catch(e){
          btnComplete.disabled = false;
          alert("Paperwork call failed: "+(e&&e.message?e.message:"error"));
        }
      };
    }

    root.appendChild(wrap);
  };

})();
