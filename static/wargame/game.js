// static/wargame/game.js
(function () {
  const DEFAULT_ITEM_KEY = "box";
  const BIN_TO_HUMAN = { S: "small", M: "medium", L: "large", XL: "xl" };
  const HUMAN_TO_BIN = { small: "S", medium: "M", large: "L", xl: "XL" };

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

    // stockpile viewmodel
    const stockpile={ label:null, terminal:null, terminalHitScale:2, fenceGfx:null, wallGroup:null, walls:[], rect:{...STOCKPILE_RECT}, yBase:STOCKPILE_RECT.bottom, geom:{}, bins:{small:[],medium:[],large:[],xl:[]}, hidden:{small:0,medium:0,large:0,xl:0}, badges:{}, sprites:[] };

    // carriers
    const carriers=[], carriersByUid=new Map(); const CART='cart', TRUCK='truck';

    // planes (bodies + wings)
    const planes=[]; // {body, wingsBack, wingsFront, facing}
    // plane obstacles (static physics rects)
    let planeObstacleGroup, planeObstacleCollider, planeObstacles = [];

    // remotes
    const remotes=new Map(); let remoteTimer=null, remoteRenderTimer=null; const clock=makeClockSync();

    // mp
    const netAvailable=!!window.WGNet; let netJoined=false; let myPlayerId=null; let seenClaimId=0;

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

    // ---------- name gate ----------
    function mountNameGate(){
      const gate=document.getElementById('wg-name-gate'), input=document.getElementById('wg-name-input'), btn=document.getElementById('wg-name-commit');
      if(!gate||!input||!btn){ enableControls(); return; }
      nameGate=gate; gate.style.display='flex'; input.focus();
      btn.addEventListener('click', function(){
        const v=(input.value||"").trim(); if (!v) { input.focus(); return; }
        pendingName=v.slice(0,24); gate.style.display='none'; startNetworking();
      });
      input.addEventListener('keydown', function(e){ if(e.key==='Enter') btn.click(); e.stopPropagation(); });
    }
    function startNetworking(){
      if(!netAvailable){ enableControls(); return; }
      try{
        WGNet.init({ sessionId:1, base:"" });
        WGNet.join(pendingName).then(async info=>{
          myPlayerId = info && info.player_id; netJoined = true; window.PLAYER_NAME = pendingName;
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
      hudText  = this.add.text(12,12,"",{fontSize:"12px", color:"#9fb7d9"}).setDepth(DEPTH.ui+100).setScrollFactor(0);

      // physics group & collider (for props) + plane obstacle group
      propsGroup=this.physics.add.staticGroup(); colliderRef=this.physics.add.collider(player, propsGroup);
      planeObstacleGroup = this.physics.add.staticGroup();
      planeObstacleCollider = this.physics.add.collider(player, planeObstacleGroup);

      // hint + modal
      buildHint(); wireModal();

      // name gate → networking
      mountNameGate();
    }

    function update(){
      if(!keyW) return;
      let vx=0, vy=0; if(keyA.isDown) vx-=1; if(keyD.isDown) vx+=1; if(keyW.isDown) vy-=1; if(keyS.isDown) vy+=1; if(vx&&vy){ vx*=Math.SQRT1_2; vy*=Math.SQRT1_2; }
      player.setVelocity(vx*SPEED, vy*SPEED);

      if(vx||vy){ lastDir=vecToDir(vx,vy); const k='ph:player-'+lastDir; if(scene.textures.exists(k)){ const px=player.x,py=player.y; player.setTexture(k).setDisplaySize(48,64).setOrigin(0.5,1.0).setPosition(px,py);} }
      nameText.setPosition(player.x, player.y+8);

      if (carrying){ const off=holdOffsetPx(heldSize); heldBox.setPosition(player.x, player.y-off); const pDepth=(player.y||0)+(player.__yExtra||0); heldBox.setDepth(Math.max(DEPTH.ui+1, pDepth+1)); }

      if (hudText && player && player.body){ const v=player.body.velocity||{x:0,y:0}; hudText.setText(`x:${player.x.toFixed(1)}  y:${player.y.toFixed(1)}  vx:${v.x.toFixed(0)}  vy:${v.y.toFixed(0)}`); }

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
    function wireModal(){ modalEl=document.getElementById('wg-modal'); modalMsgEl=document.getElementById('wg-modal-msg'); modalBodyEl=document.getElementById('wg-modal-body'); modalOK=document.getElementById('wg-modal-ok'); modalCancel=document.getElementById('wg-modal-cancel'); }
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
      base.setOrigin(0.5,1.0).refreshBody(); markForYSort(base,-5);
      const entry={ uid, type, base, loadSizes:[], loadSprites:[], facing }; carriers.push(entry); carriersByUid.set(uid, entry); return entry;
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
    function toggleCarry(force){ carrying=(typeof force==='boolean')?force:!carrying; heldBox.setVisible(carrying); if(carrying){ const off=holdOffsetPx(heldSize); heldBox.setPosition(player.x, player.y-off); const pDepth=(player.y||0)+(player.__yExtra||0); heldBox.setDepth(Math.max(DEPTH.ui+1, pDepth+1)); } }
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
        if(carrying){ activeMode='depositCarrier'; activeTarget=nearCarrier; hintContainer.setVisible(true).setPosition(player.x, player.y-PLAYER_H-6); return; }
        const cnt=countBySize(nearCarrier.loadSizes), any=cnt.small+cnt.medium+cnt.large+cnt.xl;
        if(any>0){ activeMode='pickupCarrier'; activeTarget=nearCarrier; hintContainer.setVisible(true).setPosition(player.x, player.y-PLAYER_H-6); return; }
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
      planeObstacles.push(rect);
    }

    function spawnPlaneSprites(pose) {
      const x=(pose&&typeof pose.x==='number')?pose.x: (VW/2-100);
      const y=(pose&&typeof pose.y==='number')?pose.y: (VH/2-100);
      const facing=(pose&&pose.facing)||'right';

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
      addPlaneCargoObstacleForSprite(body, facing);

      planes.push({ body, wingsBack, wingsFront, facing });
    }

    // ---------- bootstrap ----------
    async function bootstrapFromServer(){
      let nextClaimId=0, initialCarts=[];
      try{ const s0=await WGNet.getState(0); nextClaimId=(s0&&s0.next_claim_id)||0; initialCarts=(s0&&s0.carts)||[]; }catch(e){ console.warn("initial state failed", e); }
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
      planeObstacles.length = 0;
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

    function layoutTrucksFromServer(trucks){
      const inbound=(trucks&&trucks.inbound)||[], outbound=(trucks&&trucks.outbound)||[];
      const rightX=1600-BORDER-220, baseY=900/2, gapY=180;

      inbound.forEach((t,i)=>{
        const hasPose=t && t.pose && typeof t.pose.x==='number' && typeof t.pose.y==='number';
        const x=hasPose?t.pose.x:rightX, y=hasPose?t.pose.y:(baseY + (i - Math.floor(inbound.length/2))*gapY);
        const facing=(t && t.pose && t.pose.facing) || 'right';
        const entry=spawnCarrier(TRUCK,{ uid:t.truck_id, facing, x, y }); carriersByUid.set(t.truck_id, entry);
      });
      const outBaseY = baseY + gapY * (Math.max(inbound.length,1)/2 + 0.7);
      outbound.forEach((t,i)=>{
        const hasPose=t && t.pose && typeof t.pose.x==='number' && typeof t.pose.y==='number';
        const x=hasPose?t.pose.x:(rightX-40), y=hasPose?t.pose.y:(outBaseY + i*gapY);
        const facing=(t && t.pose && t.pose.facing) || 'right';
        const entry=spawnCarrier(TRUCK,{ uid:t.truck_id, facing, x, y }); carriersByUid.set(t.truck_id, entry);
      });
    }
    function seedTruckLoadsFromServer(trucks){
      const all=[]; (trucks&&trucks.inbound||[]).forEach(t=>all.push(t)); (trucks&&trucks.outbound||[]).forEach(t=>all.push(t));
      all.forEach(t=>{
        const entry=carriersByUid.get(t.truck_id); if(!entry) return;
        const perBin={S:0,M:0,L:0,XL:0}; const man=t.manifest||{};
        Object.keys(man).forEach(k=>{ const b=man[k]||{}; perBin.S+=b.S||0; perBin.M+=b.M||0; perBin.L+=b.L||0; perBin.XL+=b.XL||0; });
        entry.loadSizes=[]; Object.keys(perBin).forEach(bin=>{ const human=BIN_TO_HUMAN[bin]; for(let i=0;i<perBin[bin];i++) entry.loadSizes.push(human); }); rebuildCarrier(entry);
      });
    }
    function layoutCartsFromServer(carts){
      (carts||[]).forEach(c=>{
        const pose=c&&c.pose||{}; const x=(typeof pose.x==='number')?pose.x:(VW/2-200); const y=(typeof pose.y==='number')?pose.y:(VH/2); const facing=pose.facing||'left';
        const uid=c.id; const entry=spawnCarrier(CART,{ uid, facing, x, y }); carriersByUid.set(uid, entry);
      });
    }
    function seedCartLoadsFromServer(carts){
      (carts||[]).forEach(c=>{
        const entry=carriersByUid.get(c.id); if(!entry) return;
        const perBin={S:0,M:0,L:0,XL:0}; const cont=c.contents||{};
        Object.keys(cont).forEach(k=>{ const b=cont[k]||{}; perBin.S+=b.S||0; perBin.M+=b.M||0; perBin.L+=b.L||0; perBin.XL+=b.XL||0; });
        entry.loadSizes=[]; Object.keys(perBin).forEach(bin=>{ const human=BIN_TO_HUMAN[bin]; for(let i=0;i<perBin[bin];i++) entry.loadSizes.push(human); }); rebuildCarrier(entry);
      });
    }
    function seedStockpileFromServer(stock){
      const bins=(stock&&stock.bins)||{}; const total={S:0,M:0,L:0,XL:0};
      Object.keys(bins).forEach(item=>{ const b=bins[item]||{}; total.S+=b.S||0; total.M+=b.M||0; total.L+=b.L||0; total.XL+=b.XL||0; });
      for(let i=0;i<total.S;i++) spawnStockpileBox('small');
      for(let i=0;i<total.M;i++) spawnStockpileBox('medium');
      for(let i=0;i<total.L;i++) spawnStockpileBox('large');
      for(let i=0;i<total.XL;i++) spawnStockpileBox('xl');
    }
    function renderPlanes(list){
      (list||[]).forEach(p=>{ spawnPlaneSprites(p && p.pose || {}); });
    }

    // ---------- polling ----------
    function schedulePoll(){
      if (remoteTimer) { try{ remoteTimer.remove(false);}catch(e){} remoteTimer=null; }
      remoteTimer = scene.time.addEvent({ delay:POLL_MS, loop:true, callback:function(){
        WGNet.getState(seenClaimId).then(state=>{
          const serverTime=(state && typeof state.server_time==='number') ? state.server_time : null; if(serverTime) clock.tick(serverTime);
          const players=(state&&state.players)||[]; ingestRemotePlayers(players, serverTime); cleanupMissingRemotes(players);
          const claims=(state&&state.claims)||[]; applyClaimsBatched(claims);
        }).catch(()=>{});
      }});
      if (remoteRenderTimer) { try{ remoteRenderTimer.remove(false);}catch(e){} }
      remoteRenderTimer = scene.time.addEvent({ delay:1000/REMOTE_RENDER_HZ, loop:true, callback: renderRemotesSmoothed });
    }

    function applyClaimsBatched(all){
      if(!Array.isArray(all)||!all.length) return;
      const fresh=all.filter(c=> (c.id||0)>seenClaimId); if(!fresh.length) return;

      const pileDelta={ add:{small:0,medium:0,large:0,xl:0}, remove:{small:0,medium:0,large:0,xl:0} };
      const carrierDelta=new Map(); function ensure(uid){ if(!carrierDelta.has(uid)) carrierDelta.set(uid,{add:{},remove:{}}); return carrierDelta.get(uid); }

      fresh.forEach(c=>{
        if (consumeMatchingPending(c)) {
          if (typeof c.id==='number' && c.id>seenClaimId) seenClaimId=c.id;
          return;
        }

        const act=(c.action||'').toLowerCase(); const sizeHuman=binToHuman(c.size||'medium');
        if (act==='stockpile_add'){ pileDelta.add[sizeHuman]=(pileDelta.add[sizeHuman]||0)+1; }
        else if (act==='stockpile_remove'){ pileDelta.remove[sizeHuman]=(pileDelta.remove[sizeHuman]||0)+1; }
        else if (act==='carrier_add' || act==='carrier_remove'){
          const uid=c.carrier_uid; const b=ensure(uid);
          if (act==='carrier_add') b.add[sizeHuman]=(b.add[sizeHuman]||0)+1; else b.remove[sizeHuman]=(b.remove[sizeHuman]||0)+1;
        }
        if (typeof c.id==='number' && c.id>seenClaimId) seenClaimId=c.id;
      });

      ['small','medium','large','xl'].forEach(sz=>{ const net=(pileDelta.add[sz]||0)-(pileDelta.remove[sz]||0);
        if(net>0) for(let i=0;i<net;i++) spawnStockpileBox(sz);
        else if(net<0) for(let j=0;j<(-net);j++) removeOneFromStockpile(sz);
      });

      carrierDelta.forEach((d,uid)=>{
        let e = carriersByUid.get(uid);
        if (!e && typeof uid === 'string' && /^\d+$/.test(uid)) e = carriersByUid.get(`cart:${uid}`);
        if (e) applyCarrierDelta(e, d);
      });
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

    // ---------- interactions ----------
    async function attemptInteract(){
      if (activeMode==='depositTerminal' && carrying){
        const pend = addPending({ action:'stockpile_add', size:heldSize });
        openConfirm(`Deposit 1 <strong>${heldSize.toUpperCase()}</strong> into STOCKPILE?`, async ()=>{
          spawnStockpileBox(heldSize);
          toggleCarry(false);
          hintContainer.setVisible(false);
          try {
            await _pendingClaim;
            const itemKey = heldItemKey || DEFAULT_ITEM_KEY;
            await postClaimSerial({ action:'stockpile_add', item_key:itemKey, size: heldSize });
            heldItemKey = null;
          } catch (e) {
            cancelPending(pend);
            removeOneFromStockpile(heldSize);
            setHeldBoxTexture(heldSize);
            toggleCarry(true);
            try { await bootstrapFromServer(); } catch(_) {}
          }
        }, ()=>cancelPending(pend));
        return;
      }

      if (activeMode==='depositCarrier' && carrying && activeTarget){
        const entry=activeTarget;
        const pend = addPending({ action:'carrier_add', size:heldSize, carrier_type:entry.type, carrier_uid:entry.uid });
        applyCarrierDelta(entry, { add:{ [heldSize]:1 }, remove:{} });
        toggleCarry(false);
        hintContainer.setVisible(false);
        try {
          await _pendingClaim;
          const itemKey = heldItemKey || DEFAULT_ITEM_KEY;
          await postClaimSerial({ action:'carrier_add', carrier_type:entry.type, carrier_index:-1, carrier_uid:entry.uid, item_key:itemKey, size:heldSize });
          heldItemKey = null;
        } catch (e) {
          cancelPending(pend);
          applyCarrierDelta(entry, { add:{}, remove:{ [heldSize]:1 } });
          setHeldBoxTexture(heldSize);
          toggleCarry(true);
          try { await bootstrapFromServer(); } catch(_) {}
        }
        return;
      }

      if (activeMode==='pickupCarrier' && activeTarget){
        const entry=activeTarget; const counts=countBySize(entry.loadSizes), opts=sizeOptionsFromCounts(counts), def=(opts[0]&&opts[0].value)||'medium';
        openSelect('Pick up from '+entry.type.toUpperCase(), opts, def, async (val)=>{
          let resolved={ item_key:DEFAULT_ITEM_KEY, carrier_uid: entry.uid };
          if (entry.type===TRUCK) resolved=await resolveTruckSkuForSizeByUid(entry.uid, val);

          const pend = addPending({ action:'carrier_remove', size:val, carrier_type:entry.type, carrier_uid:resolved.carrier_uid });
          applyCarrierDelta(entry, { add:{}, remove:{ [val]:1 } });
          setHeldBoxTexture(val);
          toggleCarry(true);

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
        const countsS={ small:stockpile.bins.small.length+(stockpile.hidden.small||0), medium:stockpile.bins.medium.length+(stockpile.hidden.medium||0), large:stockpile.bins.large.length+(stockpile.hidden.large||0), xl:stockpile.bins.xl.length+(stockpile.hidden.xl||0) };
        const opts=sizeOptionsFromCounts(countsS), defS=(opts[0]&&opts[0].value)||'medium';
        openSelect('Pick up from STOCKPILE', opts, defS, async (val)=>{
          if(!removeOneFromStockpile(val)) return;
          const pend = addPending({ action:'stockpile_remove', size:val });
          setHeldBoxTexture(val);
          toggleCarry(true);

          try {
            const itemKey = await resolveStockpileSkuForSize(val);
            await postClaimSerial({ action:'stockpile_remove', item_key:itemKey, size:val });
            heldItemKey = itemKey;
          } catch (e) {
            cancelPending(pend);
            toggleCarry(false);
            spawnStockpileBox(val);
            heldItemKey = null;
            try { await bootstrapFromServer(); } catch(_) {}
          }
        });
        return;
      }
    }

    // ---------- start phaser ----------
    try{ new Phaser.Game(config); } catch(e){ console.error("Phaser failed", e); showFatal("Phaser failed to start — see console."); }
  }
})();
