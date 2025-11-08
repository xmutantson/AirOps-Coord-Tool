// static/wargame/assetkit.js
(function () {
  // Serve from /static so requests aren’t relative to /wargame/play
  const ROOT = '/static/wargame/assets';
  const globalObj =
    (typeof window !== 'undefined') ? window :
    ((typeof global !== 'undefined') ? global : {});

  const manifest = {
    background: `${ROOT}/backgrounds/base_1600x900.png`,
    player: { png: `${ROOT}/player/player.png`, json: `${ROOT}/player/player.json` },
    props: {
      boxes: { png: `${ROOT}/props/boxes.png`, json: `${ROOT}/props/boxes.json` },
      cart:  { png: `${ROOT}/props/cart.png`,  json: `${ROOT}/props/cart.json`  },
      truck: { png: `${ROOT}/props/truck.png`, json: `${ROOT}/props/truck.json` },
      // This atlas is optional; queue only if both fields are present.
      plane: { png: `${ROOT}/props/plane.png`, json: `${ROOT}/props/plane.json` }
    }
  };

  function queueOptional(scene) {
    if (!scene || !scene.load) return;
    const L = scene.load;
    L.image('bg:base', manifest.background);
    L.atlas('atlas:player', manifest.player.png, manifest.player.json);
    L.atlas('atlas:boxes',  manifest.props.boxes.png, manifest.props.boxes.json);
    L.atlas('atlas:cart',   manifest.props.cart.png,  manifest.props.cart.json);
    L.atlas('atlas:truck',  manifest.props.truck.png, manifest.props.truck.json);
    if (manifest.props.plane && manifest.props.plane.png && manifest.props.plane.json) {
      L.atlas('atlas:plane', manifest.props.plane.png, manifest.props.plane.json);
    }
  }

  function ensurePlaceholders(scene) {
    if (!scene || !scene.textures || !scene.add) return;
    const tex = scene.textures;

    const makeRect = (key, w, h, fill, stroke = 0x000000) => {
      if (tex.exists(key)) return;
      const g = scene.add.graphics();
      g.fillStyle(fill, 1).fillRect(0, 0, w, h);
      g.lineStyle(2, stroke, 1).strokeRect(1, 1, w - 2, h - 2);
      g.generateTexture(key, w, h);
      g.destroy();
    };

    // Boxes
    makeRect('ph:box-small',  22, 22, 0xf6cf65);
    makeRect('ph:box-medium', 28, 28, 0xe9a948);
    makeRect('ph:box-large',  34, 34, 0xcc7f2d);
    makeRect('ph:box-xl',     42, 42, 0xb86b21);

    // Players (8 directions + fallback)
    const makePlayerDir = (key, tri) => {
      if (tex.exists(key)) return;
      const w = 48, h = 64;
      const g = scene.add.graphics();
      g.fillStyle(0xff3b30, 1).fillRect(0, 0, w, h);
      g.lineStyle(2, 0x000000, 0.8).strokeRect(1, 1, w - 2, h - 2);
      g.fillStyle(0xffffff, 1);
      g.fillTriangle(tri[0].x, tri[0].y, tri[1].x, tri[1].y, tri[2].x, tri[2].y);
      g.generateTexture(key, w, h);
      g.destroy();
    };
    makePlayerDir('ph:player-N',  [ {x:24,y:8},  {x:14,y:26}, {x:34,y:26} ]);
    makePlayerDir('ph:player-NE', [ {x:38,y:10}, {x:21,y:10}, {x:38,y:27} ]);
    makePlayerDir('ph:player-E',  [ {x:42,y:32}, {x:26,y:20}, {x:26,y:44} ]);
    makePlayerDir('ph:player-SE', [ {x:38,y:54}, {x:21,y:54}, {x:38,y:37} ]);
    makePlayerDir('ph:player-S',  [ {x:24,y:58}, {x:14,y:34}, {x:34,y:34} ]);
    makePlayerDir('ph:player-SW', [ {x:10,y:54}, {x:10,y:37}, {x:27,y:54} ]);
    makePlayerDir('ph:player-W',  [ {x:6,y:32},  {x:22,y:20}, {x:22,y:44} ]);
    makePlayerDir('ph:player-NW', [ {x:10,y:10}, {x:27,y:10}, {x:10,y:27} ]);

    if (!tex.exists('ph:player')) {
      const w = 48, h = 64;
      const g = scene.add.graphics();
      g.fillStyle(0xff3b30, 1).fillRect(0, 0, w, h);
      g.lineStyle(2, 0x000000, 0.8).strokeRect(1, 1, w - 2, h - 2);
      g.fillStyle(0xffffff, 1);
      g.fillTriangle(24, 58, 14, 34, 34, 34);
      g.generateTexture('ph:player', w, h);
      g.destroy();
    }

    // Carts
    const makeCart = (key, w, h) => {
      if (tex.exists(key)) return;
      const g = scene.add.graphics();
      g.fillStyle(0x6aa2d9, 1).fillRoundedRect(0, 0, w, h, 4);
      g.lineStyle(2, 0x1e3a5f, 1).strokeRoundedRect(1, 1, w - 2, h - 2, 4);
      g.fillStyle(0x333333, 1).fillCircle(8, h - 4, 3).fillCircle(w - 8, h - 4, 3);
      g.generateTexture(key, w, h);
      g.destroy();
    };
    makeCart('ph:cart-left',  88, 48);
    makeCart('ph:cart-right', 88, 48); // added to complete the set
    makeCart('ph:cart-up',    48, 88);
    makeCart('ph:cart-down',  48, 88);

    // Trucks
    const makeTruck = (key, w, h) => {
      if (tex.exists(key)) return;
      const g = scene.add.graphics();
      g.fillStyle(0x708090, 1).fillRect(0, 0, w, h);
      g.fillStyle(0x36454f, 1).fillRect(2, 2, w - 4, h - 18);
      g.fillStyle(0x999999, 1).fillRect(2, h - 16, w - 4, 14);
      g.generateTexture(key, w, h);
      g.destroy();
    };
    makeTruck('ph:truck-up',    64, 128);
    makeTruck('ph:truck-down',  64, 128);
    makeTruck('ph:truck-left',  128, 64);
    makeTruck('ph:truck-right', 128, 64);

    // Plane placeholder (legacy single)
    const makePlaneLegacy = (key, w, h) => {
      if (tex.exists(key)) return;
      const g = scene.add.graphics();
      g.fillStyle(0xcfd8dc, 1).fillRect(0, 0, w, h);
      g.fillStyle(0x90a4ae, 1).fillRect(w * 0.4, 0, w * 0.2, h);
      g.generateTexture(key, w, h);
      g.destroy();
    };
    makePlaneLegacy('ph:plane-up',    60, 120);
    makePlaneLegacy('ph:plane-down',  60, 120);
    makePlaneLegacy('ph:plane-left',  140, 64);
    makePlaneLegacy('ph:plane-right', 140, 64);

    // Example art with plane BODY and WINGS as separate textures.
    // Keep sizes identical so they stack cleanly with the same origin.
    const makePlaneBody = (key, w, h) => {
      if (tex.exists(key)) return;
      const g = scene.add.graphics();
      g.fillStyle(0xd9e3e8, 1).fillRoundedRect(0, 0, w, h, 10);            // fuselage
      g.fillStyle(0xa7b5be, 1).fillRect(w * 0.40, 4, w * 0.20, h - 8);     // center stripe
      g.fillStyle(0x5c7c8a, 1).fillRoundedRect(6, h * 0.28, 22, h * 0.44, 6); // cockpit
      g.fillStyle(0xa7b5be, 1).fillRoundedRect(w - 18, h * 0.20, 12, h * 0.60, 4); // tail
      g.lineStyle(2, 0x6f7f89, 1).strokeRoundedRect(1, 1, w - 2, h - 2, 10);
      g.generateTexture(key, w, h);
      g.destroy();
    };
    const makePlaneWings = (key, w, h) => {
      if (tex.exists(key)) return;
      const g = scene.add.graphics();
      const wingH = Math.max(18, Math.floor(h * 0.38));
      g.fillStyle(0xbfcad0, 1).fillRoundedRect(0, h * 0.31, w, wingH, 6);     // slab
      g.fillStyle(0x9fb0ba, 1).fillRoundedRect(4, h * 0.31 + 4, w - 8, wingH - 8, 5); // leading edge
      g.lineStyle(2, 0x81929c, 0.8);                                          // flap hints
      const flapY = h * 0.31 + wingH * 0.5;
      for (let i = 1; i < 5; i++) g.lineBetween(i * (w / 5), flapY - 8, i * (w / 5), flapY + 8);
      g.generateTexture(key, w, h);
      g.destroy();
    };
    // One set (flip X in-game for facing left)
    makePlaneBody('ph:plane-body', 140, 64);
    makePlaneWings('ph:plane-wings', 140, 64); // matches body size for clean overlay
  }

  // Exports (safe in non-browser contexts; always include manifest)
  if (typeof window !== 'undefined') {
    window.AssetKit = Object.assign(window.AssetKit || {}, { manifest, queueOptional, ensurePlaceholders });
  }
  globalObj.AssetKit = Object.assign(globalObj.AssetKit || {}, { manifest, queueOptional, ensurePlaceholders });
})();
