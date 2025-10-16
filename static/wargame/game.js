(function () {
  // ── Fixed virtual world (16:9), scaled to fit the browser ────────────────
  const VW = 1600;            // virtual width
  const VH = 900;             // virtual height
  const SPEED = 180;          // px/s in world units
  const BORDER = 24;          // fence inset from world edge
  const FENCE_COLOR = 0x3a4453;
  const RED = 0xff3b30;

  const config = {
    type: Phaser.AUTO,
    parent: "game-root",
    backgroundColor: "#0f1115",
    // Keep a stable world; Phaser scales it to the available area.
    width: VW,
    height: VH,
    scale: { mode: Phaser.Scale.FIT, autoCenter: Phaser.Scale.CENTER_BOTH },
    physics: { default: "arcade", arcade: { debug: false } },
    scene: { preload, create, update }
  };

  let game = new Phaser.Game(config);

  let player, nameText, keyW, keyA, keyS, keyD;
  let fenceRect;
  let debugText;

  function preload() {
    // no assets needed for MVP
  }

  function create() {
    // Fixed camera & physics bounds (do not change on window resize)
    this.cameras.main.setBounds(0, 0, VW, VH);
    this.physics.world.setBounds(
      BORDER, BORDER,
      VW - BORDER * 2, VH - BORDER * 2,
      true, true, true, true
    );

    // Visual fence in world coordinates
    drawFence.call(this);

    // Player: red square 24x24 → texture from graphics
    const size = 24;
    const g = this.add.graphics();
    g.fillStyle(RED, 1).fillRect(0, 0, size, size);
    g.generateTexture("player-red", size, size);
    g.destroy();

    player = this.physics.add.sprite(VW / 2, VH / 2, "player-red");
    player.setCollideWorldBounds(true);   // collide with physics world bounds (inner fence)

    // Name label
    const name = (window.PLAYER_NAME || "Guest") + "";
    nameText = this.add.text(player.x, player.y + size/2 + 12, name, { fontSize: "14px", color: "#e6e6e6" })
                       .setOrigin(0.5, 0.0);

    // Input (WASD)
    keyW = this.input.keyboard.addKey(Phaser.Input.Keyboard.KeyCodes.W);
    keyA = this.input.keyboard.addKey(Phaser.Input.Keyboard.KeyCodes.A);
    keyS = this.input.keyboard.addKey(Phaser.Input.Keyboard.KeyCodes.S);
    keyD = this.input.keyboard.addKey(Phaser.Input.Keyboard.KeyCodes.D);

    // Debug overlay (pos + vel)
    debugText = this.add.text(12, 12, "", { fontSize: "12px", color: "#9fb7d9" }).setDepth(10);

  } // ← close create()

  function drawFence() {
    if (fenceRect) fenceRect.destroy();
    fenceRect = this.add.graphics();
    fenceRect.lineStyle(3, FENCE_COLOR, 1);
    fenceRect.strokeRect(BORDER, BORDER, VW - BORDER * 2, VH - BORDER * 2);
  }

  function update(_, delta) {
    // 8-way WASD (diagonals normalized)
    let vx = 0, vy = 0;
    if (keyA.isDown) vx -= 1;
    if (keyD.isDown) vx += 1;
    if (keyW.isDown) vy -= 1;
    if (keyS.isDown) vy += 1;
    if (vx !== 0 && vy !== 0) { vx *= Math.SQRT1_2; vy *= Math.SQRT1_2; }

    player.setVelocity(vx * SPEED, vy * SPEED);

    // Keep label under the square
    nameText.setPosition(player.x, player.y + 24);

    // Debug HUD
    if (debugText) {
      const bv = player.body && player.body.velocity ? player.body.velocity : {x: vx*SPEED, y: vy*SPEED};
      debugText.setText(
        `x:${player.x.toFixed(1)}  y:${player.y.toFixed(1)}  ` +
        `vx:${bv.x.toFixed(0)}  vy:${bv.y.toFixed(0)}`
      );
    }
  }
})();
