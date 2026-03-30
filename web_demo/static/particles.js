/**
 * QuantumShield — Particle Network Background
 * High-performance canvas particle system with mouse interaction.
 * Theme-aware: reacts to [data-theme="dark"] on <html>.
 * Usage: <canvas id="particleCanvas" data-accent="kemtls|tls"></canvas>
 */
(function () {
  'use strict';

  /* ── Color Palettes ────────────────────────────────── */
  var PALETTES = {
    kemtls: {
      light: { particle: [37, 99, 235], line: [37, 99, 235], mouse: [6, 182, 212] },
      dark:  { particle: [96, 165, 250], line: [59, 130, 246], mouse: [34, 211, 238] },
    },
    tls: {
      light: { particle: [79, 70, 229], line: [79, 70, 229], mouse: [124, 58, 237] },
      dark:  { particle: [129, 140, 248], line: [99, 102, 241], mouse: [167, 139, 250] },
    },
  };

  /* ── Particle Class ────────────────────────────────── */
  function Particle(w, h) {
    this.reset(w, h);
  }

  Particle.prototype.reset = function (w, h) {
    var speed = Math.random() * 0.35 + 0.08;
    var angle = Math.random() * Math.PI * 2;
    this.x   = Math.random() * w;
    this.y   = Math.random() * h;
    this.vx  = Math.cos(angle) * speed;
    this.vy  = Math.sin(angle) * speed;
    this.r   = Math.random() * 1.8 + 0.8;
    this.op  = Math.random() * 0.4 + 0.4;   // base opacity
    this.opD = (Math.random() > 0.5 ? 1 : -1) * (Math.random() * 0.006 + 0.003);
  };

  Particle.prototype.update = function (w, h) {
    this.x += this.vx;
    this.y += this.vy;

    // Soft wrap — teleport opposite edge with slight randomness
    if (this.x < -10) this.x = w + 10;
    if (this.x > w + 10) this.x = -10;
    if (this.y < -10) this.y = h + 10;
    if (this.y > h + 10) this.y = -10;

    // Pulse opacity
    this.op += this.opD;
    if (this.op > 0.85 || this.op < 0.25) this.opD *= -1;
  };

  /* ── Engine ────────────────────────────────────────── */
  function Engine(canvas) {
    this.canvas  = canvas;
    this.ctx     = canvas.getContext('2d');
    this.accent  = (canvas.dataset.accent || 'kemtls');
    this.isDark  = false;
    this.mouse   = { x: -9999, y: -9999 };
    this.raf     = null;
    this.particles = [];

    this._syncTheme();
    this._resize();
    this._spawnParticles();
    this._bindEvents();
    this._tick();
  }

  Engine.prototype._syncTheme = function () {
    this.isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    var palette = PALETTES[this.accent] || PALETTES.kemtls;
    this.pal = this.isDark ? palette.dark : palette.light;
  };

  Engine.prototype._resize = function () {
    this.W = this.canvas.width  = window.innerWidth;
    this.H = this.canvas.height = window.innerHeight;
  };

  Engine.prototype._spawnParticles = function () {
    // Density: ~1 particle per 10k px², capped between 50 and 130
    var count = Math.max(50, Math.min(130, Math.floor((this.W * this.H) / 10000)));
    this.particles = [];
    for (var i = 0; i < count; i++) {
      this.particles.push(new Particle(this.W, this.H));
    }
  };

  Engine.prototype._bindEvents = function () {
    var self = this;

    window.addEventListener('resize', function () {
      self._resize();
      self._spawnParticles();
    });

    // Track mouse on window so canvas can have pointer-events:none
    window.addEventListener('mousemove', function (e) {
      self.mouse.x = e.clientX;
      self.mouse.y = e.clientY;
    });
    window.addEventListener('mouseleave', function () {
      self.mouse.x = -9999;
      self.mouse.y = -9999;
    });
    // Touch support
    window.addEventListener('touchmove', function (e) {
      if (e.touches.length) {
        self.mouse.x = e.touches[0].clientX;
        self.mouse.y = e.touches[0].clientY;
      }
    }, { passive: true });

    // React to theme toggle instantly
    var obs = new MutationObserver(function () { self._syncTheme(); });
    obs.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
  };

  Engine.prototype._rgba = function (rgb, a) {
    return 'rgba(' + rgb[0] + ',' + rgb[1] + ',' + rgb[2] + ',' + a.toFixed(3) + ')';
  };

  Engine.prototype._tick = function () {
    var self    = this;
    var ctx     = this.ctx;
    var W       = this.W;
    var H       = this.H;
    var p       = this.particles;
    var n       = p.length;
    var pal     = this.pal;
    var mx      = this.mouse.x;
    var my      = this.mouse.y;

    var MAX_DIST   = 140;   // max distance for particle–particle line
    var MOUSE_DIST = 200;   // max distance for particle–mouse line
    var MAX_D2     = MAX_DIST * MAX_DIST;
    var MOUSE_D2   = MOUSE_DIST * MOUSE_DIST;

    ctx.clearRect(0, 0, W, H);

    // ── Draw lines first (behind dots) ──────────────────
    for (var i = 0; i < n; i++) {
      var pi = p[i];
      pi.update(W, H);

      // Particle–particle lines
      for (var j = i + 1; j < n; j++) {
        var pj  = p[j];
        var dx  = pi.x - pj.x;
        var dy  = pi.y - pj.y;
        var d2  = dx * dx + dy * dy;
        if (d2 < MAX_D2) {
          var t   = 1 - Math.sqrt(d2) / MAX_DIST;   // 0→1 as dist→0
          var lw  = t * 1.4;
          var la  = t * 0.55 * ((pi.op + pj.op) / 2);
          ctx.beginPath();
          ctx.moveTo(pi.x, pi.y);
          ctx.lineTo(pj.x, pj.y);
          ctx.lineWidth   = lw;
          ctx.strokeStyle = self._rgba(pal.line, la);
          ctx.stroke();
        }
      }

      // Particle–mouse lines
      var mdx = pi.x - mx;
      var mdy = pi.y - my;
      var md2 = mdx * mdx + mdy * mdy;
      if (md2 < MOUSE_D2) {
        var mt  = 1 - Math.sqrt(md2) / MOUSE_DIST;
        var mlw = mt * 1.8;
        var mla = mt * 0.75;
        ctx.beginPath();
        ctx.moveTo(pi.x, pi.y);
        ctx.lineTo(mx, my);
        ctx.lineWidth   = mlw;
        ctx.strokeStyle = self._rgba(pal.mouse, mla);
        ctx.stroke();
      }
    }

    // ── Draw particles ────────────────────────────────────
    for (var k = 0; k < n; k++) {
      var pk = p[k];

      // Highlight particles close to mouse
      var hkdx = pk.x - mx;
      var hkdy = pk.y - my;
      var hkd2 = hkdx * hkdx + hkdy * hkdy;
      var boost = hkd2 < MOUSE_D2 ? 1 + (1 - Math.sqrt(hkd2) / MOUSE_DIST) * 1.5 : 1;

      ctx.beginPath();
      ctx.arc(pk.x, pk.y, pk.r * boost, 0, Math.PI * 2);
      ctx.fillStyle = self._rgba(pal.particle, Math.min(1, pk.op * boost));
      ctx.fill();
    }

    // ── Draw mouse cursor node ────────────────────────────
    if (mx > -100) {
      // Outer ring
      ctx.beginPath();
      ctx.arc(mx, my, 6, 0, Math.PI * 2);
      ctx.strokeStyle = self._rgba(pal.mouse, 0.5);
      ctx.lineWidth   = 1.5;
      ctx.stroke();
      // Inner dot
      ctx.beginPath();
      ctx.arc(mx, my, 2.5, 0, Math.PI * 2);
      ctx.fillStyle = self._rgba(pal.mouse, 0.9);
      ctx.fill();
    }

    // Re-read live values each frame for theme responsiveness
    this.pal = (PALETTES[this.accent] || PALETTES.kemtls)[this.isDark ? 'dark' : 'light'];

    this.raf = requestAnimationFrame(function () { self._tick(); });
  };

  /* ── Init ──────────────────────────────────────────── */
  function init() {
    var canvas = document.getElementById('particleCanvas');
    if (!canvas) return;
    new Engine(canvas);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
