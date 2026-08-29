<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="theme-color" content="#02060b">
  <meta name="description" content="Routix — Web Application Firewall & Traffic Protection">
  <title>Routix — Cloud WAF</title>

  <style>
    :root {
      --bg: #02050a;
      --bg2: #06101a;
      --panel: rgba(7, 15, 25, .78);
      --panel-solid: #08131f;
      --cyan: #36e6ff;
      --blue: #397cff;
      --green: #43e6a7;
      --red: #ff526d;
      --yellow: #ffd166;
      --text: #eefaff;
      --muted: #8ba0b4;
      --muted2: #607487;
      --border: rgba(54, 230, 255, .14);
      --border-hover: rgba(54, 230, 255, .42);
      --shadow: 0 20px 70px rgba(0,0,0,.35);
    }

    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }

    html {
      scroll-behavior: smooth;
    }

    body {
      min-height: 100vh;
      overflow-x: hidden;

      background:
        radial-gradient(circle at 75% 12%, rgba(57,124,255,.17), transparent 30%),
        radial-gradient(circle at 15% 55%, rgba(54,230,255,.08), transparent 28%),
        linear-gradient(180deg, #02050a 0%, #030811 55%, #02050a 100%);

      color: var(--text);
      font-family: Tahoma, Arial, sans-serif;
    }

    a {
      color: inherit;
      text-decoration: none;
    }

    button {
      font-family: inherit;
    }

    /* =========================================================
       CYBER BACKGROUND
    ========================================================== */

    .cyber-bg {
      position: fixed;
      inset: 0;
      z-index: -10;
      pointer-events: none;
      overflow: hidden;

      background:
        linear-gradient(rgba(54,230,255,.035) 1px, transparent 1px),
        linear-gradient(90deg, rgba(54,230,255,.035) 1px, transparent 1px);

      background-size: 55px 55px;

      mask-image:
        linear-gradient(
          to bottom,
          black 0%,
          black 70%,
          transparent 100%
        );
    }

    .cyber-bg::before {
      content: "";
      position: absolute;

      width: 700px;
      height: 700px;

      left: 50%;
      top: 48%;

      transform: translate(-50%, -50%);

      border-radius: 50%;

      border: 1px solid rgba(54,230,255,.09);

      box-shadow:
        0 0 100px rgba(54,230,255,.04),
        inset 0 0 100px rgba(57,124,255,.035);
    }

    .cyber-bg::after {
      content: "";
      position: absolute;

      width: 430px;
      height: 430px;

      left: 50%;
      top: 48%;

      transform: translate(-50%, -50%);

      border-radius: 50%;

      border: 1px dashed rgba(54,230,255,.11);

      animation: rotate 35s linear infinite;
    }

    .orb {
      position: fixed;

      width: 420px;
      height: 420px;

      border-radius: 50%;

      pointer-events: none;

      filter: blur(80px);

      opacity: .12;

      z-index: -9;
    }

    .orb.one {
      top: -180px;
      right: -120px;
      background: #397cff;
    }

    .orb.two {
      bottom: -220px;
      left: -120px;
      background: #36e6ff;
    }

    .scanlines {
      position: fixed;
      inset: 0;

      z-index: 100;

      pointer-events: none;

      opacity: .075;

      background:
        linear-gradient(
          transparent 50%,
          rgba(54,230,255,.04) 50%
        );

      background-size: 100% 6px;
    }

    .particles {
      position: fixed;
      inset: 0;

      z-index: -7;

      pointer-events: none;

      opacity: .35;
    }

    .particle {
      position: absolute;

      width: 2px;
      height: 2px;

      border-radius: 50%;

      background: var(--cyan);

      box-shadow: 0 0 9px var(--cyan);

      animation: float 8s linear infinite;
    }

    @keyframes rotate {
      to {
        transform: translate(-50%, -50%) rotate(360deg);
      }
    }

    @keyframes float {
      from {
        transform: translateY(20px);
        opacity: 0;
      }

      20% {
        opacity: 1;
      }

      80% {
        opacity: .8;
      }

      to {
        transform: translateY(-180px);
        opacity: 0;
      }
    }

    /* =========================================================
       INTRO SCREEN
    ========================================================== */

    .intro {
      position: fixed;
      inset: 0;

      z-index: 200;

      display: flex;
      align-items: center;
      justify-content: center;

      background:
        radial-gradient(
          circle at center,
          rgba(9,30,48,.72),
          rgba(2,5,10,.98) 65%
        ),
        #02050a;

      transition:
        opacity .7s ease,
        visibility .7s ease,
        transform .7s ease;
    }

    .intro.hidden {
      opacity: 0;
      visibility: hidden;
      transform: scale(1.04);
      pointer-events: none;
    }

    .intro-tech {
      position: absolute;
      inset: 0;
      overflow: hidden;
      opacity: .42;
    }

    .intro-tech::before {
      content: "";

      position: absolute;

      width: min(80vw, 850px);
      height: min(80vw, 850px);

      left: 50%;
      top: 50%;

      transform: translate(-50%, -50%);

      border-radius: 50%;

      border: 1px solid rgba(54,230,255,.16);

      box-shadow:
        0 0 100px rgba(54,230,255,.08),
        inset 0 0 100px rgba(54,230,255,.05);
    }

    .intro-tech::after {
      content: "";

      position: absolute;

      width: 50%;
      height: 1px;

      left: 25%;
      top: 50%;

      background:
        linear-gradient(
          90deg,
          transparent,
          rgba(54,230,255,.45),
          transparent
        );

      box-shadow:
        0 0 25px rgba(54,230,255,.3);
    }

    .intro-grid {
      position: absolute;

      inset: -30%;

      transform: rotate(-14deg);

      background:
        linear-gradient(rgba(54,230,255,.035) 1px, transparent 1px),
        linear-gradient(90deg, rgba(54,230,255,.035) 1px, transparent 1px);

      background-size: 48px 48px;
    }

    .intro-content {
      position: relative;

      z-index: 2;

      width: min(900px, 90%);

      text-align: center;
    }

    .intro-status {
      display: inline-flex;

      align-items: center;

      gap: 9px;

      padding: 8px 14px;

      border: 1px solid var(--border);

      border-radius: 999px;

      background: rgba(54,230,255,.045);

      color: #a9eaf3;

      font-size: 11px;

      letter-spacing: .4px;

      animation: fadeUp .8s ease both;
    }

    .live-dot {
      width: 7px;
      height: 7px;

      border-radius: 50%;

      background: var(--green);

      box-shadow: 0 0 14px var(--green);

      animation: pulse 1.7s infinite;
    }

    .intro-logo {
      width: 76px;
      height: 76px;

      margin: 32px auto 26px;

      position: relative;

      transform: rotate(45deg);

      border: 1px solid var(--cyan);

      box-shadow:
        0 0 35px rgba(54,230,255,.16),
        inset 0 0 25px rgba(54,230,255,.05);

      animation: logoIn 1s ease both;
    }

    .intro-logo::before {
      content: "";

      position: absolute;

      inset: 13px;

      border: 1px solid rgba(54,230,255,.65);
    }

    .intro-logo::after {
      content: "";

      position: absolute;

      inset: 24px;

      background: rgba(54,230,255,.13);

      border: 1px solid var(--cyan);

      box-shadow: 0 0 22px rgba(54,230,255,.2);
    }

    .intro h1 {
      font-size: clamp(64px, 12vw, 130px);

      line-height: .9;

      letter-spacing: -7px;

      margin-bottom: 24px;

      text-shadow:
        0 0 50px rgba(54,230,255,.12);

      animation: fadeUp .8s .15s ease both;
    }

    .intro h1 span {
      color: var(--cyan);
    }

    .intro p {
      max-width: 680px;

      margin: 0 auto;

      color: var(--muted);

      font-size: 16px;

      line-height: 1.9;

      animation: fadeUp .8s .25s ease both;
    }

    .enter-btn {
      margin-top: 34px;

      min-width: 210px;
      height: 53px;

      padding: 0 26px;

      border: 0;

      border-radius: 13px;

      cursor: pointer;

      color: #021018;

      font-weight: 900;

      font-size: 14px;

      background:
        linear-gradient(
          135deg,
          var(--cyan),
          var(--blue)
        );

      box-shadow:
        0 16px 50px rgba(57,124,255,.22),
        0 0 35px rgba(54,230,255,.08);

      transition: .25s;

      animation: fadeUp .8s .35s ease both;
    }

    .enter-btn:hover {
      transform: translateY(-3px);

      box-shadow:
        0 20px 60px rgba(57,124,255,.3),
        0 0 45px rgba(54,230,255,.12);
    }

    .intro-corner {
      position: absolute;

      bottom: 25px;
      left: 30px;

      color: #3f586c;

      font: 10px Consolas, monospace;

      direction: ltr;
    }

    @keyframes fadeUp {
      from {
        opacity: 0;
        transform: translateY(18px);
      }

      to {
        opacity: 1;
        transform: translateY(0);
      }
    }

    @keyframes logoIn {
      from {
        opacity: 0;
        transform: rotate(45deg) scale(.6);
      }

      to {
        opacity: 1;
        transform: rotate(45deg) scale(1);
      }
    }

    @keyframes pulse {
      50% {
        opacity: .4;
        transform: scale(.75);
      }
    }

    /* =========================================================
       HEADER
    ========================================================== */

    header {
      position: fixed;

      top: 0;
      left: 0;
      right: 0;

      z-index: 90;

      height: 76px;

      display: flex;

      align-items: center;

      justify-content: space-between;

      padding: 0 6%;

      background: rgba(2,5,10,.72);

      border-bottom:
        1px solid rgba(255,255,255,.055);

      backdrop-filter: blur(18px);
    }

    .brand {
      display: flex;

      align-items: center;

      gap: 12px;

      font-weight: 900;

      letter-spacing: 1px;
    }

    .brand-logo {
      position: relative;

      width: 34px;
      height: 34px;

      transform: rotate(45deg);

      border: 1px solid var(--cyan);

      box-shadow:
        0 0 22px rgba(54,230,255,.16);
    }

    .brand-logo::before {
      content: "";

      position: absolute;

      inset: 7px;

      border: 1px solid rgba(54,230,255,.65);
    }

    .brand-logo::after {
      content: "";

      position: absolute;

      inset: 12px;

      background: rgba(54,230,255,.13);

      border: 1px solid var(--cyan);
    }

    .brand-name {
      font-size: 20px;
    }

    nav {
      display: flex;

      align-items: center;

      gap: 3px;
    }

    nav a {
      color: #9eb1c2;

      padding: 9px 12px;

      border-radius: 9px;

      font-size: 12px;

      transition: .2s;
    }

    nav a:hover {
      color: white;

      background:
        rgba(54,230,255,.065);
    }

    .header-actions {
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .header-login,
    .header-admin {
      display: inline-flex;

      align-items: center;

      gap: 7px;

      padding: 9px 13px;

      border: 1px solid var(--border);

      border-radius: 9px;

      color: var(--cyan);

      font-size: 11px;

      transition: .2s;

      cursor: pointer;

      background: transparent;
    }

    .header-login:hover,
    .header-admin:hover {
      border-color: var(--border-hover);

      background:
        rgba(54,230,255,.06);
    }

    .header-user {
      display: none;

      align-items: center;

      gap: 8px;

      padding: 8px 11px;

      border: 1px solid rgba(67,230,167,.2);

      border-radius: 9px;

      color: var(--green);

      font-size: 10px;
    }

    .header-user.show {
      display: inline-flex;
    }

    .logout-btn {
      border: 0;

      background: transparent;

      color: var(--muted);

      cursor: pointer;

      font-size: 10px;
    }

    .logout-btn:hover {
      color: var(--red);
    }

    .mobile-menu {
      display: none;

      padding: 8px 11px;

      border-radius: 9px;

      border: 1px solid var(--border);

      background: transparent;

      color: white;

      cursor: pointer;

      font-size: 18px;
    }

    /* =========================================================
       MAIN
    ========================================================== */

    main {
      opacity: 1;
    }

    .section {
      width: min(1200px, 100%);

      margin: auto;

      padding: 105px 6%;

      scroll-margin-top: 70px;
    }

    .section-title {
      max-width: 760px;

      margin-bottom: 38px;
    }

    .eyebrow {
      display: inline-block;

      margin-bottom: 10px;

      color: var(--cyan);

      font:
        900 11px Consolas, monospace;

      letter-spacing: 1.5px;

      direction: ltr;
    }

    .section-title h2 {
      font-size: clamp(30px, 5vw, 43px);

      line-height: 1.2;

      margin-bottom: 13px;
    }

    .section-title p {
      color: var(--muted);

      font-size: 14px;

      line-height: 1.9;
    }

    /* =========================================================
       DASHBOARD HERO
    ========================================================== */

    .dashboard {
      min-height: 100vh;

      padding-top: 145px;

      display: grid;

      grid-template-columns: 1.15fr .85fr;

      gap: 55px;

      align-items: center;
    }

    .dashboard-copy h1 {
      font-size: clamp(42px, 6vw, 70px);

      line-height: 1.05;

      letter-spacing: -3px;

      margin-bottom: 22px;
    }

    .dashboard-copy h1 span {
      color: var(--cyan);

      text-shadow:
        0 0 35px rgba(54,230,255,.2);
    }

    .dashboard-copy > p {
      max-width: 680px;

      color: var(--muted);

      line-height: 2;

      font-size: 16px;
    }

    .dashboard-actions {
      display: flex;

      flex-wrap: wrap;

      gap: 11px;

      margin-top: 29px;
    }

    .btn {
      min-height: 46px;

      display: inline-flex;

      align-items: center;

      justify-content: center;

      gap: 8px;

      padding: 0 20px;

      border-radius: 11px;

      border: 1px solid var(--border);

      background: rgba(255,255,255,.025);

      color: white;

      font-size: 12px;

      cursor: pointer;

      transition: .22s;
    }

    .btn:hover {
      transform: translateY(-2px);

      border-color: var(--border-hover);

      background:
        rgba(54,230,255,.045);
    }

    .btn-primary {
      border: 0;

      color: #021018;

      font-weight: 900;

      background:
        linear-gradient(
          135deg,
          var(--cyan),
          var(--blue)
        );

      box-shadow:
        0 15px 40px rgba(57,124,255,.18);
    }

    .btn-primary:hover {
      background:
        linear-gradient(
          135deg,
          #5ceaff,
          #528dff
        );
    }

    /* =========================================================
       SECURITY RADAR
    ========================================================== */

    .radar-card {
      position: relative;

      min-height: 430px;

      display: grid;

      place-items: center;

      overflow: hidden;

      border: 1px solid var(--border);

      border-radius: 25px;

      background:
        radial-gradient(
          circle at center,
          rgba(54,230,255,.08),
          transparent 43%
        ),
        rgba(5,11,18,.72);

      box-shadow: var(--shadow);
    }

    .radar {
      position: relative;

      width: 290px;
      height: 290px;

      border-radius: 50%;

      border: 1px solid rgba(54,230,255,.2);

      background:
        linear-gradient(
          rgba(54,230,255,.07) 1px,
          transparent 1px
        ),
        linear-gradient(
          90deg,
          rgba(54,230,255,.07) 1px,
          transparent 1px
        );

      background-size: 72px 72px;

      box-shadow:
        0 0 80px rgba(54,230,255,.06),
        inset 0 0 60px rgba(54,230,255,.04);
    }

    .radar::before,
    .radar::after {
      content: "";

      position: absolute;

      border-radius: 50%;

      border: 1px solid rgba(54,230,255,.15);

      inset: 25%;
    }

    .radar::after {
      inset: 48%;

      background: var(--cyan);

      box-shadow:
        0 0 20px var(--cyan);
    }

    .radar-sweep {
      position: absolute;

      width: 50%;
      height: 1px;

      left: 50%;
      top: 50%;

      transform-origin: left center;

      background:
        linear-gradient(
          90deg,
          var(--cyan),
          transparent
        );

      box-shadow:
        0 0 15px rgba(54,230,255,.5);

      animation:
        sweep 3.5s linear infinite;
    }

    .radar-ring {
      position: absolute;

      inset: -1px;

      border-radius: 50%;

      border: 1px dashed rgba(54,230,255,.12);

      animation:
        rotate 18s linear infinite;
    }

    .radar-label {
      position: absolute;

      bottom: 24px;

      left: 24px;
      right: 24px;

      display: flex;

      align-items: center;

      justify-content: space-between;

      font-size: 10px;

      color: var(--muted2);

      direction: ltr;

      font-family: Consolas, monospace;
    }

    .radar-label strong {
      color: var(--green);
    }

    @keyframes sweep {
      to {
        transform: rotate(360deg);
      }
    }

    /* =========================================================
       STATS
    ========================================================== */

    .stats {
      display: grid;

      grid-template-columns:
        repeat(4, 1fr);

      gap: 12px;

      margin-top: 20px;
    }

    .stat {
      padding: 18px;

      border: 1px solid var(--border);

      border-radius: 14px;

      background:
        rgba(8,16,26,.65);
    }

    .stat-label {
      color: var(--muted2);

      font-size: 10px;

      margin-bottom: 8px;
    }

    .stat-value {
      font:
        900 20px Consolas, monospace;

      direction: ltr;

      text-align: right;
    }

    .stat-value.green {
      color: var(--green);
    }

    .stat-value.cyan {
      color: var(--cyan);
    }

    /* =========================================================
       FEATURES
    ========================================================== */

    .features {
      display: grid;

      grid-template-columns:
        repeat(3, 1fr);

      gap: 14px;
    }

    .feature {
      position: relative;

      padding: 23px;

      overflow: hidden;

      border: 1px solid var(--border);

      border-radius: 17px;

      background:
        linear-gradient(
          145deg,
          rgba(10,22,35,.9),
          rgba(4,9,16,.8)
        );

      transition: .25s;
    }

    .feature::after {
      content: "";

      position: absolute;

      width: 100px;
      height: 100px;

      right: -55px;
      bottom: -55px;

      border-radius: 50%;

      background:
        rgba(54,230,255,.07);

      filter: blur(25px);
    }

    .feature:hover {
      transform: translateY(-5px);

      border-color: var(--border-hover);

      box-shadow:
        0 15px 45px rgba(0,0,0,.22);
    }

    .feature-icon {
      width: 43px;
      height: 43px;

      display: grid;

      place-items: center;

      margin-bottom: 16px;

      border-radius: 11px;

      border:
        1px solid rgba(54,230,255,.2);

      background:
        rgba(54,230,255,.045);

      color: var(--cyan);

      font:
        900 18px Consolas, monospace;
    }

    .feature h3 {
      margin-bottom: 9px;

      font-size: 16px;
    }

    .feature p {
      color: var(--muted);

      font-size: 12px;

      line-height: 1.85;
    }

    .tag {
      display: inline-block;

      margin-top: 14px;

      padding: 4px 7px;

      border:
        1px solid rgba(54,230,255,.13);

      border-radius: 6px;

      color: #70bdca;

      font:
        9px Consolas, monospace;

      direction: ltr;
    }

    /* =========================================================
       API / INTEGRATION
    ========================================================== */

    .integration {
      display: grid;

      grid-template-columns:
        .85fr 1.15fr;

      gap: 18px;
    }

    .steps {
      display: grid;

      gap: 11px;
    }

    .step {
      display: flex;

      gap: 13px;

      padding: 18px;

      border:
        1px solid var(--border);

      border-radius: 13px;

      background:
        rgba(7,15,25,.7);
    }

    .step-number {
      flex:
        0 0 33px;

      height: 33px;

      display: grid;

      place-items: center;

      border-radius: 8px;

      color: var(--cyan);

      background:
        rgba(54,230,255,.07);

      border:
        1px solid rgba(54,230,255,.12);

      font:
        900 12px Consolas, monospace;
    }

    .step strong {
      display: block;

      font-size: 13px;

      margin-bottom: 6px;
    }

    .step span {
      color: var(--muted);

      font-size: 11px;

      line-height: 1.7;
    }

    .code-card {
      min-width: 0;
    }

    pre {
      height: 100%;

      min-height: 360px;

      padding: 22px;

      overflow: auto;

      border:
        1px solid var(--border);

      border-radius: 17px;

      background: #010409;

      color: #b9eaf1;

      direction: ltr;

      text-align: left;

      font:
        12px/1.85 Consolas, monospace;

      box-shadow:
        inset 0 0 40px rgba(54,230,255,.018);
    }

    .code-title {
      display: flex;

      align-items: center;

      gap: 7px;

      padding: 11px 14px;

      border:
        1px solid var(--border);

      border-bottom: 0;

      border-radius: 14px 14px 0 0;

      background: #050b12;

      color: var(--muted2);

      font:
        10px Consolas, monospace;

      direction: ltr;
    }

    .code-dot {
      width: 7px;
      height: 7px;

      border-radius: 50%;

      background: var(--cyan);

      box-shadow:
        0 0 8px rgba(54,230,255,.5);
    }

    .warning {
      margin-top: 10px;

      color: #667b8e;

      font-size: 10px;

      line-height: 1.7;
    }

    /* =========================================================
       L7 / REQUEST FLOW
    ========================================================== */

    .flow {
      display: grid;

      grid-template-columns:
        repeat(5, 1fr);

      gap: 10px;

      align-items: center;
    }

    .flow-node {
      min-height: 120px;

      display: flex;

      flex-direction: column;

      align-items: center;

      justify-content: center;

      text-align: center;

      padding: 14px;

      border:
        1px solid var(--border);

      border-radius: 14px;

      background:
        rgba(7,15,25,.7);
    }

    .flow-node b {
      color: var(--cyan);

      font-size: 13px;

      margin-bottom: 7px;
    }

    .flow-node span {
      color: var(--muted);

      font-size: 10px;

      line-height: 1.6;
    }

    .flow-arrow {
      text-align: center;

      color: var(--cyan);

      font:
        20px Consolas, monospace;
    }

    /* =========================================================
       ADMIN
    ========================================================== */

    .admin-card {
      position: relative;

      overflow: hidden;

      padding: 38px;

      border:
        1px solid var(--border);

      border-radius: 22px;

      background:
        radial-gradient(
          circle at 85% 50%,
          rgba(57,124,255,.12),
          transparent 30%
        ),
        linear-gradient(
          135deg,
          rgba(54,230,255,.055),
          rgba(57,124,255,.035)
        );

      box-shadow: var(--shadow);
    }

    .admin-card::before {
      content: "ADMIN";

      position: absolute;

      top: 25px;
      left: 30px;

      color: rgba(54,230,255,.06);

      font:
        900 70px Consolas, monospace;

      pointer-events: none;

      direction: ltr;
    }

    .admin-status {
      display: inline-flex;

      align-items: center;

      gap: 7px;

      margin-bottom: 16px;

      color: var(--green);

      font:
        10px Consolas, monospace;

      direction: ltr;
    }

    .admin-card h2 {
      font-size: 31px;

      margin-bottom: 10px;
    }

    .admin-card p {
      max-width: 700px;

      color: var(--muted);

      line-height: 1.9;

      font-size: 13px;

      margin-bottom: 23px;
    }

    /* =========================================================
       SETTINGS
    ========================================================== */

    .settings-grid {
      display: grid;

      grid-template-columns:
        repeat(3, 1fr);

      gap: 13px;
    }

    .setting {
      padding: 20px;

      border:
        1px solid var(--border);

      border-radius: 14px;

      background:
        rgba(7,15,25,.65);
    }

    .setting h3 {
      font-size: 14px;

      margin-bottom: 8px;
    }

    .setting p {
      color: var(--muted);

      font-size: 11px;

      line-height: 1.75;
    }

    .setting code {
      display: block;

      margin-top: 12px;

      color: #7ed9e5;

      direction: ltr;

      text-align: left;

      font:
        10px Consolas, monospace;
    }

    /* =========================================================
       ABOUT
    ========================================================== */

    .about {
      display: grid;

      grid-template-columns:
        1fr 1fr;

      gap: 35px;

      align-items: center;
    }

    .about-copy p {
      color: var(--muted);

      line-height: 2;

      font-size: 13px;
    }

    .terminal {
      padding: 23px;

      border:
        1px solid var(--border);

      border-radius: 17px;

      background: #010409;

      color: #8ecbd4;

      font:
        11px/2.1 Consolas, monospace;

      direction: ltr;

      text-align: left;

      box-shadow:
        inset 0 0 50px rgba(54,230,255,.018);
    }

    .terminal .green {
      color: var(--green);
    }

    .terminal .cyan {
      color: var(--cyan);
    }

    .terminal .white {
      color: white;
    }

    /* =========================================================
       FOOTER
    ========================================================== */

    footer {
      padding: 30px 6%;

      border-top:
        1px solid rgba(255,255,255,.05);

      color: #586c7e;

      text-align: center;

      font-size: 10px;
    }

    footer span {
      color: var(--cyan);
    }

    /* =========================================================
       LOGIN MODAL
    ========================================================== */

    .login-overlay {
      position: fixed;

      inset: 0;

      z-index: 500;

      display: flex;

      align-items: center;

      justify-content: center;

      padding: 20px;

      background:
        rgba(0,4,9,.86);

      backdrop-filter: blur(14px);

      opacity: 0;

      visibility: hidden;

      pointer-events: none;

      transition:
        opacity .3s ease,
        visibility .3s ease;
    }

    .login-overlay.active {
      opacity: 1;

      visibility: visible;

      pointer-events: auto;
    }

    .login-box {
      position: relative;

      width: min(440px, 100%);

      padding: 32px;

      border:
        1px solid var(--border);

      border-radius: 22px;

      background:
        linear-gradient(
          145deg,
          rgba(9,22,35,.98),
          rgba(3,8,15,.98)
        );

      box-shadow:
        0 30px 100px rgba(0,0,0,.6),
        0 0 60px rgba(54,230,255,.06);

      transform:
        translateY(15px)
        scale(.97);

      transition:
        transform .3s ease;
    }

    .login-overlay.active .login-box {
      transform:
        translateY(0)
        scale(1);
    }

    .login-close {
      position: absolute;

      top: 14px;
      left: 14px;

      width: 32px;
      height: 32px;

      border:
        1px solid var(--border);

      border-radius: 8px;

      background: rgba(255,255,255,.025);

      color: var(--muted);

      cursor: pointer;

      font-size: 16px;

      transition: .2s;
    }

    .login-close:hover {
      color: white;

      border-color:
        var(--border-hover);
    }

    .login-top {
      text-align: center;

      margin-bottom: 24px;
    }

    .login-mini-logo {
      width: 48px;
      height: 48px;

      margin: 20px auto;

      position: relative;

      transform: rotate(45deg);

      border:
        1px solid var(--cyan);

      box-shadow:
        0 0 25px rgba(54,230,255,.13);
    }

    .login-mini-logo::before {
      content: "";

      position: absolute;

      inset: 9px;

      border:
        1px solid rgba(54,230,255,.6);
    }

    .login-mini-logo::after {
      content: "";

      position: absolute;

      inset: 16px;

      background:
        rgba(54,230,255,.12);

      border:
        1px solid var(--cyan);
    }

    .login-top h2 {
      font-size: 25px;

      margin-bottom: 8px;
    }

    .login-top h2 span {
      color: var(--cyan);
    }

    .login-top p {
      color: var(--muted);

      font-size: 11px;

      line-height: 1.8;
    }

    .login-label {
      display: block;

      margin-bottom: 8px;

      color: #9eb1c2;

      font-size: 11px;
    }

    .login-input {
      width: 100%;

      height: 50px;

      padding: 0 15px;

      border:
        1px solid var(--border);

      border-radius: 10px;

      outline: none;

      background:
        rgba(1,6,11,.85);

      color: white;

      font-family: Tahoma, Arial, sans-serif;

      font-size: 13px;

      direction: ltr;

      text-align: left;

      transition: .2s;
    }

    .login-input:focus {
      border-color: var(--cyan);

      box-shadow:
        0 0 0 3px rgba(54,230,255,.05);
    }

    .login-input::placeholder {
      color: #53687a;
    }

    .otp-input {
      text-align: center;

      letter-spacing: 8px;

      font:
        900 20px Consolas, monospace;
    }

    .login-submit {
      width: 100%;

      height: 50px;

      margin-top: 13px;

      border: 0;

      border-radius: 10px;

      color: #021018;

      background:
        linear-gradient(
          135deg,
          var(--cyan),
          var(--blue)
        );

      font-size: 12px;

      font-weight: 900;

      cursor: pointer;

      transition: .2s;
    }

    .login-submit:hover {
      transform: translateY(-2px);
    }

    .login-submit:disabled {
      opacity: .55;

      cursor: not-allowed;

      transform: none;
    }

    .login-secondary {
      width: 100%;

      margin-top: 10px;

      padding: 9px;

      border: 0;

      background: transparent;

      color: var(--muted);

      cursor: pointer;

      font-size: 10px;
    }

    .login-secondary:hover {
      color: var(--cyan);
    }

    .login-message {
      min-height: 22px;

      margin-top: 14px;

      text-align: center;

      font-size: 11px;

      line-height: 1.7;
    }

    .login-message.success {
      color: var(--green);
    }

    .login-message.error {
      color: var(--red);
    }

    .login-message.info {
      color: var(--muted);
    }

    .login-security {
      display: flex;

      align-items: center;

      justify-content: center;

      gap: 7px;

      margin-top: 19px;

      color: #526879;

      font:
        9px Consolas, monospace;

      direction: ltr;
    }

    /* =========================================================
       RESPONSIVE
    ========================================================== */

    @media (max-width: 1050px) {

      nav a {
        padding: 8px;
      }

      .dashboard {
        grid-template-columns: 1fr;
      }

      .radar-card {
        min-height: 350px;
      }

      .features {
        grid-template-columns:
          repeat(2, 1fr);
      }

      .integration {
        grid-template-columns: 1fr;
      }

      .flow {
        grid-template-columns:
          1fr 30px 1fr;
      }
    }

    @media (max-width: 760px) {

      header {
        padding: 0 5%;
      }

      nav,
      .header-admin {
        display: none;
      }

      .header-actions {
        display: none;
      }

      .mobile-menu {
        display: block;
      }

      nav.mobile-open {
        display: flex;

        position: absolute;

        top: 69px;

        left: 5%;
        right: 5%;

        padding: 8px;

        flex-direction: column;

        align-items: stretch;

        background:
          rgba(2,5,10,.97);

        border:
          1px solid var(--border);

        border-radius: 13px;

        backdrop-filter: blur(20px);
      }

      nav.mobile-open a {
        padding: 13px;
      }

      .section {
        padding: 75px 5%;
      }

      .dashboard {
        padding-top: 120px;
      }

      .features,
      .settings-grid,
      .stats {
        grid-template-columns:
          1fr 1fr;
      }

      .about {
        grid-template-columns: 1fr;
      }

      .flow {
        grid-template-columns: 1fr;
      }

      .flow-arrow {
        transform: rotate(90deg);
      }

      .intro h1 {
        letter-spacing: -4px;
      }

      .intro p {
        font-size: 14px;
      }

      .login-box {
        padding: 28px 20px;
      }
    }

    @media (max-width: 500px) {

      .features,
      .settings-grid,
      .stats {
        grid-template-columns: 1fr;
      }

      .dashboard-copy h1 {
        letter-spacing: -2px;
      }

      .radar {
        width: 235px;
        height: 235px;
      }

      .radar-card {
        min-height: 310px;
      }

      .admin-card {
        padding: 27px;
      }

      .intro-logo {
        width: 62px;
        height: 62px;
      }

      .intro h1 {
        font-size: 58px;
      }

      .intro-corner {
        display: none;
      }

      .login-box {
        padding: 25px 18px;
      }
    }

    @media (prefers-reduced-motion: reduce) {

      *,
      *::before,
      *::after {
        animation-duration: .001ms !important;

        animation-iteration-count: 1 !important;

        scroll-behavior: auto !important;
      }
    }
  </style>
</head>

<body>

  <!-- =========================================================
       BACKGROUND
  ========================================================== -->

  <div class="cyber-bg"></div>
  <div class="orb one"></div>
  <div class="orb two"></div>
  <div class="particles" id="particles"></div>
  <div class="scanlines"></div>


  <!-- =========================================================
       INTRO SCREEN
  ========================================================== -->

  <section class="intro" id="intro">

    <div class="intro-tech">
      <div class="intro-grid"></div>
    </div>

    <div class="intro-content">

      <div class="intro-status">
        <span class="live-dot"></span>
        ROUTIX WAF SYSTEM • PROTECTION LAYER READY
      </div>

      <div class="intro-logo"></div>

      <h1>
        Routix<span>.</span>
      </h1>

      <p>
        Web Application Firewall مصمم لمراقبة وحماية
        تطبيقات الويب من الترافيك المشبوه، الهجمات
        على مستوى L7، تجاوز المعدلات، والمصادر عالية الخطورة.
      </p>

      <button
        class="enter-btn"
        onclick="enterPlatform()"
      >
        دخول إلى المنصة
        <span>←</span>
      </button>

    </div>

    <div class="intro-corner">
      ROUTIX / SECURITY INFRASTRUCTURE / 2026
    </div>

  </section>


  <!-- =========================================================
       LOGIN MODAL
       تسجيل الدخول اختياري
  ========================================================== -->

  <section
    class="login-overlay"
    id="loginOverlay"
    aria-hidden="true"
  >

    <div class="login-box">

      <button
        class="login-close"
        type="button"
        onclick="closeLogin()"
        aria-label="إغلاق"
      >
        ×
      </button>

      <div class="login-top">

        <div class="intro-status">
          <span class="live-dot"></span>
          ROUTIX SECURITY / OPTIONAL LOGIN
        </div>

        <div class="login-mini-logo"></div>

        <h2>
          تسجيل الدخول<span>.</span>
        </h2>

        <p>
          تسجيل الدخول اختياري.
          أدخل بريدك الإلكتروني إذا أردت إنشاء جلسة آمنة
          والوصول إلى الوظائف المرتبطة بحسابك.
        </p>

      </div>


      <!-- =====================================================
           EMAIL STEP
      ====================================================== -->

      <div id="emailStep">

        <label
          class="login-label"
          for="loginEmail"
        >
          البريد الإلكتروني
        </label>

        <input
          id="loginEmail"
          class="login-input"
          type="email"
          autocomplete="email"
          placeholder="example@email.com"
          maxlength="254"
        >

        <button
          class="login-submit"
          id="sendOtpButton"
          type="button"
          onclick="sendOTP()"
        >
          إرسال رمز التحقق ←
        </button>

      </div>


      <!-- =====================================================
           OTP STEP
      ====================================================== -->

      <div
        id="otpStep"
        style="display:none;"
      >

        <label
          class="login-label"
          for="loginOtp"
        >
          رمز التحقق المرسل إلى بريدك
        </label>

        <input
          id="loginOtp"
          class="login-input otp-input"
          type="text"
          inputmode="numeric"
          autocomplete="one-time-code"
          maxlength="6"
          placeholder="••••••"
        >

        <button
          class="login-submit"
          id="verifyOtpButton"
          type="button"
          onclick="verifyOTP()"
        >
          التحقق والدخول ←
        </button>

        <button
          class="login-secondary"
          type="button"
          onclick="backToEmail()"
        >
          تغيير البريد الإلكتروني
        </button>

      </div>


      <div
        class="login-message info"
        id="loginMessage"
      ></div>

      <div class="login-security">
        <span class="live-dot"></span>
        OTP AUTHENTICATION / SECURE SESSION
      </div>

    </div>

  </section>


  <!-- =========================================================
       HEADER
  ========================================================== -->

  <header>

    <a
      href="#home"
      class="brand"
    >
      <span class="brand-logo"></span>
      <span class="brand-name">Routix</span>
    </a>


    <nav id="nav">

      <a href="#home">الرئيسية</a>

      <a href="#features">المميزات</a>

      <a href="#api">API</a>

      <a href="#integration">
        طريقة الربط
      </a>

      <a href="#admin">
        لوحة الإدارة
      </a>

      <a href="#settings">
        الإعدادات
      </a>

      <a href="#about">
        من نحن
      </a>

    </nav>


    <div class="header-actions">

      <div
        class="header-user"
        id="headerUser"
      >
        <span>●</span>

        <span id="headerEmail">
          المستخدم
        </span>

        <button
          class="logout-btn"
          type="button"
          onclick="logoutRoutix()"
        >
          خروج
        </button>
      </div>


      <button
        class="header-login"
        id="headerLogin"
        type="button"
        onclick="openLogin()"
      >
        <span>◉</span>
        تسجيل الدخول
      </button>


      <a
        href="/admin"
        class="header-admin"
      >
        <span>▣</span>
        لوحة الإدارة
      </a>

    </div>


    <button
      class="mobile-menu"
      onclick="toggleMenu()"
      aria-label="القائمة"
    >
      ☰
    </button>

  </header>


  <!-- =========================================================
       MAIN
  ========================================================== -->

  <main id="home">


    <!-- =======================================================
         DASHBOARD / HERO
    ======================================================== -->

    <section class="section dashboard">

      <div class="dashboard-copy">

        <span class="eyebrow">
          ROUTIX / CLOUD WAF
        </span>

        <h1>
          حماية موقعك تبدأ<br>
          من أول <span>Request.</span>
        </h1>

        <p>
          Routix يعمل كطبقة حماية أمام تطبيقك،
          يراقب الترافيك وطلبات HTTP، يحد من
          المعدلات المرتفعة، يكتشف أنماط الهجمات
          ويمنحك رؤية مباشرة لما يحدث على مستوى
          البنية التحتية والتطبيق.
        </p>

        <div class="dashboard-actions">

          <a
            href="/admin"
            class="btn btn-primary"
          >
            فتح لوحة الإدارة ←
          </a>

          <button
            class="btn"
            type="button"
            onclick="openLogin()"
          >
            تسجيل الدخول
          </button>

          <a
            href="#features"
            class="btn"
          >
            استكشف المميزات
          </a>

        </div>


        <div class="stats">

          <div class="stat">

            <div class="stat-label">
              WAF STATUS
            </div>

            <div class="stat-value green">
              ACTIVE
            </div>

          </div>


          <div class="stat">

            <div class="stat-label">
              LAYER
            </div>

            <div class="stat-value cyan">
              L7
            </div>

          </div>


          <div class="stat">

            <div class="stat-label">
              RATE CONTROL
            </div>

            <div class="stat-value">
              ON
            </div>

          </div>


          <div class="stat">

            <div class="stat-label">
              LIVE EVENTS
            </div>

            <div class="stat-value green">
              READY
            </div>

          </div>

        </div>

      </div>


      <div class="radar-card">

        <div class="radar">

          <div class="radar-ring"></div>

          <div class="radar-sweep"></div>

        </div>

        <div class="radar-label">

          <span>
            TRAFFIC_MONITOR
          </span>

          <strong>
            ● PROTECTED
          </strong>

        </div>

      </div>

    </section>


    <!-- =======================================================
         FEATURES
    ======================================================== -->

    <section
      id="features"
      class="section"
    >

      <div class="section-title">

        <span class="eyebrow">
          SECURITY ENGINE
        </span>

        <h2>
          حماية متعددة الطبقات للترافيك
        </h2>

        <p>
          Routix يجمع بين التحكم بالترافيك،
          تحليل الطلبات، تقييم المخاطر وآليات
          الحماية المختلفة داخل طبقة واحدة.
        </p>

      </div>


      <div class="features">


        <article class="feature">

          <div class="feature-icon">
            ◈
          </div>

          <h3>
            Rate Limiting
          </h3>

          <p>
            تحديد عدد الطلبات المسموح بها لكل IP
            خلال نافذة زمنية وتقليل إساءة استخدام
            الموارد.
          </p>

          <span class="tag">
            TRAFFIC_CONTROL
          </span>

        </article>


        <article class="feature">

          <div class="feature-icon">
            ⚡
          </div>

          <h3>
            Burst Protection
          </h3>

          <p>
            التعامل مع الارتفاعات المفاجئة والسريعة
            في الطلبات قبل انتقال الضغط إلى التطبيق
            الأصلي.
          </p>

          <span class="tag">
            BURST_DETECTION
          </span>

        </article>


        <article class="feature">

          <div class="feature-icon">
            L7
          </div>

          <h3>
            Layer 7 Protection
          </h3>

          <p>
            فحص طلبات HTTP على مستوى التطبيق
            وتحليل المسارات والرؤوس والبيانات
            وفق قواعد الحماية.
          </p>

          <span class="tag">
            HTTP_INSPECTION
          </span>

        </article>


        <article class="feature">

          <div class="feature-icon">
            SQL
          </div>

          <h3>
            SQLi Detection
          </h3>

          <p>
            كشف أنماط شائعة مرتبطة بمحاولات
            SQL Injection داخل الطلبات.
          </p>

          <span class="tag">
            ATTACK_DETECTION
          </span>

        </article>


        <article class="feature">

          <div class="feature-icon">
            X
          </div>

          <h3>
            XSS Detection
          </h3>

          <p>
            فحص الأنماط المعروفة المرتبطة بمحاولات
            Cross-Site Scripting.
          </p>

          <span class="tag">
            WEB_SECURITY
          </span>

        </article>


        <article class="feature">

          <div class="feature-icon">
            R
          </div>

          <h3>
            Risk Scoring
          </h3>

          <p>
            بناء درجة خطورة للمصادر والطلبات
            للمساعدة في اتخاذ قرار الحظر أو
            التقييد أو المراقبة.
          </p>

          <span class="tag">
            RISK_ENGINE
          </span>

        </article>


        <article class="feature">

          <div class="feature-icon">
            H
          </div>

          <h3>
            Honeypot
          </h3>

          <p>
            مسارات طُعم يمكن استخدامها لرصد
            المصادر التي تتفاعل مع نقاط لا يفترض
            أن يستخدمها المستخدم الطبيعي.
          </p>

          <span class="tag">
            THREAT_INTELLIGENCE
          </span>

        </article>


        <article class="feature">

          <div class="feature-icon">
            ⊘
          </div>

          <h3>
            Blacklist
          </h3>

          <p>
            التعامل مع المصادر التي تتجاوز سياسات
            الحماية وإبقاؤها ضمن قائمة الحظر
            حسب منطق النظام.
          </p>

          <span class="tag">
            IP_CONTROL
          </span>

        </article>


        <article class="feature">

          <div class="feature-icon">
            ↯
          </div>

          <h3>
            Concurrency Control
          </h3>

          <p>
            التحكم في عدد الاتصالات المتزامنة
            لكل IP وعلى مستوى الخدمة لتقليل
            الضغط غير الطبيعي.
          </p>

          <span class="tag">
            CONNECTION_LIMIT
          </span>

        </article>


        <article class="feature">

          <div class="feature-icon">
            ◌
          </div>

          <h3>
            Live Alerts
          </h3>

          <p>
            مراقبة الأحداث والتنبيهات بشكل مباشر
            من خلال قناة الأحداث الخاصة بالـWAF
            دون الحاجة لتحديث الصفحة.
          </p>

          <span class="tag">
            REAL_TIME
          </span>

        </article>


        <article class="feature">

          <div class="feature-icon">
            ▣
          </div>

          <h3>
            Security Headers
          </h3>

          <p>
            تحسين طبقة HTTP الأمنية باستخدام
            إعدادات Security Headers المناسبة
            للسيرفر.
          </p>

          <span class="tag">
            HTTP_SECURITY
          </span>

        </article>


        <article class="feature">

          <div class="feature-icon">
            ↗
          </div>

          <h3>
            Reverse Proxy
          </h3>

          <p>
            تمرير الطلبات الطبيعية إلى التطبيق الأصلي
            مع إبقاء التطبيق خلف طبقة Routix.
          </p>

          <span class="tag">
            PROXY_LAYER
          </span>

        </article>

      </div>

    </section>


    <!-- =======================================================
         L7 FLOW
    ======================================================== -->

    <section
      id="api"
      class="section"
    >

      <div class="section-title">

        <span class="eyebrow">
          REQUEST PIPELINE
        </span>

        <h2>
          كيف يمر الطلب داخل Routix؟
        </h2>

        <p>
          الفكرة الأساسية هي أن Routix يصبح نقطة
          الدخول العامة، بينما يبقى التطبيق الأصلي
          خلفه.
        </p>

      </div>


      <div class="flow">

        <div class="flow-node">

          <b>
            CLIENT
          </b>

          <span>
            المستخدم يرسل HTTP Request
          </span>

        </div>

        <div class="flow-arrow">
          →
        </div>

        <div class="flow-node">

          <b>
            ROUTIX
          </b>

          <span>
            استقبال وفحص الطلب
          </span>

        </div>

        <div class="flow-arrow">
          →
        </div>

        <div class="flow-node">

          <b>
            WAF ENGINE
          </b>

          <span>
            Rate / L7 / Risk / Rules
          </span>

        </div>

        <div class="flow-arrow">
          →
        </div>

        <div class="flow-node">

          <b>
            DECISION
          </b>

          <span>
            Allow / Block / Limit
          </span>

        </div>

        <div class="flow-arrow">
          →
        </div>

        <div class="flow-node">

          <b>
            TARGET
          </b>

          <span>
            تمرير الطلب الطبيعي للتطبيق
          </span>

        </div>

      </div>

    </section>


    <!-- =======================================================
         API & INTEGRATION
    ======================================================== -->

    <section
      id="integration"
      class="section"
    >

      <div class="section-title">

        <span class="eyebrow">
          API & INTEGRATION
        </span>

        <h2>
          اربط Routix بموقع العميل
        </h2>

        <p>
          Routix يعمل كطبقة حماية أمام تطبيق العميل،
          بحيث تمر الطلبات عبر طبقة الحماية أولًا قبل
          الوصول إلى التطبيق الأصلي.
        </p>

      </div>


      <div class="integration">

        <div class="steps">


          <div class="step">

            <b class="step-number">
              01
            </b>

            <div>

              <strong>
                أضف موقعك إلى Routix
              </strong>

              <span>
                أنشئ إعداد الموقع من خلال لوحة الإدارة
                وحدد النطاق والتطبيق المرتبط به.
              </span>

            </div>

          </div>


          <div class="step">

            <b class="step-number">
              02
            </b>

            <div>

              <strong>
                التحقق من حالة الربط
              </strong>

              <span>
                تحديد رابط موقع العميل في ملف البيئة،
                ثم توجيه الدومين إلى سيرفرك.
              </span>

            </div>

          </div>


          <div class="step">

            <b class="step-number">
              03
            </b>

            <div>

              <strong>
                وجّه الدومين إلى Routix
              </strong>

              <span>
                بعد إعداد الموقع، وجّه حركة المرور الخاصة
                بالدومين إلى نقطة الدخول الخاصة بـRoutix.
              </span>

            </div>

          </div>


          <div class="step">

            <b class="step-number">
              04
            </b>

            <div>

              <strong>
                احتفظ بإعدادات السيرفر بشكل آمن
              </strong>

              <span>
                مفاتيح النظام وبيانات الإدارة وإعدادات
                التطبيق الداخلي تبقى على السيرفر ولا تظهر
                في الواجهة العامة.
              </span>

            </div>

          </div>

        </div>


        <div class="code-card">

          <div class="code-title">

            <span class="code-dot"></span>

            ROUTIX / SITE CONFIGURATION

          </div>

<pre># Routix Site Configuration

SITE_DOMAIN=your-domain.com

SITE_TOKEN=YOUR_SITE_TOKEN

# يتم إنشاء القيم الحساسة
# وإدارتها من خلال السيرفر

# لا تضع:
# WAF_API_KEY
# ADMIN_PASSWORD
# TARGET_URL الداخلي
# أو أي أسرار خاصة بالسيرفر
# داخل كود الواجهة العامة.</pre>

          <div class="warning">
            لأسباب أمنية، لا يتم عرض مفاتيح النظام أو بيانات
            الإدارة أو إعدادات البنية الداخلية في الصفحة العامة.
            استخدم Token الموقع الذي يتم إنشاؤه من لوحة الإدارة
            لربط موقعك بخدمة Routix.
          </div>

        </div>

      </div>

    </section>


    <!-- =======================================================
         ADMIN
    ======================================================== -->

    <section
      id="admin"
      class="section"
    >

      <div class="admin-card">

        <div class="admin-status">

          <span class="live-dot"></span>

          ROUTIX ADMIN / LIVE MONITORING

        </div>

        <h2>
          لوحة الإدارة .
        </h2>

        <p>
          الوصول إلى لوحة الإدارة الحالية يتم من خلال
          المسار <b>/admin</b>. من هناك يمكن إدارة ومراقبة
          حالة الـWAF والأحداث والإحصائيات وفق الوظائف
          الموجودة في السيرفر.
        </p>

        <a
          href="/admin"
          class="btn btn-primary"
        >
          فتح لوحة الإدارة ←
        </a>

      </div>

    </section>


    <!-- =======================================================
         SETTINGS
    ======================================================== -->

    <section
      id="settings"
      class="section"
    >

      <div class="section-title">

        <span class="eyebrow">
          WAF CONFIGURATION
        </span>

        <h2>
          الإعدادات التشغيلية
        </h2>

        <p>
          يتم التحكم في السلوك التشغيلي للـWAF
          من خلال إعدادات البيئة الموجودة على السيرفر.
        </p>

      </div>


      <div class="settings-grid">


        <article class="setting">

          <h3>
            Traffic Control
          </h3>

          <p>
            التحكم في معدل الطلبات والحدود العامة
            وحدود الـBurst.
          </p>

          <code>
            RATE LIMITING<br>
            BURST PROTECTION<br>
            GLOBAL TRAFFIC
          </code>

        </article>


        <article class="setting">

          <h3>
            Risk Engine
          </h3>

          <p>
            تقييم مستوى خطورة الطلبات والمصادر
            واتخاذ الإجراء المناسب وفق سياسة النظام.
          </p>

          <code>
            RISK ENGINE<br>
            THREAT DETECTION<br>
            SECURITY RULES
          </code>

        </article>


        <article class="setting">

          <h3>
            Concurrency
          </h3>

          <p>
            التحكم في عدد الاتصالات المتزامنة لكل
            مصدر وعلى مستوى الخدمة.
          </p>

          <code>
            PER-IP LIMIT<br>
            GLOBAL LIMIT<br>
            CONNECTION CONTROL
          </code>

        </article>


        <article class="setting">

          <h3>
            Proxy
          </h3>

          <p>
            إدارة الاتصال بين Routix والتطبيق الأصلي
            الموجود خلف طبقة الحماية.
          </p>

          <code>
            REVERSE PROXY<br>
            UPSTREAM<br>
            CONNECTION ROUTING
          </code>

        </article>


        <article class="setting">

          <h3>
            Request Limits
          </h3>

          <p>
            التحكم في حدود ومهلات الطلبات والاتصال
            مع التطبيق الأصلي.
          </p>

          <code>
            REQUEST LIMITS<br>
            TIMEOUT CONTROL<br>
            HEADER LIMITS
          </code>

        </article>


        <article class="setting">

          <h3>
            Security
          </h3>

          <p>
            مفاتيح النظام وبيانات الإدارة والإعدادات
            الحساسة تتم إدارتها داخليًا على السيرفر.
          </p>

          <code>
            SERVER SIDE ONLY<br>
            PRIVATE CONFIGURATION<br>
            SECRET STORAGE
          </code>

        </article>

      </div>

    </section>


    <!-- =======================================================
         ABOUT
    ======================================================== -->

    <section
      id="about"
      class="section"
    >

      <div class="about">


        <div class="about-copy">

          <span class="eyebrow">
            ABOUT ROUTIX
          </span>

          <div class="section-title">

            <h2>
              نبني الحماية بعقلية
              البنية التحتية.
            </h2>

            <p>
              Routix مشروع تقني طوره مطورون شغوفون
              بالأمن السيبراني، البنية التحتية وتطوير
              الأنظمة.
              <br><br>
              نؤمن أن طبقة الحماية الجيدة يجب أن تكون
              عملية، واضحة وقابلة للمراقبة، وأن تمنح
              المطور رؤية أفضل لما يحدث على مستوى
              الترافيك والطلبات بدل أن تكون مجرد طبقة
              غير مرئية أمام التطبيق.
              <br><br>
              هدف Routix هو توفير طبقة WAF قابلة للدمج
              مع المواقع والتطبيقات، مع أدوات للتحكم
              بالترافيك ومراقبة الأحداث الأمنية.
            </p>

          </div>


          <button
            class="btn btn-primary"
            type="button"
            onclick="openLogin()"
          >
            تسجيل الدخول ←
          </button>

        </div>


        <div class="terminal">

          <div>
            <span class="white">$</span>
            routix start
          </div>

          <div class="green">
            ✓ WAF protection enabled
          </div>

          <div class="green">
            ✓ L7 inspection enabled
          </div>

          <div class="green">
            ✓ Rate limiting enabled
          </div>

          <div class="green">
            ✓ Risk engine enabled
          </div>

          <div class="green">
            ✓ Honeypot monitoring enabled
          </div>

          <div class="green">
            ✓ Blacklist engine enabled
          </div>

          <div class="green">
            ✓ Live admin events enabled
          </div>

          <div>
            <span class="cyan">→</span>
            proxying through Routix
          </div>

          <div>
            <span class="cyan">→</span>
            protection layer active
          </div>

        </div>

      </div>

    </section>

  </main>


  <!-- =========================================================
       FOOTER
  ========================================================== -->

  <footer>
    © 2026 <span>Routix</span> — Cloud WAF & Application Protection
  </footer>


  <!-- =========================================================
       JAVASCRIPT
  ========================================================== -->

  <script>

    /* =========================================================
       AUTH SERVER
    ========================================================== */

    const AUTH_SERVER =
      "https://production-1-54qv.onrender.com";


    let loginEmail = "";


    /* =========================================================
       INTRO
    ========================================================== */

    function enterPlatform() {

      const intro =
        document.getElementById("intro");

      intro.classList.add("hidden");

      setTimeout(() => {

        intro.style.display = "none";

      }, 750);
    }


    /* =========================================================
       OPTIONAL LOGIN
    ========================================================== */

    function openLogin() {

      const overlay =
        document.getElementById("loginOverlay");

      overlay.classList.add("active");

      overlay.setAttribute(
        "aria-hidden",
        "false"
      );

      setTimeout(() => {

        const email =
          document.getElementById("loginEmail");

        if (email) {
          email.focus();
        }

      }, 250);
    }


    function closeLogin() {

      const overlay =
        document.getElementById("loginOverlay");

      overlay.classList.remove("active");

      overlay.setAttribute(
        "aria-hidden",
        "true"
      );

      clearLoginMessage();
    }


    /* =========================================================
       LOGIN MESSAGE
    ========================================================== */

    function showLoginMessage(
      message,
      type = "info"
    ) {

      const box =
        document.getElementById("loginMessage");

      box.textContent = message;

      box.className =
        "login-message " + type;
    }


    function clearLoginMessage() {

      const box =
        document.getElementById("loginMessage");

      box.textContent = "";

      box.className =
        "login-message info";
    }


    /* =========================================================
       SEND OTP
    ========================================================== */

    async function sendOTP() {

      const emailInput =
        document.getElementById("loginEmail");

      const button =
        document.getElementById("sendOtpButton");

      const email =
        emailInput.value.trim().toLowerCase();


      if (!email) {

        showLoginMessage(
          "أدخل بريدك الإلكتروني أولاً.",
          "error"
        );

        emailInput.focus();

        return;
      }


      const emailPattern =
        /^[^\s@]+@[^\s@]+\.[^\s@]+$/;


      if (!emailPattern.test(email)) {

        showLoginMessage(
          "يرجى إدخال بريد إلكتروني صحيح.",
          "error"
        );

        emailInput.focus();

        return;
      }


      loginEmail = email;

      button.disabled = true;


      showLoginMessage(
        "جاري إرسال رمز التحقق...",
        "info"
      );


      try {

        const response =
          await fetch(
            `${AUTH_SERVER}/api/send-otp`,
            {
              method: "POST",

              headers: {
                "Content-Type":
                  "application/json"
              },

              body: JSON.stringify({
                email: loginEmail
              })
            }
          );


        const data =
          await response
            .json()
            .catch(() => ({}));


        if (
          !response.ok ||
          !data.success
        ) {

          throw new Error(
            data.message ||
            "تعذر إرسال رمز التحقق."
          );
        }


        showLoginMessage(
          "تم إرسال رمز التحقق إلى بريدك الإلكتروني.",
          "success"
        );


        document
          .getElementById("emailStep")
          .style.display = "none";


        document
          .getElementById("otpStep")
          .style.display = "block";


        const otpInput =
          document.getElementById("loginOtp");


        otpInput.value = "";


        setTimeout(() => {

          otpInput.focus();

        }, 100);


      } catch (error) {

        console.error(
          "ROUTIX AUTH / SEND OTP:",
          error
        );


        showLoginMessage(
          error.message ||
          "حدث خطأ أثناء الاتصال بسيرفر المصادقة.",
          "error"
        );

      } finally {

        button.disabled = false;

      }
    }


    /* =========================================================
       VERIFY OTP
    ========================================================== */

    async function verifyOTP() {

      const otpInput =
        document.getElementById("loginOtp");

      const button =
        document.getElementById("verifyOtpButton");


      const otp =
        otpInput.value.trim();


      if (!loginEmail) {

        showLoginMessage(
          "يرجى إدخال البريد الإلكتروني أولاً.",
          "error"
        );

        backToEmail();

        return;
      }


      if (!/^\d{6}$/.test(otp)) {

        showLoginMessage(
          "رمز التحقق يجب أن يتكون من 6 أرقام.",
          "error"
        );

        otpInput.focus();

        return;
      }


      button.disabled = true;


      showLoginMessage(
        "جاري التحقق من الرمز...",
        "info"
      );


      try {

        const response =
          await fetch(
            `${AUTH_SERVER}/api/verify-otp`,
            {
              method: "POST",

              headers: {
                "Content-Type":
                  "application/json"
              },

              body: JSON.stringify({
                email: loginEmail,
                otp: otp
              })
            }
          );


        const data =
          await response
            .json()
            .catch(() => ({}));


        if (
          !response.ok ||
          !data.success
        ) {

          throw new Error(
            data.message ||
            "رمز التحقق غير صحيح."
          );
        }


        /*
         * السيرفر الحالي يعيد JWT.
         *
         * يتم حفظه في sessionStorage
         * وليس localStorage.
         */

        if (data.token) {

          sessionStorage.setItem(
            "routix_auth_token",
            data.token
          );

        }


        sessionStorage.setItem(
          "routix_auth_email",
          loginEmail
        );


        updateLoggedUser();


        showLoginMessage(
          "تم تسجيل الدخول بنجاح.",
          "success"
        );


        setTimeout(() => {

          closeLogin();

        }, 700);


      } catch (error) {

        console.error(
          "ROUTIX AUTH / VERIFY OTP:",
          error
        );


        showLoginMessage(
          error.message ||
          "حدث خطأ أثناء التحقق.",
          "error"
        );

      } finally {

        button.disabled = false;

      }
    }


    /* =========================================================
       BACK TO EMAIL
    ========================================================== */

    function backToEmail() {

      document
        .getElementById("otpStep")
        .style.display = "none";


      document
        .getElementById("emailStep")
        .style.display = "block";


      document
        .getElementById("loginOtp")
        .value = "";


      clearLoginMessage();


      setTimeout(() => {

        document
          .getElementById("loginEmail")
          .focus();

      }, 100);
    }


    /* =========================================================
       SESSION
    ========================================================== */

    function getAuthToken() {

      return sessionStorage.getItem(
        "routix_auth_token"
      );
    }


    function getAuthEmail() {

      return sessionStorage.getItem(
        "routix_auth_email"
      );
    }


    /* =========================================================
       UPDATE HEADER USER
    ========================================================== */

    function updateLoggedUser() {

      const token =
        getAuthToken();

      const email =
        getAuthEmail();


      const userBox =
        document.getElementById(
          "headerUser"
        );


      const loginButton =
        document.getElementById(
          "headerLogin"
        );


      const emailBox =
        document.getElementById(
          "headerEmail"
        );


      if (token && email) {

        userBox.classList.add(
          "show"
        );

        loginButton.style.display =
          "none";

        emailBox.textContent =
          email;

      } else {

        userBox.classList.remove(
          "show"
        );

        loginButton.style.display =
          "inline-flex";

      }
    }


    /* =========================================================
       CHECK SESSION WITH SERVER
    ========================================================== */

    async function checkRoutixSession() {

      const token =
        getAuthToken();


      if (!token) {

        updateLoggedUser();

        return false;
      }


      try {

        const response =
          await fetch(
            `${AUTH_SERVER}/api/profile`,
            {
              method: "GET",

              headers: {
                "Authorization":
                  `Bearer ${token}`
              }
            }
          );


        if (!response.ok) {

          sessionStorage.removeItem(
            "routix_auth_token"
          );

          sessionStorage.removeItem(
            "routix_auth_email"
          );

          updateLoggedUser();

          return false;
        }


        const data =
          await response.json();


        if (data.success) {

          if (data.email) {

            sessionStorage.setItem(
              "routix_auth_email",
              data.email
            );

          }


          updateLoggedUser();

          return true;
        }


      } catch (error) {

        console.error(
          "ROUTIX SESSION CHECK:",
          error
        );

      }


      updateLoggedUser();

      return false;
    }


    /* =========================================================
       LOGOUT
    ========================================================== */

    function logoutRoutix() {

      sessionStorage.removeItem(
        "routix_auth_token"
      );


      sessionStorage.removeItem(
        "routix_auth_email"
      );


      loginEmail = "";


      updateLoggedUser();


      showLoginMessage(
        "تم تسجيل الخروج.",
        "success"
      );
    }


    /* =========================================================
       AUTHENTICATED FETCH
    ========================================================== */

    async function routixFetch(
      url,
      options = {}
    ) {

      const token =
        getAuthToken();


      const headers = {
        ...(options.headers || {})
      };


      if (token) {

        headers["Authorization"] =
          `Bearer ${token}`;

      }


      return fetch(
        url,
        {
          ...options,
          headers
        }
      );
    }


    /* =========================================================
       MOBILE MENU
    ========================================================== */

    function toggleMenu() {

      const nav =
        document.getElementById("nav");

      nav.classList.toggle(
        "mobile-open"
      );
    }


    document
      .querySelectorAll("#nav a")
      .forEach(link => {

        link.addEventListener(
          "click",
          () => {

            document
              .getElementById("nav")
              .classList.remove(
                "mobile-open"
              );

          }
        );

      });


    /* =========================================================
       CYBER PARTICLES
    ========================================================== */

    const particles =
      document.getElementById(
        "particles"
      );


    for (
      let i = 0;
      i < 32;
      i++
    ) {

      const p =
        document.createElement("span");


      p.className =
        "particle";


      p.style.left =
        Math.random() * 100 + "%";


      p.style.top =
        (40 + Math.random() * 60) + "%";


      p.style.animationDelay =
        (Math.random() * 8) + "s";


      p.style.animationDuration =
        (5 + Math.random() * 7) + "s";


      particles.appendChild(p);

    }


    /* =========================================================
       ESCAPE
    ========================================================== */

    document.addEventListener(
      "keydown",
      event => {

        if (event.key === "Escape") {

          document
            .getElementById("nav")
            .classList.remove(
              "mobile-open"
            );


          closeLogin();

        }

      }
    );


    /* =========================================================
       ENTER KEY
    ========================================================== */

    document.addEventListener(
      "DOMContentLoaded",
      () => {

        const email =
          document.getElementById(
            "loginEmail"
          );


        const otp =
          document.getElementById(
            "loginOtp"
          );


        if (email) {

          email.addEventListener(
            "keydown",
            event => {

              if (
                event.key === "Enter"
              ) {

                sendOTP();

              }

            }
          );

        }


        if (otp) {

          otp.addEventListener(
            "input",
            () => {

              otp.value =
                otp.value
                  .replace(/\D/g, "")
                  .slice(0, 6);

            }
          );


          otp.addEventListener(
            "keydown",
            event => {

              if (
                event.key === "Enter"
              ) {

                verifyOTP();

              }

            }
          );

        }


        /*
         * التحقق من الجلسة الموجودة.
         *
         * إذا لا توجد جلسة:
         * لا يحدث شيء.
         *
         * الموقع يبقى مفتوحًا طبيعيًا.
         */

        checkRoutixSession();

      }
    );

  </script>

</body>
</html>
