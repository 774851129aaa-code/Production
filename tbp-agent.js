/**
 * Third-Party Behavioral Passport (TBP) - Client-Side Security Agent
 * Behavioral Detection & Monitoring Layer (Privacy-Preserving)
 */
(function () {
  'use strict';

  if (window.__TBP_AGENT_LOADED__) return;
  window.__TBP_AGENT_LOADED__ = true;

  // جلب الإعدادات الممررة من سمات سكريبت التضمين
  const scriptTag = document.currentScript || document.querySelector('script[data-gateway]');
  const config = {
    gateway: scriptTag ? scriptTag.getAttribute('data-gateway') : 'http://localhost:3000/api/v1/telemetry',
    siteKey: scriptTag ? scriptTag.getAttribute('data-sitekey') : '',
    mode: scriptTag ? (scriptTag.getAttribute('data-mode') || 'learning') : 'learning' // learning أو protection
  };

  const currentDomain = window.location.hostname || 'localhost';

  // الـ Baseline الحقيقي (يتم ملؤه تلقائياً في وضع التعلم أو تحميله)
  let baseline = {
    domains: new Set([currentDomain]),
    scripts: new Set(),
    requestCounts: {}
  };

  // محاولة استرجاع الـ Baseline المخزن محلياً للموقع
  const STORAGE_KEY = `tbp_baseline_${currentDomain}`;
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved) {
      const parsed = JSON.parse(saved);
      baseline.domains = new Set(parsed.domains || [currentDomain]);
      baseline.scripts = new Set(parsed.scripts || []);
    }
  } catch (e) {}

  let state = {
    riskScore: 0,
    driftsDetected: 0,
    observedDomains: new Set([currentDomain]),
    logs: []
  };

  function persistBaseline() {
    if (config.mode === 'learning') {
      try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify({
          domains: [...baseline.domains],
          scripts: [...baseline.scripts]
        }));
      } catch (e) {}
    }
  }

  function emitLog(message, type = 'info') {
    const logEntry = { time: new Date().toLocaleTimeString(), message, type };
    state.logs.unshift(logEntry);
    if (state.logs.length > 100) state.logs.pop();
    window.dispatchEvent(new CustomEvent('TBP_LOG_EVENT', { detail: logEntry }));
  }

  // 1. نظام حساب المخاطر الحقيقي (Risk Engine)
  function calculateRisk(factorType, details) {
    let weight = 0;
    switch (factorType) {
      case 'DOMAIN_NOVELTY':
        weight = 35; // دومين جديد لم يمر به الموقع من قبل
        break;
      case 'SCRIPT_NOVELTY':
        weight = 30; // سكريبت خارجي جديد
        break;
      case 'SENSITIVE_DOM_ACCESS':
        weight = 20; // وصول لحقل حساس
        break;
      case 'HIGH_FREQUENCY':
        weight = 15; // تكرار مفرط للطلبات
        break;
      default:
        weight = 10;
    }

    state.riskScore = Math.min(100, state.riskScore + weight);
    return state.riskScore;
  }

  // إرسال الـ Metadata عبر البوابة الآمنة (Gateway) إلى تليجرام
  function dispatchAlert(eventTitle, destination) {
    if (config.mode !== 'protection') return; // لا تُرسل تنبيهات في وضع التعلم

    const payload = {
      site: currentDomain,
      event: eventTitle,
      destination: destination,
      risk: state.riskScore,
      mode: config.mode.toUpperCase(),
      time: new Date().toISOString()
    };

    // إرسال عبر sendBeacon أو fetch للخلفية
    if (navigator.sendBeacon) {
      const blob = new Blob([JSON.stringify(payload)], { type: 'application/json' });
      navigator.sendBeacon(config.gateway, blob);
    } else {
      fetch(config.gateway, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-site-key': config.siteKey
        },
        body: JSON.stringify(payload),
        keepalive: true
      }).catch(() => {});
    }
  }

  // 2. مراقبة طلبات الشبكة الحقيقية (Fetch & XHR & Beacon)
  const _nativeFetch = window.fetch;
  window.fetch = function (...args) {
    const urlStr = typeof args[0] === 'string' ? args[0] : (args[0]?.url || '');
    if (urlStr) {
      try {
        const targetUrl = new URL(urlStr, window.location.href);
        const domain = targetUrl.hostname;
        state.observedDomains.add(domain);

        // فحص التردد (Frequency check)
        const now = Date.now();
        baseline.requestCounts[domain] = baseline.requestCounts[domain] || [];
        baseline.requestCounts[domain] = baseline.requestCounts[domain].filter(t => now - t < 10000);
        baseline.requestCounts[domain].push(now);
        const isHighFreq = baseline.requestCounts[domain].length > 8;

        if (!baseline.domains.has(domain)) {
          if (config.mode === 'learning') {
            baseline.domains.add(domain);
            persistBaseline();
            emitLog(`[Learning] New safe domain registered: ${domain}`, 'info');
          } else {
            const risk = calculateRisk('DOMAIN_NOVELTY', domain);
            if (isHighFreq) calculateRisk('HIGH_FREQUENCY', domain);
            state.driftsDetected++;
            emitLog(`[Drift] Unauthorized network request to: ${domain} (Risk: ${risk})`, 'danger');
            dispatchAlert('UNAUTHORIZED_NETWORK_REQUEST', domain);
          }
        } else if (isHighFreq && config.mode === 'protection') {
          const risk = calculateRisk('HIGH_FREQUENCY', domain);
          emitLog(`[Drift] High frequency requests detected for: ${domain}`, 'warn');
          dispatchAlert('HIGH_FREQUENCY_ANOMALY', domain);
        }
      } catch (e) {}
    }
    return _nativeFetch.apply(this, args);
  };

  const _nativeOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function (method, url) {
    if (url) {
      try {
        const domain = new URL(url, window.location.href).hostname;
        state.observedDomains.add(domain);
        if (!baseline.domains.has(domain)) {
          if (config.mode === 'learning') {
            baseline.domains.add(domain);
            persistBaseline();
          } else {
            const risk = calculateRisk('DOMAIN_NOVELTY', domain);
            state.driftsDetected++;
            emitLog(`[Drift] Unauthorized XHR to: ${domain} (Risk: ${risk})`, 'danger');
            dispatchAlert('UNAUTHORIZED_XHR', domain);
          }
        }
      } catch (e) {}
    }
    return _nativeOpen.apply(this, arguments);
  };

  // مراقبة sendBeacon
  const _nativeBeacon = navigator.sendBeacon;
  if (_nativeBeacon) {
    navigator.sendBeacon = function (url, data) {
      if (url) {
        try {
          const domain = new URL(url, window.location.href).hostname;
          if (!baseline.domains.has(domain) && config.mode === 'protection') {
            const risk = calculateRisk('DOMAIN_NOVELTY', domain);
            emitLog(`[Drift] Unauthorized sendBeacon to: ${domain}`, 'danger');
            dispatchAlert('UNAUTHORIZED_SENDBEACON', domain);
          }
        } catch (e) {}
      }
      return _nativeBeacon.apply(this, arguments);
    };
  }

  // 3. مراقبة الوصول البرمجي للحقول الحساسة (Metadata Only - Privacy Preserving)
  const valDescriptor = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');
  if (valDescriptor && valDescriptor.get) {
    Object.defineProperty(HTMLInputElement.prototype, 'value', {
      configurable: true,
      get: function () {
        const isSensitive = this.type === 'password' || 
                            /card|cvv|secret|token|pass|cc|auth/i.test(this.name || '') || 
                            /card|cvv|secret|token|pass|cc|auth/i.test(this.id || '');
        if (isSensitive && config.mode === 'protection') {
          const risk = calculateRisk('SENSITIVE_DOM_ACCESS');
          emitLog(`[Security] Sensitive DOM access on field ID: #${this.id || 'unnamed'} (Metadata Only)`, 'warn');
          dispatchAlert('SENSITIVE_DOM_ACCESS', `Field ID: #${this.id || 'N/A'} (Name: ${this.name || 'N/A'})`);
        }
        return valDescriptor.get.call(this);
      },
      set: valDescriptor.set
    });
  }

  // 4. مراقبة الحقن الديناميكي للسكريبتات (Dynamic Script Injection)
  const observer = new MutationObserver(mutations => {
    mutations.forEach(m => {
      m.addedNodes.forEach(node => {
        if (node.nodeType === 1 && node.tagName === 'SCRIPT') {
          const src = node.src || 'inline-script';
          if (!baseline.scripts.has(src)) {
            if (config.mode === 'learning') {
              baseline.scripts.add(src);
              persistBaseline();
              emitLog(`[Learning] New script source registered: ${src}`, 'info');
            } else {
              const risk = calculateRisk('SCRIPT_NOVELTY', src);
              state.driftsDetected++;
              emitLog(`[Drift] Dynamic script injection detected: ${src} (Risk: ${risk})`, 'danger');
              dispatchAlert('DYNAMIC_SCRIPT_INJECTION', src);
            }
          }
        }
      });
    });
  });
  observer.observe(document.documentElement, { childList: true, subtree: true });

  // تصدير واجهة برمجية خفيفة للاستعلام من الـ Dashboard
  window.__TBP_STATE__ = {
    getState: () => state,
    getBaseline: () => baseline,
    setMode: (m) => { config.mode = m; emitLog(`Mode switched to: ${m.toUpperCase()}`, 'info'); }
  };

  emitLog(`TBP Agent initialized in [${config.mode.toUpperCase()}] mode.`, 'info');
})();
