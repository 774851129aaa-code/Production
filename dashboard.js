document.addEventListener('DOMContentLoaded', () => {
  const modeBadge = document.getElementById('modeBadge');
  const statRisk = document.getElementById('statRisk');
  const statDrifts = document.getElementById('statDrifts');
  const logsBox = document.getElementById('logsBox');
  const baselineList = document.getElementById('baselineList');
  const domainsList = document.getElementById('domainsList');

  function updateUI() {
    if (!window.__TBP_STATE__) return;
    const state = window.__TBP_STATE__.getState();
    const baseline = window.__TBP_STATE__.getBaseline();

    statRisk.textContent = `${state.riskScore} / 100`;
    statRisk.style.color = state.riskScore > 50 ? 'var(--red)' : (state.riskScore > 20 ? 'var(--yellow)' : 'var(--green)');
    statDrifts.textContent = state.driftsDetected;

    baselineList.innerHTML = [...baseline.domains].map(d => `<span class="tag">🟢 ${d}</span>`).join(' ');
    domainsList.innerHTML = [...state.observedDomains].map(d => `<span class="tag">${baseline.domains.has(d) ? '🟢' : '🔴'} ${d}</span>`).join(' ');
  }

  // الاستماع لأحداث اللوجز الصادرة من الـ Agent
  window.addEventListener('TBP_LOG_EVENT', (e) => {
    const { time, message, type } = e.detail;
    const item = document.createElement('div');
    item.className = `log-item log-${type}`;
    item.textContent = `[${time}] ${message}`;
    logsBox.prepend(item);
    updateUI();
  });

  // التبديل بين الأوضاع
  window.toggleMode = function(mode) {
    if (window.__TBP_STATE__) {
      window.__TBP_STATE__.setMode(mode);
      modeBadge.textContent = `${mode.toUpperCase()} MODE`;
      modeBadge.className = `mode-badge mode-${mode}`;
    }
  };

  // دوال اختبار حقيقية لتقييم الـ Agent
  window.testRealFetch = function(url) {
    fetch(url).catch(() => {});
  };

  window.testRealScriptInjection = function() {
    const s = document.createElement('script');
    s.src = `https://untrusted-analytics-${Math.random().toString(36).substring(7)}.com/tracker.js`;
    document.body.appendChild(s);
  };

  setInterval(updateUI, 1000);
});
