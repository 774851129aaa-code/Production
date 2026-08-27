document.addEventListener('DOMContentLoaded', () => {
  'use strict';

  const modeBadge = document.getElementById('modeBadge');
  const statRisk = document.getElementById('statRisk');
  const statDrifts = document.getElementById('statDrifts');
  const logsBox = document.getElementById('logsBox');
  const baselineList = document.getElementById('baselineList');
  const domainsList = document.getElementById('domainsList');

  /*
   * التأكد من أن TBP Agent تم تحميله
   */
  function isAgentReady() {
    return (
      window.__TBP_STATE__ &&
      typeof window.__TBP_STATE__.getState === 'function' &&
      typeof window.__TBP_STATE__.getBaseline === 'function'
    );
  }

  /*
   * تحديث حالة Mode في الواجهة
   */
  function updateModeBadge(mode) {
    if (!modeBadge) return;

    const safeMode =
      mode === 'protection'
        ? 'protection'
        : 'learning';

    modeBadge.textContent =
      `${safeMode.toUpperCase()} MODE`;

    modeBadge.className =
      `mode-badge mode-${safeMode}`;
  }

  /*
   * تحديث لون Risk Score
   */
  function updateRiskColor(score) {
    if (!statRisk) return;

    if (score >= 70) {
      statRisk.style.color = 'var(--red)';
    } else if (score >= 30) {
      statRisk.style.color = 'var(--yellow)';
    } else {
      statRisk.style.color = 'var(--green)';
    }
  }

  /*
   * تحديث قائمة Baseline
   */
  function renderBaseline(domains, scripts) {
    if (!baselineList) return;

    baselineList.innerHTML = '';

    if (
      (!domains || domains.length === 0) &&
      (!scripts || scripts.length === 0)
    ) {
      baselineList.textContent =
        'No baseline data yet.';
      return;
    }

    /*
     * Domains
     */
    for (const domain of domains || []) {
      const tag =
        document.createElement('span');

      tag.className = 'tag';
      tag.textContent = `🟢 ${domain}`;

      baselineList.appendChild(tag);
    }

    /*
     * Scripts
     */
    for (const script of scripts || []) {
      const tag =
        document.createElement('span');

      tag.className = 'tag';
      tag.textContent =
        `📜 ${script}`;

      baselineList.appendChild(tag);
    }
  }

  /*
   * تحديث Observed Domains
   */
  function renderObservedDomains(
    observedDomains,
    baselineDomains
  ) {
    if (!domainsList) return;

    domainsList.innerHTML = '';

    if (
      !observedDomains ||
      observedDomains.length === 0
    ) {
      domainsList.textContent =
        'No domains observed yet.';
      return;
    }

    const baselineSet =
      new Set(baselineDomains || []);

    for (
      const domain
      of observedDomains
    ) {
      const tag =
        document.createElement('span');

      tag.className = 'tag';

      const trusted =
        baselineSet.has(domain);

      tag.textContent =
        `${trusted ? '🟢' : '🔴'} ${domain}`;

      domainsList.appendChild(tag);
    }
  }

  /*
   * تحديث Dashboard بالكامل
   */
  function updateUI() {
    if (!isAgentReady()) {
      return;
    }

    try {
      const state =
        window.__TBP_STATE__.getState();

      const baseline =
        window.__TBP_STATE__.getBaseline();

      /*
       * Risk
       */
      const risk =
        Number(state.riskScore) || 0;

      if (statRisk) {
        statRisk.textContent =
          `${risk} / 100`;

        updateRiskColor(risk);
      }

      /*
       * Drifts
       */
      if (statDrifts) {
        statDrifts.textContent =
          String(
            Number(state.driftsDetected) || 0
          );
      }

      /*
       * Mode
       */
      if (state.mode) {
        updateModeBadge(state.mode);
      }

      /*
       * Baseline
       */
      renderBaseline(
        baseline.domains || [],
        baseline.scripts || []
      );

      /*
       * Observed domains
       */
      renderObservedDomains(
        state.observedDomains || [],
        baseline.domains || []
      );

    } catch (error) {
      console.error(
        'TBP Dashboard update error:',
        error
      );
    }
  }

  /*
   * إضافة Log للواجهة
   */
  function addLog(entry) {
    if (!logsBox || !entry) {
      return;
    }

    const item =
      document.createElement('div');

    item.className =
      `log-item log-${entry.type || 'info'}`;

    /*
     * textContent وليس innerHTML
     * لمنع HTML injection داخل لوحة التحكم.
     */
    item.textContent =
      `[${entry.time || '--:--:--'}] ${entry.message || ''}`;

    logsBox.prepend(item);

    /*
     * الاحتفاظ بآخر 100 Log فقط
     */
    while (
      logsBox.children.length > 100
    ) {
      logsBox.removeChild(
        logsBox.lastElementChild
      );
    }
  }

  /*
   * استقبال Logs من TBP Agent
   */
  window.addEventListener(
    'TBP_LOG_EVENT',
    event => {
      try {
        addLog(event.detail);
        updateUI();
      } catch (error) {
        console.error(
          'TBP log processing error:',
          error
        );
      }
    }
  );

  /*
   * تغيير Learning / Protection
   */
  window.toggleMode =
    function (mode) {

      if (!isAgentReady()) {
        console.warn(
          'TBP Agent is not ready.'
        );
        return;
      }

      if (
        mode !== 'learning' &&
        mode !== 'protection'
      ) {
        console.warn(
          'Invalid TBP mode.'
        );
        return;
      }

      try {

        const changed =
          window.__TBP_STATE__.setMode(
            mode
          );

        if (changed === false) {
          return;
        }

        updateModeBadge(mode);

        updateUI();

      } catch (error) {

        console.error(
          'TBP mode change failed:',
          error
        );

      }
    };

  /*
   * اختبار Network Request
   */
  window.testRealFetch =
    function (url) {

      if (
        typeof url !== 'string' ||
        !url
      ) {
        return;
      }

      try {

        fetch(url, {
          method: 'GET',
          credentials: 'omit'
        }).catch(() => {

          /*
           * فشل الطلب لا يعني أن Agent فشل.
           * المهم أن Agent قام برصد محاولة الطلب.
           */

        });

      } catch (error) {

        console.error(
          'Test request failed:',
          error
        );

      }
    };

  /*
   * اختبار Dynamic Script
   */
  window.testRealScriptInjection =
    function () {

      try {

        const script =
          document.createElement('script');

        script.src =
          `https://untrusted-analytics-${Math.random()
            .toString(36)
            .substring(2, 10)}.example.invalid/tracker.js`;

        script.async = true;

        /*
         * هذا الاختبار يستخدم نطاقاً غير صالح
         * حتى لا نعتمد على تحميل سكربت حقيقي.
         *
         * Agent يجب أن يرصد إضافة العنصر
         * قبل محاولة تحميله.
         */

        document.body.appendChild(script);

      } catch (error) {

        console.error(
          'Script injection test failed:',
          error
        );

      }
    };

  /*
   * اختبار الحقل الحساس
   *
   * لا تتم قراءة قيمة كلمة المرور هنا.
   */
  const passwordInput =
    document.getElementById(
      'userPassword'
    );

  if (passwordInput) {

    passwordInput.addEventListener(
      'focus',
      () => {

        console.info(
          'TBP sensitive-field test activated.'
        );

      }
    );
  }

  /*
   * محاولة أولية لتحديث الواجهة
   */
  updateUI();

  /*
   * تحديث دوري
   */
  setInterval(
    updateUI,
    1000
  );

});
