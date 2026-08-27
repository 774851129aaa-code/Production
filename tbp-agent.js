/**
 * TBP
 * Third-Party Behavioral Passport
 *
 * Client-side behavioral security sensor.
 *
 * IMPORTANT:
 * Browser JavaScript is not fully tamper-proof.
 * The authoritative security policy must remain server-side.
 */

(function () {
  'use strict';

  if (window.__TBP_AGENT_LOADED__) {
    return;
  }

  const scriptTag =
    document.currentScript ||
    document.querySelector('script[data-gateway]');

  const config = Object.freeze({

    gateway:
      scriptTag?.getAttribute('data-gateway') ||
      '/api/v1/telemetry',

    siteId:
      scriptTag?.getAttribute('data-site-id') ||
      'default-site',

    mode:
      scriptTag?.getAttribute('data-mode') === 'learning'
        ? 'learning'
        : 'protection'
  });

  const currentDomain =
    window.location.hostname || 'localhost';

  const state = {
    riskScore: 0,
    driftsDetected: 0,

    observedDomains:
      new Set([currentDomain]),

    logs: []
  };

  const baseline = {

    domains:
      new Set([currentDomain]),

    scripts:
      new Set(),

    requestCounts:
      Object.create(null)
  };

  const alertCache = new Map();

  function emitLog(message, type = 'info') {

    const entry = Object.freeze({
      time:
        new Date().toLocaleTimeString(),

      message:
        String(message),

      type
    });

    state.logs.unshift(entry);

    if (state.logs.length > 100) {
      state.logs.pop();
    }

    try {

      window.dispatchEvent(
        new CustomEvent(
          'TBP_LOG_EVENT',
          {
            detail: entry
          }
        )
      );

    } catch (_) {}
  }

  function calculateRisk(type) {

    const weights = {

      DOMAIN_NOVELTY: 35,

      SCRIPT_NOVELTY: 30,

      SENSITIVE_DOM_ACCESS: 20,

      HIGH_FREQUENCY: 15,

      UNKNOWN: 10
    };

    state.riskScore =
      Math.min(
        100,
        state.riskScore +
          (weights[type] || weights.UNKNOWN)
      );

    return state.riskScore;
  }

  function shouldAlert(
    event,
    destination
  ) {

    const key =
      `${event}|${destination}`;

    const now = Date.now();

    const previous =
      alertCache.get(key);

    if (
      previous &&
      now - previous < 60_000
    ) {
      return false;
    }

    alertCache.set(
      key,
      now
    );

    return true;
  }

  function getDomain(url) {

    try {

      return new URL(
        url,
        window.location.href
      ).hostname;

    } catch (_) {

      return null;
    }
  }

  function dispatchAlert(
    eventTitle,
    destination
  ) {

    if (
      config.mode !==
      'protection'
    ) {
      return;
    }

    if (
      !shouldAlert(
        eventTitle,
        destination
      )
    ) {
      return;
    }

    const payload = {

      site:
        currentDomain,

      siteId:
        config.siteId,

      event:
        eventTitle,

      destination:
        String(
          destination ||
          'unknown'
        ),

      risk:
        state.riskScore,

      mode:
        'PROTECTION',

      time:
        new Date().toISOString()
    };

    /*
     * Native fetch is used so the telemetry
     * request does not trigger our own sensor.
     */

    nativeFetch(
      config.gateway,
      {
        method: 'POST',

        headers: {
          'Content-Type':
            'application/json'
        },

        body:
          JSON.stringify(payload),

        keepalive:
          true,

        credentials:
          'omit'
      }
    ).catch(() => {});
  }

  function isGateway(url) {

    const target =
      getDomain(url);

    const gateway =
      getDomain(
        config.gateway
      );

    return (
      target &&
      gateway &&
      target === gateway
    );
  }

  function checkFrequency(domain) {

    const now =
      Date.now();

    if (
      !baseline.requestCounts[domain]
    ) {

      baseline.requestCounts[domain] =
        [];
    }

    baseline.requestCounts[domain] =
      baseline.requestCounts[domain]
        .filter(
          timestamp =>
            now - timestamp < 10_000
        );

    baseline.requestCounts[domain]
      .push(now);

    return (
      baseline.requestCounts[domain]
        .length > 8
    );
  }

  function inspectNetwork(
    url,
    source
  ) {

    const domain =
      getDomain(url);

    if (!domain) {
      return;
    }

    if (isGateway(url)) {
      return;
    }

    state.observedDomains.add(
      domain
    );

    const highFrequency =
      checkFrequency(domain);

    if (
      config.mode ===
      'learning'
    ) {

      if (
        !baseline.domains.has(
          domain
        )
      ) {

        baseline.domains.add(
          domain
        );

        emitLog(
          `[Learning] Registered domain: ${domain}`,
          'info'
        );
      }

      return;
    }

    if (
      !baseline.domains.has(
        domain
      )
    ) {

      const risk =
        calculateRisk(
          'DOMAIN_NOVELTY'
        );

      state.driftsDetected++;

      emitLog(
        `[Drift] Unauthorized ${source} request: ${domain} (Risk: ${risk})`,
        'danger'
      );

      dispatchAlert(
        `UNAUTHORIZED_${source}`,
        domain
      );

      return;
    }

    if (highFrequency) {

      const risk =
        calculateRisk(
          'HIGH_FREQUENCY'
        );

      emitLog(
        `[Anomaly] High request frequency: ${domain} (Risk: ${risk})`,
        'warn'
      );

      dispatchAlert(
        'HIGH_FREQUENCY_ANOMALY',
        domain
      );
    }
  }

  /*
   * Save native APIs before hooking them.
   */

  const nativeFetch =
    window.fetch.bind(window);

  const nativeXHROpen =
    XMLHttpRequest.prototype.open;

  const nativeBeacon =
    navigator.sendBeacon
      ? navigator.sendBeacon.bind(
          navigator
        )
      : null;

  /*
   * FETCH
   */

  window.fetch =
    function (...args) {

      try {

        const input =
          args[0];

        const url =
          typeof input === 'string'
            ? input
            : input?.url;

        if (url) {

          inspectNetwork(
            url,
            'FETCH'
          );
        }

      } catch (_) {}

      return nativeFetch(
        ...args
      );
    };

  /*
   * XHR
   */

  XMLHttpRequest.prototype.open =
    function (
      method,
      url,
      ...rest
    ) {

      try {

        if (url) {

          inspectNetwork(
            String(url),
            'XHR'
          );
        }

      } catch (_) {}

      return nativeXHROpen.call(
        this,
        method,
        url,
        ...rest
      );
    };

  /*
   * Beacon
   */

  if (nativeBeacon) {

    navigator.sendBeacon =
      function (
        url,
        data
      ) {

        try {

          if (url) {

            inspectNetwork(
              String(url),
              'BEACON'
            );
          }

        } catch (_) {}

        return nativeBeacon(
          url,
          data
        );
      };
  }

  /*
   * Sensitive fields
   *
   * Never reads or sends actual values.
   */

  const valueDescriptor =
    Object.getOwnPropertyDescriptor(
      HTMLInputElement.prototype,
      'value'
    );

  if (
    valueDescriptor &&
    valueDescriptor.get &&
    valueDescriptor.set
  ) {

    Object.defineProperty(
      HTMLInputElement.prototype,
      'value',
      {

        configurable:
          true,

        get:
          function () {

            try {

              const sensitive =
                this.type ===
                  'password' ||

                /card|cvv|secret|token|pass|cc|auth/i
                  .test(
                    this.name || ''
                  ) ||

                /card|cvv|secret|token|pass|cc|auth/i
                  .test(
                    this.id || ''
                  );

              /*
               * Metadata only.
               *
               * No input value is captured.
               */

              if (
                sensitive &&
                config.mode ===
                  'protection'
              ) {

                emitLog(
                  `[Security] Sensitive field accessed: #${this.id || 'unnamed'}`,
                  'info'
                );
              }

            } catch (_) {}

            return valueDescriptor.get
              .call(this);
          },

        set:
          function (value) {

            return valueDescriptor.set
              .call(
                this,
                value
              );
          }
      }
    );
  }

  /*
   * Dynamic scripts
   */

  const observer =
    new MutationObserver(
      mutations => {

        for (
          const mutation
          of mutations
        ) {

          for (
            const node
            of mutation.addedNodes
          ) {

            if (
              node.nodeType !== 1 ||
              node.tagName !==
                'SCRIPT'
            ) {
              continue;
            }

            const src =
              node.src ||
              'inline-script';

            if (
              config.mode ===
              'learning'
            ) {

              if (
                !baseline.scripts
                  .has(src)
              ) {

                baseline.scripts
                  .add(src);

                emitLog(
                  `[Learning] Script registered: ${src}`,
                  'info'
                );
              }

              continue;
            }

            if (
              !baseline.scripts
                .has(src)
            ) {

              const risk =
                calculateRisk(
                  'SCRIPT_NOVELTY'
                );

              state.driftsDetected++;

              emitLog(
                `[Drift] New dynamic script: ${src} (Risk: ${risk})`,
                'danger'
              );

              dispatchAlert(
                'DYNAMIC_SCRIPT_INJECTION',
                src
              );
            }
          }
        }
      }
    );

  if (
    document.documentElement
  ) {

    observer.observe(
      document.documentElement,
      {
        childList:
          true,

        subtree:
          true
      }
    );
  }

  /*
   * Read-only dashboard API
   */

  const publicState = {

    getState() {

      return Object.freeze({

        riskScore:
          state.riskScore,

        driftsDetected:
          state.driftsDetected,

        observedDomains:
          [
            ...state.observedDomains
          ],

        logs:
          [
            ...state.logs
          ]
      });
    },

    getBaseline() {

      return Object.freeze({

        domains:
          [
            ...baseline.domains
          ],

        scripts:
          [
            ...baseline.scripts
          ]
      });
    }
  };

  try {

    Object.defineProperty(
      window,
      '__TBP_STATE__',
      {

        value:
          Object.freeze(
            publicState
          ),

        writable:
          false,

        configurable:
          false,

        enumerable:
          false
      }
    );

  } catch (_) {}

  emitLog(
    `TBP Sensor initialized [${config.mode.toUpperCase()}]`,
    'info'
  );

  try {

    Object.defineProperty(
      window,
      '__TBP_AGENT_LOADED__',
      {

        value:
          true,

        writable:
          false,

        configurable:
          false,

        enumerable:
          false
      }
    );

  } catch (_) {

    window.__TBP_AGENT_LOADED__ =
      true;
  }

})();
