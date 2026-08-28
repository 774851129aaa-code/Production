'use strict';

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import http from "node:http";

import express, {
  type Request,
  type Response,
  type NextFunction
} from "express";

import helmet from "helmet";
import { z } from "zod";

import {
  createProxyMiddleware,
  fixRequestBody
} from "http-proxy-middleware";

/* ============================================================
   CONFIG
   ============================================================ */

const ConfigSchema = z.object({
  PORT: z.coerce.number().int().positive().default(8080),

  TARGET_URL: z.string().url(),

  WAF_API_KEY: z.string().min(20),

  ADMIN_USER: z.string().min(3),

  ADMIN_PASSWORD: z.string().min(12),

  DATA_FILE: z.string().default("waf-db.json"),

  TRUST_PROXY: z.coerce.boolean().default(false),

  RATE_LIMIT_WINDOW: z.coerce.number().int().positive().default(60),

  RATE_LIMIT_MAX: z.coerce.number().int().positive().default(120),

  BURST_WINDOW_MS: z.coerce.number().int().positive().default(1000),

  BURST_MAX: z.coerce.number().int().positive().default(15),

  GLOBAL_RATE_WINDOW_MS: z.coerce.number().int().positive().default(1000),

  GLOBAL_RATE_MAX: z.coerce.number().int().positive().default(2000),

  MAX_CONCURRENT_PER_IP: z.coerce.number().int().positive().default(30),

  MAX_GLOBAL_CONCURRENT: z.coerce.number().int().positive().default(1000),

  VIOLATION_LIMIT: z.coerce.number().int().positive().default(5),

  VIOLATION_WINDOW_MS: z.coerce.number().int().positive().default(60000),

  AUTO_BLACKLIST_SECONDS: z.coerce.number().int().positive().default(86400),

  RISK_BLOCK_THRESHOLD: z.coerce.number().int().positive().default(100),

  RISK_HONEYPOT_THRESHOLD: z.coerce.number().int().positive().default(70),

  RISK_TTL: z.coerce.number().int().positive().default(21600),

  BLACKLIST_TTL: z.coerce.number().int().positive().default(86400),

  MAX_BODY_SIZE: z.string().default("256kb"),

  REQUEST_TIMEOUT_MS: z.coerce.number().int().positive().default(15000),

  HEADERS_TIMEOUT_MS: z.coerce.number().int().positive().default(10000),

  KEEP_ALIVE_TIMEOUT_MS: z.coerce.number().int().positive().default(5000),

  PROXY_TIMEOUT_MS: z.coerce.number().int().positive().default(15000)
});

const config = ConfigSchema.parse({
  PORT: process.env.PORT,

  TARGET_URL: process.env.TARGET_URL,

  WAF_API_KEY: process.env.WAF_API_KEY,

  ADMIN_USER: process.env.ADMIN_USER,

  ADMIN_PASSWORD: process.env.ADMIN_PASSWORD,

  DATA_FILE: process.env.DATA_FILE,

  TRUST_PROXY: process.env.TRUST_PROXY,

  RATE_LIMIT_WINDOW: process.env.RATE_LIMIT_WINDOW,

  RATE_LIMIT_MAX: process.env.RATE_LIMIT_MAX,

  BURST_WINDOW_MS: process.env.BURST_WINDOW_MS,

  BURST_MAX: process.env.BURST_MAX,

  GLOBAL_RATE_WINDOW_MS: process.env.GLOBAL_RATE_WINDOW_MS,

  GLOBAL_RATE_MAX: process.env.GLOBAL_RATE_MAX,

  MAX_CONCURRENT_PER_IP: process.env.MAX_CONCURRENT_PER_IP,

  MAX_GLOBAL_CONCURRENT: process.env.MAX_GLOBAL_CONCURRENT,

  VIOLATION_LIMIT: process.env.VIOLATION_LIMIT,

  VIOLATION_WINDOW_MS: process.env.VIOLATION_WINDOW_MS,

  AUTO_BLACKLIST_SECONDS: process.env.AUTO_BLACKLIST_SECONDS,

  RISK_BLOCK_THRESHOLD: process.env.RISK_BLOCK_THRESHOLD,

  RISK_HONEYPOT_THRESHOLD: process.env.RISK_HONEYPOT_THRESHOLD,

  RISK_TTL: process.env.RISK_TTL,

  BLACKLIST_TTL: process.env.BLACKLIST_TTL,

  MAX_BODY_SIZE: process.env.MAX_BODY_SIZE,

  REQUEST_TIMEOUT_MS: process.env.REQUEST_TIMEOUT_MS,

  HEADERS_TIMEOUT_MS: process.env.HEADERS_TIMEOUT_MS,

  KEEP_ALIVE_TIMEOUT_MS: process.env.KEEP_ALIVE_TIMEOUT_MS,

  PROXY_TIMEOUT_MS: process.env.PROXY_TIMEOUT_MS
});

/* ============================================================
   DATABASE
   ============================================================ */

interface DbSchema {
  blacklists: Record<
    string,
    {
      reason: string;
      createdAt: string;
      expiresAt: number;
    }
  >;

  risks: Record<
    string,
    {
      score: number;
      expiresAt: number;
    }
  >;
}

const dbFilePath = path.resolve(
  process.cwd(),
  config.DATA_FILE
);

function emptyDb(): DbSchema {
  return {
    blacklists: {},
    risks: {}
  };
}

function loadDb(): DbSchema {
  try {
    if (!fs.existsSync(dbFilePath)) {
      return emptyDb();
    }

    const parsed = JSON.parse(
      fs.readFileSync(
        dbFilePath,
        "utf8"
      )
    );

    return {
      blacklists: parsed.blacklists || {},
      risks: parsed.risks || {}
    };
  } catch (error) {
    console.error(
      "Database load error:",
      error
    );

    return emptyDb();
  }
}

let db = loadDb();

let dbDirty = false;

function saveDb(): void {
  try {
    const now = Date.now();

    for (const [key, value] of Object.entries(
      db.blacklists
    )) {
      if (value.expiresAt < now) {
        delete db.blacklists[key];
      }
    }

    for (const [key, value] of Object.entries(
      db.risks
    )) {
      if (value.expiresAt < now) {
        delete db.risks[key];
      }
    }

    fs.writeFileSync(
      dbFilePath,
      JSON.stringify(
        db,
        null,
        2
      ),
      "utf8"
    );

    dbDirty = false;
  } catch (error) {
    console.error(
      "Database save error:",
      error
    );
  }
}

setInterval(
  () => {
    if (dbDirty) {
      saveDb();
    }
  },
  5000
);

/* ============================================================
   MEMORY RATE LIMITERS
   ============================================================ */

interface Counter {
  count: number;
  expiresAt: number;
}

const requestCounters =
  new Map<string, Counter>();

const burstCounters =
  new Map<string, Counter>();

const globalCounters =
  new Map<string, Counter>();

const violations =
  new Map<string, Counter>();

const concurrentByIp =
  new Map<string, number>();

let globalConcurrent = 0;

/* ============================================================
   LIVE ADMIN ALERTS
   ============================================================ */

interface WafAlert {
  id: string;
  time: string;
  ip: string;
  path: string;
  risk: number;
  action: Action;
  reasons: string[];
}

const alerts: WafAlert[] = [];

const alertClients =
  new Set<Response>();

const MAX_ALERTS = 200;

function addAlert(data: {
  ip: string;
  path: string;
  risk: number;
  action: Action;
  reasons: string[];
}): void {
  const alert: WafAlert = {
    id: crypto.randomUUID(),

    time: new Date().toISOString(),

    ip: data.ip,

    path: truncate(
      data.path,
      500
    ),

    risk: data.risk,

    action: data.action,

    reasons: data.reasons.slice(
      0,
      20
    )
  };

  alerts.unshift(alert);

  if (alerts.length > MAX_ALERTS) {
    alerts.length = MAX_ALERTS;
  }

  const payload =
    `data: ${JSON.stringify(
      alert
    )}\n\n`;

  for (const client of alertClients) {
    try {
      client.write(payload);
    } catch {
      alertClients.delete(client);
    }
  }
}

/* ============================================================
   MEMORY CLEANUP
   ============================================================ */

function cleanupMemory(): void {
  const now = Date.now();

  for (const [key, value] of requestCounters) {
    if (value.expiresAt < now) {
      requestCounters.delete(key);
    }
  }

  for (const [key, value] of burstCounters) {
    if (value.expiresAt < now) {
      burstCounters.delete(key);
    }
  }

  for (const [key, value] of globalCounters) {
    if (value.expiresAt < now) {
      globalCounters.delete(key);
    }
  }

  for (const [key, value] of violations) {
    if (value.expiresAt < now) {
      violations.delete(key);
    }
  }
}

setInterval(
  cleanupMemory,
  10000
);

/* ============================================================
   TYPES
   ============================================================ */

type Action =
  | "allow"
  | "block"
  | "honeypot";

interface Decision {
  action: Action;
  riskScore: number;
  reasons: string[];
  requestId: string;
}

/* ============================================================
   UTILITIES
   ============================================================ */

function normalizeIp(
  ip: string
): string {
  if (ip.startsWith("::ffff:")) {
    return ip.slice(7);
  }

  if (ip === "::1") {
    return "127.0.0.1";
  }

  return ip;
}

function getClientIp(
  req: Request
): string {
  return normalizeIp(
    req.ip || "0.0.0.0"
  );
}

function truncate(
  value: string,
  max = 4096
): string {
  return value.length > max
    ? value.slice(0, max)
    : value;
}

function safeJson(
  value: unknown
): string {
  try {
    return JSON.stringify(value);
  } catch {
    return "";
  }
}

function secureCompare(
  a: string,
  b: string
): boolean {
  const aBuf = Buffer.from(a);
  const bBuf = Buffer.from(b);

  if (aBuf.length !== bBuf.length) {
    return false;
  }

  return crypto.timingSafeEqual(
    aBuf,
    bBuf
  );
}

/* ============================================================
   BLACKLIST
   ============================================================ */

function isBlacklisted(
  ip: string
): boolean {
  const entry =
    db.blacklists[ip];

  if (!entry) {
    return false;
  }

  if (entry.expiresAt < Date.now()) {
    delete db.blacklists[ip];

    dbDirty = true;

    return false;
  }

  return true;
}

function blacklist(
  ip: string,
  reason: string
): void {
  db.blacklists[ip] = {
    reason,

    createdAt:
      new Date().toISOString(),

    expiresAt:
      Date.now() +
      Math.max(
        config.BLACKLIST_TTL,
        config.AUTO_BLACKLIST_SECONDS
      ) *
        1000
  };

  dbDirty = true;
}

/* ============================================================
   RISK
   ============================================================ */

function getRisk(
  ip: string
): number {
  const entry = db.risks[ip];

  if (
    !entry ||
    entry.expiresAt < Date.now()
  ) {
    return 0;
  }

  return entry.score;
}

function addRisk(
  ip: string,
  points: number
): number {
  const now = Date.now();

  let entry = db.risks[ip];

  if (
    !entry ||
    entry.expiresAt < now
  ) {
    entry = {
      score: 0,

      expiresAt:
        now +
        config.RISK_TTL *
          1000
    };
  }

  entry.score += points;

  db.risks[ip] = entry;

  dbDirty = true;

  return entry.score;
}

/* ============================================================
   COUNTERS
   ============================================================ */

function incrementCounter(
  map: Map<string, Counter>,
  key: string,
  windowMs: number
): number {
  const now = Date.now();

  let entry = map.get(key);

  if (
    !entry ||
    entry.expiresAt < now
  ) {
    entry = {
      count: 0,

      expiresAt:
        now + windowMs
    };
  }

  entry.count++;

  map.set(
    key,
    entry
  );

  return entry.count;
}

/* ============================================================
   VIOLATIONS
   ============================================================ */

function registerViolation(
  ip: string
): number {
  return incrementCounter(
    violations,
    ip,
    config.VIOLATION_WINDOW_MS
  );
}

/* ============================================================
   RATE LIMIT
   ============================================================ */

function checkRateLimit(
  ip: string
): {
  allowed: boolean;
  remaining: number;
} {
  const count =
    incrementCounter(
      requestCounters,
      ip,
      config.RATE_LIMIT_WINDOW *
        1000
    );

  return {
    allowed:
      count <=
      config.RATE_LIMIT_MAX,

    remaining:
      Math.max(
        0,
        config.RATE_LIMIT_MAX -
          count
      )
  };
}

/* ============================================================
   BURST
   ============================================================ */

function checkBurst(
  ip: string
): boolean {
  const count =
    incrementCounter(
      burstCounters,
      ip,
      config.BURST_WINDOW_MS
    );

  return (
    count <=
    config.BURST_MAX
  );
}

/* ============================================================
   GLOBAL FLOOD
   ============================================================ */

function checkGlobalRate(): boolean {
  const count =
    incrementCounter(
      globalCounters,
      "global",
      config.GLOBAL_RATE_WINDOW_MS
    );

  return (
    count <=
    config.GLOBAL_RATE_MAX
  );
}

/* ============================================================
   CONCURRENCY
   ============================================================ */

function acquireConcurrency(
  ip: string
): boolean {
  if (
    globalConcurrent >=
    config.MAX_GLOBAL_CONCURRENT
  ) {
    return false;
  }

  const current =
    concurrentByIp.get(ip) ||
    0;

  if (
    current >=
    config.MAX_CONCURRENT_PER_IP
  ) {
    return false;
  }

  concurrentByIp.set(
    ip,
    current + 1
  );

  globalConcurrent++;

  return true;
}

function releaseConcurrency(
  ip: string
): void {
  const current =
    concurrentByIp.get(ip) ||
    0;

  if (current <= 1) {
    concurrentByIp.delete(ip);
  } else {
    concurrentByIp.set(
      ip,
      current - 1
    );
  }

  globalConcurrent =
    Math.max(
      0,
      globalConcurrent - 1
    );
}

/* ============================================================
   DETECTION RULES
   ============================================================ */

const SQL_PATTERNS = [
  /\bunion\s+(?:all\s+)?select\b/i,
  /\bselect\b.{0,100}\bfrom\b/i,
  /\binsert\s+into\b/i,
  /\bupdate\b.{0,100}\bset\b/i,
  /\bdelete\s+from\b/i,
  /\bdrop\s+(?:table|database)\b/i,
  /\bor\s+1\s*=\s*1\b/i,
  /\band\s+1\s*=\s*1\b/i,
  /(?:--|\/\*|\*\/)/
];

const XSS_PATTERNS = [
  /<\s*script\b/i,
  /javascript\s*:/i,
  /on(?:error|load|click|mouseover)\s*=/i,
  /<\s*(?:iframe|object|embed)\b/i,
  /document\s*\.\s*(?:cookie|location)/i
];

const PATH_PATTERNS = [
  /\.\.[/\\]/,
  /%2e%2e(?:%2f|%5c)/i,
  /\.\.%2f/i,
  /\.\.%5c/i
];

const RCE_PATTERNS = [
  /\$\([^)]{1,200}\)/,
  /`[^`]{1,200}`/,
  /(?:^|[;&|])\s*(?:curl|wget)\s+/i,
  /(?:^|[;&|])\s*(?:bash|sh|cmd|powershell)\b/i,
  /\b(?:eval|exec|system|popen)\s*\(/
];

/* ============================================================
   INSPECTION
   ============================================================ */

function inspectString(
  value: string,
  location: string
): {
  score: number;
  reasons: string[];
} {
  const input = truncate(value);

  let score = 0;

  const reasons: string[] = [];

  if (
    SQL_PATTERNS.some(
      pattern =>
        pattern.test(input)
    )
  ) {
    score += 35;

    reasons.push(
      `sql_injection:${location}`
    );
  }

  if (
    XSS_PATTERNS.some(
      pattern =>
        pattern.test(input)
    )
  ) {
    score += 30;

    reasons.push(
      `xss:${location}`
    );
  }

  if (
    PATH_PATTERNS.some(
      pattern =>
        pattern.test(input)
    )
  ) {
    score += 25;

    reasons.push(
      `path_traversal:${location}`
    );
  }

  if (
    RCE_PATTERNS.some(
      pattern =>
        pattern.test(input)
    )
  ) {
    score += 50;

    reasons.push(
      `rce:${location}`
    );
  }

  return {
    score,
    reasons
  };
}

function inspectRequest(
  req: Request
): {
  score: number;
  reasons: string[];
} {
  let score = 0;

  const reasons: string[] = [];

  const values = [
    {
      value: req.originalUrl,
      location: "url"
    },

    {
      value:
        req.headers[
          "user-agent"
        ],
      location: "user-agent"
    },

    {
      value:
        req.headers[
          "referer"
        ],
      location: "referer"
    },

    {
      value:
        req.headers[
          "origin"
        ],
      location: "origin"
    }
  ];

  for (const item of values) {
    if (
      typeof item.value ===
      "string"
    ) {
      const result =
        inspectString(
          item.value,
          item.location
        );

      score += result.score;

      reasons.push(
        ...result.reasons
      );
    }
  }

  if (
    req.body !==
    undefined
  ) {
    const serialized =
      safeJson(
        req.body
      );

    if (serialized) {
      const result =
        inspectString(
          serialized,
          "body"
        );

      score += result.score;

      reasons.push(
        ...result.reasons
      );
    }
  }

  return {
    score,

    reasons: [
      ...new Set(
        reasons
      )
    ]
  };
}

/* ============================================================
   WAF DECISION
   ============================================================ */

async function evaluate(
  req: Request
): Promise<Decision> {
  const requestId =
    crypto.randomUUID();

  const ip =
    getClientIp(req);

  if (
    isBlacklisted(ip)
  ) {
    return {
      action: "block",

      riskScore:
        config.RISK_BLOCK_THRESHOLD,

      reasons: [
        "global_blacklist"
      ],

      requestId
    };
  }

  if (
    !checkGlobalRate()
  ) {
    const score =
      addRisk(
        ip,
        20
      );

    registerViolation(ip);

    const action =
      score >=
      config.RISK_HONEYPOT_THRESHOLD
        ? "honeypot"
        : "block";

    addAlert({
      ip,

      path:
        req.originalUrl,

      risk: score,

      action,

      reasons: [
        "global_rate_limit"
      ]
    });

    return {
      action,

      riskScore: score,

      reasons: [
        "global_rate_limit"
      ],

      requestId
    };
  }

  if (
    !checkBurst(ip)
  ) {
    const score =
      addRisk(
        ip,
        20
      );

    const count =
      registerViolation(ip);

    if (
      count >=
      config.VIOLATION_LIMIT
    ) {
      blacklist(
        ip,
        "repeated_burst_violation"
      );

      addAlert({
        ip,

        path:
          req.originalUrl,

        risk: score,

        action:
          "block",

        reasons: [
          "repeated_burst_violation"
        ]
      });

      return {
        action: "block",

        riskScore:
          Math.max(
            score,
            config.RISK_BLOCK_THRESHOLD
          ),

        reasons: [
          "repeated_burst_violation"
        ],

        requestId
      };
    }

    addAlert({
      ip,

      path:
        req.originalUrl,

      risk: score,

      action:
        "honeypot",

      reasons: [
        "burst_rate_limit"
      ]
    });

    return {
      action:
        "honeypot",

      riskScore: score,

      reasons: [
        "burst_rate_limit"
      ],

      requestId
    };
  }

  const rate =
    checkRateLimit(ip);

  if (
    !rate.allowed
  ) {
    const score =
      addRisk(
        ip,
        30
      );

    const count =
      registerViolation(ip);

    if (
      count >=
      config.VIOLATION_LIMIT
    ) {
      blacklist(
        ip,
        "repeated_rate_limit_violation"
      );

      addAlert({
        ip,

        path:
          req.originalUrl,

        risk: score,

        action:
          "block",

        reasons: [
          "rate_limit_violation"
        ]
      });

      return {
        action:
          "block",

        riskScore:
          Math.max(
            score,
            config.RISK_BLOCK_THRESHOLD
          ),

        reasons: [
          "rate_limit_violation"
        ],

        requestId
      };
    }

    addAlert({
      ip,

      path:
        req.originalUrl,

      risk: score,

      action:
        "honeypot",

      reasons: [
        "rate_limit_violation"
      ]
    });

    return {
      action:
        "honeypot",

      riskScore: score,

      reasons: [
        "rate_limit_violation"
      ],

      requestId
    };
  }

  if (
    !acquireConcurrency(ip)
  ) {
    const score =
      addRisk(
        ip,
        25
      );

    const count =
      registerViolation(ip);

    if (
      count >=
      config.VIOLATION_LIMIT
    ) {
      blacklist(
        ip,
        "connection_flood"
      );

      addAlert({
        ip,

        path:
          req.originalUrl,

        risk: score,

        action:
          "block",

        reasons: [
          "connection_flood"
        ]
      });

      return {
        action:
          "block",

        riskScore:
          Math.max(
            score,
            config.RISK_BLOCK_THRESHOLD
          ),

        reasons: [
          "connection_flood"
        ],

        requestId
      };
    }

    addAlert({
      ip,

      path:
        req.originalUrl,

      risk: score,

      action:
        "honeypot",

      reasons: [
        "too_many_concurrent_requests"
      ]
    });

    return {
      action:
        "honeypot",

      riskScore: score,

      reasons: [
        "too_many_concurrent_requests"
      ],

      requestId
    };
  }

  const inspection =
    inspectRequest(req);

  const risk =
    inspection.score > 0
      ? addRisk(
          ip,
          inspection.score
        )
      : getRisk(ip);

  if (
    risk >=
    config.RISK_BLOCK_THRESHOLD
  ) {
    blacklist(
      ip,
      inspection.reasons.join(
        ","
      ) ||
        "risk_threshold"
    );

    addAlert({
      ip,

      path:
        req.originalUrl,

      risk,

      action:
        "block",

      reasons:
        inspection.reasons.length
          ? inspection.reasons
          : [
              "risk_threshold"
            ]
    });

    return {
      action:
        "block",

      riskScore: risk,

      reasons:
        inspection.reasons.length
          ? inspection.reasons
          : [
              "risk_threshold"
            ],

      requestId
    };
  }

  if (
    risk >=
    config.RISK_HONEYPOT_THRESHOLD
  ) {
    addAlert({
      ip,

      path:
        req.originalUrl,

      risk,

      action:
        "honeypot",

      reasons:
        inspection.reasons
    });

    return {
      action:
        "honeypot",

      riskScore: risk,

      reasons:
        inspection.reasons,

      requestId
    };
  }

  return {
    action:
      "allow",

    riskScore: risk,

    reasons:
      inspection.reasons,

    requestId
  };
}

/* ============================================================
   EXPRESS
   ============================================================ */

const app =
  express();

app.disable(
  "x-powered-by"
);

if (
  config.TRUST_PROXY
) {
  app.set(
    "trust proxy",
    true
  );
}

/* ============================================================
   SECURITY HEADERS
   ============================================================ */

app.use(
  helmet({
    contentSecurityPolicy:
      false
  })
);

/* ============================================================
   BODY LIMITS
   ============================================================ */

app.use(
  express.json({
    limit:
      config.MAX_BODY_SIZE,

    strict:
      true
  })
);

app.use(
  express.urlencoded({
    extended:
      false,

    limit:
      config.MAX_BODY_SIZE
  })
);

/* ============================================================
   ADMIN AUTH
   ============================================================ */

function adminAuth(
  req: Request,
  res: Response,
  next: NextFunction
) {
  const authorization =
    req.headers.authorization;

  if (
    !authorization
  ) {
    res.setHeader(
      "WWW-Authenticate",
      'Basic realm="WAF Admin"'
    );

    return res
      .status(401)
      .send(
        "Authentication required"
      );
  }

  const parts =
    authorization.split(
      " "
    );

  if (
    parts.length !== 2 ||
    parts[0] !== "Basic"
  ) {
    return res
      .status(401)
      .send(
        "Unauthorized"
      );
  }

  let decoded = "";

  try {
    decoded =
      Buffer.from(
        parts[1],
        "base64"
      ).toString(
        "utf8"
      );
  } catch {
    return res
      .status(401)
      .send(
        "Unauthorized"
      );
  }

  const separator =
    decoded.indexOf(
      ":"
    );

  if (
    separator === -1
  ) {
    return res
      .status(401)
      .send(
        "Unauthorized"
      );
  }

  const user =
    decoded.slice(
      0,
      separator
    );

  const password =
    decoded.slice(
      separator + 1
    );

  if (
    !secureCompare(
      user,
      config.ADMIN_USER
    ) ||
    !secureCompare(
      password,
      config.ADMIN_PASSWORD
    )
  ) {
    res.setHeader(
      "WWW-Authenticate",
      'Basic realm="WAF Admin"'
    );

    return res
      .status(401)
      .send(
        "Unauthorized"
      );
  }

  return next();
}

/* ============================================================
   ADMIN API
   ============================================================ */

app.get(
  "/__waf/admin/alerts",
  adminAuth,
  (_req, res) => {
    return res.json({
      alerts
    });
  }
);

app.get(
  "/__waf/admin/stats",
  adminAuth,
  (_req, res) => {
    let blacklisted = 0;

    const now =
      Date.now();

    for (
      const entry of
      Object.values(
        db.blacklists
      )
    ) {
      if (
        entry.expiresAt >
        now
      ) {
        blacklisted++;
      }
    }

    return res.json({
      globalConcurrent,

      activeClients:
        concurrentByIp.size,

      blacklisted,

      alerts:
        alerts.length,

      target:
        config.TARGET_URL,

      uptime:
        Math.floor(
          process.uptime()
        )
    });
  }
);

app.get(
  "/__waf/admin/events",
  adminAuth,
  (req, res) => {
    res.setHeader(
      "Content-Type",
      "text/event-stream"
    );

    res.setHeader(
      "Cache-Control",
      "no-cache, no-transform"
    );

    res.setHeader(
      "Connection",
      "keep-alive"
    );

    res.setHeader(
      "X-Accel-Buffering",
      "no"
    );

    res.flushHeaders();

    alertClients.add(res);

    res.write(
      `data: ${JSON.stringify({
        type:
          "connected"
      })}\n\n`
    );

    const heartbeat =
      setInterval(
        () => {
          try {
            res.write(
              ": heartbeat\n\n"
            );
          } catch {
            clearInterval(
              heartbeat
            );

            alertClients.delete(
              res
            );
          }
        },
        15000
      );

    req.on(
      "close",
      () => {
        clearInterval(
          heartbeat
        );

        alertClients.delete(
          res
        );
      }
    );
  }
);

/* ============================================================
   ADMIN DASHBOARD
   ============================================================ */

app.get(
  "/admin",
  adminAuth,
  (_req, res) => {
    res.type(
      "html"
    ).send(`
<!DOCTYPE html>
<html lang="ar" dir="rtl">

<head>

<meta charset="UTF-8">

<meta
  name="viewport"
  content="width=device-width,initial-scale=1"
/>

<title>WAF Admin</title>

<style>

* {
  box-sizing: border-box;
}

body {
  margin: 0;

  background: #080c11;

  color: #e8eef5;

  font-family:
    Arial,
    Tahoma,
    sans-serif;
}

header {
  padding: 20px;

  background: #10161d;

  border-bottom:
    1px solid #222c36;

  display: flex;

  align-items: center;

  justify-content: space-between;
}

.logo {
  font-size: 23px;

  font-weight: 700;
}

.status {
  display: flex;

  align-items: center;

  gap: 8px;

  color: #9eabb8;

  font-size: 13px;
}

.dot {
  width: 9px;

  height: 9px;

  border-radius: 50%;

  background: #34d399;

  box-shadow:
    0 0 10px #34d399;
}

.container {
  max-width: 1300px;

  margin: auto;

  padding: 20px;
}

.stats {
  display: grid;

  grid-template-columns:
    repeat(
      auto-fit,
      minmax(190px, 1fr)
    );

  gap: 15px;

  margin-bottom: 20px;
}

.card {
  background: #10161d;

  border:
    1px solid #222c36;

  border-radius: 14px;

  padding: 20px;
}

.card-title {
  color: #8e9aa7;

  font-size: 14px;
}

.number {
  margin-top: 8px;

  font-size: 30px;

  font-weight: 700;
}

.panel {
  background: #10161d;

  border:
    1px solid #222c36;

  border-radius: 14px;

  overflow: hidden;
}

.panel-header {
  padding: 18px;

  border-bottom:
    1px solid #222c36;

  font-weight: 700;
}

.alert {
  padding: 17px;

  border-bottom:
    1px solid #1e2730;
}

.alert:last-child {
  border-bottom: 0;
}

.alert.block {
  background:
    rgba(220, 38, 38, .10);
}

.alert.honeypot {
  background:
    rgba(245, 158, 11, .08);
}

.badge {
  display: inline-block;

  padding:
    5px 9px;

  border-radius: 6px;

  font-size: 11px;

  font-weight: 700;
}

.badge.block {
  background:
    rgba(220,38,38,.18);

  color: #ff8f8f;
}

.badge.honeypot {
  background:
    rgba(245,158,11,.18);

  color: #ffc96b;
}

.meta {
  margin-top: 8px;

  color: #95a2af;

  font-size: 13px;

  word-break: break-word;
}

.reason {
  margin-top: 10px;

  color: #ff9d9d;

  font-family:
    monospace;

  font-size: 12px;
}

.empty {
  padding: 45px;

  text-align: center;

  color: #788592;
}

@media (
  max-width: 600px
) {

  .container {
    padding: 12px;
  }

  header {
    padding: 15px;
  }

  .logo {
    font-size: 19px;
  }

}

</style>

</head>

<body>

<header>

<div class="logo">
  🛡️ WAF Admin
</div>

<div class="status">

<span class="dot"></span>

حماية مباشرة

</div>

</header>

<div class="container">

<div class="stats">

<div class="card">

<div class="card-title">
  العملاء النشطون
</div>

<div
  class="number"
  id="clients"
>
  0
</div>

</div>

<div class="card">

<div class="card-title">
  الاتصالات الحالية
</div>

<div
  class="number"
  id="connections"
>
  0
</div>

</div>

<div class="card">

<div class="card-title">
  IPs المحظورة
</div>

<div
  class="number"
  id="blacklisted"
>
  0
</div>

</div>

<div class="card">

<div class="card-title">
  التنبيهات المسجلة
</div>

<div
  class="number"
  id="alertCount"
>
  0
</div>

</div>

</div>

<div class="panel">

<div class="panel-header">
  🚨 التنبيهات المباشرة
</div>

<div id="alerts">

<div class="empty">
  لا توجد تنبيهات حتى الآن
</div>

</div>

</div>

</div>

<script>

const alertsElement =
  document.getElementById(
    "alerts"
  );

const clientsElement =
  document.getElementById(
    "clients"
  );

const connectionsElement =
  document.getElementById(
    "connections"
  );

const blacklistedElement =
  document.getElementById(
    "blacklisted"
  );

const alertCountElement =
  document.getElementById(
    "alertCount"
  );

function escapeHtml(
  value
) {
  return String(value)
    .replaceAll(
      "&",
      "&amp;"
    )
    .replaceAll(
      "<",
      "&lt;"
    )
    .replaceAll(
      ">",
      "&gt;"
    )
    .replaceAll(
      '"',
      "&quot;"
    )
    .replaceAll(
      "'",
      "&#039;"
    );
}

function renderAlert(
  alert
) {

  const element =
    document.createElement(
      "div"
    );

  element.className =
    "alert " +
    (
      alert.action ===
      "block"
        ? "block"
        : "honeypot"
    );

  const reasons =
    Array.isArray(
      alert.reasons
    )
      ? alert.reasons.join(
          ", "
        )
      : "";

  element.innerHTML = \`
    <span class="badge \${escapeHtml(
      alert.action
    )}">
      \${escapeHtml(
        alert.action.toUpperCase()
      )}
    </span>

    <div class="meta">
      IP:
      <strong>
        \${escapeHtml(
          alert.ip
        )}
      </strong>
    </div>

    <div class="meta">
      Risk:
      <strong>
        \${escapeHtml(
          alert.risk
        )}
      </strong>
    </div>

    <div class="meta">
      Path:
      \${escapeHtml(
        alert.path
      )}
    </div>

    <div class="meta">
      Time:
      \${escapeHtml(
        alert.time
      )}
    </div>

    <div class="reason">
      \${escapeHtml(
        reasons
      )}
    </div>
  \`;

  return element;
}

function addAlert(
  alert
) {

  if (
    alertsElement.querySelector(
      ".empty"
    )
  ) {
    alertsElement.innerHTML =
      "";
  }

  const element =
    renderAlert(
      alert
    );

  alertsElement.prepend(
    element
  );

  while (
    alertsElement.children
      .length > 200
  ) {
    alertsElement.lastElementChild
      ?.remove();
  }
}

async function loadAlerts() {

  try {

    const response =
      await fetch(
        "/__waf/admin/alerts",
        {
          credentials:
            "same-origin"
        }
      );

    if (
      !response.ok
    ) {
      return;
    }

    const data =
      await response.json();

    alertsElement.innerHTML =
      "";

    if (
      !data.alerts ||
      !data.alerts.length
    ) {

      alertsElement.innerHTML =
        '<div class="empty">لا توجد تنبيهات حتى الآن</div>';

      alertCountElement.textContent =
        "0";

      return;
    }

    for (
      const alert of
      data.alerts
    ) {
      addAlert(
        alert
      );
    }

    alertCountElement.textContent =
      data.alerts.length;

  } catch {
    // Ignore dashboard polling errors.
  }
}

async function loadStats() {

  try {

    const response =
      await fetch(
        "/__waf/admin/stats",
        {
          credentials:
            "same-origin"
        }
      );

    if (
      !response.ok
    ) {
      return;
    }

    const data =
      await response.json();

    clientsElement.textContent =
      data.activeClients ?? 0;

    connectionsElement.textContent =
      data.globalConcurrent ?? 0;

    blacklistedElement.textContent =
      data.blacklisted ?? 0;

    alertCountElement.textContent =
      data.alerts ?? 0;

  } catch {
    // Ignore dashboard errors.
  }
}

const events =
  new EventSource(
    "/__waf/admin/events"
  );

events.onmessage =
  event => {

    try {

      const data =
        JSON.parse(
          event.data
        );

      if (
        data.type ===
        "connected"
      ) {
        return;
      }

      addAlert(
        data
      );

      loadStats();

    } catch {
      // Ignore malformed events.
    }

  };

events.onerror =
  () => {
    // EventSource automatically reconnects.
  };

loadAlerts();

loadStats();

setInterval(
  loadStats,
  3000
);

</script>

</body>

</html>
`);
  }
);

/* ============================================================
   HEALTH
   ============================================================ */

app.get(
  "/__waf/health",
  (_req, res) => {
    return res.json({
      status: "ok",

      service:
        "single-site-cloud-waf",

      protection:
        "strong-l7",

      globalConcurrent,

      activeClients:
        concurrentByIp.size
    });
  }
);

/* ============================================================
   ADMIN STATUS
   ============================================================ */

app.get(
  "/__waf/status/:ip",
  (req, res) => {
    const suppliedKey =
      req.header(
        "x-waf-api-key"
      );

    if (
      suppliedKey !==
      config.WAF_API_KEY
    ) {
      return res
        .status(401)
        .json({
          error:
            "unauthorized"
        });
    }

    const ip =
      normalizeIp(
        req.params.ip
      );

    return res.json({
      ip,

      blacklisted:
        isBlacklisted(
          ip
        ),

      risk:
        getRisk(ip),

      concurrent:
        concurrentByIp.get(
          ip
        ) || 0
    });
  }
);

/* ============================================================
   HONEYPOT
   ============================================================ */

app.all(
  "/__waf_honeypot",
  (req, res) => {
    const ip =
      getClientIp(req);

    const score =
      addRisk(
        ip,
        config.RISK_BLOCK_THRESHOLD
      );

    blacklist(
      ip,
      "honeypot_triggered"
    );

    addAlert({
      ip,

      path:
        req.originalUrl,

      risk: score,

      action:
        "block",

      reasons: [
        "honeypot_triggered"
      ]
    });

    return res
      .status(404)
      .json({
        error:
          "not_found"
      });
  }
);

/* ============================================================
   INDEX.HTML
   ============================================================ */

const indexFilePath =
  path.resolve(
    process.cwd(),
    "index.html"
  );

/*
 * الصفحة الرئيسية:
 *
 * index.html يجب أن يكون في نفس مجلد
 * cloud-waf-proxy.ts
 */

app.get(
  "/",
  async (
    req,
    res,
    next
  ) => {

    let acquired =
      false;

    try {

      const decision =
        await evaluate(
          req
        );

      acquired =
        decision.action ===
          "allow" ||
        decision.action ===
          "honeypot";

      res.setHeader(
        "x-waf-request-id",
        decision.requestId
      );

      res.setHeader(
        "x-waf-risk-score",
        String(
          decision.riskScore
        )
      );

      res.setHeader(
        "x-waf-protected",
        "true"
      );

      if (
        decision.action ===
        "block"
      ) {

        if (acquired) {
          releaseConcurrency(
            getClientIp(req)
          );

          acquired =
            false;
        }

        return res
          .status(403)
          .json({
            error:
              "request_blocked",

            requestId:
              decision.requestId,

            reasons:
              decision.reasons
          });
      }

      if (
        decision.action ===
        "honeypot"
      ) {

        if (acquired) {
          releaseConcurrency(
            getClientIp(req)
          );

          acquired =
            false;
        }

        return res
          .status(404)
          .json({
            error:
              "not_found",

            requestId:
              decision.requestId
          });
      }

      if (
        !fs.existsSync(
          indexFilePath
        )
      ) {

        if (acquired) {
          releaseConcurrency(
            getClientIp(req)
          );

          acquired =
            false;
        }

        return res
          .status(404)
          .send(
            "index.html not found"
          );
      }

      res.once(
        "finish",
        () => {
          if (acquired) {
            releaseConcurrency(
              getClientIp(req)
            );

            acquired =
              false;
          }
        }
      );

      res.once(
        "close",
        () => {
          if (acquired) {
            releaseConcurrency(
              getClientIp(req)
            );

            acquired =
              false;
          }
        }
      );

      return res.sendFile(
        indexFilePath
      );

    } catch (error) {

      if (acquired) {
        releaseConcurrency(
          getClientIp(req)
        );
      }

      console.error(
        "Index WAF error:",
        error
      );

      return next(error);
    }
  }
);

/* ============================================================
   MAIN WAF
   ============================================================ */

app.use(
  async (
    req,
    res,
    next
  ) => {

    if (
      req.path ===
      "/__waf/health"
    ) {
      return next();
    }

    if (
      req.path.startsWith(
        "/__waf/"
      )
    ) {
      return next();
    }

    if (
      req.path ===
      "/admin"
    ) {
      return next();
    }

    if (
      req.path ===
      "/"
    ) {
      return next();
    }

    let acquired =
      false;

    try {

      const decision =
        await evaluate(
          req
        );

      acquired =
        decision.action ===
          "allow" ||
        decision.action ===
          "honeypot";

      res.setHeader(
        "x-waf-request-id",
        decision.requestId
      );

      res.setHeader(
        "x-waf-risk-score",
        String(
          decision.riskScore
        )
      );

      res.setHeader(
        "x-waf-protected",
        "true"
      );

      if (
        decision.action ===
        "block"
      ) {

        if (acquired) {

          releaseConcurrency(
            getClientIp(req)
          );

          acquired =
            false;
        }

        return res
          .status(403)
          .json({
            error:
              "request_blocked",

            requestId:
              decision.requestId,

            reasons:
              decision.reasons
          });
      }

      if (
        decision.action ===
        "honeypot"
      ) {

        if (acquired) {

          releaseConcurrency(
            getClientIp(req)
          );

          acquired =
            false;
        }

        return res
          .status(404)
          .json({
            error:
              "not_found",

            requestId:
              decision.requestId
          });
      }

      return next();

    } catch (error) {

      if (acquired) {

        releaseConcurrency(
          getClientIp(req)
        );
      }

      console.error(
        "WAF evaluation error:",
        error
      );

      return res
        .status(503)
        .json({
          error:
            "waf_unavailable"
        });
    }
  }
);

/* ============================================================
   RELEASE CONCURRENCY
   ============================================================ */

app.use(
  (
    req,
    res,
    next
  ) => {

    const ip =
      getClientIp(req);

    let released =
      false;

    const release =
      () => {

        if (released) {
          return;
        }

        released =
          true;

        releaseConcurrency(
          ip
        );
      };

    res.once(
      "finish",
      release
    );

    res.once(
      "close",
      release
    );

    next();
  }
);

/* ============================================================
   REVERSE PROXY
   ============================================================ */

const proxy =
  createProxyMiddleware({
    target:
      config.TARGET_URL,

    changeOrigin:
      true,

    xfwd:
      true,

    ws:
      true,

    proxyTimeout:
      config.PROXY_TIMEOUT_MS,

    timeout:
      config.PROXY_TIMEOUT_MS,

    onProxyReq(
      proxyReq,
      req
    ) {

      proxyReq.setHeader(
        "x-waf-protected",
        "true"
      );

      proxyReq.setHeader(
        "x-waf-request-id",
        req.headers[
          "x-waf-request-id"
        ] ||
          crypto.randomUUID()
      );

      proxyReq.setHeader(
        "x-forwarded-host",
        req.headers.host ||
          ""
      );

      fixRequestBody(
        proxyReq,
        req
      );
    },

    onError(
      error,
      _req,
      res
    ) {

      console.error(
        "Proxy error:",
        error
      );

      if (
        !res.headersSent
      ) {

        res
          .status(502)
          .json({
            error:
              "protected_site_unavailable"
          });
      }
    }
  });

app.use(
  "/",
  proxy
);

/* ============================================================
   ERROR HANDLER
   ============================================================ */

app.use(
  (
    error: unknown,
    _req: Request,
    res: Response,
    _next: NextFunction
  ) => {

    console.error(
      "Unhandled WAF error:",
      error
    );

    if (
      !res.headersSent
    ) {

      return res
        .status(500)
        .json({
          error:
            "internal_error"
        });
    }

    return res.end();
  }
);

/* ============================================================
   SERVER
   ============================================================ */

const server =
  http.createServer(
    app
  );

server.requestTimeout =
  config.REQUEST_TIMEOUT_MS;

server.headersTimeout =
  Math.min(
    config.HEADERS_TIMEOUT_MS,
    config.REQUEST_TIMEOUT_MS
  );

server.keepAliveTimeout =
  config.KEEP_ALIVE_TIMEOUT_MS;

server.maxHeadersCount =
  100;

/* ============================================================
   SOCKET PROTECTION
   ============================================================ */

const socketCounts =
  new Map<
    string,
    number
  >();

const MAX_SOCKETS_PER_IP =
  config.MAX_CONCURRENT_PER_IP *
  2;

server.on(
  "connection",
  socket => {

    const rawIp =
      normalizeIp(
        socket.remoteAddress ||
          "0.0.0.0"
      );

    const current =
      socketCounts.get(
        rawIp
      ) || 0;

    if (
      current >=
      MAX_SOCKETS_PER_IP
    ) {

      socket.destroy();

      return;
    }

    socketCounts.set(
      rawIp,
      current + 1
    );

    socket.setTimeout(
      config.REQUEST_TIMEOUT_MS
    );

    socket.on(
      "close",
      () => {

        const count =
          socketCounts.get(
            rawIp
          ) || 0;

        if (
          count <= 1
        ) {

          socketCounts.delete(
            rawIp
          );

        } else {

          socketCounts.set(
            rawIp,
            count - 1
          );
        }
      }
    );
  }
);

/* ============================================================
   START
   ============================================================ */

server.listen(
  config.PORT,
  "0.0.0.0",
  () => {

    console.log(
      "=========================================="
    );

    console.log(
      " Strong Single-Site Cloud WAF"
    );

    console.log(
      " Live Admin Dashboard Enabled"
    );

    console.log(
      " L7 Anti-DDoS Protection Enabled"
    );

    console.log(
      ` WAF: http://0.0.0.0:${config.PORT}`
    );

    console.log(
      ` Target: ${config.TARGET_URL}`
    );

    console.log(
      ` Index: /index.html`
    );

    console.log(
      ` Admin: /admin`
    );

    console.log(
      ` Rate: ${config.RATE_LIMIT_MAX}/${config.RATE_LIMIT_WINDOW}s`
    );

    console.log(
      ` Burst: ${config.BURST_MAX}/${config.BURST_WINDOW_MS}ms`
    );

    console.log(
      ` Max concurrent/IP: ${config.MAX_CONCURRENT_PER_IP}`
    );

    console.log(
      ` Max global concurrent: ${config.MAX_GLOBAL_CONCURRENT}`
    );

    console.log(
      "=========================================="
    );
  }
);

/* ============================================================
   GRACEFUL SHUTDOWN
   ============================================================ */

function shutdown(
  signal: string
): void {

  console.log(
    `${signal}: shutting down WAF...`
  );

  saveDb();

  server.close(
    () => {
      process.exit(0);
    }
  );

  setTimeout(
    () => {
      process.exit(1);
    },
    10000
  ).unref();
}

process.on(
  "SIGTERM",
  () =>
    shutdown(
      "SIGTERM"
    )
);

process.on(
  "SIGINT",
  () =>
    shutdown(
      "SIGINT"
    )
);
