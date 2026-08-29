'use strict';

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import http from "node:http";

import express, {
  type Request,
  type Response,
  type NextFunction,
} from "express";

import helmet from "helmet";
import { z } from "zod";

import {
  createProxyMiddleware,
  fixRequestBody,
} from "http-proxy-middleware";

/* ============================================================
   CONFIG
============================================================ */

const ConfigSchema = z.object({
  PORT: z.coerce.number().int().positive().default(8080),

  ADMIN_USER: z.string().min(3),
  ADMIN_PASSWORD: z.string().min(12),

  DATA_FILE: z.string().default("sites-db.json"),

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
  PROXY_TIMEOUT_MS: z.coerce.number().int().positive().default(15000),

  /*
   * Global Anti-Bot Challenge
   */
  CHALLENGE_SECRET: z.string().min(32),

  CHALLENGE_WAIT_SECONDS: z.coerce.number().int().min(1).max(30).default(5),

  CHALLENGE_TTL_SECONDS: z.coerce.number().int().positive().default(86400),

  CHALLENGE_TICKET_TTL_SECONDS: z.coerce.number().int().positive().default(60),
});

const config = ConfigSchema.parse({
  PORT: process.env.PORT,

  ADMIN_USER: process.env.ADMIN_USER,
  ADMIN_PASSWORD: process.env.ADMIN_PASSWORD,

  DATA_FILE: process.env.DATA_FILE || "sites-db.json",

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
  PROXY_TIMEOUT_MS: process.env.PROXY_TIMEOUT_MS,

  CHALLENGE_SECRET: process.env.CHALLENGE_SECRET,

  CHALLENGE_WAIT_SECONDS: process.env.CHALLENGE_WAIT_SECONDS,

  CHALLENGE_TTL_SECONDS: process.env.CHALLENGE_TTL_SECONDS,

  CHALLENGE_TICKET_TTL_SECONDS:
    process.env.CHALLENGE_TICKET_TTL_SECONDS,
});

/* ============================================================
   TYPES
============================================================ */

type Action =
  | "allow"
  | "block"
  | "honeypot";

interface SiteSettings {
  rateLimitWindow?: number;
  rateLimitMax?: number;

  burstWindowMs?: number;
  burstMax?: number;

  globalRateWindowMs?: number;
  globalRateMax?: number;

  maxConcurrentPerIp?: number;
  maxGlobalConcurrent?: number;

  violationLimit?: number;
  violationWindowMs?: number;

  autoBlacklistSeconds?: number;

  riskBlockThreshold?: number;
  riskHoneypotThreshold?: number;

  riskTtl?: number;
  blacklistTtl?: number;

  enableSqlInjection?: boolean;
  enableXss?: boolean;
  enableRce?: boolean;
  enablePathTraversal?: boolean;

  enabled?: boolean;

  /*
   * Challenge can be enabled/disabled per site.
   * Global default remains enabled.
   */
  enableChallenge?: boolean;
}

interface SiteStats {
  totalRequests: number;
  allowedRequests: number;
  blockedRequests: number;
  honeypotRequests: number;
  attacks: number;

  lastRequestAt?: string;
  lastAttackAt?: string;
}

interface Site {
  id: string;

  owner_id: string;

  client_domain: string;

  domains: string[];

  target_url: string;

  api_key: string;

  settings: SiteSettings;

  stats: SiteStats;
}

interface BlacklistEntry {
  reason: string;
  createdAt: string;
  expiresAt: number;
}

interface RiskEntry {
  score: number;
  expiresAt: number;
}

interface WafAlert {
  id: string;
  siteId: string;
  ownerId: string;
  domain: string;
  time: string;
  ip: string;
  path: string;
  risk: number;
  action: Action;
  reasons: string[];
}

interface DbSchema {
  sites: Site[];

  blacklists: Record<string, BlacklistEntry>;

  risks: Record<string, RiskEntry>;

  alerts: WafAlert[];
}

interface Counter {
  count: number;
  expiresAt: number;
}

interface Decision {
  action: Action;
  riskScore: number;
  reasons: string[];
  requestId: string;
  site: Site;
}

type WafRequest = Request & {
  wafSite?: Site;
  wafRequestId?: string;
  wafAcquired?: boolean;
};

/* ============================================================
   UTILITIES
============================================================ */

function normalizeDomain(domain: string): string {
  return domain
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .split("/")[0]
    .split(":")[0]
    .trim();
}

function normalizeHost(host: string): string {
  return normalizeDomain(host);
}

function normalizeDomains(values: string[]): string[] {
  return [
    ...new Set(
      values
        .map(normalizeDomain)
        .filter(Boolean)
    ),
  ];
}

function truncate(
  value: string,
  max = 4096
): string {
  return value.length > max
    ? value.slice(0, max)
    : value;
}

function safeJson(value: unknown): string {
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

function normalizeIp(ip: string): string {
  if (ip.startsWith("::ffff:")) {
    return ip.slice(7);
  }

  if (ip === "::1") {
    return "127.0.0.1";
  }

  return ip;
}

function getClientIp(req: Request): string {
  return normalizeIp(
    req.ip || "0.0.0.0"
  );
}

function base64UrlEncode(
  value: Buffer | string
): string {
  return Buffer
    .from(value)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function base64UrlDecode(
  value: string
): Buffer {
  const normalized = value
    .replace(/-/g, "+")
    .replace(/_/g, "/");

  const padding =
    normalized.length % 4 === 0
      ? ""
      : "=".repeat(
          4 - (normalized.length % 4)
        );

  return Buffer.from(
    normalized + padding,
    "base64"
  );
}

/* ============================================================
   PATHS / ROUTIX WEBSITE
============================================================ */

const PROJECT_DIR = process.cwd();

const INDEX_FILE = path.join(
  PROJECT_DIR,
  "index.html"
);

const SERVER_HOSTS = new Set<string>();

const renderHost =
  process.env.RENDER_EXTERNAL_HOSTNAME;

const publicHost =
  process.env.PUBLIC_HOST;

if (renderHost) {
  SERVER_HOSTS.add(
    normalizeHost(renderHost)
  );
}

if (publicHost) {
  SERVER_HOSTS.add(
    normalizeHost(publicHost)
  );
}

/*
 * Existing Render hostname.
 */
SERVER_HOSTS.add(
  "production-1-54qv.onrender.com"
);

/*
 * Routix custom domain.
 */
SERVER_HOSTS.add(
  "www.routix.nx.kg"
);

SERVER_HOSTS.add(
  "routix.nx.kg"
);

/* ============================================================
   DATABASE
============================================================ */

const dbFilePath = path.resolve(
  process.cwd(),
  config.DATA_FILE
);

function createSiteStats(): SiteStats {
  return {
    totalRequests: 0,
    allowedRequests: 0,
    blockedRequests: 0,
    honeypotRequests: 0,
    attacks: 0,
  };
}

function emptyDb(): DbSchema {
  return {
    sites: [],
    blacklists: {},
    risks: {},
    alerts: [],
  };
}

function migrateSite(
  site: any
): Site {
  const primaryDomain =
    normalizeDomain(
      String(
        site.client_domain || ""
      )
    );

  const oldDomains =
    Array.isArray(site.domains)
      ? site.domains
      : [];

  const domains =
    normalizeDomains([
      primaryDomain,
      ...oldDomains,
    ]);

  return {
    id: String(
      site.id ||
      crypto.randomUUID()
    ),

    owner_id: String(
      site.owner_id ||
      "default"
    ),

    client_domain:
      primaryDomain ||
      domains[0] ||
      "",

    domains,

    target_url: String(
      site.target_url || ""
    ),

    api_key: String(
      site.api_key ||
      crypto
        .randomBytes(32)
        .toString("hex")
    ),

    settings:
      site.settings &&
      typeof site.settings === "object"
        ? site.settings
        : {
            enableChallenge: true,
          },

    stats:
      site.stats ||
      createSiteStats(),
  };
}

function loadDb(): DbSchema {
  try {
    if (!fs.existsSync(dbFilePath)) {
      const initial = emptyDb();

      fs.writeFileSync(
        dbFilePath,
        JSON.stringify(
          initial,
          null,
          2
        ),
        "utf8"
      );

      return initial;
    }

    const parsed =
      JSON.parse(
        fs.readFileSync(
          dbFilePath,
          "utf8"
        )
      );

    const rawSites =
      Array.isArray(parsed.sites)
        ? parsed.sites
        : [];

    const sites =
      rawSites.map(migrateSite);

    return {
      sites,

      blacklists:
        parsed.blacklists || {},

      risks:
        parsed.risks || {},

      alerts:
        Array.isArray(parsed.alerts)
          ? parsed.alerts
          : [],
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

    for (
      const [
        key,
        value,
      ] of Object.entries(
        db.blacklists
      )
    ) {
      if (
        value.expiresAt < now
      ) {
        delete db.blacklists[key];
      }
    }

    for (
      const [
        key,
        value,
      ] of Object.entries(
        db.risks
      )
    ) {
      if (
        value.expiresAt < now
      ) {
        delete db.risks[key];
      }
    }

    db.alerts =
      db.alerts.slice(0, 1000);

    const tempFile =
      `${dbFilePath}.tmp`;

    fs.writeFileSync(
      tempFile,
      JSON.stringify(
        db,
        null,
        2
      ),
      "utf8"
    );

    fs.renameSync(
      tempFile,
      dbFilePath
    );

    dbDirty = false;
  } catch (error) {
    console.error(
      "Database save error:",
      error
    );
  }
}

setInterval(() => {
  if (dbDirty) {
    saveDb();
  }
}, 5000);

/* ============================================================
   SITE LOOKUP
============================================================ */

function getSiteByHost(
  host: string
): Site | null {
  const normalized =
    normalizeHost(host);

  const site =
    db.sites.find(
      (currentSite) => {
        const domains =
          normalizeDomains([
            currentSite.client_domain,
            ...(Array.isArray(
              currentSite.domains
            )
              ? currentSite.domains
              : []),
          ]);

        return domains.includes(
          normalized
        );
      }
    );

  return site || null;
}

function getSiteById(
  id: string
): Site | null {
  return (
    db.sites.find(
      (site) =>
        site.id === id
    ) || null
  );
}

function getSiteByApiKey(
  apiKey: string
): Site | null {
  return (
    db.sites.find(
      (site) =>
        secureCompare(
          site.api_key,
          apiKey
        )
    ) || null
  );
}

/* ============================================================
   MEMORY RATE LIMITERS
============================================================ */

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

const concurrentBySite =
  new Map<string, number>();

let globalConcurrent = 0;

/* ============================================================
   LIVE ADMIN ALERTS
============================================================ */

const alertClients =
  new Set<Response>();

function addAlert(data: {
  site: Site;
  ip: string;
  path: string;
  risk: number;
  action: Action;
  reasons: string[];
}): void {
  const alert: WafAlert = {
    id: crypto.randomUUID(),

    siteId: data.site.id,

    ownerId:
      data.site.owner_id,

    domain:
      data.site.client_domain,

    time:
      new Date().toISOString(),

    ip: data.ip,

    path: truncate(
      data.path,
      500
    ),

    risk: data.risk,

    action: data.action,

    reasons:
      data.reasons.slice(
        0,
        20
      ),
  };

  db.alerts.unshift(alert);

  if (db.alerts.length > 1000) {
    db.alerts.length = 1000;
  }

  dbDirty = true;

  const payload =
    `data: ${JSON.stringify(
      alert
    )}\n\n`;

  for (
    const client of alertClients
  ) {
    try {
      client.write(payload);
    } catch {
      alertClients.delete(
        client
      );
    }
  }
}

/* ============================================================
   MEMORY CLEANUP
============================================================ */

function cleanupMemory(): void {
  const now = Date.now();

  for (
    const [
      key,
      value,
    ] of requestCounters
  ) {
    if (
      value.expiresAt < now
    ) {
      requestCounters.delete(
        key
      );
    }
  }

  for (
    const [
      key,
      value,
    ] of burstCounters
  ) {
    if (
      value.expiresAt < now
    ) {
      burstCounters.delete(
        key
      );
    }
  }

  for (
    const [
      key,
      value,
    ] of globalCounters
  ) {
    if (
      value.expiresAt < now
    ) {
      globalCounters.delete(
        key
      );
    }
  }

  for (
    const [
      key,
      value,
    ] of violations
  ) {
    if (
      value.expiresAt < now
    ) {
      violations.delete(
        key
      );
    }
  }
}

setInterval(
  cleanupMemory,
  10000
);

/* ============================================================
   SITE SETTINGS
============================================================ */

function settingNumber(
  site: Site,

  key:
    | "rateLimitWindow"
    | "rateLimitMax"
    | "burstWindowMs"
    | "burstMax"
    | "globalRateWindowMs"
    | "globalRateMax"
    | "maxConcurrentPerIp"
    | "maxGlobalConcurrent"
    | "violationLimit"
    | "violationWindowMs"
    | "autoBlacklistSeconds"
    | "riskBlockThreshold"
    | "riskHoneypotThreshold"
    | "riskTtl"
    | "blacklistTtl",

  fallback: number
): number {
  const value =
    site.settings[key];

  return typeof value === "number" &&
    Number.isFinite(value) &&
    value > 0
    ? value
    : fallback;
}

function settingBoolean(
  site: Site,

  key:
    | "enabled"
    | "enableSqlInjection"
    | "enableXss"
    | "enableRce"
    | "enablePathTraversal"
    | "enableChallenge",

  fallback = true
): boolean {
  const value =
    site.settings[key];

  return typeof value === "boolean"
    ? value
    : fallback;
}

/* ============================================================
   BLACKLIST
============================================================ */

function blacklistKey(
  siteId: string,
  ip: string
): string {
  return `${siteId}:${ip}`;
}

function isBlacklisted(
  site: Site,
  ip: string
): boolean {
  const key =
    blacklistKey(
      site.id,
      ip
    );

  const entry =
    db.blacklists[key];

  if (!entry) {
    return false;
  }

  if (
    entry.expiresAt <
    Date.now()
  ) {
    delete db.blacklists[
      key
    ];

    dbDirty = true;

    return false;
  }

  return true;
}

function blacklist(
  site: Site,
  ip: string,
  reason: string
): void {
  const key =
    blacklistKey(
      site.id,
      ip
    );

  const ttl = Math.max(
    settingNumber(
      site,
      "blacklistTtl",
      config.BLACKLIST_TTL
    ),

    settingNumber(
      site,
      "autoBlacklistSeconds",
      config.AUTO_BLACKLIST_SECONDS
    )
  );

  db.blacklists[key] = {
    reason,

    createdAt:
      new Date().toISOString(),

    expiresAt:
      Date.now() +
      ttl * 1000,
  };

  dbDirty = true;
}

/* ============================================================
   RISK
============================================================ */

function riskKey(
  siteId: string,
  ip: string
): string {
  return `${siteId}:${ip}`;
}

function getRisk(
  site: Site,
  ip: string
): number {
  const key =
    riskKey(
      site.id,
      ip
    );

  const entry =
    db.risks[key];

  if (
    !entry ||
    entry.expiresAt <
      Date.now()
  ) {
    return 0;
  }

  return entry.score;
}

function addRisk(
  site: Site,
  ip: string,
  points: number
): number {
  const key =
    riskKey(
      site.id,
      ip
    );

  const now =
    Date.now();

  let entry =
    db.risks[key];

  if (
    !entry ||
    entry.expiresAt < now
  ) {
    entry = {
      score: 0,

      expiresAt:
        now +
        settingNumber(
          site,
          "riskTtl",
          config.RISK_TTL
        ) *
          1000,
    };
  }

  entry.score += points;

  db.risks[key] =
    entry;

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
  const now =
    Date.now();

  let entry =
    map.get(key);

  if (
    !entry ||
    entry.expiresAt < now
  ) {
    entry = {
      count: 0,

      expiresAt:
        now + windowMs,
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
  site: Site,
  ip: string
): number {
  return incrementCounter(
    violations,

    `${site.id}:${ip}`,

    settingNumber(
      site,
      "violationWindowMs",
      config.VIOLATION_WINDOW_MS
    )
  );
}

/* ============================================================
   RATE LIMIT
============================================================ */

function checkRateLimit(
  site: Site,
  ip: string
): {
  allowed: boolean;
  remaining: number;
} {
  const max =
    settingNumber(
      site,
      "rateLimitMax",
      config.RATE_LIMIT_MAX
    );

  const windowMs =
    settingNumber(
      site,
      "rateLimitWindow",
      config.RATE_LIMIT_WINDOW
    ) * 1000;

  const count =
    incrementCounter(
      requestCounters,

      `${site.id}:${ip}`,

      windowMs
    );

  return {
    allowed:
      count <= max,

    remaining:
      Math.max(
        0,
        max - count
      ),
  };
}

/* ============================================================
   BURST
============================================================ */

function checkBurst(
  site: Site,
  ip: string
): boolean {
  const count =
    incrementCounter(
      burstCounters,

      `${site.id}:${ip}`,

      settingNumber(
        site,
        "burstWindowMs",
        config.BURST_WINDOW_MS
      )
    );

  return (
    count <=
    settingNumber(
      site,
      "burstMax",
      config.BURST_MAX
    )
  );
}

/* ============================================================
   GLOBAL FLOOD
============================================================ */

function checkGlobalRate(
  site: Site
): boolean {
  const count =
    incrementCounter(
      globalCounters,

      site.id,

      settingNumber(
        site,
        "globalRateWindowMs",
        config.GLOBAL_RATE_WINDOW_MS
      )
    );

  return (
    count <=
    settingNumber(
      site,
      "globalRateMax",
      config.GLOBAL_RATE_MAX
    )
  );
}

/* ============================================================
   CONCURRENCY
============================================================ */

function acquireConcurrency(
  site: Site,
  ip: string
): boolean {
  const maxGlobal =
    settingNumber(
      site,
      "maxGlobalConcurrent",
      config.MAX_GLOBAL_CONCURRENT
    );

  const maxIp =
    settingNumber(
      site,
      "maxConcurrentPerIp",
      config.MAX_CONCURRENT_PER_IP
    );

  if (
    globalConcurrent >=
    maxGlobal
  ) {
    return false;
  }

  const ipKey =
    `${site.id}:${ip}`;

  const currentIp =
    concurrentByIp.get(
      ipKey
    ) || 0;

  if (
    currentIp >= maxIp
  ) {
    return false;
  }

  const siteCurrent =
    concurrentBySite.get(
      site.id
    ) || 0;

  if (
    siteCurrent >=
    maxGlobal
  ) {
    return false;
  }

  concurrentByIp.set(
    ipKey,
    currentIp + 1
  );

  concurrentBySite.set(
    site.id,
    siteCurrent + 1
  );

  globalConcurrent++;

  return true;
}

function releaseConcurrency(
  site: Site,
  ip: string
): void {
  const ipKey =
    `${site.id}:${ip}`;

  const currentIp =
    concurrentByIp.get(
      ipKey
    ) || 0;

  if (
    currentIp <= 1
  ) {
    concurrentByIp.delete(
      ipKey
    );
  } else {
    concurrentByIp.set(
      ipKey,
      currentIp - 1
    );
  }

  const currentSite =
    concurrentBySite.get(
      site.id
    ) || 0;

  if (
    currentSite <= 1
  ) {
    concurrentBySite.delete(
      site.id
    );
  } else {
    concurrentBySite.set(
      site.id,
      currentSite - 1
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
  /(?:--|\/\*|\*\/)/i,
];

const XSS_PATTERNS = [
  /<\s*script\b/i,
  /javascript\s*:/i,
  /on(?:error|load|click|mouseover)\s*=/i,
  /<\s*(?:iframe|object|embed)\b/i,
  /document\s*\.\s*(?:cookie|location)/i,
];

const PATH_PATTERNS = [
  /\.\.[/\\]/,
  /%2e%2e(?:%2f|%5c)/i,
  /\.\.%2f/i,
  /\.\.%5c/i,
];

const RCE_PATTERNS = [
  /\$\([^)]{1,200}\)/,
  /`[^`]{1,200}`/,
  /(?:^|[;&|])\s*(?:curl|wget)\s+/i,
  /(?:^|[;&|])\s*(?:bash|sh|cmd|powershell)\b/i,
  /\b(?:eval|exec|system|popen)\s*\(/i,
];

/* ============================================================
   INSPECTION
============================================================ */

function inspectString(
  site: Site,
  value: string,
  location: string
): {
  score: number;
  reasons: string[];
} {
  const input =
    truncate(value);

  let score = 0;

  const reasons: string[] =
    [];

  if (
    settingBoolean(
      site,
      "enableSqlInjection"
    ) &&
    SQL_PATTERNS.some(
      (pattern) =>
        pattern.test(input)
    )
  ) {
    score += 35;

    reasons.push(
      `sql_injection:${location}`
    );
  }

  if (
    settingBoolean(
      site,
      "enableXss"
    ) &&
    XSS_PATTERNS.some(
      (pattern) =>
        pattern.test(input)
    )
  ) {
    score += 30;

    reasons.push(
      `xss:${location}`
    );
  }

  if (
    settingBoolean(
      site,
      "enablePathTraversal"
    ) &&
    PATH_PATTERNS.some(
      (pattern) =>
        pattern.test(input)
    )
  ) {
    score += 25;

    reasons.push(
      `path_traversal:${location}`
    );
  }

  if (
    settingBoolean(
      site,
      "enableRce"
    ) &&
    RCE_PATTERNS.some(
      (pattern) =>
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
    reasons,
  };
}

function inspectRequest(
  site: Site,
  req: Request
): {
  score: number;
  reasons: string[];
} {
  let score = 0;

  const reasons: string[] =
    [];

  const values: Array<{
    value: unknown;
    location: string;
  }> = [
    {
      value:
        req.originalUrl,
      location: "url",
    },

    {
      value:
        req.headers[
          "user-agent"
        ],
      location: "user-agent",
    },

    {
      value:
        req.headers[
          "referer"
        ],
      location: "referer",
    },

    {
      value:
        req.headers[
          "origin"
        ],
      location: "origin",
    },
  ];

  for (
    const item of values
  ) {
    if (
      typeof item.value ===
      "string"
    ) {
      const result =
        inspectString(
          site,
          item.value,
          item.location
        );

      score +=
        result.score;

      reasons.push(
        ...result.reasons
      );
    }
  }

  if (
    req.body !== undefined
  ) {
    const serialized =
      safeJson(
        req.body
      );

    if (serialized) {
      const result =
        inspectString(
          site,
          serialized,
          "body"
        );

      score +=
        result.score;

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
      ),
    ],
  };
}

/* ============================================================
   SITE STATS
============================================================ */

function registerSiteRequest(
  site: Site
): void {
  site.stats.totalRequests++;

  site.stats.lastRequestAt =
    new Date().toISOString();

  dbDirty = true;
}

function registerSiteAction(
  site: Site,
  action: Action,
  attack = false
): void {
  if (
    action === "allow"
  ) {
    site.stats.allowedRequests++;
  }

  if (
    action === "block"
  ) {
    site.stats.blockedRequests++;
  }

  if (
    action === "honeypot"
  ) {
    site.stats.honeypotRequests++;
  }

  if (attack) {
    site.stats.attacks++;

    site.stats.lastAttackAt =
      new Date().toISOString();
  }

  dbDirty = true;
}

/* ============================================================
   GLOBAL ANTI-BOT CHALLENGE
   AES-256-GCM + HMAC-SHA256
============================================================ */

const challengeSecret =
  Buffer.from(
    config.CHALLENGE_SECRET,
    "utf8"
  );

/*
 * Derive independent encryption/HMAC keys.
 */
const challengeEncryptionKey =
  crypto
    .createHash("sha256")
    .update(
      Buffer.concat([
        challengeSecret,
        Buffer.from(
          "routix-encryption-key",
          "utf8"
        ),
      ])
    )
    .digest();

const challengeHmacKey =
  crypto
    .createHash("sha256")
    .update(
      Buffer.concat([
        challengeSecret,
        Buffer.from(
          "routix-hmac-key",
          "utf8"
        ),
      ])
    )
    .digest();

const CHALLENGE_COOKIE =
  "__routix_challenge";

const CHALLENGE_WAIT_MS =
  config.CHALLENGE_WAIT_SECONDS *
  1000;

function hmacSign(
  value: string
): string {
  return base64UrlEncode(
    crypto
      .createHmac(
        "sha256",
        challengeHmacKey
      )
      .update(value)
      .digest()
  );
}

function createChallengeTicket(
  host: string,
  ip: string
): string {
  const issuedAt =
    Date.now();

  const nonce =
    crypto.randomBytes(24);

  const payload = {
    v: 1,
    host: normalizeHost(host),
    ipHash:
      crypto
        .createHash("sha256")
        .update(ip)
        .digest("hex"),
    issuedAt,
    nonce:
      base64UrlEncode(nonce),
  };

  const body =
    base64UrlEncode(
      JSON.stringify(payload)
    );

  const signature =
    hmacSign(body);

  return `${body}.${signature}`;
}

function verifyChallengeTicket(
  ticket: string,
  host: string,
  ip: string
): {
  valid: boolean;
  reason?: string;
} {
  try {
    const parts =
      ticket.split(".");

    if (
      parts.length !== 2
    ) {
      return {
        valid: false,
        reason: "invalid_ticket",
      };
    }

    const [
      body,
      signature,
    ] = parts;

    const expected =
      hmacSign(body);

    if (
      !secureCompare(
        signature,
        expected
      )
    ) {
      return {
        valid: false,
        reason:
          "invalid_signature",
      };
    }

    const payload =
      JSON.parse(
        base64UrlDecode(
          body
        ).toString("utf8")
      );

    if (
      !payload ||
      payload.v !== 1 ||
      typeof payload.host !==
        "string" ||
      typeof payload.ipHash !==
        "string" ||
      typeof payload.issuedAt !==
        "number" ||
      typeof payload.nonce !==
        "string"
    ) {
      return {
        valid: false,
        reason:
          "invalid_payload",
      };
    }

    const normalizedHost =
      normalizeHost(host);

    if (
      payload.host !==
      normalizedHost
    ) {
      return {
        valid: false,
        reason:
          "host_mismatch",
      };
    }

    const expectedIpHash =
      crypto
        .createHash("sha256")
        .update(ip)
        .digest("hex");

    if (
      payload.ipHash !==
      expectedIpHash
    ) {
      return {
        valid: false,
        reason:
          "ip_mismatch",
      };
    }

    const age =
      Date.now() -
      payload.issuedAt;

    if (
      age <
      CHALLENGE_WAIT_MS
    ) {
      return {
        valid: false,
        reason:
          "challenge_too_fast",
      };
    }

    if (
      age >
      config.CHALLENGE_TICKET_TTL_SECONDS *
        1000
    ) {
      return {
        valid: false,
        reason:
          "ticket_expired",
      };
    }

    return {
      valid: true,
    };
  } catch {
    return {
      valid: false,
      reason:
        "invalid_ticket",
    };
  }
}

function encryptChallengeCookie(
  data: {
    host: string;
    issuedAt: number;
    expiresAt: number;
    nonce: string;
  }
): string {
  const iv =
    crypto.randomBytes(12);

  const cipher =
    crypto.createCipheriv(
      "aes-256-gcm",
      challengeEncryptionKey,
      iv
    );

  const plaintext =
    JSON.stringify(data);

  const encrypted =
    Buffer.concat([
      cipher.update(
        plaintext,
        "utf8"
      ),
      cipher.final(),
    ]);

  const authTag =
    cipher.getAuthTag();

  const body = [
    base64UrlEncode(iv),
    base64UrlEncode(authTag),
    base64UrlEncode(encrypted),
  ].join(".");

  const signature =
    hmacSign(body);

  return `${body}.${signature}`;
}

function decryptChallengeCookie(
  value: string
): {
  valid: boolean;
  host?: string;
  issuedAt?: number;
  expiresAt?: number;
} {
  try {
    const parts =
      value.split(".");

    if (
      parts.length !== 4
    ) {
      return {
        valid: false,
      };
    }

    const [
      ivEncoded,
      tagEncoded,
      encryptedEncoded,
      signature,
    ] = parts;

    const body = [
      ivEncoded,
      tagEncoded,
      encryptedEncoded,
    ].join(".");

    const expected =
      hmacSign(body);

    if (
      !secureCompare(
        signature,
        expected
      )
    ) {
      return {
        valid: false,
      };
    }

    const iv =
      base64UrlDecode(
        ivEncoded
      );

    const authTag =
      base64UrlDecode(
        tagEncoded
      );

    const encrypted =
      base64UrlDecode(
        encryptedEncoded
      );

    const decipher =
      crypto.createDecipheriv(
        "aes-256-gcm",
        challengeEncryptionKey,
        iv
      );

    decipher.setAuthTag(
      authTag
    );

    const decrypted =
      Buffer.concat([
        decipher.update(
          encrypted
        ),
        decipher.final(),
      ]).toString("utf8");

    const payload =
      JSON.parse(
        decrypted
      );

    if (
      !payload ||
      typeof payload.host !==
        "string" ||
      typeof payload.issuedAt !==
        "number" ||
      typeof payload.expiresAt !==
        "number"
    ) {
      return {
        valid: false,
      };
    }

    if (
      payload.expiresAt <
      Date.now()
    ) {
      return {
        valid: false,
      };
    }

    return {
      valid: true,
      host: payload.host,
      issuedAt:
        payload.issuedAt,
      expiresAt:
        payload.expiresAt,
    };
  } catch {
    return {
      valid: false,
    };
  }
}

function getCookie(
  req: Request,
  name: string
): string | null {
  const header =
    req.headers.cookie;

  if (!header) {
    return null;
  }

  const cookies =
    header.split(";");

  for (
    const cookie of cookies
  ) {
    const index =
      cookie.indexOf("=");

    if (index === -1) {
      continue;
    }

    const key =
      cookie
        .slice(0, index)
        .trim();

    if (key !== name) {
      continue;
    }

    return decodeURIComponent(
      cookie
        .slice(index + 1)
        .trim()
    );
  }

  return null;
}

function setChallengeCookie(
  req: Request,
  res: Response,
  value: string
): void {
  const secure =
    req.secure ||
    req.headers["x-forwarded-proto"] ===
      "https";

  const parts = [
    `${CHALLENGE_COOKIE}=${encodeURIComponent(
      value
    )}`,

    "Path=/",

    "HttpOnly",

    "SameSite=Lax",

    `Max-Age=${config.CHALLENGE_TTL_SECONDS}`,
  ];

  if (secure) {
    parts.push(
      "Secure"
    );
  }

  res.setHeader(
    "Set-Cookie",
    parts.join("; ")
  );
}

function clearChallengeCookie(
  res: Response
): void {
  res.setHeader(
    "Set-Cookie",
    `${CHALLENGE_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`
  );
}

function isChallengeCookieValid(
  req: Request
): boolean {
  const cookie =
    getCookie(
      req,
      CHALLENGE_COOKIE
    );

  if (!cookie) {
    return false;
  }

  const result =
    decryptChallengeCookie(
      cookie
    );

  if (!result.valid) {
    return false;
  }

  const currentHost =
    normalizeHost(
      req.headers.host || ""
    );

  if (
    result.host !==
    currentHost
  ) {
    return false;
  }

  return true;
}

function sendChallengePage(
  req: Request,
  res: Response
): void {
  const host =
    normalizeHost(
      req.headers.host || ""
    );

  const ip =
    getClientIp(req);

  const ticket =
    createChallengeTicket(
      host,
      ip
    );

  const safeTicket =
    JSON.stringify(ticket);

  const wait =
    config.CHALLENGE_WAIT_SECONDS;

  res.status(403);

  res.setHeader(
    "Cache-Control",
    "no-store, no-cache, must-revalidate, proxy-revalidate"
  );

  res.setHeader(
    "Pragma",
    "no-cache"
  );

  res.setHeader(
    "Expires",
    "0"
  );

  res.setHeader(
    "Content-Type",
    "text/html; charset=utf-8"
  );

  res.send(`
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow,noarchive">
<title>Checking your browser</title>
<style>
html,body{
  margin:0;
  width:100%;
  height:100%;
  background:#02060b;
  color:#dce7f5;
  font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
}
body{
  display:flex;
  align-items:center;
  justify-content:center;
}
.box{
  text-align:center;
  max-width:420px;
  padding:30px;
}
.spinner{
  width:34px;
  height:34px;
  margin:0 auto 20px;
  border:3px solid rgba(255,255,255,.12);
  border-top-color:#fff;
  border-radius:50%;
  animation:spin .8s linear infinite;
}
@keyframes spin{
  to{transform:rotate(360deg)}
}
.small{
  opacity:.55;
  font-size:13px;
  margin-top:10px;
}
</style>
</head>
<body>
<div class="box">
  <div class="spinner"></div>
  <div>Checking your browser...</div>
  <div class="small">Please wait ${wait} seconds.</div>
</div>

<script>
(function(){
  "use strict";

  const ticket = ${safeTicket};

  const waitMs = ${CHALLENGE_WAIT_MS};

  const started = Date.now();

  setTimeout(async function(){
    try {
      const elapsed = Date.now() - started;

      if (elapsed < waitMs) {
        return;
      }

      const response = await fetch(
        "/__waf/challenge/verify",
        {
          method: "POST",
          credentials: "same-origin",
          cache: "no-store",
          headers: {
            "Content-Type": "application/json",
            "X-Routix-Challenge": ticket
          },
          body: JSON.stringify({
            ticket: ticket
          })
        }
      );

      if (response.ok) {
        window.location.reload();
        return;
      }

      document.body.innerHTML =
        '<div class="box"><div>Verification failed.</div></div>';
    } catch {
      document.body.innerHTML =
        '<div class="box"><div>Verification failed.</div></div>';
    }
  }, waitMs);
})();
</script>
</body>
</html>
  `);
}

/*
 * Challenge verification endpoint.
 */
function challengeVerification(
  req: Request,
  res: Response
): void {
  const supplied =
    String(
      req.headers[
        "x-routix-challenge"
      ] ||
        req.body?.ticket ||
        ""
    );

  if (!supplied) {
    return res
      .status(400)
      .json({
        error:
          "missing_challenge_ticket",
      });
  }

  const result =
    verifyChallengeTicket(
      supplied,
      req.headers.host || "",
      getClientIp(req)
    );

  if (!result.valid) {
    clearChallengeCookie(
      res
    );

    return res
      .status(403)
      .json({
        error:
          "challenge_failed",
        reason:
          result.reason ||
          "verification_failed",
      });
  }

  const host =
    normalizeHost(
      req.headers.host || ""
    );

  const issuedAt =
    Date.now();

  const expiresAt =
    issuedAt +
    config.CHALLENGE_TTL_SECONDS *
      1000;

  const nonce =
    crypto
      .randomBytes(32)
      .toString("hex");

  const cookie =
    encryptChallengeCookie({
      host,
      issuedAt,
      expiresAt,
      nonce,
    });

  setChallengeCookie(
    req,
    res,
    cookie
  );

  res.setHeader(
    "Cache-Control",
    "no-store"
  );

  return res.json({
    success: true,
    verified: true,
    expiresAt,
  });
}

/* ============================================================
   EXPRESS
============================================================ */

const app =
  express();

app.disable(
  "x-powered-by"
);

if (config.TRUST_PROXY) {
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
      false,
    crossOriginEmbedderPolicy:
      false,
  })
);

/* ============================================================
   BODY LIMITS
============================================================ */

app.use(
  express.json({
    limit:
      config.MAX_BODY_SIZE,

    strict: true,
  })
);

app.use(
  express.urlencoded({
    extended: false,

    limit:
      config.MAX_BODY_SIZE,
  })
);

/* ============================================================
   BASIC SECURITY
============================================================ */

app.use(
  (
    req: Request,
    res: Response,
    next: NextFunction
  ) => {
    res.setHeader(
      "X-Content-Type-Options",
      "nosniff"
    );

    res.setHeader(
      "X-Frame-Options",
      "SAMEORIGIN"
    );

    res.setHeader(
      "Referrer-Policy",
      "strict-origin-when-cross-origin"
    );

    res.setHeader(
      "Permissions-Policy",
      "camera=(), microphone=(), geolocation=()"
    );

    return next();
  }
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

  if (!authorization) {
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
    authorization.split(" ");

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
    decoded.indexOf(":");

  if (separator === -1) {
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
   API KEY AUTH
============================================================ */

function siteApiAuth(
  req: Request,
  res: Response,
  next: NextFunction
) {
  const suppliedKey =
    req.header(
      "x-waf-api-key"
    );

  if (!suppliedKey) {
    return res
      .status(401)
      .json({
        error:
          "missing_api_key",
      });
  }

  const site =
    getSiteByApiKey(
      suppliedKey
    );

  if (!site) {
    return res
      .status(401)
      .json({
        error:
          "invalid_api_key",
      });
  }

  (
    req as WafRequest
  ).wafSite =
    site;

  return next();
}

/* ============================================================
   CHALLENGE ENDPOINTS
============================================================ */

app.post(
  "/__waf/challenge/verify",
  challengeVerification
);

/*
 * Allows a browser to explicitly clear its challenge.
 */
app.post(
  "/__waf/challenge/reset",
  (_req, res) => {
    clearChallengeCookie(
      res
    );

    return res.json({
      success: true,
    });
  }
);

/* ============================================================
   ADMIN API - SITES
============================================================ */

app.get(
  "/__waf/admin/sites",
  adminAuth,
  (_req, res) => {
    return res.json({
      sites:
        db.sites.map(
          (site) => ({
            id: site.id,
            owner_id:
              site.owner_id,
            client_domain:
              site.client_domain,
            domains:
              site.domains,
            target_url:
              site.target_url,
            api_key:
              site.api_key,
            settings:
              site.settings,
            stats:
              site.stats,
          })
        ),
    });
  }
);

/* ============================================================
   ADMIN API - CREATE SITE
============================================================ */

app.post(
  "/__waf/admin/sites",
  adminAuth,
  (req, res) => {
    const schema =
      z.object({
        owner_id:
          z.string()
            .min(1),

        client_domain:
          z.string()
            .min(1)
            .optional(),

        domains:
          z.array(
            z.string().min(1)
          )
          .optional(),

        target_url:
          z.string().url(),

        api_key:
          z.string()
            .min(20)
            .optional(),

        settings:
          z.record(
            z.unknown()
          )
          .default({}),
      });

    const parsed =
      schema.safeParse(
        req.body
      );

    if (!parsed.success) {
      return res
        .status(400)
        .json({
          error:
            "invalid_site_data",
          details:
            parsed.error.flatten(),
        });
    }

    const incomingDomains =
      normalizeDomains([
        ...(parsed.data
          .client_domain
          ? [
              parsed.data
                .client_domain,
            ]
          : []),

        ...(parsed.data
          .domains || []),
      ]);

    if (
      incomingDomains.length ===
      0
    ) {
      return res
        .status(400)
        .json({
          error:
            "at_least_one_domain_required",
        });
    }

    /*
     * Validate target URL.
     */
    let targetUrl: URL;

    try {
      targetUrl =
        new URL(
          parsed.data.target_url
        );
    } catch {
      return res
        .status(400)
        .json({
          error:
            "invalid_target_url",
        });
    }

    if (
      !["http:", "https:"].includes(
        targetUrl.protocol
      )
    ) {
      return res
        .status(400)
        .json({
          error:
            "target_url_must_use_http_or_https",
        });
    }

    const alreadyUsed =
      incomingDomains.find(
        (domain) =>
          db.sites.some(
            (site) => {
              const siteDomains =
                normalizeDomains([
                  site.client_domain,
                  ...(site.domains ||
                    []),
                ]);

              return siteDomains.includes(
                domain
              );
            }
          )
      );

    if (alreadyUsed) {
      return res
        .status(409)
        .json({
          error:
            "domain_already_exists",

          domain:
            alreadyUsed,
        });
    }

    const primaryDomain =
      incomingDomains[0];

    const settings =
      parsed.data.settings as SiteSettings;

    if (
      typeof settings
        .enableChallenge !==
      "boolean"
    ) {
      settings.enableChallenge =
        true;
    }

    const site: Site = {
      id:
        crypto.randomUUID(),

      owner_id:
        parsed.data.owner_id,

      client_domain:
        primaryDomain,

      domains:
        incomingDomains,

      target_url:
        targetUrl.toString(),

      api_key:
        parsed.data.api_key ||
        crypto
          .randomBytes(32)
          .toString("hex"),

      settings,

      stats:
        createSiteStats(),
    };

    db.sites.push(
      site
    );

    dbDirty = true;

    saveDb();

    return res
      .status(201)
      .json({
        site,
      });
  }
);

/* ============================================================
   ADMIN API - ADD DOMAINS
============================================================ */

app.post(
  "/__waf/admin/sites/:id/domains",
  adminAuth,
  (req, res) => {
    const site =
      getSiteById(
        req.params.id
      );

    if (!site) {
      return res
        .status(404)
        .json({
          error:
            "site_not_found",
        });
    }

    const schema =
      z.object({
        domains:
          z.array(
            z.string().min(1)
          )
          .min(1),
      });

    const parsed =
      schema.safeParse(
        req.body
      );

    if (!parsed.success) {
      return res
        .status(400)
        .json({
          error:
            "invalid_domains",

          details:
            parsed.error.flatten(),
        });
    }

    const newDomains =
      normalizeDomains(
        parsed.data.domains
      );

    const existingDomains =
      normalizeDomains([
        site.client_domain,
        ...(site.domains ||
          []),
      ]);

    const conflicts: string[] =
      [];

    for (
      const domain of newDomains
    ) {
      const usedByOther =
        db.sites.some(
          (otherSite) => {
            if (
              otherSite.id ===
              site.id
            ) {
              return false;
            }

            const otherDomains =
              normalizeDomains([
                otherSite.client_domain,
                ...(otherSite.domains ||
                  []),
              ]);

            return otherDomains.includes(
              domain
            );
          }
        );

      if (usedByOther) {
        conflicts.push(
          domain
        );
      }
    }

    if (conflicts.length) {
      return res
        .status(409)
        .json({
          error:
            "domain_already_exists",

          domains:
            conflicts,
        });
    }

    site.domains =
      normalizeDomains([
        ...existingDomains,
        ...newDomains,
      ]);

    if (
      !site.client_domain
    ) {
      site.client_domain =
        site.domains[0] ||
        "";
    }

    dbDirty = true;

    saveDb();

    return res.json({
      success: true,
      site,
    });
  }
);

/* ============================================================
   ADMIN API - DELETE DOMAIN
============================================================ */

app.delete(
  "/__waf/admin/sites/:id/domains",
  adminAuth,
  (req, res) => {
    const site =
      getSiteById(
        req.params.id
      );

    if (!site) {
      return res
        .status(404)
        .json({
          error:
            "site_not_found",
        });
    }

    const domain =
      normalizeDomain(
        String(
          req.body?.domain ||
            req.query.domain ||
            ""
        )
      );

    if (!domain) {
      return res
        .status(400)
        .json({
          error:
            "domain_required",
        });
    }

    const currentDomains =
      normalizeDomains([
        site.client_domain,
        ...(site.domains ||
          []),
      ]);

    if (
      !currentDomains.includes(
        domain
      )
    ) {
      return res
        .status(404)
        .json({
          error:
            "domain_not_found",
        });
    }

    if (
      currentDomains.length <= 1
    ) {
      return res
        .status(400)
        .json({
          error:
            "cannot_remove_last_domain",
        });
    }

    const remaining =
      currentDomains.filter(
        (item) =>
          item !== domain
      );

    site.domains =
      remaining;

    if (
      site.client_domain ===
      domain
    ) {
      site.client_domain =
        remaining[0];
    }

    dbDirty = true;

    saveDb();

    return res.json({
      success: true,
      site,
    });
  }
);

/* ============================================================
   ADMIN API - DELETE SITE
============================================================ */

app.delete(
  "/__waf/admin/sites/:id",
  adminAuth,
  (req, res) => {
    const index =
      db.sites.findIndex(
        (site) =>
          site.id ===
          req.params.id
      );

    if (index === -1) {
      return res
        .status(404)
        .json({
          error:
            "site_not_found",
        });
    }

    const removed =
      db.sites.splice(
        index,
        1
      )[0];

    if (!removed) {
      return res
        .status(404)
        .json({
          error:
            "site_not_found",
        });
    }

    for (
      const key of Object.keys(
        db.blacklists
      )
    ) {
      if (
        key.startsWith(
          `${removed.id}:`
        )
      ) {
        delete db.blacklists[
          key
        ];
      }
    }

    for (
      const key of Object.keys(
        db.risks
      )
    ) {
      if (
        key.startsWith(
          `${removed.id}:`
        )
      ) {
        delete db.risks[
          key
        ];
      }
    }

    db.alerts =
      db.alerts.filter(
        (alert) =>
          alert.siteId !==
          removed.id
      );

    dbDirty = true;

    saveDb();

    return res.json({
      deleted: true,
    });
  }
);

/* ============================================================
   SITE API - STATS
============================================================ */

app.get(
  "/__waf/api/stats",
  siteApiAuth,
  (req, res) => {
    const site =
      (req as WafRequest)
        .wafSite!;

    return res.json({
      site: {
        id: site.id,

        owner_id:
          site.owner_id,

        client_domain:
          site.client_domain,

        domains:
          site.domains,

        target_url:
          site.target_url,
      },

      stats:
        site.stats,
    });
  }
);

/* ============================================================
   SITE API - ALERTS
============================================================ */

app.get(
  "/__waf/api/alerts",
  siteApiAuth,
  (req, res) => {
    const site =
      (req as WafRequest)
        .wafSite!;

    const limit =
      Math.min(
        Math.max(
          Number(
            req.query.limit
          ) || 100,
          1
        ),
        500
      );

    const alerts =
      db.alerts
        .filter(
          (alert) =>
            alert.siteId ===
            site.id
        )
        .slice(
          0,
          limit
        );

    return res.json({
      site_id:
        site.id,

      client_domain:
        site.client_domain,

      domains:
        site.domains,

      alerts,
    });
  }
);

/* ============================================================
   SITE API - STATUS
============================================================ */

app.get(
  "/__waf/api/status",
  siteApiAuth,
  (req, res) => {
    const site =
      (req as WafRequest)
        .wafSite!;

    const ip =
      normalizeIp(
        String(
          req.query.ip ||
            getClientIp(req)
        )
      );

    return res.json({
      site_id:
        site.id,

      client_domain:
        site.client_domain,

      domains:
        site.domains,

      ip,

      blacklisted:
        isBlacklisted(
          site,
          ip
        ),

      risk:
        getRisk(
          site,
          ip
        ),

      concurrent:
        concurrentByIp.get(
          `${site.id}:${ip}`
        ) || 0,
    });
  }
);

/* ============================================================
   ADMIN API - ALERTS
============================================================ */

app.get(
  "/__waf/admin/alerts",
  adminAuth,
  (req, res) => {
    const siteId =
      typeof req.query.site_id ===
      "string"
        ? req.query.site_id
        : null;

    const alerts =
      siteId
        ? db.alerts.filter(
            (alert) =>
              alert.siteId ===
              siteId
          )
        : db.alerts;

    return res.json({
      alerts:
        alerts.slice(
          0,
          500
        ),
    });
  }
);

/* ============================================================
   ADMIN API - STATS
============================================================ */

app.get(
  "/__waf/admin/stats",
  adminAuth,
  (_req, res) => {
    let blacklisted = 0;

    const now =
      Date.now();

    for (
      const entry of Object.values(
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

    const totals =
      db.sites.reduce(
        (
          result,
          site
        ) => {
          result.requests +=
            site.stats.totalRequests;

          result.allowed +=
            site.stats.allowedRequests;

          result.blocked +=
            site.stats.blockedRequests;

          result.honeypot +=
            site.stats.honeypotRequests;

          result.attacks +=
            site.stats.attacks;

          return result;
        },

        {
          requests: 0,
          allowed: 0,
          blocked: 0,
          honeypot: 0,
          attacks: 0,
        }
      );

    return res.json({
      sites:
        db.sites.length,

      globalConcurrent,

      activeClients:
        concurrentByIp.size,

      activeSites:
        concurrentBySite.size,

      blacklisted,

      alerts:
        db.alerts.length,

      totals,

      uptime:
        Math.floor(
          process.uptime()
        ),
    });
  }
);

/* ============================================================
   ADMIN API - SITE DETAILS
============================================================ */

app.get(
  "/__waf/admin/sites/:id",
  adminAuth,
  (req, res) => {
    const site =
      getSiteById(
        req.params.id
      );

    if (!site) {
      return res
        .status(404)
        .json({
          error:
            "site_not_found",
        });
    }

    return res.json({
      site,

      alerts:
        db.alerts
          .filter(
            (alert) =>
              alert.siteId ===
              site.id
          )
          .slice(
            0,
            200
          ),
    });
  }
);

/* ============================================================
   ADMIN EVENTS
============================================================ */

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

    alertClients.add(
      res
    );

    res.write(
      `data: ${JSON.stringify({
        type: "connected",
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
    res
      .type("html")
      .send(`
<!doctype html>
<html lang="ar" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Routix — WAF Admin</title>
<style>
*{
  box-sizing:border-box;
}
body{
  margin:0;
  background:#02060b;
  color:#e8eef7;
  font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
}
main{
  width:min(1200px,94%);
  margin:30px auto;
}
h1,h2{
  margin-top:0;
}
.card{
  background:#09111b;
  border:1px solid #182635;
  border-radius:16px;
  padding:20px;
  margin-bottom:20px;
}
.grid{
  display:grid;
  grid-template-columns:repeat(auto-fit,minmax(160px,1fr));
  gap:12px;
}
.stat{
  padding:18px;
  border:1px solid #182635;
  border-radius:12px;
  background:#060c13;
}
.stat b{
  display:block;
  font-size:26px;
  margin-top:5px;
}
input,textarea,button{
  width:100%;
  padding:12px;
  margin-top:8px;
  border-radius:9px;
  border:1px solid #26384a;
  background:#050a10;
  color:#fff;
}
button{
  cursor:pointer;
  background:#102337;
}
button:hover{
  background:#17324c;
}
.site{
  border:1px solid #1b2c3d;
  padding:16px;
  border-radius:12px;
  margin-top:12px;
}
pre{
  white-space:pre-wrap;
  word-break:break-word;
  font-size:12px;
  opacity:.85;
}
.success{
  color:#7ee2a8;
}
.error{
  color:#ff8585;
}
</style>
</head>

<body>
<main>

<div class="card">
<h1>🛡️ Routix Multi-Site WAF Admin</h1>

<div class="grid">
<div class="stat">
المواقع
<b id="sites">0</b>
</div>

<div class="stat">
الطلبات
<b id="requests">0</b>
</div>

<div class="stat">
الهجمات
<b id="attacks">0</b>
</div>

<div class="stat">
IPs المحظورة
<b id="blacklisted">0</b>
</div>

<div class="stat">
الاتصالات الحالية
<b id="concurrent">0</b>
</div>
</div>
</div>

<div class="card">
<h2>➕ إضافة موقع للحماية</h2>

<p>
أضف الدومين الذي تريد حمايته عبر Routix.
يمكنك إضافة أكثر من دومين لنفس الموقع، كل دومين في سطر مستقل.
</p>

<label>Owner ID</label>
<input id="owner_id" value="default">

<label>Target URL</label>
<input id="target_url" placeholder="http://127.0.0.1:3000">

<label>الدومينات المراد حمايتها</label>
<textarea id="domains" rows="5"
placeholder="example.com&#10;www.example.com"></textarea>

<button onclick="createSite()">
إضافة الموقع
</button>

<div id="message"></div>
</div>

<div class="card">
<h2>🌐 المواقع المحمية</h2>
<div id="sitesList">
جاري التحميل...
</div>
</div>

<div class="card">
<h2>🚨 التنبيهات</h2>
<div id="alerts">
جاري التحميل...
</div>
</div>

</main>

<script>
"use strict";

async function api(url, options){
  const response = await fetch(url, options);

  let data = null;

  try{
    data = await response.json();
  }catch{}

  if(!response.ok){
    throw new Error(
      data && data.error
        ? data.error
        : "Request failed"
    );
  }

  return data;
}

async function createSite(){
  const owner_id =
    document.getElementById("owner_id").value.trim();

  const target_url =
    document.getElementById("target_url").value.trim();

  const domains =
    document.getElementById("domains").value
      .split("\\n")
      .map(x => x.trim())
      .filter(Boolean);

  const message =
    document.getElementById("message");

  try{
    const data = await api(
      "/__waf/admin/sites",
      {
        method:"POST",
        headers:{
          "Content-Type":"application/json"
        },
        body:JSON.stringify({
          owner_id,
          target_url,
          domains,
          settings:{
            enabled:true,
            enableChallenge:true,
            enableSqlInjection:true,
            enableXss:true,
            enableRce:true,
            enablePathTraversal:true
          }
        })
      }
    );

    message.className = "success";

    message.innerHTML =
      "تمت إضافة الموقع بنجاح.<br>" +
      "API Key: <code>" +
      escapeHtml(data.site.api_key) +
      "</code>";

    document.getElementById("domains").value = "";

    await loadAll();
  }catch(error){
    message.className = "error";
    message.textContent =
      "خطأ: " + error.message;
  }
}

function escapeHtml(value){
  return String(value)
    .replace(/&/g,"&amp;")
    .replace(/</g,"&lt;")
    .replace(/>/g,"&gt;")
    .replace(/"/g,"&quot;")
    .replace(/'/g,"&#039;");
}

async function loadStats(){
  const data =
    await api("/__waf/admin/stats");

  document.getElementById("sites")
    .textContent = data.sites;

  document.getElementById("requests")
    .textContent = data.totals.requests;

  document.getElementById("attacks")
    .textContent = data.totals.attacks;

  document.getElementById("blacklisted")
    .textContent = data.blacklisted;

  document.getElementById("concurrent")
    .textContent = data.globalConcurrent;
}

async function loadSites(){
  const data =
    await api("/__waf/admin/sites");

  const container =
    document.getElementById("sitesList");

  if(!data.sites.length){
    container.textContent =
      "لا توجد مواقع مسجلة.";
    return;
  }

  container.innerHTML =
    data.sites.map(site => {

      return \`
      <div class="site">
        <strong>\${escapeHtml(site.client_domain)}</strong>

        <p>
          Domains:
          \${escapeHtml(site.domains.join(", "))}
        </p>

        <p>
          Target:
          \${escapeHtml(site.target_url)}
        </p>

        <p>
          Challenge:
          \${site.settings.enableChallenge !== false
            ? "مفعل"
            : "معطل"}
        </p>

        <p>
          Requests:
          \${site.stats.totalRequests}
          |
          Blocked:
          \${site.stats.blockedRequests}
          |
          Attacks:
          \${site.stats.attacks}
        </p>

        <details>
          <summary>API Key</summary>
          <pre>\${escapeHtml(site.api_key)}</pre>
        </details>

        <button onclick="deleteSite('\${site.id}')">
          حذف الموقع
        </button>
      </div>
      \`;
    }).join("");
}

async function deleteSite(id){
  if(!confirm("هل تريد حذف الموقع؟")){
    return;
  }

  try{
    await api(
      "/__waf/admin/sites/" +
      encodeURIComponent(id),
      {
        method:"DELETE"
      }
    );

    await loadAll();
  }catch(error){
    alert(error.message);
  }
}

async function loadAlerts(){
  const data =
    await api("/__waf/admin/alerts");

  const container =
    document.getElementById("alerts");

  if(!data.alerts.length){
    container.textContent =
      "لا توجد تنبيهات.";
    return;
  }

  container.innerHTML =
    data.alerts.map(alert => \`
      <div class="site">
        <strong>
          \${escapeHtml(alert.action)}
        </strong>

        <p>
          Domain:
          \${escapeHtml(alert.domain)}
        </p>

        <p>
          IP:
          \${escapeHtml(alert.ip)}
        </p>

        <p>
          Risk:
          \${alert.risk}
        </p>

        <p>
          Path:
          \${escapeHtml(alert.path)}
        </p>

        <pre>
\${escapeHtml(alert.reasons.join("\\n"))}
        </pre>
      </div>
    \`).join("");
}

async function loadAll(){
  try{
    await Promise.all([
      loadStats(),
      loadSites(),
      loadAlerts()
    ]);
  }catch(error){
    console.error(error);
  }
}

loadAll();

setInterval(
  loadAll,
  5000
);

const events =
  new EventSource(
    "/__waf/admin/events"
  );

events.onmessage =
  function(){
    loadAll();
  };
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
        "multi-site-cloud-waf",

      protection:
        "strong-l7",

      challenge:
        "global-anti-bot",

      challengeWaitSeconds:
        config.CHALLENGE_WAIT_SECONDS,

      sites:
        db.sites.length,

      globalConcurrent,

      activeClients:
        concurrentByIp.size,

      serverHosts:
        [
          ...SERVER_HOSTS,
        ],
    });
  }
);

/* ============================================================
   OLD STATUS COMPATIBILITY
============================================================ */

app.get(
  "/__waf/status/:ip",
  siteApiAuth,
  (req, res) => {
    const site =
      (req as WafRequest)
        .wafSite!;

    const ip =
      normalizeIp(
        req.params.ip
      );

    return res.json({
      site_id:
        site.id,

      domain:
        site.client_domain,

      domains:
        site.domains,

      ip,

      blacklisted:
        isBlacklisted(
          site,
          ip
        ),

      risk:
        getRisk(
          site,
          ip
        ),

      concurrent:
        concurrentByIp.get(
          `${site.id}:${ip}`
        ) || 0,
    });
  }
);

/* ============================================================
   HONEYPOT
============================================================ */

app.all(
  "/__waf_honeypot",
  (req, res) => {
    const host =
      req.headers.host ||
      "";

    const site =
      getSiteByHost(
        host
      );

    if (!site) {
      return res
        .status(404)
        .json({
          error:
            "not_found",
        });
    }

    const ip =
      getClientIp(req);

    const score =
      addRisk(
        site,
        ip,
        settingNumber(
          site,
          "riskBlockThreshold",
          config.RISK_BLOCK_THRESHOLD
        )
      );

    blacklist(
      site,
      ip,
      "honeypot_triggered"
    );

    registerSiteAction(
      site,
      "block",
      true
    );

    addAlert({
      site,

      ip,

      path:
        req.originalUrl,

      risk: score,

      action:
        "block",

      reasons: [
        "honeypot_triggered",
      ],
    });

    return res
      .status(404)
      .json({
        error:
          "not_found",
      });
  }
);

/* ============================================================
   SITE RESOLUTION
============================================================ */

function resolveSite(
  req: Request,
  res: Response
): Site | null {
  const host =
    normalizeHost(
      req.headers.host ||
        ""
    );

  /*
   * Routix itself.
   */
  if (
    SERVER_HOSTS.has(host)
  ) {
    return null;
  }

  const site =
    getSiteByHost(host);

  if (!site) {
    res
      .status(404)
      .json({
        error:
          "site_not_configured",

        host,
      });

    return null;
  }

  return site;
}

/* ============================================================
   GLOBAL ANTI-BOT MIDDLEWARE
============================================================ */

app.use(
  (
    req,
    res,
    next
  ) => {
    const host =
      normalizeHost(
        req.headers.host ||
          ""
      );

    /*
     * Challenge verification itself
     * must always be accessible.
     */
    if (
      req.path ===
        "/__waf/challenge/verify" ||
      req.path ===
        "/__waf/challenge/reset"
    ) {
      return next();
    }

    /*
     * Internal WAF API and admin
     * are intentionally excluded.
     */
    if (
      req.path.startsWith(
        "/__waf/"
      ) ||
      req.path === "/admin"
    ) {
      return next();
    }

    /*
     * If it is a completely unknown host,
     * let normal site resolution handle it.
     */
    const site =
      getSiteByHost(host);

    const isRoutixHost =
      SERVER_HOSTS.has(host);

    const challengeEnabled =
      isRoutixHost
        ? true
        : site
          ? settingBoolean(
              site,
              "enableChallenge",
              true
            )
          : true;

    if (
      !challengeEnabled
    ) {
      return next();
    }

    /*
     * Existing valid cookie:
     * visitor already passed.
     */
    if (
      isChallengeCookieValid(
        req
      )
    ) {
      return next();
    }

    /*
     * Challenge is designed for
     * browser navigation.
     */
    if (
      req.method !== "GET" &&
      req.method !== "HEAD"
    ) {
      res.setHeader(
        "Cache-Control",
        "no-store"
      );

      return res
        .status(403)
        .json({
          error:
            "browser_challenge_required",

          message:
            "Open the website in a browser first and complete the security check.",
        });
    }

    return sendChallengePage(
      req,
      res
    );
  }
);

/* ============================================================
   SERVER WEBSITE
============================================================ */

app.use(
  (
    req,
    res,
    next
  ) => {
    const host =
      normalizeHost(
        req.headers.host ||
          ""
      );

    /*
     * ONLY Routix's own domains.
     */
    if (
      !SERVER_HOSTS.has(host)
    ) {
      return next();
    }

    /*
     * Keep APIs/Admin working.
     */
    if (
      req.path.startsWith(
        "/__waf/"
      ) ||
      req.path === "/admin"
    ) {
      return next();
    }

    /*
     * Only GET/HEAD serve website.
     */
    if (
      req.method !== "GET" &&
      req.method !== "HEAD"
    ) {
      return next();
    }

    /*
     * Root -> index.html.
     */
    if (
      req.path === "/"
    ) {
      if (
        !fs.existsSync(
          INDEX_FILE
        )
      ) {
        return res
          .status(500)
          .json({
            error:
              "index_html_not_found",

            expected:
              INDEX_FILE,
          });
      }

      return res.sendFile(
        INDEX_FILE
      );
    }

    /*
     * Static assets.
     */
    return express.static(
      PROJECT_DIR,
      {
        index: false,

        fallthrough:
          true,

        redirect:
          false,
      }
    )(
      req,
      res,
      next
    );
  }
);

/* ============================================================
   SPA FALLBACK FOR ROUTIX
============================================================ */

app.use(
  (
    req,
    res,
    next
  ) => {
    const host =
      normalizeHost(
        req.headers.host ||
          ""
      );

    if (
      !SERVER_HOSTS.has(host)
    ) {
      return next();
    }

    if (
      req.path.startsWith(
        "/__waf/"
      ) ||
      req.path === "/admin"
    ) {
      return next();
    }

    if (
      req.method !== "GET" &&
      req.method !== "HEAD"
    ) {
      return next();
    }

    if (
      !fs.existsSync(
        INDEX_FILE
      )
    ) {
      return res
        .status(500)
        .json({
          error:
            "index_html_not_found",

          expected:
            INDEX_FILE,
        });
    }

    return res.sendFile(
      INDEX_FILE
    );
  }
);

/* ============================================================
   WAF MIDDLEWARE
============================================================ */

app.use(
  async (
    req,
    res,
    next
  ) => {
    const host =
      normalizeHost(
        req.headers.host ||
          ""
      );

    /*
     * Routix website has already
     * passed the global challenge.
     */
    if (
      SERVER_HOSTS.has(host)
    ) {
      return next();
    }

    /*
     * WAF internal APIs.
     */
    if (
      req.path.startsWith(
        "/__waf/"
      )
    ) {
      return next();
    }

    /*
     * Admin dashboard.
     */
    if (
      req.path === "/admin"
    ) {
      return next();
    }

    const site =
      resolveSite(
        req,
        res
      );

    if (!site) {
      return;
    }

    let acquired =
      false;

    try {
      const decision =
        await evaluate(
          req,
          site
        );

      acquired =
        decision.action ===
        "allow";

      res.setHeader(
        "x-waf-site-id",
        site.id
      );

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

      res.setHeader(
        "x-waf-client-domain",
        site.client_domain
      );

      if (
        decision.action ===
        "block"
      ) {
        if (acquired) {
          releaseConcurrency(
            site,
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

            siteId:
              site.id,

            reasons:
              decision.reasons,
          });
      }

      if (
        decision.action ===
        "honeypot"
      ) {
        if (acquired) {
          releaseConcurrency(
            site,
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
              decision.requestId,
          });
      }

      (
        req as WafRequest
      ).wafSite =
        site;

      (
        req as WafRequest
      ).wafRequestId =
        decision.requestId;

      (
        req as WafRequest
      ).wafAcquired =
        acquired;

      return next();
    } catch (error) {
      if (acquired) {
        releaseConcurrency(
          site,
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
            "waf_unavailable",
        });
    }
  }
);

/* ============================================================
   EVALUATE WAF
============================================================ */

async function evaluate(
  req: Request,
  site: Site
): Promise<Decision> {
  const requestId =
    crypto.randomUUID();

  const ip =
    getClientIp(req);

  registerSiteRequest(
    site
  );

  if (
    !settingBoolean(
      site,
      "enabled",
      true
    )
  ) {
    registerSiteAction(
      site,
      "allow"
    );

    return {
      action: "allow",

      riskScore:
        getRisk(
          site,
          ip
        ),

      reasons: [],

      requestId,

      site,
    };
  }

  if (
    isBlacklisted(
      site,
      ip
    )
  ) {
    registerSiteAction(
      site,
      "block",
      true
    );

    return {
      action: "block",

      riskScore:
        settingNumber(
          site,
          "riskBlockThreshold",
          config.RISK_BLOCK_THRESHOLD
        ),

      reasons: [
        "site_blacklist",
      ],

      requestId,

      site,
    };
  }

  if (
    !checkGlobalRate(
      site
    )
  ) {
    const score =
      addRisk(
        site,
        ip,
        20
      );

    registerViolation(
      site,
      ip
    );

    const action: Action =
      score >=
      settingNumber(
        site,
        "riskHoneypotThreshold",
        config.RISK_HONEYPOT_THRESHOLD
      )
        ? "honeypot"
        : "block";

    registerSiteAction(
      site,
      action,
      true
    );

    addAlert({
      site,

      ip,

      path:
        req.originalUrl,

      risk:
        score,

      action,

      reasons: [
        "global_rate_limit",
      ],
    });

    return {
      action,

      riskScore:
        score,

      reasons: [
        "global_rate_limit",
      ],

      requestId,

      site,
    };
  }

  if (
    !checkBurst(
      site,
      ip
    )
  ) {
    const score =
      addRisk(
        site,
        ip,
        20
      );

    const count =
      registerViolation(
        site,
        ip
      );

    if (
      count >=
      settingNumber(
        site,
        "violationLimit",
        config.VIOLATION_LIMIT
      )
    ) {
      blacklist(
        site,
        ip,
        "repeated_burst_violation"
      );

      registerSiteAction(
        site,
        "block",
        true
      );

      addAlert({
        site,

        ip,

        path:
          req.originalUrl,

        risk:
          score,

        action:
          "block",

        reasons: [
          "repeated_burst_violation",
        ],
      });

      return {
        action:
          "block",

        riskScore:
          Math.max(
            score,

            settingNumber(
              site,
              "riskBlockThreshold",
              config.RISK_BLOCK_THRESHOLD
            )
          ),

        reasons: [
          "repeated_burst_violation",
        ],

        requestId,

        site,
      };
    }

    registerSiteAction(
      site,
      "honeypot",
      true
    );

    addAlert({
      site,

      ip,

      path:
        req.originalUrl,

      risk:
        score,

      action:
        "honeypot",

      reasons: [
        "burst_rate_limit",
      ],
    });

    return {
      action:
        "honeypot",

      riskScore:
        score,

      reasons: [
        "burst_rate_limit",
      ],

      requestId,

      site,
    };
  }

  const rate =
    checkRateLimit(
      site,
      ip
    );

  if (
    !rate.allowed
  ) {
    const score =
      addRisk(
        site,
        ip,
        30
      );

    const count =
      registerViolation(
        site,
        ip
      );

    if (
      count >=
      settingNumber(
        site,
        "violationLimit",
        config.VIOLATION_LIMIT
      )
    ) {
      blacklist(
        site,
        ip,
        "repeated_rate_limit_violation"
      );

      registerSiteAction(
        site,
        "block",
        true
      );

      addAlert({
        site,

        ip,

        path:
          req.originalUrl,

        risk:
          score,

        action:
          "block",

        reasons: [
          "rate_limit_violation",
        ],
      });

      return {
        action:
          "block",

        riskScore:
          Math.max(
            score,

            settingNumber(
              site,
              "riskBlockThreshold",
              config.RISK_BLOCK_THRESHOLD
            )
          ),

        reasons: [
          "rate_limit_violation",
        ],

        requestId,

        site,
      };
    }

    registerSiteAction(
      site,
      "honeypot",
      true
    );

    addAlert({
      site,

      ip,

      path:
        req.originalUrl,

      risk:
        score,

      action:
        "honeypot",

      reasons: [
        "rate_limit_violation",
      ],
    });

    return {
      action:
        "honeypot",

      riskScore:
        score,

      reasons: [
        "rate_limit_violation",
      ],

      requestId,

      site,
    };
  }

  if (
    !acquireConcurrency(
      site,
      ip
    )
  ) {
    const score =
      addRisk(
        site,
        ip,
        25
      );

    const count =
      registerViolation(
        site,
        ip
      );

    if (
      count >=
      settingNumber(
        site,
        "violationLimit",
        config.VIOLATION_LIMIT
      )
    ) {
      blacklist(
        site,
        ip,
        "connection_flood"
      );

      registerSiteAction(
        site,
        "block",
        true
      );

      addAlert({
        site,

        ip,

        path:
          req.originalUrl,

        risk:
          score,

        action:
          "block",

        reasons: [
          "connection_flood",
        ],
      });

      return {
        action:
          "block",

        riskScore:
          Math.max(
            score,

            settingNumber(
              site,
              "riskBlockThreshold",
              config.RISK_BLOCK_THRESHOLD
            )
          ),

        reasons: [
          "connection_flood",
        ],

        requestId,

        site,
      };
    }

    registerSiteAction(
      site,
      "honeypot",
      true
    );

    addAlert({
      site,

      ip,

      path:
        req.originalUrl,

      risk:
        score,

      action:
        "honeypot",

      reasons: [
        "too_many_concurrent_requests",
      ],
    });

    return {
      action:
        "honeypot",

      riskScore:
        score,

      reasons: [
        "too_many_concurrent_requests",
      ],

      requestId,

      site,
    };
  }

  const inspection =
    inspectRequest(
      site,
      req
    );

  const risk =
    inspection.score > 0
      ? addRisk(
          site,
          ip,
          inspection.score
        )
      : getRisk(
          site,
          ip
        );

  const blockThreshold =
    settingNumber(
      site,
      "riskBlockThreshold",
      config.RISK_BLOCK_THRESHOLD
    );

  const honeypotThreshold =
    settingNumber(
      site,
      "riskHoneypotThreshold",
      config.RISK_HONEYPOT_THRESHOLD
    );

  if (
    risk >=
    blockThreshold
  ) {
    blacklist(
      site,
      ip,
      inspection.reasons.join(
        ","
      ) ||
        "risk_threshold"
    );

    registerSiteAction(
      site,
      "block",
      true
    );

    addAlert({
      site,

      ip,

      path:
        req.originalUrl,

      risk,

      action:
        "block",

      reasons:
        inspection.reasons
          .length
          ? inspection.reasons
          : [
              "risk_threshold",
            ],
    });

    return {
      action:
        "block",

      riskScore:
        risk,

      reasons:
        inspection.reasons
          .length
          ? inspection.reasons
          : [
              "risk_threshold",
            ],

      requestId,

      site,
    };
  }

  if (
    risk >=
    honeypotThreshold
  ) {
    registerSiteAction(
      site,
      "honeypot",
      true
    );

    addAlert({
      site,

      ip,

      path:
        req.originalUrl,

      risk,

      action:
        "honeypot",

      reasons:
        inspection.reasons,
    });

    return {
      action:
        "honeypot",

      riskScore:
        risk,

      reasons:
        inspection.reasons,

      requestId,

      site,
    };
  }

  registerSiteAction(
    site,
    "allow",
    inspection.score > 0
  );

  return {
    action:
      "allow",

    riskScore:
      risk,

    reasons:
      inspection.reasons,

    requestId,

    site,
  };
}

/* ============================================================
   CONCURRENCY RELEASE
============================================================ */

app.use(
  (
    req,
    res,
    next
  ) => {
    const site =
      (req as WafRequest)
        .wafSite;

    if (!site) {
      return next();
    }

    let released =
      false;

    const release =
      () => {
        if (released) {
          return;
        }

        released = true;

        const acquired =
          (req as WafRequest)
            .wafAcquired;

        if (acquired) {
          releaseConcurrency(
            site,
            getClientIp(req)
          );

          (
            req as WafRequest
          ).wafAcquired =
            false;
        }
      };

    res.once(
      "finish",
      release
    );

    res.once(
      "close",
      release
    );

    return next();
  }
);

/* ============================================================
   DYNAMIC REVERSE PROXY
============================================================ */

const proxy =
  createProxyMiddleware({
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

    router:
      (req) => {
        const site =
          (req as WafRequest)
            .wafSite;

        if (!site) {
          return undefined;
        }

        return site.target_url;
      },

    onProxyReq:
      (
        proxyReq,
        req
      ) => {
        const site =
          (req as WafRequest)
            .wafSite;

        const requestId =
          (req as WafRequest)
            .wafRequestId;

        proxyReq.setHeader(
          "x-waf-protected",
          "true"
        );

        proxyReq.setHeader(
          "x-waf-site-id",
          site?.id || ""
        );

        proxyReq.setHeader(
          "x-waf-client-domain",
          site?.client_domain ||
            ""
        );

        proxyReq.setHeader(
          "x-waf-owner-id",
          site?.owner_id ||
            ""
        );

        proxyReq.setHeader(
          "x-waf-request-id",
          requestId ||
            crypto.randomUUID()
        );

        proxyReq.setHeader(
          "x-forwarded-for",
          getClientIp(req)
        );

        proxyReq.setHeader(
          "x-forwarded-host",
          req.headers.host ||
            ""
        );

        proxyReq.setHeader(
          "x-forwarded-proto",
          req.protocol ||
            "http"
        );

        fixRequestBody(
          proxyReq,
          req
        );
      },

    onError:
      (
        error,
        req,
        res
      ) => {
        const site =
          (req as WafRequest)
            .wafSite;

        console.error(
          "Proxy error:",
          error
        );

        if (site) {
          addAlert({
            site,

            ip:
              getClientIp(
                req
              ),

            path:
              req.originalUrl,

            risk:
              0,

            action:
              "block",

            reasons: [
              "proxy_error",
            ],
          });
        }

        if (
          !res.headersSent
        ) {
          res
            .status(502)
            .json({
              error:
                "protected_site_unavailable",
            });
        }
      },
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
            "internal_error",
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
  (socket) => {
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
      " Multi-Site Cloud WAF"
    );

    console.log(
      " Dynamic Reverse Proxy Enabled"
    );

    console.log(
      " Live Admin Dashboard Enabled"
    );

    console.log(
      " Multi-Domain Protection Enabled"
    );

    console.log(
      " L7 Protection Enabled"
    );

    console.log(
      " Global Anti-Bot Challenge Enabled"
    );

    console.log(
      ` Challenge Wait: ${config.CHALLENGE_WAIT_SECONDS}s`
    );

    console.log(
      ` WAF: http://0.0.0.0:${config.PORT}`
    );

    console.log(
      ` Sites: ${db.sites.length}`
    );

    console.log(
      ` Database: ${dbFilePath}`
    );

    console.log(
      ` Index: ${INDEX_FILE}`
    );

    console.log(
      ` Server Hosts: ${
        [
          ...SERVER_HOSTS,
        ].join(", ") ||
        "none"
      }`
    );

    console.log(
      " Admin: /admin"
    );

    console.log(
      " Site API: /__waf/api/*"
    );

    console.log(
      ` Rate default: ${config.RATE_LIMIT_MAX}/${config.RATE_LIMIT_WINDOW}s`
    );

    console.log(
      ` Burst default: ${config.BURST_MAX}/${config.BURST_WINDOW_MS}ms`
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

    for (
      const site of db.sites
    ) {
      console.log(
        `[SITE] ${site.domains.join(
          ", "
        )} -> ${site.target_url}`
      );
    }
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
