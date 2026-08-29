'use strict';

import 'dotenv/config';

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';

import express, {
  type Request,
  type Response,
  type NextFunction,
} from 'express';

import helmet from 'helmet';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';

import { z } from 'zod';

import {
  createProxyMiddleware,
  fixRequestBody,
} from 'http-proxy-middleware';

import {
  MongoClient,
  type Db,
  type Collection,
} from 'mongodb';

import mongoose, {
  Document,
  Schema,
} from 'mongoose';

import jwt, {
  type JwtPayload,
} from 'jsonwebtoken';

import argon2 from 'argon2';

/* ============================================================
   CONFIG
============================================================ */

const ConfigSchema = z.object({
  PORT: z.coerce.number().int().positive().default(8080),

  ADMIN_USER: z.string().min(3),
  ADMIN_PASSWORD: z.string().min(12),

  MONGO_URI: z.string().min(1),

  DATA_FILE: z.string().default('sites-db.json'),

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

  MAX_BODY_SIZE: z.string().default('256kb'),

  REQUEST_TIMEOUT_MS: z.coerce.number().int().positive().default(15000),
  HEADERS_TIMEOUT_MS: z.coerce.number().int().positive().default(10000),
  KEEP_ALIVE_TIMEOUT_MS: z.coerce.number().int().positive().default(5000),
  PROXY_TIMEOUT_MS: z.coerce.number().int().positive().default(15000),

  CHALLENGE_SECRET: z.string().min(32),
  CHALLENGE_WAIT_SECONDS: z.coerce.number().int().min(1).max(30).default(5),
  CHALLENGE_TTL_SECONDS: z.coerce.number().int().positive().default(86400),
  CHALLENGE_TICKET_TTL_SECONDS: z.coerce.number().int().positive().default(60),

  JWT_SECRET: z.string().min(32),

  BREVO_API_KEY: z.string().optional(),
  SENDER_EMAIL: z.string().email().default('ttbnatlh@gmail.com'),
});

const config = ConfigSchema.parse({
  PORT: process.env.PORT,
  ADMIN_USER: process.env.ADMIN_USER,
  ADMIN_PASSWORD: process.env.ADMIN_PASSWORD,
  MONGO_URI: process.env.MONGO_URI,

  DATA_FILE: process.env.DATA_FILE || 'sites-db.json',

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

  JWT_SECRET: process.env.JWT_SECRET,

  BREVO_API_KEY: process.env.BREVO_API_KEY,
  SENDER_EMAIL:
    process.env.SENDER_EMAIL || 'ttbnatlh@gmail.com',
});

/* ============================================================
   TYPES
============================================================ */

type Action =
  | 'allow'
  | 'block'
  | 'honeypot';

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
   AUTH TYPES
============================================================ */

interface IUser extends Document {
  email: string;
  passwordHash: string;
  emailVerified: boolean;
  createdAt: Date;
  lastLoginAt: Date | null;
}

interface IOTP extends Document {
  email: string;
  otp: string;
  passwordHash: string;
  createdAt: Date;
}

interface AuthJwtPayload extends JwtPayload {
  userId: string;
  email: string;
}

interface AuthenticatedRequest extends Request {
  user?: IUser;
}

interface BrevoResponse {
  [key: string]: unknown;
}

/* ============================================================
   UTILITIES
============================================================ */

const normalizeDomain = (value: string): string =>
  value
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .split('/')[0]
    .split(':')[0]
    .trim();

const normalizeHost = normalizeDomain;

const normalizeDomains = (
  values: string[],
): string[] =>
  [
    ...new Set(
      values
        .map(normalizeDomain)
        .filter(Boolean),
    ),
  ];

const truncate = (
  value: string,
  max = 4096,
): string =>
  value.length > max
    ? value.slice(0, max)
    : value;

const safeJson = (
  value: unknown,
): string => {
  try {
    return JSON.stringify(value);
  } catch {
    return '';
  }
};

function secureCompare(
  a: string,
  b: string,
): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);

  return (
    x.length === y.length &&
    crypto.timingSafeEqual(x, y)
  );
}

function normalizeIp(
  ip: string,
): string {
  if (ip.startsWith('::ffff:')) {
    return ip.slice(7);
  }

  if (ip === '::1') {
    return '127.0.0.1';
  }

  return ip;
}

const getClientIp = (
  req: Request,
): string =>
  normalizeIp(
    req.ip || '0.0.0.0',
  );

function base64UrlEncode(
  value: Buffer | string,
): string {
  return Buffer.from(value)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function base64UrlDecode(
  value: string,
): Buffer {
  const normalized = value
    .replace(/-/g, '+')
    .replace(/_/g, '/');

  return Buffer.from(
    normalized +
      '='.repeat(
        (4 - (normalized.length % 4)) % 4,
      ),
    'base64',
  );
}

/* ============================================================
   HOSTS
============================================================ */

const PROJECT_DIR = process.cwd();

const INDEX_FILE = path.join(
  PROJECT_DIR,
  'index.html',
);

const SERVER_HOSTS = new Set<string>();

for (
  const host of [
    process.env.RENDER_EXTERNAL_HOSTNAME,
    process.env.PUBLIC_HOST,
    'production-1-54qv.onrender.com',
    'www.routix.nx.kg',
    'routix.nx.kg',
  ]
) {
  if (host) {
    SERVER_HOSTS.add(
      normalizeHost(host),
    );
  }
}

/* ============================================================
   EXPRESS
============================================================ */

const app = express();

app.disable('x-powered-by');

if (config.TRUST_PROXY) {
  app.set('trust proxy', true);
} else {
  /*
   Render and common reverse-proxy deployments
   normally provide one proxy hop.
  */
  app.set('trust proxy', 1);
}

/* ============================================================
   SECURITY
============================================================ */

app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: false,
  }),
);

app.use(
  express.json({
    limit: config.MAX_BODY_SIZE,
    strict: true,
  }),
);

app.use(
  express.urlencoded({
    extended: false,
    limit: config.MAX_BODY_SIZE,
  }),
);

app.use(cookieParser());

app.use(
  (
    _req: Request,
    res: Response,
    next: NextFunction,
  ) => {
    res.setHeader(
      'X-Content-Type-Options',
      'nosniff',
    );

    res.setHeader(
      'X-Frame-Options',
      'SAMEORIGIN',
    );

    res.setHeader(
      'Referrer-Policy',
      'strict-origin-when-cross-origin',
    );

    res.setHeader(
      'Permissions-Policy',
      'camera=(), microphone=(), geolocation=()',
    );

    next();
  },
);

/* ============================================================
   CORS
============================================================ */

const allowedOrigins = [
  'https://production-1-54qv.onrender.com',
  'https://www.routix.nx.kg',
  'https://routix.nx.kg',
];

app.use(
  cors({
    origin: (
      origin,
      callback,
    ) => {
      if (
        !origin ||
        allowedOrigins.includes(origin)
      ) {
        callback(null, true);
        return;
      }

      callback(
        new Error(
          'Blocked by CORS policy',
        ),
      );
    },

    credentials: true,

    methods: [
      'GET',
      'POST',
      'PUT',
      'PATCH',
      'DELETE',
      'OPTIONS',
    ],

    allowedHeaders: [
      'Content-Type',
      'Authorization',
      'x-waf-api-key',
      'x-routix-challenge',
    ],
  }),
);

/* ============================================================
   AUTH RATE LIMIT
============================================================ */

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,

  message: {
    success: false,
    message:
      'تم تجاوز الحد المسموح من الطلبات، يرجى المحاولة لاحقاً.',
  },
});

app.use(
  '/api/',
  authLimiter,
);

/* ============================================================
   MONGODB WAF
============================================================ */

const mongoClient =
  new MongoClient(
    config.MONGO_URI,
    {
      maxPoolSize: 20,
      serverSelectionTimeoutMS: 10000,
      connectTimeoutMS: 10000,
    },
  );

let mongoDb: Db;

let stateCollection:
  Collection<{
    _id: string;
    data: DbSchema;
    updatedAt: Date;
  }>;

let visitorsCollection:
  Collection<{
    siteId: string;
    visitorHash: string;
    firstSeenAt: Date;
    lastSeenAt: Date;
  }>;

const createSiteStats =
  (): SiteStats => ({
    totalRequests: 0,
    allowedRequests: 0,
    blockedRequests: 0,
    honeypotRequests: 0,
    attacks: 0,
  });

const emptyDb =
  (): DbSchema => ({
    sites: [],
    blacklists: {},
    risks: {},
    alerts: [],
  });

function migrateSite(
  site: any,
): Site {
  const primary =
    normalizeDomain(
      String(
        site?.client_domain || '',
      ),
    );

  const domains =
    normalizeDomains([
      primary,
      ...(Array.isArray(
        site?.domains,
      )
        ? site.domains
        : []),
    ]);

  return {
    id: String(
      site?.id ||
        crypto.randomUUID(),
    ),

    owner_id: String(
      site?.owner_id ||
        'default',
    ),

    client_domain:
      primary ||
      domains[0] ||
      '',

    domains,

    target_url: String(
      site?.target_url || '',
    ),

    api_key: String(
      site?.api_key ||
        crypto
          .randomBytes(32)
          .toString('hex'),
    ),

    settings:
      site?.settings &&
      typeof site.settings ===
        'object'
        ? site.settings
        : {
            enableChallenge: true,
          },

    stats:
      site?.stats &&
      typeof site.stats ===
        'object'
        ? {
            ...createSiteStats(),
            ...site.stats,
          }
        : createSiteStats(),
  };
}

async function connectDatabase(): Promise<void> {
  await mongoClient.connect();

  mongoDb =
    mongoClient.db('routix');

  stateCollection =
    mongoDb.collection('state');

  visitorsCollection =
    mongoDb.collection(
      'visitors',
    );

  await visitorsCollection.createIndex(
    {
      siteId: 1,
      visitorHash: 1,
    },
    {
      unique: true,
    },
  );

  await visitorsCollection.createIndex(
    {
      siteId: 1,
    },
  );

  console.log(
    '[MongoDB] WAF database connected',
  );
}

async function loadDb(): Promise<DbSchema> {
  const state =
    await stateCollection.findOne({
      _id: 'main',
    });

  if (!state?.data) {
    const initial =
      emptyDb();

    await stateCollection.updateOne(
      {
        _id: 'main',
      },
      {
        $set: {
          data: initial,
          updatedAt:
            new Date(),
        },
      },
      {
        upsert: true,
      },
    );

    return initial;
  }

  const data =
    state.data ||
    emptyDb();

  return {
    sites:
      Array.isArray(
        data.sites,
      )
        ? data.sites.map(
            migrateSite,
          )
        : [],

    blacklists:
      data.blacklists &&
      typeof data.blacklists ===
        'object'
        ? data.blacklists
        : {},

    risks:
      data.risks &&
      typeof data.risks ===
        'object'
        ? data.risks
        : {},

    alerts:
      Array.isArray(
        data.alerts,
      )
        ? data.alerts
        : [],
  };
}

let db: DbSchema =
  emptyDb();

let dbDirty = false;
let saveInProgress = false;

async function saveDb(): Promise<void> {
  if (saveInProgress) {
    return;
  }

  saveInProgress = true;

  try {
    const now =
      Date.now();

    for (
      const [
        key,
        value,
      ] of Object.entries(
        db.blacklists,
      )
    ) {
      if (
        value.expiresAt <
        now
      ) {
        delete db.blacklists[
          key
        ];
      }
    }

    for (
      const [
        key,
        value,
      ] of Object.entries(
        db.risks,
      )
    ) {
      if (
        value.expiresAt <
        now
      ) {
        delete db.risks[
          key
        ];
      }
    }

    db.alerts =
      db.alerts.slice(
        0,
        1000,
      );

    await stateCollection.updateOne(
      {
        _id: 'main',
      },
      {
        $set: {
          data: db,
          updatedAt:
            new Date(),
        },
      },
      {
        upsert: true,
      },
    );

    dbDirty = false;
  } catch (error) {
    console.error(
      '[MongoDB] Save error:',
      error,
    );
  } finally {
    saveInProgress =
      false;
  }
}

setInterval(() => {
  if (dbDirty) {
    void saveDb();
  }
}, 5000);

/* ============================================================
   VISITORS
============================================================ */

const visitorHashSecret =
  crypto
    .createHash('sha256')
    .update(
      `${config.CHALLENGE_SECRET}:visitor`,
    )
    .digest();

function hashVisitor(
  siteId: string,
  ip: string,
): string {
  return crypto
    .createHmac(
      'sha256',
      visitorHashSecret,
    )
    .update(
      `${siteId}:${ip}`,
    )
    .digest('hex');
}

async function registerVisitor(
  site: Site,
  ip: string,
): Promise<void> {
  try {
    const visitorHash =
      hashVisitor(
        site.id,
        ip,
      );

    const now =
      new Date();

    await visitorsCollection.updateOne(
      {
        siteId:
          site.id,
        visitorHash,
      },
      {
        $set: {
          lastSeenAt:
            now,
        },

        $setOnInsert: {
          siteId:
            site.id,
          visitorHash,
          firstSeenAt:
            now,
        },
      },
      {
        upsert: true,
      },
    );
  } catch (error) {
    console.error(
      '[Visitors] Error:',
      error,
    );
  }
}

async function getSiteVisitorCount(
  siteId: string,
): Promise<number> {
  try {
    return await visitorsCollection.countDocuments(
      {
        siteId,
      },
    );
  } catch (error) {
    console.error(
      '[Visitors] Count error:',
      error,
    );

    return 0;
  }
}

async function getTotalVisitorCount(): Promise<number> {
  try {
    return await visitorsCollection.countDocuments(
      {},
    );
  } catch (error) {
    console.error(
      '[Visitors] Total count error:',
      error,
    );

    return 0;
  }
}

/* ============================================================
   SITE LOOKUP
============================================================ */

function getSiteByHost(
  host: string,
): Site | null {
  const normalized =
    normalizeHost(host);

  return (
    db.sites.find(
      (site) =>
        normalizeDomains([
          site.client_domain,
          ...(site.domains ||
            []),
        ]).includes(
          normalized,
        ),
    ) || null
  );
}

const getSiteById =
  (
    id: string,
  ): Site | null =>
    db.sites.find(
      (site) =>
        site.id === id,
    ) || null;

function getSiteByApiKey(
  apiKey: string,
): Site | null {
  return (
    db.sites.find(
      (site) =>
        secureCompare(
          site.api_key,
          apiKey,
        ),
    ) || null
  );
}

/* ============================================================
   MEMORY LIMITERS
============================================================ */

const requestCounters =
  new Map<
    string,
    Counter
  >();

const burstCounters =
  new Map<
    string,
    Counter
  >();

const globalCounters =
  new Map<
    string,
    Counter
  >();

const violations =
  new Map<
    string,
    Counter
  >();

const concurrentByIp =
  new Map<
    string,
    number
  >();

const concurrentBySite =
  new Map<
    string,
    number
  >();

let globalConcurrent =
  0;

/* ============================================================
   ALERTS
============================================================ */

const alertClients =
  new Set<Response>();

function addAlert(
  data: {
    site: Site;
    ip: string;
    path: string;
    risk: number;
    action: Action;
    reasons: string[];
  },
): void {
  const alert:
    WafAlert = {
      id:
        crypto.randomUUID(),

      siteId:
        data.site.id,

      ownerId:
        data.site.owner_id,

      domain:
        data.site.client_domain,

      time:
        new Date().toISOString(),

      ip:
        data.ip,

      path:
        truncate(
          data.path,
          500,
        ),

      risk:
        data.risk,

      action:
        data.action,

      reasons:
        data.reasons.slice(
          0,
          20,
        ),
    };

  db.alerts.unshift(
    alert,
  );

  if (
    db.alerts.length >
    1000
  ) {
    db.alerts.length =
      1000;
  }

  dbDirty = true;

  const payload =
    `data: ${JSON.stringify(
      alert,
    )}\n\n`;

  for (
    const client of alertClients
  ) {
    try {
      client.write(
        payload,
      );
    } catch {
      alertClients.delete(
        client,
      );
    }
  }
}

/* ============================================================
   CLEANUP
============================================================ */

function cleanupMemory(): void {
  const now =
    Date.now();

  for (
    const map of [
      requestCounters,
      burstCounters,
      globalCounters,
      violations,
    ]
  ) {
    for (
      const [
        key,
        value,
      ] of map
    ) {
      if (
        value.expiresAt <
        now
      ) {
        map.delete(key);
      }
    }
  }
}

setInterval(
  cleanupMemory,
  10000,
);

/* ============================================================
   SETTINGS
============================================================ */

type NumberSetting =
  | 'rateLimitWindow'
  | 'rateLimitMax'
  | 'burstWindowMs'
  | 'burstMax'
  | 'globalRateWindowMs'
  | 'globalRateMax'
  | 'maxConcurrentPerIp'
  | 'maxGlobalConcurrent'
  | 'violationLimit'
  | 'violationWindowMs'
  | 'autoBlacklistSeconds'
  | 'riskBlockThreshold'
  | 'riskHoneypotThreshold'
  | 'riskTtl'
  | 'blacklistTtl';

type BooleanSetting =
  | 'enabled'
  | 'enableSqlInjection'
  | 'enableXss'
  | 'enableRce'
  | 'enablePathTraversal'
  | 'enableChallenge';

function settingNumber(
  site: Site,
  key: NumberSetting,
  fallback: number,
): number {
  const value =
    site.settings[key];

  return typeof value ===
    'number' &&
    Number.isFinite(value) &&
    value > 0
    ? value
    : fallback;
}

function settingBoolean(
  site: Site,
  key: BooleanSetting,
  fallback = true,
): boolean {
  const value =
    site.settings[key];

  return typeof value ===
    'boolean'
    ? value
    : fallback;
}

/* ============================================================
   BLACKLIST / RISK
============================================================ */

const blacklistKey = (
  siteId: string,
  ip: string,
): string =>
  `${siteId}:${ip}`;

function isBlacklisted(
  site: Site,
  ip: string,
): boolean {
  const key =
    blacklistKey(
      site.id,
      ip,
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
  reason: string,
): void {
  const ttl =
    Math.max(
      settingNumber(
        site,
        'blacklistTtl',
        config.BLACKLIST_TTL,
      ),
      settingNumber(
        site,
        'autoBlacklistSeconds',
        config.AUTO_BLACKLIST_SECONDS,
      ),
    );

  db.blacklists[
    blacklistKey(
      site.id,
      ip,
    )
  ] = {
    reason,

    createdAt:
      new Date().toISOString(),

    expiresAt:
      Date.now() +
      ttl * 1000,
  };

  dbDirty = true;
}

const riskKey = (
  siteId: string,
  ip: string,
): string =>
  `${siteId}:${ip}`;

function getRisk(
  site: Site,
  ip: string,
): number {
  const entry =
    db.risks[
      riskKey(
        site.id,
        ip,
      )
    ];

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
  points: number,
): number {
  const key =
    riskKey(
      site.id,
      ip,
    );

  const now =
    Date.now();

  let entry =
    db.risks[key];

  if (
    !entry ||
    entry.expiresAt <
      now
  ) {
    entry = {
      score: 0,

      expiresAt:
        now +
        settingNumber(
          site,
          'riskTtl',
          config.RISK_TTL,
        ) *
          1000,
    };
  }

  entry.score +=
    points;

  db.risks[key] =
    entry;

  dbDirty = true;

  return entry.score;
}

/* ============================================================
   COUNTERS
============================================================ */

function incrementCounter(
  map: Map<
    string,
    Counter
  >,
  key: string,
  windowMs: number,
): number {
  const now =
    Date.now();

  let entry =
    map.get(key);

  if (
    !entry ||
    entry.expiresAt <
      now
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
    entry,
  );

  return entry.count;
}

function registerViolation(
  site: Site,
  ip: string,
): number {
  return incrementCounter(
    violations,
    `${site.id}:${ip}`,
    settingNumber(
      site,
      'violationWindowMs',
      config.VIOLATION_WINDOW_MS,
    ),
  );
}

function checkRateLimit(
  site: Site,
  ip: string,
): {
  allowed: boolean;
  remaining: number;
} {
  const max =
    settingNumber(
      site,
      'rateLimitMax',
      config.RATE_LIMIT_MAX,
    );

  const count =
    incrementCounter(
      requestCounters,
      `${site.id}:${ip}`,
      settingNumber(
        site,
        'rateLimitWindow',
        config.RATE_LIMIT_WINDOW,
      ) * 1000,
    );

  return {
    allowed:
      count <= max,

    remaining:
      Math.max(
        0,
        max - count,
      ),
  };
}

function checkBurst(
  site: Site,
  ip: string,
): boolean {
  const count =
    incrementCounter(
      burstCounters,
      `${site.id}:${ip}`,
      settingNumber(
        site,
        'burstWindowMs',
        config.BURST_WINDOW_MS,
      ),
    );

  return (
    count <=
    settingNumber(
      site,
      'burstMax',
      config.BURST_MAX,
    )
  );
}

function checkGlobalRate(
  site: Site,
): boolean {
  const count =
    incrementCounter(
      globalCounters,
      site.id,
      settingNumber(
        site,
        'globalRateWindowMs',
        config.GLOBAL_RATE_WINDOW_MS,
      ),
    );

  return (
    count <=
    settingNumber(
      site,
      'globalRateMax',
      config.GLOBAL_RATE_MAX,
    )
  );
}

/* ============================================================
   CONCURRENCY
============================================================ */

function acquireConcurrency(
  site: Site,
  ip: string,
): boolean {
  const maxGlobal =
    settingNumber(
      site,
      'maxGlobalConcurrent',
      config.MAX_GLOBAL_CONCURRENT,
    );

  const maxIp =
    settingNumber(
      site,
      'maxConcurrentPerIp',
      config.MAX_CONCURRENT_PER_IP,
    );

  if (
    globalConcurrent >=
    maxGlobal
  ) {
    return false;
  }

  const ipKey =
    `${site.id}:${ip}`;

  const ipCount =
    concurrentByIp.get(
      ipKey,
    ) || 0;

  const siteCount =
    concurrentBySite.get(
      site.id,
    ) || 0;

  if (
    ipCount >= maxIp ||
    siteCount >= maxGlobal
  ) {
    return false;
  }

  concurrentByIp.set(
    ipKey,
    ipCount + 1,
  );

  concurrentBySite.set(
    site.id,
    siteCount + 1,
  );

  globalConcurrent++;

  return true;
}

function releaseConcurrency(
  site: Site,
  ip: string,
): void {
  const ipKey =
    `${site.id}:${ip}`;

  const ipCount =
    concurrentByIp.get(
      ipKey,
    ) || 0;

  if (
    ipCount <= 1
  ) {
    concurrentByIp.delete(
      ipKey,
    );
  } else {
    concurrentByIp.set(
      ipKey,
      ipCount - 1,
    );
  }

  const siteCount =
    concurrentBySite.get(
      site.id,
    ) || 0;

  if (
    siteCount <= 1
  ) {
    concurrentBySite.delete(
      site.id,
    );
  } else {
    concurrentBySite.set(
      site.id,
      siteCount - 1,
    );
  }

  globalConcurrent =
    Math.max(
      0,
      globalConcurrent - 1,
    );
}

/* ============================================================
   DETECTION
============================================================ */

const SQL_PATTERNS: RegExp[] = [
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

const XSS_PATTERNS: RegExp[] = [
  /<\s*script\b/i,
  /javascript\s*:/i,
  /on(?:error|load|click|mouseover)\s*=/i,
  /<\s*(?:iframe|object|embed)\b/i,
  /document\s*\.\s*(?:cookie|location)/i,
];

const PATH_PATTERNS: RegExp[] = [
  /\.\.[/\\]/,
  /%2e%2e(?:%2f|%5c)/i,
  /\.\.%2f/i,
  /\.\.%5c/i,
];

const RCE_PATTERNS: RegExp[] = [
  /\$[^)]{1,200}/,
  /`[^`]{1,200}`/,
  /(?:^|[;&|])\s*(?:curl|wget)\s+/i,
  /(?:^|[;&|])\s*(?:bash|sh|cmd|powershell)\b/i,
  /\b(?:eval|exec|system|popen)\s*\(/i,
];

function inspectString(
  site: Site,
  value: string,
  location: string,
): {
  score: number;
  reasons: string[];
} {
  const input =
    truncate(value);

  let score = 0;

  const reasons: string[] =
    [];

  const rules: Array<
    [
      boolean,
      RegExp[],
      number,
      string,
    ]
  > = [
    [
      settingBoolean(
        site,
        'enableSqlInjection',
      ),
      SQL_PATTERNS,
      35,
      'sql_injection',
    ],

    [
      settingBoolean(
        site,
        'enableXss',
      ),
      XSS_PATTERNS,
      30,
      'xss',
    ],

    [
      settingBoolean(
        site,
        'enablePathTraversal',
      ),
      PATH_PATTERNS,
      25,
      'path_traversal',
    ],

    [
      settingBoolean(
        site,
        'enableRce',
      ),
      RCE_PATTERNS,
      50,
      'rce',
    ],
  ];

  for (
    const [
      enabled,
      patterns,
      points,
      name,
    ] of rules
  ) {
    if (
      enabled &&
      patterns.some(
        (pattern) =>
          pattern.test(
            input,
          ),
      )
    ) {
      score += points;

      reasons.push(
        `${name}:${location}`,
      );
    }
  }

  return {
    score,
    reasons,
  };
}

function inspectRequest(
  site: Site,
  req: Request,
): {
  score: number;
  reasons: string[];
} {
  let score = 0;

  const reasons: string[] =
    [];

  const values: Array<
    [unknown, string]
  > = [
    [
      req.originalUrl,
      'url',
    ],

    [
      req.headers[
        'user-agent'
      ],
      'user-agent',
    ],

    [
      req.headers[
        'referer'
      ],
      'referer',
    ],

    [
      req.headers[
        'origin'
      ],
      'origin',
    ],
  ];

  for (
    const [
      value,
      location,
    ] of values
  ) {
    if (
      typeof value ===
      'string'
    ) {
      const result =
        inspectString(
          site,
          value,
          location,
        );

      score +=
        result.score;

      reasons.push(
        ...result.reasons,
      );
    }
  }

  if (
    req.body !==
    undefined
  ) {
    const body =
      safeJson(
        req.body,
      );

    if (body) {
      const result =
        inspectString(
          site,
          body,
          'body',
        );

      score +=
        result.score;

      reasons.push(
        ...result.reasons,
      );
    }
  }

  return {
    score,
    reasons: [
      ...new Set(
        reasons,
      ),
    ],
  };
}

/* ============================================================
   STATS
============================================================ */

function registerSiteRequest(
  site: Site,
): void {
  site.stats.totalRequests++;

  site.stats.lastRequestAt =
    new Date().toISOString();

  dbDirty = true;
}

function registerSiteAction(
  site: Site,
  action: Action,
  attack = false,
): void {
  if (
    action === 'allow'
  ) {
    site.stats.allowedRequests++;
  }

  if (
    action === 'block'
  ) {
    site.stats.blockedRequests++;
  }

  if (
    action === 'honeypot'
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
   CHALLENGE
============================================================ */

const challengeSecret =
  Buffer.from(
    config.CHALLENGE_SECRET,
    'utf8',
  );

const challengeEncryptionKey =
  crypto
    .createHash('sha256')
    .update(
      Buffer.concat([
        challengeSecret,
        Buffer.from(
          'routix-encryption-key',
          'utf8',
        ),
      ]),
    )
    .digest();

const challengeHmacKey =
  crypto
    .createHash('sha256')
    .update(
      Buffer.concat([
        challengeSecret,
        Buffer.from(
          'routix-hmac-key',
          'utf8',
        ),
      ]),
    )
    .digest();

const CHALLENGE_COOKIE =
  '__routix_challenge';

const CHALLENGE_WAIT_MS =
  config.CHALLENGE_WAIT_SECONDS *
  1000;

const hmacSign = (
  value: string,
): string =>
  base64UrlEncode(
    crypto
      .createHmac(
        'sha256',
        challengeHmacKey,
      )
      .update(value)
      .digest(),
  );

/*
  The challenge ticket is intentionally NOT bound
  to the client IP. This avoids false failures when
  a proxy/load-balancer changes the apparent IP.
*/
function createChallengeTicket(
  host: string,
): string {
  const payload = {
    v: 1,

    host:
      normalizeHost(host),

    issuedAt:
      Date.now(),

    nonce:
      base64UrlEncode(
        crypto.randomBytes(
          24,
        ),
      ),
  };

  const body =
    base64UrlEncode(
      JSON.stringify(
        payload,
      ),
    );

  return `${body}.${hmacSign(
    body,
  )}`;
}

function verifyChallengeTicket(
  ticket: string,
  host: string,
): {
  valid: boolean;
  reason?: string;
} {
  try {
    const parts =
      ticket.split('.');

    if (
      parts.length !== 2
    ) {
      return {
        valid: false,
        reason:
          'invalid_ticket',
      };
    }

    const [
      body,
      signature,
    ] = parts;

    if (
      !body ||
      !signature
    ) {
      return {
        valid: false,
        reason:
          'invalid_ticket',
      };
    }

    if (
      !secureCompare(
        signature,
        hmacSign(body),
      )
    ) {
      return {
        valid: false,
        reason:
          'invalid_signature',
      };
    }

    const payload =
      JSON.parse(
        base64UrlDecode(
          body,
        ).toString('utf8'),
      ) as {
        v?: unknown;
        host?: unknown;
        issuedAt?: unknown;
        nonce?: unknown;
      };

    if (
      payload.v !== 1 ||
      typeof payload.host !==
        'string' ||
      typeof payload.issuedAt !==
        'number' ||
      typeof payload.nonce !==
        'string'
    ) {
      return {
        valid: false,
        reason:
          'invalid_payload',
      };
    }

    if (
      payload.host !==
      normalizeHost(host)
    ) {
      return {
        valid: false,
        reason:
          'host_mismatch',
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
          'challenge_too_fast',
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
          'ticket_expired',
      };
    }

    return {
      valid: true,
    };
  } catch {
    return {
      valid: false,
      reason:
        'invalid_ticket',
    };
  }
}

function encryptChallengeCookie(
  data: {
    host: string;
    issuedAt: number;
    expiresAt: number;
    nonce: string;
  },
): string {
  const iv =
    crypto.randomBytes(
      12,
    );

  const cipher =
    crypto.createCipheriv(
      'aes-256-gcm',
      challengeEncryptionKey,
      iv,
    );

  const encrypted =
    Buffer.concat([
      cipher.update(
        JSON.stringify(data),
        'utf8',
      ),

      cipher.final(),
    ]);

  const body = [
    base64UrlEncode(iv),
    base64UrlEncode(
      cipher.getAuthTag(),
    ),
    base64UrlEncode(
      encrypted,
    ),
  ].join('.');

  return `${body}.${hmacSign(
    body,
  )}`;
}

function decryptChallengeCookie(
  value: string,
): {
  valid: boolean;
  host?: string;
  issuedAt?: number;
  expiresAt?: number;
} {
  try {
    const parts =
      value.split('.');

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

    if (
      !ivEncoded ||
      !tagEncoded ||
      !encryptedEncoded ||
      !signature
    ) {
      return {
        valid: false,
      };
    }

    const body = [
      ivEncoded,
      tagEncoded,
      encryptedEncoded,
    ].join('.');

    if (
      !secureCompare(
        signature,
        hmacSign(body),
      )
    ) {
      return {
        valid: false,
      };
    }

    const decipher =
      crypto.createDecipheriv(
        'aes-256-gcm',
        challengeEncryptionKey,
        base64UrlDecode(
          ivEncoded,
        ),
      );

    decipher.setAuthTag(
      base64UrlDecode(
        tagEncoded,
      ),
    );

    const decrypted =
      Buffer.concat([
        decipher.update(
          base64UrlDecode(
            encryptedEncoded,
          ),
        ),

        decipher.final(),
      ]).toString(
        'utf8',
      );

    const payload =
      JSON.parse(
        decrypted,
      ) as {
        host?: unknown;
        issuedAt?: unknown;
        expiresAt?: unknown;
      };

    if (
      typeof payload.host !==
        'string' ||
      typeof payload.issuedAt !==
        'number' ||
      typeof payload.expiresAt !==
        'number' ||
      payload.expiresAt <
        Date.now()
    ) {
      return {
        valid: false,
      };
    }

    return {
      valid: true,
      host:
        payload.host,
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
  name: string,
): string | null {
  const header =
    req.headers.cookie;

  if (!header) {
    return null;
  }

  for (
    const cookie of header.split(
      ';',
    )
  ) {
    const index =
      cookie.indexOf('=');

    if (index < 0) {
      continue;
    }

    const key =
      cookie
        .slice(0, index)
        .trim();

    if (key !== name) {
      continue;
    }

    const value =
      cookie
        .slice(index + 1)
        .trim();

    try {
      return decodeURIComponent(
        value,
      );
    } catch {
      return value;
    }
  }

  return null;
}

function setChallengeCookie(
  req: Request,
  res: Response,
  value: string,
): void {
  const secure =
    req.secure ||
    req.headers[
      'x-forwarded-proto'
    ] === 'https';

  const parts = [
    `${CHALLENGE_COOKIE}=${encodeURIComponent(
      value,
    )}`,

    'Path=/',
    'HttpOnly',
    'SameSite=Lax',

    `Max-Age=${config.CHALLENGE_TTL_SECONDS}`,
  ];

  if (secure) {
    parts.push('Secure');
  }

  res.setHeader(
    'Set-Cookie',
    parts.join('; '),
  );
}

function clearChallengeCookie(
  res: Response,
): void {
  res.setHeader(
    'Set-Cookie',
    `${CHALLENGE_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`,
  );
}

function isChallengeCookieValid(
  req: Request,
): boolean {
  const cookie =
    getCookie(
      req,
      CHALLENGE_COOKIE,
    );

  if (!cookie) {
    return false;
  }

  const result =
    decryptChallengeCookie(
      cookie,
    );

  return (
    result.valid &&
    result.host ===
      normalizeHost(
        req.headers.host ||
          '',
      )
  );
}

function sendChallengePage(
  req: Request,
  res: Response,
): void {
  const host =
    normalizeHost(
      req.headers.host ||
        '',
    );

  const ticket =
    createChallengeTicket(
      host,
    );

  const wait =
    config.CHALLENGE_WAIT_SECONDS;

  res.status(403);

  res.setHeader(
    'Cache-Control',
    'no-store, no-cache, must-revalidate, proxy-revalidate',
  );

  res.setHeader(
    'Pragma',
    'no-cache',
  );

  res.setHeader(
    'Expires',
    '0',
  );

  res.type('html');

  /*
    The browser page automatically waits and then
    sends the signed ticket to the verification endpoint.
  */
  res.send(`
<!doctype html>
<html lang="ar">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Checking your browser...</title>
<style>
body{
  margin:0;
  min-height:100vh;
  display:flex;
  align-items:center;
  justify-content:center;
  font-family:Arial,sans-serif;
  background:#f5f7fa;
  color:#222;
}
.box{
  width:min(92%,480px);
  padding:32px;
  background:white;
  border-radius:16px;
  box-shadow:0 10px 35px rgba(0,0,0,.08);
  text-align:center;
}
.loader{
  width:38px;
  height:38px;
  margin:0 auto 20px;
  border:4px solid #ddd;
  border-top-color:#222;
  border-radius:50%;
  animation:spin 1s linear infinite;
}
@keyframes spin{
  to{transform:rotate(360deg)}
}
</style>
</head>
<body>
<div class="box">
  <div class="loader"></div>
  <h2>Checking your browser...</h2>
  <p>Please wait ${wait} seconds.</p>
  <p>Protected by Routix</p>
</div>

<script>
(() => {
  const ticket = ${JSON.stringify(
    ticket,
  )};

  const waitMs = ${wait * 1000};

  setTimeout(async () => {
    try {
      const response = await fetch(
        '/__waf/challenge/verify',
        {
          method: 'POST',
          credentials: 'same-origin',
          headers: {
            'Content-Type': 'application/json',
            'x-routix-challenge': ticket
          },
          body: JSON.stringify({
            ticket
          })
        }
      );

      if (response.ok) {
        window.location.reload();
        return;
      }

      document.body.innerHTML =
        '<div class="box"><h2>تعذر التحقق</h2><p>يرجى تحديث الصفحة والمحاولة مرة أخرى.</p></div>';
    } catch {
      document.body.innerHTML =
        '<div class="box"><h2>تعذر الاتصال</h2><p>يرجى تحديث الصفحة والمحاولة مرة أخرى.</p></div>';
    }
  }, waitMs);
})();
</script>
</body>
</html>
  `);
}

/* ============================================================
   AUTH DATABASE
============================================================ */

const userSchema =
  new Schema<IUser>({
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      index: true,
    },

    passwordHash: {
      type: String,
      required: true,
    },

    emailVerified: {
      type: Boolean,
      default: true,
    },

    createdAt: {
      type: Date,
      default: Date.now,
    },

    lastLoginAt: {
      type: Date,
      default: null,
    },
  });

const UserModel =
  mongoose.model<IUser>(
    'User',
    userSchema,
  );

const otpSchema =
  new Schema<IOTP>({
    email: {
      type: String,
      required: true,
      lowercase: true,
      trim: true,
      index: true,
    },

    otp: {
      type: String,
      required: true,
    },

    passwordHash: {
      type: String,
      required: true,
    },

    createdAt: {
      type: Date,
      default: Date.now,

      /*
        MongoDB TTL:
        OTP is automatically deleted after 5 minutes.
      */
      expires: 300,
    },
  });

const OTPModel =
  mongoose.model<IOTP>(
    'OTPVerification',
    otpSchema,
  );

/* ============================================================
   AUTH HELPERS
============================================================ */

function normalizeEmail(
  email: unknown,
): string {
  return String(
    email || '',
  )
    .trim()
    .toLowerCase();
}

function isValidEmail(
  email: string,
): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(
    email,
  );
}

function isValidPassword(
  password: unknown,
): password is string {
  if (
    typeof password !==
    'string'
  ) {
    return false;
  }

  return (
    password.length >= 8 &&
    password.length <= 128
  );
}

function normalizeOtp(
  value: unknown,
): string {
  return String(
    value ?? '',
  )
    .trim()
    .replace(/\s+/g, '');
}

/*
  Supports the existing "otp" field and common
  frontend names without changing the endpoint.
*/
function getOtpFromRequest(
  req: Request,
): string {
  const body =
    req.body || {};

  return normalizeOtp(
    body.otp ??
      body.code ??
      body.verificationCode ??
      body.verification_code,
  );
}

/* ============================================================
   SESSION
============================================================ */

const SESSION_COOKIE =
  'routix_session';

const SESSION_COOKIE_OPTIONS = {
  httpOnly: true,
  secure: true,
  sameSite:
    'none' as const,
  path: '/',
  maxAge:
    7 *
    24 *
    60 *
    60 *
    1000,
};

function createSession(
  res: Response,
  user: IUser,
): void {
  const token =
    jwt.sign(
      {
        userId:
          user._id.toString(),

        email:
          user.email,
      },

      config.JWT_SECRET,

      {
        expiresIn: '7d',
      },
    );

  res.cookie(
    SESSION_COOKIE,
    token,
    SESSION_COOKIE_OPTIONS,
  );
}

/* ============================================================
   AUTH ROUTES
============================================================ */

app.post(
  '/api/check-email',
  async (
    req: Request,
    res: Response,
  ) => {
    try {
      const email =
        normalizeEmail(
          req.body?.email,
        );

      if (
        !isValidEmail(email)
      ) {
        return res
          .status(400)
          .json({
            success: false,
            message:
              'البريد الإلكتروني غير صالح أو مطلوب',
          });
      }

      const user =
        await UserModel.findOne({
          email,
        }).select('_id');

      return res.json({
        success: true,
        registered:
          !!user,
      });
    } catch (error) {
      console.error(
        'Check Email Error:',
        error,
      );

      return res
        .status(500)
        .json({
          success: false,
          message:
            'خطأ داخلي في الخادم',
        });
    }
  },
);

app.post(
  '/api/register',
  async (
    req: Request,
    res: Response,
  ) => {
    try {
      const email =
        normalizeEmail(
          req.body?.email,
        );

      const password =
        String(
          req.body?.password ||
            '',
        );

      if (
        !isValidEmail(email)
      ) {
        return res
          .status(400)
          .json({
            success: false,
            message:
              'البريد الإلكتروني غير صالح',
          });
      }

      if (
        !isValidPassword(
          password,
        )
      ) {
        return res
          .status(400)
          .json({
            success: false,
            message:
              'كلمة المرور يجب أن تكون بين 8 و128 حرفاً',
          });
      }

      const existingUser =
        await UserModel.findOne({
          email,
        });

      if (existingUser) {
        return res
          .status(409)
          .json({
            success: false,
            registered: true,
            message:
              'هذا البريد مسجل مسبقاً، استخدم تسجيل الدخول',
          });
      }

      if (
        !config.BREVO_API_KEY
      ) {
        console.error(
          'BREVO_API_KEY is missing.',
        );

        return res
          .status(500)
          .json({
            success: false,
            message:
              'خدمة البريد غير مهيأة على السيرفر',
          });
      }

      const passwordHash =
        await argon2.hash(
          password,
          {
            type:
              argon2.argon2id,
          },
        );

      const otpCode =
        crypto
          .randomInt(
            100000,
            1000000,
          )
          .toString();

      /*
        IMPORTANT:
        Send the email first.
        Only save the OTP when Brevo accepts it.
        This prevents an invalid/old OTP from remaining
        after a failed email request.
      */

      const response =
        await fetch(
          'https://api.brevo.com/v3/smtp/email',
          {
            method: 'POST',

            headers: {
              accept:
                'application/json',

              'api-key':
                config.BREVO_API_KEY,

              'content-type':
                'application/json',
            },

            body: JSON.stringify({
              sender: {
                name:
                  'Routix Security',

                email:
                  config.SENDER_EMAIL,
              },

              to: [
                {
                  email,
                },
              ],

              subject:
                'رمز إنشاء حساب Routix',

              htmlContent: `
<!doctype html>
<html lang="ar">
<head>
<meta charset="utf-8">
</head>
<body dir="rtl">
<h2>إنشاء حساب Routix</h2>

<p>مرحباً بك في Routix.</p>

<p>رمز التحقق الخاص بك هو:</p>

<h1 style="letter-spacing:8px">
${otpCode}
</h1>

<p>
هذا الرمز صالح لمدة 5 دقائق فقط.
</p>

<p>
لا تشارك الرمز مع أي شخص.
</p>
</body>
</html>
              `,
            }),
          },
        );

      let data:
        BrevoResponse = {};

      try {
        data =
          (await response.json()) as
            BrevoResponse;
      } catch {
        data = {};
      }

      if (
        !response.ok
      ) {
        console.error(
          'Brevo error:',
          data,
        );

        return res
          .status(400)
          .json({
            success: false,
            message:
              'فشل في إرسال رمز التحقق',
          });
      }

      /*
        Delete any previous OTP and create the new one
        only after Brevo accepted the message.
      */
      await OTPModel.deleteMany({
        email,
      });

      await OTPModel.create({
        email,
        otp:
          otpCode,
        passwordHash,
        createdAt:
          new Date(),
      });

      return res.json({
        success: true,
        registered: false,
        message:
          'تم إرسال رمز التحقق إلى بريدك',
      });
    } catch (error) {
      console.error(
        'Register Error:',
        error,
      );

      return res
        .status(500)
        .json({
          success: false,
          message:
            'خطأ داخلي في الخادم',
        });
    }
  },
);

/* ============================================================
   OTP VERIFICATION
============================================================ */

app.post(
  '/api/verify-otp',
  async (
    req: Request,
    res: Response,
  ) => {
    try {
      const email =
        normalizeEmail(
          req.body?.email,
        );

      const otp =
        getOtpFromRequest(
          req,
        );

      if (
        !isValidEmail(email) ||
        !/^\d{6}$/.test(
          otp,
        )
      ) {
        return res
          .status(400)
          .json({
            success: false,
            message:
              'البريد الإلكتروني ورمز التحقق مطلوبان',
          });
      }

      const existingUser =
        await UserModel.findOne({
          email,
        });

      if (existingUser) {
        await OTPModel.deleteMany({
          email,
        });

        return res
          .status(409)
          .json({
            success: false,
            registered: true,
            message:
              'هذا البريد مسجل مسبقاً، استخدم تسجيل الدخول',
          });
      }

      const record =
        await OTPModel.findOne({
          email,
        }).sort({
          createdAt: -1,
        });

      if (!record) {
        return res
          .status(400)
          .json({
            success: false,
            message:
              'انتهت صلاحية رمز التحقق أو لم يتم طلب رمز',
          });
      }

      /*
        Constant-time comparison.
      */
      if (
        !secureCompare(
          record.otp,
          otp,
        )
      ) {
        return res
          .status(400)
          .json({
            success: false,
            message:
              'رمز التحقق غير صحيح',
          });
      }

      /*
        Delete OTP before creating the account.
        This prevents the same code from being reused.
      */
      await OTPModel.deleteOne({
        _id:
          record._id,
      });

      const user =
        await UserModel.create({
          email:
            record.email,

          passwordHash:
            record.passwordHash,

          emailVerified:
            true,

          createdAt:
            new Date(),

          lastLoginAt:
            new Date(),
        });

      createSession(
        res,
        user,
      );

      return res
        .status(201)
        .json({
          success: true,
          registered: true,

          message:
            'تم إنشاء الحساب وتسجيل الدخول بنجاح',

          user: {
            id:
              user._id.toString(),

            email:
              user.email,
          },
        });
    } catch (
      error: unknown
    ) {
      console.error(
        'Verify OTP Error:',
        error,
      );

      if (
        typeof error ===
          'object' &&
        error !== null &&
        'code' in error &&
        (
          error as {
            code?: unknown;
          }
        ).code === 11000
      ) {
        return res
          .status(409)
          .json({
            success: false,
            registered: true,
            message:
              'هذا البريد مسجل مسبقاً، استخدم تسجيل الدخول',
          });
      }

      return res
        .status(500)
        .json({
          success: false,
          message:
            'خطأ داخلي في الخادم',
        });
    }
  },
);

/* ============================================================
   LOGIN
============================================================ */

app.post(
  '/api/login',
  async (
    req: Request,
    res: Response,
  ) => {
    try {
      const email =
        normalizeEmail(
          req.body?.email,
        );

      const password =
        String(
          req.body?.password ||
            '',
        );

      if (
        !isValidEmail(email)
      ) {
        return res
          .status(400)
          .json({
            success: false,
            message:
              'البريد الإلكتروني غير صالح',
          });
      }

      if (!password) {
        return res
          .status(400)
          .json({
            success: false,
            message:
              'كلمة المرور مطلوبة',
          });
      }

      const user =
        await UserModel.findOne({
          email,
        });

      if (!user) {
        return res
          .status(401)
          .json({
            success: false,
            registered: false,
            message:
              'البريد الإلكتروني أو كلمة المرور غير صحيحة',
          });
      }

      let passwordCorrect =
        false;

      try {
        passwordCorrect =
          await argon2.verify(
            user.passwordHash,
            password,
          );
      } catch {
        passwordCorrect =
          false;
      }

      if (
        !passwordCorrect
      ) {
        return res
          .status(401)
          .json({
            success: false,
            registered: true,
            message:
              'البريد الإلكتروني أو كلمة المرور غير صحيحة',
          });
      }

      user.lastLoginAt =
        new Date();

      await user.save();

      createSession(
        res,
        user,
      );

      return res.json({
        success: true,
        registered: true,
        message:
          'تم تسجيل الدخول بنجاح',

        user: {
          id:
            user._id.toString(),

          email:
            user.email,
        },
      });
    } catch (error) {
      console.error(
        'Login Error:',
        error,
      );

      return res
        .status(500)
        .json({
          success: false,
          message:
            'خطأ داخلي في الخادم',
        });
    }
  },
);

/* ============================================================
   SESSION VERIFICATION
============================================================ */

const verifySession = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction,
): Promise<
  Response | void
> => {
  const token =
    req.cookies[
      SESSION_COOKIE
    ] as
      | string
      | undefined;

  if (!token) {
    return res
      .status(401)
      .json({
        success: false,
        loggedIn: false,
        message:
          'مطلوب تسجيل الدخول',
      });
  }

  try {
    const decoded =
      jwt.verify(
        token,
        config.JWT_SECRET,
      );

    if (
      typeof decoded ===
        'string' ||
      !decoded.userId
    ) {
      res.clearCookie(
        SESSION_COOKIE,
        {
          httpOnly: true,
          sameSite:
            'none',
          secure: true,
          path: '/',
        },
      );

      return res
        .status(401)
        .json({
          success: false,
          loggedIn: false,
          message:
            'جلسة غير صالحة',
        });
    }

    const payload =
      decoded as
        AuthJwtPayload;

    const user =
      await UserModel.findById(
        payload.userId,
      ).select(
        '_id email emailVerified passwordHash createdAt lastLoginAt',
      );

    if (!user) {
      res.clearCookie(
        SESSION_COOKIE,
        {
          httpOnly: true,
          sameSite:
            'none',
          secure: true,
          path: '/',
        },
      );

      return res
        .status(401)
        .json({
          success: false,
          loggedIn: false,
          message:
            'الحساب غير موجود',
        });
    }

    req.user =
      user;

    return next();
  } catch (error) {
    console.error(
      'Session Verification Error:',
      error,
    );

    res.clearCookie(
      SESSION_COOKIE,
      {
        httpOnly: true,
        sameSite:
          'none',
        secure: true,
        path: '/',
      },
    );

    return res
      .status(401)
      .json({
        success: false,
        loggedIn: false,
        message:
          'انتهت صلاحية الجلسة، يرجى تسجيل الدخول مرة أخرى',
      });
  }
};

/* ============================================================
   PROFILE
============================================================ */

app.get(
  '/api/profile',
  verifySession,
  (
    req: AuthenticatedRequest,
    res: Response,
  ) => {
    if (!req.user) {
      return res
        .status(401)
        .json({
          success: false,
          loggedIn: false,
          message:
            'مطلوب تسجيل الدخول',
        });
    }

    return res.json({
      success: true,
      loggedIn: true,
      message:
        'الجلسة فعالة',

      user: {
        id:
          req.user._id.toString(),

        email:
          req.user.email,

        emailVerified:
          req.user.emailVerified,
      },
    });
  },
);

/* ============================================================
   LOGOUT
============================================================ */

app.post(
  '/api/logout',
  (
    _req: Request,
    res: Response,
  ) => {
    res.clearCookie(
      SESSION_COOKIE,
      {
        httpOnly: true,
        sameSite:
          'none',
        secure: true,
        path: '/',
      },
    );

    return res.json({
      success: true,
      loggedIn: false,
      message:
        'تم تسجيل الخروج بنجاح',
    });
  },
);

/* ============================================================
   AUTH HEALTH
============================================================ */

app.get(
  '/api/health',
  (
    _req: Request,
    res: Response,
  ) => {
    return res.json({
      success: true,
      status:
        'online',
      service:
        'Routix Authentication',
    });
  },
);

/* ============================================================
   ADMIN AUTH
============================================================ */

const adminFailures =
  new Map<
    string,
    Counter
  >();

const ADMIN_MAX_FAILURES =
  3;

const ADMIN_FAILURE_WINDOW_MS =
  15 * 60 * 1000;

function adminAuth(
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  const ip =
    getClientIp(req);

  const failure =
    adminFailures.get(
      ip,
    );

  if (
    failure &&
    failure.expiresAt >
      Date.now() &&
    failure.count >=
      ADMIN_MAX_FAILURES
  ) {
    res.setHeader(
      'Retry-After',
      String(
        Math.ceil(
          (
            failure.expiresAt -
            Date.now()
          ) / 1000,
        ),
      ),
    );

    res
      .status(429)
      .send(
        'Too many failed authentication attempts. Try again later.',
      );

    return;
  }

  const authorization =
    req.headers.authorization;

  if (!authorization) {
    res.setHeader(
      'WWW-Authenticate',
      'Basic realm="WAF Admin"',
    );

    res
      .status(401)
      .send(
        'Authentication required',
      );

    return;
  }

  const [
    scheme,
    encoded,
  ] =
    authorization.split(
      ' ',
    );

  if (
    scheme !== 'Basic' ||
    !encoded
  ) {
    res
      .status(401)
      .send(
        'Unauthorized',
      );

    return;
  }

  let decoded: string;

  try {
    decoded =
      Buffer.from(
        encoded,
        'base64',
      ).toString(
        'utf8',
      );
  } catch {
    res
      .status(401)
      .send(
        'Unauthorized',
      );

    return;
  }

  if (
    decoded.length >
    2048
  ) {
    res
      .status(401)
      .send(
        'Unauthorized',
      );

    return;
  }

  const separator =
    decoded.indexOf(
      ':',
    );

  if (
    separator < 0
  ) {
    res
      .status(401)
      .send(
        'Unauthorized',
      );

    return;
  }

  const user =
    decoded.slice(
      0,
      separator,
    );

  const password =
    decoded.slice(
      separator + 1,
    );

  const valid =
    secureCompare(
      user,
      config.ADMIN_USER,
    ) &&
    secureCompare(
      password,
      config.ADMIN_PASSWORD,
    );

  if (!valid) {
    const now =
      Date.now();

    const current =
      adminFailures.get(
        ip,
      );

    if (
      !current ||
      current.expiresAt <=
        now
    ) {
      adminFailures.set(
        ip,
        {
          count: 1,
          expiresAt:
            now +
            ADMIN_FAILURE_WINDOW_MS,
        },
      );
    } else {
      current.count++;
    }

    res.setHeader(
      'WWW-Authenticate',
      'Basic realm="WAF Admin"',
    );

    res
      .status(401)
      .send(
        'Unauthorized',
      );

    return;
  }

  adminFailures.delete(
    ip,
  );

  next();
}

/* ============================================================
   SITE API AUTH
============================================================ */

function siteApiAuth(
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  const key =
    req.header(
      'x-waf-api-key',
    );

  if (!key) {
    res
      .status(401)
      .json({
        error:
          'missing_api_key',
      });

    return;
  }

  if (
    key.length > 512
  ) {
    res
      .status(401)
      .json({
        error:
          'invalid_api_key',
      });

    return;
  }

  const site =
    getSiteByApiKey(
      key,
    );

  if (!site) {
    res
      .status(401)
      .json({
        error:
          'invalid_api_key',
      });

    return;
  }

  (
    req as WafRequest
  ).wafSite =
    site;

  next();
}

/* ============================================================
   CHALLENGE API
============================================================ */

function challengeVerification(
  req: Request,
  res: Response,
): void {
  const supplied =
    String(
      req.headers[
        'x-routix-challenge'
      ] ||
        req.body?.ticket ||
        '',
    ).trim();

  if (!supplied) {
    res
      .status(400)
      .json({
        error:
          'missing_challenge_ticket',
      });

    return;
  }

  if (
    supplied.length >
    8192
  ) {
    res
      .status(400)
      .json({
        error:
          'invalid_challenge_ticket',
      });

    return;
  }

  const result =
    verifyChallengeTicket(
      supplied,
      req.headers.host ||
        '',
    );

  if (!result.valid) {
    clearChallengeCookie(
      res,
    );

    res
      .status(403)
      .json({
        error:
          'challenge_failed',

        reason:
          result.reason ||
          'verification_failed',
      });

    return;
  }

  const host =
    normalizeHost(
      req.headers.host ||
        '',
    );

  const issuedAt =
    Date.now();

  const expiresAt =
    issuedAt +
    config.CHALLENGE_TTL_SECONDS *
      1000;

  const cookie =
    encryptChallengeCookie({
      host,
      issuedAt,
      expiresAt,

      nonce:
        crypto
          .randomBytes(
            32,
          )
          .toString('hex'),
    });

  setChallengeCookie(
    req,
    res,
    cookie,
  );

  res.setHeader(
    'Cache-Control',
    'no-store',
  );

  res.json({
    success: true,
    verified: true,
    expiresAt,
  });
}

app.post(
  '/__waf/challenge/verify',
  challengeVerification,
);

app.post(
  '/__waf/challenge/reset',
  (
    _req,
    res,
  ) => {
    clearChallengeCookie(
      res,
    );

    res.json({
      success: true,
    });
  },
);

/* ============================================================
   ADMIN SITES
============================================================ */

app.get(
  '/__waf/admin/sites',
  adminAuth,
  async (
    _req,
    res,
  ) => {
    const sites =
      await Promise.all(
        db.sites.map(
          async (
            site,
          ) => ({
            id:
              site.id,

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

            visitors:
              await getSiteVisitorCount(
                site.id,
              ),
          }),
        ),
      );

    res.json({
      sites,
    });
  },
);

const siteCreateSchema =
  z.object({
    owner_id:
      z.string()
        .min(1)
        .max(200),

    client_domain:
      z.string()
        .min(1)
        .max(253)
        .optional(),

    domains:
      z.array(
        z.string()
          .min(1)
          .max(253),
      )
        .max(100)
        .optional(),

    target_url:
      z.string()
        .url()
        .max(2048),

    api_key:
      z.string()
        .min(20)
        .max(512)
        .optional(),

    settings:
      z.record(
        z.string(),
        z.unknown(),
      )
        .default({}),
  });

app.post(
  '/__waf/admin/sites',
  adminAuth,
  async (
    req,
    res,
  ) => {
    const parsed =
      siteCreateSchema.safeParse(
        req.body,
      );

    if (
      !parsed.success
    ) {
      res
        .status(400)
        .json({
          error:
            'invalid_site_data',

          details:
            parsed.error.flatten(),
        });

      return;
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
      !incomingDomains.length
    ) {
      res
        .status(400)
        .json({
          error:
            'at_least_one_domain_required',
        });

      return;
    }

    let targetUrl: URL;

    try {
      targetUrl =
        new URL(
          parsed.data
            .target_url,
        );
    } catch {
      res
        .status(400)
        .json({
          error:
            'invalid_target_url',
        });

      return;
    }

    if (
      ![
        'http:',
        'https:',
      ].includes(
        targetUrl.protocol,
      )
    ) {
      res
        .status(400)
        .json({
          error:
            'target_url_must_use_http_or_https',
        });

      return;
    }

    const conflict =
      incomingDomains.find(
        (domain) =>
          db.sites.some(
            (site) =>
              normalizeDomains([
                site.client_domain,
                ...(site.domains ||
                  []),
              ]).includes(
                domain,
              ),
          ),
      );

    if (conflict) {
      res
        .status(409)
        .json({
          error:
            'domain_already_exists',

          domain:
            conflict,
        });

      return;
    }

    const settings =
      parsed.data
        .settings as SiteSettings;

    if (
      typeof settings.enableChallenge !==
      'boolean'
    ) {
      settings.enableChallenge =
        true;
    }

    const site: Site =
      {
        id:
          crypto.randomUUID(),

        owner_id:
          parsed.data.owner_id,

        client_domain:
          incomingDomains[0],

        domains:
          incomingDomains,

        target_url:
          targetUrl.toString(),

        api_key:
          parsed.data
            .api_key ||
          crypto
            .randomBytes(32)
            .toString('hex'),

        settings,

        stats:
          createSiteStats(),
      };

    db.sites.push(
      site,
    );

    dbDirty = true;

    await saveDb();

    res
      .status(201)
      .json({
        site,
        visitors: 0,
      });
  },
);

/* ============================================================
   ADMIN DOMAIN MANAGEMENT
============================================================ */

app.post(
  '/__waf/admin/sites/:id/domains',
  adminAuth,
  async (
    req,
    res,
  ) => {
    const site =
      getSiteById(
        req.params.id,
      );

    if (!site) {
      res
        .status(404)
        .json({
          error:
            'site_not_found',
        });

      return;
    }

    const parsed =
      z.object({
        domains:
          z.array(
            z.string()
              .min(1)
              .max(253),
          )
            .min(1)
            .max(100),
      }).safeParse(
        req.body,
      );

    if (
      !parsed.success
    ) {
      res
        .status(400)
        .json({
          error:
            'invalid_domains',

          details:
            parsed.error.flatten(),
        });

      return;
    }

    const newDomains =
      normalizeDomains(
        parsed.data
          .domains,
      );

    const existing =
      normalizeDomains([
        site.client_domain,
        ...(site.domains ||
          []),
      ]);

    const conflicts =
      newDomains.filter(
        (domain) =>
          db.sites.some(
            (other) =>
              other.id !==
                site.id &&
              normalizeDomains([
                other.client_domain,
                ...(other.domains ||
                  []),
              ]).includes(
                domain,
              ),
          ),
      );

    if (
      conflicts.length
    ) {
      res
        .status(409)
        .json({
          error:
            'domain_already_exists',

          domains:
            conflicts,
        });

      return;
    }

    site.domains =
      normalizeDomains([
        ...existing,
        ...newDomains,
      ]);

    if (
      !site.client_domain
    ) {
      site.client_domain =
        site.domains[0] ||
        '';
    }

    dbDirty = true;

    await saveDb();

    res.json({
      success: true,
      site,
    });
  },
);

app.delete(
  '/__waf/admin/sites/:id/domains',
  adminAuth,
  async (
    req,
    res,
  ) => {
    const site =
      getSiteById(
        req.params.id,
      );

    if (!site) {
      res
        .status(404)
        .json({
          error:
            'site_not_found',
        });

      return;
    }

    const domain =
      normalizeDomain(
        String(
          req.body?.domain ||
            req.query.domain ||
            '',
        ),
      );

    if (!domain) {
      res
        .status(400)
        .json({
          error:
            'domain_required',
        });

      return;
    }

    const current =
      normalizeDomains([
        site.client_domain,
        ...(site.domains ||
          []),
      ]);

    if (
      !current.includes(
        domain,
      )
    ) {
      res
        .status(404)
        .json({
          error:
            'domain_not_found',
        });

      return;
    }

    if (
      current.length <= 1
    ) {
      res
        .status(400)
        .json({
          error:
            'cannot_remove_last_domain',
        });

      return;
    }

    const remaining =
      current.filter(
        (value) =>
          value !== domain,
      );

    site.domains =
      remaining;

    if (
      site.client_domain ===
      domain
    ) {
      site.client_domain =
        remaining[0] ||
        '';
    }

    dbDirty = true;

    await saveDb();

    res.json({
      success: true,
      site,
    });
  },
);

/* ============================================================
   ADMIN DELETE SITE
============================================================ */

app.delete(
  '/__waf/admin/sites/:id',
  adminAuth,
  async (
    req,
    res,
  ) => {
    const index =
      db.sites.findIndex(
        (site) =>
          site.id ===
          req.params.id,
      );

    if (index < 0) {
      res
        .status(404)
        .json({
          error:
            'site_not_found',
        });

      return;
    }

    const removed =
      db.sites.splice(
        index,
        1,
      )[0];

    if (!removed) {
      res
        .status(404)
        .json({
          error:
            'site_not_found',
        });

      return;
    }

    for (
      const key of Object.keys(
        db.blacklists,
      )
    ) {
      if (
        key.startsWith(
          `${removed.id}:`,
        )
      ) {
        delete db.blacklists[
          key
        ];
      }
    }

    for (
      const key of Object.keys(
        db.risks,
      )
    ) {
      if (
        key.startsWith(
          `${removed.id}:`,
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
          removed.id,
      );

    await visitorsCollection.deleteMany(
      {
        siteId:
          removed.id,
      },
    );

    dbDirty = true;

    await saveDb();

    res.json({
      deleted: true,
    });
  },
);

/* ============================================================
   SITE API
============================================================ */

app.get(
  '/__waf/api/stats',
  siteApiAuth,
  async (
    req,
    res,
  ) => {
    const site =
      (
        req as WafRequest
      ).wafSite!;

    res.json({
      site: {
        id:
          site.id,

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

      visitors:
        await getSiteVisitorCount(
          site.id,
        ),
    });
  },
);

app.get(
  '/__waf/api/alerts',
  siteApiAuth,
  (
    req,
    res,
  ) => {
    const site =
      (
        req as WafRequest
      ).wafSite!;

    const raw =
      Number(
        req.query.limit,
      );

    const limit =
      Math.min(
        Math.max(
          Number.isFinite(
            raw,
          )
            ? raw
            : 100,
          1,
        ),
        500,
      );

    res.json({
      site_id:
        site.id,

      client_domain:
        site.client_domain,

      domains:
        site.domains,

      alerts:
        db.alerts
          .filter(
            (alert) =>
              alert.siteId ===
              site.id,
          )
          .slice(
            0,
            limit,
          ),
    });
  },
);

app.get(
  '/__waf/api/status',
  siteApiAuth,
  (
    req,
    res,
  ) => {
    const site =
      (
        req as WafRequest
      ).wafSite!;

    const ip =
      normalizeIp(
        String(
          req.query.ip ||
            getClientIp(
              req,
            ),
        ),
      );

    res.json({
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
          ip,
        ),

      risk:
        getRisk(
          site,
          ip,
        ),

      concurrent:
        concurrentByIp.get(
          `${site.id}:${ip}`,
        ) || 0,
    });
  },
);

app.get(
  '/__waf/api/visitors',
  siteApiAuth,
  async (
    req,
    res,
  ) => {
    const site =
      (
        req as WafRequest
      ).wafSite!;

    res.json({
      site_id:
        site.id,

      domain:
        site.client_domain,

      visitors:
        await getSiteVisitorCount(
          site.id,
        ),
    });
  },
);

/* ============================================================
   ADMIN ALERTS / STATS / BLACKLISTS
============================================================ */

app.get(
  '/__waf/admin/alerts',
  adminAuth,
  (
    req,
    res,
  ) => {
    const siteId =
      typeof req.query
        .site_id ===
      'string'
        ? req.query
            .site_id
        : null;

    const alerts =
      siteId
        ? db.alerts.filter(
            (alert) =>
              alert.siteId ===
              siteId,
          )
        : db.alerts;

    res.json({
      alerts:
        alerts.slice(
          0,
          500,
        ),
    });
  },
);

app.get(
  '/__waf/admin/stats',
  adminAuth,
  async (
    _req,
    res,
  ) => {
    const now =
      Date.now();

    const blacklisted =
      Object.values(
        db.blacklists,
      ).filter(
        (entry) =>
          entry.expiresAt >
          now,
      ).length;

    const totals =
      db.sites.reduce(
        (
          result,
          site,
        ) => {
          result.requests +=
            site.stats
              .totalRequests;

          result.allowed +=
            site.stats
              .allowedRequests;

          result.blocked +=
            site.stats
              .blockedRequests;

          result.honeypot +=
            site.stats
              .honeypotRequests;

          result.attacks +=
            site.stats
              .attacks;

          return result;
        },
        {
          requests: 0,
          allowed: 0,
          blocked: 0,
          honeypot: 0,
          attacks: 0,
        },
      );

    const visitors =
      await getTotalVisitorCount();

    const visitorsBySite =
      await Promise.all(
        db.sites.map(
          async (
            site,
          ) => ({
            site_id:
              site.id,

            domain:
              site.client_domain,

            visitors:
              await getSiteVisitorCount(
                site.id,
              ),
          }),
        ),
      );

    res.json({
      sites:
        db.sites.length,

      visitors,

      visitorsBySite,

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
          process.uptime(),
        ),
    });
  },
);

app.get(
  '/__waf/admin/blacklists',
  adminAuth,
  (
    _req,
    res,
  ) => {
    const now =
      Date.now();

    const blacklists =
      Object.entries(
        db.blacklists,
      )
        .filter(
          ([, entry]) =>
            entry.expiresAt >
            now,
        )
        .map(
          ([
            key,
            entry,
          ]) => {
            const separator =
              key.indexOf(
                ':',
              );

            if (
              separator < 0
            ) {
              return null;
            }

            const siteId =
              key.slice(
                0,
                separator,
              );

            const ip =
              key.slice(
                separator + 1,
              );

            const site =
              getSiteById(
                siteId,
              );

            return {
              site_id:
                siteId,

              ip,

              domain:
                site?.client_domain ||
                'unknown',

              domains:
                site?.domains ||
                [],

              reason:
                entry.reason,

              createdAt:
                entry.createdAt,

              expiresAt:
                entry.expiresAt,

              remainingSeconds:
                Math.max(
                  0,
                  Math.ceil(
                    (
                      entry.expiresAt -
                      now
                    ) / 1000,
                  ),
                ),

              temporary:
                true,
            };
          },
        )
        .filter(
          (
            value,
          ): value is NonNullable<
            typeof value
          > =>
            value !== null,
        );

    res.json({
      blacklists,
      count:
        blacklists.length,
    });
  },
);

app.get(
  '/__waf/admin/sites/:id',
  adminAuth,
  async (
    req,
    res,
  ) => {
    const site =
      getSiteById(
        req.params.id,
      );

    if (!site) {
      res
        .status(404)
        .json({
          error:
            'site_not_found',
        });

      return;
    }

    res.json({
      site,

      visitors:
        await getSiteVisitorCount(
          site.id,
        ),

      alerts:
        db.alerts
          .filter(
            (alert) =>
              alert.siteId ===
              site.id,
          )
          .slice(
            0,
            200,
          ),
    });
  },
);

/* ============================================================
   ADMIN SSE
============================================================ */

app.get(
  '/__waf/admin/events',
  adminAuth,
  (
    req,
    res,
  ) => {
    res.setHeader(
      'Content-Type',
      'text/event-stream',
    );

    res.setHeader(
      'Cache-Control',
      'no-cache, no-transform',
    );

    res.setHeader(
      'Connection',
      'keep-alive',
    );

    res.setHeader(
      'X-Accel-Buffering',
      'no',
    );

    res.flushHeaders();

    alertClients.add(
      res,
    );

    res.write(
      `data: ${JSON.stringify({
        type: 'connected',
      })}\n\n`,
    );

    const heartbeat =
      setInterval(
        () => {
          try {
            res.write(
              ': heartbeat\n\n',
            );
          } catch {
            clearInterval(
              heartbeat,
            );

            alertClients.delete(
              res,
            );
          }
        },
        15000,
      );

    req.on(
      'close',
      () => {
        clearInterval(
          heartbeat,
        );

        alertClients.delete(
          res,
        );
      },
    );
  },
);

/* ============================================================
   ADMIN DASHBOARD
============================================================ */

function escapeHtml(
  value: unknown,
): string {
  return String(value)
    .replace(
      /&/g,
      '&amp;',
    )
    .replace(
      /</g,
      '&lt;',
    )
    .replace(
      />/g,
      '&gt;',
    )
    .replace(
      /"/g,
      '&quot;',
    )
    .replace(
      /'/g,
      '&#039;',
    );
}

app.get(
  '/admin',
  adminAuth,
  (
    _req,
    res,
  ) => {
    res.type('html').send(`
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
  font-family:Arial,sans-serif;
  background:#f4f6f8;
  color:#222;
}

header{
  padding:24px;
  background:#111;
  color:#fff;
}

main{
  max-width:1400px;
  margin:auto;
  padding:24px;
}

.grid{
  display:grid;
  grid-template-columns:repeat(auto-fit,minmax(180px,1fr));
  gap:16px;
  margin-bottom:30px;
}

.card{
  background:#fff;
  border-radius:14px;
  padding:20px;
  box-shadow:0 3px 15px rgba(0,0,0,.06);
}

.number{
  font-size:30px;
  font-weight:bold;
  margin-top:8px;
}

.status{
  margin-top:12px;
}

form{
  display:grid;
  gap:12px;
  max-width:700px;
  margin-bottom:30px;
}

input,button{
  padding:12px;
  border-radius:8px;
  border:1px solid #ccc;
  font:inherit;
}

button{
  cursor:pointer;
  background:#111;
  color:#fff;
}

.table-wrap{
  overflow:auto;
  background:#fff;
  border-radius:14px;
  margin-bottom:30px;
}

table{
  width:100%;
  border-collapse:collapse;
  min-width:900px;
}

th,td{
  padding:12px;
  border-bottom:1px solid #eee;
  text-align:right;
  vertical-align:top;
}

th{
  background:#fafafa;
}

code{
  word-break:break-all;
}
</style>
</head>

<body>

<header>
  <h1>🛡️ Routix Multi-Site WAF Admin</h1>
  <p>
    إدارة المواقع المحمية ومراقبة الطلبات والزوار والتنبيهات.
  </p>
  <div class="status">
    🟢 Routix WAF Online
  </div>
</header>

<main>

<section class="grid">

<div class="card">
  <div>المواقع</div>
  <div class="number" id="sitesCount">0</div>
</div>

<div class="card">
  <div>الزوار الفريدون</div>
  <div class="number" id="visitorsCount">0</div>
</div>

<div class="card">
  <div>الطلبات</div>
  <div class="number" id="requestsCount">0</div>
</div>

<div class="card">
  <div>الهجمات</div>
  <div class="number" id="attacksCount">0</div>
</div>

<div class="card">
  <div>IPs المحظورة</div>
  <div class="number" id="blacklistedCount">0</div>
</div>

<div class="card">
  <div>الاتصالات الحالية</div>
  <div class="number" id="concurrentCount">0</div>
</div>

</section>

<section class="card">

<h2>➕ إضافة موقع للحماية</h2>

<p>
أضف الدومين والوجهة التي تريد حمايتها.
</p>

<form id="siteForm">

<input
  name="owner_id"
  placeholder="Owner ID"
  required
>

<input
  name="client_domain"
  placeholder="example.com"
>

<input
  name="domains"
  placeholder="example.com,www.example.com"
>

<input
  name="target_url"
  placeholder="https://origin.example.com"
  required
>

<button type="submit">
  إضافة الموقع
</button>

</form>

</section>

<section class="card">

<h2>🌐 المواقع المحمية</h2>

<button id="refreshSites">
  🔄 تحديث
</button>

<div class="table-wrap">

<table>

<thead>
<tr>
<th>ID</th>
<th>Owner</th>
<th>الدومينات</th>
<th>Target</th>
<th>الزوار</th>
<th>الطلبات</th>
<th>الهجمات</th>
<th>API Key</th>
</tr>
</thead>

<tbody id="sitesBody">
<tr>
<td colspan="8">
جاري التحميل...
</td>
</tr>
</tbody>

</table>

</div>

</section>

<section class="card">

<h2>🚫 IPs المحظورة</h2>

<div class="table-wrap">

<table>

<thead>
<tr>
<th>IP</th>
<th>الدومين</th>
<th>السبب</th>
<th>ينتهي</th>
<th>المتبقي</th>
</tr>
</thead>

<tbody id="blacklistBody">
<tr>
<td colspan="5">
جاري التحميل...
</td>
</tr>
</tbody>

</table>

</div>

</section>

<section class="card">

<h2>🚨 التنبيهات</h2>

<div class="table-wrap">

<table>

<thead>
<tr>
<th>الوقت</th>
<th>IP</th>
<th>الدومين</th>
<th>المسار</th>
<th>Risk</th>
<th>Action</th>
<th>الأسباب</th>
</tr>
</thead>

<tbody id="alertsBody">
<tr>
<td colspan="7">
جاري التحميل...
</td>
</tr>
</tbody>

</table>

</div>

</section>

</main>

<script>
'use strict';

const esc = (value) =>
  String(value ?? '')
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;')
    .replace(/'/g,'&#039;');

async function api(url, options = {}) {
  const response = await fetch(url, {
    credentials: 'same-origin',
    ...options
  });

  if (!response.ok) {
    throw new Error(
      await response.text()
    );
  }

  return response.json();
}

async function loadStats() {
  const data =
    await api('/__waf/admin/stats');

  document.getElementById(
    'sitesCount'
  ).textContent =
    data.sites ?? 0;

  document.getElementById(
    'visitorsCount'
  ).textContent =
    data.visitors ?? 0;

  document.getElementById(
    'requestsCount'
  ).textContent =
    data.totals?.requests ?? 0;

  document.getElementById(
    'attacksCount'
  ).textContent =
    data.totals?.attacks ?? 0;

  document.getElementById(
    'blacklistedCount'
  ).textContent =
    data.blacklisted ?? 0;

  document.getElementById(
    'concurrentCount'
  ).textContent =
    data.globalConcurrent ?? 0;
}

async function loadSites() {
  const data =
    await api('/__waf/admin/sites');

  const body =
    document.getElementById(
      'sitesBody'
    );

  body.innerHTML =
    data.sites.map(
      site => \`
<tr>
<td><code>\${esc(site.id)}</code></td>

<td>
\${esc(site.owner_id)}
</td>

<td>
\${esc(
  (site.domains || []).join(', ')
)}
</td>

<td>
\${esc(site.target_url)}
</td>

<td>
\${esc(site.visitors)}
</td>

<td>
\${esc(site.stats?.totalRequests)}
</td>

<td>
\${esc(site.stats?.attacks)}
</td>

<td>
<code>\${esc(site.api_key)}</code>
</td>
</tr>
\`
    ).join('') ||
    '<tr><td colspan="8">لا توجد مواقع</td></tr>';
}

async function loadBlacklists() {
  const data =
    await api(
      '/__waf/admin/blacklists'
    );

  const body =
    document.getElementById(
      'blacklistBody'
    );

  body.innerHTML =
    data.blacklists.map(
      item => \`
<tr>

<td>
\${esc(item.ip)}
</td>

<td>
\${esc(item.domain)}
</td>

<td>
\${esc(item.reason)}
</td>

<td>
\${esc(
  new Date(
    item.expiresAt
  ).toLocaleString()
)}
</td>

<td>
\${esc(item.remainingSeconds)}s
</td>

</tr>
\`
    ).join('') ||
    '<tr><td colspan="5">لا توجد عناوين محظورة</td></tr>';
}

async function loadAlerts() {
  const data =
    await api(
      '/__waf/admin/alerts'
    );

  const body =
    document.getElementById(
      'alertsBody'
    );

  body.innerHTML =
    data.alerts.map(
      alert => \`
<tr>

<td>
\${esc(
  new Date(
    alert.time
  ).toLocaleString()
)}
</td>

<td>
\${esc(alert.ip)}
</td>

<td>
\${esc(alert.domain)}
</td>

<td>
\${esc(alert.path)}
</td>

<td>
\${esc(alert.risk)}
</td>

<td>
\${esc(alert.action)}
</td>

<td>
\${esc(
  (alert.reasons || []).join(', ')
)}
</td>

</tr>
\`
    ).join('') ||
    '<tr><td colspan="7">لا توجد تنبيهات</td></tr>';
}

async function refreshAll() {
  try {
    await Promise.all([
      loadStats(),
      loadSites(),
      loadBlacklists(),
      loadAlerts()
    ]);
  } catch (error) {
    console.error(error);
  }
}

document
  .getElementById('refreshSites')
  .addEventListener(
    'click',
    refreshAll
  );

document
  .getElementById('siteForm')
  .addEventListener(
    'submit',
    async event => {
      event.preventDefault();

      const form =
        event.currentTarget;

      const formData =
        new FormData(form);

      const domains =
        String(
          formData.get(
            'domains'
          ) || ''
        )
          .split(',')
          .map(
            value =>
              value.trim()
          )
          .filter(Boolean);

      const payload = {
        owner_id:
          String(
            formData.get(
              'owner_id'
            ) || ''
          ),

        client_domain:
          String(
            formData.get(
              'client_domain'
            ) || ''
          ) || undefined,

        domains,

        target_url:
          String(
            formData.get(
              'target_url'
            ) || ''
          ),

        settings: {
          enableChallenge: true
        }
      };

      try {
        await api(
          '/__waf/admin/sites',
          {
            method: 'POST',

            headers: {
              'Content-Type':
                'application/json'
            },

            body:
              JSON.stringify(
                payload
              )
          }
        );

        form.reset();

        await refreshAll();

        alert(
          'تمت إضافة الموقع بنجاح'
        );
      } catch (error) {
        console.error(error);

        alert(
          'تعذر إضافة الموقع'
        );
      }
    }
  );

const eventSource =
  new EventSource(
    '/__waf/admin/events'
  );

eventSource.onmessage =
  () => {
    refreshAll();
  };

refreshAll();

setInterval(
  refreshAll,
  10000
);
</script>

</body>
</html>
    `);
  },
);

/* ============================================================
   WAF SITE API COMPATIBILITY
============================================================ */

app.get(
  '/__waf/status/:ip',
  siteApiAuth,
  (
    req,
    res,
  ) => {
    const site =
      (
        req as WafRequest
      ).wafSite!;

    const ip =
      normalizeIp(
        req.params.ip,
      );

    res.json({
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
          ip,
        ),

      risk:
        getRisk(
          site,
          ip,
        ),

      concurrent:
        concurrentByIp.get(
          `${site.id}:${ip}`,
        ) || 0,
    });
  },
);

/* ============================================================
   HONEYPOT
============================================================ */

app.all(
  '/__waf_honeypot',
  (
    req,
    res,
  ) => {
    const site =
      getSiteByHost(
        req.headers.host ||
          '',
      );

    if (!site) {
      res
        .status(404)
        .json({
          error:
            'not_found',
        });

      return;
    }

    const ip =
      getClientIp(
        req,
      );

    const score =
      addRisk(
        site,
        ip,
        settingNumber(
          site,
          'riskBlockThreshold',
          config.RISK_BLOCK_THRESHOLD,
        ),
      );

    blacklist(
      site,
      ip,
      'honeypot_triggered',
    );

    registerSiteAction(
      site,
      'block',
      true,
    );

    addAlert({
      site,
      ip,

      path:
        req.originalUrl,

      risk:
        score,

      action:
        'block',

      reasons: [
        'honeypot_triggered',
      ],
    });

    res
      .status(404)
      .json({
        error:
          'not_found',
      });
  },
);

/* ============================================================
   HEALTH
============================================================ */

app.get(
  '/__waf/health',
  async (
    _req,
    res,
  ) => {
    res.json({
      status:
        'ok',

      service:
        'multi-site-cloud-waf',

      protection:
        'strong-l7',

      challenge:
        'global-anti-bot',

      challengeWaitSeconds:
        config.CHALLENGE_WAIT_SECONDS,

      sites:
        db.sites.length,

      visitors:
        await getTotalVisitorCount(),

      globalConcurrent,

      activeClients:
        concurrentByIp.size,

      serverHosts: [
        ...SERVER_HOSTS,
      ],
    });
  },
);

/* ============================================================
   SITE RESOLUTION
============================================================ */

function resolveSite(
  req: Request,
  res: Response,
): Site | null {
  const host =
    normalizeHost(
      req.headers.host ||
        '',
    );

  if (
    SERVER_HOSTS.has(
      host,
    )
  ) {
    return null;
  }

  const site =
    getSiteByHost(
      host,
    );

  if (!site) {
    res
      .status(404)
      .json({
        error:
          'site_not_configured',

        host,
      });

    return null;
  }

  return site;
}

/* ============================================================
   GLOBAL CHALLENGE
============================================================ */

app.use(
  (
    req,
    res,
    next,
  ) => {
    if (
      req.path.startsWith(
        '/api/',
      )
    ) {
      next();
      return;
    }

    if (
      req.path ===
        '/__waf/challenge/verify' ||
      req.path ===
        '/__waf/challenge/reset'
    ) {
      next();
      return;
    }

    if (
      req.path.startsWith(
        '/__waf/',
      ) ||
      req.path ===
        '/admin'
    ) {
      next();
      return;
    }

    const host =
      normalizeHost(
        req.headers.host ||
          '',
      );

    const site =
      getSiteByHost(
        host,
      );

    const isRoutixHost =
      SERVER_HOSTS.has(
        host,
      );

    const enabled =
      isRoutixHost
        ? true
        : site
          ? settingBoolean(
              site,
              'enableChallenge',
              true,
            )
          : true;

    if (!enabled) {
      next();
      return;
    }

    if (
      isChallengeCookieValid(
        req,
      )
    ) {
      next();
      return;
    }

    if (
      req.method !==
        'GET' &&
      req.method !==
        'HEAD'
    ) {
      res.setHeader(
        'Cache-Control',
        'no-store',
      );

      res
        .status(403)
        .json({
          error:
            'browser_challenge_required',

          message:
            'Open the website in a browser first and complete the security check.',
        });

      return;
    }

    sendChallengePage(
      req,
      res,
    );
  },
);

/* ============================================================
   ROUTIX WEBSITE
============================================================ */

app.use(
  (
    req,
    res,
    next,
  ) => {
    const host =
      normalizeHost(
        req.headers.host ||
          '',
      );

    if (
      !SERVER_HOSTS.has(
        host,
      )
    ) {
      next();
      return;
    }

    if (
      req.path.startsWith(
        '/__waf/',
      ) ||
      req.path ===
        '/admin' ||
      req.path.startsWith(
        '/api/',
      )
    ) {
      next();
      return;
    }

    if (
      req.method !==
        'GET' &&
      req.method !==
        'HEAD'
    ) {
      next();
      return;
    }

    if (
      req.path === '/'
    ) {
      if (
        !fs.existsSync(
          INDEX_FILE,
        )
      ) {
        res
          .status(500)
          .json({
            error:
              'index_html_not_found',

            expected:
              INDEX_FILE,
          });

        return;
      }

      res.sendFile(
        INDEX_FILE,
      );

      return;
    }

    express.static(
      PROJECT_DIR,
      {
        index: false,
        fallthrough: true,
        redirect: false,
      },
    )(
      req,
      res,
      next,
    );
  },
);

/* ============================================================
   SPA FALLBACK
============================================================ */

app.use(
  (
    req,
    res,
    next,
  ) => {
    const host =
      normalizeHost(
        req.headers.host ||
          '',
      );

    if (
      !SERVER_HOSTS.has(
        host,
      )
    ) {
      next();
      return;
    }

    if (
      req.path.startsWith(
        '/__waf/',
      ) ||
      req.path ===
        '/admin' ||
      req.path.startsWith(
        '/api/',
      )
    ) {
      next();
      return;
    }

    if (
      req.method !==
        'GET' &&
      req.method !==
        'HEAD'
    ) {
      next();
      return;
    }

    if (
      !fs.existsSync(
        INDEX_FILE,
      )
    ) {
      res
        .status(500)
        .json({
          error:
            'index_html_not_found',

          expected:
            INDEX_FILE,
        });

      return;
    }

    res.sendFile(
      INDEX_FILE,
    );
  },
);

/* ============================================================
   WAF EVALUATION
============================================================ */

function violationDecision(
  site: Site,
  ip: string,
  requestId: string,
  score: number,
  reason: string,
  action: Action,
): Decision {
  registerSiteAction(
    site,
    action,
    true,
  );

  addAlert({
    site,
    ip,
    path: '',
    risk:
      score,
    action,
    reasons: [
      reason,
    ],
  });

  return {
    action,
    riskScore:
      score,
    reasons: [
      reason,
    ],
    requestId,
    site,
  };
}

async function evaluate(
  req: Request,
  site: Site,
): Promise<Decision> {
  const requestId =
    crypto.randomUUID();

  const ip =
    getClientIp(req);

  registerSiteRequest(
    site,
  );

  void registerVisitor(
    site,
    ip,
  );

  if (
    !settingBoolean(
      site,
      'enabled',
      true,
    )
  ) {
    registerSiteAction(
      site,
      'allow',
    );

    return {
      action:
        'allow',

      riskScore:
        getRisk(
          site,
          ip,
        ),

      reasons: [],

      requestId,

      site,
    };
  }

  if (
    isBlacklisted(
      site,
      ip,
    )
  ) {
    const risk =
      settingNumber(
        site,
        'riskBlockThreshold',
        config.RISK_BLOCK_THRESHOLD,
      );

    registerSiteAction(
      site,
      'block',
      true,
    );

    addAlert({
      site,
      ip,

      path:
        req.originalUrl,

      risk,

      action:
        'block',

      reasons: [
        'site_blacklist',
      ],
    });

    return {
      action:
        'block',

      riskScore:
        risk,

      reasons: [
        'site_blacklist',
      ],

      requestId,

      site,
    };
  }

  const fail = (
    reason: string,
    points: number,
    honeypot = true,
  ): Decision | null => {
    const score =
      addRisk(
        site,
        ip,
        points,
      );

    const count =
      registerViolation(
        site,
        ip,
      );

    const limit =
      settingNumber(
        site,
        'violationLimit',
        config.VIOLATION_LIMIT,
      );

    if (
      count >= limit
    ) {
      blacklist(
        site,
        ip,
        reason,
      );

      const blockScore =
        Math.max(
          score,

          settingNumber(
            site,
            'riskBlockThreshold',
            config.RISK_BLOCK_THRESHOLD,
          ),
        );

      registerSiteAction(
        site,
        'block',
        true,
      );

      addAlert({
        site,
        ip,

        path:
          req.originalUrl,

        risk:
          blockScore,

        action:
          'block',

        reasons: [
          reason,
        ],
      });

      return {
        action:
          'block',

        riskScore:
          blockScore,

        reasons: [
          reason,
        ],

        requestId,

        site,
      };
    }

    if (!honeypot) {
      return null;
    }

    registerSiteAction(
      site,
      'honeypot',
      true,
    );

    addAlert({
      site,
      ip,

      path:
        req.originalUrl,

      risk:
        score,

      action:
        'honeypot',

      reasons: [
        reason,
      ],
    });

    return {
      action:
        'honeypot',

      riskScore:
        score,

      reasons: [
        reason,
      ],

      requestId,

      site,
    };
  };

  if (
    !checkGlobalRate(
      site,
    )
  ) {
    const score =
      addRisk(
        site,
        ip,
        20,
      );

    const threshold =
      settingNumber(
        site,
        'riskHoneypotThreshold',
        config.RISK_HONEYPOT_THRESHOLD,
      );

    const action: Action =
      score >= threshold
        ? 'honeypot'
        : 'block';

    if (
      action ===
      'block'
    ) {
      blacklist(
        site,
        ip,
        'global_rate_limit',
      );
    }

    registerSiteAction(
      site,
      action,
      true,
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
        'global_rate_limit',
      ],
    });

    return {
      action,

      riskScore:
        score,

      reasons: [
        'global_rate_limit',
      ],

      requestId,

      site,
    };
  }

  if (
    !checkBurst(
      site,
      ip,
    )
  ) {
    const decision =
      fail(
        'burst_rate_limit',
        20,
      );

    if (decision) {
      return decision;
    }
  }

  const rate =
    checkRateLimit(
      site,
      ip,
    );

  if (!rate.allowed) {
    const decision =
      fail(
        'rate_limit_violation',
        30,
      );

    if (decision) {
      return decision;
    }
  }

  if (
    !acquireConcurrency(
      site,
      ip,
    )
  ) {
    const decision =
      fail(
        'too_many_concurrent_requests',
        25,
      );

    if (decision) {
      return decision;
    }
  }

  const inspection =
    inspectRequest(
      site,
      req,
    );

  const risk =
    inspection.score > 0
      ? addRisk(
          site,
          ip,
          inspection.score,
        )
      : getRisk(
          site,
          ip,
        );

  const blockThreshold =
    settingNumber(
      site,
      'riskBlockThreshold',
      config.RISK_BLOCK_THRESHOLD,
    );

  const honeypotThreshold =
    settingNumber(
      site,
      'riskHoneypotThreshold',
      config.RISK_HONEYPOT_THRESHOLD,
    );

  if (
    risk >=
    blockThreshold
  ) {
    blacklist(
      site,
      ip,
      inspection.reasons.join(
        ',',
      ) ||
        'risk_threshold',
    );

    registerSiteAction(
      site,
      'block',
      true,
    );

    const reasons =
      inspection
        .reasons.length
        ? inspection.reasons
        : [
            'risk_threshold',
          ];

    addAlert({
      site,
      ip,

      path:
        req.originalUrl,

      risk,

      action:
        'block',

      reasons,
    });

    releaseConcurrency(
      site,
      ip,
    );

    return {
      action:
        'block',

      riskScore:
        risk,

      reasons,

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
      'honeypot',
      true,
    );

    addAlert({
      site,
      ip,

      path:
        req.originalUrl,

      risk,

      action:
        'honeypot',

      reasons:
        inspection.reasons,
    });

    releaseConcurrency(
      site,
      ip,
    );

    return {
      action:
        'honeypot',

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
    'allow',
    inspection.score >
      0,
  );

  return {
    action:
      'allow',

    riskScore:
      risk,

    reasons:
      inspection.reasons,

    requestId,

    site,
  };
}

/* ============================================================
   WAF MIDDLEWARE
============================================================ */

app.use(
  async (
    req,
    res,
    next,
  ) => {
    const host =
      normalizeHost(
        req.headers.host ||
          '',
      );

    if (
      SERVER_HOSTS.has(
        host,
      ) ||
      req.path.startsWith(
        '/__waf/',
      ) ||
      req.path ===
        '/admin' ||
      req.path.startsWith(
        '/api/',
      )
    ) {
      next();
      return;
    }

    const site =
      resolveSite(
        req,
        res,
      );

    if (!site) {
      return;
    }

    try {
      const decision =
        await evaluate(
          req,
          site,
        );

      res.setHeader(
        'x-waf-site-id',
        site.id,
      );

      res.setHeader(
        'x-waf-request-id',
        decision.requestId,
      );

      res.setHeader(
        'x-waf-risk-score',
        String(
          decision.riskScore,
        ),
      );

      res.setHeader(
        'x-waf-protected',
        'true',
      );

      res.setHeader(
        'x-waf-client-domain',
        site.client_domain,
      );

      if (
        decision.action ===
        'block'
      ) {
        res
          .status(403)
          .json({
            error:
              'request_blocked',

            requestId:
              decision.requestId,

            siteId:
              site.id,

            reasons:
              decision.reasons,
          });

        return;
      }

      if (
        decision.action ===
        'honeypot'
      ) {
        res
          .status(404)
          .json({
            error:
              'not_found',

            requestId:
              decision.requestId,
          });

        return;
      }

      const wafReq =
        req as WafRequest;

      wafReq.wafSite =
        site;

      wafReq.wafRequestId =
        decision.requestId;

      wafReq.wafAcquired =
        true;

      next();
    } catch (error) {
      console.error(
        'WAF evaluation error:',
        error,
      );

      res
        .status(503)
        .json({
          error:
            'waf_unavailable',
        });
    }
  },
);

/* ============================================================
   CONCURRENCY RELEASE
============================================================ */

app.use(
  (
    req,
    _res,
    next,
  ) => {
    const wafReq =
      req as WafRequest;

    const site =
      wafReq.wafSite;

    if (!site) {
      next();
      return;
    }

    /*
      The release middleware is installed before proxy.
      The actual finish/close listeners are registered here.
    */
    let released =
      false;

    const release =
      () => {
        if (
          released ||
          !wafReq.wafAcquired
        ) {
          return;
        }

        released =
          true;

        releaseConcurrency(
          site,
          getClientIp(
            req,
          ),
        );

        wafReq.wafAcquired =
          false;
      };

    _res.once(
      'finish',
      release,
    );

    _res.once(
      'close',
      release,
    );

    next();
  },
);

/* ============================================================
   REVERSE PROXY
============================================================ */

const proxy =
  createProxyMiddleware({
    changeOrigin: true,

    xfwd: true,

    ws: true,

    proxyTimeout:
      config.PROXY_TIMEOUT_MS,

    timeout:
      config.PROXY_TIMEOUT_MS,

    router: (
      req,
    ) =>
      (
        req as WafRequest
      ).wafSite
        ?.target_url,

    on: {
      proxyReq: (
        proxyReq,
        req,
      ) => {
        const wafReq =
          req as WafRequest;

        const site =
          wafReq.wafSite;

        proxyReq.setHeader(
          'x-waf-protected',
          'true',
        );

        proxyReq.setHeader(
          'x-waf-site-id',
          site?.id || '',
        );

        proxyReq.setHeader(
          'x-waf-client-domain',
          site?.client_domain ||
            '',
        );

        proxyReq.setHeader(
          'x-waf-owner-id',
          site?.owner_id ||
            '',
        );

        proxyReq.setHeader(
          'x-waf-request-id',
          wafReq.wafRequestId ||
            crypto.randomUUID(),
        );

        proxyReq.setHeader(
          'x-forwarded-for',
          getClientIp(req),
        );

        proxyReq.setHeader(
          'x-forwarded-host',
          req.headers.host ||
            '',
        );

        proxyReq.setHeader(
          'x-forwarded-proto',
          req.protocol ||
            'http',
        );

        fixRequestBody(
          proxyReq,
          req,
        );
      },

      error: (
        error,
        req,
        res,
      ) => {
        const site =
          (
            req as WafRequest
          ).wafSite;

        console.error(
          'Proxy error:',
          error,
        );

        if (site) {
          addAlert({
            site,

            ip:
              getClientIp(
                req,
              ),

            path:
              req.originalUrl,

            risk: 0,

            action:
              'block',

            reasons: [
              'proxy_error',
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
                'protected_site_unavailable',
            });
        }
      },
    },
  });

app.use(
  '/',
  proxy,
);

/* ============================================================
   GLOBAL ERROR HANDLER
============================================================ */

app.use(
  (
    error: unknown,
    _req: Request,
    res: Response,
    _next: NextFunction,
  ) => {
    console.error(
      'Unhandled WAF error:',
      error,
    );

    if (
      !res.headersSent
    ) {
      res
        .status(500)
        .json({
          error:
            'internal_error',
        });

      return;
    }

    res.end();
  },
);

/* ============================================================
   SERVER
============================================================ */

const server =
  http.createServer(
    app,
  );

server.requestTimeout =
  config.REQUEST_TIMEOUT_MS;

server.headersTimeout =
  Math.min(
    config.HEADERS_TIMEOUT_MS,
    config.REQUEST_TIMEOUT_MS,
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
  'connection',
  (socket) => {
    const ip =
      normalizeIp(
        socket.remoteAddress ||
          '0.0.0.0',
      );

    const current =
      socketCounts.get(
        ip,
      ) || 0;

    if (
      current >=
      MAX_SOCKETS_PER_IP
    ) {
      socket.destroy();
      return;
    }

    socketCounts.set(
      ip,
      current + 1,
    );

    socket.setTimeout(
      config.REQUEST_TIMEOUT_MS,
    );

    socket.on(
      'close',
      () => {
        const count =
          socketCounts.get(
            ip,
          ) || 0;

        if (
          count <= 1
        ) {
          socketCounts.delete(
            ip,
          );
        } else {
          socketCounts.set(
            ip,
            count - 1,
          );
        }
      },
    );
  },
);

/* ============================================================
   START
============================================================ */

async function start(): Promise<void> {
  try {
    await connectDatabase();

    db =
      await loadDb();

    await mongoose.connect(
      config.MONGO_URI,
      {
        serverSelectionTimeoutMS:
          10000,
      },
    );

    console.log(
      '[MongoDB] Authentication database connected',
    );

    /*
      Make sure the OTP TTL index is created.
      This is especially useful after deploying to a fresh DB.
    */
    await OTPModel.createIndexes();

    console.log(
      '==========================================',
    );

    console.log(
      ' Routix Multi-Site Cloud WAF',
    );

    console.log(
      ' Dynamic Reverse Proxy Enabled',
    );

    console.log(
      ' Live Admin Dashboard Enabled',
    );

    console.log(
      ' Multi-Domain Protection Enabled',
    );

    console.log(
      ' L7 Protection Enabled',
    );

    console.log(
      ' Global Anti-Bot Challenge Enabled',
    );

    console.log(
      ` Challenge Wait: ${config.CHALLENGE_WAIT_SECONDS}s`,
    );

    console.log(
      ` Server: http://0.0.0.0:${config.PORT}`,
    );

    console.log(
      ` Sites: ${db.sites.length}`,
    );

    console.log(
      ' Database: MongoDB / routix',
    );

    console.log(
      ` Index: ${INDEX_FILE}`,
    );

    console.log(
      ` Server Hosts: ${
        [...SERVER_HOSTS].join(
          ', ',
        ) || 'none'
      }`,
    );

    console.log(
      ' Admin: /admin',
    );

    console.log(
      ' Auth: /api/*',
    );

    console.log(
      ' Site API: /__waf/api/*',
    );

    console.log(
      ` Rate default: ${config.RATE_LIMIT_MAX}/${config.RATE_LIMIT_WINDOW}s`,
    );

    console.log(
      ` Burst default: ${config.BURST_MAX}/${config.BURST_WINDOW_MS}ms`,
    );

    console.log(
      ` Max concurrent/IP: ${config.MAX_CONCURRENT_PER_IP}`,
    );

    console.log(
      ` Max global concurrent: ${config.MAX_GLOBAL_CONCURRENT}`,
    );

    console.log(
      ' Visitor Counter: MongoDB',
    );

    console.log(
      ' Authentication: MongoDB + Argon2 + JWT',
    );

    console.log(
      ` Brevo Email: ${
        config.BREVO_API_KEY
          ? 'configured'
          : 'not configured'
      }`,
    );

    console.log(
      '==========================================',
    );

    for (
      const site of db.sites
    ) {
      console.log(
        `[SITE] ${site.domains.join(
          ', ',
        )} -> ${site.target_url}`,
      );
    }

    server.listen(
      config.PORT,
      '0.0.0.0',
      () => {
        console.log(
          `Server listening on port ${config.PORT}`,
        );
      },
    );
  } catch (error) {
    console.error(
      'FATAL STARTUP ERROR:',
      error,
    );

    try {
      await mongoose.disconnect();
    } catch {}

    try {
      await mongoClient.close();
    } catch {}

    process.exit(1);
  }
}

/* ============================================================
   GRACEFUL SHUTDOWN
============================================================ */

let shuttingDown =
  false;

async function shutdown(
  signal: string,
): Promise<void> {
  if (shuttingDown) {
    return;
  }

  shuttingDown =
    true;

  console.log(
    `${signal}: shutting down WAF...`,
  );

  try {
    await saveDb();
  } catch (error) {
    console.error(
      'Final database save error:',
      error,
    );
  }

  server.close(
    async () => {
      try {
        await mongoose.disconnect();
      } catch {}

      try {
        await mongoClient.close();
      } catch {}

      process.exit(0);
    },
  );

  setTimeout(
    async () => {
      try {
        await mongoose.disconnect();
      } catch {}

      try {
        await mongoClient.close();
      } catch {}

      process.exit(1);
    },
    10000,
  ).unref();
}

process.on(
  'SIGTERM',
  () =>
    void shutdown(
      'SIGTERM',
    ),
);

process.on(
  'SIGINT',
  () =>
    void shutdown(
      'SIGINT',
    ),
);

/* ============================================================
   START APPLICATION
============================================================ */

void start();
