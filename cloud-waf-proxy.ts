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

PROXY_TIMEOUT_MS: z.coerce.number().int().positive().default(15000)
});

const config = ConfigSchema.parse({
PORT: process.env.PORT,

ADMIN_USER: process.env.ADMIN_USER,

ADMIN_PASSWORD: process.env.ADMIN_PASSWORD,

DATA_FILE:
process.env.DATA_FILE ||
"sites-db.json",

TRUST_PROXY: process.env.TRUST_PROXY,

RATE_LIMIT_WINDOW:
process.env.RATE_LIMIT_WINDOW,

RATE_LIMIT_MAX:
process.env.RATE_LIMIT_MAX,

BURST_WINDOW_MS:
process.env.BURST_WINDOW_MS,

BURST_MAX:
process.env.BURST_MAX,

GLOBAL_RATE_WINDOW_MS:
process.env.GLOBAL_RATE_WINDOW_MS,

GLOBAL_RATE_MAX:
process.env.GLOBAL_RATE_MAX,

MAX_CONCURRENT_PER_IP:
process.env.MAX_CONCURRENT_PER_IP,

MAX_GLOBAL_CONCURRENT:
process.env.MAX_GLOBAL_CONCURRENT,

VIOLATION_LIMIT:
process.env.VIOLATION_LIMIT,

VIOLATION_WINDOW_MS:
process.env.VIOLATION_WINDOW_MS,

AUTO_BLACKLIST_SECONDS:
process.env.AUTO_BLACKLIST_SECONDS,

RISK_BLOCK_THRESHOLD:
process.env.RISK_BLOCK_THRESHOLD,

RISK_HONEYPOT_THRESHOLD:
process.env.RISK_HONEYPOT_THRESHOLD,

RISK_TTL:
process.env.RISK_TTL,

BLACKLIST_TTL:
process.env.BLACKLIST_TTL,

MAX_BODY_SIZE:
process.env.MAX_BODY_SIZE,

REQUEST_TIMEOUT_MS:
process.env.REQUEST_TIMEOUT_MS,

HEADERS_TIMEOUT_MS:
process.env.HEADERS_TIMEOUT_MS,

KEEP_ALIVE_TIMEOUT_MS:
process.env.KEEP_ALIVE_TIMEOUT_MS,

PROXY_TIMEOUT_MS:
process.env.PROXY_TIMEOUT_MS
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

blacklists: Record<
string,
BlacklistEntry

> ;



risks: Record<
string,
RiskEntry

> ;



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

attacks: 0

};
}

function emptyDb(): DbSchema {
return {
sites: [],

blacklists: {},  

risks: {},  

alerts: []

};
}

function normalizeDomain(
domain: string
): string {
return domain
.trim()
.toLowerCase()
.split(":")[0];
}

function normalizeHost(
host: string
): string {
return host
.trim()
.toLowerCase()
.split(":")[0];
}

function loadDb(): DbSchema {
try {
if (!fs.existsSync(dbFilePath)) {
const initial =
emptyDb();

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

const sites =  
  Array.isArray(parsed.sites)  
    ? parsed.sites  
    : [];  

for (const site of sites) {  
  if (!site.stats) {  
    site.stats =  
      createSiteStats();  
  }  
}  

return {  
  sites,  

  blacklists:  
    parsed.blacklists || {},  

  risks:  
    parsed.risks || {},  

  alerts:  
    Array.isArray(parsed.alerts)  
      ? parsed.alerts  
      : []  
};

} catch (error) {

console.error(  
  "Database load error:",  
  error  
);  

return emptyDb();

}
}

let db =
loadDb();

let dbDirty =
false;

function saveDb(): void {
try {

const now =  
  Date.now();  

for (  
  const [key, value]  
  of Object.entries(  
    db.blacklists  
  )  
) {  

  if (  
    value.expiresAt <  
    now  
  ) {  
    delete db.blacklists[key];  
  }  
}  

for (  
  const [key, value]  
  of Object.entries(  
    db.risks  
  )  
) {  

  if (  
    value.expiresAt <  
    now  
  ) {  
    delete db.risks[key];  
  }  
}  

db.alerts =  
  db.alerts.slice(  
    0,  
    1000  
  );  

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

dbDirty =  
  false;

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
SITE LOOKUP
============================================================ */

function getSiteByHost(
host: string
): Site | null {

const normalized =
normalizeHost(host);

return (
db.sites.find(
site => {

const domain =  
      normalizeDomain(  
        site.client_domain  
      );  

    return (  
      domain ===  
      normalized  
    );  
  }  
) || null

);
}

function getSiteById(
id: string
): Site | null {

return (
db.sites.find(
site =>
site.id === id
) || null
);
}

function getSiteByApiKey(
apiKey: string
): Site | null {

return (
db.sites.find(
site =>
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

let globalConcurrent =
0;

/* ============================================================
LIVE ADMIN ALERTS
============================================================ */

const alertClients =
new Set<Response>();

const MAX_ALERTS =
200;

function addAlert(
data: {
site: Site;

ip: string;  

path: string;  

risk: number;  

action: Action;  

reasons: string[];

}
): void {

const alert: WafAlert = {

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
    500  
  ),  

risk:  
  data.risk,  

action:  
  data.action,  

reasons:  
  data.reasons.slice(  
    0,  
    20  
  )

};

db.alerts.unshift(
alert
);

if (
db.alerts.length >
1000
) {
db.alerts.length =
1000;
}

dbDirty =
true;

const payload =
data: ${JSON.stringify(   alert   )}\n\n;

for (
const client
of alertClients
) {

try {  

  client.write(  
    payload  
  );  

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

const now =
Date.now();

for (
const [key, value]
of requestCounters
) {

if (  
  value.expiresAt <  
  now  
) {  
  requestCounters.delete(  
    key  
  );  
}

}

for (
const [key, value]
of burstCounters
) {

if (  
  value.expiresAt <  
  now  
) {  
  burstCounters.delete(  
    key  
  );  
}

}

for (
const [key, value]
of globalCounters
) {

if (  
  value.expiresAt <  
  now  
) {  
  globalCounters.delete(  
    key  
  );  
}

}

for (
const [key, value]
of violations
) {

if (  
  value.expiresAt <  
  now  
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
UTILITIES
============================================================ */

function normalizeIp(
ip: string
): string {

if (
ip.startsWith(
"::ffff:"
)
) {
return ip.slice(
7
);
}

if (
ip === "::1"
) {
return "127.0.0.1";
}

return ip;
}

function getClientIp(
req: Request
): string {

return normalizeIp(
req.ip ||
"0.0.0.0"
);
}

function truncate(
value: string,
max = 4096
): string {

return value.length >
max
? value.slice(
0,
max
)
: value;
}

function safeJson(
value: unknown
): string {

try {

return JSON.stringify(  
  value  
);

} catch {

return "";

}
}

function secureCompare(
a: string,
b: string
): boolean {

const aBuf =
Buffer.from(a);

const bBuf =
Buffer.from(b);

if (
aBuf.length !==
bBuf.length
) {
return false;
}

return crypto.timingSafeEqual(
aBuf,
bBuf
);
}

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

return (
typeof value ===
"number" &&
Number.isFinite(value) &&
value > 0
)
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
| "enablePathTraversal",
fallback = true
): boolean {

const value =
site.settings[key];

return typeof value ===
"boolean"
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

return ${siteId}:${ip};
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

dbDirty =  
  true;  

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

const ttl =
Math.max(
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
  ttl * 1000

};

dbDirty =
true;
}

/* ============================================================
RISK
============================================================ */

function riskKey(
siteId: string,
ip: string
): string {

return ${siteId}:${ip};
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
entry.expiresAt <
now
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
      1000  
};

}

entry.score +=
points;

db.risks[key] =
entry;

dbDirty =
true;

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
entry.expiresAt <
now
) {

entry = {  

  count: 0,  

  expiresAt:  
    now +  
    windowMs  
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
) *
1000;

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
  )

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
${site.id}:${ip};

const currentIp =
concurrentByIp.get(
ipKey
) || 0;

if (
currentIp >=
maxIp
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
${site.id}:${ip};

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
/\bor\s+1\s*=\s1\b/i,
/\band\s+1\s=\s*1\b/i,
/(?:--|/*|*/)/
];

const XSS_PATTERNS = [
/<\sscript\b/i,
/javascript\s:/i,
/on(?:error|load|click|mouseover)\s*=/i,
/<\s*(?:iframe|object|embed)\b/i,
/document\s*.\s*(?:cookie|location)/i
];

const PATH_PATTERNS = [
/..[/\]/,
/%2e%2e(?:%2f|%5c)/i,
/..%2f/i,
/..%5c/i
];

const RCE_PATTERNS = [
/$\([^)]{1,200}\)/,
/[^]{1,200}`/,
/(?:^|[;&|])\s*(?:curl|wget)\s+/i,
/(?:^|[;&|])\s*(?:bash|sh|cmd|powershell)\b/i,
/\b(?:eval|exec|system|popen)\s*(/
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
settingBoolean(
site,
"enableXss"
) &&
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
settingBoolean(
site,
"enablePathTraversal"
) &&
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
settingBoolean(
site,
"enableRce"
) &&
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
site: Site,
req: Request
): {
score: number;

reasons: string[];
} {

let score = 0;

const reasons: string[] =
[];

const values = [

{  
  value:  
    req.originalUrl,  

  location:  
    "url"  
},  

{  
  value:  
    req.headers[  
      "user-agent"  
    ],  

  location:  
    "user-agent"  
},  

{  
  value:  
    req.headers[  
      "referer"  
    ],  

  location:  
    "referer"  
},  

{  
  value:  
    req.headers[  
      "origin"  
    ],  

  location:  
    "origin"  
}

];

for (
const item
of values
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
  )  
]

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

dbDirty =
true;
}

function registerSiteAction(
site: Site,
action: Action,
attack = false
): void {

if (
action ===
"allow"
) {
site.stats.allowedRequests++;
}

if (
action ===
"block"
) {
site.stats.blockedRequests++;
}

if (
action ===
"honeypot"
) {
site.stats.honeypotRequests++;
}

if (attack) {

site.stats.attacks++;  

site.stats.lastAttackAt =  
  new Date().toISOString();

}

dbDirty =
true;
}

/* ============================================================
WAF DECISION
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

  action:  
    "allow",  

  riskScore:  
    getRisk(  
      site,  
      ip  
    ),  

  reasons: [],  

  requestId,  

  site  
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

  action:  
    "block",  

  riskScore:  
    settingNumber(  
      site,  
      "riskBlockThreshold",  
      config.RISK_BLOCK_THRESHOLD  
    ),  

  reasons: [  
    "site_blacklist"  
  ],  

  requestId,  

  site  
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

const action =  
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
    "global_rate_limit"  
  ]  
});  

return {  

  action,  

  riskScore:  
    score,  

  reasons: [  
    "global_rate_limit"  
  ],  

  requestId,  

  site  
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
      "repeated_burst_violation"  
    ]  
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
      "repeated_burst_violation"  
    ],  

    requestId,  

    site  
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
    "burst_rate_limit"  
  ]  
});  

return {  

  action:  
    "honeypot",  

  riskScore:  
    score,  

  reasons: [  
    "burst_rate_limit"  
  ],  

  requestId,  

  site  
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
      "rate_limit_violation"  
    ]  
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
      "rate_limit_violation"  
    ],  

    requestId,  

    site  
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
    "rate_limit_violation"  
  ]  
});  

return {  

  action:  
    "honeypot",  

  riskScore:  
    score,  

  reasons: [  
    "rate_limit_violation"  
  ],  

  requestId,  

  site  
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
      "connection_flood"  
    ]  
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
      "connection_flood"  
    ],  

    requestId,  

    site  
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
    "too_many_concurrent_requests"  
  ]  
});  

return {  

  action:  
    "honeypot",  

  riskScore:  
    score,  

  reasons: [  
    "too_many_concurrent_requests"  
  ],  

  requestId,  

  site  
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
    inspection.reasons.length  
      ? inspection.reasons  
      : [  
          "risk_threshold"  
        ]  
});  

return {  

  action:  
    "block",  

  riskScore:  
    risk,  

  reasons:  
    inspection.reasons.length  
      ? inspection.reasons  
      : [  
          "risk_threshold"  
        ],  

  requestId,  

  site  
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
    inspection.reasons  
});  

return {  

  action:  
    "honeypot",  

  riskScore:  
    risk,  

  reasons:  
    inspection.reasons,  

  requestId,  

  site  
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

site

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

if (
!suppliedKey
) {

return res  
  .status(401)  
  .json({  
    error:  
      "missing_api_key"  
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
      "invalid_api_key"  
  });

}

(
req as Request & {
wafSite?: Site;
}
).wafSite =
site;

return next();
}

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
      site => ({  
        id:  
          site.id,  

        owner_id:  
          site.owner_id,  

        client_domain:  
          site.client_domain,  

        target_url:  
          site.target_url,  

        settings:  
          site.settings,  

        stats:  
          site.stats  
      })  
    )  
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
      z.string().min(1),  

    client_domain:  
      z.string().min(1),  

    target_url:  
      z.string().url(),  

    api_key:  
      z.string().min(20).optional(),  

    settings:  
      z.record(  
        z.unknown()  
      ).default({})  
  });  

const parsed =  
  schema.safeParse(  
    req.body  
  );  

if (  
  !parsed.success  
) {  

  return res  
    .status(400)  
    .json({  
      error:  
        "invalid_site_data",  

      details:  
        parsed.error.flatten()  
    });  
}  

const domain =  
  normalizeDomain(  
    parsed.data.client_domain  
  );  

if (  
  db.sites.some(  
    site =>  
      normalizeDomain(  
        site.client_domain  
      ) === domain  
  )  
) {  

  return res  
    .status(409)  
    .json({  
      error:  
        "domain_already_exists"  
    });  
}  

const site: Site = {  

  id:  
    crypto.randomUUID(),  

  owner_id:  
    parsed.data.owner_id,  

  client_domain:  
    domain,  

  target_url:  
    parsed.data.target_url,  

  api_key:  
    parsed.data.api_key ||  
    crypto.randomBytes(  
      32  
    ).toString(  
      "hex"  
    ),  

  settings:  
    parsed.data.settings,  

  stats:  
    createSiteStats()  
};  

db.sites.push(  
  site  
);  

dbDirty =  
  true;  

saveDb();  

return res  
  .status(201)  
  .json({  
    site  
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
    site =>  
      site.id ===  
      req.params.id  
  );  

if (  
  index === -1  
) {  

  return res  
    .status(404)  
    .json({  
      error:  
        "site_not_found"  
    });  
}  

const [  
  removed  
] =  
  db.sites.splice(  
    index,  
    1  
  );  

for (  
  const key of  
  Object.keys(  
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
  const key of  
  Object.keys(  
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
    alert =>  
      alert.siteId !==  
      removed.id  
  );  

dbDirty =  
  true;  

saveDb();  

return res.json({  
  deleted:  
    true  
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
  (  
    req as Request & {  
      wafSite?: Site;  
    }  
  ).wafSite!;  

return res.json({  

  site: {  

    id:  
      site.id,  

    owner_id:  
      site.owner_id,  

    client_domain:  
      site.client_domain,  

    target_url:  
      site.target_url  
  },  

  stats:  
    site.stats  
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
  (  
    req as Request & {  
      wafSite?: Site;  
    }  
  ).wafSite!;  

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
      alert =>  
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

  alerts  
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
  (  
    req as Request & {  
      wafSite?: Site;  
    }  
  ).wafSite!;  

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
    ) || 0  
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
        alert =>  
          alert.siteId ===  
          siteId  
      )  
    : db.alerts;  

return res.json({  
  alerts:  
    alerts.slice(  
      0,  
      500  
    )  
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

let blacklisted =  
  0;  

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

      attacks: 0  
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
    )  
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
        "site_not_found"  
    });  
}  

return res.json({  
  site,  

  alerts:  
    db.alerts.filter(  
      alert =>  
        alert.siteId ===  
        site.id  
    ).slice(  
      0,  
      200  
    )  
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

<!DOCTYPE html>  <html lang="ar" dir="rtl">  <head>  <meta charset="UTF-8">  <meta  
name="viewport"  
content="width=device-width,initial-scale=1"  
/>

<title>Multi-Site WAF Admin</title>  <style>  
  
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
  max-width: 1400px;  
  
  margin: auto;  
  
  padding: 20px;  
}  
  
.stats {  
  display: grid;  
  
  grid-template-columns:  
    repeat(  
      auto-fit,  
      minmax(180px, 1fr)  
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
  
.grid {  
  display: grid;  
  
  grid-template-columns:  
    minmax(300px, .8fr)  
    minmax(500px, 1.5fr);  
  
  gap: 20px;  
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
  
.site {  
  padding: 16px;  
  
  border-bottom:  
    1px solid #1e2730;  
  
  cursor: pointer;  
}  
  
.site:hover {  
  background: #151d26;  
}  
  
.site:last-child {  
  border-bottom: 0;  
}  
  
.site-name {  
  font-weight: 700;  
  
  margin-bottom: 6px;  
}  
  
.site-target {  
  color: #8794a1;  
  
  font-size: 12px;  
  
  word-break: break-all;  
}  
  
.site-stats {  
  margin-top: 10px;  
  
  display: flex;  
  
  gap: 10px;  
  
  flex-wrap: wrap;  
}  
  
.tag {  
  padding:  
    4px 7px;  
  
  background: #18212b;  
  
  border-radius: 5px;  
  
  font-size: 11px;  
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
  max-width: 900px  
) {  
  
  .grid {  
    grid-template-columns: 1fr;  
  }  
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
  
</style>  </head>  <body>  <header>  <div class="logo">  
  🛡️ Multi-Site WAF Admin  
</div>  <div class="status">  <span class="dot"></span>

حماية مباشرة

</div>  </header>  <div class="container">  <div class="stats">  <div class="card">  <div class="card-title">  
  المواقع  
</div>  <div  
  class="number"  
  id="sites"  
>  
  0  
</div>  </div>  <div class="card">  <div class="card-title">  
  الطلبات  
</div>  <div  
  class="number"  
  id="requests"  
>  
  0  
</div>  </div>  <div class="card">  <div class="card-title">  
  الهجمات  
</div>  <div  
  class="number"  
  id="attacks"  
>  
  0  
</div>  </div>  <div class="card">  <div class="card-title">  
  IPs المحظورة  
</div>  <div  
  class="number"  
  id="blacklisted"  
>  
  0  
</div>  </div>  <div class="card">  <div class="card-title">  
  الاتصالات الحالية  
</div>  <div  
  class="number"  
  id="connections"  
>  
  0  
</div>  </div>  </div>  <div class="grid">  <div class="panel">  <div class="panel-header">  
  🌐 المواقع  
</div>  <div id="sitesList">  <div class="empty">  
  لا توجد مواقع  
</div>  </div>  </div>  <div class="panel">  <div class="panel-header">  
  🚨 التنبيهات المباشرة  
</div>  <div id="alerts">  <div class="empty">  
  لا توجد تنبيهات حتى الآن  
</div>  </div>  </div>  </div>  </div>  <script>  
  
const sitesElement =  
  document.getElementById(  
    "sites"  
  );  
  
const requestsElement =  
  document.getElementById(  
    "requests"  
  );  
  
const attacksElement =  
  document.getElementById(  
    "attacks"  
  );  
  
const blacklistedElement =  
  document.getElementById(  
    "blacklisted"  
  );  
  
const connectionsElement =  
  document.getElementById(  
    "connections"  
  );  
  
const sitesList =  
  document.getElementById(  
    "sitesList"  
  );  
  
const alertsElement =  
  document.getElementById(  
    "alerts"  
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
      Site:  
      <strong>  
        \${escapeHtml(  
          alert.domain  
        )}  
      </strong>  
    </div>  
  
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
  
  alertsElement.prepend(  
    renderAlert(  
      alert  
    )  
  );  
  
  while (  
    alertsElement.children  
      .length > 200  
  ) {  
  
    alertsElement.lastElementChild  
      ?.remove();  
  }  
}  
  
async function loadSites() {  
  
  try {  
  
    const response =  
      await fetch(  
        "/__waf/admin/sites",  
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
  
    sitesList.innerHTML =  
      "";  
  
    if (  
      !data.sites ||  
      !data.sites.length  
    ) {  
  
      sitesList.innerHTML =  
        '<div class="empty">لا توجد مواقع</div>';  
  
      return;  
    }  
  
    for (  
      const site of  
      data.sites  
    ) {  
  
      const element =  
        document.createElement(  
          "div"  
        );  
  
      element.className =  
        "site";  
  
      element.innerHTML = \`  
        <div class="site-name">  
          \${escapeHtml(  
            site.client_domain  
          )}  
        </div>  
  
        <div class="site-target">  
          \${escapeHtml(  
            site.target_url  
          )}  
        </div>  
  
        <div class="site-stats">  
  
          <span class="tag">  
            Requests:  
            \${escapeHtml(  
              site.stats?.totalRequests ?? 0  
            )}  
          </span>  
  
          <span class="tag">  
            Blocked:  
            \${escapeHtml(  
              site.stats?.blockedRequests ?? 0  
            )}  
          </span>  
  
          <span class="tag">  
            Attacks:  
            \${escapeHtml(  
              site.stats?.attacks ?? 0  
            )}  
          </span>  
  
        </div>  
      \`;  
  
      sitesList.appendChild(  
        element  
      );  
    }  
  
  } catch {  
    // Ignore dashboard errors.  
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
  
    sitesElement.textContent =  
      data.sites ?? 0;  
  
    requestsElement.textContent =  
      data.totals?.requests ?? 0;  
  
    attacksElement.textContent =  
      data.totals?.attacks ?? 0;  
  
    blacklistedElement.textContent =  
      data.blacklisted ?? 0;  
  
    connectionsElement.textContent =  
      data.globalConcurrent ?? 0;  
  
  } catch {  
    // Ignore dashboard errors.  
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
  
      loadSites();  
  
    } catch {  
      // Ignore malformed events.  
    }  
  };  
  
events.onerror =  
  () => {  
    // EventSource automatically reconnects.  
  };  
  
loadSites();  
  
loadStats();  
  
loadAlerts();  
  
setInterval(  
  loadStats,  
  3000  
);  
  
setInterval(  
  loadSites,  
  5000  
);  
  
</script>  </body>  </html>  
`);  
  }  
);  /* ============================================================
HEALTH
============================================================ */

app.get(
"/__waf/health",
(_req, res) => {

return res.json({  

  status:  
    "ok",  

  service:  
    "multi-site-cloud-waf",  

  protection:  
    "strong-l7",  

  sites:  
    db.sites.length,  

  globalConcurrent,  

  activeClients:  
    concurrentByIp.size  
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
  (  
    req as Request & {  
      wafSite?: Site;  
    }  
  ).wafSite!;  

const ip =  
  normalizeIp(  
    req.params.ip  
  );  

return res.json({  

  site_id:  
    site.id,  

  domain:  
    site.client_domain,  

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
        "not_found"  
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

  risk:  
    score,  

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
SITE RESOLUTION
============================================================ */

function resolveSite(
req: Request,
res: Response
): Site | null {

const host =
req.headers.host ||
"";

const site =
getSiteByHost(
host
);

if (!site) {

res  
  .status(404)  
  .json({  
    error:  
      "site_not_configured",  

    host  
  });  

return null;

}

return site;
}

/* ============================================================
WAF MIDDLEWARE
============================================================ */

app.use(
async (
req,
res,
next
) => {

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
          decision.reasons  
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
          decision.requestId  
      });  
  }  

  (  
    req as Request & {  
      wafSite?: Site;  
    }  
  ).wafSite =  
    site;  

  (  
    req as Request & {  
      wafRequestId?: string;  
    }  
  ).wafRequestId =  
    decision.requestId;  

  (  
    req as Request & {  
      wafAcquired?: boolean;  
    }  
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
        "waf_unavailable"  
    });  
}

}
);

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
  (  
    req as Request & {  
      wafSite?: Site;  
    }  
  ).wafSite;  

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

    released =  
      true;  

    const acquired =  
      (  
        req as Request & {  
          wafAcquired?: boolean;  
        }  
      ).wafAcquired;  

    if (acquired) {  

      releaseConcurrency(  
        site,  
        getClientIp(req)  
      );  

      (  
        req as Request & {  
          wafAcquired?: boolean;  
        }  
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
  (  
    req  
  ) => {  

    const site =  
      (  
        req as Request & {  
          wafSite?: Site;  
        }  
      ).wafSite;  

    if (!site) {  
      return undefined;  
    }  

    return site.target_url;  
  },  

onProxyReq(  
  proxyReq,  
  req  
) {  

  const site =  
    (  
      req as Request & {  
        wafSite?: Site;  
      }  
    ).wafSite;  

  const requestId =  
    (  
      req as Request & {  
        wafRequestId?: string;  
      }  
    ).wafRequestId;  

  proxyReq.setHeader(  
    "x-waf-protected",  
    "true"  
  );  

  proxyReq.setHeader(  
    "x-waf-site-id",  
    site?.id ||  
      ""  
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
  req,  
  res  
) {  

  const site =  
    (  
      req as Request & {  
        wafSite?: Site;  
      }  
    ).wafSite;  

  console.error(  
    "Proxy error:",  
    error  
  );  

  if (  
    site  
  ) {  

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
        "proxy_error"  
      ]  
    });  
  }  

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

> ();



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
  " Multi-Site Cloud WAF"  
);  

console.log(  
  " Dynamic Reverse Proxy Enabled"  
);  

console.log(  
  " Live Admin Dashboard Enabled"  
);  

console.log(  
  " L7 Protection Enabled"  
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
  ` Admin: /admin`  
);  

console.log(  
  ` Site API: /__waf/api/*`  
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
    `[SITE] ${site.client_domain} -> ${site.target_url}`  
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
${signal}: shutting down WAF...
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
