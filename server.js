'use strict';

const express = require('express');
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const dns = require('dns').promises;
const net = require('net');
const Redis = require('redis');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { Transform, pipeline } = require('stream');
const { promisify } = require('util');
const pipelineAsync = promisify(pipeline);
const app = express();
const server = http.createServer(app);

let activeRequests = 0;
let isShuttingDown = false;

server.requestTimeout = 30_000;
server.headersTimeout = 10_000;
server.keepAliveTimeout = 5_000;

function parseTrustProxy(value) {
    if (!value || value === 'false' || value === '0') {
        return false;
    }
    if (value === 'true' || value === '1') {
        throw new Error('TRUST_PROXY must contain explicit trusted IP/CIDR values.');
    }
    return value
        .split(',')
        .map(v => v.trim())
        .filter(Boolean);
}

const CONFIG = {
    PORT: Number(process.env.PORT || 3000),
    TARGET_SERVER: process.env.TARGET_SERVER || 'http://127.0.0.1:8080',
    ORIGIN_SECRET_TOKEN: process.env.ORIGIN_SECRET_TOKEN || 'k9X#mP2$vL9_qR5!wZ8*yF3@bN6%dT1', // تم وضع قيمة افتراضية للاختبار
    REDIS_URL: process.env.REDIS_URL || 'redis://127.0.0.1:6379',
    MAX_BODY_SIZE: 5 * 1024 * 1024,
    MAX_CONCURRENT_REQUESTS: 500,
    RATE_LIMIT_WINDOW: 60,
    RATE_LIMIT_MAX: 150,
    BLOCK_DURATION: 15 * 60 * 1000,
    LEARNING_PHASE_REQUESTS: 100,
    CONFIDENCE_THRESHOLD: 0.85,
    DNS_CACHE_TTL: 30_000,
    BODY_SAMPLE_SIZE: 8192,
    UPSTREAM_TIMEOUT: 20_000,
    PROFILE_TTL: 1800,
    BASELINE_TTL: 30 * 24 * 60 * 60,
    MAX_MEMORY_RATE_LIMIT_ENTRIES: 10_000,
    MAX_TEMP_FILE_AGE: 60 * 60 * 1000
};

app.set('trust proxy', parseTrustProxy(process.env.TRUST_PROXY));

if (!Number.isInteger(CONFIG.PORT) || CONFIG.PORT < 1 || CONFIG.PORT > 65535) {
    throw new Error('Invalid PORT.');
}
if (!CONFIG.ORIGIN_SECRET_TOKEN) {
    throw new Error('ORIGIN_SECRET_TOKEN is required.');
}
if (CONFIG.ORIGIN_SECRET_TOKEN.length < 32) {
    throw new Error('ORIGIN_SECRET_TOKEN must be at least 32 characters.');
}

function structuredLog(level, message, meta = {}) {
    console.log(JSON.stringify({ timestamp: new Date().toISOString(), level, message, ...meta }));
}

function getIpLocation(ip) {
    return new Promise((resolve) => {
        if (ip === '127.0.0.1' || ip === '::1' || ip.startsWith('192.168.') || ip.startsWith('10.')) {
            return resolve('شبكة محلية (Localhost)');
        }

        https.get(`https://ipapi.co/${ip}/json/`, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                try {
                    const info = JSON.parse(data);
                    if (info.error) {
                        return resolve('غير معروف');
                    }
                    resolve(`${info.city || 'غير معروف'}, ${info.country_name || 'غير معروف'}`);
                } catch {
                    resolve('غير معروف');
                }
            });
        }).on('error', () => resolve('غير معروف'));
    });
}

async function sendSecurityAlert(ip, score, pathVal, attackType) {
    const token = '8817540855:AAEzpJxQtLKZmiHcL0RcDlCZnLVehMaaTIU';
    const chatId = '2025220567';
    
    const location = await getIpLocation(ip);

    const message = `🚨 *تم رصد وحظر هجوم أمني!*\n\n` +
                    `🌐 *الـ IP:* \`${ip}\`\n` +
                    `📍 *الموقع:* ${location}\n` +
                    `⚔️ *نوع الهجوم:* ${attackType}\n` +
                    `📊 *درجة الخطورة:* \`${score}\`\n` +
                    `📂 *المسار المستهدف:* \`${pathVal}\``;

    const data = JSON.stringify({
        chat_id: chatId,
        text: message,
        parse_mode: 'Markdown'
    });

    const options = {
        hostname: 'api.telegram.org',
        port: 443,
        path: `/bot${token}/sendMessage`,
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(data)
        }
    };

    const req = https.request(options);
    req.on('error', (error) => {
        structuredLog('ERROR', 'Telegram alert failed', { error: error.message });
    });
    req.write(data);
    req.end();
}

function normalizeIPv4(ip) {
    if (!net.isIPv4(ip)) {
        return null;
    }
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4 || parts.some(x => !Number.isInteger(x) || x < 0 || x > 255)) {
        return null;
    }
    return parts;
}

function ipv4ToBigInt(ip) {
    const parts = normalizeIPv4(ip);
    if (!parts) {
        throw new Error('Invalid IPv4.');
    }
    return (
        (BigInt(parts[0]) << 24n) |
        (BigInt(parts[1]) << 16n) |
        (BigInt(parts[2]) << 8n) |
        BigInt(parts[3])
    );
}

function expandIPv6(ip) {
    let address = String(ip).toLowerCase();
    if (address.includes('.')) {
        const lastColon = address.lastIndexOf(':');
        if (lastColon === -1) {
            throw new Error('Invalid IPv6.');
        }
        const ipv4 = address.slice(lastColon + 1);
        if (!net.isIPv4(ipv4)) {
            throw new Error('Invalid embedded IPv4.');
        }
        const value = ipv4ToBigInt(ipv4);
        const high = Number((value >> 16n) & 0xffffn).toString(16);
        const low = Number(value & 0xffffn).toString(16);
        address = address.slice(0, lastColon + 1) + high + ':' + low;
    }
    const sections = address.split('::');
    if (sections.length > 2) {
        throw new Error('Invalid IPv6.');
    }
    const left = sections[0] ? sections[0].split(':').filter(Boolean) : [];
    const right = sections[1] ? sections[1].split(':').filter(Boolean) : [];
    const missing = 8 - left.length - right.length;
    if (missing < 0) {
        throw new Error('Invalid IPv6.');
    }
    const groups = sections.length === 1 ? [...left] : [...left, ...new Array(missing).fill('0'), ...right];
    if (groups.length !== 8) {
        throw new Error('Invalid IPv6.');
    }
    return groups.map(group => {
        if (!/^[0-9a-f]{1,4}$/i.test(group)) {
            throw new Error('Invalid IPv6 group.');
        }
        const value = parseInt(group, 16);
        if (!Number.isInteger(value) || value < 0 || value > 0xffff) {
            throw new Error('Invalid IPv6 group.');
        }
        return value;
    });
}

function ipv6ToBigInt(ip) {
    const groups = expandIPv6(ip);
    let result = 0n;
    for (const group of groups) {
        result = (result << 16n) | BigInt(group);
    }
    return result;
}

function ipToBigInt(ip) {
    if (net.isIPv4(ip)) {
        return { family: 4, value: ipv4ToBigInt(ip) };
    }
    if (net.isIPv6(ip)) {
        return { family: 6, value: ipv6ToBigInt(ip) };
    }
    throw new Error(`Invalid IP: ${ip}`);
}

function getIPv4MappedAddress(ip) {
    if (!net.isIPv6(ip)) {
        return null;
    }
    try {
        const groups = expandIPv6(ip);
        const mapped = groups[0] === 0 && groups[1] === 0 && groups[2] === 0 && groups[3] === 0 && groups[4] === 0 && groups[5] === 0xffff;
        if (!mapped) {
            return null;
        }
        const high = groups[6];
        const low = groups[7];
        return [high >> 8, high & 0xff, low >> 8, low & 0xff].join('.');
    } catch {
        return null;
    }
}

function isIpInCidr(ip, cidr) {
    try {
        const [network, bitsString] = cidr.split('/');
        let ipInfo = ipToBigInt(ip);
        let networkInfo = ipToBigInt(network);
        const mappedIp = getIPv4MappedAddress(ip);
        const mappedNetwork = getIPv4MappedAddress(network);
        if (mappedIp) {
            ipInfo = ipToBigInt(mappedIp);
        }
        if (mappedNetwork) {
            networkInfo = ipToBigInt(mappedNetwork);
        }
        if (ipInfo.family !== networkInfo.family) {
            return false;
        }
        const totalBits = ipInfo.family === 4 ? 32 : 128;
        const bits = bitsString === undefined ? totalBits : Number(bitsString);
        if (!Number.isInteger(bits) || bits < 0 || bits > totalBits) {
            return false;
        }
        if (bits === 0) {
            return true;
        }
        const shift = BigInt(totalBits - bits);
        return (ipInfo.value >> shift) === (networkInfo.value >> shift);
    } catch {
        return false;
    }
}

const BLOCKED_CIDRS = [
    '0.0.0.0/8',
    '10.0.0.0/8',
    '100.64.0.0/10',
    '127.0.0.0/8',
    '169.254.0.0/16',
    '172.16.0.0/12',
    '192.0.0.0/24',
    '192.0.2.0/24',
    '192.168.0.0/16',
    '198.18.0.0/15',
    '198.51.100.0/24',
    '203.0.113.0/24',
    '224.0.0.0/4',
    '240.0.0.0/4',
    '::/128',
    '::1/128',
    'fc00::/7',
    'fe80::/10',
    'ff00::/8',
    '2001:db8::/32'
];

function isRestrictedIp(ip) {
    const mapped = getIPv4MappedAddress(ip);
    const candidate = mapped || ip;
    return BLOCKED_CIDRS.some(cidr => isIpInCidr(candidate, cidr));
}

let dnsCache = null;

async function resolveAndPinTarget() {
    const now = Date.now();
    if (dnsCache && now - dnsCache.timestamp < CONFIG.DNS_CACHE_TTL) {
        return dnsCache.value;
    }
    const parsed = new URL(CONFIG.TARGET_SERVER);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        throw new Error('TARGET_SERVER must use HTTP or HTTPS.');
    }
    if (parsed.username || parsed.password) {
        throw new Error('TARGET_SERVER must not contain credentials.');
    }
    const hostname = parsed.hostname;
    if (!hostname) {
        throw new Error('TARGET_SERVER hostname is missing.');
    }
    if (net.isIP(hostname)) {
        if (isRestrictedIp(hostname)) {
            throw new Error(`Restricted target IP: ${hostname}`);
        }
        const result = { parsed, pinnedIp: hostname, family: net.isIPv6(hostname) ? 6 : 4 };
        dnsCache = { timestamp: now, value: result };
        return result;
    }
    const [ipv4, ipv6] = await Promise.all([
        dns.resolve4(hostname).catch(() => []),
        dns.resolve6(hostname).catch(() => [])
    ]);
    const addresses = [...ipv4, ...ipv6];
    if (addresses.length === 0) {
        throw new Error(`DNS resolution failed: ${hostname}`);
    }
    for (const address of addresses) {
        if (isRestrictedIp(address)) {
            throw new Error(`DNS resolved to restricted IP: ${address}`);
        }
    }
    const pinnedIp = ipv4[0] || ipv6[0];
    if (!pinnedIp) {
        throw new Error('No usable upstream address.');
    }
    const result = { parsed, pinnedIp, family: net.isIPv6(pinnedIp) ? 6 : 4 };
    dnsCache = { timestamp: now, value: result };
    return result;
}

const redisClient = Redis.createClient({ url: CONFIG.REDIS_URL, disableOfflineQueue: true });
let redisAvailable = false;

redisClient.on('connect', () => {
    structuredLog('INFO', 'Redis connecting');
});
redisClient.on('ready', () => {
    redisAvailable = true;
    structuredLog('INFO', 'Redis ready');
});
redisClient.on('end', () => {
    redisAvailable = false;
    structuredLog('WARN', 'Redis connection ended');
});
redisClient.on('error', error => {
    redisAvailable = false;
    structuredLog('ERROR', 'Redis error', { error: error.message });
});

const memoryRateLimits = new Map();

function memoryRateLimit(ip) {
    const now = Date.now();
    let record = memoryRateLimits.get(ip);
    if (!record || now >= record.reset) {
        if (memoryRateLimits.size >= CONFIG.MAX_MEMORY_RATE_LIMIT_ENTRIES) {
            const firstKey = memoryRateLimits.keys().next().value;
            if (firstKey) {
                memoryRateLimits.delete(firstKey);
            }
        }
        record = { count: 0, reset: now + CONFIG.RATE_LIMIT_WINDOW * 1000 };
        memoryRateLimits.set(ip, record);
    }
    record.count++;
    return (record.count > CONFIG.RATE_LIMIT_MAX);
}

setInterval(() => {
    const now = Date.now();
    for (const [ip, record] of memoryRateLimits) {
        if (now >= record.reset) {
            memoryRateLimits.delete(ip);
        }
    }
}, 60_000).unref();

const RATE_LIMIT_LUA = `
local zsetKey = KEYS[1]
local blockKey = KEYS[2]
local now = tonumber(ARGV[1])
local windowStart = tonumber(ARGV[2])
local maxLimit = tonumber(ARGV[3])
local ttl = tonumber(ARGV[4])
local blockDuration = tonumber(ARGV[5])
local member = ARGV[6]
if redis.call('EXISTS', blockKey) == 1 then
    return 1
end
redis.call('ZREMRANGEBYSCORE', zsetKey, '-inf', windowStart)
redis.call('ZADD', zsetKey, now, member)
local count = redis.call('ZCARD', zsetKey)
redis.call('EXPIRE', zsetKey, ttl)
if count > maxLimit then
    redis.call('SETEX', blockKey, blockDuration, '1')
    return 1
end
return 0
`;

const BEHAVIORAL_LUA = `
local profileKey = KEYS[1]
local baselineKey = KEYS[2]
local now = tonumber(ARGV[1])
local route = ARGV[2]
local path = ARGV[3]
local learningMax = tonumber(ARGV[4])
local requiredConfidence = tonumber(ARGV[5])
local payloadSize = tonumber(ARGV[6])
local entropy = tonumber(ARGV[7])
local sensitive = tonumber(ARGV[8])
local maxEndpoints = tonumber(ARGV[9])
local maxTransitions = tonumber(ARGV[10])
local profileJson = redis.call('GET', profileKey)
local baselineJson = redis.call('GET', baselineKey)
local profile
if profileJson then
    profile = cjson.decode(profileJson)
else
    profile = {
        lastRequestTime = now,
        requestIntervals = {},
        lastEndpoint = false,
        endpointsVisited = {},
        transitionMatrix = {},
        totalRequests = 0,
        stage = 'QUARANTINE'
    }
end
local baseline
if baselineJson then
    baseline = cjson.decode(baselineJson)
else
    baseline = {
        established = false,
        baselineTransitions = {},
        baselineMeanInterval = 0,
        baselineStdDev = 0,
        confidenceScore = 0
    }
end
local previousTime = tonumber(profile.lastRequestTime or now)
local interval = now - previousTime
if interval < 0 then
    interval = 0
end
profile.lastRequestTime = now
profile.totalRequests = tonumber(profile.totalRequests or 0) + 1
local totalRequests = profile.totalRequests
table.insert(profile.requestIntervals, interval)
if #profile.requestIntervals > 50 then
    table.remove(profile.requestIntervals, 1)
end
if not baseline.established then
    local endpointCount = 0
    for _ in pairs(profile.endpointsVisited) do
        endpointCount = endpointCount + 1
    end
    if profile.endpointsVisited[path] then
        profile.endpointsVisited[path] = profile.endpointsVisited[path] + 1
    elseif endpointCount < maxEndpoints then
        profile.endpointsVisited[path] = 1
    end
    if profile.lastEndpoint then
        if not profile.transitionMatrix[profile.lastEndpoint] then
            profile.transitionMatrix[profile.lastEndpoint] = {}
        end
        local transition = profile.lastEndpoint .. ' => ' .. route
        local transitionCount = 0
        for _ in pairs(profile.transitionMatrix[profile.lastEndpoint]) do
            transitionCount = transitionCount + 1
        end
        if profile.transitionMatrix[profile.lastEndpoint][transition] or transitionCount < maxTransitions then
            local old = profile.transitionMatrix[profile.lastEndpoint][transition] or 0
            profile.transitionMatrix[profile.lastEndpoint][transition] = old + 1
        end
    end
    profile.lastEndpoint = route
    local uniqueEndpoints = 0
    for _ in pairs(profile.endpointsVisited) do
        uniqueEndpoints = uniqueEndpoints + 1
    end
    local sum = 0
    for i = 1, #profile.requestIntervals do
        sum = sum + profile.requestIntervals[i]
    end
    local mean = 1
    if #profile.requestIntervals > 0 then
        mean = sum / #profile.requestIntervals
    end
    local varianceSum = 0
    for i = 1, #profile.requestIntervals do
        local delta = profile.requestIntervals[i] - mean
        varianceSum = varianceSum + delta * delta
    end
    local stdDev = 0
    if #profile.requestIntervals > 1 then
        stdDev = math.sqrt(varianceSum / #profile.requestIntervals)
    end
    local coefficient = 1
    if mean > 0 then
        coefficient = stdDev / mean
    end
    local timingFactor = 1 - math.min(1, coefficient / 2)
    if timingFactor < 0 then
        timingFactor = 0
    end
    local diversityFactor = math.min(1, uniqueEndpoints / 10)
    local confidence = (timingFactor * 0.5) + (diversityFactor * 0.5)
    if totalRequests >= learningMax and confidence >= requiredConfidence then
        baseline.established = true
        baseline.baselineTransitions = profile.transitionMatrix
        baseline.baselineMeanInterval = mean
        baseline.baselineStdDev = stdDev
        baseline.confidenceScore = confidence
        redis.call('SETEX', baselineKey, 2592000, cjson.encode(baseline))
        profile.stage = 'PROTECTING'
    else
        profile.stage = 'QUARANTINE'
    end
    redis.call('SETEX', profileKey, 1800, cjson.encode(profile))
    return cjson.encode({
        totalRiskScore = 0,
        vector = { stage = profile.stage, confidence = confidence }
    })
end
local velocity = 0
if baseline.baselineStdDev > 0.1 then
    local z = math.abs((interval - baseline.baselineMeanInterval) / baseline.baselineStdDev)
    if z > 4.0 and interval < 10 then
        velocity = 30
    end
end
local sequence = 0
if profile.lastEndpoint and baseline.baselineTransitions[profile.lastEndpoint] then
    local transition = profile.lastEndpoint .. ' => ' .. route
    if not baseline.baselineTransitions[profile.lastEndpoint][transition] then
        sequence = 35
    end
end
profile.lastEndpoint = route
local content = 0
if entropy > 7.6 and sensitive == 1 and payloadSize > 1024 then
    content = 15
end
local risk = velocity + sequence + content
if risk >= 60 then
    profile.stage = 'ESCALATED'
elseif risk >= 40 then
    profile.stage = 'HIGH_RISK'
elseif risk >= 20 then
    profile.stage = 'SUSPICIOUS'
else
    profile.stage = 'PROTECTING'
end
redis.call('SETEX', profileKey, 1800, cjson.encode(profile))
return cjson.encode({
    totalRiskScore = risk,
    vector = {
        stage = profile.stage,
        velocity = velocity,
        sequence = sequence,
        content = content
    }
})
`;

const SAFE_BEHAVIORAL_LUA = BEHAVIORAL_LUA.replace(/\/\*[\s\S]*?\*\//g, '');

function normalizeRoutePath(input) {
    return String(input || '/')
        .replace(/\/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?=\/|$)/g, '/:id')
        .replace(/\/\d+(?=\/|$)/g, '/:id');
}

function calculateEntropy(buffer) {
    if (!buffer || buffer.length === 0) {
        return 0;
    }
    const frequencies = new Array(256).fill(0);
    for (const byte of buffer) {
        frequencies[byte]++;
    }
    let entropy = 0;
    for (const frequency of frequencies) {
        if (frequency === 0) {
            continue;
        }
        const probability = frequency / buffer.length;
        entropy -= probability * Math.log2(probability);
    }
    return entropy;
}

class BehavioralEngine {
    constructor(redis) {
        this.redis = redis;
    }

    profileKey(req) {
        const material = [
            req.clientIp,
            req.headers['user-agent'] || '',
            req.headers['accept-language'] || ''
        ].join('|');
        return crypto
            .createHash('sha256')
            .update(material)
            .digest('hex')
            .slice(0, 32);
    }

    async isBlocked(ip) {
        if (!redisAvailable) {
            return false;
        }
        try {
            return !!(await this.redis.get(`block:${ip}`));
        } catch (error) {
            structuredLog('WARN', 'Block lookup failed', { error: error.message });
            return false;
        }
    }

    async blockIp(ip) {
        if (!redisAvailable) {
            return;
        }
        try {
            await this.redis.setEx(`block:${ip}`, Math.ceil(CONFIG.BLOCK_DURATION / 1000), '1');
        } catch (error) {
            structuredLog('ERROR', 'Failed to block IP', { error: error.message });
        }
    }

    async rateLimit(ip) {
        if (!redisAvailable) {
            return memoryRateLimit(ip);
        }
        const now = Date.now();
        try {
            const result = await this.redis.eval(RATE_LIMIT_LUA, {
                keys: [`rl:${ip}`, `block:${ip}`],
                arguments: [
                    String(now),
                    String(now - CONFIG.RATE_LIMIT_WINDOW * 1000),
                    String(CONFIG.RATE_LIMIT_MAX),
                    String(CONFIG.RATE_LIMIT_WINDOW + 5),
                    String(Math.ceil(CONFIG.BLOCK_DURATION / 1000)),
                    `${now}:${crypto.randomUUID()}`
                ]
            });
            return Number(result) === 1;
        } catch (error) {
            structuredLog('ERROR', 'Redis rate limiter failed', { error: error.message });
            return memoryRateLimit(ip);
        }
    }

    async evaluate(req, sample, totalLength, sensitive) {
        if (!redisAvailable) {
            return {
                totalRiskScore: sensitive ? 50 : 10,
                vector: { stage: 'REDIS_FALLBACK', status: 'BEHAVIORAL_ENGINE_UNAVAILABLE' }
            };
        }
        const key = this.profileKey(req);
        const normalized = normalizeRoutePath(req.path);
        const route = `${req.method} ${normalized}`;
        try {
            const result = await this.redis.eval(SAFE_BEHAVIORAL_LUA, {
                keys: [`profile:${key}`, `baseline:${key}`],
                arguments: [
                    String(Date.now()),
                    route,
                    normalized,
                    String(CONFIG.LEARNING_PHASE_REQUESTS),
                    String(CONFIG.CONFIDENCE_THRESHOLD),
                    String(totalLength),
                    String(calculateEntropy(sample)),
                    sensitive ? '1' : '0',
                    '50',
                    '100'
                ]
            });
            return JSON.parse(result);
        } catch (error) {
            structuredLog('ERROR', 'Behavioral evaluation failed', { error: error.message });
            return {
                totalRiskScore: sensitive ? 50 : 10,
                vector: { stage: 'BEHAVIORAL_ERROR' }
            };
        }
    }
}

const behavioral = new BehavioralEngine(redisClient);

function getClientIp(req) {
    const ip = req.ip || req.socket.remoteAddress;
    if (!ip) {
        return '0.0.0.0';
    }
    return ip;
}

const HOP_BY_HOP_HEADERS = new Set([
    'connection',
    'keep-alive',
    'proxy-authenticate',
    'proxy-authorization',
    'te',
    'trailer',
    'transfer-encoding',
    'upgrade',
    'host'
]);

function getConnectionHeaderTokens(headers) {
    const value = headers.connection;
    if (!value) {
        return new Set();
    }
    const values = Array.isArray(value) ? value : [value];
    const tokens = new Set();
    for (const item of values) {
        String(item)
            .split(',')
            .map(x => x.trim().toLowerCase())
            .filter(Boolean)
            .forEach(x => tokens.add(x));
    }
    return tokens;
}

function isUnsafeForwardHeader(name, connectionTokens) {
    const lower = name.toLowerCase();
    return (
        HOP_BY_HOP_HEADERS.has(lower) ||
        connectionTokens.has(lower) ||
        lower.startsWith('proxy-') ||
        lower === 'x-forwarded-for' ||
        lower === 'x-forwarded-host' ||
        lower === 'x-forwarded-proto' ||
        lower === 'x-forwarded-port' ||
        lower === 'x-tbp-origin-secret'
    );
}

function buildUpstreamHeaders(req, target, clientIp, bodyLength) {
    const headers = {};
    const connectionTokens = getConnectionHeaderTokens(req.headers);
    for (const [key, value] of Object.entries(req.headers)) {
        if (isUnsafeForwardHeader(key, connectionTokens)) {
            continue;
        }
        headers[key] = value;
    }
    headers.host = target.parsed.host;
    headers['x-forwarded-for'] = clientIp;
    headers['x-forwarded-proto'] = req.protocol === 'https:' ? 'https' : 'http';
    headers['x-tbp-origin-secret'] = CONFIG.ORIGIN_SECRET_TOKEN;
    headers['content-length'] = String(bodyLength);
    delete headers['transfer-encoding'];
    return headers;
}

function sanitizeResponseHeaders(input) {
    const output = {};
    const connectionTokens = getConnectionHeaderTokens(input || {});
    for (const [key, value] of Object.entries(input || {})) {
        const lower = key.toLowerCase();
        if (HOP_BY_HOP_HEADERS.has(lower) || connectionTokens.has(lower) || lower.startsWith('proxy-')) {
            continue;
        }
        output[key] = value;
    }
    return output;
}

app.disable('x-powered-by');
app.use((req, res, next) => {
    if (isShuttingDown) {
        res.setHeader('Connection', 'close');
        return res.status(503).json({ status: 'SERVER_SHUTTING_DOWN' });
    }
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Content-Security-Policy', "default-src 'self'");
    next();
});

app.get('/_tbp/health', (req, res) => {
    res.status(200).json({
        status: isShuttingDown ? 'SHUTTING_DOWN' : 'OK',
        redis: redisAvailable ? 'UP' : 'DOWN',
        activeRequests,
        uptime: Math.floor(process.uptime())
    });
});

class BodySpool extends Transform {
    constructor(maxBytes, sampleBytes) {
        super();
        this.maxBytes = maxBytes;
        this.sampleLimit = sampleBytes;
        this.totalBytes = 0;
        this.sampleParts = [];
        this.sampledBytes = 0;
    }

    _transform(chunk, encoding, callback) {
        try {
            if (!Buffer.isBuffer(chunk)) {
                chunk = Buffer.from(chunk, encoding);
            }
            this.totalBytes += chunk.length;
            if (this.totalBytes > this.maxBytes) {
                const error = new Error('PAYLOAD_TOO_LARGE');
                error.code = 'PAYLOAD_TOO_LARGE';
                return callback(error);
            }
            if (this.sampledBytes < this.sampleLimit) {
                const remaining = this.sampleLimit - this.sampledBytes;
                const amount = Math.min(remaining, chunk.length);
                this.sampleParts.push(Buffer.from(chunk.subarray(0, amount)));
                this.sampledBytes += amount;
            }
            callback(null, chunk);
        } catch (error) {
            callback(error);
        }
    }

    getSample() {
        return Buffer.concat(this.sampleParts);
    }
}

function createTempFile() {
    return path.join(os.tmpdir(), `tbp-${crypto.randomUUID()}.tmp`);
}

async function safeUnlink(file) {
    if (!file) {
        return;
    }
    try {
        await fs.promises.unlink(file);
    } catch (error) {
        if (error.code !== 'ENOENT') {
            structuredLog('WARN', 'Temp file cleanup failed', { error: error.message });
        }
    }
}

app.use(async (req, res) => {
    if (activeRequests >= CONFIG.MAX_CONCURRENT_REQUESTS) {
        return res.status(503).json({ status: 'SERVER_BUSY' });
    }
    activeRequests++;
    let released = false;
    const release = () => {
        if (released) {
            return;
        }
        released = true;
        activeRequests = Math.max(0, activeRequests - 1);
    };
    res.once('finish', release);
    res.once('close', release);

    let tempFile = null;
    try {
        const clientIp = getClientIp(req);
        req.clientIp = clientIp;

        const sensitive = /(?:^|\/)(api\/auth|admin|exec)(?:\/|$)/i.test(req.path);

        const contentLength = req.headers['content-length'];
        if (contentLength !== undefined) {
            const parsedLength = Number(contentLength);
            if (!Number.isSafeInteger(parsedLength) || parsedLength < 0) {
                return res.status(400).json({ status: 'INVALID_CONTENT_LENGTH' });
            }
            if (parsedLength > CONFIG.MAX_BODY_SIZE) {
                return res.status(413).json({ status: 'PAYLOAD_TOO_LARGE' });
            }
        }

        if (await behavioral.isBlocked(clientIp)) {
            structuredLog('WARN', 'Blocked IP access', { ip: clientIp, path: req.path });
            return res.status(403).json({ status: 'ACCESS_DENIED' });
        }

        let rateLimited;
        try {
            rateLimited = await behavioral.rateLimit(clientIp);
        } catch (error) {
            structuredLog('ERROR', 'Rate limit exception', { error: error.message });
            rateLimited = memoryRateLimit(clientIp);
        }
        if (rateLimited) {
            structuredLog('WARN', 'Rate limit exceeded', { ip: clientIp });
            return res.status(429).json({ status: 'RATE_LIMITED' });
        }

        const target = await resolveAndPinTarget();

        tempFile = createTempFile();
        const spool = new BodySpool(CONFIG.MAX_BODY_SIZE, CONFIG.BODY_SAMPLE_SIZE);
        const fileWriter = fs.createWriteStream(tempFile, { flags: 'wx', mode: 0o600 });

        try {
            await pipelineAsync(req, spool, fileWriter);
        } catch (error) {
            await safeUnlink(tempFile);
            tempFile = null;
            if (error.code === 'PAYLOAD_TOO_LARGE') {
                return res.status(413).json({ status: 'PAYLOAD_TOO_LARGE' });
            }
            if (error.code === 'ECONNRESET') {
                return;
            }
            if (!res.headersSent) {
                return res.status(400).json({ status: 'INVALID_REQUEST_BODY' });
            }
            return;
        }

        const evaluation = await behavioral.evaluate(req, spool.getSample(), spool.totalBytes, sensitive);
        const score = Number(evaluation.totalRiskScore || 0);
        let tier = 'NORMAL';
        if (score >= 60) {
            tier = 'BLOCK';
        } else if (score >= 40) {
            tier = 'HIGH_RISK';
        } else if (score >= 20) {
            tier = 'SUSPICIOUS';
        }

        if (tier === 'BLOCK') {
            await behavioral.blockIp(clientIp);
            await safeUnlink(tempFile);
            tempFile = null;
            structuredLog('ALERT', 'Behavioral block', { ip: clientIp, score, vector: evaluation.vector });
            
            let attackType = 'سلوك مشبوه أو تجاوز معدل الطلبات';
            if (evaluation.vector && evaluation.vector.velocity > 0) {
                attackType = 'هجوم تدفق سريع (Velocity Flood / Brute Force)';
            } else if (evaluation.vector && evaluation.vector.sequence > 0) {
                attackType = 'تخطي تسلسل المسارات (Path Traversal / Sequence Violation)';
            } else if (evaluation.vector && evaluation.vector.content > 0) {
                attackType = 'حمولة عالية الإنتروبيا (High Entropy Payload / Possible Exploit)';
            }

            await sendSecurityAlert(clientIp, score, req.path, attackType);

            return res.status(403).json({ status: 'ACCESS_DENIED' });
        }

        res.setHeader('X-TBP-Risk-Tier', tier);
        res.setHeader('X-TBP-Risk-Score', String(score));

        const headers = buildUpstreamHeaders(req, target, clientIp, spool.totalBytes);
        const isHttps = target.parsed.protocol === 'https:';
        const transport = isHttps ? https : http;
        const upstreamPort = target.parsed.port ? Number(target.parsed.port) : (isHttps ? 443 : 80);
        const upstreamPath = req.url || '/';

        const options = {
            hostname: target.pinnedIp,
            port: upstreamPort,
            method: req.method,
            path: upstreamPath,
            headers,
            timeout: CONFIG.UPSTREAM_TIMEOUT
        };

        if (isHttps) {
            options.servername = target.parsed.hostname;
            options.rejectUnauthorized = true;
        }

        let responseFinished = false;
        const proxyReq = transport.request(options, proxyRes => {
            if (responseFinished) {
                return;
            }
            responseFinished = true;
            const safeHeaders = sanitizeResponseHeaders(proxyRes.headers);
            if (!res.headersSent) {
                res.writeHead(proxyRes.statusCode || 502, safeHeaders);
            }
            proxyRes.pipe(res);
            proxyRes.once('end', async () => {
                await safeUnlink(tempFile);
                tempFile = null;
            });
            proxyRes.once('error', async error => {
                structuredLog('ERROR', 'Upstream response error', { error: error.message });
                await safeUnlink(tempFile);
                tempFile = null;
                if (!res.writableEnded) {
                    res.destroy();
                }
            });
        });

        let upstreamTimedOut = false;
        proxyReq.setTimeout(CONFIG.UPSTREAM_TIMEOUT, () => {
            upstreamTimedOut = true;
            proxyReq.destroy(new Error('UPSTREAM_TIMEOUT'));
        });

        proxyReq.once('error', async error => {
            structuredLog('ERROR', 'Upstream error', { error: error.message, ip: clientIp });
            await safeUnlink(tempFile);
            tempFile = null;
            if (!res.headersSent) {
                return res.status(upstreamTimedOut ? 504 : 502).json({
                    error: upstreamTimedOut ? 'GATEWAY_TIMEOUT' : 'BAD_GATEWAY'
                });
            }
            if (!res.writableEnded) {
                res.destroy();
            }
        });

        const fileReader = fs.createReadStream(tempFile);
        fileReader.once('error', async error => {
            structuredLog('ERROR', 'Temp file read error', { error: error.message });
            proxyReq.destroy(error);
        });

        try {
            await pipelineAsync(fileReader, proxyReq);
        } catch (error) {
            await safeUnlink(tempFile);
            tempFile = null;
            if (!res.headersSent) {
                return res.status(502).json({ error: 'UPSTREAM_WRITE_FAILED' });
            }
            if (!res.writableEnded) {
                res.destroy();
            }
        }
    } catch (error) {
        structuredLog('ERROR', 'Gateway request failure', { error: error.stack || error.message, ip: req.clientIp });
        await safeUnlink(tempFile);
        tempFile = null;
        if (!res.headersSent) {
            return res.status(502).json({ error: 'BAD_GATEWAY' });
        }
        if (!res.writableEnded) {
            res.destroy();
        }
    }
});

async function start() {
    try {
        await redisClient.connect();
        const target = await resolveAndPinTarget();
        structuredLog('INFO', 'Origin resolved', {
            hostname: target.parsed.hostname,
            pinnedIp: target.pinnedIp,
            family: target.family
        });
        server.listen(CONFIG.PORT, () => {
            structuredLog('INFO', 'TBP v14 started', { port: CONFIG.PORT, target: CONFIG.TARGET_SERVER });
        });
    } catch (error) {
        structuredLog('ERROR', 'Fatal startup error', { error: error.stack || error.message });
        try {
            if (redisClient.isOpen) {
                await redisClient.quit();
            }
        } catch {}
        process.exit(1);
    }
}

async function shutdown(signal) {
    if (isShuttingDown) {
        return;
    }
    isShuttingDown = true;
    structuredLog('INFO', 'Graceful shutdown started', { signal, activeRequests });
    const forceTimer = setTimeout(() => {
        structuredLog('ERROR', 'Forced shutdown');
        process.exit(1);
    }, 10_000);
    forceTimer.unref();
    server.close(async () => {
        try {
            if (redisClient.isOpen) {
                await redisClient.quit();
            }
        } catch (error) {
            structuredLog('WARN', 'Redis shutdown error', { error: error.message });
        }
        clearTimeout(forceTimer);
        process.exit(0);
    });
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('uncaughtException', error => {
    structuredLog('ERROR', 'Uncaught exception', { error: error.stack || error.message });
    shutdown('UNCAUGHT_EXCEPTION');
});
process.on('unhandledRejection', reason => {
    structuredLog('ERROR', 'Unhandled rejection', {
        error: reason instanceof Error ? reason.stack : String(reason)
    });
});

// استدعاء دالة البدء للتشغيل الفعلي
start();
