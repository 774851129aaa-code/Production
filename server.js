'use strict';

const express = require('express');
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const dns = require('dns').promises;
const net = require('net');
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
    ORIGIN_SECRET_TOKEN: process.env.ORIGIN_SECRET_TOKEN || 'k9X#mP2$vL9_qR5!wZ8*yF3@bN6%dT1',
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
    MAX_MEMORY_RATE_LIMIT_ENTRIES: 10_000
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
    if (!net.isIPv4(ip)) return null;
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4 || parts.some(x => !Number.isInteger(x) || x < 0 || x > 255)) return null;
    return parts;
}

function ipv4ToBigInt(ip) {
    const parts = normalizeIPv4(ip);
    if (!parts) throw new Error('Invalid IPv4.');
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
        if (lastColon === -1) throw new Error('Invalid IPv6.');
        const ipv4 = address.slice(lastColon + 1);
        if (!net.isIPv4(ipv4)) throw new Error('Invalid embedded IPv4.');
        const value = ipv4ToBigInt(ipv4);
        const high = Number((value >> 16n) & 0xffffn).toString(16);
        const low = Number(value & 0xffffn).toString(16);
        address = address.slice(0, lastColon + 1) + high + ':' + low;
    }
    const sections = address.split('::');
    if (sections.length > 2) throw new Error('Invalid IPv6.');
    const left = sections[0] ? sections[0].split(':').filter(Boolean) : [];
    const right = sections[1] ? sections[1].split(':').filter(Boolean) : [];
    const missing = 8 - left.length - right.length;
    if (missing < 0) throw new Error('Invalid IPv6.');
    const groups = sections.length === 1 ? [...left] : [...left, ...new Array(missing).fill('0'), ...right];
    if (groups.length !== 8) throw new Error('Invalid IPv6.');
    return groups.map(group => {
        const value = parseInt(group, 16);
        if (!Number.isInteger(value) || value < 0 || value > 0xffff) throw new Error('Invalid IPv6 group.');
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
    if (net.isIPv4(ip)) return { family: 4, value: ipv4ToBigInt(ip) };
    if (net.isIPv6(ip)) return { family: 6, value: ipv6ToBigInt(ip) };
    throw new Error(`Invalid IP: ${ip}`);
}

function getIPv4MappedAddress(ip) {
    if (!net.isIPv6(ip)) return null;
    try {
        const groups = expandIPv6(ip);
        const mapped = groups[0] === 0 && groups[1] === 0 && groups[2] === 0 && groups[3] === 0 && groups[4] === 0 && groups[5] === 0xffff;
        if (!mapped) return null;
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
        if (mappedIp) ipInfo = ipToBigInt(mappedIp);
        if (mappedNetwork) networkInfo = ipToBigInt(mappedNetwork);
        if (ipInfo.family !== networkInfo.family) return false;
        const totalBits = ipInfo.family === 4 ? 32 : 128;
        const bits = bitsString === undefined ? totalBits : Number(bitsString);
        if (!Number.isInteger(bits) || bits < 0 || bits > totalBits) return false;
        if (bits === 0) return true;
        const shift = BigInt(totalBits - bits);
        return (ipInfo.value >> shift) === (networkInfo.value >> shift);
    } catch {
        return false;
    }
}

const BLOCKED_CIDRS = [
    '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
    '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24',
    '192.168.0.0/16', '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24',
    '224.0.0.0/4', '240.0.0.0/4', '::/128', '::1/128', 'fc00::/7',
    'fe80::/10', 'ff00::/8', '2001:db8::/32'
];

function isRestrictedIp(ip) {
    const mapped = getIPv4MappedAddress(ip);
    const candidate = mapped || ip;
    return BLOCKED_CIDRS.some(cidr => isIpInCidr(candidate, cidr));
}

const dnsCacheMap = new Map();

async function resolveAndPinTarget(targetUrl) {
    const now = Date.now();
    const cached = dnsCacheMap.get(targetUrl);
    if (cached && now - cached.timestamp < CONFIG.DNS_CACHE_TTL) {
        return cached.value;
    }
    const parsed = new URL(targetUrl);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        throw new Error('Target must use HTTP or HTTPS.');
    }
    const hostname = parsed.hostname;
    if (!hostname) throw new Error('Target hostname is missing.');

    if (net.isIP(hostname)) {
        if (isRestrictedIp(hostname)) throw new Error(`Restricted target IP: ${hostname}`);
        const result = { parsed, pinnedIp: hostname, family: net.isIPv6(hostname) ? 6 : 4 };
        dnsCacheMap.set(targetUrl, { timestamp: now, value: result });
        return result;
    }

    const [ipv4, ipv6] = await Promise.all([
        dns.resolve4(hostname).catch(() => []),
        dns.resolve6(hostname).catch(() => [])
    ]);
    const addresses = [...ipv4, ...ipv6];
    if (addresses.length === 0) throw new Error(`DNS resolution failed: ${hostname}`);
    for (const address of addresses) {
        if (isRestrictedIp(address)) throw new Error(`DNS resolved to restricted IP: ${address}`);
    }
    const pinnedIp = ipv4[0] || ipv6[0];
    const result = { parsed, pinnedIp, family: net.isIPv6(pinnedIp) ? 6 : 4 };
    dnsCacheMap.set(targetUrl, { timestamp: now, value: result });
    return result;
}

const DB_FILE = path.join(os.tmpdir(), 'tbp_database.json');

function loadJsonDb() {
    try {
        if (fs.existsSync(DB_FILE)) {
            return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
        }
    } catch (error) {
        structuredLog('ERROR', 'Failed to load JSON DB', { error: error.message });
    }
    return { blocks: {}, profiles: {}, baselines: {}, stats: { total: 0, blocked: 0, suspicious: 0 } };
}

function saveJsonDb(db) {
    try {
        fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2), 'utf8');
    } catch (error) {
        structuredLog('ERROR', 'Failed to save JSON DB', { error: error.message });
    }
}

const memoryRateLimits = new Map();

function memoryRateLimit(ip) {
    const now = Date.now();
    let record = memoryRateLimits.get(ip);
    if (!record || now >= record.reset) {
        if (memoryRateLimits.size >= CONFIG.MAX_MEMORY_RATE_LIMIT_ENTRIES) {
            const firstKey = memoryRateLimits.keys().next().value;
            if (firstKey) memoryRateLimits.delete(firstKey);
        }
        record = { count: 0, reset: now + CONFIG.RATE_LIMIT_WINDOW * 1000 };
        memoryRateLimits.set(ip, record);
    }
    record.count++;
    return (record.count > CONFIG.RATE_LIMIT_MAX);
}

function normalizeRoutePath(input) {
    return String(input || '/')
        .replace(/\/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?=\/|$)/g, '/:id')
        .replace(/\/\d+(?=\/|$)/g, '/:id');
}

function calculateEntropy(buffer) {
    if (!buffer || buffer.length === 0) return 0;
    const frequencies = new Array(256).fill(0);
    for (const byte of buffer) frequencies[byte]++;
    let entropy = 0;
    for (const frequency of frequencies) {
        if (frequency === 0) continue;
        const probability = frequency / buffer.length;
        entropy -= probability * Math.log2(probability);
    }
    return entropy;
}

class BehavioralEngineJson {
    profileKey(req) {
        const material = [
            req.clientIp,
            req.headers['user-agent'] || '',
            req.headers['accept-language'] || ''
        ].join('|');
        return crypto.createHash('sha256').update(material).digest('hex').slice(0, 32);
    }

    isBlocked(ip) {
        const db = loadJsonDb();
        const blockUntil = db.blocks[ip];
        if (blockUntil && Date.now() < blockUntil) return true;
        if (blockUntil && Date.now() >= blockUntil) {
            delete db.blocks[ip];
            saveJsonDb(db);
        }
        return false;
    }

    blockIp(ip) {
        const db = loadJsonDb();
        db.blocks[ip] = Date.now() + CONFIG.BLOCK_DURATION;
        saveJsonDb(db);
    }

    rateLimit(ip) {
        return memoryRateLimit(ip);
    }

    evaluate(req, sample, totalLength, sensitive) {
        const db = loadJsonDb();
        const key = this.profileKey(req);
        const normalized = normalizeRoutePath(req.path);
        const route = `${req.method} ${normalized}`;
        const now = Date.now();

        let profile = db.profiles[key] || {
            lastRequestTime: now,
            requestIntervals: [],
            lastEndpoint: false,
            endpointsVisited: {},
            transitionMatrix: {},
            totalRequests: 0,
            stage: 'QUARANTINE'
        };

        let baseline = db.baselines[key] || {
            established: false,
            baselineTransitions: {},
            baselineMeanInterval: 0,
            baselineStdDev: 0,
            confidenceScore: 0
        };

        const interval = Math.max(0, now - profile.lastRequestTime);
        profile.lastRequestTime = now;
        profile.totalRequests = (profile.totalRequests || 0) + 1;
        db.stats.total = (db.stats.total || 0) + 1;

        profile.requestIntervals.push(interval);
        if (profile.requestIntervals.length > 50) profile.requestIntervals.shift();

        if (!baseline.established) {
            if (profile.endpointsVisited[normalized]) {
                profile.endpointsVisited[normalized]++;
            } else if (Object.keys(profile.endpointsVisited).length < 50) {
                profile.endpointsVisited[normalized] = 1;
            }

            if (profile.lastEndpoint) {
                if (!profile.transitionMatrix[profile.lastEndpoint]) {
                    profile.transitionMatrix[profile.lastEndpoint] = {};
                }
                const transition = `${profile.lastEndpoint} => ${route}`;
                profile.transitionMatrix[profile.lastEndpoint][transition] = (profile.transitionMatrix[profile.lastEndpoint][transition] || 0) + 1;
            }
            profile.lastEndpoint = route;

            const sum = profile.requestIntervals.reduce((a, b) => a + b, 0);
            const mean = profile.requestIntervals.length ? sum / profile.requestIntervals.length : 1;
            const varianceSum = profile.requestIntervals.reduce((acc, val) => acc + Math.pow(val - mean, 2), 0);
            const stdDev = profile.requestIntervals.length > 1 ? Math.sqrt(varianceSum / profile.requestIntervals.length) : 0;

            const coefficient = mean > 0 ? stdDev / mean : 1;
            const timingFactor = Math.max(0, 1 - Math.min(1, coefficient / 2));
            const diversityFactor = Math.min(1, Object.keys(profile.endpointsVisited).length / 10);
            const confidence = (timingFactor * 0.5) + (diversityFactor * 0.5);

            if (profile.totalRequests >= CONFIG.LEARNING_PHASE_REQUESTS && confidence >= CONFIG.CONFIDENCE_THRESHOLD) {
                baseline.established = true;
                baseline.baselineTransitions = profile.transitionMatrix;
                baseline.baselineMeanInterval = mean;
                baseline.baselineStdDev = stdDev;
                baseline.confidenceScore = confidence;
                db.baselines[key] = baseline;
                profile.stage = 'PROTECTING';
            } else {
                profile.stage = 'QUARANTINE';
            }

            db.profiles[key] = profile;
            saveJsonDb(db);
            return { totalRiskScore: 0, vector: { stage: profile.stage, confidence } };
        }

        let velocity = 0;
        if (baseline.baselineStdDev > 0.1) {
            const z = Math.abs((interval - baseline.baselineMeanInterval) / baseline.baselineStdDev);
            if (z > 4.0 && interval < 10) velocity = 30;
        }

        let sequence = 0;
        if (profile.lastEndpoint && baseline.baselineTransitions[profile.lastEndpoint]) {
            const transition = `${profile.lastEndpoint} => ${route}`;
            if (!baseline.baselineTransitions[profile.lastEndpoint][transition]) {
                sequence = 35;
            }
        }
        profile.lastEndpoint = route;

        let content = 0;
        const entropy = calculateEntropy(sample);
        if (entropy > 7.6 && sensitive && totalLength > 1024) {
            content = 15;
        }

        const risk = velocity + sequence + content;
        if (risk >= 60) {
            profile.stage = 'ESCALATED';
            db.stats.blocked = (db.stats.blocked || 0) + 1;
        } else if (risk >= 40) {
            profile.stage = 'HIGH_RISK';
            db.stats.suspicious = (db.stats.suspicious || 0) + 1;
        } else if (risk >= 20) {
            profile.stage = 'SUSPICIOUS';
        } else {
            profile.stage = 'PROTECTING';
        }

        db.profiles[key] = profile;
        saveJsonDb(db);

        return {
            totalRiskScore: risk,
            vector: { stage: profile.stage, velocity, sequence, content }
        };
    }
}

const behavioral = new BehavioralEngineJson();

function getClientIp(req) {
    return req.ip || req.socket.remoteAddress || '0.0.0.0';
}

const HOP_BY_HOP_HEADERS = new Set([
    'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
    'te', 'trailer', 'transfer-encoding', 'upgrade', 'host'
]);

function getConnectionHeaderTokens(headers) {
    const value = headers.connection;
    if (!value) return new Set();
    const values = Array.isArray(value) ? value : [value];
    const tokens = new Set();
    for (const item of values) {
        String(item).split(',').map(x => x.trim().toLowerCase()).filter(Boolean).forEach(x => tokens.add(x));
    }
    return tokens;
}

function isUnsafeForwardHeader(name, connectionTokens) {
    const lower = name.toLowerCase();
    return HOP_BY_HOP_HEADERS.has(lower) || connectionTokens.has(lower) || lower.startsWith('proxy-') ||
        lower.startsWith('x-forwarded-') || lower === 'x-tbp-origin-secret';
}

function buildUpstreamHeaders(req, target, clientIp, bodyLength) {
    const headers = {};
    const connectionTokens = getConnectionHeaderTokens(req.headers);
    for (const [key, value] of Object.entries(req.headers)) {
        if (isUnsafeForwardHeader(key, connectionTokens)) continue;
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
        if (HOP_BY_HOP_HEADERS.has(lower) || connectionTokens.has(lower) || lower.startsWith('proxy-')) continue;
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
        storage: 'JSON_LOCAL_FILE',
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
            if (!Buffer.isBuffer(chunk)) chunk = Buffer.from(chunk, encoding);
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
    if (!file) return;
    try {
        await fs.promises.unlink(file);
    } catch (error) {
        if (error.code !== 'ENOENT') {
            structuredLog('WARN', 'Temp file cleanup failed', { error: error.message });
        }
    }
}

// تعديل المسار ليكون البروكسي ديناميكياً بناءً على الرابط الذي يرسله المستخدم (عبر Query Param مثل ?target=...)
app.use(async (req, res) => {
    // تجاهل طلبات الصحة والـ metrics الخاصة بالبروكسي نفسه
    if (req.path.startsWith('/_tbp/')) {
        return res.status(404).json({ error: 'NOT_FOUND' });
    }

    // استخراج الرابط المستهدف من طلب المستخدم (مثال: ?target=https://example.com أو عبر Header)
    const targetUrl = req.query.target || req.headers['x-target-url'];
    if (!targetUrl) {
        return res.status(400).json({ 
            error: 'MISSING_TARGET', 
            message: 'Please provide the target URL using ?target=https://your-website.com query parameter.' 
        });
    }

    if (activeRequests >= CONFIG.MAX_CONCURRENT_REQUESTS) {
        return res.status(503).json({ status: 'SERVER_BUSY' });
    }
    activeRequests++;
    let released = false;
    const release = () => {
        if (released) return;
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

        if (behavioral.isBlocked(clientIp)) {
            structuredLog('WARN', 'Blocked IP access', { ip: clientIp, path: req.path });
            return res.status(403).json({ status: 'ACCESS_DENIED' });
        }

        if (behavioral.rateLimit(clientIp)) {
            structuredLog('WARN', 'Rate limit exceeded', { ip: clientIp });
            return res.status(429).json({ status: 'RATE_LIMITED' });
        }

        // تحليل وفحص الرابط الديناميكي المدخل من المستخدم
        const target = await resolveAndPinTarget(targetUrl);

        tempFile = createTempFile();
        const spool = new BodySpool(CONFIG.MAX_BODY_SIZE, CONFIG.BODY_SAMPLE_SIZE);
        const fileWriter = fs.createWriteStream(tempFile, { flags: 'wx', mode: 0o600 });

        try {
            await pipelineAsync(req, spool, fileWriter);
        } catch (error) {
            await safeUnlink(tempFile);
            tempFile = null;
            if (error.code === 'PAYLOAD_TOO_LARGE') return res.status(413).json({ status: 'PAYLOAD_TOO_LARGE' });
            if (error.code === 'ECONNRESET') return;
            if (!res.headersSent) return res.status(400).json({ status: 'INVALID_REQUEST_BODY' });
            return;
        }

        const evaluation = behavioral.evaluate(req, spool.getSample(), spool.totalBytes, sensitive);
        const score = Number(evaluation.totalRiskScore || 0);
        let tier = 'NORMAL';
        if (score >= 60) tier = 'BLOCK';
        else if (score >= 40) tier = 'HIGH_RISK';
        else if (score >= 20) tier = 'SUSPICIOUS';

        if (tier === 'BLOCK') {
            behavioral.blockIp(clientIp);
            await safeUnlink(tempFile);
            tempFile = null;
            structuredLog('ALERT', 'Behavioral block', { ip: clientIp, score, vector: evaluation.vector });
            
            let attackType = 'سلوك مشبوه أو تجاوز معدل الطلبات';
            if (evaluation.vector?.velocity > 0) attackType = 'هجوم تدفق سريع (Velocity Flood / Brute Force)';
            else if (evaluation.vector?.sequence > 0) attackType = 'تخطي تسلسل المسارات (Path Traversal / Sequence Violation)';
            else if (evaluation.vector?.content > 0) attackType = 'حمولة عالية الإنتروبيا (High Entropy Payload / Possible Exploit)';

            await sendSecurityAlert(clientIp, score, req.path, attackType);
            return res.status(403).json({ status: 'ACCESS_DENIED' });
        }

        res.setHeader('X-TBP-Risk-Tier', tier);
        res.setHeader('X-TBP-Risk-Score', String(score));

        const headers = buildUpstreamHeaders(req, target, clientIp, spool.totalBytes);
        const isHttps = target.parsed.protocol === 'https:';
        const transport = isHttps ? https : http;
        const upstreamPort = target.parsed.port ? Number(target.parsed.port) : (isHttps ? 443 : 80);
        
        // الحفاظ على المسار الأصلي وباراميترات البحث ما عدا باراميتر الـ target نفسه لكي لا يذهب للسيرفر المستهدف
        const originalUrlObj = new URL(req.url, `http://${req.headers.host}`);
        originalUrlObj.searchParams.delete('target');
        const upstreamPath = originalUrlObj.pathname + originalUrlObj.search;

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
            if (responseFinished) return;
            responseFinished = true;
            const safeHeaders = sanitizeResponseHeaders(proxyRes.headers);
            if (!res.headersSent) {
                res.writeHead(proxyRes.statusCode || 502, safeHeaders);
            }
            proxyRes.pipe(res);
            proxyRes.once('end', async () => { await safeUnlink(tempFile); tempFile = null; });
            proxyRes.once('error', async error => {
                structuredLog('ERROR', 'Upstream response error', { error: error.message });
                await safeUnlink(tempFile);
                tempFile = null;
                if (!res.writableEnded) res.destroy();
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
            if (!res.writableEnded) res.destroy();
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
            if (!res.headersSent) return res.status(502).json({ error: 'UPSTREAM_WRITE_FAILED' });
            if (!res.writableEnded) res.destroy();
        }
    } catch (error) {
        structuredLog('ERROR', 'Gateway request failure', { error: error.stack || error.message, ip: req.clientIp });
        await safeUnlink(tempFile);
        tempFile = null;
        if (!res.headersSent) return res.status(502).json({ error: 'BAD_GATEWAY' });
        if (!res.writableEnded) res.destroy();
    }
});

server.listen(CONFIG.PORT, () => {
    structuredLog('INFO', 'Dynamic TBP v14 started', { port: CONFIG.PORT });
});

async function shutdown(signal) {
    if (isShuttingDown) return;
    isShuttingDown = true;
    structuredLog('INFO', 'Graceful shutdown started', { signal, activeRequests });
    const forceTimer = setTimeout(() => {
        structuredLog('ERROR', 'Forced shutdown');
        process.exit(1);
    }, 10_000);
    forceTimer.unref();
    server.close(() => {
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
