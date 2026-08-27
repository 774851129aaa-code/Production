require('dotenv').config();
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const app =express();

// التحقق من المتغيرات الأساسية
if (!process.env.TELEGRAM_BOT_TOKEN || !process.env.TELEGRAM_CHAT_ID || !process.env.SITE_API_KEY) {
  console.error('❌ Error: Missing critical environment variables in .env');
  process.exit(1);
}

// إعدادات CORS الآمنة
const allowedOrigins = process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : [];
app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.length === 0 || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS policy'));
    }
  }
}));

app.use(express.json({ limit: '10kb' })); // منع الهجمات عبر تقييد حجم الحزمة

// Rate Limiting لحماية الـ Gateway من الـ Flooding
const limiter = rateLimit({
  windowMs: 60 * 1000, // دقيقة واحدة
  max: 30, // الحد الأقصى 30 طلب لكل IP في الدقيقة
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Rate limit exceeded. Please slow down.' }
});
app.use('/api/v1/telemetry', limiter);

// نظام Deduplication في الذاكرة لمنع تكرار تنبيهات تليجرام خلال 60 ثانية
const alertCache = new Map();

function shouldThrottle(site, eventType, destination) {
  const key = `${site}:${eventType}:${destination}`;
  const now = Date.now();
  if (alertCache.has(key)) {
    const lastSent = alertCache.get(key);
    if (now - lastSent < 60000) {
      return true; // يجب عمل Throttle (منع الإرسال)
    }
  }
  alertCache.set(key, now);
  return false;
}

// تنظيف دوري للذاكرة المؤقتة كل 10 دقائق
setInterval(() => {
  const now = Date.now();
  for (const [key, timestamp] of alertCache.entries()) {
    if (now - timestamp > 120000) alertCache.delete(key);
  }
}, 600000);

// دالة تنقية النصوص ومنع إدخال HTML/JS خبيث في تليجرام
function sanitizeMarkdown(str) {
  if (typeof str !== 'string') return '';
  return str.replace(/[_*[\]()~`>#+\-=|{}.!]/g, '\\$&');
}

// مسار استقبال الـ Telemetry وإرسال التنبيه إلى تليجرام
app.post('/api/v1/telemetry', async (req, res) => {
  try {
    const apiKey = req.headers['x-site-key'];
    if (!apiKey || apiKey !== process.env.SITE_API_KEY) {
      return res.status(401).json({ error: 'Unauthorized: Invalid Site API Key' });
    }

    const { site, event, destination, risk, mode, time } = req.body;

    if (!site || !event || typeof risk !== 'number') {
      return res.status(400).json({ error: 'Invalid payload structure' });
    }

    // تطبيق الـ Deduplication
    if (shouldThrottle(site, event, destination)) {
      return res.status(200).json({ status: 'throttled', message: 'Alert suppressed due to deduplication rule.' });
    }

    // صياغة رسالة تليجرام الاحترافية والآمنة
    const telegramMessage = 
      `🚨 *TBP SECURITY ALERT*\n\n` +
      `*Site:*\n\`${sanitizeMarkdown(site)}\`\n\n` +
      `*Event:*\n\`${sanitizeMarkdown(event)}\`\n\n` +
      `*Source/Destination:*\n\`${sanitizeMarkdown(String(destination || 'N/A'))}\`\n\n` +
      `*Risk:*\n\`${risk}/100\`\n\n` +
      `*Mode:*\n\`${sanitizeMarkdown(mode || 'PROTECTION')}\`\n\n` +
      `*Time:*\n\`${sanitizeMarkdown(time || new Date().toISOString())}\``;

    const tgUrl = `https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/sendMessage`;
    
    const tgResponse = await fetch(tgUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: process.env.TELEGRAM_CHAT_ID,
        text: telegramMessage,
        parse_mode: 'Markdown'
      })
    });

    if (!tgResponse.ok) {
      throw new Error(`Telegram API responded with status ${tgResponse.status}`);
    }

    return res.status(200).json({ status: 'success', delivered: true });
  } catch (err) {
    console.error('Gateway Error:', err.message);
    return res.status(500).json({ error: 'Internal gateway processing error' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🛡️ TBP Secure Gateway running on port ${PORT}`);
});
