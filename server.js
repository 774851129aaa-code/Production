const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();

// إعدادات الحماية والأمان
app.use(helmet());
app.use(express.json({ limit: '10kb' }));

// السماح بالاتصال من دوميناتك المحددة حصراً لتأمين السيرفر
const allowedOrigins = [
    'https://production-1-54qv.onrender.com',
    'https://www.routix.nx.kg',
    'https://routix.nx.kg'
];

app.use(cors({
    origin: function (origin, callback) {
        if (!origin || allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            callback(new Error('Blocked by CORS policy'));
        }
    },
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// حماية مسارات الـ API من هجمات السبام وحرق الأكواد
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 دقيقة
    max: 20, 
    message: { success: false, message: 'تم تجاوز الحد المسموح من الطلبات، يرجى المحاولة لاحقاً.' }
});
app.use('/api/', limiter);

// الثوابت والبيانات السرية
const JWT_SECRET = process.env.JWT_SECRET || 'your_super_secret_jwt_key_here';
const MONGO_URI = 'mongodb+srv://ttbnatlh_db_user:b1VNQiNMi9ia9v26@cluster0.kwx1wfr.mongodb.net/otp_database?retryWrites=true&w=majority&appName=Cluster0';
const BREVO_API_KEY = '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';
const SENDER_EMAIL = 'ttbnatlh@gmail.com';

// الاتصال بقاعدة البيانات MongoDB Atlas
mongoose.connect(MONGO_URI)
    .then(() => console.log('Connected to MongoDB successfully!'))
    .catch((err) => {
        console.error('MongoDB connection error:', err);
        process.exit(1);
    });

// تصميم جدول حفظ الأكواد مع الحذف التلقائي بعد 5 دقائق
const otpSchema = new mongoose.Schema({
    email: { type: String, required: true, lowercase: true, trim: true, index: true },
    otp: { type: String, required: true },
    createdAt: { type: Date, default: Date.now, expires: 300 }
});

const OTPModel = mongoose.model('OTPVerification', otpSchema);

// 1. مسار إرسال كود التحقق (OTP)
app.post('/api/send-otp', async (req, res) => {
    try {
        const { email } = req.body;

        if (!email || !email.includes('@')) {
            return res.status(400).json({ success: false, message: 'البريد الإلكتروني غير صالح أو مطلوب' });
        }

        const otpCode = Math.floor(100000 + Math.random() * 900000).toString();

        await OTPModel.findOneAndUpdate(
            { email: email },
            { otp: otpCode, createdAt: Date.now() },
            { upsert: true, new: true }
        );

        const response = await fetch('https://api.brevo.com/v3/smtp/email', {
            method: 'POST',
            headers: {
                'accept': 'application/json',
                'api-key': BREVO_API_KEY,
                'content-type': 'application/json'
            },
            body: JSON.stringify({
                sender: { name: "Routix Security", email: SENDER_EMAIL },
                to: [{ email: email }],
                subject: "رمز التحقق الأمني الخاص بك",
                htmlContent: `
                    <div dir="rtl" style="font-family: Tahoma, sans-serif; padding: 20px; color: #333; background: #f9f9f9; border-radius: 8px;">
                        <h2 style="color: #4F46E5;">رمز التحقق الأمني</h2>
                        <p>مرحباً بك،</p>
                        <p>كود التحقق الخاص بك هو:</p>
                        <h1 style="color: #4F46E5; letter-spacing: 6px; background: #fff; padding: 10px; display: inline-block; border-radius: 5px;">${otpCode}</h1>
                        <p>هذا الرمز صالح لمدة 5 دقائق فقط، يرجى عدم مشاركته مع أي شخص.</p>
                    </div>
                `
            })
        });

        const data = await response.json();

        if (response.ok) {
            return res.json({ success: true, message: 'تم إرسال كود التحقق بنجاح إلى بريدك' });
        } else {
            return res.status(400).json({ success: false, message: 'فشل في إرسال البريد', error: data });
        }
    } catch (error) {
        console.error('Send OTP Error:', error);
        return res.status(500).json({ success: false, message: 'خطأ داخلي في الخادم' });
    }
});

// 2. مسار التحقق من الكود وإصدار جلسة فريدة (JWT)
app.post('/api/verify-otp', async (req, res) => {
    try {
        const { email, otp } = req.body;

        if (!email || !otp) {
            return res.status(400).json({ success: false, message: 'البريد الإلكتروني وكود التحقق مطلوبان' });
        }

    const record = await OTPModel.findOne({ email });

        if (!record) {
            return res.status(400).json({ success: false, message: 'انتهت صلاحية الكود أو البريد غير صحيح' });
        }

        if (record.otp === otp) {
            await OTPModel.deleteOne({ email });

            const token = jwt.sign({ email: email }, JWT_SECRET, { expiresIn: '7d' });

            return res.json({ 
                success: true, 
                message: 'تم التحقق بنجاح وتم إنشاء الجلسة الفريدة!', 
                token 
            });
        } else {
            return res.status(400).json({ success: false, message: 'كود التحقق غير صحيح' });
        }
    } catch (error) {
        console.error('Verify OTP Error:', error);
        return res.status(500).json({ success: false, message: 'خطأ داخلي في الخادم' });
    }
});

// 3. التحقق من الجلسة للمسارات المحمية
const verifySession = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ success: false, message: 'مطلوب تسجيل الدخول، التوكن غير موجود' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ success: false, message: 'انتهت صلاحية الجلسة، يرجى إعادة تسجيل الدخول' });
        }
        req.user = user;
        next();
    });
};

app.get('/api/profile', verifySession, (req, res) => {
    res.json({ 
        success: true, 
        message: 'أهلاً بك في لوحتك المحمية', 
        email: req.user.email 
    });
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
    console.log(`Server is running smoothly on port ${PORT}`);
});
