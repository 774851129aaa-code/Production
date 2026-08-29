'use strict';

const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');

require('dotenv').config();

const app = express();

/* =========================================================
   BASIC CONFIG
========================================================= */

app.set('trust proxy', 1);

app.use(
    helmet({
        crossOriginResourcePolicy: false
    })
);

app.use(express.json({ limit: '10kb' }));

app.use(cookieParser());

/* =========================================================
   CORS
========================================================= */

const allowedOrigins = [
    'https://production-1-54qv.onrender.com',
    'https://www.routix.nx.kg',
    'https://routix.nx.kg'
];

app.use(
    cors({
        origin: function (origin, callback) {
            if (!origin || allowedOrigins.includes(origin)) {
                callback(null, true);
            } else {
                callback(new Error('Blocked by CORS policy'));
            }
        },

        credentials: true,

        methods: ['GET', 'POST', 'OPTIONS'],

        allowedHeaders: [
            'Content-Type',
            'Authorization'
        ]
    })
);

/* =========================================================
   RATE LIMITING
========================================================= */

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,

    standardHeaders: true,
    legacyHeaders: false,

    message: {
        success: false,
        message:
            'تم تجاوز الحد المسموح من الطلبات، يرجى المحاولة لاحقاً.'
    }
});

app.use('/api/', limiter);

/* =========================================================
   SECRETS
========================================================= */

const JWT_SECRET =
    process.env.JWT_SECRET ||
    'CHANGE_THIS_SECRET_IN_ENV';

const MONGO_URI =
    process.env.MONGO_URI;

const BREVO_API_KEY =
    process.env.BREVO_API_KEY;

const SENDER_EMAIL =
    process.env.SENDER_EMAIL ||
    'ttbnatlh@gmail.com';

/* =========================================================
   SESSION COOKIE
========================================================= */

const SESSION_COOKIE = 'routix_session';

const SESSION_COOKIE_OPTIONS = {
    httpOnly: true,

    // مطلوب عند استخدام الواجهة وسيرفر المصادقة على نطاقين مختلفين
    sameSite: 'none',

    // مطلوب مع SameSite=None
    secure: true,

    // يمنع إرسال الكوكي مع مسارات غير API
    path: '/',

    // JWT نفسه ينتهي بعد 7 أيام
    maxAge: 7 * 24 * 60 * 60 * 1000
};

/* =========================================================
   MONGODB
========================================================= */

if (!MONGO_URI) {
    console.error('MONGO_URI is missing from environment variables.');
    process.exit(1);
}

mongoose
    .connect(MONGO_URI)
    .then(() => {
        console.log('Connected to MongoDB successfully!');
    })
    .catch((err) => {
        console.error('MongoDB connection error:', err);
        process.exit(1);
    });

/* =========================================================
   OTP SCHEMA
========================================================= */

const otpSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true,
        lowercase: true,
        trim: true,
        index: true
    },

    otp: {
        type: String,
        required: true
    },

    createdAt: {
        type: Date,
        default: Date.now,
        expires: 300
    }
});

const OTPModel = mongoose.model(
    'OTPVerification',
    otpSchema
);

/* =========================================================
   EMAIL VALIDATION
========================================================= */

function normalizeEmail(email) {
    return String(email || '')
        .trim()
        .toLowerCase();
}

function isValidEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

/* =========================================================
   1. SEND OTP
========================================================= */

app.post('/api/send-otp', async (req, res) => {
    try {
        const email = normalizeEmail(req.body.email);

        if (!isValidEmail(email)) {
            return res.status(400).json({
                success: false,
                message: 'البريد الإلكتروني غير صالح أو مطلوب'
            });
        }

        if (!BREVO_API_KEY) {
            console.error(
                'BREVO_API_KEY is missing from environment variables.'
            );

            return res.status(500).json({
                success: false,
                message: 'خدمة البريد غير مهيأة على السيرفر'
            });
        }

        const otpCode = Math.floor(
            100000 + Math.random() * 900000
        ).toString();

        await OTPModel.findOneAndUpdate(
            { email },

            {
                email,
                otp: otpCode,
                createdAt: new Date()
            },

            {
                upsert: true,
                new: true,
                setDefaultsOnInsert: true
            }
        );

        const response = await fetch(
            'https://api.brevo.com/v3/smtp/email',
            {
                method: 'POST',

                headers: {
                    accept: 'application/json',
                    'api-key': BREVO_API_KEY,
                    'content-type': 'application/json'
                },

                body: JSON.stringify({
                    sender: {
                        name: 'Routix Security',
                        email: SENDER_EMAIL
                    },

                    to: [
                        {
                            email
                        }
                    ],

                    subject:
                        'رمز التحقق الأمني الخاص بك',

                    htmlContent: `
                        <div dir="rtl"
                             style="
                                font-family:Tahoma,Arial,sans-serif;
                                padding:20px;
                                color:#333;
                                background:#f9f9f9;
                                border-radius:8px;
                             ">

                            <h2 style="color:#4F46E5;">
                                رمز التحقق الأمني
                            </h2>

                            <p>
                                مرحباً بك في Routix،
                            </p>

                            <p>
                                كود التحقق الخاص بك هو:
                            </p>

                            <h1 style="
                                color:#4F46E5;
                                letter-spacing:6px;
                                background:#fff;
                                padding:10px;
                                display:inline-block;
                                border-radius:5px;
                            ">
                                ${otpCode}
                            </h1>

                            <p>
                                هذا الرمز صالح لمدة 5 دقائق فقط.
                            </p>

                            <p>
                                يرجى عدم مشاركة الرمز مع أي شخص.
                            </p>

                        </div>
                    `
                })
            }
        );

        let data = {};

        try {
            data = await response.json();
        } catch {
            data = {};
        }

        if (!response.ok) {
            console.error(
                'Brevo error:',
                data
            );

            return res.status(400).json({
                success: false,
                message: 'فشل في إرسال البريد'
            });
        }

        return res.json({
            success: true,
            message:
                'تم إرسال كود التحقق بنجاح إلى بريدك'
        });

    } catch (error) {
        console.error(
            'Send OTP Error:',
            error
        );

        return res.status(500).json({
            success: false,
            message: 'خطأ داخلي في الخادم'
        });
    }
});

/* =========================================================
   2. VERIFY OTP + CREATE HTTPONLY SESSION
========================================================= */

app.post('/api/verify-otp', async (req, res) => {
    try {
        const email = normalizeEmail(
            req.body.email
        );

        const otp = String(
            req.body.otp || ''
        ).trim();

        if (!isValidEmail(email) || !otp) {
            return res.status(400).json({
                success: false,
                message:
                    'البريد الإلكتروني وكود التحقق مطلوبان'
            });
        }

        const record =
            await OTPModel.findOne({
                email
            });

        if (!record) {
            return res.status(400).json({
                success: false,
                message:
                    'انتهت صلاحية الكود أو البريد غير صحيح'
            });
        }

        if (record.otp !== otp) {
            return res.status(400).json({
                success: false,
                message:
                    'كود التحقق غير صحيح'
            });
        }

        /* حذف OTP بعد استخدامه */
        await OTPModel.deleteOne({
            _id: record._id
        });

        /* إنشاء JWT */
        const token = jwt.sign(
            {
                email
            },

            JWT_SECRET,

            {
                expiresIn: '7d'
            }
        );

        /*
         * تخزين JWT داخل HttpOnly Cookie
         *
         * JavaScript لن يستطيع الوصول إليها
         * عبر document.cookie
         */
        res.cookie(
            SESSION_COOKIE,
            token,
            SESSION_COOKIE_OPTIONS
        );

        return res.json({
            success: true,

            message:
                'تم التحقق بنجاح وتم إنشاء الجلسة',

            user: {
                email
            }
        });

    } catch (error) {
        console.error(
            'Verify OTP Error:',
            error
        );

        return res.status(500).json({
            success: false,
            message:
                'خطأ داخلي في الخادم'
        });
    }
});

/* =========================================================
   SESSION VERIFICATION
========================================================= */

const verifySession = (
    req,
    res,
    next
) => {

    /*
     * أولاً نبحث عن HttpOnly Cookie
     */
    const cookieToken =
        req.cookies[SESSION_COOKIE];

    /*
     * دعم Authorization بشكل اختياري
     * في حال احتجته لمسارات أخرى
     */
    const authHeader =
        req.headers.authorization;

    const bearerToken =
        authHeader &&
        authHeader.startsWith('Bearer ')
            ? authHeader.slice(7)
            : null;

    const token =
        cookieToken || bearerToken;

    if (!token) {
        return res.status(401).json({
            success: false,
            message:
                'مطلوب تسجيل الدخول'
        });
    }

    jwt.verify(
        token,
        JWT_SECRET,
        (err, user) => {

            if (err) {

                /*
                 * إذا كانت الجلسة منتهية
                 * نحذف الكوكي القديمة
                 */
                res.clearCookie(
                    SESSION_COOKIE,
                    {
                        httpOnly: true,
                        sameSite: 'none',
                        secure: true,
                        path: '/'
                    }
                );

                return res.status(401).json({
                    success: false,
                    message:
                        'انتهت صلاحية الجلسة، يرجى تسجيل الدخول مرة أخرى'
                });
            }

            req.user = user;

            next();
        }
    );
};

/* =========================================================
   3. PROFILE / SESSION CHECK
========================================================= */

app.get(
    '/api/profile',
    verifySession,
    (req, res) => {

        return res.json({
            success: true,

            loggedIn: true,

            message:
                'الجلسة فعالة',

            user: {
                email: req.user.email
            }
        });
    }
);

/* =========================================================
   4. LOGOUT
========================================================= */

app.post(
    '/api/logout',
    (req, res) => {

        res.clearCookie(
            SESSION_COOKIE,
            {
                httpOnly: true,
                sameSite: 'none',
                secure: true,
                path: '/'
            }
        );

        return res.json({
            success: true,
            message:
                'تم تسجيل الخروج بنجاح'
        });
    }
);

/* =========================================================
   HEALTH CHECK
========================================================= */

app.get(
    '/api/health',
    (req, res) => {

        return res.json({
            success: true,
            status: 'online',
            service: 'Routix Authentication'
        });
    }
);

/* =========================================================
   GLOBAL ERROR HANDLER
========================================================= */

app.use(
    (err, req, res, next) => {

        console.error(
            'Server Error:',
            err
        );

        if (
            err &&
            err.message ===
                'Blocked by CORS policy'
        ) {
            return res.status(403).json({
                success: false,
                message:
                    'هذا المصدر غير مسموح له بالاتصال بالسيرفر'
            });
        }

        return res.status(500).json({
            success: false,
            message:
                'خطأ داخلي في الخادم'
        });
    }
);

/* =========================================================
   START SERVER
========================================================= */

const PORT =
    process.env.PORT || 4000;

app.listen(
    PORT,
    () => {
        console.log(
            `Authentication server is running on port ${PORT}`
        );
    }
);
