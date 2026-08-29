'use strict';

const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const crypto = require('crypto');
const argon2 = require('argon2');
const cookieParser = require('cookie-parser');
require('dotenv').config();

/* =========================================================
   APP
========================================================= */

const app = express();

/* =========================================================
   CONFIG
========================================================= */

const PORT =
    Number(process.env.PORT || 4000);

const MONGO_URI =
    process.env.MONGO_URI;

const BREVO_API_KEY =
    process.env.BREVO_API_KEY;

const SENDER_EMAIL =
    process.env.SENDER_EMAIL;

const SENDER_NAME =
    process.env.SENDER_NAME || 'Routix';

const SESSION_SECRET =
    process.env.SESSION_SECRET;

const NODE_ENV =
    process.env.NODE_ENV || 'development';

const IS_PRODUCTION =
    NODE_ENV === 'production';

const SESSION_TTL_DAYS =
    Number(
        process.env.SESSION_TTL_DAYS || 7
    );

const SESSION_TTL_MS =
    SESSION_TTL_DAYS *
    24 *
    60 *
    60 *
    1000;

/* =========================================================
   FRONTEND DOMAINS
========================================================= */

const FRONTEND_ORIGINS = [
    'https://www.routix.nx.kg',
    'https://routix.nx.kg'
];

/*
 * أثناء التطوير فقط نسمح بـ localhost.
 *
 * في الإنتاج لا يتم السماح به.
 */

if (!IS_PRODUCTION) {
    FRONTEND_ORIGINS.push(
        'http://localhost:3000',
        'http://127.0.0.1:3000'
    );
}

/* =========================================================
   SECURITY CONFIG
========================================================= */

const OTP_EXPIRES_MS =
    5 * 60 * 1000;

const RESEND_COOLDOWN_MS =
    60 * 1000;

const MAX_OTP_ATTEMPTS =
    5;

const OTP_LENGTH =
    6;

/* =========================================================
   BASIC CONFIG CHECK
========================================================= */

if (!MONGO_URI) {
    console.error(
        'ERROR: MONGO_URI is missing.'
    );

    process.exit(1);
}

if (!BREVO_API_KEY) {
    console.error(
        'ERROR: BREVO_API_KEY is missing.'
    );

    process.exit(1);
}

if (!SENDER_EMAIL) {
    console.error(
        'ERROR: SENDER_EMAIL is missing.'
    );

    process.exit(1);
}

if (
    !SESSION_SECRET ||
    SESSION_SECRET.length < 32
) {
    console.error(
        'ERROR: SESSION_SECRET must be at least 32 characters.'
    );

    process.exit(1);
}

/* =========================================================
   TRUST PROXY
========================================================= */

if (IS_PRODUCTION) {
    app.set(
        'trust proxy',
        1
    );
}

/* =========================================================
   MIDDLEWARE
========================================================= */

app.use(
    express.json({
        limit: '20kb'
    })
);

app.use(
    express.urlencoded({
        extended: false,
        limit: '20kb'
    })
);

app.use(
    cookieParser()
);

/* =========================================================
   CORS
========================================================= */

app.use(
    cors({
        origin: function (
            origin,
            callback
        ) {

            /*
             * بعض الطلبات لا تحتوي Origin.
             * نسمح بها مثل الطلبات الداخلية أو أدوات
             * الفحص المباشر للسيرفر.
             */

            if (!origin) {
                return callback(
                    null,
                    true
                );
            }

            /*
             * السماح فقط بالدومينات المحددة.
             */

            if (
                FRONTEND_ORIGINS.includes(
                    origin
                )
            ) {
                return callback(
                    null,
                    true
                );
            }

            console.warn(
                `Blocked CORS origin: ${origin}`
            );

            return callback(
                new Error(
                    'CORS origin not allowed'
                )
            );
        },

        /*
         * مهم جدًا للجلسات والكوكيز.
         */

        credentials: true,

        methods: [
            'GET',
            'POST',
            'OPTIONS'
        ],

        allowedHeaders: [
            'Content-Type'
        ],

        optionsSuccessStatus: 204
    })
);

/* =========================================================
   HELPERS
========================================================= */

function normalizeEmail(value) {

    if (
        typeof value !== 'string'
    ) {
        return '';
    }

    return value
        .trim()
        .toLowerCase();
}

function isValidEmail(email) {

    if (!email) {
        return false;
    }

    if (email.length > 254) {
        return false;
    }

    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(
        email
    );
}

function isValidPassword(password) {

    if (
        typeof password !== 'string'
    ) {
        return false;
    }

    return (
        password.length >= 8 &&
        password.length <= 128
    );
}

function generateOTP() {

    return crypto
        .randomInt(
            100000,
            1000000
        )
        .toString();
}

function generateRandomToken(
    bytes = 32
) {

    return crypto
        .randomBytes(bytes)
        .toString('hex');
}

function hashToken(token) {

    return crypto
        .createHmac(
            'sha256',
            SESSION_SECRET
        )
        .update(token)
        .digest('hex');
}

function timingSafeStringEqual(
    a,
    b
) {

    if (
        typeof a !== 'string' ||
        typeof b !== 'string'
    ) {
        return false;
    }

    if (
        a.length !== b.length
    ) {
        return false;
    }

    return crypto.timingSafeEqual(
        Buffer.from(a),
        Buffer.from(b)
    );
}

function getSessionExpiration() {

    return new Date(
        Date.now() +
        SESSION_TTL_MS
    );
}

/* =========================================================
   COOKIE
========================================================= */

const SESSION_COOKIE_NAME =
    'routix_session';

/*
 * في الإنتاج:
 *
 * secure: true
 * sameSite: none
 *
 * حتى يتم إرسال Cookie بين:
 *
 * https://www.routix.nx.kg
 *
 * و:
 *
 * https://production-1-54qv.onrender.com
 *
 * أما في التطوير المحلي فنستخدم:
 *
 * secure: false
 * sameSite: lax
 */

const SESSION_COOKIE_OPTIONS = {

    httpOnly: true,

    secure:
        IS_PRODUCTION,

    sameSite:
        IS_PRODUCTION
            ? 'none'
            : 'lax',

    path: '/',

    maxAge:
        SESSION_TTL_MS
};

/* =========================================================
   DATABASE SCHEMAS
========================================================= */

/* =========================================================
   USERS
========================================================= */

const userSchema =
    new mongoose.Schema(
        {
            email: {
                type: String,
                required: true,
                unique: true,
                index: true,
                lowercase: true,
                trim: true,
                maxlength: 254
            },

            passwordHash: {
                type: String,
                required: true
            },

            apiTokenHash: {
                type: String,
                required: true
            },

            verifiedAt: {
                type: Date,
                required: true
            }
        },
        {
            timestamps: true
        }
    );

/* =========================================================
   SESSIONS
========================================================= */

const sessionSchema =
    new mongoose.Schema(
        {
            userId: {
                type:
                    mongoose.Schema.Types.ObjectId,

                ref: 'User',

                required: true,

                index: true
            },

            sessionTokenHash: {
                type: String,

                required: true,

                unique: true,

                index: true
            },

            expiresAt: {
                type: Date,

                required: true,

                index: true
            },

            createdAt: {
                type: Date,

                default: Date.now
            },

            lastUsedAt: {
                type: Date,

                default: Date.now
            }
        }
    );

/*
 * MongoDB يحذف الجلسة تلقائيًا
 * عند الوصول إلى expiresAt.
 */

sessionSchema.index(
    {
        expiresAt: 1
    },
    {
        expireAfterSeconds: 0
    }
);

/* =========================================================
   OTP VERIFICATION
========================================================= */

const otpSchema =
    new mongoose.Schema(
        {
            email: {
                type: String,

                required: true,

                unique: true,

                index: true,

                lowercase: true,

                trim: true,

                maxlength: 254
            },

            otpHash: {
                type: String,

                required: true
            },

            passwordHash: {
                type: String,

                required: true
            },

            attempts: {
                type: Number,

                default: 0,

                min: 0,

                max:
                    MAX_OTP_ATTEMPTS
            },

            createdAt: {
                type: Date,

                default: Date.now
            },

            lastSentAt: {
                type: Date,

                default: Date.now
            }
        },
        {
            timestamps: true
        }
    );

/*
 * OTP ينتهي تلقائيًا بعد 5 دقائق.
 */

otpSchema.index(
    {
        createdAt: 1
    },
    {
        expireAfterSeconds: 300
    }
);

const User =
    mongoose.model(
        'User',
        userSchema
    );

const Session =
    mongoose.model(
        'Session',
        sessionSchema
    );

const OTPVerification =
    mongoose.model(
        'OTPVerification',
        otpSchema
    );

/* =========================================================
   DATABASE CONNECTION
========================================================= */

mongoose
    .connect(MONGO_URI)
    .then(() => {

        console.log(
            '✓ MongoDB connected successfully.'
        );

    })
    .catch((error) => {

        console.error(
            'MongoDB connection error:',
            error
        );

        process.exit(1);
    });

/* =========================================================
   HEALTH
========================================================= */

app.get(
    '/',
    (req, res) => {

        res.json({
            success: true,

            service:
                'Routix Auth Server',

            status:
                'online'
        });
    }
);

app.get(
    '/health',
    (req, res) => {

        res.json({

            success: true,

            status:
                'ok',

            database:
                mongoose.connection
                    .readyState === 1
                    ? 'connected'
                    : 'disconnected'
        });
    }
);

/* =========================================================
   SEND OTP
========================================================= */

app.post(
    '/api/register',
    async (req, res) => {

        try {

            const email =
                normalizeEmail(
                    req.body?.email
                );

            const password =
                typeof req.body?.password === 'string'
                    ? req.body.password
                    : '';

            /* ---------------------------------------------
               VALIDATION
            --------------------------------------------- */

            if (
                !isValidEmail(email)
            ) {

                return res.status(400).json({

                    success: false,

                    code:
                        'INVALID_EMAIL',

                    message:
                        'يرجى إدخال بريد إلكتروني صحيح.'
                });
            }

            if (
                !isValidPassword(password)
            ) {

                return res.status(400).json({

                    success: false,

                    code:
                        'INVALID_PASSWORD',

                    message:
                        'كلمة المرور يجب أن تكون بين 8 و128 حرفًا.'
                });
            }

            /* ---------------------------------------------
               CHECK EXISTING USER
            --------------------------------------------- */

            const existingUser =
                await User.exists({
                    email
                });

            if (existingUser) {

                return res.status(409).json({

                    success: false,

                    code:
                        'EMAIL_ALREADY_REGISTERED',

                    message:
                        'هذا البريد مسجل مسبقاً، قم بتسجيل الدخول بدلاً من ذلك.'
                });
            }

            /* ---------------------------------------------
               EXISTING OTP
            --------------------------------------------- */

            const existingOTP =
                await OTPVerification.findOne({
                    email
                });

            if (existingOTP) {

                const lastSent =
                    new Date(
                        existingOTP.lastSentAt
                    ).getTime();

                const elapsed =
                    Date.now() -
                    lastSent;

                if (
                    elapsed <
                    RESEND_COOLDOWN_MS
                ) {

                    const remaining =
                        Math.ceil(
                            (
                                RESEND_COOLDOWN_MS -
                                elapsed
                            ) / 1000
                        );

                    return res.status(429).json({

                        success: false,

                        code:
                            'RESEND_COOLDOWN',

                        message:
                            `انتظر ${remaining} ثانية قبل طلب رمز جديد.`,

                        retryAfter:
                            remaining
                    });
                }
            }

            /* ---------------------------------------------
               HASH PASSWORD
            --------------------------------------------- */

            const passwordHash =
                await argon2.hash(
                    password,
                    {
                        type:
                            argon2.argon2id
                    }
                );

            /* ---------------------------------------------
               GENERATE OTP
            --------------------------------------------- */

            const otp =
                generateOTP();

            const otpHash =
                await argon2.hash(
                    otp,
                    {
                        type:
                            argon2.argon2id
                    }
                );

            /* ---------------------------------------------
               STORE OTP
            --------------------------------------------- */

            await OTPVerification.findOneAndUpdate(
                {
                    email
                },
                {
                    email,

                    otpHash,

                    passwordHash,

                    attempts:
                        0,

                    createdAt:
                        new Date(),

                    lastSentAt:
                        new Date()
                },
                {
                    upsert:
                        true,

                    new:
                        true,

                    setDefaultsOnInsert:
                        true
                }
            );

            /* ---------------------------------------------
               BREVO
            --------------------------------------------- */

            const brevoResponse =
                await fetch(
                    'https://api.brevo.com/v3/smtp/email',
                    {
                        method: 'POST',

                        headers: {

                            accept:
                                'application/json',

                            'api-key':
                                BREVO_API_KEY,

                            'content-type':
                                'application/json'
                        },

                        body:
                            JSON.stringify({

                                sender: {

                                    name:
                                        SENDER_NAME,

                                    email:
                                        SENDER_EMAIL
                                },

                                to: [
                                    {
                                        email
                                    }
                                ],

                                subject:
                                    'رمز التحقق الخاص بك - Routix',

                                htmlContent: `
<!DOCTYPE html>
<html lang="ar" dir="rtl">

<head>
<meta charset="UTF-8">
<meta name="viewport"
content="width=device-width,initial-scale=1.0">
</head>

<body style="
margin:0;
padding:0;
background:#02050a;
font-family:Tahoma,Arial,sans-serif;
">

<div style="
max-width:560px;
margin:40px auto;
padding:35px;
background:#08131f;
border:1px solid #183342;
border-radius:18px;
color:#eefaff;
">

<h1 style="
margin:0 0 20px;
color:#36e6ff;
font-size:30px;
">
Routix
</h1>

<h2 style="
color:#ffffff;
margin-bottom:15px;
">
تأكيد البريد الإلكتروني
</h2>

<p style="
color:#9eb1c2;
line-height:1.9;
">
استخدم رمز التحقق التالي لإكمال إنشاء
حسابك في Routix.
</p>

<div style="
margin:30px 0;
padding:22px;
text-align:center;
background:#010409;
border:1px solid #23495a;
border-radius:14px;
">

<div style="
color:#8ba0b4;
font-size:12px;
margin-bottom:12px;
">
رمز التحقق
</div>

<div style="
color:#36e6ff;
font-size:38px;
font-weight:bold;
letter-spacing:9px;
direction:ltr;
">
${otp}
</div>

</div>

<p style="
color:#8ba0b4;
font-size:13px;
line-height:1.8;
">
هذا الرمز صالح لمدة 5 دقائق فقط.
ولا تشارك الرمز مع أي شخص.
</p>

<hr style="
border:0;
border-top:1px solid #183342;
margin:25px 0;
">

<p style="
color:#607487;
font-size:11px;
line-height:1.7;
">
إذا لم تطلب إنشاء حساب في Routix،
يمكنك تجاهل هذه الرسالة.
</p>

</div>

</body>
</html>
                                `
                            })
                    }
                );

            let brevoData = {};

            try {

                brevoData =
                    await brevoResponse.json();

            } catch {

                brevoData = {};
            }

            /* ---------------------------------------------
               BREVO FAILED
            --------------------------------------------- */

            if (
                !brevoResponse.ok
            ) {

                await OTPVerification.deleteOne({
                    email
                });

                console.error(
                    'Brevo error:',
                    brevoResponse.status,
                    brevoData
                );

                return res.status(502).json({

                    success: false,

                    code:
                        'EMAIL_SEND_FAILED',

                    message:
                        'تعذر إرسال رمز التحقق، حاول مرة أخرى لاحقاً.'
                });
            }

            /* ---------------------------------------------
               SUCCESS
            --------------------------------------------- */

            return res.json({

                success: true,

                code:
                    'OTP_SENT',

                message:
                    'تم إرسال رمز التحقق إلى بريدك الإلكتروني.'
            });

        } catch (error) {

            console.error(
                'REGISTER ERROR:',
                error
            );

            return res.status(500).json({

                success: false,

                code:
                    'INTERNAL_ERROR',

                message:
                    'حدث خطأ داخلي في السيرفر.'
            });
        }
    }
);

/* =========================================================
   VERIFY OTP + CREATE USER
========================================================= */

app.post(
    '/api/verify-otp',
    async (req, res) => {

        try {

            const email =
                normalizeEmail(
                    req.body?.email
                );

            const otp =
                typeof req.body?.otp === 'string'
                    ? req.body.otp.trim()
                    : '';

            /* ---------------------------------------------
               VALIDATION
            --------------------------------------------- */

            if (
                !isValidEmail(email)
            ) {

                return res.status(400).json({

                    success: false,

                    code:
                        'INVALID_EMAIL',

                    message:
                        'البريد الإلكتروني غير صحيح.'
                });
            }

            if (
                !new RegExp(
                    `^\\d{${OTP_LENGTH}}$`
                ).test(otp)
            ) {

                return res.status(400).json({

                    success: false,

                    code:
                        'INVALID_OTP_FORMAT',

                    message:
                        'رمز التحقق يجب أن يتكون من 6 أرقام.'
                });
            }

            /* ---------------------------------------------
               ALREADY REGISTERED
            --------------------------------------------- */

            const existingUser =
                await User.exists({
                    email
                });

            if (existingUser) {

                await OTPVerification.deleteOne({
                    email
                });

                return res.status(409).json({

                    success: false,

                    code:
                        'EMAIL_ALREADY_REGISTERED',

                    message:
                        'هذا البريد مسجل مسبقاً، قم بتسجيل الدخول بدلاً من ذلك.'
                });
            }

            /* ---------------------------------------------
               FIND OTP
            --------------------------------------------- */

            const record =
                await OTPVerification.findOne({
                    email
                });

            if (!record) {

                return res.status(400).json({

                    success: false,

                    code:
                        'OTP_EXPIRED',

                    message:
                        'انتهت صلاحية الكود أو لم يتم طلب كود لهذا البريد.'
                });
            }

            /* ---------------------------------------------
               EXPIRATION CHECK
            --------------------------------------------- */

            const createdAt =
                new Date(
                    record.createdAt
                ).getTime();

            if (
                Date.now() -
                createdAt >
                OTP_EXPIRES_MS
            ) {

                await OTPVerification.deleteOne({
                    email
                });

                return res.status(400).json({

                    success: false,

                    code:
                        'OTP_EXPIRED',

                    message:
                        'انتهت صلاحية الكود، اطلب رمزاً جديداً.'
                });
            }

            /* ---------------------------------------------
               ATTEMPT LIMIT
            --------------------------------------------- */

            if (
                record.attempts >=
                MAX_OTP_ATTEMPTS
            ) {

                await OTPVerification.deleteOne({
                    email
                });

                return res.status(429).json({

                    success: false,

                    code:
                        'TOO_MANY_ATTEMPTS',

                    message:
                        'تم تجاوز عدد محاولات التحقق، اطلب رمزاً جديداً.'
                });
            }

            /* ---------------------------------------------
               VERIFY OTP
            --------------------------------------------- */

            let validOTP =
                false;

            try {

                validOTP =
                    await argon2.verify(
                        record.otpHash,
                        otp
                    );

            } catch {

                validOTP =
                    false;
            }

            /* ---------------------------------------------
               WRONG OTP
            --------------------------------------------- */

            if (!validOTP) {

                record.attempts += 1;

                if (
                    record.attempts >=
                    MAX_OTP_ATTEMPTS
                ) {

                    await record.deleteOne();

                    return res.status(429).json({

                        success: false,

                        code:
                            'TOO_MANY_ATTEMPTS',

                        message:
                            'تم تجاوز عدد محاولات التحقق، اطلب رمزاً جديداً.'
                    });
                }

                await record.save();

                return res.status(400).json({

                    success: false,

                    code:
                        'INVALID_OTP',

                    message:
                        'كود التحقق غير صحيح.',

                    attemptsRemaining:
                        MAX_OTP_ATTEMPTS -
                        record.attempts
                });
            }

            /* ---------------------------------------------
               GENERATE API TOKEN
            --------------------------------------------- */

            const apiToken =
                'rtx_' +
                generateRandomToken(32);

            const apiTokenHash =
                hashToken(
                    apiToken
                );

            /* ---------------------------------------------
               CREATE USER
            --------------------------------------------- */

            let user;

            try {

                user =
                    await User.create({

                        email,

                        passwordHash:
                            record.passwordHash,

                        apiTokenHash,

                        verifiedAt:
                            new Date()
                    });

            } catch (error) {

                if (
                    error &&
                    error.code === 11000
                ) {

                    await OTPVerification.deleteOne({
                        email
                    });

                    return res.status(409).json({

                        success: false,

                        code:
                            'EMAIL_ALREADY_REGISTERED',

                        message:
                            'هذا البريد مسجل مسبقاً، قم بتسجيل الدخول بدلاً من ذلك.'
                    });
                }

                throw error;
            }

            /* ---------------------------------------------
               DELETE OTP
            --------------------------------------------- */

            await OTPVerification.deleteOne({
                email
            });

            /* ---------------------------------------------
               CREATE SESSION
            --------------------------------------------- */

            const sessionToken =
                generateRandomToken(48);

            const sessionTokenHash =
                hashToken(
                    sessionToken
                );

            const expiresAt =
                getSessionExpiration();

            await Session.create({

                userId:
                    user._id,

                sessionTokenHash,

                expiresAt,

                createdAt:
                    new Date(),

                lastUsedAt:
                    new Date()
            });

            /* ---------------------------------------------
               SET SESSION COOKIE
            --------------------------------------------- */

            res.cookie(
                SESSION_COOKIE_NAME,
                sessionToken,
                SESSION_COOKIE_OPTIONS
            );

            /* ---------------------------------------------
               RESPONSE
            --------------------------------------------- */

            return res.status(201).json({

                success: true,

                code:
                    'ACCOUNT_CREATED',

                message:
                    'تم إنشاء الحساب والتحقق من البريد بنجاح.',

                user: {

                    id:
                        user._id.toString(),

                    email:
                        user.email,

                    verifiedAt:
                        user.verifiedAt
                },

                apiToken
            });

        } catch (error) {

            console.error(
                'VERIFY OTP ERROR:',
                error
            );

            return res.status(500).json({

                success: false,

                code:
                    'INTERNAL_ERROR',

                message:
                    'حدث خطأ داخلي في السيرفر.'
            });
        }
    }
);

/* =========================================================
   SESSION MIDDLEWARE
========================================================= */

async function requireSession(
    req,
    res,
    next
) {

    try {

        const sessionToken =
            req.cookies[
                SESSION_COOKIE_NAME
            ];

        if (!sessionToken) {

            return res.status(401).json({

                success: false,

                code:
                    'NOT_AUTHENTICATED',

                message:
                    'يجب تسجيل الدخول أولاً.'
            });
        }

        if (
            typeof sessionToken !== 'string' ||
            sessionToken.length < 32
        ) {

            return res.status(401).json({

                success: false,

                code:
                    'INVALID_SESSION',

                message:
                    'الجلسة غير صالحة.'
            });
        }

        const sessionTokenHash =
            hashToken(
                sessionToken
            );

        const session =
            await Session.findOne({
                sessionTokenHash
            });

        if (!session) {

            res.clearCookie(
                SESSION_COOKIE_NAME,
                SESSION_COOKIE_OPTIONS
            );

            return res.status(401).json({

                success: false,

                code:
                    'INVALID_SESSION',

                message:
                    'الجلسة غير صالحة أو انتهت.'
            });
        }

        /* ---------------------------------------------
           EXPIRATION
        --------------------------------------------- */

        if (
            session.expiresAt.getTime() <=
            Date.now()
        ) {

            await Session.deleteOne({
                _id:
                    session._id
            });

            res.clearCookie(
                SESSION_COOKIE_NAME,
                SESSION_COOKIE_OPTIONS
            );

            return res.status(401).json({

                success: false,

                code:
                    'SESSION_EXPIRED',

                message:
                    'انتهت صلاحية الجلسة، قم بتسجيل الدخول مرة أخرى.'
            });
        }

        /* ---------------------------------------------
           USER
        --------------------------------------------- */

        const user =
            await User.findById(
                session.userId
            );

        if (!user) {

            await Session.deleteOne({
                _id:
                    session._id
            });

            res.clearCookie(
                SESSION_COOKIE_NAME,
                SESSION_COOKIE_OPTIONS
            );

            return res.status(401).json({

                success: false,

                code:
                    'USER_NOT_FOUND',

                message:
                    'الحساب غير موجود.'
            });
        }

        /* ---------------------------------------------
           UPDATE LAST USED
        --------------------------------------------- */

        session.lastUsedAt =
            new Date();

        await session.save();

        /* ---------------------------------------------
           ATTACH
        --------------------------------------------- */

        req.user =
            user;

        req.session =
            session;

        next();

    } catch (error) {

        console.error(
            'SESSION ERROR:',
            error
        );

        return res.status(500).json({

            success: false,

            code:
                'SESSION_ERROR',

            message:
                'حدث خطأ أثناء التحقق من الجلسة.'
        });
    }
}

/* =========================================================
   LOGIN
========================================================= */

app.post(
    '/api/login',
    async (req, res) => {

        try {

            const email =
                normalizeEmail(
                    req.body?.email
                );

            const password =
                typeof req.body?.password === 'string'
                    ? req.body.password
                    : '';

            /* ---------------------------------------------
               VALIDATION
            --------------------------------------------- */

            if (
                !isValidEmail(email)
            ) {

                return res.status(400).json({

                    success: false,

                    code:
                        'INVALID_CREDENTIALS',

                    message:
                        'البريد الإلكتروني أو كلمة المرور غير صحيحة.'
                });
            }

            if (!password) {

                return res.status(400).json({

                    success: false,

                    code:
                        'INVALID_CREDENTIALS',

                    message:
                        'البريد الإلكتروني أو كلمة المرور غير صحيحة.'
                });
            }

            /* ---------------------------------------------
               FIND USER
            --------------------------------------------- */

            const user =
                await User.findOne({
                    email
                });

            if (!user) {

                return res.status(401).json({

                    success: false,

                    code:
                        'INVALID_CREDENTIALS',

                    message:
                        'البريد الإلكتروني أو كلمة المرور غير صحيحة.'
                });
            }

            /* ---------------------------------------------
               VERIFY PASSWORD
            --------------------------------------------- */

            let validPassword =
                false;

            try {

                validPassword =
                    await argon2.verify(
                        user.passwordHash,
                        password
                    );

            } catch {

                validPassword =
                    false;
            }

            if (!validPassword) {

                return res.status(401).json({

                    success: false,

                    code:
                        'INVALID_CREDENTIALS',

                    message:
                        'البريد الإلكتروني أو كلمة المرور غير صحيحة.'
                });
            }

            /* ---------------------------------------------
               CREATE UNIQUE SESSION
            --------------------------------------------- */

            const sessionToken =
                generateRandomToken(48);

            const sessionTokenHash =
                hashToken(
                    sessionToken
                );

            const expiresAt =
                getSessionExpiration();

            await Session.create({

                userId:
                    user._id,

                sessionTokenHash,

                expiresAt,

                createdAt:
                    new Date(),

                lastUsedAt:
                    new Date()
            });

            /* ---------------------------------------------
               COOKIE
            --------------------------------------------- */

            res.cookie(
                SESSION_COOKIE_NAME,
                sessionToken,
                SESSION_COOKIE_OPTIONS
            );

            /* ---------------------------------------------
               RESPONSE
            --------------------------------------------- */

            return res.json({

                success: true,

                code:
                    'LOGIN_SUCCESS',

                message:
                    'تم تسجيل الدخول بنجاح.',

                user: {

                    id:
                        user._id.toString(),

                    email:
                        user.email,

                    verifiedAt:
                        user.verifiedAt
                }
            });

        } catch (error) {

            console.error(
                'LOGIN ERROR:',
                error
            );

            return res.status(500).json({

                success: false,

                code:
                    'INTERNAL_ERROR',

                message:
                    'حدث خطأ داخلي في السيرفر.'
            });
        }
    }
);

/* =========================================================
   ME
========================================================= */

app.get(
    '/api/me',
    requireSession,
    async (req, res) => {

        return res.json({

            success: true,

            authenticated:
                true,

            user: {

                id:
                    req.user._id.toString(),

                email:
                    req.user.email,

                verifiedAt:
                    req.user.verifiedAt,

                createdAt:
                    req.user.createdAt
            },

            session: {

                createdAt:
                    req.session.createdAt,

                lastUsedAt:
                    req.session.lastUsedAt,

                expiresAt:
                    req.session.expiresAt
            }
        });
    }
);

/* =========================================================
   LOGOUT
========================================================= */

app.post(
    '/api/logout',
    async (req, res) => {

        try {

            const sessionToken =
                req.cookies[
                    SESSION_COOKIE_NAME
                ];

            if (sessionToken) {

                const sessionTokenHash =
                    hashToken(
                        sessionToken
                    );

                await Session.deleteOne({
                    sessionTokenHash
                });
            }

            res.clearCookie(
                SESSION_COOKIE_NAME,
                SESSION_COOKIE_OPTIONS
            );

            return res.json({

                success: true,

                code:
                    'LOGOUT_SUCCESS',

                message:
                    'تم تسجيل الخروج بنجاح.'
            });

        } catch (error) {

            console.error(
                'LOGOUT ERROR:',
                error
            );

            return res.status(500).json({

                success: false,

                code:
                    'INTERNAL_ERROR',

                message:
                    'حدث خطأ أثناء تسجيل الخروج.'
            });
        }
    }
);

/* =========================================================
   GET API TOKEN INFO
========================================================= */

app.get(
    '/api/account/token',
    requireSession,
    async (req, res) => {

        return res.json({

            success: true,

            message:
                'API Token موجود للحساب. لأسباب أمنية لا يتم إرجاع التوكن الحالي.'
        });
    }
);

/* =========================================================
   REGENERATE API TOKEN
========================================================= */

app.post(
    '/api/account/token/regenerate',
    requireSession,
    async (req, res) => {

        try {

            const newApiToken =
                'rtx_' +
                generateRandomToken(32);

            const newApiTokenHash =
                hashToken(
                    newApiToken
                );

            req.user.apiTokenHash =
                newApiTokenHash;

            await req.user.save();

            return res.json({

                success: true,

                code:
                    'API_TOKEN_REGENERATED',

                message:
                    'تم إنشاء API Token جديد. التوكن السابق لم يعد صالحاً.',

                apiToken:
                    newApiToken
            });

        } catch (error) {

            console.error(
                'TOKEN REGENERATE ERROR:',
                error
            );

            return res.status(500).json({

                success: false,

                code:
                    'INTERNAL_ERROR',

                message:
                    'تعذر إنشاء API Token جديد.'
            });
        }
    }
);

/* =========================================================
   404
========================================================= */

app.use(
    (req, res) => {

        res.status(404).json({

            success: false,

            code:
                'NOT_FOUND',

            message:
                'المسار المطلوب غير موجود.'
        });
    }
);

/* =========================================================
   ERROR HANDLER
========================================================= */

app.use(
    (error, req, res, next) => {

        console.error(
            'UNHANDLED ERROR:',
            error
        );

        if (
            res.headersSent
        ) {
            return next(error);
        }

        /*
         * معالجة خطأ CORS بشكل واضح.
         */

        if (
            error &&
            error.message ===
                'CORS origin not allowed'
        ) {

            return res.status(403).json({

                success: false,

                code:
                    'CORS_ORIGIN_NOT_ALLOWED',

                message:
                    'هذا النطاق غير مسموح له بالاتصال بالسيرفر.'
            });
        }

        return res.status(500).json({

            success: false,

            code:
                'INTERNAL_ERROR',

            message:
                'حدث خطأ داخلي في السيرفر.'
        });
    }
);

/* =========================================================
   START
========================================================= */

app.listen(
    PORT,
    () => {

        console.log(
            '========================================'
        );

        console.log(
            '        ROUTIX AUTH SERVER'
        );

        console.log(
            '========================================'
        );

        console.log(
            `✓ Server: http://localhost:${PORT}`
        );

        console.log(
            '✓ OTP: enabled'
        );

        console.log(
            '✓ Brevo: enabled'
        );

        console.log(
            '✓ MongoDB: enabled'
        );

        console.log(
            '✓ Argon2id: enabled'
        );

        console.log(
            '✓ Sessions: enabled'
        );

        console.log(
            '✓ API Tokens: enabled'
        );

        console.log(
            '✓ CORS: enabled'
        );

        console.log(
            '✓ Credentials: enabled'
        );

        console.log(
            '✓ www.routix.nx.kg: allowed'
        );

        console.log(
            '✓ routix.nx.kg: allowed'
        );

        console.log(
            `✓ Session TTL: ${SESSION_TTL_DAYS} days`
        );

        console.log(
            `✓ Cookie SameSite: ${
                IS_PRODUCTION
                    ? 'none'
                    : 'lax'
            }`
        );

        console.log(
            `✓ Cookie Secure: ${
                IS_PRODUCTION
                    ? 'true'
                    : 'false'
            }`
        );

        console.log(
            '========================================'
        );
    }
);
