'use strict';

import express, {
    Request,
    Response,
    NextFunction
} from 'express';

import cors from 'cors';
import mongoose, {
    Document,
    Model,
    Schema
} from 'mongoose';

import jwt, {
    JwtPayload
} from 'jsonwebtoken';

import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import cookieParser from 'cookie-parser';
import argon2 from 'argon2';

import 'dotenv/config';

/* =========================================================
   TYPES
========================================================= */

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

/* =========================================================
   APP
========================================================= */

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

app.use(
    express.json({
        limit: '10kb'
    })
);

app.use(cookieParser());

/* =========================================================
   CORS
========================================================= */

const allowedOrigins: string[] = [
    'https://production-1-54qv.onrender.com',
    'https://www.routix.nx.kg',
    'https://routix.nx.kg'
];

app.use(
    cors({
        origin: (
            origin: string | undefined,
            callback: (
                error: Error | null,
                success?: boolean
            ) => void
        ) => {

            if (
                !origin ||
                allowedOrigins.includes(origin)
            ) {
                return callback(null, true);
            }

            return callback(
                new Error('Blocked by CORS policy')
            );
        },

        credentials: true,

        methods: [
            'GET',
            'POST',
            'OPTIONS'
        ],

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

    max: 30,

    standardHeaders: true,

    legacyHeaders: false,

    message: {
        success: false,
        message:
            'تم تجاوز الحد المسموح من الطلبات، يرجى المحاولة لاحقاً.'
    }
});

app.use(
    '/api/',
    limiter
);

/* =========================================================
   ENVIRONMENT VARIABLES
========================================================= */

const JWT_SECRET: string | undefined =
    process.env.JWT_SECRET;

const MONGO_URI: string | undefined =
    process.env.MONGO_URI;

const BREVO_API_KEY: string | undefined =
    process.env.BREVO_API_KEY;

const SENDER_EMAIL: string =
    process.env.SENDER_EMAIL ||
    'ttbnatlh@gmail.com';

/* =========================================================
   REQUIRED SECRETS
========================================================= */

if (!JWT_SECRET) {

    console.error(
        'JWT_SECRET is missing from environment variables.'
    );

    process.exit(1);
}

if (!MONGO_URI) {

    console.error(
        'MONGO_URI is missing from environment variables.'
    );

    process.exit(1);
}

/* =========================================================
   SESSION COOKIE
========================================================= */

const SESSION_COOKIE =
    'routix_session';

const SESSION_COOKIE_OPTIONS = {

    httpOnly: true,

    secure: true,

    sameSite: 'none' as const,

    path: '/',

    maxAge:
        7 *
        24 *
        60 *
        60 *
        1000
};

/* =========================================================
   MONGODB
========================================================= */

mongoose
    .connect(MONGO_URI)
    .then(() => {

        console.log(
            'Connected to MongoDB successfully!'
        );
    })
    .catch((error: unknown) => {

        console.error(
            'MongoDB connection error:',
            error
        );

        process.exit(1);
    });

/* =========================================================
   USER SCHEMA
========================================================= */

const userSchema =
    new Schema<IUser>({

        email: {
            type: String,
            required: true,
            unique: true,
            lowercase: true,
            trim: true,
            index: true
        },

        passwordHash: {
            type: String,
            required: true
        },

        emailVerified: {
            type: Boolean,
            default: true
        },

        createdAt: {
            type: Date,
            default: Date.now
        },

        lastLoginAt: {
            type: Date,
            default: null
        }
    });

const UserModel: Model<IUser> =
    mongoose.model<IUser>(
        'User',
        userSchema
    );

/* =========================================================
   OTP SCHEMA
========================================================= */

const otpSchema =
    new Schema<IOTP>({

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

        /*
         * كلمة المرور المشفرة مؤقتاً أثناء
         * عملية إنشاء الحساب.
         *
         * لا نحفظ كلمة المرور الأصلية.
         */

        passwordHash: {
            type: String,
            required: true
        },

        createdAt: {
            type: Date,
            default: Date.now,
            expires: 300
        }
    });

const OTPModel: Model<IOTP> =
    mongoose.model<IOTP>(
        'OTPVerification',
        otpSchema
    );

/* =========================================================
   EMAIL HELPERS
========================================================= */

function normalizeEmail(
    email: unknown
): string {

    return String(email || '')
        .trim()
        .toLowerCase();
}

function isValidEmail(
    email: string
): boolean {

    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(
        email
    );
}

/* =========================================================
   PASSWORD VALIDATION
========================================================= */

function isValidPassword(
    password: unknown
): password is string {

    if (
        typeof password !== 'string'
    ) {
        return false;
    }

    /*
     * الحد الأدنى 8 أحرف
     */

    return (
        password.length >= 8 &&
        password.length <= 128
    );
}

/* =========================================================
   CREATE SESSION
========================================================= */

function createSession(
    res: Response,
    user: IUser
): void {

    const token =
        jwt.sign(
            {
                userId:
                    user._id.toString(),

                email:
                    user.email
            },

            JWT_SECRET,

            {
                expiresIn: '7d'
            }
        );

    res.cookie(
        SESSION_COOKIE,
        token,
        SESSION_COOKIE_OPTIONS
    );
}

/* =========================================================
   1. CHECK EMAIL
========================================================= */

app.post(
    '/api/check-email',
    async (
        req: Request,
        res: Response
    ) => {

        try {

            const email =
                normalizeEmail(
                    req.body.email
                );

            if (
                !isValidEmail(email)
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        'البريد الإلكتروني غير صالح أو مطلوب'
                });
            }

            const user =
                await UserModel.findOne({
                    email
                }).select('_id');

            return res.json({

                success: true,

                registered:
                    !!user
            });

        } catch (error: unknown) {

            console.error(
                'Check Email Error:',
                error
            );

            return res.status(500).json({

                success: false,

                message:
                    'خطأ داخلي في الخادم'
            });
        }
    }
);

/* =========================================================
   2. REGISTER - SEND OTP
========================================================= */

app.post(
    '/api/register',
    async (
        req: Request,
        res: Response
    ) => {

        try {

            const email =
                normalizeEmail(
                    req.body.email
                );

            const password =
                String(
                    req.body.password || ''
                );

            /* -----------------------------------------
               Validate email
            ----------------------------------------- */

            if (
                !isValidEmail(email)
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        'البريد الإلكتروني غير صالح'
                });
            }

            /* -----------------------------------------
               Validate password
            ----------------------------------------- */

            if (
                !isValidPassword(password)
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        'كلمة المرور يجب أن تكون بين 8 و128 حرفاً'
                });
            }

            /* -----------------------------------------
               Check existing account
            ----------------------------------------- */

            const existingUser =
                await UserModel.findOne({
                    email
                });

            if (existingUser) {

                return res.status(409).json({

                    success: false,

                    registered: true,

                    message:
                        'هذا البريد مسجل مسبقاً، استخدم تسجيل الدخول'
                });
            }

            /* -----------------------------------------
               Hash password
            ----------------------------------------- */

            const passwordHash =
                await argon2.hash(
                    password,
                    {
                        type:
                            argon2.argon2id
                    }
                );

            /* -----------------------------------------
               Generate OTP
            ----------------------------------------- */

            const otpCode =
                Math.floor(
                    100000 +
                    Math.random() *
                    900000
                ).toString();

            /* -----------------------------------------
               Save OTP + hashed password
            ----------------------------------------- */

            await OTPModel.findOneAndUpdate(

                {
                    email
                },

                {
                    email,

                    otp:
                        otpCode,

                    passwordHash,

                    createdAt:
                        new Date()
                },

                {
                    upsert: true,

                    new: true,

                    setDefaultsOnInsert: true
                }
            );

            /* -----------------------------------------
               Check Brevo
            ----------------------------------------- */

            if (!BREVO_API_KEY) {

                console.error(
                    'BREVO_API_KEY is missing.'
                );

                return res.status(500).json({

                    success: false,

                    message:
                        'خدمة البريد غير مهيأة على السيرفر'
                });
            }

            /* -----------------------------------------
               Send OTP
            ----------------------------------------- */

            const response =
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
                                        'Routix Security',

                                    email:
                                        SENDER_EMAIL
                                },

                                to: [
                                    {
                                        email
                                    }
                                ],

                                subject:
                                    'رمز إنشاء حساب Routix',

                                htmlContent: `

                                    <div
                                        dir="rtl"
                                        style="
                                            font-family:
                                                Tahoma,
                                                Arial,
                                                sans-serif;

                                            padding:20px;

                                            color:#333;

                                            background:#f9f9f9;

                                            border-radius:8px;
                                        "
                                    >

                                        <h2
                                            style="
                                                color:#4F46E5;
                                            "
                                        >
                                            إنشاء حساب Routix
                                        </h2>

                                        <p>
                                            مرحباً بك في Routix.
                                        </p>

                                        <p>
                                            رمز التحقق الخاص بك هو:
                                        </p>

                                        <h1
                                            style="
                                                color:#4F46E5;

                                                letter-spacing:6px;

                                                background:#fff;

                                                padding:10px;

                                                display:inline-block;

                                                border-radius:5px;
                                            "
                                        >
                                            ${otpCode}
                                        </h1>

                                        <p>
                                            هذا الرمز صالح لمدة 5 دقائق فقط.
                                        </p>

                                        <p>
                                            لا تشارك الرمز مع أي شخص.
                                        </p>

                                    </div>

                                `
                            })
                    }
                );

            let data: BrevoResponse = {};

            try {

                data =
                    (
                        await response.json()
                    ) as BrevoResponse;

            } catch {

                data = {};
            }

            if (
                !response.ok
            ) {

                console.error(
                    'Brevo error:',
                    data
                );

                return res.status(400).json({

                    success: false,

                    message:
                        'فشل في إرسال رمز التحقق'
                });
            }

            return res.json({

                success: true,

                registered: false,

                message:
                    'تم إرسال رمز التحقق إلى بريدك'
            });

        } catch (error: unknown) {

            console.error(
                'Register Error:',
                error
            );

            return res.status(500).json({

                success: false,

                message:
                    'خطأ داخلي في الخادم'
            });
        }
    }
);

/* =========================================================
   3. VERIFY OTP + CREATE ACCOUNT + SESSION
========================================================= */

app.post(
    '/api/verify-otp',
    async (
        req: Request,
        res: Response
    ) => {

        try {

            const email =
                normalizeEmail(
                    req.body.email
                );

            const otp =
                String(
                    req.body.otp || ''
                ).trim();

            if (
                !isValidEmail(email) ||
                !/^\d{6}$/.test(otp)
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        'البريد الإلكتروني ورمز التحقق مطلوبان'
                });
            }

            /* -----------------------------------------
               Check if account already exists
            ----------------------------------------- */

            const existingUser =
                await UserModel.findOne({
                    email
                });

            if (existingUser) {

                await OTPModel.deleteMany({
                    email
                });

                return res.status(409).json({

                    success: false,

                    registered: true,

                    message:
                        'هذا البريد مسجل مسبقاً، استخدم تسجيل الدخول'
                });
            }

            /* -----------------------------------------
               Find OTP
            ----------------------------------------- */

            const record =
                await OTPModel.findOne({
                    email
                });

            if (!record) {

                return res.status(400).json({

                    success: false,

                    message:
                        'انتهت صلاحية رمز التحقق أو لم يتم طلب رمز'
                });
            }

            /* -----------------------------------------
               Verify OTP
            ----------------------------------------- */

            if (
                record.otp !== otp
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        'رمز التحقق غير صحيح'
                });
            }

            /* -----------------------------------------
               Create account
            ----------------------------------------- */

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
                        new Date()
                });

            /* -----------------------------------------
               Delete used OTP
            ----------------------------------------- */

            await OTPModel.deleteOne({
                _id:
                    record._id
            });

            /* -----------------------------------------
               Create HttpOnly session
            ----------------------------------------- */

            createSession(
                res,
                user
            );

            return res.status(201).json({

                success: true,

                registered: true,

                message:
                    'تم إنشاء الحساب وتسجيل الدخول بنجاح',

                user: {

                    id:
                        user._id.toString(),

                    email:
                        user.email
                }
            });

        } catch (error: unknown) {

            console.error(
                'Verify OTP Error:',
                error
            );

            /*
             * منع مشكلة duplicate email
             */

            if (
                typeof error === 'object' &&
                error !== null &&
                'code' in error &&
                (error as { code?: unknown }).code === 11000
            ) {

                return res.status(409).json({

                    success: false,

                    registered: true,

                    message:
                        'هذا البريد مسجل مسبقاً، استخدم تسجيل الدخول'
                });
            }

            return res.status(500).json({

                success: false,

                message:
                    'خطأ داخلي في الخادم'
            });
        }
    }
);

/* =========================================================
   4. LOGIN WITH EMAIL + PASSWORD
========================================================= */

app.post(
    '/api/login',
    async (
        req: Request,
        res: Response
    ) => {

        try {

            const email =
                normalizeEmail(
                    req.body.email
                );

            const password =
                String(
                    req.body.password || ''
                );

            if (
                !isValidEmail(email)
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        'البريد الإلكتروني غير صالح'
                });
            }

            if (
                !password
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        'كلمة المرور مطلوبة'
                });
            }

            /* -----------------------------------------
               Find user
            ----------------------------------------- */

            const user =
                await UserModel.findOne({
                    email
                });

            if (!user) {

                return res.status(401).json({

                    success: false,

                    registered: false,

                    message:
                        'البريد الإلكتروني أو كلمة المرور غير صحيحة'
                });
            }

            /* -----------------------------------------
               Verify password
            ----------------------------------------- */

            let passwordCorrect =
                false;

            try {

                passwordCorrect =
                    await argon2.verify(
                        user.passwordHash,
                        password
                    );

            } catch {

                passwordCorrect =
                    false;
            }

            if (
                !passwordCorrect
            ) {

                return res.status(401).json({

                    success: false,

                    registered: true,

                    message:
                        'البريد الإلكتروني أو كلمة المرور غير صحيحة'
                });
            }

            /* -----------------------------------------
               Update last login
            ----------------------------------------- */

            user.lastLoginAt =
                new Date();

            await user.save();

            /* -----------------------------------------
               Create HttpOnly session
            ----------------------------------------- */

            createSession(
                res,
                user
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
                        user.email
                }
            });

        } catch (error: unknown) {

            console.error(
                'Login Error:',
                error
            );

            return res.status(500).json({

                success: false,

                message:
                    'خطأ داخلي في الخادم'
            });
        }
    }
);

/* =========================================================
   SESSION VERIFICATION MIDDLEWARE
========================================================= */

const verifySession = async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
): Promise<Response | void> => {

    const token =
        req.cookies[
            SESSION_COOKIE
        ] as string | undefined;

    if (!token) {

        return res.status(401).json({

            success: false,

            loggedIn: false,

            message:
                'مطلوب تسجيل الدخول'
        });
    }

    try {

        const decoded =
            jwt.verify(
                token,
                JWT_SECRET
            );

        if (
            typeof decoded === 'string' ||
            !decoded.userId
        ) {

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

                loggedIn: false,

                message:
                    'جلسة غير صالحة'
            });
        }

        const payload =
            decoded as AuthJwtPayload;

        const user =
            await UserModel.findById(
                payload.userId
            ).select(
                '_id email emailVerified passwordHash createdAt lastLoginAt'
            );

        if (!user) {

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

                loggedIn: false,

                message:
                    'الحساب غير موجود'
            });
        }

        req.user =
            user;

        return next();

    } catch (error: unknown) {

        console.error(
            'Session Verification Error:',
            error
        );

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

            loggedIn: false,

            message:
                'انتهت صلاحية الجلسة، يرجى تسجيل الدخول مرة أخرى'
        });
    }
};

/* =========================================================
   5. PROFILE / SESSION CHECK
========================================================= */

app.get(
    '/api/profile',
    verifySession,
    (
        req: AuthenticatedRequest,
        res: Response
    ) => {

        if (!req.user) {

            return res.status(401).json({

                success: false,

                loggedIn: false,

                message:
                    'مطلوب تسجيل الدخول'
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
                    req.user.emailVerified
            }
        });
    }
);

/* =========================================================
   6. LOGOUT
========================================================= */

app.post(
    '/api/logout',
    (
        req: Request,
        res: Response
    ) => {

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

            loggedIn: false,

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
    (
        req: Request,
        res: Response
    ) => {

        return res.json({

            success: true,

            status:
                'online',

            service:
                'Routix Authentication'
        });
    }
);

/* =========================================================
   GLOBAL ERROR HANDLER
========================================================= */

app.use(
    (
        err: unknown,
        req: Request,
        res: Response,
        next: NextFunction
    ) => {

        console.error(
            'Server Error:',
            err
        );

        if (
            err instanceof Error &&
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

const PORT: number =
    Number(
        process.env.PORT || 4000
    );

app.listen(
    PORT,
    () => {

        console.log(
            `Authentication server is running on port ${PORT}`
        );
    }
);
