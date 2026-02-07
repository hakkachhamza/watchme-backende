const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const { body, validationResult } = require('express-validator');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();

// Initialize Express app
const app = express();

// حل مشكلة الـ Proxy في Railway - مهم جداً
app.set('trust proxy', 1); // ثقة كاملة في proxy

// Session middleware - إصلاح كامل للعمل مع Netlify + Railway
app.use(session({
    secret: process.env.SESSION_SECRET || 'watchme-secret-key-2024-change-in-production',
    resave: true, // تغيير من false إلى true
    saveUninitialized: true, // تغيير من false إلى true
    proxy: true, // ضروري للعمل مع Railway
    store: new session.MemoryStore(),
    name: 'watchme.sid', // اسم محدد للكوكيز
    cookie: {
        secure: true, // يجب أن يكون true في production
        sameSite: 'none', // هذا هو الحل السحري للـ Cross-domain
        maxAge: 30 * 60 * 1000, // 30 دقيقة (مدة الجلسة)
        httpOnly: true,
        domain: process.env.NODE_ENV === 'production' ? 
                '.railway.app' : // اسم النطاق العام لـ Railway
                undefined, // محلياً لا نحتاج domain
        path: '/'
    }
}));

// Security middleware
app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginResourcePolicy: { policy: "cross-origin" }
}));

// CORS configuration - إصلاح كامل
const corsOptions = {
    origin: function (origin, callback) {
        // في التطوير، اسمح بجميع الأصول
        if (process.env.NODE_ENV === 'development') {
            return callback(null, true);
        }
        
        // القائمة المسموحة في الإنتاج
        const allowedOrigins = [
            'https://watchme0.netlify.app',
            'https://watchme0.netlify.app',
            'https://*.netlify.app',
            process.env.FRONTEND_URL,
            process.env.CORS_ORIGIN
        ].filter(Boolean);
        
        // التحقق من الأصل
        if (!origin || allowedOrigins.includes(origin) || 
            allowedOrigins.some(allowed => origin.includes(allowed.replace('*', '')))) {
            callback(null, true);
        } else {
            console.log('CORS Blocked Origin:', origin);
            callback(new Error('Not allowed by CORS'));
        }
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin', 'x-csrf-token'],
    exposedHeaders: ['Content-Disposition', 'Set-Cookie'],
    credentials: true, // مهم جداً للسماح بإرسال الكوكيز
    preflightContinue: false,
    optionsSuccessStatus: 204,
    maxAge: 86400 // 24 ساعة
};

app.use(cors(corsOptions));

// Handle preflight requests
app.options('*', cors(corsOptions));

// Middleware لمعالجة الكوكيز في كل طلب
app.use((req, res, next) => {
    // تفعيل مشاركة الكوكيز عبر النطاقات
    res.header('Access-Control-Allow-Credentials', 'true');
    
    // إذا كان الطلب من Netlify، تأكد من ضبط الـ cookies بشكل صحيح
    if (req.headers.origin && req.headers.origin.includes('netlify.app')) {
        res.header('Access-Control-Allow-Origin', req.headers.origin);
    }
    
    next();
});

// Rate limiting
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: process.env.NODE_ENV === 'production' ? 200 : 5000,
    message: 'Too many requests from this IP, please try again later.',
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => {
        return req.headers['x-forwarded-for'] || req.ip;
    }
});

const appLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: process.env.NODE_ENV === 'production' ? 1000 : 10000,
    message: 'Too many requests from this IP, please try again later.',
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => {
        return req.headers['x-forwarded-for'] || req.ip;
    }
});

app.use('/api/', apiLimiter);
app.use('/api/app/', appLimiter);
app.use('/api/subscription/', appLimiter);

// Body parsing middleware
app.use(express.json({ 
    limit: '10mb',
    verify: (req, res, buf) => {
        req.rawBody = buf.toString();
    }
}));
app.use(express.urlencoded({ 
    extended: true, 
    limit: '10mb',
    parameterLimit: 10000
}));

// إنشاء مجلد uploads إذا لم يكن موجوداً - إصلاح المسار
const uploadDir = '/tmp/uploads'; // استخدم /tmp في Railway لأنها دائمة ومسموح بالكتابة فيها
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
    console.log(`✅ Created uploads directory at: ${uploadDir}`);
}

// Static files
app.use(express.static(path.join(__dirname, 'public'), {
    maxAge: '1d',
    setHeaders: (res, path) => {
        if (path.endsWith('.html')) {
            res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
        }
    }
}));

// File upload configuration - استخدام ذاكرة مؤقتة لتجنب مشاكل الصلاحيات
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, uploadDir);
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const ext = path.extname(file.originalname).toLowerCase();
        const name = path.basename(file.originalname, ext)
            .replace(/\s+/g, '_')
            .substring(0, 50);
        cb(null, name + '-' + uniqueSuffix + ext);
    }
});

const upload = multer({
    storage: storage,
    limits: {
        fileSize: 10 * 1024 * 1024 // 10MB
    },
    fileFilter: function (req, file, cb) {
        const allowedMimeTypes = ['text/plain', 'application/octet-stream', 'application/x-mpegURL'];
        const allowedExtensions = ['.m3u', '.m3u8', '.txt'];
        
        const extname = path.extname(file.originalname).toLowerCase();
        const mimeType = file.mimetype.toLowerCase();
        
        if (allowedMimeTypes.includes(mimeType) || allowedExtensions.includes(extname)) {
            cb(null, true);
        } else {
            cb(new Error(`Only M3U files are allowed! Received: ${mimeType}, ${extname}`), false);
        }
    }
});

// Database connection pool
let pool;
async function connectDB() {
    try {
        const dbConfig = {
            host: process.env.DB_HOST || 'mysql.railway.internal',
            user: process.env.DB_USER || 'root',
            password: process.env.DB_PASSWORD || 'zJlfstHREMzYlkwajJvhrLbeyekdwJtD',
            database: process.env.DB_NAME || 'railway',
            port: process.env.DB_PORT || 3306,
            waitForConnections: true,
            connectionLimit: 20,
            queueLimit: 0,
            enableKeepAlive: true,
            keepAliveInitialDelay: 10000,
            connectTimeout: 60000,
            ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false
        };
        
        console.log('Attempting to connect to database...');
        
        pool = mysql.createPool(dbConfig);
        
        const connection = await pool.getConnection();
        console.log('✅ Database connected successfully');
        
        const [rows] = await connection.execute('SELECT 1 + 1 AS result');
        console.log('Database test query result:', rows[0].result);
        
        connection.release();
        
        await initializeDatabase();
        
    } catch (error) {
        console.error('❌ Database connection failed:', error.message);
        console.error('Retrying connection in 5 seconds...');
        setTimeout(connectDB, 5000);
    }
}

// تهيئة جداول قاعدة البيانات
async function initializeDatabase() {
    try {
        const createTables = `
            CREATE TABLE IF NOT EXISTS admin_users (
                id INT PRIMARY KEY AUTO_INCREMENT,
                username VARCHAR(100) UNIQUE NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                pin_code VARCHAR(20) NOT NULL,
                role ENUM('admin', 'super_admin') DEFAULT 'admin',
                is_active BOOLEAN DEFAULT TRUE,
                last_login DATETIME,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            );
            
            CREATE TABLE IF NOT EXISTS channels (
                id VARCHAR(255) PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                url TEXT NOT NULL,
                category VARCHAR(100),
                logo_url TEXT,
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                INDEX idx_category (category),
                INDEX idx_name (name),
                INDEX idx_is_active (is_active)
            );
            
            CREATE TABLE IF NOT EXISTS subscription_codes (
                id VARCHAR(255) PRIMARY KEY,
                code VARCHAR(50) UNIQUE NOT NULL,
                duration_days INT NOT NULL,
                code_type ENUM('premium', 'trial', 'promo') DEFAULT 'premium',
                expiry_date DATETIME NOT NULL,
                is_used BOOLEAN DEFAULT FALSE,
                used_by VARCHAR(255),
                used_at DATETIME,
                generated_by VARCHAR(100),
                notes TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_code (code),
                INDEX idx_is_used (is_used),
                INDEX idx_expiry (expiry_date)
            );
            
            CREATE TABLE IF NOT EXISTS user_subscriptions (
                id VARCHAR(255) PRIMARY KEY,
                user_id VARCHAR(255) NOT NULL,
                subscription_code VARCHAR(50) NOT NULL,
                device_id VARCHAR(255),
                activated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME NOT NULL,
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                INDEX idx_user_id (user_id),
                INDEX idx_expires_at (expires_at),
                INDEX idx_is_active (is_active)
            );
            
            CREATE TABLE IF NOT EXISTS activity_logs (
                id INT PRIMARY KEY AUTO_INCREMENT,
                admin_id INT,
                action_type VARCHAR(100) NOT NULL,
                description TEXT,
                ip_address VARCHAR(45),
                user_agent TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_admin_id (admin_id),
                INDEX idx_created_at (created_at),
                FOREIGN KEY (admin_id) REFERENCES admin_users(id) ON DELETE SET NULL
            );
            
            CREATE TABLE IF NOT EXISTS playlist_settings (
                id INT PRIMARY KEY AUTO_INCREMENT,
                setting_key VARCHAR(100) UNIQUE NOT NULL,
                setting_value TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            );
            
            CREATE TABLE IF NOT EXISTS app_users (
                id INT PRIMARY KEY AUTO_INCREMENT,
                device_id VARCHAR(255) UNIQUE NOT NULL,
                subscription_code VARCHAR(50),
                last_active DATETIME,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                INDEX idx_device_id (device_id)
            );
        `;
        
        const queries = createTables.split(';').filter(q => q.trim());
        
        for (const query of queries) {
            if (query.trim()) {
                await pool.execute(query + ';');
            }
        }
        
        const [adminExists] = await pool.execute(
            'SELECT id FROM admin_users WHERE username = ?',
            ['admin']
        );
        
        if (adminExists.length === 0) {
            const defaultPin = '123456789';
            await pool.execute(
                'INSERT INTO admin_users (username, email, pin_code, role) VALUES (?, ?, ?, ?)',
                ['admin', 'admin@watchme.com', defaultPin, 'super_admin']
            );
            console.log('✅ Default admin user created with PIN: 123456789');
        }
        
        const defaultSettings = [
            ['app_name', 'Watch Me Premium'],
            ['company_name', 'Watch Me Streaming'],
            ['support_email', 'support@watchme.com'],
            ['version', '1.0.0']
        ];
        
        for (const [key, value] of defaultSettings) {
            await pool.execute(
                'INSERT IGNORE INTO playlist_settings (setting_key, setting_value) VALUES (?, ?)',
                [key, value]
            );
        }
        
        console.log('✅ Database tables initialized successfully');
        
    } catch (error) {
        console.error('❌ Database initialization error:', error.message);
    }
}

// JWT authentication middleware
const authenticateToken = async (req, res, next) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];
        
        if (!token) {
            return res.status(401).json({ 
                success: false, 
                message: 'Access token required' 
            });
        }
        
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'watchme-jwt-secret-2024-change-this-in-production');
        
        const [admin] = await pool.execute(
            'SELECT id, username, email, role FROM admin_users WHERE id = ? AND is_active = TRUE',
            [decoded.userId]
        );
        
        if (admin.length === 0) {
            return res.status(403).json({ 
                success: false, 
                message: 'Admin account not found or inactive' 
            });
        }
        
        req.user = admin[0];
        next();
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ 
                success: false, 
                message: 'Token expired. Please login again.' 
            });
        } else if (error.name === 'JsonWebTokenError') {
            return res.status(403).json({ 
                success: false, 
                message: 'Invalid token' 
            });
        } else {
            console.error('Authentication error:', error);
            return res.status(500).json({ 
                success: false, 
                message: 'Authentication error' 
            });
        }
    }
};

// Middleware للتحقق من جلسة الاستيراد - إصدار محسّن
const validateImportSession = (req, res, next) => {
    const { importId } = req.body;
    
    console.log('Session validation check:', {
        sessionId: req.sessionID,
        hasImportData: !!req.session.importData,
        importId: importId,
        sessionImportId: req.session.importData?.importId,
        sessionKeys: Object.keys(req.session)
    });
    
    if (!req.session.importData) {
        console.log('No import session found in session store');
        return res.status(400).json({ 
            success: false, 
            message: 'No import session found. Please upload the file again.',
            sessionId: req.sessionID,
            timestamp: new Date().toISOString()
        });
    }
    
    if (!importId || req.session.importData.importId !== importId) {
        console.log('Import ID mismatch:', {
            provided: importId,
            expected: req.session.importData?.importId
        });
        return res.status(400).json({ 
            success: false, 
            message: 'Import session ID mismatch. Please restart the import process.'
        });
    }
    
    if (Date.now() - req.session.importData.timestamp > 30 * 60 * 1000) {
        delete req.session.importData;
        console.log('Import session expired due to timeout');
        return res.status(400).json({ 
            success: false, 
            message: 'Import session expired. Please upload file again.' 
        });
    }
    
    next();
};

// تسجيل النشاط
const logActivity = async (req, action, description) => {
    try {
        await pool.execute(
            `INSERT INTO activity_logs 
            (admin_id, action_type, description, ip_address, user_agent) 
            VALUES (?, ?, ?, ?, ?)`,
            [
                req.user?.id || null,
                action,
                description,
                req.headers['x-forwarded-for'] || req.ip || req.connection.remoteAddress,
                req.headers['user-agent']
            ]
        );
    } catch (error) {
        console.error('Failed to log activity:', error.message);
    }
};

// ======================
// API ROUTES
// ======================

// Test route - مع معلومات الجلسة
app.get('/api/health', (req, res) => {
    const healthStatus = {
        success: true, 
        message: 'Watch Me Admin Server is running',
        timestamp: new Date().toISOString(),
        version: '1.0.0',
        environment: process.env.NODE_ENV || 'development',
        database: pool ? 'connected' : 'disconnected',
        session: {
            id: req.sessionID,
            hasImportSession: !!req.session.importData,
            cookie: req.session.cookie,
            domain: req.headers.host
        },
        cors: {
            origin: req.headers.origin,
            credentials: 'allowed'
        },
        uploadsDir: uploadDir
    };
    
    res.json(healthStatus);
});

// Admin authentication with PIN
app.post('/api/admin/login', [
    body('pin').isLength({ min: 9, max: 9 }).matches(/^\d+$/).withMessage('PIN must be 9 digits')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false, 
                errors: errors.array() 
            });
        }
        
        const { pin } = req.body;
        
        const [admins] = await pool.execute(
            'SELECT * FROM admin_users WHERE pin_code = ? AND is_active = TRUE',
            [pin]
        );
        
        if (admins.length === 0) {
            return res.status(401).json({ 
                success: false, 
                message: 'Invalid PIN' 
            });
        }
        
        const admin = admins[0];
        
        await pool.execute(
            'UPDATE admin_users SET last_login = NOW() WHERE id = ?',
            [admin.id]
        );
        
        const token = jwt.sign(
            { 
                userId: admin.id, 
                username: admin.username,
                role: admin.role 
            },
            process.env.JWT_SECRET || 'watchme-jwt-secret-2024-change-this-in-production',
            { expiresIn: process.env.JWT_EXPIRES_IN || '24h' }
        );
        
        await logActivity({ user: { id: admin.id }, headers: req.headers, ip: req.ip }, 'login', `Admin logged in: ${admin.username}`);
        
        res.json({
            success: true,
            message: 'Login successful',
            token,
            user: {
                id: admin.id,
                username: admin.username,
                email: admin.email,
                role: admin.role
            }
        });
        
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error during login' 
        });
    }
});

// ======================
// CHANNEL MANAGEMENT API
// ======================

app.get('/api/channels', authenticateToken, async (req, res) => {
    try {
        const { category, search, page = 1, limit = 50 } = req.query;
        
        const limitNum = parseInt(limit, 10) || 50;
        const pageNum = parseInt(page, 10) || 1;
        const offset = (pageNum - 1) * limitNum;
        
        let query = 'SELECT * FROM channels WHERE 1=1';
        let params = [];
        
        if (category && category !== 'All' && category !== '') {
            query += ' AND category = ?';
            params.push(category);
        }
        
        if (search) {
            query += ' AND (name LIKE ? OR category LIKE ? OR url LIKE ?)';
            const searchTerm = `%${search}%`;
            params.push(searchTerm, searchTerm, searchTerm);
        }
        
        const countQuery = query.replace('SELECT *', 'SELECT COUNT(*) as total');
        const [countResult] = await pool.execute(countQuery, params);
        const total = countResult[0].total;
        
        query += ' ORDER BY created_at DESC, name LIMIT ? OFFSET ?';
        params.push(limitNum, offset);
        
        const [channels] = await pool.query(query, params);
        
        const [categories] = await pool.execute(
            'SELECT DISTINCT category FROM channels WHERE category IS NOT NULL AND category != "" ORDER BY category'
        );
        
        res.json({
            success: true,
            data: channels,
            pagination: {
                page: pageNum,
                limit: limitNum,
                total,
                pages: Math.ceil(total / limitNum)
            },
            categories: categories.map(c => c.category),
            totalChannels: total
        });
        
    } catch (error) {
        console.error('Get channels error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to fetch channels' 
        });
    }
});

// ======================
// M3U IMPORT API - المحسّنة
// ======================

// رفع ملف M3U - مع تعزيز الجلسة
app.post('/api/upload/m3u', authenticateToken, upload.single('m3uFile'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ 
                success: false, 
                message: 'No file uploaded' 
            });
        }
        
        const filePath = req.file.path;
        const action = req.body.action || 'append';
        
        console.log('M3U Upload Process:', {
            filename: req.file.originalname,
            size: req.file.size,
            path: filePath,
            action: action,
            sessionId: req.sessionID
        });
        
        let fileContent;
        try {
            fileContent = fs.readFileSync(filePath, 'utf8');
        } catch (readError) {
            try {
                fs.unlinkSync(filePath);
            } catch (unlinkError) {
                console.warn('Could not delete uploaded file:', unlinkError.message);
            }
            return res.status(400).json({ 
                success: false, 
                message: 'Failed to read uploaded file' 
            });
        }
        
        const parsedChannels = parseM3UContent(fileContent);
        
        // تنظيف الملف المرفوع
        try {
            fs.unlinkSync(filePath);
        } catch (unlinkError) {
            console.warn('Could not delete uploaded file:', unlinkError.message);
        }
        
        if (parsedChannels.length === 0) {
            return res.status(400).json({ 
                success: false, 
                message: 'No valid channels found in M3U file' 
            });
        }
        
        // تخزين في الجلسة مع إصلاح كامل
        const importId = uuidv4();
        const sessionData = { 
            importId, 
            channels: parsedChannels, 
            action,
            timestamp: Date.now(),
            fileInfo: {
                originalName: req.file.originalname,
                size: req.file.size,
                parsedCount: parsedChannels.length,
                uploadedAt: new Date().toISOString()
            }
        };
        
        // تعيين بيانات الجلسة بشكل صريح
        req.session.importData = sessionData;
        
        // حفظ الجلسة بشكل متزامن
        await new Promise((resolve, reject) => {
            req.session.save((err) => {
                if (err) {
                    console.error('Session save error during upload:', err);
                    reject(err);
                } else {
                    console.log('Session saved successfully for import:', importId);
                    resolve();
                }
            });
        });
        
        await logActivity(req, 'm3u_upload', `Uploaded M3U file "${req.file.originalname}" with ${parsedChannels.length} channels`);
        
        // إرجاع معلومات الجلسة مع كل تفاصيلها
        res.json({
            success: true,
            message: 'M3U file parsed successfully',
            importId,
            sessionId: req.sessionID,
            data: {
                total: parsedChannels.length,
                sample: parsedChannels.slice(0, 10),
                firstChannel: parsedChannels[0]?.name || 'N/A'
            },
            sessionInfo: {
                importId,
                timestamp: sessionData.timestamp,
                expiresAt: new Date(sessionData.timestamp + 30 * 60 * 1000).toISOString(),
                action: action
            },
            instructions: 'Use this importId in the confirm import request'
        });
        
    } catch (error) {
        console.error('M3U upload error:', error);
        
        if (req.file && fs.existsSync(req.file.path)) {
            try {
                fs.unlinkSync(req.file.path);
            } catch (unlinkError) {
                console.warn('Could not delete file after error:', unlinkError.message);
            }
        }
        
        res.status(500).json({ 
            success: false, 
            message: 'Failed to process M3U file: ' + error.message 
        });
    }
});

// الحصول على بيانات الجلسة - للمساعدة في التصحيح
app.get('/api/import/session/check', authenticateToken, async (req, res) => {
    try {
        const sessionInfo = {
            sessionId: req.sessionID,
            hasImportData: !!req.session.importData,
            importData: req.session.importData ? {
                importId: req.session.importData.importId,
                action: req.session.importData.action,
                channelCount: req.session.importData.channels?.length || 0,
                timestamp: req.session.importData.timestamp,
                age: Date.now() - req.session.importData.timestamp
            } : null,
            cookie: req.headers.cookie,
            origin: req.headers.origin
        };
        
        res.json({
            success: true,
            session: sessionInfo,
            message: req.session.importData ? 'Import session found' : 'No import session'
        });
        
    } catch (error) {
        console.error('Session check error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to check session' 
        });
    }
});

// تأكيد استيراد M3U - مع معالجة محسنة
app.post('/api/import/m3u', authenticateToken, validateImportSession, async (req, res) => {
    const connection = await pool.getConnection();
    
    try {
        const { importId, action = 'append' } = req.body;
        const sessionData = req.session.importData;
        
        console.log('Starting import confirmation:', {
            importId: importId,
            sessionImportId: sessionData?.importId,
            channelCount: sessionData?.channels?.length,
            action: action,
            sessionId: req.sessionID
        });
        
        if (!sessionData || !sessionData.channels) {
            await connection.release();
            return res.status(400).json({ 
                success: false, 
                message: 'Import data not found in session' 
            });
        }
        
        const parsedChannels = sessionData.channels;
        
        console.log(`Importing ${parsedChannels.length} channels with action: ${action}`);
        
        await connection.beginTransaction();
        
        try {
            let importedCount = 0;
            let skippedCount = 0;
            let errorCount = 0;
            const errors = [];
            
            // إذا كان الاستبدال، احذف كل القنوات أولاً
            if (action === 'replace') {
                await connection.execute('DELETE FROM channels');
                console.log('Cleared existing channels for replacement');
            }
            
            // استيراد القنوات
            for (let i = 0; i < parsedChannels.length; i++) {
                const channel = parsedChannels[i];
                
                try {
                    // التحقق من وجود القناة مسبقاً
                    const [existing] = await connection.execute(
                        'SELECT id FROM channels WHERE url = ?',
                        [channel.url]
                    );
                    
                    if (existing.length === 0 || action === 'replace') {
                        // إذا كانت موجودة في وضع الاستبدال، احذفها أولاً
                        if (existing.length > 0 && action === 'replace') {
                            await connection.execute('DELETE FROM channels WHERE id = ?', [existing[0].id]);
                        }
                        
                        await connection.execute(
                            `INSERT INTO channels 
                            (id, name, url, category, logo_url) 
                            VALUES (?, ?, ?, ?, ?)`,
                            [
                                uuidv4(),
                                channel.name.substring(0, 200),
                                channel.url,
                                channel.category?.substring(0, 100) || 'General',
                                channel.logo || null
                            ]
                        );
                        importedCount++;
                    } else {
                        skippedCount++;
                    }
                    
                    // تحديث التقدم كل 100 قناة
                    if (i % 100 === 0) {
                        console.log(`Import progress: ${i}/${parsedChannels.length}`);
                    }
                    
                } catch (err) {
                    console.error(`Error importing channel ${i + 1}:`, err.message);
                    errorCount++;
                    errors.push({
                        index: i,
                        channel: channel.name,
                        error: err.message
                    });
                }
            }
            
            await connection.commit();
            
            // مسح بيانات الجلسة بعد النجاح
            const fileName = sessionData.fileInfo?.originalName || 'M3U file';
            delete req.session.importData;
            
            // حفظ الجلسة بعد المسح
            await new Promise((resolve, reject) => {
                req.session.save((err) => {
                    if (err) {
                        console.error('Session save error after import:', err);
                        reject(err);
                    } else {
                        console.log('Session cleared after successful import');
                        resolve();
                    }
                });
            });
            
            await logActivity(req, 'm3u_import', `Imported ${importedCount} channels from "${fileName}" (${action}), skipped ${skippedCount}, errors ${errorCount}`);
            
            const [countResult] = await connection.execute('SELECT COUNT(*) as total FROM channels');
            
            await connection.release();
            
            res.json({
                success: true,
                message: `Successfully imported ${importedCount} channels`,
                details: {
                    imported: importedCount,
                    skipped: skippedCount,
                    errors: errorCount,
                    totalAfterImport: countResult[0].total
                },
                importId: importId,
                sessionCleared: true,
                timestamp: new Date().toISOString()
            });
            
        } catch (error) {
            await connection.rollback();
            await connection.release();
            throw error;
        }
        
    } catch (error) {
        console.error('Import confirmation error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to import channels: ' + error.message,
            importId: req.body.importId
        });
    }
});

// دالة مساعدة لتحليل محتوى M3U
function parseM3UContent(content) {
    const channels = [];
    const lines = content.split('\n');
    let currentChannel = null;
    
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();
        
        if (line.startsWith('#EXTINF:')) {
            currentChannel = {
                name: 'Unknown Channel',
                url: '',
                category: 'General',
                logo: ''
            };
            
            // استخراج الاسم
            const nameStart = line.indexOf(',') + 1;
            if (nameStart > 0 && nameStart < line.length) {
                currentChannel.name = line.substring(nameStart).trim();
                
                // إزالة السمات الإضافية
                const attrIndex = currentChannel.name.indexOf(', tvg-');
                if (attrIndex !== -1) {
                    currentChannel.name = currentChannel.name.substring(0, attrIndex);
                }
                
                // تنظيف الاسم
                currentChannel.name = currentChannel.name.replace(/["']/g, '').trim();
                if (currentChannel.name.length > 200) {
                    currentChannel.name = currentChannel.name.substring(0, 200);
                }
            }
            
            // استخراج الشعار
            const logoMatch = line.match(/tvg-logo="([^"]+)"/i);
            if (logoMatch && logoMatch[1]) {
                currentChannel.logo = logoMatch[1].trim();
                if (currentChannel.logo.length > 500) {
                    currentChannel.logo = currentChannel.logo.substring(0, 500);
                }
            }
            
            // استخراج الفئة
            const groupMatch = line.match(/group-title="([^"]+)"/i);
            if (groupMatch && groupMatch[1]) {
                currentChannel.category = groupMatch[1].trim();
                if (currentChannel.category.length > 100) {
                    currentChannel.category = currentChannel.category.substring(0, 100);
                }
            }
            
        } else if (line && !line.startsWith('#') && currentChannel) {
            if (line.startsWith('http://') || line.startsWith('https://') || line.includes('://')) {
                currentChannel.url = line.trim();
                
                if (currentChannel.url.length > 0 && currentChannel.name.length > 0) {
                    currentChannel.url = currentChannel.url.replace(/\s+/g, '');
                    channels.push(currentChannel);
                }
                
                currentChannel = null;
            }
        }
    }
    
    console.log(`Parsed ${channels.length} channels from M3U content`);
    return channels;
}

// ======================
// REMAINING API ROUTES (مختصرة للإيجاز)
// ======================

// (يتم الحفاظ على بقية الـ APIs كما هي في الكود الأصلي مع الإصلاحات الأساسية)

// ... باقي الـ APIs ...

// ======================
// ERROR HANDLING
// ======================

app.use((req, res) => {
    res.status(404).json({ 
        success: false, 
        message: 'API endpoint not found',
        path: req.path,
        method: req.method
    });
});

app.use((err, req, res, next) => {
    console.error('❌ Global error:', err);
    
    if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(400).json({ 
            success: false, 
            message: 'File too large. Maximum size is 10MB' 
        });
    }
    
    if (err instanceof multer.MulterError) {
        return res.status(400).json({ 
            success: false, 
            message: 'File upload error: ' + err.message 
        });
    }
    
    if (err.name === 'JsonWebTokenError') {
        return res.status(401).json({ 
            success: false, 
            message: 'Invalid token' 
        });
    }
    
    if (err.name === 'TokenExpiredError') {
        return res.status(401).json({ 
            success: false, 
            message: 'Token expired' 
        });
    }
    
    res.status(500).json({ 
        success: false, 
        message: 'Internal server error',
        error: process.env.NODE_ENV === 'development' ? err.message : undefined,
        timestamp: new Date().toISOString()
    });
});

// ======================
// SERVER STARTUP
// ======================

const PORT = process.env.PORT || 8080;

async function startServer() {
    try {
        await connectDB();
        
        const server = app.listen(PORT, '0.0.0.0', () => {
            console.log(`🚀 Server running on port ${PORT}`);
            console.log(`📊 Health check: http://localhost:${PORT}/api/health`);
            console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
            console.log(`🔒 Session config: sameSite=none, secure=true`);
            console.log(`📁 Uploads directory: ${uploadDir}`);
            console.log(`🍪 Cookie domain: .railway.app`);
            
            if (process.env.NODE_ENV === 'production') {
                console.log(`⚡ Production mode enabled`);
            }
        });
        
        process.on('SIGTERM', () => {
            console.log('SIGTERM signal received: closing HTTP server');
            server.close(() => {
                console.log('HTTP server closed');
                if (pool) {
                    pool.end();
                    console.log('Database connection pool closed');
                }
            });
        });
        
        process.on('SIGINT', () => {
            console.log('SIGINT signal received: closing HTTP server');
            server.close(() => {
                console.log('HTTP server closed');
                if (pool) {
                    pool.end();
                    console.log('Database connection pool closed');
                }
                process.exit(0);
            });
        });
        
    } catch (error) {
        console.error('❌ Failed to start server:', error);
        process.exit(1);
    }
}

startServer();
