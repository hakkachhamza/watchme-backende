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

// حل مشكلة الـ Proxy في Railway
app.set('trust proxy', 1);

// Session middleware - معدل للعمل مع Railway
app.use(session({
    secret: process.env.SESSION_SECRET || 'watchme-secret-key-2024-change-in-production',
    resave: false,
    saveUninitialized: false,
    proxy: process.env.NODE_ENV === 'production', // مهم للـ proxy
    cookie: { 
        secure: process.env.NODE_ENV === 'production',
        sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

// Security middleware
app.use(helmet({
    contentSecurityPolicy: false,  // Disable CSP for development
    crossOriginResourcePolicy: { policy: "cross-origin" } // مهم للصور والموارد
}));

// CORS configuration - معدل للأمان
const corsOptions = {
    origin: function (origin, callback) {
        // السماح بطلبات بدون أصل (مثل mobile apps, curl)
        if (!origin) return callback(null, true);
        
        const allowedOrigins = [
            'http://localhost:3000',
            'http://localhost:8080',
            'http://localhost:8081',
            'https://watchme0.netlify.app',
            // أضف أصول Netlify الخاصة بك هنا
            process.env.CORS_ORIGIN
        ].filter(Boolean);
        
        if (allowedOrigins.indexOf(origin) !== -1 || process.env.NODE_ENV === 'development') {
            callback(null, true);
        } else {
            console.log('CORS Blocked Origin:', origin);
            callback(new Error('Not allowed by CORS'));
        }
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    credentials: true,
    optionsSuccessStatus: 200,
    maxAge: 86400 // 24 ساعة
};

app.use(cors(corsOptions));

// Handle preflight requests
app.options('*', cors(corsOptions));

// Rate limiting - أكثر تساهلاً للنشر الأولي
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 دقيقة
    max: process.env.NODE_ENV === 'production' ? 200 : 5000,
    message: 'Too many requests from this IP, please try again later.',
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => {
        // استخدام IP حقيقي مع الـ proxy
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

// Static files
app.use(express.static(path.join(__dirname, 'public'), {
    maxAge: '1d',
    setHeaders: (res, path) => {
        if (path.endsWith('.html')) {
            res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
        }
    }
}));

// File upload configuration
const upload = multer({
    storage: multer.diskStorage({
        destination: function (req, file, cb) {
            const uploadDir = path.join(__dirname, 'uploads');
            if (!fs.existsSync(uploadDir)) {
                fs.mkdirSync(uploadDir, { recursive: true });
            }
            cb(null, uploadDir);
        },
        filename: function (req, file, cb) {
            const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
            cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
        }
    }),
    limits: {
        fileSize: 10 * 1024 * 1024 // 10MB
    },
    fileFilter: function (req, file, cb) {
        const allowedMimeTypes = ['text/plain', 'application/octet-stream', 'application/x-mpegURL'];
        const allowedExtensions = ['.m3u', '.m3u8'];
        
        const extname = path.extname(file.originalname).toLowerCase();
        
        if (allowedMimeTypes.includes(file.mimetype) || allowedExtensions.includes(extname)) {
            cb(null, true);
        } else {
            cb(new Error('Only M3U files are allowed!'), false);
        }
    }
});

// Database connection pool
let pool;
async function connectDB() {
    try {
        // استخدام متغيرات البيئة أو القيم الافتراضية
        const dbConfig = {
            host: process.env.DB_HOST || 'mysql.railway.internal',
            user: process.env.DB_USER || 'root',
            password: process.env.DB_PASSWORD || 'zJlfstHREMzYlkwajJvhrLbeyekdwJtD',
            database: process.env.DB_NAME || 'railway',
            port: process.env.DB_PORT || 3306,
            waitForConnections: true,
            connectionLimit: 20, // زيادة للتعامل مع طلبات متعددة
            queueLimit: 0,
            enableKeepAlive: true,
            keepAliveInitialDelay: 10000,
            connectTimeout: 60000,
            ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false
        };
        
        console.log('Attempting to connect to database with config:', {
            host: dbConfig.host,
            user: dbConfig.user,
            database: dbConfig.database,
            port: dbConfig.port
        });
        
        pool = mysql.createPool(dbConfig);
        
        // اختبار الاتصال
        const connection = await pool.getConnection();
        console.log('✅ Database connected successfully');
        
        // اختبار استعلام بسيط
        const [rows] = await connection.execute('SELECT 1 + 1 AS result');
        console.log('Database test query result:', rows[0].result);
        
        connection.release();
        
        // تهيئة جداول قاعدة البيانات
        await initializeDatabase();
        
    } catch (error) {
        console.error('❌ Database connection failed:', error.message);
        console.error('Error stack:', error.stack);
        console.error('Please ensure:');
        console.error('1. MySQL server is running');
        console.error('2. Database exists');
        console.error('3. User has proper permissions');
        console.error('4. Check your .env file configuration');
        console.error('Current DB config:', {
            host: process.env.DB_HOST,
            user: process.env.DB_USER,
            database: process.env.DB_NAME,
            port: process.env.DB_PORT
        });
        
        // إعادة المحاولة بعد 5 ثواني
        console.log('Retrying connection in 5 seconds...');
        setTimeout(connectDB, 5000);
    }
}

// تهيئة جداول قاعدة البيانات
async function initializeDatabase() {
    try {
        // إنشاء الجداول إذا لم تكن موجودة
        const createTables = `
            -- جدول المستخدمين الإداريين
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
            
            -- جدول القنوات
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
                INDEX idx_name (name)
            );
            
            -- جدول رموز الاشتراك
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
            
            -- جدول اشتراكات المستخدمين
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
            
            -- جدول سجل النشاط
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
            
            -- جدول إعدادات القائمة
            CREATE TABLE IF NOT EXISTS playlist_settings (
                id INT PRIMARY KEY AUTO_INCREMENT,
                setting_key VARCHAR(100) UNIQUE NOT NULL,
                setting_value TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            );
            
            -- جدول مستخدمي التطبيق
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
        
        // تنفيذ استعلامات إنشاء الجداول
        const queries = createTables.split(';').filter(q => q.trim());
        
        for (const query of queries) {
            if (query.trim()) {
                await pool.execute(query + ';');
            }
        }
        
        // إدخال مستخدم إداري افتراضي إذا لم يكن موجودًا
        const [adminExists] = await pool.execute(
            'SELECT id FROM admin_users WHERE username = ?',
            ['admin']
        );
        
        if (adminExists.length === 0) {
            const defaultPin = '123456789'; // تغيير هذا في البيئة الإنتاجية
            await pool.execute(
                'INSERT INTO admin_users (username, email, pin_code, role) VALUES (?, ?, ?, ?)',
                ['admin', 'admin@watchme.com', defaultPin, 'super_admin']
            );
            console.log('✅ Default admin user created with PIN: 123456789');
        }
        
        // إدخال إعدادات افتراضية
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
        console.error('Error stack:', error.stack);
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
        
        // التحقق من JWT
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'watchme-jwt-secret-2024-change-this-in-production');
        
        // التحقق من وجود المسؤول ونشاطه
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

// تسجيل النشاط middleware
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

// Test route
app.get('/api/health', (req, res) => {
    const healthStatus = {
        success: true, 
        message: 'Watch Me Admin Server is running',
        timestamp: new Date().toISOString(),
        version: '1.0.0',
        environment: process.env.NODE_ENV || 'development',
        database: pool ? 'connected' : 'disconnected',
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        ip: req.headers['x-forwarded-for'] || req.ip
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
        
        // البحث عن المسؤول باستخدام PIN
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
        
        // تحديث آخر تسجيل دخول
        await pool.execute(
            'UPDATE admin_users SET last_login = NOW() WHERE id = ?',
            [admin.id]
        );
        
        // إنشاء JWT token
        const token = jwt.sign(
            { 
                userId: admin.id, 
                username: admin.username,
                role: admin.role 
            },
            process.env.JWT_SECRET || 'watchme-jwt-secret-2024-change-this-in-production',
            { expiresIn: process.env.JWT_EXPIRES_IN || '24h' }
        );
        
        // تسجيل النشاط
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

// الحصول على جميع القنوات
app.get('/api/channels', authenticateToken, async (req, res) => {
    try {
        const { category, search, page = 1, limit = 50 } = req.query;
        
        // إصلاح: تحويل القيم القادمة من الرابط (Query Params) إلى أرقام صحيحة
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
        
        // إصلاح: استخدام query بدلاً من execute إذا استمرت المشكلة
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

// إضافة قناة جديدة
app.post('/api/channels', authenticateToken, [
    body('name').notEmpty().trim().isLength({ min: 1, max: 200 }),
    body('url').notEmpty().trim(),
    body('category').optional().trim().isLength({ max: 100 }),
    body('logo').optional().trim()
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false, 
                errors: errors.array() 
            });
        }
        
        const { name, url, category = 'General', logo } = req.body;
        
        // التحقق من وجود القناة مسبقًا
        const [existing] = await pool.execute(
            'SELECT id FROM channels WHERE url = ? OR name = ?',
            [url, name]
        );
        
        if (existing.length > 0) {
            return res.status(409).json({ 
                success: false, 
                message: 'Channel with this URL or name already exists' 
            });
        }
        
        const channelId = uuidv4();
        
        const [result] = await pool.execute(
            `INSERT INTO channels 
            (id, name, url, category, logo_url) 
            VALUES (?, ?, ?, ?, ?)`,
            [channelId, name, url, category, logo || null]
        );
        
        const [channels] = await pool.execute(
            'SELECT * FROM channels WHERE id = ?',
            [channelId]
        );
        
        await logActivity(req, 'channel_add', `Added channel: ${name}`);
        
        res.status(201).json({
            success: true,
            message: 'Channel added successfully',
            data: channels[0]
        });
        
    } catch (error) {
        console.error('Add channel error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to add channel' 
        });
    }
});

// تحديث القناة
app.put('/api/channels/:id', authenticateToken, [
    body('name').optional().trim().isLength({ min: 1, max: 200 }),
    body('url').optional().trim(),
    body('category').optional().trim().isLength({ max: 100 }),
    body('logo').optional().trim()
], async (req, res) => {
    try {
        const { id } = req.params;
        const updates = req.body;
        
        // التحقق من وجود القناة
        const [existing] = await pool.execute(
            'SELECT name FROM channels WHERE id = ?',
            [id]
        );
        
        if (existing.length === 0) {
            return res.status(404).json({ 
                success: false, 
                message: 'Channel not found' 
            });
        }
        
        const updateFields = [];
        const values = [];
        
        // بناء استعلام التحديث الديناميكي
        if (updates.name !== undefined) {
            updateFields.push('name = ?');
            values.push(updates.name);
        }
        
        if (updates.url !== undefined) {
            updateFields.push('url = ?');
            values.push(updates.url);
        }
        
        if (updates.category !== undefined) {
            updateFields.push('category = ?');
            values.push(updates.category);
        }
        
        if (updates.logo !== undefined) {
            updateFields.push('logo_url = ?');
            values.push(updates.logo);
        }
        
        if (updates.is_active !== undefined) {
            updateFields.push('is_active = ?');
            values.push(updates.is_active);
        }
        
        if (updateFields.length === 0) {
            return res.status(400).json({ 
                success: false, 
                message: 'No valid fields to update' 
            });
        }
        
        updateFields.push('updated_at = CURRENT_TIMESTAMP');
        values.push(id);
        
        const query = `UPDATE channels SET ${updateFields.join(', ')} WHERE id = ?`;
        
        await pool.execute(query, values);
        
        const [channels] = await pool.execute(
            'SELECT * FROM channels WHERE id = ?',
            [id]
        );
        
        await logActivity(req, 'channel_update', `Updated channel: ${channels[0].name}`);
        
        res.json({
            success: true,
            message: 'Channel updated successfully',
            data: channels[0]
        });
        
    } catch (error) {
        console.error('Update channel error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to update channel' 
        });
    }
});

// حذف القناة
app.delete('/api/channels/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        
        // الحصول على معلومات القناة قبل الحذف
        const [channels] = await pool.execute(
            'SELECT name FROM channels WHERE id = ?',
            [id]
        );
        
        if (channels.length === 0) {
            return res.status(404).json({ 
                success: false, 
                message: 'Channel not found' 
            });
        }
        
        const channelName = channels[0].name;
        
        await pool.execute(
            'DELETE FROM channels WHERE id = ?',
            [id]
        );
        
        await logActivity(req, 'channel_delete', `Deleted channel: ${channelName}`);
        
        res.json({
            success: true,
            message: 'Channel deleted successfully'
        });
        
    } catch (error) {
        console.error('Delete channel error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to delete channel' 
        });
    }
});

// حذف جماعي للقنوات
app.post('/api/channels/bulk-delete', authenticateToken, async (req, res) => {
    const connection = await pool.getConnection();
    
    try {
        const { channelIds } = req.body;
        
        if (!Array.isArray(channelIds) || channelIds.length === 0) {
            await connection.release();
            return res.status(400).json({ 
                success: false, 
                message: 'No channels selected' 
            });
        }
        
        await connection.beginTransaction();
        
        try {
            // الحصول على أسماء القنوات للتسجيل
            const placeholders = channelIds.map(() => '?').join(',');
            const [channels] = await connection.execute(
                `SELECT name FROM channels WHERE id IN (${placeholders})`,
                channelIds
            );
            
            const channelNames = channels.map(c => c.name).join(', ');
            
            // حذف القنوات
            const [result] = await connection.execute(
                `DELETE FROM channels WHERE id IN (${placeholders})`,
                channelIds
            );
            
            await connection.commit();
            await connection.release();
            
            await logActivity(req, 'channel_bulk_delete', `Deleted ${result.affectedRows} channels: ${channelNames.substring(0, 200)}`);
            
            res.json({
                success: true,
                message: `${result.affectedRows} channels deleted successfully`
            });
            
        } catch (error) {
            await connection.rollback();
            await connection.release();
            throw error;
        }
        
    } catch (error) {
        console.error('Bulk delete error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to delete channels' 
        });
    }
});

// ======================
// M3U IMPORT API
// ======================

// رفع ملف M3U
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
        
        // قراءة وتحليل الملف
        const fileContent = fs.readFileSync(filePath, 'utf8');
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
        
        // تخزين في الجلسة
        const importId = Date.now().toString();
        req.session.importData = { 
            importId, 
            channels: parsedChannels, 
            action 
        };
        
        await logActivity(req, 'm3u_upload', `Uploaded M3U file with ${parsedChannels.length} channels`);
        
        res.json({
            success: true,
            message: 'M3U file parsed successfully',
            importId,
            data: parsedChannels.slice(0, 50),
            total: parsedChannels.length,
            sampleCount: Math.min(50, parsedChannels.length)
        });
        
    } catch (error) {
        console.error('M3U upload error:', error);
        
        // تنظيف الملف إذا كان موجودًا
        if (req.file && fs.existsSync(req.file.path)) {
            try {
                fs.unlinkSync(req.file.path);
            } catch (unlinkError) {
                console.warn('Could not delete file after error:', unlinkError.message);
            }
        }
        
        res.status(500).json({ 
            success: false, 
            message: 'Failed to process M3U file' 
        });
    }
});

// تأكيد استيراد M3U
app.post('/api/import/m3u', authenticateToken, async (req, res) => {
    const connection = await pool.getConnection();
    
    try {
        const { importId, action = 'append' } = req.body;
        
        if (!req.session.importData || req.session.importData.importId !== importId) {
            await connection.release();
            return res.status(400).json({ 
                success: false, 
                message: 'Import session expired or invalid' 
            });
        }
        
        const { channels: parsedChannels } = req.session.importData;
        
        if (!parsedChannels || parsedChannels.length === 0) {
            await connection.release();
            return res.status(400).json({ 
                success: false, 
                message: 'No channels to import' 
            });
        }
        
        await connection.beginTransaction();
        
        try {
            if (action === 'replace') {
                await connection.execute('DELETE FROM channels');
                console.log('Cleared existing channels for replacement');
            }
            
            let importedCount = 0;
            let skippedCount = 0;
            let errorCount = 0;
            
            for (const channel of parsedChannels) {
                try {
                    // التحقق مما إذا كانت القناة موجودة مسبقًا (عن طريق URL)
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
                } catch (err) {
                    console.error('Error importing channel:', err.message);
                    errorCount++;
                }
            }
            
            await connection.commit();
            
            // مسح بيانات الجلسة
            delete req.session.importData;
            
            await logActivity(req, 'm3u_import', `Imported ${importedCount} channels from M3U (${action}), skipped ${skippedCount}, errors ${errorCount}`);
            
            const [countResult] = await connection.execute('SELECT COUNT(*) as total FROM channels');
            
            await connection.release();
            
            res.json({
                success: true,
                message: `Successfully imported ${importedCount} channels (${skippedCount} skipped, ${errorCount} errors)`,
                imported: importedCount,
                skipped: skippedCount,
                errors: errorCount,
                totalChannels: countResult[0].total
            });
            
        } catch (error) {
            await connection.rollback();
            await connection.release();
            throw error;
        }
        
    } catch (error) {
        console.error('Import error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to import channels' 
        });
    }
});

// دالة مساعدة لتحليل محتوى M3U
function parseM3UContent(content) {
    const channels = [];
    const lines = content.split('\n');
    let currentChannel = null;
    
    for (const line of lines) {
        const trimmedLine = line.trim();
        
        if (trimmedLine.startsWith('#EXTINF:')) {
            currentChannel = {
                name: 'Unknown Channel',
                url: '',
                category: 'General',
                logo: ''
            };
            
            // استخراج الاسم
            const nameStart = trimmedLine.indexOf(',') + 1;
            if (nameStart > 0 && nameStart < trimmedLine.length) {
                currentChannel.name = trimmedLine.substring(nameStart).trim();
                
                // إزالة السمات الإضافية من الاسم
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
            const logoMatch = trimmedLine.match(/tvg-logo="([^"]+)"/);
            if (logoMatch && logoMatch[1]) {
                currentChannel.logo = logoMatch[1].trim();
                if (currentChannel.logo.length > 500) {
                    currentChannel.logo = currentChannel.logo.substring(0, 500);
                }
            }
            
            // استخراج المجموعة/الفئة
            const groupMatch = trimmedLine.match(/group-title="([^"]+)"/);
            if (groupMatch && groupMatch[1]) {
                currentChannel.category = groupMatch[1].trim();
                if (currentChannel.category.length > 100) {
                    currentChannel.category = currentChannel.category.substring(0, 100);
                }
            }
            
        } else if (trimmedLine && !trimmedLine.startsWith('#') && currentChannel) {
            if (trimmedLine.startsWith('http://') || trimmedLine.startsWith('https://') || trimmedLine.includes('://')) {
                currentChannel.url = trimmedLine.trim();
                
                // التحقق من صحة URL
                if (currentChannel.url.length > 0 && currentChannel.name.length > 0) {
                    channels.push(currentChannel);
                }
                
                currentChannel = null;
            }
        }
    }
    
    return channels;
}

// ======================
// SUBSCRIPTION CODE API
// ======================

// إنشاء رموز اشتراك
app.post('/api/codes/generate', authenticateToken, [
    body('duration_days').isInt({ min: 1, max: 3650 }),
    body('quantity').isInt({ min: 1, max: 100 }),
    body('code_type').isIn(['premium', 'trial', 'promo']),
    body('notes').optional().trim()
], async (req, res) => {
    const connection = await pool.getConnection();
    
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            await connection.release();
            return res.status(400).json({ 
                success: false, 
                errors: errors.array() 
            });
        }
        
        const { duration_days, quantity, code_type, notes } = req.body;
        const generatedBy = req.user.username;
        const generatedCodes = [];
        
        await connection.beginTransaction();
        
        try {
            for (let i = 0; i < quantity; i++) {
                let code;
                let isUnique = false;
                let attempts = 0;
                
                // التأكد من أن الرمز فريد
                while (!isUnique && attempts < 10) {
                    code = generateSubscriptionCode();
                    const [existing] = await connection.execute(
                        'SELECT id FROM subscription_codes WHERE code = ?',
                        [code]
                    );
                    
                    if (existing.length === 0) {
                        isUnique = true;
                    }
                    attempts++;
                }
                
                if (!isUnique) {
                    throw new Error('Failed to generate unique code after 10 attempts');
                }
                
                const expiryDate = new Date();
                expiryDate.setDate(expiryDate.getDate() + duration_days);
                
                await connection.execute(
                    `INSERT INTO subscription_codes 
                    (id, code, duration_days, code_type, expiry_date, generated_by, notes) 
                    VALUES (?, ?, ?, ?, ?, ?, ?)`,
                    [uuidv4(), code, duration_days, code_type, expiryDate, generatedBy, notes || null]
                );
                
                generatedCodes.push({
                    code,
                    duration_days,
                    code_type,
                    expiry_date: expiryDate.toISOString(),
                    generated_by: generatedBy,
                    notes: notes || null
                });
            }
            
            await connection.commit();
            await connection.release();
            
            await logActivity(req, 'code_generate', `Generated ${quantity} ${code_type} codes (${duration_days} days)`);
            
            res.status(201).json({
                success: true,
                message: `${quantity} codes generated successfully`,
                data: generatedCodes
            });
            
        } catch (error) {
            await connection.rollback();
            await connection.release();
            throw error;
        }
        
    } catch (error) {
        console.error('Generate code error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to generate codes' 
        });
    }
});

// الحصول على جميع الرموز
app.get('/api/codes', authenticateToken, async (req, res) => {
    try {
        const { status, search, page = 1, limit = 50 } = req.query;
        
        // إصلاح: تحويل القيم القادمة من الرابط (Query Params) إلى أرقام صحيحة
        const limitNum = parseInt(limit, 10) || 50;
        const pageNum = parseInt(page, 10) || 1;
        const offset = (pageNum - 1) * limitNum;
        
        let query = `
            SELECT sc.* 
            FROM subscription_codes sc
            WHERE 1=1
        `;
        let params = [];
        
        if (status === 'active') {
            query += ' AND sc.is_used = FALSE AND sc.expiry_date > NOW()';
        } else if (status === 'used') {
            query += ' AND sc.is_used = TRUE';
        } else if (status === 'expired') {
            query += ' AND sc.expiry_date <= NOW()';
        }
        
        if (search) {
            query += ' AND (sc.code LIKE ? OR sc.generated_by LIKE ? OR sc.notes LIKE ?)';
            const searchTerm = `%${search}%`;
            params.push(searchTerm, searchTerm, searchTerm);
        }
        
        const countQuery = query.replace('SELECT sc.*', 'SELECT COUNT(*) as total');
        const [countResult] = await pool.execute(countQuery, params);
        const total = countResult[0].total;
        
        query += ' ORDER BY sc.created_at DESC LIMIT ? OFFSET ?';
        params.push(limitNum, offset);
        
        // إصلاح: استخدام query بدلاً من execute لضمان معالجة الأرقام بشكل صحيح
        const [codes] = await pool.query(query, params);
        
        // الحصول على الإحصائيات
        const [stats] = await pool.execute(`
            SELECT 
                COUNT(*) as total_codes,
                SUM(CASE WHEN is_used = FALSE AND expiry_date > NOW() THEN 1 ELSE 0 END) as active_codes,
                SUM(CASE WHEN is_used = TRUE THEN 1 ELSE 0 END) as used_codes,
                SUM(CASE WHEN expiry_date <= NOW() THEN 1 ELSE 0 END) as expired_codes
            FROM subscription_codes
        `);
        
        res.json({
            success: true,
            data: codes,
            pagination: {
                page: pageNum,
                limit: limitNum,
                total,
                pages: Math.ceil(total / limitNum)
            },
            statistics: stats[0]
        });
        
    } catch (error) {
        console.error('Get codes error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to fetch codes' 
        });
    }
});

// حذف الرمز
app.delete('/api/codes/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        
        // التحقق من وجود الرمز
        const [codes] = await pool.execute(
            'SELECT code FROM subscription_codes WHERE id = ?',
            [id]
        );
        
        if (codes.length === 0) {
            return res.status(404).json({ 
                success: false, 
                message: 'Code not found' 
            });
        }
        
        const code = codes[0].code;
        
        // حذف الرمز
        await pool.execute(
            'DELETE FROM subscription_codes WHERE id = ?',
            [id]
        );
        
        await logActivity(req, 'code_delete', `Deleted subscription code: ${code}`);
        
        res.json({
            success: true,
            message: 'Code deleted successfully'
        });
        
    } catch (error) {
        console.error('Delete code error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to delete code' 
        });
    }
});

// ======================
// SUBSCRIPTION API FOR FLUTTER APP
// ======================

// التحقق من رمز الاشتراك
app.post('/api/codes/validate', async (req, res) => {
    const connection = await pool.getConnection();
    
    try {
        const { code, device_id } = req.body;
        
        if (!code || !device_id) {
            await connection.release();
            return res.status(400).json({ 
                success: false, 
                message: 'Code and device ID are required' 
            });
        }
        
        const cleanCode = code.trim();
        
        // التحقق من تنسيق الرمز - يجب أن يكون 12 رقمًا
        if (!/^\d{12}$/.test(cleanCode)) {
            await connection.release();
            return res.json({
                success: true,
                valid: false,
                message: 'Invalid code format. Must be 12 digits.'
            });
        }
        
        await connection.beginTransaction();
        
        try {
            // البحث عن رمز صالح وغير مستخدم وغير منتهي الصلاحية
            const [codes] = await connection.execute(`
                SELECT * 
                FROM subscription_codes 
                WHERE code = ? 
                AND is_used = FALSE 
                AND expiry_date > NOW()
                FOR UPDATE
            `, [cleanCode]);
            
            if (codes.length === 0) {
                await connection.rollback();
                await connection.release();
                return res.json({
                    success: true,
                    valid: false,
                    message: 'Invalid or expired code'
                });
            }
            
            const subscriptionCode = codes[0];
            
            // التحقق مما إذا كان الجهاز لديه اشتراك نشط بالفعل
            const [existingSubs] = await connection.execute(`
                SELECT * FROM user_subscriptions 
                WHERE user_id = ? AND is_active = TRUE AND expires_at > NOW()
            `, [device_id]);
            
            if (existingSubs.length > 0) {
                await connection.rollback();
                await connection.release();
                return res.json({
                    success: true,
                    valid: false,
                    message: 'Device already has active subscription'
                });
            }
            
            // وضع علامة على الرمز كمستخدم
            await connection.execute(
                'UPDATE subscription_codes SET is_used = TRUE, used_by = ?, used_at = NOW() WHERE code = ?',
                [device_id, cleanCode]
            );
            
            // حساب تاريخ انتهاء الصلاحية
            const expiryDate = new Date();
            expiryDate.setDate(expiryDate.getDate() + subscriptionCode.duration_days);
            
            // إنشاء اشتراك المستخدم
            await connection.execute(
                `INSERT INTO user_subscriptions 
                (id, user_id, subscription_code, device_id, expires_at, is_active) 
                VALUES (?, ?, ?, ?, ?, TRUE)`,
                [uuidv4(), device_id, cleanCode, device_id, expiryDate]
            );
            
            // تحديث مستخدمي التطبيق
            await connection.execute(
                `INSERT INTO app_users (device_id, subscription_code, last_active) 
                VALUES (?, ?, NOW()) 
                ON DUPLICATE KEY UPDATE 
                subscription_code = VALUES(subscription_code),
                last_active = NOW()`,
                [device_id, cleanCode]
            );
            
            await connection.commit();
            await connection.release();
            
            res.json({
                success: true,
                valid: true,
                message: 'Subscription activated successfully',
                data: {
                    code: cleanCode,
                    duration_days: subscriptionCode.duration_days,
                    expiry_date: expiryDate.toISOString(),
                    activated_at: new Date().toISOString()
                }
            });
            
        } catch (error) {
            await connection.rollback();
            await connection.release();
            throw error;
        }
        
    } catch (error) {
        console.error('Validate code error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to validate code' 
        });
    }
});

// التحقق من حالة الاشتراك (للتطبيق)
app.post('/api/subscription/status', async (req, res) => {
    try {
        const { device_id } = req.body;
        
        if (!device_id) {
            return res.status(400).json({ 
                success: false, 
                message: 'Device ID is required' 
            });
        }
        
        // التحقق مما إذا كان الجهاز لديه اشتراك نشط
        const [subscriptions] = await pool.execute(`
            SELECT us.*, sc.duration_days, sc.code_type, sc.code
            FROM user_subscriptions us
            LEFT JOIN subscription_codes sc ON us.subscription_code = sc.code
            WHERE us.user_id = ? 
            AND us.is_active = TRUE
            ORDER BY us.expires_at DESC
            LIMIT 1
        `, [device_id]);
        
        if (subscriptions.length === 0) {
            return res.json({
                success: true,
                has_active_subscription: false,
                message: 'No active subscription found'
            });
        }
        
        const subscription = subscriptions[0];
        const expiryDate = new Date(subscription.expires_at);
        const now = new Date();
        const isActive = expiryDate > now;
        
        let remainingDays = 0;
        if (isActive) {
            const diffTime = Math.abs(expiryDate - now);
            remainingDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
        }
        
        res.json({
            success: true,
            has_active_subscription: isActive,
            data: {
                code: subscription.code || '',
                activated_at: subscription.activated_at ? subscription.activated_at.toISOString() : new Date().toISOString(),
                expires_at: subscription.expires_at.toISOString(),
                remaining_days: remainingDays,
                is_active: isActive,
                duration_days: subscription.duration_days || 30,
                code_type: subscription.code_type || 'premium'
            },
            message: isActive ? 'Active subscription found' : 'Subscription expired'
        });
        
    } catch (error) {
        console.error('Check subscription error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to check subscription status' 
        });
    }
});

// تفعيل الاشتراك (للتطبيق)
app.post('/api/subscription/activate', async (req, res) => {
    const connection = await pool.getConnection();
    
    try {
        const { code, device_id } = req.body;
        
        if (!code || !device_id) {
            await connection.release();
            return res.status(400).json({ 
                success: false, 
                message: 'Code and device ID are required' 
            });
        }
        
        const cleanCode = code.trim();
        
        // التحقق من تنسيق الرمز - يجب أن يكون 12 رقمًا
        if (!/^\d{12}$/.test(cleanCode)) {
            await connection.release();
            return res.json({
                success: false,
                activated: false,
                message: 'Invalid code format. Must be 12 digits.'
            });
        }
        
        await connection.beginTransaction();
        
        try {
            // أولاً التحقق من صحة الرمز
            const [codes] = await connection.execute(`
                SELECT * 
                FROM subscription_codes 
                WHERE code = ? 
                AND is_used = FALSE 
                AND expiry_date > NOW()
                FOR UPDATE
            `, [cleanCode]);
            
            if (codes.length === 0) {
                await connection.rollback();
                await connection.release();
                return res.json({
                    success: false,
                    activated: false,
                    message: 'Invalid or expired code'
                });
            }
            
            const subscriptionCode = codes[0];
            
            // التحقق مما إذا كان الجهاز لديه اشتراك نشط بالفعل
            const [existingSubs] = await connection.execute(`
                SELECT * FROM user_subscriptions 
                WHERE user_id = ? AND is_active = TRUE AND expires_at > NOW()
            `, [device_id]);
            
            if (existingSubs.length > 0) {
                await connection.rollback();
                await connection.release();
                return res.json({
                    success: false,
                    activated: false,
                    message: 'Device already has active subscription'
                });
            }
            
            // وضع علامة على الرمز كمستخدم
            await connection.execute(
                'UPDATE subscription_codes SET is_used = TRUE, used_by = ?, used_at = NOW() WHERE code = ?',
                [device_id, cleanCode]
            );
            
            // حساب تاريخ انتهاء الصلاحية
            const expiryDate = new Date();
            expiryDate.setDate(expiryDate.getDate() + subscriptionCode.duration_days);
            
            // إنشاء اشتراك المستخدم
            await connection.execute(
                `INSERT INTO user_subscriptions 
                (id, user_id, subscription_code, device_id, expires_at, is_active) 
                VALUES (?, ?, ?, ?, ?, TRUE)`,
                [uuidv4(), device_id, cleanCode, device_id, expiryDate]
            );
            
            // تحديث مستخدمي التطبيق
            await connection.execute(
                `INSERT INTO app_users (device_id, subscription_code, last_active) 
                VALUES (?, ?, NOW()) 
                ON DUPLICATE KEY UPDATE 
                subscription_code = VALUES(subscription_code),
                last_active = NOW()`,
                [device_id, cleanCode]
            );
            
            await connection.commit();
            await connection.release();
            
            res.json({
                success: true,
                activated: true,
                message: 'Subscription activated successfully',
                data: {
                    code: cleanCode,
                    duration_days: subscriptionCode.duration_days,
                    expiry_date: expiryDate.toISOString(),
                    activated_at: new Date().toISOString(),
                    remaining_days: subscriptionCode.duration_days
                }
            });
            
        } catch (error) {
            await connection.rollback();
            await connection.release();
            throw error;
        }
        
    } catch (error) {
        console.error('Activate subscription error:', error);
        res.status(500).json({ 
            success: false,
            activated: false,
            message: 'Failed to activate subscription'
        });
    }
});

// ======================
// DASHBOARD API
// ======================

// الحصول على إحصائيات لوحة التحكم
app.get('/api/dashboard/stats', authenticateToken, async (req, res) => {
    try {
        // الحصول على إحصائيات القنوات
        const [channelResult] = await pool.execute('SELECT COUNT(*) as total FROM channels');
        
        // الحصول على إحصائيات الرموز
        const [codeStats] = await pool.execute(`
            SELECT 
                COUNT(*) as total_codes,
                SUM(CASE WHEN is_used = FALSE AND expiry_date > NOW() THEN 1 ELSE 0 END) as active_codes,
                SUM(CASE WHEN is_used = TRUE THEN 1 ELSE 0 END) as used_codes
            FROM subscription_codes
        `);
        
        // الحصول على إحصائيات المستخدمين
        const [userStats] = await pool.execute(`
            SELECT 
                COUNT(DISTINCT user_id) as active_users,
                COUNT(*) as total_subscriptions
            FROM user_subscriptions 
            WHERE expires_at > NOW() AND is_active = TRUE
        `);
        
        // الحصول على النشاطات الأخيرة
        const [activities] = await pool.execute(`
            SELECT al.*, au.username as admin_name
            FROM activity_logs al
            LEFT JOIN admin_users au ON al.admin_id = au.id
            ORDER BY al.created_at DESC
            LIMIT 10
        `);
        
        // الحصول على فئات القنوات
        const [categories] = await pool.execute(`
            SELECT category, COUNT(*) as count 
            FROM channels 
            WHERE category IS NOT NULL AND category != ''
            GROUP BY category 
            ORDER BY count DESC
            LIMIT 10
        `);
        
        // الحصول على مستخدمي التطبيق النشطين
        const [recentUsers] = await pool.execute(`
            SELECT device_id, last_active 
            FROM app_users 
            WHERE last_active > DATE_SUB(NOW(), INTERVAL 7 DAY)
            ORDER BY last_active DESC
            LIMIT 10
        `);
        
        res.json({
            success: true,
            data: {
                channels: {
                    total: channelResult[0].total,
                    categories: categories
                },
                codes: codeStats[0],
                users: {
                    active: userStats[0].active_users || 0,
                    total_subscriptions: userStats[0].total_subscriptions || 0,
                    recent_users: recentUsers
                },
                recent_activities: activities
            }
        });
        
    } catch (error) {
        console.error('Dashboard stats error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to load dashboard statistics' 
        });
    }
});

// ======================
// APP API (For Flutter App)
// ======================

// الحصول على القنوات للتطبيق (نقطة نهاية عامة)
app.get('/api/app/channels', async (req, res) => {
    try {
        const { category } = req.query;
        
        let query = 'SELECT id, name, url, category, logo_url FROM channels WHERE is_active = TRUE';
        let params = [];
        
        if (category && category !== 'All' && category !== '') {
            query += ' AND category = ?';
            params.push(category);
        }
        
        query += ' ORDER BY name';
        
        const [channels] = await pool.execute(query, params);
        
        // تنسيق القنوات للتطبيق
        const formattedChannels = channels.map(channel => ({
            id: channel.id,
            name: channel.name || 'Unknown Channel',
            url: channel.url || '',
            category: channel.category || 'General',
            logo_url: channel.logo_url || '',
            is_active: true
        }));
        
        // الحصول على الفئات للتصفية
        const [categoriesResult] = await pool.execute(
            'SELECT DISTINCT category FROM channels WHERE is_active = TRUE AND category IS NOT NULL AND category != "" ORDER BY category'
        );
        
        const categories = categoriesResult.map(c => c.category);
        
        res.json({
            success: true,
            channels: formattedChannels,
            categories: categories,
            total: formattedChannels.length,
            timestamp: new Date().toISOString()
        });
        
    } catch (error) {
        console.error('App channels error:', error);
        res.status(500).json({ 
            success: false, 
            channels: [],
            categories: [],
            message: 'Failed to load channels'
        });
    }
});

// الحصول على إعدادات التطبيق
app.get('/api/app/settings', async (req, res) => {
    try {
        const [settings] = await pool.execute(
            'SELECT setting_key, setting_value FROM playlist_settings'
        );
        
        const settingsObj = {};
        settings.forEach(setting => {
            settingsObj[setting.setting_key] = setting.setting_value;
        });
        
        // إضافة قيم افتراضية إذا كانت مفقودة
        settingsObj.app_name = settingsObj.app_name || 'Watch Me Premium';
        settingsObj.company_name = settingsObj.company_name || 'Watch Me Streaming';
        settingsObj.support_email = settingsObj.support_email || 'support@watchme.com';
        settingsObj.version = settingsObj.version || '1.0.0';
        
        res.json({
            success: true,
            settings: settingsObj,
            server_time: new Date().toISOString()
        });
        
    } catch (error) {
        console.error('App settings error:', error);
        res.status(500).json({ 
            success: false, 
            settings: {},
            message: 'Failed to load settings'
        });
    }
});

// دالة مساعدة لإنشاء رمز اشتراك
function generateSubscriptionCode() {
    // إنشاء رمز رقمي مكون من 12 رقمًا
    let code = '';
    for (let i = 0; i < 12; i++) {
        code += Math.floor(Math.random() * 10); // توليد رقم عشوائي من 0-9
    }
    return code;
}

// ======================
// ERROR HANDLING
// ======================

// معالج 404
app.use((req, res) => {
    res.status(404).json({ 
        success: false, 
        message: 'API endpoint not found',
        path: req.path,
        method: req.method
    });
});

// معالج الأخطاء العام
app.use((err, req, res, next) => {
    console.error('❌ Global error:', err);
    
    // التعامل مع أخطاء محددة
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
    
    // أخطاء JWT
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
    
    // استجابة الخطأ الافتراضية
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
            console.log(`👑 Admin panel: http://localhost:${PORT}/index.html`);
            console.log(`📱 Flutter app API: http://localhost:${PORT}/api/app/channels`);
            console.log(`🎯 Subscription API: http://localhost:${PORT}/api/subscription/status`);
            console.log(`🔐 Admin login: http://localhost:${PORT}/index.html (PIN: 123456789)`);
            console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
            console.log(`🌐 CORS: Configured for multiple origins`);
            console.log(`🗄️ Database: ${process.env.DB_NAME || 'railway'}`);
            
            // معلومات مفيدة للنشر
            if (process.env.NODE_ENV === 'production') {
                console.log(`⚡ Production mode enabled`);
                console.log(`🔒 Trust proxy: Enabled`);
                console.log(`🍪 Secure cookies: Enabled`);
            }
        });
        
        // معالجة إغلاق الخادم بشكل أنيق
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
