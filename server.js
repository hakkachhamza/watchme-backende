const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const { body, validationResult } = require('express-validator');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();

// Initialize Express app
const app = express();

// حل مشكلة الـ Proxy في Railway - ثقة كاملة
app.set('trust proxy', 1);

// Session middleware - إصلاح كامل للعمل مع Netlify + Railway
const sessionConfig = {
    secret: process.env.SESSION_SECRET || 'watchme-secret-key-2024-change-in-production',
    resave: true, // تغيير مهم
    saveUninitialized: true, // تغيير مهم
    proxy: true, // مهم لـ Railway
    name: 'watchme.sid',
    store: new session.MemoryStore(),
    cookie: {
        secure: true, // يجب أن يكون true في الإنتاج
        sameSite: 'none', // هذا هو الحل السحري للـ Cross-domain
        maxAge: 30 * 60 * 1000, // 30 دقيقة
        httpOnly: true,
        path: '/',
        // لا تحدد domain لتسمح للكوكيز بالعمل على جميع subdomains
    }
};

// في حالة التطوير، استخدم إعدادات مختلفة
if (process.env.NODE_ENV === 'development') {
    sessionConfig.cookie.secure = false;
    sessionConfig.cookie.sameSite = 'lax';
}

app.use(session(sessionConfig));

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
        
        // السماح بطلبات بدون أصل (مثل curl)
        if (!origin) {
            return callback(null, true);
        }
        
        // التحقق من الأصل
        const isAllowed = allowedOrigins.some(allowed => {
            if (allowed.includes('*')) {
                const domain = allowed.replace('*.', '');
                return origin.endsWith(domain);
            }
            return allowed === origin;
        });
        
        if (isAllowed) {
            callback(null, true);
        } else {
            console.log('CORS Blocked Origin:', origin);
            callback(new Error('Not allowed by CORS'));
        }
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin', 'x-csrf-token'],
    exposedHeaders: ['Content-Disposition'],
    credentials: true, // مهم جداً للسماح بإرسال الكوكيز
    preflightContinue: false,
    optionsSuccessStatus: 204,
    maxAge: 86400 // 24 ساعة
};

app.use(cors(corsOptions));

// Handle preflight requests بشكل صريح
app.options('*', cors(corsOptions));

// Middleware لإضافة رؤوس CORS في كل استجابة
app.use((req, res, next) => {
    const origin = req.headers.origin;
    if (origin && (origin.includes('netlify.app') || origin.includes('localhost'))) {
        res.header('Access-Control-Allow-Origin', origin);
    }
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
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
    limit: '10mb'
}));
app.use(express.urlencoded({ 
    extended: true, 
    limit: '10mb'
}));

// إنشاء مجلد uploads
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
    console.log(`✅ Created uploads directory at: ${uploadDir}`);
}

// Static files
app.use(express.static(path.join(__dirname, 'public'), {
    maxAge: '1d',
    setHeaders: (res, filePath) => {
        if (filePath.endsWith('.html')) {
            res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
        }
    }
}));

// File upload configuration
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, uploadDir);
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const ext = path.extname(file.originalname).toLowerCase();
        const name = path.basename(file.originalname, ext)
            .replace(/\s+/g, '_')
            .replace(/[^a-zA-Z0-9_]/g, '')
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
        const allowedExtensions = ['.m3u', '.m3u8'];
        const ext = path.extname(file.originalname).toLowerCase();
        
        if (allowedExtensions.includes(ext)) {
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
        const dbConfig = {
            host: process.env.DB_HOST || 'localhost',
            user: process.env.DB_USER || 'root',
            password: process.env.DB_PASSWORD || '',
            database: process.env.DB_NAME || 'watchme',
            port: process.env.DB_PORT || 3306,
            waitForConnections: true,
            connectionLimit: 10,
            queueLimit: 0,
            enableKeepAlive: true,
            keepAliveInitialDelay: 0
        };
        
        console.log('Connecting to database...');
        
        pool = mysql.createPool(dbConfig);
        
        // Test connection
        const connection = await pool.getConnection();
        console.log('✅ Database connected successfully');
        connection.release();
        
        await initializeDatabase();
        
    } catch (error) {
        console.error('❌ Database connection failed:', error.message);
        console.log('Retrying in 5 seconds...');
        setTimeout(connectDB, 5000);
    }
}

// Initialize database tables
async function initializeDatabase() {
    try {
        const tables = [
            `CREATE TABLE IF NOT EXISTS admin_users (
                id INT PRIMARY KEY AUTO_INCREMENT,
                username VARCHAR(100) UNIQUE NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                pin_code VARCHAR(20) NOT NULL,
                role ENUM('admin', 'super_admin') DEFAULT 'admin',
                is_active BOOLEAN DEFAULT TRUE,
                last_login DATETIME,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            )`,
            
            `CREATE TABLE IF NOT EXISTS channels (
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
            )`,
            
            `CREATE TABLE IF NOT EXISTS subscription_codes (
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
            )`,
            
            `CREATE TABLE IF NOT EXISTS user_subscriptions (
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
            )`,
            
            `CREATE TABLE IF NOT EXISTS activity_logs (
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
            )`,
            
            `CREATE TABLE IF NOT EXISTS playlist_settings (
                id INT PRIMARY KEY AUTO_INCREMENT,
                setting_key VARCHAR(100) UNIQUE NOT NULL,
                setting_value TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            )`,
            
            `CREATE TABLE IF NOT EXISTS app_users (
                id INT PRIMARY KEY AUTO_INCREMENT,
                device_id VARCHAR(255) UNIQUE NOT NULL,
                subscription_code VARCHAR(50),
                last_active DATETIME,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                INDEX idx_device_id (device_id)
            )`
        ];
        
        for (const tableSql of tables) {
            await pool.execute(tableSql);
        }
        
        // Check if admin exists
        const [adminExists] = await pool.execute(
            'SELECT id FROM admin_users WHERE username = ?',
            ['admin']
        );
        
        if (adminExists.length === 0) {
            await pool.execute(
                'INSERT INTO admin_users (username, email, pin_code, role) VALUES (?, ?, ?, ?)',
                ['admin', 'admin@watchme.com', '123456789', 'super_admin']
            );
            console.log('✅ Default admin user created');
        }
        
        // Default settings
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
        
        console.log('✅ Database initialized successfully');
        
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
        
        const decoded = jwt.verify(
            token, 
            process.env.JWT_SECRET || 'watchme-jwt-secret-2024-change-this-in-production'
        );
        
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

// Activity logging middleware
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

// Health check with session info
app.get('/api/health', (req, res) => {
    res.json({
        success: true,
        message: 'Server is running',
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development',
        database: pool ? 'connected' : 'disconnected',
        session: {
            id: req.sessionID,
            hasImportData: !!req.session.importData,
            cookie: req.session.cookie
        }
    });
});

// Admin login
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
        
        // Update last login
        await pool.execute(
            'UPDATE admin_users SET last_login = NOW() WHERE id = ?',
            [admin.id]
        );
        
        // Create JWT token
        const token = jwt.sign(
            { 
                userId: admin.id, 
                username: admin.username,
                role: admin.role 
            },
            process.env.JWT_SECRET || 'watchme-jwt-secret-2024-change-this-in-production',
            { expiresIn: process.env.JWT_EXPIRES_IN || '24h' }
        );
        
        // Log activity
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
// CHANNEL MANAGEMENT
// ======================

// Get all channels
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
            query += ' AND (name LIKE ? OR category LIKE ?)';
            const searchTerm = `%${search}%`;
            params.push(searchTerm, searchTerm);
        }
        
        // Get total count
        const countQuery = query.replace('SELECT *', 'SELECT COUNT(*) as total');
        const [countResult] = await pool.execute(countQuery, params);
        const total = countResult[0].total;
        
        // Get paginated data
        query += ' ORDER BY name LIMIT ? OFFSET ?';
        params.push(limitNum, offset);
        
        const [channels] = await pool.execute(query, params);
        
        // Get unique categories
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

// Add new channel
app.post('/api/channels', authenticateToken, [
    body('name').notEmpty().trim(),
    body('url').notEmpty().trim()
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
        const channelId = uuidv4();
        
        await pool.execute(
            'INSERT INTO channels (id, name, url, category, logo_url) VALUES (?, ?, ?, ?, ?)',
            [channelId, name, url, category, logo || null]
        );
        
        await logActivity(req, 'channel_add', `Added channel: ${name}`);
        
        res.status(201).json({
            success: true,
            message: 'Channel added successfully'
        });
        
    } catch (error) {
        console.error('Add channel error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to add channel' 
        });
    }
});

// Update channel
app.put('/api/channels/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { name, url, category, logo, is_active } = req.body;
        
        const updateFields = [];
        const values = [];
        
        if (name !== undefined) {
            updateFields.push('name = ?');
            values.push(name);
        }
        
        if (url !== undefined) {
            updateFields.push('url = ?');
            values.push(url);
        }
        
        if (category !== undefined) {
            updateFields.push('category = ?');
            values.push(category);
        }
        
        if (logo !== undefined) {
            updateFields.push('logo_url = ?');
            values.push(logo);
        }
        
        if (is_active !== undefined) {
            updateFields.push('is_active = ?');
            values.push(is_active);
        }
        
        if (updateFields.length === 0) {
            return res.status(400).json({ 
                success: false, 
                message: 'No fields to update' 
            });
        }
        
        values.push(id);
        
        const query = `UPDATE channels SET ${updateFields.join(', ')}, updated_at = CURRENT_TIMESTAMP WHERE id = ?`;
        
        await pool.execute(query, values);
        
        await logActivity(req, 'channel_update', `Updated channel: ${id}`);
        
        res.json({
            success: true,
            message: 'Channel updated successfully'
        });
        
    } catch (error) {
        console.error('Update channel error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to update channel' 
        });
    }
});

// Delete channel
app.delete('/api/channels/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        
        await pool.execute('DELETE FROM channels WHERE id = ?', [id]);
        
        await logActivity(req, 'channel_delete', `Deleted channel: ${id}`);
        
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

// Bulk delete channels
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
            const placeholders = channelIds.map(() => '?').join(',');
            const [result] = await connection.execute(
                `DELETE FROM channels WHERE id IN (${placeholders})`,
                channelIds
            );
            
            await connection.commit();
            await connection.release();
            
            await logActivity(req, 'channel_bulk_delete', `Deleted ${result.affectedRows} channels`);
            
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
// M3U IMPORT - FIXED VERSION
// ======================

// Parse M3U content function
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
            
            // Extract name
            const nameStart = trimmedLine.indexOf(',') + 1;
            if (nameStart > 0) {
                currentChannel.name = trimmedLine.substring(nameStart).trim();
                
                // Clean name
                currentChannel.name = currentChannel.name.replace(/["']/g, '').trim();
                if (currentChannel.name.length > 200) {
                    currentChannel.name = currentChannel.name.substring(0, 200);
                }
            }
            
            // Extract logo
            const logoMatch = trimmedLine.match(/tvg-logo="([^"]+)"/i);
            if (logoMatch) {
                currentChannel.logo = logoMatch[1].trim();
            }
            
            // Extract category
            const groupMatch = trimmedLine.match(/group-title="([^"]+)"/i);
            if (groupMatch) {
                currentChannel.category = groupMatch[1].trim();
            }
            
        } else if (trimmedLine && !trimmedLine.startsWith('#') && currentChannel) {
            if (trimmedLine.startsWith('http')) {
                currentChannel.url = trimmedLine.trim();
                
                if (currentChannel.url && currentChannel.name) {
                    channels.push(currentChannel);
                }
                
                currentChannel = null;
            }
        }
    }
    
    return channels;
}

// Upload M3U file
app.post('/api/upload/m3u', authenticateToken, upload.single('m3uFile'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ 
                success: false, 
                message: 'No file uploaded' 
            });
        }
        
        console.log('File uploaded:', req.file.originalname);
        
        // Read and parse file
        const fileContent = fs.readFileSync(req.file.path, 'utf8');
        const parsedChannels = parseM3UContent(fileContent);
        
        // Clean up uploaded file
        try {
            fs.unlinkSync(req.file.path);
        } catch (error) {
            console.warn('Could not delete file:', error.message);
        }
        
        if (parsedChannels.length === 0) {
            return res.status(400).json({ 
                success: false, 
                message: 'No valid channels found in M3U file' 
            });
        }
        
        // Store in session with unique ID
        const importId = uuidv4();
        req.session.importData = {
            importId,
            channels: parsedChannels,
            action: req.body.action || 'append',
            timestamp: Date.now(),
            filename: req.file.originalname,
            channelCount: parsedChannels.length
        };
        
        // Save session explicitly
        req.session.save((err) => {
            if (err) {
                console.error('Session save error:', err);
            }
        });
        
        await logActivity(req, 'm3u_upload', `Uploaded M3U file with ${parsedChannels.length} channels`);
        
        res.json({
            success: true,
            message: `Successfully parsed ${parsedChannels.length} channels`,
            importId,
            channelCount: parsedChannels.length,
            sample: parsedChannels.slice(0, 5),
            sessionInfo: {
                sessionId: req.sessionID,
                expiresIn: '30 minutes'
            }
        });
        
    } catch (error) {
        console.error('Upload M3U error:', error);
        
        // Clean up file if exists
        if (req.file && fs.existsSync(req.file.path)) {
            try {
                fs.unlinkSync(req.file.path);
            } catch (unlinkError) {
                console.warn('Could not delete file:', unlinkError.message);
            }
        }
        
        res.status(500).json({ 
            success: false, 
            message: 'Failed to process M3U file' 
        });
    }
});

// Session validation middleware
const validateImportSession = (req, res, next) => {
    const { importId } = req.body;
    
    console.log('Validating session:', {
        sessionId: req.sessionID,
        hasImportData: !!req.session.importData,
        requestedImportId: importId,
        storedImportId: req.session.importData?.importId
    });
    
    if (!req.session.importData) {
        return res.status(400).json({ 
            success: false, 
            message: 'No import session found. Please upload the file again.',
            sessionId: req.sessionID
        });
    }
    
    if (!importId || req.session.importData.importId !== importId) {
        return res.status(400).json({ 
            success: false, 
            message: 'Invalid import session. Please restart the import process.'
        });
    }
    
    // Check if session is expired (30 minutes)
    if (Date.now() - req.session.importData.timestamp > 30 * 60 * 1000) {
        delete req.session.importData;
        return res.status(400).json({ 
            success: false, 
            message: 'Import session expired. Please upload the file again.' 
        });
    }
    
    next();
};

// Confirm M3U import
app.post('/api/import/m3u', authenticateToken, validateImportSession, async (req, res) => {
    const connection = await pool.getConnection();
    
    try {
        const { importId, action = 'append' } = req.body;
        const sessionData = req.session.importData;
        
        if (!sessionData || !sessionData.channels) {
            await connection.release();
            return res.status(400).json({ 
                success: false, 
                message: 'No import data found in session' 
            });
        }
        
        const channels = sessionData.channels;
        
        console.log(`Starting import of ${channels.length} channels with action: ${action}`);
        
        await connection.beginTransaction();
        
        try {
            // Clear existing channels if replace action
            if (action === 'replace') {
                await connection.execute('DELETE FROM channels');
                console.log('Cleared existing channels');
            }
            
            let imported = 0;
            let skipped = 0;
            let errors = 0;
            
            for (const channel of channels) {
                try {
                    // Check if channel already exists (by URL)
                    const [existing] = await connection.execute(
                        'SELECT id FROM channels WHERE url = ?',
                        [channel.url]
                    );
                    
                    if (existing.length === 0 || action === 'replace') {
                        // If exists in replace mode, delete first
                        if (existing.length > 0 && action === 'replace') {
                            await connection.execute('DELETE FROM channels WHERE id = ?', [existing[0].id]);
                        }
                        
                        await connection.execute(
                            'INSERT INTO channels (id, name, url, category, logo_url) VALUES (?, ?, ?, ?, ?)',
                            [uuidv4(), channel.name, channel.url, channel.category, channel.logo || null]
                        );
                        imported++;
                    } else {
                        skipped++;
                    }
                } catch (error) {
                    console.error('Error importing channel:', error.message);
                    errors++;
                }
            }
            
            await connection.commit();
            
            // Clear session data after successful import
            delete req.session.importData;
            req.session.save((err) => {
                if (err) {
                    console.error('Error saving session after import:', err);
                }
            });
            
            await logActivity(req, 'm3u_import', `Imported ${imported} channels (${action}), skipped ${skipped}, errors ${errors}`);
            
            const [countResult] = await connection.execute('SELECT COUNT(*) as total FROM channels');
            
            await connection.release();
            
            res.json({
                success: true,
                message: `Import completed successfully`,
                summary: {
                    imported,
                    skipped,
                    errors,
                    totalChannels: countResult[0].total
                }
            });
            
        } catch (error) {
            await connection.rollback();
            await connection.release();
            throw error;
        }
        
    } catch (error) {
        console.error('Import M3U error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to import channels' 
        });
    }
});

// Check import session status
app.get('/api/import/session/status', authenticateToken, (req, res) => {
    res.json({
        success: true,
        session: {
            id: req.sessionID,
            hasImportData: !!req.session.importData,
            importData: req.session.importData ? {
                importId: req.session.importData.importId,
                filename: req.session.importData.filename,
                channelCount: req.session.importData.channelCount,
                timestamp: new Date(req.session.importData.timestamp).toISOString(),
                age: Math.floor((Date.now() - req.session.importData.timestamp) / 1000) + ' seconds'
            } : null
        }
    });
});

// Clear import session
app.delete('/api/import/session', authenticateToken, (req, res) => {
    delete req.session.importData;
    req.session.save((err) => {
        if (err) {
            console.error('Error saving session after clear:', err);
        }
    });
    
    res.json({
        success: true,
        message: 'Import session cleared'
    });
});

// ======================
// SUBSCRIPTION CODES
// ======================

// Generate subscription codes
app.post('/api/codes/generate', authenticateToken, [
    body('duration_days').isInt({ min: 1 }),
    body('quantity').isInt({ min: 1, max: 100 })
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false, 
                errors: errors.array() 
            });
        }
        
        const { duration_days, quantity, code_type = 'premium', notes } = req.body;
        const generatedBy = req.user.username;
        const codes = [];
        
        for (let i = 0; i < quantity; i++) {
            const code = Array.from({length: 12}, () => Math.floor(Math.random() * 10)).join('');
            const expiryDate = new Date();
            expiryDate.setDate(expiryDate.getDate() + duration_days);
            
            await pool.execute(
                'INSERT INTO subscription_codes (id, code, duration_days, code_type, expiry_date, generated_by, notes) VALUES (?, ?, ?, ?, ?, ?, ?)',
                [uuidv4(), code, duration_days, code_type, expiryDate, generatedBy, notes || null]
            );
            
            codes.push({
                code,
                duration_days,
                expiry_date: expiryDate.toISOString(),
                code_type
            });
        }
        
        await logActivity(req, 'code_generate', `Generated ${quantity} ${code_type} codes`);
        
        res.status(201).json({
            success: true,
            message: `${quantity} codes generated successfully`,
            data: codes
        });
        
    } catch (error) {
        console.error('Generate codes error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to generate codes' 
        });
    }
});

// Get all codes
app.get('/api/codes', authenticateToken, async (req, res) => {
    try {
        const { status, page = 1, limit = 50 } = req.query;
        
        const limitNum = parseInt(limit, 10) || 50;
        const pageNum = parseInt(page, 10) || 1;
        const offset = (pageNum - 1) * limitNum;
        
        let query = 'SELECT * FROM subscription_codes WHERE 1=1';
        let params = [];
        
        if (status === 'active') {
            query += ' AND is_used = FALSE AND expiry_date > NOW()';
        } else if (status === 'used') {
            query += ' AND is_used = TRUE';
        } else if (status === 'expired') {
            query += ' AND expiry_date <= NOW()';
        }
        
        // Get total count
        const countQuery = query.replace('SELECT *', 'SELECT COUNT(*) as total');
        const [countResult] = await pool.execute(countQuery, params);
        const total = countResult[0].total;
        
        // Get paginated data
        query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
        params.push(limitNum, offset);
        
        const [codes] = await pool.execute(query, params);
        
        // Get statistics
        const [stats] = await pool.execute(`
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN is_used = FALSE AND expiry_date > NOW() THEN 1 ELSE 0 END) as active,
                SUM(CASE WHEN is_used = TRUE THEN 1 ELSE 0 END) as used,
                SUM(CASE WHEN expiry_date <= NOW() THEN 1 ELSE 0 END) as expired
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

// Delete code
app.delete('/api/codes/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        
        await pool.execute('DELETE FROM subscription_codes WHERE id = ?', [id]);
        
        await logActivity(req, 'code_delete', `Deleted subscription code: ${id}`);
        
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
// APP SUBSCRIPTION API
// ======================

// Validate and activate subscription code
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
        
        const cleanCode = code.trim().replace(/\s/g, '');
        
        if (!/^\d{12}$/.test(cleanCode)) {
            await connection.release();
            return res.json({
                success: false,
                valid: false,
                message: 'Invalid code format'
            });
        }
        
        await connection.beginTransaction();
        
        try {
            // Check if code is valid
            const [codes] = await connection.execute(
                'SELECT * FROM subscription_codes WHERE code = ? AND is_used = FALSE AND expiry_date > NOW()',
                [cleanCode]
            );
            
            if (codes.length === 0) {
                await connection.rollback();
                await connection.release();
                return res.json({
                    success: false,
                    valid: false,
                    message: 'Invalid or expired code'
                });
            }
            
            const subscriptionCode = codes[0];
            
            // Check if device already has active subscription
            const [existing] = await connection.execute(
                'SELECT * FROM user_subscriptions WHERE device_id = ? AND expires_at > NOW() AND is_active = TRUE',
                [device_id]
            );
            
            if (existing.length > 0) {
                await connection.rollback();
                await connection.release();
                return res.json({
                    success: false,
                    valid: false,
                    message: 'Device already has active subscription'
                });
            }
            
            // Mark code as used
            await connection.execute(
                'UPDATE subscription_codes SET is_used = TRUE, used_by = ?, used_at = NOW() WHERE code = ?',
                [device_id, cleanCode]
            );
            
            // Calculate expiry date
            const expiryDate = new Date();
            expiryDate.setDate(expiryDate.getDate() + subscriptionCode.duration_days);
            
            // Create subscription
            await connection.execute(
                'INSERT INTO user_subscriptions (id, user_id, subscription_code, device_id, expires_at) VALUES (?, ?, ?, ?, ?)',
                [uuidv4(), device_id, cleanCode, device_id, expiryDate]
            );
            
            // Update app users
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
                    expiry_date: expiryDate.toISOString()
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
            message: 'Failed to activate subscription' 
        });
    }
});

// Check subscription status
app.post('/api/subscription/status', async (req, res) => {
    try {
        const { device_id } = req.body;
        
        if (!device_id) {
            return res.status(400).json({ 
                success: false, 
                message: 'Device ID is required' 
            });
        }
        
        const [subscription] = await pool.execute(
            `SELECT us.*, sc.duration_days, sc.code_type 
             FROM user_subscriptions us
             LEFT JOIN subscription_codes sc ON us.subscription_code = sc.code
             WHERE us.device_id = ? AND us.expires_at > NOW() AND us.is_active = TRUE
             ORDER BY us.expires_at DESC
             LIMIT 1`,
            [device_id]
        );
        
        if (subscription.length === 0) {
            return res.json({
                success: true,
                has_subscription: false,
                message: 'No active subscription found'
            });
        }
        
        const sub = subscription[0];
        const expiryDate = new Date(sub.expires_at);
        const now = new Date();
        const remainingDays = Math.ceil((expiryDate - now) / (1000 * 60 * 60 * 24));
        
        res.json({
            success: true,
            has_subscription: true,
            data: {
                expiry_date: expiryDate.toISOString(),
                remaining_days: remainingDays,
                duration_days: sub.duration_days,
                code_type: sub.code_type
            }
        });
        
    } catch (error) {
        console.error('Check subscription error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to check subscription status' 
        });
    }
});

// ======================
// APP CHANNELS API
// ======================

// Get channels for app
app.get('/api/app/channels', async (req, res) => {
    try {
        const { category } = req.query;
        
        let query = 'SELECT id, name, url, category, logo_url FROM channels WHERE is_active = TRUE';
        let params = [];
        
        if (category && category !== 'All') {
            query += ' AND category = ?';
            params.push(category);
        }
        
        query += ' ORDER BY name';
        
        const [channels] = await pool.execute(query, params);
        
        // Get categories
        const [categories] = await pool.execute(
            'SELECT DISTINCT category FROM channels WHERE is_active = TRUE AND category IS NOT NULL AND category != "" ORDER BY category'
        );
        
        res.json({
            success: true,
            channels: channels,
            categories: categories.map(c => c.category),
            total: channels.length
        });
        
    } catch (error) {
        console.error('App channels error:', error);
        res.status(500).json({ 
            success: false, 
            channels: [],
            message: 'Failed to load channels'
        });
    }
});

// Get app settings
app.get('/api/app/settings', async (req, res) => {
    try {
        const [settings] = await pool.execute(
            'SELECT setting_key, setting_value FROM playlist_settings'
        );
        
        const settingsObj = {};
        settings.forEach(setting => {
            settingsObj[setting.setting_key] = setting.setting_value;
        });
        
        res.json({
            success: true,
            settings: settingsObj
        });
        
    } catch (error) {
        console.error('App settings error:', error);
        res.status(500).json({ 
            success: false, 
            settings: {}
        });
    }
});

// ======================
// DASHBOARD API
// ======================

// Get dashboard stats
app.get('/api/dashboard/stats', authenticateToken, async (req, res) => {
    try {
        // Channel stats
        const [channelStats] = await pool.execute('SELECT COUNT(*) as total FROM channels');
        
        // Code stats
        const [codeStats] = await pool.execute(`
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN is_used = FALSE AND expiry_date > NOW() THEN 1 ELSE 0 END) as active,
                SUM(CASE WHEN is_used = TRUE THEN 1 ELSE 0 END) as used
            FROM subscription_codes
        `);
        
        // User stats
        const [userStats] = await pool.execute(`
            SELECT COUNT(DISTINCT device_id) as active_users 
            FROM user_subscriptions 
            WHERE expires_at > NOW() AND is_active = TRUE
        `);
        
        // Recent activities
        const [activities] = await pool.execute(`
            SELECT al.*, au.username 
            FROM activity_logs al
            LEFT JOIN admin_users au ON al.admin_id = au.id
            ORDER BY al.created_at DESC
            LIMIT 10
        `);
        
        res.json({
            success: true,
            stats: {
                channels: channelStats[0].total,
                codes: codeStats[0],
                users: userStats[0].active_users || 0
            },
            recent_activities: activities
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
// ERROR HANDLING
// ======================

// 404 handler
app.use((req, res) => {
    res.status(404).json({ 
        success: false, 
        message: 'API endpoint not found',
        path: req.path
    });
});

// Global error handler
app.use((err, req, res, next) => {
    console.error('Global error:', err);
    
    if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(400).json({ 
            success: false, 
            message: 'File too large. Maximum size is 10MB' 
        });
    }
    
    if (err instanceof multer.MulterError) {
        return res.status(400).json({ 
            success: false, 
            message: 'File upload error' 
        });
    }
    
    if (err.name === 'JsonWebTokenError') {
        return res.status(401).json({ 
            success: false, 
            message: 'Invalid token' 
        });
    }
    
    res.status(500).json({ 
        success: false, 
        message: 'Internal server error',
        error: process.env.NODE_ENV === 'development' ? err.message : undefined
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
            console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
            console.log(`🔐 Session: sameSite=${sessionConfig.cookie.sameSite}, secure=${sessionConfig.cookie.secure}`);
            console.log(`🌐 CORS: Enabled with credentials`);
            console.log(`📁 Uploads: ${uploadDir}`);
            
            if (process.env.NODE_ENV === 'production') {
                console.log(`⚡ Production mode`);
                console.log(`⚠️  IMPORTANT: Set SESSION_SECRET environment variable`);
            }
        });
        
        // Graceful shutdown
        process.on('SIGTERM', () => {
            console.log('SIGTERM received, shutting down...');
            server.close(() => {
                console.log('Server closed');
                if (pool) {
                    pool.end();
                    console.log('Database pool closed');
                }
            });
        });
        
        process.on('SIGINT', () => {
            console.log('SIGINT received, shutting down...');
            server.close(() => {
                console.log('Server closed');
                if (pool) {
                    pool.end();
                    console.log('Database pool closed');
                }
                process.exit(0);
            });
        });
        
    } catch (error) {
        console.error('Failed to start server:', error);
        process.exit(1);
    }
}

startServer();
