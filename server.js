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

// Session middleware
app.use(session({
    secret: process.env.SESSION_SECRET || 'watchme-secret-key-2024',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: process.env.NODE_ENV === 'production',
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

// Security middleware
app.use(helmet({
    contentSecurityPolicy: false  // Disable CSP for development
}));

// CORS configuration - Updated for Flutter app support
const corsOptions = {
    origin: function (origin, callback) {
        // Allow all origins in development
        if (process.env.NODE_ENV === 'development' || !origin) {
            callback(null, true);
        } else {
            const allowedOrigins = [
                'http://localhost:3000',
                'http://localhost:5000',
                'http://localhost:8080',
                'http://localhost:8081',
                'http://localhost',  // For any localhost port
                'http://10.0.2.2:5000',  // For Android emulator
                'http://127.0.0.1:5000',  // For local testing
                'http://10.0.2.2',  // Android emulator
                'capacitor://localhost',  // Capacitor
                'ionic://localhost'  // Ionic
            ];
            
            if (allowedOrigins.indexOf(origin) !== -1 || origin.includes('localhost')) {
                callback(null, true);
            } else {
                console.log('Blocked by CORS:', origin);
                callback(new Error('Not allowed by CORS'));
            }
        }
    },
    credentials: true,
    optionsSuccessStatus: 200,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
};
app.use(cors(corsOptions));

// Handle preflight requests
app.options('*', cors(corsOptions));

// Rate limiting - more permissive for app endpoints
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: process.env.NODE_ENV === 'production' ? 100 : 1000,
    message: 'Too many requests from this IP, please try again later.'
});

const appLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: process.env.NODE_ENV === 'production' ? 500 : 5000,
    message: 'Too many requests from this IP, please try again later.'
});

app.use('/api/', apiLimiter);
app.use('/api/app/', appLimiter);
app.use('/api/subscription/', appLimiter);

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Static files
app.use(express.static(path.join(__dirname, 'public')));

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
        const allowedMimeTypes = ['text/plain', 'application/octet-stream'];
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
        pool = mysql.createPool({
            host: process.env.DB_HOST || 'localhost',
            user: process.env.DB_USER || 'root',
            password: process.env.DB_PASSWORD || '',
            database: process.env.DB_NAME || 'watchme_db',
            port: process.env.DB_PORT || 3306,
            waitForConnections: true,
            connectionLimit: 10,
            queueLimit: 0,
            enableKeepAlive: true,
            keepAliveInitialDelay: 0
        });
        
        // Test connection
        const connection = await pool.getConnection();
        console.log('✅ Database connected successfully');
        connection.release();
        
        // Initialize database tables if needed
        await initializeDatabase();
        
    } catch (error) {
        console.error('❌ Database connection failed:', error.message);
        console.error('Please ensure:');
        console.error('1. MySQL server is running');
        console.error('2. Database "watchme_db" exists');
        console.error('3. User has proper permissions');
        console.error('4. Check your .env file configuration');
        process.exit(1);
    }
}

// Initialize database tables
async function initializeDatabase() {
    try {
        // Check if tables exist
        const [tables] = await pool.execute(`
            SELECT TABLE_NAME 
            FROM information_schema.TABLES 
            WHERE TABLE_SCHEMA = ?
        `, [process.env.DB_NAME || 'watchme_db']);
        
        const tableNames = tables.map(t => t.TABLE_NAME);
        
        // Create tables if they don't exist
        const requiredTables = ['admin_users', 'channels', 'subscription_codes', 'user_subscriptions', 'activity_logs', 'playlist_settings'];
        const missingTables = requiredTables.filter(table => !tableNames.includes(table));
        
        if (missingTables.length > 0) {
            console.log('⚠️ Missing tables detected. Please run the database.sql script.');
            console.log('Missing tables:', missingTables);
        } else {
            console.log('✅ All database tables are present');
        }
        
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
        
        // Verify JWT
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'watchme-jwt-secret-2024-change-this-in-production');
        
        // Check if admin exists and is active
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

// Log activity middleware
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
                req.ip || req.connection.remoteAddress,
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
    res.json({ 
        success: true, 
        message: 'Watch Me Admin Server is running',
        timestamp: new Date().toISOString(),
        version: '1.0.0',
        environment: process.env.NODE_ENV || 'development'
    });
});


// Admin authentication routes
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
        
        // Find admin user by PIN
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
        
        // Generate JWT token
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
        await logActivity({ user: { id: admin.id }, ip: req.ip }, 'login', `Admin logged in with PIN: ${admin.username}`);
        
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

// Get all channels
app.get('/api/channels', authenticateToken, async (req, res) => {
    try {
        const { category, search, page = 1, limit = 50 } = req.query;
        const offset = (page - 1) * limit;
        
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
        
        const countQuery = query.replace('SELECT *', 'SELECT COUNT(*) as total');
        const [countResult] = await pool.execute(countQuery, params);
        const total = countResult[0].total;
        
        query += ' ORDER BY name LIMIT ? OFFSET ?';
        params.push(parseInt(limit), parseInt(offset));
        
        const [channels] = await pool.execute(query, params);
        
        const [categories] = await pool.execute(
            'SELECT DISTINCT category FROM channels WHERE category IS NOT NULL AND category != "" ORDER BY category'
        );
        
        res.json({
            success: true,
            data: channels,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total,
                pages: Math.ceil(total / limit)
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
    body('name').notEmpty().trim().isLength({ min: 1, max: 200 }),
    body('url').notEmpty().trim().isURL(),
    body('category').optional().trim().isLength({ max: 100 }),
    body('logo').optional().trim().isURL()
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
        
        // Check if channel already exists
        const [existing] = await pool.execute(
            'SELECT id FROM channels WHERE url = ?',
            [url]
        );
        
        if (existing.length > 0) {
            return res.status(409).json({ 
                success: false, 
                message: 'Channel with this URL already exists' 
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

// Update channel
app.put('/api/channels/:id', authenticateToken, [
    body('name').optional().trim().isLength({ min: 1, max: 200 }),
    body('url').optional().trim().isURL(),
    body('category').optional().trim().isLength({ max: 100 }),
    body('logo').optional().trim().isURL()
], async (req, res) => {
    try {
        const { id } = req.params;
        const updates = req.body;
        
        // Check if channel exists
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
        
        // Build dynamic update query
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

// Delete channel
app.delete('/api/channels/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        
        // Get channel info before deleting
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

// Bulk delete channels
app.post('/api/channels/bulk-delete', authenticateToken, async (req, res) => {
    try {
        const { channelIds } = req.body;
        
        if (!Array.isArray(channelIds) || channelIds.length === 0) {
            return res.status(400).json({ 
                success: false, 
                message: 'No channels selected' 
            });
        }
        
        // Get channel names for logging
        const placeholders = channelIds.map(() => '?').join(',');
        const [channels] = await pool.execute(
            `SELECT name FROM channels WHERE id IN (${placeholders})`,
            channelIds
        );
        
        const channelNames = channels.map(c => c.name).join(', ');
        
        // Delete channels
        const [result] = await pool.execute(
            `DELETE FROM channels WHERE id IN (${placeholders})`,
            channelIds
        );
        
        await logActivity(req, 'channel_bulk_delete', `Deleted ${result.affectedRows} channels: ${channelNames}`);
        
        res.json({
            success: true,
            message: `${result.affectedRows} channels deleted successfully`
        });
        
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

// Upload M3U file
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
        
        // Read and parse file
        const fileContent = fs.readFileSync(filePath, 'utf8');
        const parsedChannels = parseM3UContent(fileContent);
        
        // Clean up uploaded file
        fs.unlinkSync(filePath);
        
        if (parsedChannels.length === 0) {
            return res.status(400).json({ 
                success: false, 
                message: 'No valid channels found in M3U file' 
            });
        }
        
        // Store in session
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
            total: parsedChannels.length
        });
        
    } catch (error) {
        console.error('M3U upload error:', error);
        
        // Clean up file if exists
        if (req.file && fs.existsSync(req.file.path)) {
            fs.unlinkSync(req.file.path);
        }
        
        res.status(500).json({ 
            success: false, 
            message: 'Failed to process M3U file' 
        });
    }
});

// Confirm M3U import
app.post('/api/import/m3u', authenticateToken, async (req, res) => {
    const connection = await pool.getConnection();
    
    try {
        const { importId, action = 'append' } = req.body;
        
        if (!req.session.importData || req.session.importData.importId !== importId) {
            return res.status(400).json({ 
                success: false, 
                message: 'Import session expired or invalid' 
            });
        }
        
        const { channels: parsedChannels } = req.session.importData;
        
        await connection.beginTransaction();
        
        try {
            if (action === 'replace') {
                await connection.execute('DELETE FROM channels');
            }
            
            let importedCount = 0;
            let skippedCount = 0;
            
            for (const channel of parsedChannels) {
                try {
                    // Check if channel already exists (by URL)
                    const [existing] = await connection.execute(
                        'SELECT id FROM channels WHERE url = ?',
                        [channel.url]
                    );
                    
                    if (existing.length === 0 || action === 'replace') {
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
                    skippedCount++;
                }
            }
            
            await connection.commit();
            
            // Clear session data
            delete req.session.importData;
            
            await logActivity(req, 'm3u_import', `Imported ${importedCount} channels from M3U (${action}), skipped ${skippedCount}`);
            
            const [countResult] = await connection.execute('SELECT COUNT(*) as total FROM channels');
            
            res.json({
                success: true,
                message: `Successfully imported ${importedCount} channels (${skippedCount} skipped)`,
                imported: importedCount,
                skipped: skippedCount,
                totalChannels: countResult[0].total
            });
            
        } catch (error) {
            await connection.rollback();
            throw error;
        }
        
    } catch (error) {
        console.error('Import error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to import channels' 
        });
    } finally {
        connection.release();
    }
});

// Parse M3U content helper function
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
            if (nameStart > 0 && nameStart < trimmedLine.length) {
                currentChannel.name = trimmedLine.substring(nameStart).trim();
                
                // Remove extra attributes from name
                const attrIndex = currentChannel.name.indexOf(', tvg-');
                if (attrIndex !== -1) {
                    currentChannel.name = currentChannel.name.substring(0, attrIndex);
                }
                
                // Clean up name
                currentChannel.name = currentChannel.name.replace(/["']/g, '').trim();
            }
            
            // Extract logo
            const logoMatch = trimmedLine.match(/tvg-logo="([^"]+)"/);
            if (logoMatch && logoMatch[1]) {
                currentChannel.logo = logoMatch[1].trim();
            }
            
            // Extract group/category
            const groupMatch = trimmedLine.match(/group-title="([^"]+)"/);
            if (groupMatch && groupMatch[1]) {
                currentChannel.category = groupMatch[1].trim();
            }
            
        } else if (trimmedLine && !trimmedLine.startsWith('#') && currentChannel) {
            if (trimmedLine.startsWith('http://') || trimmedLine.startsWith('https://')) {
                currentChannel.url = trimmedLine.trim();
                
                // Validate URL
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

// Generate subscription codes
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
                const code = generateSubscriptionCode();
                const expiryDate = new Date();
                expiryDate.setDate(expiryDate.getDate() + duration_days);
                
                await connection.execute(
                    `INSERT INTO subscription_codes 
                    (id, code, duration_days, code_type, expiry_date, generated_by, notes) 
                    VALUES (?, ?, ?, ?, ?, ?, ?)`,
                    [uuidv4(), code, duration_days, code_type, expiryDate, generatedBy, notes || null]
                );
                
                generatedCodes.push({
                    id: null,
                    code,
                    duration_days,
                    code_type,
                    expiry_date: expiryDate.toISOString(),
                    is_used: false,
                    used_by: null,
                    used_at: null,
                    generated_by: generatedBy,
                    notes: notes || null,
                    created_at: new Date().toISOString()
                });
            }
            
            await connection.commit();
            
            await logActivity(req, 'code_generate', `Generated ${quantity} ${code_type} codes (${duration_days} days)`);
            
            res.status(201).json({
                success: true,
                message: `${quantity} codes generated successfully`,
                data: generatedCodes
            });
            
        } catch (error) {
            await connection.rollback();
            throw error;
        }
        
    } catch (error) {
        console.error('Generate code error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to generate codes' 
        });
    } finally {
        connection.release();
    }
});

// Get all codes
app.get('/api/codes', authenticateToken, async (req, res) => {
    try {
        const { status, search, page = 1, limit = 50 } = req.query;
        const offset = (page - 1) * limit;
        
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
        params.push(parseInt(limit), parseInt(offset));
        
        const [codes] = await pool.execute(query, params);
        
        // Get statistics
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
                page: parseInt(page),
                limit: parseInt(limit),
                total,
                pages: Math.ceil(total / limit)
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
        
        // Check if code exists
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
        
        // Delete code
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

// Validate subscription code
app.post('/api/codes/validate', async (req, res) => {
    const connection = await pool.getConnection();
    
    try {
        const { code, device_id } = req.body;
        
        if (!code || !device_id) {
            return res.status(400).json({ 
                success: false, 
                message: 'Code and device ID are required' 
            });
        }
        
        const cleanCode = code.trim();
        
        // Validate code format - must be 12 digits
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
            // Find valid, unused, non-expired code
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
            
            // Check if device already has active subscription
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
            
            // Mark code as used
            await connection.execute(
                'UPDATE subscription_codes SET is_used = TRUE, used_by = ?, used_at = NOW() WHERE code = ?',
                [device_id, cleanCode]
            );
            
            // Calculate expiry date
            const expiryDate = new Date();
            expiryDate.setDate(expiryDate.getDate() + subscriptionCode.duration_days);
            
            // Create user subscription
            await connection.execute(
                `INSERT INTO user_subscriptions 
                (id, user_id, subscription_code, device_id, expires_at, is_active) 
                VALUES (?, ?, ?, ?, ?, TRUE)`,
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

// Check subscription status (for Flutter app)
app.post('/api/subscription/status', async (req, res) => {
    try {
        const { device_id } = req.body;
        
        if (!device_id) {
            return res.status(400).json({ 
                success: false, 
                message: 'Device ID is required' 
            });
        }
        
        // Check if device has active subscription
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

// Activate subscription (for Flutter app)
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
        
        // Validate code format - must be 12 digits
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
            // First validate the code
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
            
            // Check if device already has active subscription
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
            
            // Mark code as used
            await connection.execute(
                'UPDATE subscription_codes SET is_used = TRUE, used_by = ?, used_at = NOW() WHERE code = ?',
                [device_id, cleanCode]
            );
            
            // Calculate expiry date
            const expiryDate = new Date();
            expiryDate.setDate(expiryDate.getDate() + subscriptionCode.duration_days);
            
            // Create user subscription
            await connection.execute(
                `INSERT INTO user_subscriptions 
                (id, user_id, subscription_code, device_id, expires_at, is_active) 
                VALUES (?, ?, ?, ?, ?, TRUE)`,
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

// Get dashboard statistics
app.get('/api/dashboard/stats', authenticateToken, async (req, res) => {
    try {
        // Get channel statistics
        const [channelResult] = await pool.execute('SELECT COUNT(*) as total FROM channels');
        
        // Get code statistics
        const [codeStats] = await pool.execute(`
            SELECT 
                COUNT(*) as total_codes,
                SUM(CASE WHEN is_used = FALSE AND expiry_date > NOW() THEN 1 ELSE 0 END) as active_codes,
                SUM(CASE WHEN is_used = TRUE THEN 1 ELSE 0 END) as used_codes
            FROM subscription_codes
        `);
        
        // Get user statistics
        const [userStats] = await pool.execute(`
            SELECT 
                COUNT(DISTINCT user_id) as active_users,
                COUNT(*) as total_subscriptions
            FROM user_subscriptions 
            WHERE expires_at > NOW() AND is_active = TRUE
        `);
        
        // Get recent activities
        const [activities] = await pool.execute(`
            SELECT al.*, au.username as admin_name
            FROM activity_logs al
            LEFT JOIN admin_users au ON al.admin_id = au.id
            ORDER BY al.created_at DESC
            LIMIT 10
        `);
        
        // Get channel categories
        const [categories] = await pool.execute(`
            SELECT category, COUNT(*) as count 
            FROM channels 
            WHERE category IS NOT NULL AND category != ''
            GROUP BY category 
            ORDER BY count DESC
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
                users: userStats[0],
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

// Get channels for app (public endpoint)
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
        
        // Format channels for app
        const formattedChannels = channels.map(channel => ({
            id: channel.id,
            name: channel.name || 'Unknown Channel',
            url: channel.url || '',
            category: channel.category || 'General',
            logo_url: channel.logo_url || '',
            is_active: true
        }));
        
        // Get categories for filter
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
        
        // Add default values if missing
        settingsObj.app_name = settingsObj.app_name || 'Watch Me Premium';
        settingsObj.company_name = settingsObj.company_name || 'Watch Me Streaming';
        
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

// Generate subscription code helper
function generateSubscriptionCode() {
    // Generate 12-digit numeric code
    let code = '';
    for (let i = 0; i < 12; i++) {
        code += Math.floor(Math.random() * 10); // Generate random digit 0-9
    }
    return code;
}

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
    console.error('❌ Global error:', err);
    
    // Handle specific errors
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
    
    // JWT errors
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
    
    // Default error response
    res.status(500).json({ 
        success: false, 
        message: 'Internal server error',
        error: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
});

// ======================
// SERVER STARTUP
// ======================

const PORT = process.env.PORT || 5000;

async function startServer() {
    try {
        await connectDB();
        
        app.listen(PORT, '0.0.0.0', () => {
            console.log(`🚀 Server running on port ${PORT}`);
            console.log(`📊 Health check: http://localhost:${PORT}/api/health`);
            console.log(`👑 Admin panel: http://localhost:${PORT}/index.html`);
            console.log(`📱 Flutter app API: http://localhost:${PORT}/api/app/channels`);
            console.log(`🎯 Subscription API: http://localhost:${PORT}/api/subscription/status`);
            console.log(`🔐 Admin login: http://localhost:${PORT}/index.html (PIN: 123456789)`);
            console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
        });
        
    } catch (error) {
        console.error('❌ Failed to start server:', error);
        process.exit(1);
    }
}

startServer();