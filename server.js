const express = require('express');
const fs = require('fs').promises;
const fsSync = require('fs');
const crypto = require('crypto');
const path = require('path');
const multer = require('multer');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const session = require('express-session');
const bodyParser = require('body-parser');
const stream = require('stream');
const util = require('util');
const MongoDBStore = require('connect-mongodb-session')(session);

const app = express();
const port = 3000;
const activeUploads = new Map();
const fileLinks = {};

function getFileIconHelper(fileName) {
    const extension = path.extname(fileName).toLowerCase();
    
    // Map of file extensions to icon representations
    const iconMap = {
        // Images
        '.jpg': '🖼️',
        '.jpeg': '🖼️',
        '.png': '🖼️',
        '.gif': '🖼️',
        '.svg': '🖼️',
        '.webp': '🖼️',
        
        // Documents
        '.pdf': '📄',
        '.doc': '📝',
        '.docx': '📝',
        '.txt': '📝',
        '.md': '📝',
        '.rtf': '📝',
        
        // Spreadsheets
        '.xls': '📊',
        '.xlsx': '📊',
        '.csv': '📊',
        
        // Archives
        '.zip': '📦',
        '.rar': '📦',
        '.7z': '📦',
        '.tar': '📦',
        '.gz': '📦',
        
        // Audio
        '.mp3': '🎵',
        '.wav': '🎵',
        '.ogg': '🎵',
        '.m4a': '🎵',
        
        // Video
        '.mp4': '🎥',
        '.mov': '🎥',
        '.avi': '🎥',
        '.mkv': '🎥',
        
        // Code
        '.js': '💻',
        '.py': '💻',
        '.java': '💻',
        '.html': '💻',
        '.css': '💻',
        '.php': '💻',
        
        // Others
        '.exe': '⚙️',
        '.msi': '⚙️'
    };
    
    // Return the matching icon or default icon
    return iconMap[extension] || '📄';
}

// Initialize directories
(async () => {
    try {
        await fs.mkdir(path.join(__dirname, 'uploads'), { recursive: true });
        await fs.mkdir(path.join(__dirname, 'uploads', 'temp'), { recursive: true });
        console.log('Upload directories initialized');
    } catch (error) {
        console.error('Error creating upload directories:', error);
    }
})();

// Body parser configuration
app.use(bodyParser.json({limit: '10gb'}));
app.use(bodyParser.urlencoded({limit: '10gb', extended: true}));

// Session store setup
const store = new MongoDBStore({
    uri: 'mongodb://localhost:27017/upfile',
    collection: 'sessions'
});

store.on('error', function(error) {
    console.error('Session store error:', error);
});

// MongoDB connection
mongoose.connect('mongodb://localhost:27017/upfile', {
    maxPoolSize: 100,
    minPoolSize: 10,
    maxIdleTimeMS: 30000,
    connectTimeoutMS: 30000,
    socketTimeoutMS: 360000,
    serverSelectionTimeoutMS: 5000,
    heartbeatFrequencyMS: 10000
}).then(() => {
    console.log('Connected to MongoDB successfully');
}).catch(err => {
    console.error('MongoDB connection error:', err);
});

// MongoDB connection handlers
mongoose.connection.on('error', err => console.error('MongoDB connection error:', err));
mongoose.connection.on('disconnected', () => console.log('MongoDB disconnected'));
mongoose.connection.on('reconnected', () => console.log('MongoDB reconnected'));

// Schema definitions
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    isAdmin: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now },
    downloadedFiles: [{
        fileId: String,
        fileName: String,
        downloadDate: { type: Date, default: Date.now }
    }],
    uploadedFiles: [{
        fileId: String,
        fileName: String,
        uploadDate: { type: Date, default: Date.now },
        encryptionKey: String,
        encryptionIv: String
    }]
});

const settingsSchema = new mongoose.Schema({
    maxUploadSize: { type: Number, default: 100 * 1024 * 1024 },
    maxDownloadSize: { type: Number, default: 2 * 1024 * 1024 * 1024 },
    throttleSpeed: { type: Number, default: 2 * 1024 * 1024 },
    defaultTheme: { type: String, default: 'light', enum: ['light', 'dark'] },
    encryptionEnabled: { type: Boolean, default: true },
    allowUnregisteredUploads: { type: Boolean, default: false },
    anonymousUploadExpiry: { type: Number, default: 7 }, // Days until anonymous uploads expire
    lastUpdated: { type: Date, default: Date.now }
});

// Also update the File schema if you haven't already
const fileSchema = new mongoose.Schema({
    fileId: { type: String, required: true, unique: true },
    filePath: { type: String, required: true },
    fileName: { type: String, required: true },
    encrypted: { type: Boolean, default: false },
    uploadDate: { type: Date, default: Date.now },
    uploadedBy: { 
        type: String,
        default: 'anonymous'
    },
    uploadedFromIP: String,
    expiryDate: Date
});

// Add an index for automatic file cleanup
fileSchema.index({ expiryDate: 1 }, { expireAfterSeconds: 0 })


const bannedIPSchema = new mongoose.Schema({
    ip: { type: String, required: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    reason: String,
    bannedAt: { type: Date, default: Date.now }
});

const downloadTrackingSchema = new mongoose.Schema({
    ip: { type: String, required: true },
    bytesDownloaded: { type: Number, default: 0 },
    lastReset: { type: Date, default: Date.now }
});

// Model definitions
const User = mongoose.model('User', userSchema);
const Settings = mongoose.model('Settings', settingsSchema);
const File = mongoose.model('File', fileSchema);
const BannedIP = mongoose.model('BannedIP', bannedIPSchema);
const DownloadTracking = mongoose.model('DownloadTracking', downloadTrackingSchema);

// Initialize settings
async function initializeSettings() {
    try {
        const settings = await Settings.findOne();
        if (!settings) {
            await new Settings({}).save();
        }
    } catch (error) {
        console.error('Error initializing settings:', error);
    }
}
initializeSettings();

// Utility functions
const getFileSize = async () => {
    const settings = await Settings.findOne();
    return settings ? settings.maxUploadSize : 100 * 1024 * 1024;
};

function createThrottledStream(readStream, speedBytesPerSecond) {
    let bytesTransferred = 0;
    let lastTime = Date.now();
    
    const throttle = new stream.Transform({
        transform(chunk, encoding, callback) {
            const now = Date.now();
            const elapsedMs = now - lastTime;
            bytesTransferred += chunk.length;
            const expectedBytes = (elapsedMs / 1000) * speedBytesPerSecond;

            if (bytesTransferred > expectedBytes) {
                const excessBytes = bytesTransferred - expectedBytes;
                const requiredDelay = (excessBytes / speedBytesPerSecond) * 1000;
                setTimeout(() => {
                    this.push(chunk);
                    callback();
                }, requiredDelay);
            } else {
                this.push(chunk);
                callback();
            }
        }
    });

    readStream.on('error', (err) => {
        console.error('Read stream error:', err);
        throttle.destroy(err);
    });

    throttle.on('error', (err) => {
        console.error('Throttle stream error:', err);
    });

    readStream.pipe(throttle);
    return throttle;
}

// Middleware configurations
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'public'));
app.use(express.static('public'));

app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: false,
    store: store,
    cookie: {
        secure: false,
        maxAge: 24 * 60 * 60 * 1000
    }
}));

// IP Ban middleware
app.use(async (req, res, next) => {
    const ip = req.ip;
    const banned = await BannedIP.findOne({ ip });
    if (banned) {
        return res.status(403).send('Access Denied: Your IP has been banned.');
    }
    next();
});

// Theme middleware
app.use(async (req, res, next) => {
    try {
        const settings = await Settings.findOne();
        res.locals.theme = settings ? settings.defaultTheme : 'light';
        next();
    } catch (error) {
        console.error('Error loading theme:', error);
        res.locals.theme = 'light';
        next();
    }
});

app.use((req, res, next) => {
    res.locals.session = req.session;
    next();
});

const requireAuthAPI = async (req, res, next) => {
    const settings = await Settings.findOne();
    
    // If unregistered uploads are allowed for upload endpoints, skip authentication
    if (settings.allowUnregisteredUploads && (
        req.path === '/upload' || 
        req.path === '/init-upload' || 
        req.path.startsWith('/upload-chunk') ||
        req.path === '/finalize-upload')
    ) {
        return next();
    }
    
    // For API endpoints, return JSON instead of redirecting
    if (!req.session.userId) {
        return res.status(401).json({ 
            success: false, 
            message: 'Authentication required' 
        });
    }
    next();
};

async function cleanupExpiredFiles() {
    try {
        // Get current settings
        const settings = await Settings.findOne();
        
        // Find all expired files
        const expiredFiles = await File.find({
            expiryDate: { $lt: new Date() }
        });

        let deletedCount = 0;
        let errorCount = 0;

        // Delete each expired file
        for (const file of expiredFiles) {
            try {
                // Delete the physical file
                await fs.unlink(file.filePath);
                // Delete the database entry
                await File.deleteOne({ _id: file._id });
                deletedCount++;
                console.log(`Cleaned up expired file: ${file.fileName}`);
            } catch (error) {
                errorCount++;
                console.error(`Error cleaning up file ${file.fileName}:`, error);
            }
        }

        // Log cleanup results
        console.log(`Cleanup completed: ${deletedCount} files deleted, ${errorCount} errors`);
        
        // Update expiry dates for any anonymous uploads that don't have one
        await File.updateMany(
            { 
                uploadedBy: 'anonymous',
                expiryDate: null 
            },
            { 
                $set: { 
                    expiryDate: new Date(Date.now() + settings.anonymousUploadExpiry * 24 * 60 * 60 * 1000) 
                } 
            }
        );

    } catch (error) {
        console.error('Error in cleanup routine:', error);
    }
}

// Run cleanup every hour
setInterval(cleanupExpiredFiles, 60 * 60 * 1000);

// Run cleanup on server start
cleanupExpiredFiles();

// Authentication middleware
const requireAuth = async (req, res, next) => {
    const settings = await Settings.findOne();
    
    // If unregistered uploads are allowed, skip authentication
    if (settings.allowUnregisteredUploads && req.path === '/upload') {
        return next();
    }
    
    // Otherwise, require authentication
    if (!req.session.userId) {
        return res.redirect('/login');
    }
    next();
};

const requireAdmin = async (req, res, next) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }
    const user = await User.findById(req.session.userId);
    if (!user || !user.isAdmin) {
        return res.redirect('/profile');
    }
    next();
};

// Upload configurations
const chunkStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        const tempDir = path.join(__dirname, 'uploads', 'temp');
        cb(null, tempDir);
    },
    filename: (req, file, cb) => {
        const uniqueName = crypto.randomBytes(16).toString('hex');
        cb(null, uniqueName);
    }
});

const standardStorage = multer.diskStorage({
    destination: './uploads/',
    filename: (req, file, cb) => {
        const uniqueSuffix = crypto.randomBytes(8).toString('hex');
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});

const uploadChunk = multer({ storage: chunkStorage });
const upload = multer({
    storage: standardStorage,
    limits: { fileSize: 1024 * 1024 * 1024 * 2 }
});

// Chunk Upload Routes
app.post('/init-upload', requireAuthAPI, async (req, res) => {
    try {
        const { fileName, fileSize } = req.body;
        if (!fileName || !fileSize) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        const uploadId = crypto.randomBytes(16).toString('hex');
        const uploadDir = path.join(__dirname, 'uploads', 'temp', uploadId);
        await fs.mkdir(uploadDir, { recursive: true });

        const totalChunks = Math.ceil(fileSize / (10 * 1024 * 1024));
        activeUploads.set(uploadId, {
            fileName,
            fileSize,
            uploadDir,
            chunks: new Set(),
            totalChunks,
            startTime: Date.now()
        });

        console.log(`Initialized upload ${uploadId} for ${fileName} (${totalChunks} chunks)`);
        res.json({ uploadId, chunkSize: 10 * 1024 * 1024, totalChunks });
    } catch (error) {
        console.error('Error initializing upload:', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/upload-chunk', requireAuthAPI, uploadChunk.single('chunk'), async (req, res) => {
    try {
        const { uploadId, chunkIndex, totalChunks } = req.body;
        
        if (!req.file) {
            return res.status(400).json({ error: 'No chunk provided' });
        }

        if (!uploadId || !activeUploads.has(uploadId)) {
            await fs.unlink(req.file.path);
            return res.status(404).json({ error: 'Upload not found' });
        }

        const uploadInfo = activeUploads.get(uploadId);
        const chunkDir = path.join(__dirname, 'uploads', 'temp', uploadId);
        const finalPath = path.join(chunkDir, `chunk-${chunkIndex}`);

        await fs.mkdir(chunkDir, { recursive: true });
        await fs.rename(req.file.path, finalPath);

        uploadInfo.chunks.add(parseInt(chunkIndex));
        
        console.log(`Received chunk ${chunkIndex}. Total: ${uploadInfo.chunks.size}/${totalChunks}`);
        
        res.json({
            success: true,
            receivedChunks: uploadInfo.chunks.size,
            totalChunks: parseInt(totalChunks)
        });
    } catch (error) {
        if (req.file) {
            try {
                await fs.unlink(req.file.path);
            } catch (unlinkError) {
                console.error('Error cleaning up temp file:', unlinkError);
            }
        }
        console.error('Chunk upload error:', error);
        res.status(500).json({ error: 'Failed to process chunk' });
    }
});

app.post('/finalize-upload', requireAuthAPI, async (req, res) => {
    try {
        const { uploadId } = req.body;
        console.log('Finalizing upload:', uploadId);

        const uploadInfo = activeUploads.get(uploadId);
        if (!uploadInfo) {
            throw new Error('Upload not found');
        }

        // Verify all chunks
        const expectedChunks = new Set(Array.from({ length: uploadInfo.totalChunks }, (_, i) => i));
        const missingChunks = [...expectedChunks].filter(x => !uploadInfo.chunks.has(x));
        
        if (missingChunks.length > 0) {
            throw new Error(`Missing chunks: ${missingChunks.join(', ')}`);
        }

        // Combine chunks
        const finalFileName = crypto.randomBytes(8).toString('hex');
        const finalPath = path.join(__dirname, 'uploads', finalFileName);
        const writeStream = fsSync.createWriteStream(finalPath);

        for (let i = 0; i < uploadInfo.totalChunks; i++) {
            const chunkPath = path.join(uploadInfo.uploadDir, `chunk-${i}`);
            const chunkData = await fs.readFile(chunkPath);
            writeStream.write(chunkData);
        }

        await new Promise((resolve, reject) => {
            writeStream.on('finish', resolve);
            writeStream.on('error', reject);
            writeStream.end();
        });

        // Handle encryption
        const settings = await Settings.findOne();
        const expiryDays = settings.anonymousUploadExpiry;
        let encryptionKey = null;
        let encryptionIv = null;
        let finalFilePath = finalPath;

        if (settings.encryptionEnabled) {
            const key = crypto.randomBytes(32);
            const iv = crypto.randomBytes(16);
            
            const readStream = fsSync.createReadStream(finalPath);
            const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
            const encryptedPath = `${finalPath}.encrypted`;
            const writeStream = fsSync.createWriteStream(encryptedPath);
        
            await new Promise((resolve, reject) => {
                readStream
                    .pipe(cipher)
                    .pipe(writeStream)
                    .on('finish', resolve)
                    .on('error', (error) => {
                        console.error('Encryption error:', error);
                        reject(error);
                    });
            });
        
            await fs.unlink(finalPath);
            finalFilePath = encryptedPath;
            encryptionKey = key.toString('hex');
            encryptionIv = iv.toString('hex');
        
            console.log('File encrypted successfully');
        }

        // Save to database
        const downloadId = path.basename(finalFilePath);
        
        // Create file record
        await File.create({
            fileId: downloadId,
            filePath: finalFilePath,
            fileName: uploadInfo.fileName,
            encrypted: settings.encryptionEnabled,
            uploadedBy: req.session.userId || 'anonymous',
            uploadedFromIP: req.ip,
            // Set expiry based on admin setting
            expiryDate: req.session.userId ? null : new Date(Date.now() + expiryDays * 24 * 60 * 60 * 1000)
        });

        // If user is logged in, add to their uploads
        if (req.session.userId) {
            const user = await User.findById(req.session.userId);
            if (user) {
                user.uploadedFiles.push({
                    fileId: downloadId,
                    fileName: uploadInfo.fileName,
                    encryptionKey,
                    encryptionIv
                });
                await user.save();
            }
        }

        // Cleanup
        await fs.rm(uploadInfo.uploadDir, { recursive: true });
        activeUploads.delete(uploadId);

        res.json({
            success: true,
            downloadLink: `/download/${downloadId}`,
            key: encryptionKey,
            iv: encryptionIv
        });

    } catch (error) {
        console.error('Error finalizing upload:', error);
        res.status(500).json({ error: error.message });
    }
});

app.get('/check-download-status', async (req, res) => {
    try {
        // Get current settings and download tracking
        const settings = await Settings.findOne();
        const tracking = await DownloadTracking.findOne({ ip: req.ip });

        // Calculate if download should be throttled
        const willBeThrottled = tracking && tracking.bytesDownloaded > settings.maxDownloadSize;
        const throttleSpeed = settings.throttleSpeed;

        res.json({
            willBeThrottled,
            throttleSpeed: willBeThrottled ? (throttleSpeed / (1024 * 1024)).toFixed(2) + ' MB/s' : null
        });
    } catch (error) {
        console.error('Error checking download status:', error);
        res.status(500).json({ error: 'Failed to check download status' });
    }
});

// Download Routes
app.get('/download/:id', async (req, res) => {
    try {
        const fileInfo = await File.findOne({ fileId: req.params.id });
        if (!fileInfo) {
            console.error('File not found in database:', req.params.id);
            return res.status(404).send('File not found.');
        }

        // Verify file exists on disk
        try {
            const stats = await fs.stat(fileInfo.filePath);
            const formattedSize = (stats.size / (1024 * 1024)).toFixed(2) + " MB";
            
            // Log successful file access
            console.log('File found:', {
                id: fileInfo.fileId,
                path: fileInfo.filePath,
                size: formattedSize,
                encrypted: fileInfo.encrypted
            });

            res.render('download', {
                fileName: fileInfo.fileName,
                fileSize: formattedSize,
                encrypted: fileInfo.encrypted
            });
        } catch (statError) {
            console.error('File exists in DB but not on disk:', fileInfo.filePath);
            // Clean up DB entry if file doesn't exist
            await File.deleteOne({ fileId: req.params.id });
            return res.status(404).send('File not found on server.');
        }
    } catch (error) {
        console.error('Download page error:', error);
        res.status(500).send('Error accessing file.');
    }
});

app.get('/download/:id/download', async (req, res) => {
    let fileStream = null;
    
    try {
        // Find file in database
        const fileInfo = await File.findOne({ fileId: req.params.id });
        if (!fileInfo) {
            console.error('File not found in database:', req.params.id);
            return res.status(404).send('File not found.');
        }

        // Verify file exists
        const stats = await fs.stat(fileInfo.filePath);
        console.log('Starting download:', {
            id: fileInfo.fileId,
            path: fileInfo.filePath,
            size: stats.size,
            encrypted: fileInfo.encrypted
        });

        // Update download tracking
        const settings = await Settings.findOne();
        let tracking = await DownloadTracking.findOne({ ip: req.ip });
        if (!tracking) {
            tracking = new DownloadTracking({ ip: req.ip });
        }
        tracking.bytesDownloaded += stats.size;
        await tracking.save();

        // Set response headers
        const headers = {
            'Content-Type': 'application/octet-stream',
            'Content-Disposition': `attachment; filename="${encodeURIComponent(fileInfo.fileName)}"`,
            'Content-Length': stats.size,
            'X-File-Encrypted': fileInfo.encrypted
        };

        for (const [key, value] of Object.entries(headers)) {
            res.setHeader(key, value);
        }

        // Create file stream
        fileStream = fsSync.createReadStream(fileInfo.filePath);

        // Handle throttling
        if (tracking.bytesDownloaded > settings.maxDownloadSize) {
            console.log('Throttling download:', settings.throttleSpeed, 'bytes/second');
            const throttledStream = createThrottledStream(fileStream, settings.throttleSpeed);
            throttledStream.pipe(res);
        } else {
            fileStream.pipe(res);
        }

        // Handle stream errors
        fileStream.on('error', (error) => {
            console.error('File stream error:', error);
            if (!res.headersSent) {
                res.status(500).send('Error streaming file');
            }
            if (fileStream) fileStream.destroy();
        });

        // Handle client disconnect
        req.on('close', () => {
            console.log('Download interrupted by client');
            if (fileStream) fileStream.destroy();
        });

        // Handle successful completion
        res.on('finish', () => {
            console.log('Download completed successfully');
            if (fileStream) fileStream.destroy();
        });

    } catch (error) {
        console.error('Download error:', error);
        if (fileStream) fileStream.destroy();
        if (!res.headersSent) {
            res.status(500).send('Error processing download.');
        }
    }
});

// Also add this helper function if you don't already have it
function deleteFile(filePath) {
    return fs.unlink(filePath).catch(error => {
        console.error('Error deleting file:', filePath, error);
    });
}

// Standard Upload Route (for smaller files)
app.post('/upload', requireAuthAPI, upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ 
                success: false, 
                message: 'No file uploaded.' 
            });
        }

        const settings = await Settings.findOne();
        const maxSize = await getFileSize();
        
        if (parseInt(req.headers['content-length']) > maxSize) {
            return res.status(400).json({
                success: false,
                message: `File size exceeds limit of ${maxSize / (1024 * 1024)} MB`
            });
        }

        const downloadId = crypto.randomBytes(8).toString('hex');
        
        await File.create({
            fileId: downloadId,
            filePath: req.file.path,
            fileName: req.body.originalName || req.file.originalname,
            encrypted: settings.encryptionEnabled,
            uploadedBy: req.session.userId || 'anonymous',
            uploadedFromIP: req.ip
        });

        // If user is logged in, add to their uploads
        if (req.session.userId) {
            const user = await User.findById(req.session.userId);
            user.uploadedFiles.push({
                fileId: downloadId,
                fileName: req.body.originalName || req.file.originalname,
                encryptionKey: req.body.key,
                encryptionIv: req.body.iv
            });
            await user.save();
        }

        res.json({
            success: true,
            message: 'File uploaded successfully!',
            downloadLink: `/download/${downloadId}`,
            encrypted: settings.encryptionEnabled
        });
    } catch (error) {
        console.error('Upload error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error during upload.'
        });
    }
});
app.get('/admin-settings', requireAdmin, async (req, res) => {
    try {
        const settings = await Settings.findOne();
        const users = await User.find({}).sort({ createdAt: -1 });
        const user = await User.findById(req.session.userId);
        
        res.render('admin-settings', { 
            user,
            users,
            settings: settings || { 
                maxUploadSize: 100 * 1024 * 1024, 
                maxDownloadSize: 2 * 1024 * 1024 * 1024,
                throttleSpeed: 2 * 1024 * 1024,
                defaultTheme: 'light',
                encryptionEnabled: true,
                lastUpdated: new Date()
            }
        });
    } catch (error) {
        console.error('Admin settings error:', error);
        res.redirect('/profile');
    }
});

app.get('/get-upload-permissions', async (req, res) => {
    try {
        const settings = await Settings.findOne();
        res.json({
            allowUnregisteredUploads: settings.allowUnregisteredUploads,
            isAuthenticated: !!req.session.userId
        });
    } catch (error) {
        console.error('Error getting upload permissions:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to get upload permissions' 
        });
    }
});

app.post('/admin-settings/general', requireAdmin, async (req, res) => {
    try {
        const maxUploadSize = parseInt(req.body.maxUploadSize);
        const maxDownloadSize = parseInt(req.body.maxDownloadSize);
        const throttleSpeed = parseFloat(req.body.throttleSpeed);
        const encryptionEnabled = req.body.encryptionEnabled === 'true';
        const allowUnregisteredUploads = req.body.allowUnregisteredUploads === 'true';
        const anonymousUploadExpiry = parseInt(req.body.anonymousUploadExpiry);
        
        // Validate expiry days
        if (isNaN(anonymousUploadExpiry) || anonymousUploadExpiry < 1) {
            throw new Error('Invalid expiry days value');
        }
        
        const settings = {
            maxUploadSize: maxUploadSize * 1024 * 1024,
            maxDownloadSize: maxDownloadSize * 1024 * 1024 * 1024,
            throttleSpeed: Math.floor(throttleSpeed * 1024 * 1024),
            encryptionEnabled: encryptionEnabled,
            allowUnregisteredUploads: allowUnregisteredUploads,
            anonymousUploadExpiry: anonymousUploadExpiry,
            lastUpdated: new Date()
        };

        await Settings.findOneAndUpdate({}, settings, { upsert: true });
        
        // Update expiry dates for existing anonymous uploads
        await File.updateMany(
            { uploadedBy: 'anonymous' },
            { $set: { expiryDate: new Date(Date.now() + anonymousUploadExpiry * 24 * 60 * 60 * 1000) } }
        );
        
        console.log('Updated settings:', settings);
        
        res.redirect('/admin-settings');
    } catch (error) {
        console.error('Settings update error:', error);
        res.redirect('/admin-settings');
    }
});

// User details route
app.get('/admin/user/:userId', requireAdmin, async (req, res) => {
    try {
        const userData = await User.findById(req.params.userId);
        if (!userData) {
            return res.status(404).send('User not found');
        }

        // Calculate total storage used
        let totalStorageUsed = 0;
        for (const file of userData.uploadedFiles) {
            const filePath = fileLinks[file.fileId]?.filePath;
            if (filePath && fs.existsSync(filePath)) {
                const stats = fs.statSync(filePath);
                totalStorageUsed += stats.size;
            }
        }

        // Helper function to format bytes
        const formatBytes = (bytes) => {
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        };

        res.render('admin-user-details', { 
            userData, 
            totalStorageUsed,
            formatBytes
        });
    } catch (error) {
        console.error('Error fetching user details:', error);
        res.redirect('/admin-settings');
    }
});

// Ban user route
app.post('/admin/user/:userId/ban', requireAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.params.userId);
        if (!user) {
            return res.status(404).send('User not found');
        }

        // Get the user's last known IP (you'll need to track this when users log in)
        const lastIP = user.lastKnownIP || req.ip;

        // Create ban record
        const ban = new BannedIP({
            ip: lastIP,
            userId: user._id,
            reason: req.body.banReason
        });
        await ban.save();

        // Optionally disable the user account
        user.isBanned = true;
        await user.save();

        res.redirect('/admin-settings');
    } catch (error) {
        console.error('Error banning user:', error);
        res.redirect(`/admin/user/${req.params.userId}`);
    }
});

// Delete file route
app.post('/admin/file/:fileId/delete', requireAdmin, async (req, res) => {
    try {
        const fileId = req.params.fileId;
        const filePath = fileLinks[fileId]?.filePath;
        
        if (filePath) {
            // Delete the physical file
            fs.unlink(filePath, (err) => {
                if (err) {
                    console.error('Error deleting file from server:', err);
                }
            });
            
            // Remove from fileLinks
            delete fileLinks[fileId];
            
            // Remove from all users' uploaded files
            await User.updateMany(
                { 'uploadedFiles.fileId': fileId },
                { $pull: { uploadedFiles: { fileId: fileId } } }
            );
        }
        
        // Redirect back to the user details page
        res.redirect(req.headers.referer || '/admin-settings');
    } catch (error) {
        console.error('Error deleting file:', error);
        res.redirect('/admin-settings');
    }
});

app.post('/admin-settings/display', requireAdmin, async (req, res) => {
    try {
        const { defaultTheme } = req.body;
        
        await Settings.findOneAndUpdate({}, {
            defaultTheme,
            lastUpdated: new Date()
        }, { upsert: true });
        
        res.redirect('/admin-settings');
    } catch (error) {
        console.error('Display settings update error:', error);
        res.redirect('/admin-settings');
    }
});

app.post('/delete-upload/:fileId', requireAuth, async (req, res) => {
    try {
        const user = await User.findById(req.session.userId);
        const fileToDelete = user.uploadedFiles.find(file => file.fileId === req.params.fileId);

        if (fileToDelete) {
            // Find file in database
            const fileInfo = await File.findOne({ fileId: req.params.fileId });
            if (fileInfo) {
                // Delete the physical file
                fs.unlink(fileInfo.filePath, (err) => {
                    if (err) {
                        console.error('Error deleting file from server:', err);
                    } else {
                        console.log('File successfully deleted from server:', fileInfo.filePath);
                    }
                });
                
                // Remove from database
                await File.deleteOne({ fileId: req.params.fileId });
            }

            // Remove from user's uploadedFiles array
            user.uploadedFiles = user.uploadedFiles.filter(file => file.fileId !== req.params.fileId);
            await user.save();
        }
        
        res.redirect('/profile');
    } catch (error) {
        console.error('Error deleting upload:', error);
        res.status(500).send('Error deleting upload.');
    }
});

app.get('/register', (req, res) => {
    res.render('register');
});

app.post('/register', async (req, res) => {
    try {
        const userCount = await User.countDocuments();
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        const user = new User({
            username: req.body.username,
            password: hashedPassword,
            email: req.body.email,
            isAdmin: userCount === 0 // First user becomes admin
        });
        await user.save();
        res.redirect('/login');
    } catch (error) {
        console.error('Registration error:', error);
        res.redirect('/register');
    }
});

// Authentication Routes
app.post('/login', async (req, res) => {
    try {
        const user = await User.findOne({ username: req.body.username });
        if (user && await bcrypt.compare(req.body.password, user.password)) {
            req.session.userId = user._id;
            if (req.body.rememberMe) {
                req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000;
            }
            res.redirect('/profile');
        } else {
            res.redirect('/login');
        }
    } catch (error) {
        console.error('Login error:', error);
        res.redirect('/login');
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error('Logout error:', err);
        }
        res.redirect('/');
    });
});

// View Routes
app.get('/', (req, res) => res.render('index'));
app.get('/login', (req, res) => res.render('login'));
app.get('/register', (req, res) => res.render('register'));
app.get('/about', (req, res) => res.render('about'));

app.get('/profile', requireAuth, async (req, res) => {
    try {
        const user = await User.findById(req.session.userId);
        const baseUrl = `${req.protocol}://${req.get('host')}`;
        
        // Add these helper functions to be available in the template
        const helpers = {
            getFileIcon: getFileIconHelper,
            formatDate: (date) => {
                return new Date(date).toLocaleDateString('en-US', {
                    year: 'numeric',
                    month: 'short',
                    day: 'numeric',
                    hour: '2-digit',
                    minute: '2-digit'
                });
            }
        };
        
        res.render('profile', { 
            user,
            baseUrl,
            ...helpers
        });
    } catch (error) {
        console.error('Profile error:', error);
        res.redirect('/login');
    }
});

// Error handling
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Something broke!');
});

// Server startup
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});