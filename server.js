const express = require('express');
const fs = require('fs');
const crypto = require('crypto');
const path = require('path');
const multer = require('multer');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const session = require('express-session');
const bodyParser = require('body-parser');
const stream = require('stream');
const util = require('util');

const app = express();
const port = 3000;

// MongoDB connection
mongoose.connect('mongodb://localhost/upfile', { 
    useNewUrlParser: true, 
    useUnifiedTopology: true 
}).then(() => {
    console.log('Connected to MongoDB');
}).catch(err => {
    console.error('MongoDB connection error:', err);
});

// User Schema
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    isAdmin: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

const settingsSchema = new mongoose.Schema({
    maxUploadSize: { type: Number, default: 100 * 1024 * 1024 },
    maxDownloadSize: { type: Number, default: 2 * 1024 * 1024 * 1024 },
    throttleSpeed: { type: Number, default: 2 * 1024 * 1024 },
    defaultTheme: { type: String, default: 'light', enum: ['light', 'dark'] },
    lastUpdated: { type: Date, default: Date.now }
});

const Settings = mongoose.model('Settings', settingsSchema);

// Initialize default settings
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

const downloadTrackingSchema = new mongoose.Schema({
    ip: { type: String, required: true },
    bytesDownloaded: { type: Number, default: 0 },
    lastReset: { type: Date, default: Date.now }
});

const DownloadTracking = mongoose.model('DownloadTracking', downloadTrackingSchema);

// Add this after the Settings model definition
const getFileSize = async () => {
    const settings = await Settings.findOne();
    return settings ? settings.maxUploadSize : 100 * 1024 * 1024; // Default 100MB if no settings
};

// Middleware
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'public'));
app.use(express.static('public'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false } // set to true if using HTTPS
}));

function createThrottledStream(readStream, speedBytes) {
    const throttle = new stream.Transform({
        transform(chunk, encoding, callback) {
            this.push(chunk);
            callback();
        }
    });

    let totalBytes = 0;
    let startTime = Date.now();

    throttle.on('data', chunk => {
        totalBytes += chunk.length;
        const elapsedSeconds = (Date.now() - startTime) / 1000;
        const currentSpeed = totalBytes / elapsedSeconds;

        if (currentSpeed > speedBytes) {
            const requiredDelay = (totalBytes / speedBytes) - elapsedSeconds;
            if (requiredDelay > 0) {
                throttle.pause();
                setTimeout(() => throttle.resume(), requiredDelay * 1000);
            }
        }
    });

    readStream.pipe(throttle);
    return throttle;
}

const trackDownload = async (req, res, next) => {
    try {
        const ip = req.ip;
        const settings = await Settings.findOne();
        const maxDownloadSize = settings ? settings.maxDownloadSize : 2 * 1024 * 1024 * 1024;

        let tracking = await DownloadTracking.findOne({ ip });
        
        // If no tracking exists or it's been more than 24 hours, create/reset tracking
        if (!tracking || (Date.now() - tracking.lastReset > 24 * 60 * 60 * 1000)) {
            tracking = new DownloadTracking({ 
                ip, 
                bytesDownloaded: 0, 
                lastReset: new Date() 
            });
        }

        // Store tracking object in request for later use
        req.downloadTracking = tracking;
        next();
    } catch (error) {
        console.error('Download tracking error:', error);
        next(error);
    }
};

// Dark Theme
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



// Multer configuration
const storage = multer.diskStorage({
    destination: './uploads/',
    filename: (req, file, cb) => {
        const uniqueSuffix = crypto.randomBytes(8).toString('hex');
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({
    storage: storage,
    fileFilter: async (req, file, cb) => {
        try {
            const maxSize = await getFileSize();
            const fileSize = parseInt(req.headers['content-length']);
            if (fileSize > maxSize) {
                return cb(new Error('File size exceeds the limit'));
            }
            cb(null, true);
        } catch (error) {
            cb(error);
        }
    }
});

const fileLinks = {};

// Authentication middleware
const requireAuth = (req, res, next) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }
    next();
};

// Routes
app.get('/', (req, res) => {
    res.render('index');  // Instead of res.sendFile()
});

app.get('/check-download-status', trackDownload, async (req, res) => {
    try {
        const tracking = req.downloadTracking;
        const settings = await Settings.findOne();
        
        res.json({
            willBeThrottled: tracking.bytesDownloaded > settings.maxDownloadSize,
            throttleSpeed: Math.floor(settings.throttleSpeed / (1024 * 1024)) // Convert to MB/s
        });
    } catch (error) {
        console.error('Error checking download status:', error);
        res.status(500).json({ error: 'Error checking download status' });
    }
});

// Authentication routes
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

app.get('/login', (req, res) => {
    res.render('login');
});

app.post('/login', async (req, res) => {
    try {
        const user = await User.findOne({ username: req.body.username });
        if (user && await bcrypt.compare(req.body.password, user.password)) {
            req.session.userId = user._id;
            res.redirect('/profile');
        } else {
            res.redirect('/login');
        }
    } catch (error) {
        console.error('Login error:', error);
        res.redirect('/login');
    }
});

app.get('/profile', requireAuth, async (req, res) => {
    try {
        const user = await User.findById(req.session.userId);
        res.render('profile', { user });
    } catch (error) {
        console.error('Profile error:', error);
        res.redirect('/login');
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

// Add this with your other routes
app.get('/about', (req, res) => {
    res.render('about');
});

// Admin middleware
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

// Admin settings GET route
app.get('/admin-settings', requireAdmin, async (req, res) => {
    try {
        const settings = await Settings.findOne();
        const user = await User.findById(req.session.userId);
        res.render('admin-settings', { 
            user,
            settings: settings || { maxUploadSize: 100 * 1024 * 1024, lastUpdated: new Date() }
        });
    } catch (error) {
        console.error('Admin settings error:', error);
        res.redirect('/profile');
    }
});

// Admin settings POST route
// Update the admin settings routes
app.post('/admin-settings/general', requireAdmin, async (req, res) => {
    try {
        const maxUploadSize = parseInt(req.body.maxUploadSize);
        const maxDownloadSize = parseInt(req.body.maxDownloadSize);
        const throttleSpeed = parseInt(req.body.throttleSpeed);
        
        await Settings.findOneAndUpdate({}, {
            maxUploadSize: maxUploadSize * 1024 * 1024,
            maxDownloadSize: maxDownloadSize * 1024 * 1024 * 1024,
            throttleSpeed: throttleSpeed * 1024 * 1024,
            lastUpdated: new Date()
        }, { upsert: true });
        
        res.redirect('/admin-settings');
    } catch (error) {
        console.error('Settings update error:', error);
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

// File Size Check
app.get('/get-max-file-size', async (req, res) => {
    try {
        const settings = await Settings.findOne();
        const maxSize = settings ? settings.maxUploadSize : 100 * 1024 * 1024; // Default 100MB
        res.json({ maxSize });
    } catch (error) {
        console.error('Error getting max file size:', error);
        res.status(500).json({ 
            error: 'Server error',
            maxSize: 100 * 1024 * 1024 // Default fallback
        });
    }
});

// File upload routes
app.post('/upload', async (req, res) => {
    try {
        const maxSize = await getFileSize();
        const fileSize = parseInt(req.headers['content-length']);
        
        if (fileSize > maxSize) {
            const maxSizeMB = (maxSize / (1024 * 1024)).toFixed(2);
            return res.status(400).json({
                success: false,
                message: `File size exceeds the limit of ${maxSizeMB} MB`
            });
        }

        upload.single('file')(req, res, function(err) {
            if (err) {
                console.error('Upload error:', err);
                return res.status(400).json({
                    success: false,
                    message: err.message || 'Error uploading file'
                });
            }

            if (!req.file) {
                return res.status(400).json({
                    success: false,
                    message: 'No file uploaded.'
                });
            }

            const downloadId = crypto.randomBytes(8).toString('hex');
            const filePath = path.join(__dirname, 'uploads', req.file.filename);
            fileLinks[downloadId] = { 
                filePath: filePath, 
                fileName: req.file.originalname 
            };
            
            const downloadLink = `/download/${downloadId}`;
            res.json({
                success: true,
                message: 'File uploaded successfully!',
                downloadLink: downloadLink
            });
        });
    } catch (error) {
        console.error('Upload error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error during upload'
        });
    }
});

app.get('/download/:id', (req, res) => {
    const downloadId = req.params.id;
    const fileInfo = fileLinks[downloadId];
    
    if (!fileInfo) {
        return res.status(404).send('File not found.');
    }

    const fileSize = fs.statSync(fileInfo.filePath).size;
    const formattedSize = (fileSize / (1024 * 1024)).toFixed(2) + " MB";

    res.render('download', {
        fileName: fileInfo.fileName,
        fileSize: formattedSize
    });
});

app.get('/download/:id/download', trackDownload, async (req, res) => {
    const downloadId = req.params.id;
    const fileInfo = fileLinks[downloadId];

    if (!fileInfo) {
        return res.status(404).send('File not found.');
    }

    try {
        const stats = fs.statSync(fileInfo.filePath);
        const tracking = req.downloadTracking;
        const settings = await Settings.findOne();
        
        // Update bytes downloaded
        tracking.bytesDownloaded += stats.size;
        await tracking.save();

        // Set up the file stream
        const fileStream = fs.createReadStream(fileInfo.filePath);

        // Check if throttling is needed
        if (tracking.bytesDownloaded > settings.maxDownloadSize) {
            // Apply throttling
            const throttledStream = createThrottledStream(fileStream, settings.throttleSpeed);
            res.setHeader('Content-Type', 'application/octet-stream');
            res.setHeader('Content-Disposition', `attachment; filename="${fileInfo.fileName}"`);
            throttledStream.pipe(res);
        } else {
            // Normal download
            res.download(fileInfo.filePath, fileInfo.fileName);
        }

    } catch (error) {
        console.error('Download error:', error);
        res.status(500).send('Error processing download.');
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Something broke!');
});

// Start server
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});