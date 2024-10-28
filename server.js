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

const userSchema = new mongoose.Schema({
    // Existing fields
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    isAdmin: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now },

    // Fields for tracking files
    downloadedFiles: [
        {
            fileId: String,
            fileName: String,
            downloadDate: { type: Date, default: Date.now }
        }
    ],
    uploadedFiles: [
        {
            fileId: String,
            fileName: String,
            uploadDate: { type: Date, default: Date.now }
        }
    ]
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
    cookie: {
        secure: false, // Set to true if using HTTPS
        maxAge: 7 * 24 * 60 * 60 * 1000 // 1 week in milliseconds
    }
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

app.use((req, res, next) => {
    res.locals.session = req.session;
    next();
});


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

const trackDownload = async (req, res, next) => {
    try {
        const ip = req.ip;
        const settings = await Settings.findOne();
        const maxDownloadSize = settings ? settings.maxDownloadSize : 2 * 1024 * 1024 * 1024;

        let tracking = await DownloadTracking.findOne({ ip });

        if (!tracking || (Date.now() - tracking.lastReset > 24 * 60 * 60 * 1000)) {
            tracking = new DownloadTracking({ ip, bytesDownloaded: 0, lastReset: new Date() });
        }

        // Update user’s downloaded files if authenticated
        if (req.session.userId) {
            const user = await User.findById(req.session.userId);
            user.downloadedFiles.push({
                fileId: req.params.id, // fileId from route parameter
                fileName: fileInfo.fileName // Retrieved from fileLinks object
            });
            await user.save();
        }

        req.downloadTracking = tracking;
        next();
    } catch (error) {
        console.error('Download tracking error:', error);
        next(error);
    }
};



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

app.get('/check-download-status', (async (req, res, next) => {
        try {
            const ip = req.ip;
            const settings = await Settings.findOne();
            const maxDownloadSize = settings ? settings.maxDownloadSize : 2 * 1024 * 1024 * 1024;

            let tracking = await DownloadTracking.findOne({ ip });

            if (!tracking || (Date.now() - tracking.lastReset > 24 * 60 * 60 * 1000)) {
                tracking = new DownloadTracking({ ip, bytesDownloaded: 0, lastReset: new Date() });
            }

            // Save download to user's downloaded files if logged in
            if (req.session.userId && req.params.id) {
                const user = await User.findById(req.session.userId);
                const fileInfo = fileLinks[req.params.id];

                // Check if file exists in fileLinks and then push download record
                if (fileInfo) {
                    user.downloadedFiles.push({
                        fileId: req.params.id,
                        fileName: fileInfo.fileName
                    });
                    await user.save();
                }
            }

            req.downloadTracking = tracking;
            next();
        } catch (error) {
            console.error('Download tracking error:', error);
            next(error);
        }
    }), async (req, res) => {
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

// Add this temporary route to server.js for testing
app.get('/generate-test-file', async (req, res) => {
    const filePath = path.join(__dirname, 'uploads', 'test-large-file');
    const fileSize = 100 * 1024 * 1024; // 100MB
    
    await new Promise((resolve, reject) => {
        const writeStream = fs.createWriteStream(filePath);
        let bytesWritten = 0;
        
        function writeChunk() {
            const chunkSize = 1024 * 1024; // 1MB chunks
            const buffer = Buffer.alloc(chunkSize, 'x');
            
            if (bytesWritten < fileSize) {
                writeStream.write(buffer);
                bytesWritten += chunkSize;
                setImmediate(writeChunk);
            } else {
                writeStream.end();
                resolve();
            }
        }
        
        writeChunk();
    });
    
    res.send('Test file generated');
});

// Add this to server.js to help with testing
app.get('/test-throttling', (req, res) => {
    res.render('test-throttling');
});

// Add to server.js
app.get('/test-throttling-setup', async (req, res) => {
    try {
        // Generate a 100MB test file
        const testFilePath = path.join(__dirname, 'uploads', 'throttle-test-file');
        const fileSize = 100 * 1024 * 1024; // 100MB
        
        // Generate file if it doesn't exist
        if (!fs.existsSync(testFilePath)) {
            const writeStream = fs.createWriteStream(testFilePath);
            const buffer = Buffer.alloc(1024 * 1024, 'x'); // 1MB chunk
            
            for(let i = 0; i < 100; i++) { // Write 100 chunks of 1MB
                writeStream.write(buffer);
            }
            writeStream.end();
        }

        // Create a download link
        const downloadId = crypto.randomBytes(8).toString('hex');
        fileLinks[downloadId] = {
            filePath: testFilePath,
            fileName: 'throttle-test-file'
        };

        res.send(`
            <h1>Throttling Test</h1>
            <p>Test file created (100MB)</p>
            <p>Download ID: ${downloadId}</p>
            <p><a href="/download/${downloadId}">Download Link</a></p>
            <p>Steps to test:</p>
            <ol>
                <li>Set throttle speed to 0.1 MB/s in admin settings</li>
                <li>Set download limit to 1 MB</li>
                <li>Open browser dev tools (Network tab)</li>
                <li>Click download link and monitor speed</li>
            </ol>
        `);
    } catch (error) {
        res.status(500).send('Error setting up test: ' + error.message);
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

app.post('/delete-download/:fileId', requireAuth, async (req, res) => {
    try {
        const user = await User.findById(req.session.userId);
        user.downloadedFiles = user.downloadedFiles.filter(file => file.fileId !== req.params.fileId);
        await user.save();
        res.redirect('/profile');
    } catch (error) {
        console.error('Error deleting download:', error);
        res.status(500).send('Error deleting download.');
    }
});

app.post('/delete-upload/:fileId', requireAuth, async (req, res) => {
    try {
        const user = await User.findById(req.session.userId);
        const fileToDelete = user.uploadedFiles.find(file => file.fileId === req.params.fileId);

        if (fileToDelete) {
            // Remove the file from the filesystem
            const filePath = fileLinks[req.params.fileId]?.filePath;
            if (filePath) {
                fs.unlink(filePath, (err) => {
                    if (err) {
                        console.error('Error deleting file from server:', err);
                    } else {
                        console.log('File successfully deleted from server:', filePath);
                    }
                });
                
                // Remove file from fileLinks
                delete fileLinks[req.params.fileId];
            }

            // Remove the file from user's uploadedFiles array
            user.uploadedFiles = user.uploadedFiles.filter(file => file.fileId !== req.params.fileId);
            await user.save();
        }
        
        res.redirect('/profile');
    } catch (error) {
        console.error('Error deleting upload:', error);
        res.status(500).send('Error deleting upload.');
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Logout error:', err);
            res.redirect('/profile');
        } else {
            res.redirect('/');
        }
    });
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
app.post('/upload', upload.single('file'), async (req, res) => {
    try {
        const maxSize = await getFileSize();
        const fileSize = parseInt(req.headers['content-length']);

        // Check if file size exceeds the limit
        if (fileSize > maxSize) {
            const maxSizeMB = (maxSize / (1024 * 1024)).toFixed(2);
            return res.status(400).json({
                success: false,
                message: `File size exceeds the limit of ${maxSizeMB} MB`
            });
        }

        if (!req.file) {
            return res.status(400).json({
                success: false,
                message: 'No file uploaded.'
            });
        }

        // Only save upload info if user is authenticated
        if (req.session.userId) {
            const user = await User.findById(req.session.userId);
            const downloadId = crypto.randomBytes(8).toString('hex');

            // Store file information for future downloads
            fileLinks[downloadId] = {
                filePath: req.file.path,
                fileName: req.file.originalname
            };
            
            user.uploadedFiles.push({
                fileId: downloadId,
                fileName: req.file.originalname
            });
            await user.save();
            
            const downloadLink = `/download/${downloadId}`;
            return res.json({
                success: true,
                message: 'File uploaded successfully!',
                downloadLink
            });
        } else {
            return res.status(403).json({ success: false, message: 'User not authenticated.' });
        }
    } catch (error) {
        console.error('Upload error:', error);
        return res.status(500).json({
            success: false,
            message: 'Server error during upload.'
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

app.get('/download/:id/download', (async (req, res, next) => {
        try {
            const ip = req.ip;
            const settings = await Settings.findOne();
            const maxDownloadSize = settings ? settings.maxDownloadSize : 2 * 1024 * 1024 * 1024;

            let tracking = await DownloadTracking.findOne({ ip });

            if (!tracking || (Date.now() - tracking.lastReset > 24 * 60 * 60 * 1000)) {
                tracking = new DownloadTracking({ ip, bytesDownloaded: 0, lastReset: new Date() });
            }

            // Save download to user's downloaded files if logged in
            if (req.session.userId && req.params.id) {
                const user = await User.findById(req.session.userId);
                const fileInfo = fileLinks[req.params.id];

                // Check if file exists in fileLinks and then push download record
                if (fileInfo) {
                    user.downloadedFiles.push({
                        fileId: req.params.id,
                        fileName: fileInfo.fileName
                    });
                    await user.save();
                }
            }

            req.downloadTracking = tracking;
            next();
        } catch (error) {
            console.error('Download tracking error:', error);
            next(error);
        }
    }), async (req, res) => {
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