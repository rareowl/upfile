const express = require('express');
const fs = require('fs');
const crypto = require('crypto');
const path = require('path');
const multer = require('multer');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const session = require('express-session');
const bodyParser = require('body-parser');

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
    maxUploadSize: { type: Number, default: 0 * 1024 * 1024 }, // Default unlimited
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
app.post('/admin-settings', requireAdmin, async (req, res) => {
    try {
        const maxSize = parseInt(req.body.maxUploadSize);
        await Settings.findOneAndUpdate({}, {
            maxUploadSize: maxSize * 1024 * 1024, // Convert MB to bytes
            lastUpdated: new Date()
        }, { upsert: true });
        res.redirect('/admin-settings');
    } catch (error) {
        console.error('Settings update error:', error);
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

app.get('/download/:id/download', (req, res) => {
    const downloadId = req.params.id;
    const fileInfo = fileLinks[downloadId];

    if (!fileInfo) {
        return res.status(404).send('File not found.');
    }

    res.download(fileInfo.filePath, fileInfo.fileName, (err) => {
        if (err) {
            console.error(`Error downloading file: ${err}`);
            res.status(500).send('Error downloading file.');
        }
    });
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