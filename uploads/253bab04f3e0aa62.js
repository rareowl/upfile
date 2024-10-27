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
    maxUploadSize: { type: Number, default: 100 * 1024 * 1024 }, // Default 100MB
    lastUpdated: { type: Date, default: Date.now }
});

const Settings = mongoose.model('Settings', settingsSchema);

// Initialize default settings if none exist
async function initializeSettings() {
    const settings = await Settings.findOne();
    if (!settings) {
        await new Settings({}).save();
    }
}
initializeSettings();

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

const upload = multer({ storage: storage });

// Create uploads folder if it doesn't exist
if (!fs.existsSync('./uploads')) {
    fs.mkdirSync('./uploads');
}

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

// File upload routes
app.post('/upload', upload.single('file'), (req, res) => {
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