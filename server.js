const express = require('express');
const fs = require('fs');
const crypto = require('crypto');
const path = require('path');
const multer = require('multer');

const app = express();
const port = 3000;

// Set up EJS as view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'public'));

// Serve static files from the 'public' folder
app.use(express.static('public'));

// Set up storage for files
const storage = multer.diskStorage({
    destination: './uploads/',
    filename: (req, file, cb) => {
        const uniqueSuffix = crypto.randomBytes(8).toString('hex');
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({ storage: storage });

// Create the uploads folder if it doesn't exist
if (!fs.existsSync('./uploads')) {
    fs.mkdirSync('./uploads');
}

const fileLinks = {};

// Routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

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

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});