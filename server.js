const express = require('express');
const multer = require('multer');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');

const app = express();
const port = 3000;

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

app.post('/upload', upload.single('file'), (req, res) => {
    if (!req.file) {
        console.error('No file uploaded.');
        return res.status(400).send('No file uploaded.');
    }

    const downloadId = crypto.randomBytes(8).toString('hex');
    const filePath = path.join(__dirname, 'uploads', req.file.filename);
    fileLinks[downloadId] = { filePath: filePath, fileName: req.file.originalname };
    const downloadLink = `http://localhost:${port}/download/${downloadId}`;
    
    res.json({
        success: true,
        message: 'File uploaded successfully!',
        downloadLink: downloadLink
    });
});
app.get('/', (req, res) => {   
     res.sendFile(path.join(__dirname, 'public', 'index.html'));});

     app.get('/download/:id', (req, res) => {    
        const downloadId = req.params.id;    const fileInfo = fileLinks[downloadId];    
        if (!fileInfo) {        return res.status(404).send('File not found.');    }   
         res.download(fileInfo.filePath, fileInfo.fileName, (err) => {        if (err) {            
            console.error(`Error downloading file: ${err}`);            
            res.status(500).send('Error downloading file.');        }    });});

app.get('/', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Upload File</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    background-color: #f0f0f0;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    margin: 0;
                }
                .container {
                    text-align: center;
                    background-color: #fff;
                    padding: 30px;
                    border-radius: 10px;
                    box-shadow: 0 4px 10px rgba(0, 0, 0, 0.1);
                    max-width: 400px;
                    width: 100%;
                }
                h1 {
                    font-size: 24px;
                    margin-bottom: 20px;
                }
                input[type="file"] {
                    margin-bottom: 20px;
                }
                .progress-container {
                    margin: 20px 0;
                    display: none;
                }
                .progress {
                    width: 100%;
                    background-color: #f3f3f3;
                    border-radius: 5px;
                    overflow: hidden;
                }
                .progress-bar {
                    height: 20px;
                    width: 0;
                    background-color: #3498db;
                    transition: width 0.3s ease;
                }
                .progress-status {
                    margin-top: 10px;
                    font-size: 14px;
                    color: #666;
                }
                button {
                    background-color: #3498db;
                    color: white;
                    padding: 10px 20px;
                    border: none;
                    border-radius: 5px;
                    cursor: pointer;
                    font-size: 16px;
                }
                button:hover {
                    background-color: #2980b9;
                }
                button:disabled {
                    background-color: #bdc3c7;
                    cursor: not-allowed;
                }
                #upload-result {
                    margin-top: 20px;
                    padding: 10px;
                    border-radius: 5px;
                    display: none;
                }
                #upload-result.success {
                    background-color: #d4edda;
                    color: #155724;
                    border: 1px solid #c3e6cb;
                }
                #upload-result.error {
                    background-color: #f8d7da;
                    color: #721c24;
                    border: 1px solid #f5c6cb;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Upload Your File</h1>
                <input type="file" id="fileInput" />
                <button id="uploadButton" onclick="uploadFile()">Upload</button>
                
                <div class="progress-container" id="progressContainer">
                    <div class="progress">
                        <div class="progress-bar" id="progressBar"></div>
                    </div>
                    <div class="progress-status" id="progressStatus">0%</div>
                </div>

                <div id="upload-result"></div>
            </div>

            <script>
                const uploadButton = document.getElementById('uploadButton');
                const fileInput = document.getElementById('fileInput');
                const progressContainer = document.getElementById('progressContainer');
                const progressBar = document.getElementById('progressBar');
                const progressStatus = document.getElementById('progressStatus');
                const uploadResult = document.getElementById('upload-result');

                function formatFileSize(bytes) {
                    if (bytes === 0) return '0 Bytes';
                    const k = 1024;
                    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
                    const i = Math.floor(Math.log(bytes) / Math.log(k));
                    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
                }

                function uploadFile() {
                    const file = fileInput.files[0];
                    if (!file) {
                        alert('Please select a file to upload.');
                        return;
                    }

                    // Reset and show progress elements
                    progressBar.style.width = '0%';
                    progressStatus.textContent = '0%';
                    progressContainer.style.display = 'block';
                    uploadButton.disabled = true;
                    uploadResult.style.display = 'none';

                    const formData = new FormData();
                    formData.append('file', file);

                    const xhr = new XMLHttpRequest();
                    xhr.open('POST', '/upload', true);

                    // Track upload progress
                    xhr.upload.onprogress = function(event) {
                        if (event.lengthComputable) {
                            const percentComplete = Math.round((event.loaded / event.total) * 100);
                            const uploadedSize = formatFileSize(event.loaded);
                            const totalSize = formatFileSize(event.total);
                            
                            progressBar.style.width = percentComplete + '%';
                            progressStatus.textContent = \`\${percentComplete}% (\${uploadedSize} of \${totalSize})\`;
                        }
                    };

                    // Handle completion
                    xhr.onload = function() {
                        uploadButton.disabled = false;
                        
                        if (xhr.status === 200) {
                            const response = JSON.parse(xhr.responseText);
                            uploadResult.innerHTML = \`
                                File uploaded successfully!<br>
                                <a href="\${response.downloadLink}" target="_blank">Download Link</a>
                            \`;
                            uploadResult.className = 'success';
                        } else {
                            uploadResult.textContent = 'Error uploading file.';
                            uploadResult.className = 'error';
                        }
                        uploadResult.style.display = 'block';
                    };

                    // Handle errors
                    xhr.onerror = function() {
                        uploadButton.disabled = false;
                        uploadResult.textContent = 'Network error occurred while uploading.';
                        uploadResult.className = 'error';
                        uploadResult.style.display = 'block';
                    };

                    xhr.send(formData);
                }

                // Reset UI when a new file is selected
                fileInput.addEventListener('change', function() {
                    progressContainer.style.display = 'none';
                    uploadResult.style.display = 'none';
                    uploadButton.disabled = false;
                });
            </script>
        </body>
        </html>
    `);
});

// [Rest of the routes remain the same...]

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});