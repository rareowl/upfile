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
    destination: './uploads/', // Folder where files will be stored
    filename: (req, file, cb) => {
        const uniqueSuffix = crypto.randomBytes(8).toString('hex');
        cb(null, uniqueSuffix + path.extname(file.originalname)); // Example: 'f23e1fae.txt'
    }
});

const upload = multer({ storage: storage });

// Create the uploads folder if it doesn't exist
if (!fs.existsSync('./uploads')) {
    fs.mkdirSync('./uploads');
}

// Object to store file paths mapped to download IDs
const fileLinks = {};

// Route to handle file uploads
app.post('/upload', upload.single('file'), (req, res) => {
    if (!req.file) {
        return res.status(400).send('No file uploaded.');
    }

    // Generate a random string for the download link
    const downloadId = crypto.randomBytes(8).toString('hex');
    
    // Store the mapping between the download ID and the file path
    const filePath = path.join(__dirname, 'uploads', req.file.filename);
    fileLinks[downloadId] = { filePath: filePath, fileName: req.file.originalname };
    
    // Create the download link
    const downloadLink = `http://localhost:${port}/download/${downloadId}`;
    
    // Send the link as a response
    res.send(`File uploaded successfully! Download it here: <a href="${downloadLink}">${downloadLink}</a>`);
});

// Route to render the upload page
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
                .progress {
                    width: 100%;
                    background-color: #f3f3f3;
                    border-radius: 5px;
                    overflow: hidden;
                    display: none; /* Initially hidden */
                }
                .progress-bar {
                    height: 20px;
                    width: 0;
                    background-color: #3498db;
                    transition: width 0.2s;
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
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Upload Your File</h1>
                <input type="file" id="fileInput" />
                <button onclick="uploadFile()">Upload</button>
                <div class="progress" id="progress">
                    <div class="progress-bar" id="progress-bar"></div>
                </div>
            </div>

            <script>
                function uploadFile() {
                    const fileInput = document.getElementById('fileInput');
                    const progressBar = document.getElementById('progress-bar');
                    const progressContainer = document.getElementById('progress');
                    const file = fileInput.files[0];

                    if (!file) {
                        alert('Please select a file to upload.');
                        return;
                    }

                    const formData = new FormData();
                    formData.append('file', file);

                    progressContainer.style.display = 'block'; // Show progress bar

                    const xhr = new XMLHttpRequest();
                    xhr.open('POST', '/upload', true);

                    // Track upload progress
                    xhr.upload.onprogress = function(event) {
                        if (event.lengthComputable) {
                            const percentCompleted = (event.loaded / event.total) * 100;
                            progressBar.style.width = percentCompleted + '%';
                        }
                    };

                    xhr.onload = function() {
                        if (xhr.status === 200) {
                            alert(xhr.responseText); // Show upload result
                            progressBar.style.width = '0'; // Reset progress bar
                            progressContainer.style.display = 'none'; // Hide progress bar
                        } else {
                            alert('Error uploading file.');
                            progressBar.style.width = '0'; // Reset progress bar
                            progressContainer.style.display = 'none'; // Hide progress bar
                        }
                    };

                    xhr.onerror = function() {
                        console.error('Upload error');
                        alert('Error uploading file.');
                        progressBar.style.width = '0'; // Reset progress bar
                        progressContainer.style.display = 'none'; // Hide progress bar
                    };

                    xhr.send(formData);
                }
            </script>
        </body>
        </html>
    `);
});

// Route to render the download landing page
app.get('/download/:id', (req, res) => {
    const downloadId = req.params.id;

    // Check if the download ID exists
    const fileData = fileLinks[downloadId];
    if (!fileData) {
        return res.status(404).send('File not found or link expired.');
    }

    // Render the landing page with a download button
    res.send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Download File</title>
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
                .filename {
                    font-size: 18px;
                    margin-bottom: 20px;
                    display: flex;
                    justify-content: center;
                    align-items: center;
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
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Download Your File</h1>
                <div class="filename">
                    <span>File: ${fileData.fileName}</span>
                </div>
                <button onclick="downloadFile()">Download</button>
            </div>

            <script>
                function downloadFile() {
                    const downloadId = '${downloadId}';
                    
                    // Use fetch to download the file
                    fetch(\`/download-file/\${downloadId}\`)
                        .then(response => response.blob())
                        .then(blob => {
                            // Create a link to download the blob
                            const url = window.URL.createObjectURL(blob);
                            const a = document.createElement('a');
                            a.href = url;
                            a.download = '${fileData.fileName}';
                            document.body.appendChild(a);
                            a.click();
                            a.remove();
                            window.URL.revokeObjectURL(url); // Cleanup
                        })
                        .catch(err => {
                            console.error('Download error:', err);
                            alert('Error downloading file.');
                        });
                }
            </script>
        </body>
        </html>
    `);
});

// Route to handle the actual file download
app.get('/download-file/:id', (req, res) => {
    const downloadId = req.params.id;

    // Check if the download ID exists
    const fileData = fileLinks[downloadId];
    if (!fileData) {
        return res.status(404).send('File not found or link expired.');
    }

    const filePath = fileData.filePath;
    const fileSize = fs.statSync(filePath).size; // Get file size for download
    const fileStream = fs.createReadStream(filePath);

    // Set headers for the file download
    res.setHeader('Content-Disposition', `attachment; filename="${fileData.fileName}"`);
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Length', fileSize);

    // Stream the file to the client
    fileStream.pipe(res);

    fileStream.on('end', () => {
        console.log('File download completed');
    });

    fileStream.on('error', (err) => {
        console.error('Error during file streaming:', err);
        res.status(500).send('Error while downloading the file.');
    });
});

// Start the server
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
