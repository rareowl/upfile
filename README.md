<div align="center">

# Upfile.1 - Secure, Self-Hosted File Sharing

</div>

Welcome to Upfile.1 - a privacy-focused, self-hosted file-sharing platform designed with end-to-end encryption. Upfile.1 combines ease of use with robust security, allowing users to safely upload, download, and manage files with confidence.

Features
End-to-End Encryption: All files are encrypted client-side before being uploaded to the server, ensuring that even the server cannot access file contents.
User Authentication: Secure login and registration functionality with encrypted user passwords using bcrypt.
Admin Controls: Advanced settings and user management, including banning by IP, throttling, and enforcing maximum upload/download sizes.
Speed Throttling: Adjustable download speed limits for users who exceed bandwidth limits.
Customizable Themes: Light and dark theme options to enhance user experience.
Persistent Sessions: Users stay logged in for enhanced usability.
Why Upfile.1 is Secure
Client-Side Encryption: Files are encrypted on the client-side with AES-GCM before upload. Only the user holds the encryption keys, ensuring that even if the server is compromised, the files remain inaccessible without the key.

Secure Key Storage: The encryption keys and initialization vectors (IVs) are stored as URL fragments. This prevents them from being sent to the server, keeping decryption data strictly with the user.

Data Access Control: Only authenticated users have access to their data. Sensitive data like user credentials are hashed and salted with bcrypt, ensuring strong password protection.

Download Throttling and Limits: To prevent misuse and safeguard server bandwidth, administrators can enforce download speed throttling and daily download limits per IP.

IP Banning: IP addresses with suspicious activity can be restricted from accessing the platform.

Quick Start Guide
Prerequisites
Node.js and npm: Ensure Node.js (v14+) and npm are installed.
MongoDB: Install and run MongoDB for data storage.
Installation
Clone the Repository:

bash
Copy code
git clone https://github.com/yourusername/upfile.1.git
cd upfile.1
Install Dependencies:

bash
Copy code
npm install
Configure Environment Variables: Create a .env file with necessary configurations. Example:

plaintext
Copy code
MONGO_URI=mongodb://localhost:27017/upfile
SESSION_SECRET=your-secret-key
Start the Server:

bash
Copy code
npm start
Access Upfile.1: Navigate to http://localhost:3000 to use the platform.

Usage
File Upload: Choose a file and upload it to the server. The file will be encrypted before transmission.
File Download: Retrieve files securely by providing the unique URL with encryption keys.
Admin Controls: Admin users can configure limits, theme settings, and user management in the admin settings panel.
Customization
Theming: Modify themes by adjusting the variables in style.css under public/.

Settings: Admins can control file size limits, download throttling, and encryption toggle in the admin settings page.

License
This project is licensed under the MIT License.


