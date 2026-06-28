/**
 * Ghazal Node.js Express Clean Application
 * Demonstrates secure coding patterns - zero vulnerabilities expected
 */
const express = require('express');
const path = require('path');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const app = express();
const PORT = 3000;

// Security middleware
app.use(helmet());
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100
});
app.use(limiter);

// CORS - restricted origins
app.use((req, res, next) => {
    const allowedOrigins = ['https://ghazal.example.com'];
    const origin = req.headers.origin;
    if (allowedOrigins.includes(origin)) {
        res.header('Access-Control-Allow-Origin', origin);
    }
    res.header('Access-Control-Allow-Methods', 'GET, POST');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    next();
});

// Database connection from environment variables (not hardcoded)
const dbConfig = {
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME
};

// SAFE: Parameterized SQL query (no SQL injection)
app.get('/api/users', (req, res) => {
    const userId = req.query.id;
    const query = 'SELECT id, name, email FROM users WHERE id = ?';
    db.query(query, [userId], (err, results) => {
        if (err) {
            res.status(500).json({ error: 'Internal server error' });
        } else {
            res.json(results);
        }
    });
});

// SAFE: Parameterized login query
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    const sql = 'SELECT id, username FROM users WHERE username = ? AND password = ?';
    db.query(sql, [username, password], (err, result) => {
        if (err || result.length === 0) {
            res.status(401).json({ success: false });
        } else {
            res.json({ success: true });
        }
    });
});

// SAFE: Input validation + use of execFile (no shell)
const { execFile } = require('child_process');
app.get('/api/ping', (req, res) => {
    const host = req.query.host;
    // Validate: only allow alphanumeric, dots, and hyphens
    if (!/^[a-zA-Z0-9.-]+$/.test(host)) {
        return res.status(400).json({ error: 'Invalid host' });
    }
    execFile('ping', ['-c', '4', host], (error, stdout, stderr) => {
        res.send(stdout || stderr);
    });
});

// SAFE: Path traversal prevention with basename check
const fs = require('fs');
app.get('/api/file', (req, res) => {
    const filename = req.query.name;
    // Validate: only allow alphanumeric and specific extensions
    const safeName = path.basename(filename);
    if (safeName !== filename || !/^[a-zA-Z0-9._-]+$/.test(safeName)) {
        return res.status(400).json({ error: 'Invalid filename' });
    }
    const filepath = path.join(__dirname, '../data', safeName);
    // Ensure the resolved path is within the data directory
    const resolved = path.resolve(filepath);
    const dataDir = path.resolve(path.join(__dirname, '../data'));
    if (!resolved.startsWith(dataDir)) {
        return res.status(403).json({ error: 'Access denied' });
    }
    fs.readFile(resolved, 'utf8', (err, data) => {
        if (err) {
            res.status(404).json({ error: 'File not found' });
        } else {
            res.send(data);
        }
    });
});

// SAFE: HTML entity encoding for XSS prevention
function escapeHtml(str) {
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

app.get('/api/search', (req, res) => {
    const query = escapeHtml(req.query.q);
    const html = `<html><body><h1>Search results for: ${query}</h1><p>No results found.</p></body></html>`;
    res.send(html);
});

// SAFE: Parameterized hash with strong algorithm
app.post('/api/hash-password', (req, res) => {
    const { password } = req.body;
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
    res.json({ hash, salt });
});

// SAFE: Strong token generation
app.get('/api/token', (req, res) => {
    const token = crypto.randomBytes(32).toString('hex');
    res.json({ token });
});

// SAFE: No unsafe eval, no exec, no file traversal
app.post('/api/calculate', (req, res) => {
    const { a, b, op } = req.body;
    let result;
    switch (op) {
        case 'add': result = a + b; break;
        case 'sub': result = a - b; break;
        case 'mul': result = a * b; break;
        case 'div': result = b !== 0 ? a / b : 'Error'; break;
        default: result = 'Error: invalid operation';
    }
    res.json({ result });
});

app.listen(PORT, () => {
    console.log(`Ghazal Node.js clean app running on port ${PORT}`);
});

module.exports = app;
