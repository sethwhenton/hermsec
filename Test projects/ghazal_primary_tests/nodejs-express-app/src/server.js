const express = require('express');
const path = require('path');
const fs = require('fs');
const { exec } = require('child_process');
const crypto = require('crypto');
const app = express();
const PORT = 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// VULN 1: Hardcoded API key (CWE-798)
const STRIPE_KEY = 'sk_live_ghazal_TEST_4eC39HqLyjWDarjtT1zdp7dc';

// VULN 2: Hardcoded database password (CWE-798)
const DB_PASSWORD = 'admin123!@#';

// VULN 3: SQL Injection - string interpolation in query (CWE-89)
app.get('/api/users', (req, res) => {
    const userId = req.query.id;
    const query = `SELECT * FROM users WHERE id = '${userId}'`;
    db.query(query, (err, results) => {
        res.json(results);
    });
});

// VULN 4: SQL Injection - concatenated username (CWE-89)
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    const sql = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
    db.query(sql, (err, result) => {
        if (result.length > 0) {
            res.json({ success: true, token: 'auth-token-ghazal' });
        } else {
            res.json({ success: false });
        }
    });
});

// VULN 5: Command Injection via exec() (CWE-78)
app.get('/api/ping', (req, res) => {
    const host = req.query.host;
    exec(`ping -c 4 ${host}`, (error, stdout, stderr) => {
        res.send(stdout || stderr);
    });
});

// VULN 6: Command Injection with user input in exec (CWE-78)
app.post('/api/run', (req, res) => {
    const { command } = req.body;
    exec(command, (error, stdout, stderr) => {
        res.json({ output: stdout, error: stderr });
    });
});

// VULN 7: Path Traversal - read arbitrary file (CWE-22)
app.get('/api/file', (req, res) => {
    const filename = req.query.name;
    const filepath = path.join(__dirname, '../data', filename);
    fs.readFile(filepath, 'utf8', (err, data) => {
        if (err) {
            res.status(404).send('File not found');
        } else {
            res.send(data);
        }
    });
});

// VULN 8: Path Traversal via download endpoint (CWE-22)
app.get('/api/download', (req, res) => {
    const file = req.query.file;
    const fullPath = path.join('/var/uploads', file);
    res.download(fullPath);
});

// VULN 9: Reflected XSS - unsanitized HTML response (CWE-79)
app.get('/api/search', (req, res) => {
    const query = req.query.q;
    const html = `<html><body><h1>Search results for: ${query}</h1><p>No results found.</p></body></html>`;
    res.send(html);
});

// VULN 10: XSS via innerHTML simulation (CWE-79)
app.get('/api/profile/:id', (req, res) => {
    const userId = req.params.id;
    const userBio = getUserBio(userId);
    res.send(`<div id="bio">${userBio}</div>`);
});

// VULN 11: Unsafe eval() (CWE-95)
app.post('/api/calculate', (req, res) => {
    const { expression } = req.body;
    const result = eval(expression);
    res.json({ result });
});

// VULN 12: Weak hash - MD5 for password (CWE-328)
app.post('/api/hash-password', (req, res) => {
    const { password } = req.body;
    const hash = crypto.createHash('md5').update(password).digest('hex');
    res.json({ hash });
});

// VULN 13: CORS wildcard (CWE-942)
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    next();
});

// VULN 14: TLS verification disabled (CWE-295)
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

// VULN 15: Debug mode / verbose errors exposed (CWE-209)
app.use((err, req, res, next) => {
    res.status(500).json({
        error: err.message,
        stack: err.stack,
        fullError: err
    });
});

// VULN 16: Hardcoded JWT secret (CWE-798)
const JWT_SECRET = 'ghazal-jwt-secret-key-2024';

// VULN 17: Insecure session config (CWE-614)
app.use(require('express-session')({
    secret: 'ghazal-session-secret',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false, httpOnly: false }
}));

// VULN 18: Unsafe redirect with user input (CWE-601)
app.get('/api/redirect', (req, res) => {
    const url = req.query.url;
    res.redirect(url);
});

// VULN 19: Known vulnerable lodash usage (CWE-798/CVE-2021-23337)
const _ = require('lodash');
app.get('/api/template', (req, res) => {
    const template = req.query.tpl;
    const compiled = _.template(template);
    res.send(compiled({ name: 'ghazal' }));
});

// VULN 20: Weak random for token generation (CWE-330)
app.get('/api/token', (req, res) => {
    const token = Math.random().toString(36).substring(2);
    res.json({ token });
});

app.listen(PORT, () => {
    console.log(`Ghazal Node.js vulnerable app running on port ${PORT}`);
});

module.exports = app;
