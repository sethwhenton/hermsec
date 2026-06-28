// VULN 1: innerHTML assignment (hermsec.js.inner-html)
// VULN 2: new Function constructor (hermsec.js.function-constructor)
// VULN 3: child_process with shell:true (hermsec.js.shell-true)
// VULN 4: unsanitized HTML response (hermsec.js.unsanitized-html-response)
// VULN 5: command injection via req.query (hermsec.js.command-injection-input)

const { execSync, spawn } = require('child_process');
const express = require('express');
const app = express();
app.use(express.json());

// VULN 1: innerHTML assignment (CWE-79)
app.get('/api/render', (req, res) => {
    const userInput = req.query.content;
    const html = `<div id="output">${userInput}</div>`;
    res.send(html);
});

// VULN 2: Function constructor (CWE-95)
app.post('/api/evaluate', (req, res) => {
    const { expression } = req.body;
    const fn = new Function('return ' + expression);
    const result = fn();
    res.json({ result });
});

// VULN 3: child_process spawn with shell:true (CWE-78)
app.get('/api/execute', (req, res) => {
    const cmd = req.query.cmd;
    const child = spawn(cmd, { shell: true });
    let output = '';
    child.stdout.on('data', (data) => { output += data; });
    child.on('close', () => { res.send(output); });
});

// VULN 4: unsanitized HTML response (CWE-79)
app.get('/api/profile', (req, res) => {
    const name = req.query.name;
    const bio = req.query.bio;
    const html = `<html><body>
        <h1>${name}</h1>
        <p>${bio}</p>
    </body></html>`;
    res.send(html);
});

// VULN 5: command injection via req.query (CWE-78)
app.get('/api/ping', (req, res) => {
    const host = req.query.host;
    execSync(`ping -c 1 ${host}`);
    res.send('done');
});

// VULN 6: command injection via req.body (CWE-78)
app.post('/api/run', (req, res) => {
    const { command } = req.body;
    const output = execSync(command).toString();
    res.json({ output });
});

// VULN 7: eval (CWE-95)
app.post('/api/calc', (req, res) => {
    const { expr } = req.body;
    const result = eval(expr);
    res.json({ result });
});

// VULN 8: SQL injection (CWE-89)
app.get('/api/users', (req, res) => {
    const id = req.query.id;
    const query = `SELECT * FROM users WHERE id = '${id}'`;
    res.json({ query });
});

// VULN 9: path traversal (CWE-22)
const fs = require('fs');
app.get('/api/file', (req, res) => {
    const name = req.query.name;
    const data = fs.readFileSync('data/' + name, 'utf8');
    res.send(data);
});

// VULN 10: hardcoded secret (CWE-798)
const JWT_SECRET = 'ghazal-js-ts-advanced-secret-key-2024';

// VULN 11: CORS wildcard (CWE-942)
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    next();
});

// VULN 12: TLS disabled (CWE-295)
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

app.listen(3001, () => console.log('Advanced JS/TS app on port 3001'));
module.exports = app;
