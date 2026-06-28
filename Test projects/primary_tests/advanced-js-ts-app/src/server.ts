// TypeScript version - tests hermsec.ts.* rules
import express from 'express';

const app = express();
app.use(express.json());

// VULN 1: innerHTML via TypeScript (CWE-79)
app.get('/api/render', (req, res) => {
    const content: string = req.query.content as string;
    const html = `<div id="output">${content}</div>`;
    res.send(html);
});

// VULN 2: Function constructor (CWE-95)
app.post('/api/evaluate', (req, res) => {
    const { expression } = req.body;
    const fn = new Function('return ' + expression);
    const result = fn();
    res.json({ result });
});

// VULN 3: child_process with shell:true (CWE-78)
import { spawn } from 'child_process';
app.get('/api/execute', (req, res) => {
    const cmd = req.query.cmd as string;
    const child = spawn(cmd, { shell: true });
    let output = '';
    child.stdout?.on('data', (data: Buffer) => { output += data.toString(); });
    child.on('close', () => { res.send(output); });
});

// VULN 4: unsanitized HTML response (CWE-79)
app.get('/api/profile', (req, res) => {
    const name = req.query.name as string;
    const bio = req.query.bio as string;
    const html = `<html><body><h1>${name}</h1><p>${bio}</p></body></html>`;
    res.send(html);
});

// VULN 5: command injection via req.query (CWE-78)
import { execSync } from 'child_process';
app.get('/api/ping', (req, res) => {
    const host = req.query.host as string;
    execSync(`ping -c 1 ${host}`);
    res.send('done');
});

// VULN 6: command injection via req.body (CWE-78)
app.post('/api/run', (req, res) => {
    const { command } = req.body;
    const output = execSync(command).toString();
    res.json({ output });
});

// VULN 7: SQL injection (CWE-89)
app.get('/api/users', (req, res) => {
    const id = req.query.id as string;
    const query = `SELECT * FROM users WHERE id = '${id}'`;
    res.json({ query });
});

// VULN 8: path traversal (CWE-22)
import fs from 'fs';
app.get('/api/file', (req, res) => {
    const name = req.query.name as string;
    const data = fs.readFileSync('data/' + name, 'utf8');
    res.send(data);
});

// VULN 9: hardcoded secret (CWE-798)
const API_KEY = 'ghazal-ts-advanced-api-key-1234567890abcdef';

// VULN 10: TLS disabled (CWE-295)
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

// VULN 11: eval (CWE-95)
app.post('/api/calc', (req, res) => {
    const { expr } = req.body;
    const result = eval(expr);
    res.json({ result });
});

// VULN 12: CORS wildcard (CWE-942)
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    next();
});

app.listen(3002, () => console.log('Advanced TS app on port 3002'));
export default app;
