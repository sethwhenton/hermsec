// VULN: Hardcoded GitHub token (hermsec.secret.github-token)
const GITHUB_TOKEN = 'REPLACE_WITH_GITHUB_TOKEN';

// VULN: Hardcoded Slack token (hermsec.secret.slack-token)
const SLACK_TOKEN = 'REPLACE_WITH_YOUR_SLACK_TOKEN';

// VULN: Private key file reference
const fs = require('fs');
const privateKey = fs.readFileSync('private-key.pem', 'utf8');

// VULN: npm install with shell command
const { execSync } = require('child_process');
execSync('npm install malicious-package');

// VULN: Dynamic require with user input
function loadModule(name) {
    return require(name);
}

// VULN: eval with remote code
function loadRemote(url) {
    const code = require('https').get(url, (res) => {
        let data = '';
        res.on('data', (chunk) => { data += chunk; });
        res.on('end', () => { eval(data); });
    });
}

module.exports = { GITHUB_TOKEN, SLACK_TOKEN, loadModule, loadRemote };
