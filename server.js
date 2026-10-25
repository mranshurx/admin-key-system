const express = require('express');
const crypto = require('crypto');
const path = require('path');
const app = express();

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Environment Variables configured in Render
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'your-admin-secret';
const GITHUB_TOKEN = process.env.GITHUB_TOKEN; // GitHub Personal Access Token
const GITHUB_OWNER = process.env.GITHUB_OWNER; // Your GitHub Username
const GITHUB_REPO = process.env.GITHUB_REPO;   // Your Repository Name

// Generate standard license key format (XXXX-XXXX-XXXX-XXXX)
function generateLicenseKey() {
  const bytes = crypto.randomBytes(8).toString('hex').toUpperCase();
  return bytes.match(/.{1,4}/g).join('-');
}

// Fetch keys.json from GitHub repository
async function getKeysFromGitHub() {
  const url = `https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/keys.json`;
  const response = await fetch(url, {
    headers: {
      'Authorization': `Bearer ${GITHUB_TOKEN}`,
      'Accept': 'application/vnd.github+json',
      'User-Agent': 'Render-Key-Server'
    }
  });
  if (!response.ok) return { keys: [], sha: null };
  const data = await response.json();
  const content = Buffer.from(data.content, 'base64').toString('utf8');
  return { keys: JSON.parse(content), sha: data.sha };
}

// Save updated keys.json back to GitHub repository
async function saveKeysToGitHub(keysArray, sha) {
  const url = `https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/keys.json`;
  const content = Buffer.from(JSON.stringify(keysArray, null, 2)).toString('base64');
  
  const response = await fetch(url, {
    method: 'PUT',
    headers: {
      'Authorization': `Bearer ${GITHUB_TOKEN}`,
      'Accept': 'application/vnd.github+json',
      'Content-Type': 'application/json',
      'User-Agent': 'Render-Key-Server'
    },
    body: JSON.stringify({
      message: 'Admin: Generated new license key',
      content: content,
      sha: sha
    })
  });
  return response.ok;
}

// -------------------------------------------------------------
// 1. ADMIN ENDPOINT: Generate Key & Commit to GitHub
// -------------------------------------------------------------
app.post('/api/admin/generate', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (authHeader !== `Bearer ${ADMIN_SECRET}`) {
    return res.status(403).json({ error: 'Unauthorized' });
  }

  try {
    const { keys, sha } = await getKeysFromGitHub();
    const newKey = generateLicenseKey();
    
    const keyObj = {
      key: newKey,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(), // 30 days validity
      isUsed: false,
      hardwareId: null
    };

    keys.push(keyObj);
    const success = await saveKeysToGitHub(keys, sha);

    if (!success) {
      return res.status(500).json({ error: 'Failed to update GitHub repository' });
    }

    res.json({ message: 'Key generated successfully', key: newKey });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// 2. CLIENT ENDPOINT: Verify Key from APK
// -------------------------------------------------------------
app.post('/api/keys/verify', async (req, res) => {
  const { key, hardwareId } = req.body;
  if (!key) return res.status(400).json({ valid: false, message: 'Key is required' });

  try {
    const { keys, sha } = await getKeysFromGitHub();
    const foundIndex = keys.findIndex(k => k.key === key);

    if (foundIndex === -1) {
      return res.status(400).json({ valid: false, message: 'Invalid Key' });
    }

    const keyData = keys[foundIndex];

    // Check expiration date
    if (new Date() > new Date(keyData.expiresAt)) {
      return res.status(403).json({ valid: false, message: 'Key Has Expired' });
    }

    // Optional device locking
    if (keyData.hardwareId && keyData.hardwareId !== hardwareId) {
      return res.status(403).json({ valid: false, message: 'Key bound to another device' });
    }

    // Bind hardware ID on first use
    if (!keyData.hardwareId && hardwareId) {
      keys[foundIndex].hardwareId = hardwareId;
      keys[foundIndex].isUsed = true;
      await saveKeysToGitHub(keys, sha);
    }

    res.json({ valid: true, message: 'Access Granted' });
  } catch (err) {
    res.status(500).json({ valid: false, message: 'Verification error' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
