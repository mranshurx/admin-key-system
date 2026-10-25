const express = require('express');
const crypto = require('crypto');
const path = require('path');
const app = express();

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Only Admin Secret is required in Render Environment Variables
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'your-admin-secret';

// In-memory config updated dynamically from the Admin Panel
let gitHubConfig = {
  token: null,
  owner: null,
  repo: null
};

// Generate standard license key format (XXXX-XXXX-XXXX-XXXX)
function generateLicenseKey() {
  const bytes = crypto.randomBytes(8).toString('hex').toUpperCase();
  return bytes.match(/.{1,4}/g).join('-');
}

// Fetch keys.json from GitHub repository
async function getKeysFromGitHub() {
  if (!gitHubConfig.token || !gitHubConfig.owner || !gitHubConfig.repo) {
    throw new Error('GitHub configuration missing. Please enter your credentials in the Admin Panel.');
  }

  const url = `https://api.github.com/repos/${gitHubConfig.owner}/${gitHubConfig.repo}/contents/keys.json`;
  const response = await fetch(url, {
    headers: {
      'Authorization': `Bearer ${gitHubConfig.token}`,
      'Accept': 'application/vnd.github+json',
      'User-Agent': 'Render-Key-Server'
    }
  });

  if (!response.ok) {
    const errText = await response.text();
    throw new Error(`GitHub API Error: ${response.status} - ${errText}`);
  }

  const data = await response.json();
  const content = Buffer.from(data.content, 'base64').toString('utf8');
  return { keys: JSON.parse(content), sha: data.sha };
}

// Save updated keys.json back to GitHub repository
async function saveKeysToGitHub(keysArray, sha) {
  const url = `https://api.github.com/repos/${gitHubConfig.owner}/${gitHubConfig.repo}/contents/keys.json`;
  const content = Buffer.from(JSON.stringify(keysArray, null, 2)).toString('base64');
  
  const response = await fetch(url, {
    method: 'PUT',
    headers: {
      'Authorization': `Bearer ${gitHubConfig.token}`,
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

  if (!response.ok) {
    const errText = await response.text();
    throw new Error(`GitHub Save Error: ${response.status} - ${errText}`);
  }
  return true;
}

// -------------------------------------------------------------
// 1. ADMIN ENDPOINT: Generate Key & Commit to GitHub
// -------------------------------------------------------------
app.post('/api/admin/generate', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (authHeader !== `Bearer ${ADMIN_SECRET}`) {
    return res.status(403).json({ error: 'Unauthorized: Invalid Admin Secret' });
  }

  const { token, owner, repo } = req.body;
  if (!token || !owner || !repo) {
    return res.status(400).json({ error: 'Please provide GitHub Token, Username, and Repo Name' });
  }

  // Update server configuration dynamically from the admin panel
  gitHubConfig = { token, owner, repo };

  try {
    const { keys, sha } = await getKeysFromGitHub();
    const newKey = generateLicenseKey();
    
    const keyObj = {
      key: newKey,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(), // 30 days
      isUsed: false,
      hardwareId: null
    };

    keys.push(keyObj);
    await saveKeysToGitHub(keys, sha);

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

    // Check expiration
    if (new Date() > new Date(keyData.expiresAt)) {
      return res.status(403).json({ valid: false, message: 'Key Has Expired' });
    }

    // Device binding check
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
    res.status(500).json({ valid: false, message: err.message || 'Verification error' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
