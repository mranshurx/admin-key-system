const express = require('express');
const crypto = require('crypto');
const path = require('path');
const app = express();

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Hardcoded Admin Key
const ADMIN_SECRET = '-- ANSHU-BAAP';

// In-memory store for active GitHub configuration set via Admin Panel
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

// Fetch keys.json from GitHub
async function getKeysFromGitHub() {
  if (!gitHubConfig.token || !gitHubConfig.owner || !gitHubConfig.repo) {
    throw new Error('GitHub configuration missing. Please save your credentials in the panel.');
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
    if (response.status === 404) {
      return { keys: [], sha: null };
    }
    const errText = await response.text();
    throw new Error(`GitHub API Error: ${response.status} - ${errText}`);
  }

  const data = await response.json();
  const content = Buffer.from(data.content, 'base64').toString('utf8');
  return { keys: JSON.parse(content), sha: data.sha };
}

// Save keys.json to GitHub
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
      message: 'Admin Panel: Updated license keys',
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

// Middleware: Verify Admin Key
function verifyAdmin(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (authHeader !== `Bearer ${ADMIN_SECRET}` && authHeader !== `Bearer ANSHU-BAAP`) {
    return res.status(403).json({ error: 'Unauthorized: Invalid Admin Key' });
  }
  next();
}

// -------------------------------------------------------------
// ADMIN ENDPOINTS
// -------------------------------------------------------------

// 1. Login Verification
app.post('/api/admin/login', verifyAdmin, (req, res) => {
  res.json({ success: true, message: 'Access Granted' });
});

// 2. Set GitHub Config
app.post('/api/admin/config', verifyAdmin, (req, res) => {
  const { token, owner, repo } = req.body;
  if (!token || !owner || !repo) {
    return res.status(400).json({ error: 'All GitHub fields are required' });
  }
  gitHubConfig = { token, owner, repo };
  res.json({ success: true, message: 'Configuration saved' });
});

// 3. Get All Keys
app.post('/api/admin/keys', verifyAdmin, async (req, res) => {
  try {
    const { keys } = await getKeysFromGitHub();
    res.json({ keys });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 4. Generate Key
app.post('/api/admin/generate', verifyAdmin, async (req, res) => {
  const { durationDays = 30 } = req.body;
  try {
    let { keys, sha } = await getKeysFromGitHub();
    const newKey = generateLicenseKey();
    
    const keyObj = {
      key: newKey,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + parseInt(durationDays) * 24 * 60 * 60 * 1000).toISOString(),
      isRevoked: false,
      hardwareId: null
    };

    keys.push(keyObj);
    await saveKeysToGitHub(keys, sha);

    res.json({ success: true, key: newKey });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 5. Revoke Key
app.post('/api/admin/revoke', verifyAdmin, async (req, res) => {
  const { key } = req.body;
  try {
    let { keys, sha } = await getKeysFromGitHub();
    const index = keys.findIndex(k => k.key === key);
    if (index === -1) return res.status(404).json({ error: 'Key not found' });

    keys[index].isRevoked = true;
    await saveKeysToGitHub(keys, sha);
    res.json({ success: true, message: 'Key revoked successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 6. Delete Key
app.post('/api/admin/delete', verifyAdmin, async (req, res) => {
  const { key } = req.body;
  try {
    let { keys, sha } = await getKeysFromGitHub();
    const filtered = keys.filter(k => k.key !== key);
    if (filtered.length === keys.length) return res.status(404).json({ error: 'Key not found' });

    await saveKeysToGitHub(filtered, sha);
    res.json({ success: true, message: 'Key deleted successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// CLIENT APK VERIFICATION ENDPOINT
// -------------------------------------------------------------
app.post('/api/keys/verify', async (req, res) => {
  const { key, hardwareId } = req.body;
  if (!key) return res.status(400).json({ valid: false, message: 'Key is required' });

  try {
    const { keys, sha } = await getKeysFromGitHub();
    const found = keys.find(k => k.key === key);

    if (!found) {
      return res.status(400).json({ valid: false, message: 'Invalid Key' });
    }

    if (found.isRevoked) {
      return res.status(403).json({ valid: false, message: 'Key has been revoked' });
    }

    if (new Date() > new Date(found.expiresAt)) {
      return res.status(403).json({ valid: false, message: 'Key has expired' });
    }

    if (found.hardwareId && found.hardwareId !== hardwareId) {
      return res.status(403).json({ valid: false, message: 'Key bound to another device' });
    }

    // Bind hardware ID on first successful activation
    if (!found.hardwareId && hardwareId) {
      found.hardwareId = hardwareId;
      await saveKeysToGitHub(keys, sha);
    }

    res.json({ valid: true, message: 'Access Granted' });
  } catch (err) {
    res.status(500).json({ valid: false, message: 'Verification error' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
