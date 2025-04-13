// Required modules
const express = require('express');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Paths
const UPLOADS_FOLDER = path.join(__dirname, 'uploads');
const DATA_FOLDER = path.join(__dirname, 'data');
const MAPPINGS_FILE = path.join(DATA_FOLDER, 'mappings.json');

// Ensure folders/files exist
if (!fs.existsSync(UPLOADS_FOLDER)) fs.mkdirSync(UPLOADS_FOLDER, { recursive: true });
if (!fs.existsSync(DATA_FOLDER)) fs.mkdirSync(DATA_FOLDER, { recursive: true });
if (!fs.existsSync(MAPPINGS_FILE)) fs.writeFileSync(MAPPINGS_FILE, '{}');

// Multer config
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_FOLDER),
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname),
});
const upload = multer({ storage });

// Helpers
function getExpiryTimestamp(label) {
  const now = Date.now();
  switch (label) {
    case "1min": return now + 60000;
    case "10min": return now + 10 * 60000;
    case "1hr": return now + 3600000;
    case "3hrs": return now + 3 * 3600000;
    case "24hrs": return now + 24 * 3600000;
    case "7days": return now + 7 * 24 * 3600000;
    case "1month": return now + 30 * 24 * 3600000;
    default: return null;
  }
}

function encrypt(text, key) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', crypto.scryptSync(key, 'salt', 32), iv);
  const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(data, key) {
  const [ivHex, encryptedHex] = data.split(':');
  const iv = Buffer.from(ivHex, 'hex');
  const encrypted = Buffer.from(encryptedHex, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', crypto.scryptSync(key, 'salt', 32), iv);
  const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
  return decrypted.toString('utf8');
}

app.post('/upload', upload.single('file'), (req, res) => {
  const { customLink, deleteAfter, textContent } = req.body;

  if (!customLink) {
      return res.status(400).send("Custom link is required");
  }

  const mappings = JSON.parse(fs.readFileSync(MAPPINGS_FILE));
  if (mappings[customLink]) {
      return res.status(400).send("Custom link already exists");
  }

  const expiry = getExpiryTimestamp(deleteAfter);
  if (!expiry) {
      return res.status(400).send("Invalid deleteAfter value");
  }

  let filePath = null;
  let textPath = null;

  if (req.file) {
      filePath = req.file.filename;
  }

  if (textContent) {
      const textFileName = `${Date.now()}-${customLink}.txt`;
      textPath = textFileName;
      fs.writeFileSync(path.join(UPLOADS_FOLDER, textFileName), textContent);
  }

  mappings[customLink] = {
      file: filePath,
      text: textPath,
      expiresAt: expiry,
  };

  fs.writeFileSync(MAPPINGS_FILE, JSON.stringify(mappings, null, 2));
  res.send("Upload successful! Your link: /" + customLink);
});

app.get('/:customLink', (req, res) => {
  const customLink = req.params.customLink;
  const mappings = JSON.parse(fs.readFileSync(MAPPINGS_FILE));

  const data = mappings[customLink];

  if (!data) {
    return res.status(404).send("Custom link not found.");
  }

  const now = Date.now();
  if (data.expiresAt && now > data.expiresAt) {
    return res.status(410).send("This link has expired.");
  }

  // Serve file if exists
  if (data.file) {
    const filePath = path.join(UPLOADS_FOLDER, data.file);
    if (fs.existsSync(filePath)) {
      return res.download(filePath); // or res.sendFile(...) to display inline
    } else {
      return res.status(404).send("File not found.");
    }
  }

  // Serve text if exists
  if (data.text) {
    const textPath = path.join(UPLOADS_FOLDER, data.text);
    if (fs.existsSync(textPath)) {
      const content = fs.readFileSync(textPath, 'utf-8');
      return res.send(`<pre>${content}</pre>`);
    } else {
      return res.status(404).send("Text content not found.");
    }
  }

  return res.status(404).send("No content available.");
});

// Upload secure route
app.post('/secure-upload', upload.single('file'), (req, res) => {
  const { customLink, textContent, deleteAfter, key } = req.body;
  let mappings = JSON.parse(fs.readFileSync(MAPPINGS_FILE, 'utf-8'));

  if (mappings[customLink]) {
    return res.status(409).send('Custom link already exists');
  }

  const expiresAt = getExpiryTimestamp(deleteAfter);

  if (req.file) {
    const fileBuffer = fs.readFileSync(req.file.path);
    const encryptedContent = encrypt(fileBuffer.toString('base64'), key);
    fs.writeFileSync(path.join(UPLOADS_FOLDER, req.file.filename), encryptedContent);

    mappings[customLink] = {
      type: 'file',
      filename: req.file.filename,
      originalName: req.file.originalname,
      deleteAfter,
      expiresAt,
      isEncrypted: true
    };
  } else if (textContent) {
    const encryptedText = encrypt(textContent, key);
    mappings[customLink] = {
      type: 'text',
      content: encryptedText,
      deleteAfter,
      expiresAt,
      isEncrypted: true
    };
  } else {
    return res.status(400).send('No file or text provided');
  }

  fs.writeFileSync(MAPPINGS_FILE, JSON.stringify(mappings, null, 2));
  res.status(200).send(`Secure upload successful! Access it at /secure/${customLink}`);
});

// Secure Access Page
app.get('/secure/:customLink', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'keyprompt.html'));
});

// Secure POST route (shared logic)
function handleDecryption(req, res) {
  const { customLink, key } = req.body;
  let mappings = JSON.parse(fs.readFileSync(MAPPINGS_FILE, 'utf-8'));
  const data = mappings[customLink];
  const now = Date.now();

  if (!data) return res.status(404).send('Custom link not found.');
  if (data.expiresAt && now > data.expiresAt) {
    if (data.type === 'file') {
      const filePath = path.join(UPLOADS_FOLDER, data.filename);
      if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    }
    delete mappings[customLink];
    fs.writeFileSync(MAPPINGS_FILE, JSON.stringify(mappings, null, 2));
    return res.status(410).send('This link has expired.');
  }

  try {
    if (data.type === 'file') {
      const encryptedFile = fs.readFileSync(path.join(UPLOADS_FOLDER, data.filename), 'utf-8');
      const decrypted = decrypt(encryptedFile, key);
      const buffer = Buffer.from(decrypted, 'base64');
      const tempPath = path.join(__dirname, 'temp', data.filename);
      if (!fs.existsSync('temp')) fs.mkdirSync('temp');
      fs.writeFileSync(tempPath, buffer);
      res.download(tempPath, data.originalName, err => {
        if (err) res.status(500).send('Download failed.');
        fs.unlinkSync(tempPath);
      });
    } else {
      const decrypted = decrypt(data.content, key);
      res.setHeader('Content-Type', 'text/plain');
      res.send(decrypted);
    }
  } catch (err) {
    res.status(401).send('Invalid decryption key.');
  }
}

// Decryption POST routes
app.post('/secure-access', handleDecryption);
app.post('/secure/decrypt', handleDecryption); // <-- Fix for your form

// Auto-cleaner
setInterval(() => {
  let mappings = JSON.parse(fs.readFileSync(MAPPINGS_FILE, 'utf-8'));
  let now = Date.now();
  let changed = false;

  for (let key in mappings) {
    let entry = mappings[key];
    if (entry.expiresAt && now > entry.expiresAt) {
      console.log(`Auto-deleting expired: ${key}`);
      if (entry.type === 'file') {
        const filePath = path.join(UPLOADS_FOLDER, entry.filename);
        if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
      }
      delete mappings[key];
      changed = true;
    }
  }

  if (changed) fs.writeFileSync(MAPPINGS_FILE, JSON.stringify(mappings, null, 2));
}, 60 * 1000);

// Start server
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
