const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const router = express.Router();

// VULN (CWE-434): Unrestricted File Upload. Multer's diskStorage uses the
// client-supplied original filename verbatim — no extension allow-list, no
// MIME-type validation, no size limit, no AV scan.
// VULN (CWE-22): Path Traversal — a filename like "../../server.js" is used
// as-is, allowing writes outside the intended uploads directory.
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, path.join(__dirname, '..', 'uploads')),
  filename: (req, file, cb) => cb(null, file.originalname), // VULN sink
});
const upload = multer({ storage });

router.post('/', upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'file required' });
  res.json({ status: 'uploaded', path: req.file.path });
});

module.exports = router;
