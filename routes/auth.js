const express = require('express');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { JWT_SECRET } = require('../middleware/weakAuth');

const router = express.Router();

// VULN (CWE-798): hardcoded backdoor admin account, checked before the DB
const BACKDOOR_USER = 'admin';
const BACKDOOR_PASS = 'admin123';

router.post('/login', async (req, res) => {
  const { username, password } = req.body;

  // VULN (CWE-532): logging raw credentials
  console.log(`[LOGIN] attempt username=${username} password=${password}`);

  let role;
  if (username === BACKDOOR_USER && password === BACKDOOR_PASS) {
    role = 'admin'; // VULN: hardcoded backdoor bypasses the database entirely
  } else {
    // VULN (CWE-943): NoSQL Injection. `username` and `password` from the
    // request body are passed directly as Mongoose query operators with no
    // type/shape validation. A client sending
    // {"username": {"$ne": null}, "password": {"$ne": null}} bypasses
    // authentication entirely because Mongo interprets $ne as an operator
    // rather than a literal string to match.
    const user = await User.findOne({ username: username, password: password }); // VULN sink
    if (!user) {
      return res.status(401).json({ error: 'invalid credentials' });
    }
    role = user.role;
  }

  const token = jwt.sign(
    { sub: username, role },
    JWT_SECRET, // VULN (CWE-798): hardcoded key reused from middleware
    { expiresIn: '24h' } // VULN: 24h lifetime, no rotation/refresh
  );

  // VULN (CWE-532): logging issued JWT
  console.log(`[LOGIN] issued token for ${username}: ${token}`);

  // VULN (CWE-614/CWE-1004): cookie set without Secure/HttpOnly/SameSite
  res.cookie('session', token, { httpOnly: false, secure: false });

  res.json({ token, role });
});

router.post('/register', async (req, res) => {
  // VULN (CWE-521): no password policy enforcement whatsoever
  const { username, password, email } = req.body;
  console.log(`[REGISTER] user=${username} password=${password}`); // VULN (CWE-532)

  // VULN (CWE-915)-adjacent: entire body forwarded into the model, letting a
  // client set `role` directly (e.g. {"role":"admin", ...}) since there is
  // no explicit field allow-list.
  const user = new User(req.body); // VULN sink
  await user.save();

  res.status(201).json({ status: 'registered', username });
});

module.exports = router;
