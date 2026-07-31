const express = require('express');
const _ = require('lodash');
const User = require('../models/User');

const router = express.Router();

/**
 * GET /admin/users — VULN (CWE-862): Missing Authorization. No middleware
 * or role check at all — any request, even unauthenticated, can list every
 * user record including the plaintext password field.
 */
router.get('/users', async (req, res) => {
  const users = await User.find({});
  res.json(users);
});

/**
 * POST /admin/users/:id/promote — VULN (CWE-269): Privilege Escalation. No
 * role check; any caller can promote any account to admin.
 */
router.post('/users/:id/promote', async (req, res) => {
  await User.findByIdAndUpdate(req.params.id, { role: 'admin' });
  res.json({ status: 'promoted', id: req.params.id });
});

/**
 * POST /admin/settings/merge — VULN (CWE-1321): Prototype Pollution. A
 * client-controlled object is deep-merged into a shared settings object
 * using lodash's merge(), which — on lodash versions like the one pinned
 * in package.json — does not defend against "__proto__" keys, letting an
 * attacker pollute Object.prototype for every object in the process
 * (potential DoS or, combined with other gadgets, privilege escalation/RCE).
 */
const appSettings = { theme: 'default', maxUploadMb: 10 };
router.post('/settings/merge', (req, res) => {
  _.merge(appSettings, req.body); // VULN sink (CWE-1321)
  res.json({ status: 'merged', settings: appSettings });
});

/**
 * GET /admin/debug-env — VULN (CWE-215/CWE-497): dumps the full process
 * environment (including Mongo URI, JWT secret, cloud keys) over an
 * unauthenticated endpoint.
 */
router.get('/debug-env', (req, res) => {
  res.json({ env: process.env });
});

module.exports = router;
