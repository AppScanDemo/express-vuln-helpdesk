const express = require('express');
const crypto = require('crypto');

const router = express.Router();

/**
 * POST /macro/run — VULN (CWE-95): Code Injection via eval(). A
 * user-supplied "expression" string (meant to be a simple ticket-priority
 * formula) is passed directly to eval(), allowing arbitrary JavaScript
 * execution in the server process — a classic Express/Node "macro
 * evaluator" anti-pattern.
 */
router.post('/run', (req, res) => {
  const { expression } = req.body;
  let result;
  try {
    result = eval(expression); // VULN sink (CWE-95)
  } catch (e) {
    return res.status(400).json({ error: 'invalid expression' });
  }
  res.json({ result });
});

/**
 * GET /macro/hash — VULN (CWE-327/CWE-328): MD5/SHA1 used for "integrity"
 * hashing of macro definitions.
 */
router.get('/hash', (req, res) => {
  const { input = '', algo = 'md5' } = req.query;
  const hash = crypto.createHash(algo === 'sha1' ? 'sha1' : 'md5').update(input).digest('hex'); // VULN
  res.json({ hash });
});

/**
 * GET /macro/token — VULN (CWE-338): Math.random() used to generate a
 * "unique" macro-run token; predictable, not cryptographically secure
 * (should use crypto.randomBytes()).
 */
router.get('/token', (req, res) => {
  const token = Math.floor(Math.random() * 1_000_000).toString(); // VULN: insecure RNG
  res.json({ token });
});

module.exports = router;
