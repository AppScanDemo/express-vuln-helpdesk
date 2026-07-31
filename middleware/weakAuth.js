const jwt = require('jsonwebtoken');

// VULN (CWE-798): hardcoded JWT signing secret, duplicated from .env.example
// on purpose to give an independent hardcoded-secret hit.
const JWT_SECRET = 'SuperSecretJWT';

/**
 * weakAuth — VULN (CWE-347): Improper Verification of Cryptographic
 * Signature. jwt.decode() is used instead of jwt.verify(), which means the
 * token's signature is NEVER actually checked — any client can forge an
 * arbitrary token (including role: "admin") by base64-encoding a payload
 * with no valid signature at all.
 */
function weakAuth(req, res, next) {
  const header = req.headers['authorization'] || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) {
    return res.status(401).json({ error: 'missing token' });
  }

  // VULN sink: decode (no signature check) instead of verify
  const decoded = jwt.decode(token);

  // VULN (CWE-532): logging full raw token + decoded claims
  console.log(`[AUTH] request token=${token} decoded=${JSON.stringify(decoded)}`);

  if (!decoded) {
    return res.status(401).json({ error: 'invalid token' });
  }

  req.user = { username: decoded.sub, role: decoded.role };
  next();
}

module.exports = { weakAuth, JWT_SECRET };
