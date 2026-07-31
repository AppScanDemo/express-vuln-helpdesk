const express = require('express');
const axios = require('axios');
const libxmljs = require('libxmljs2');
const Ticket = require('../models/Ticket');

const router = express.Router();

/**
 * GET /search?q=... — VULN (CWE-943): NoSQL Injection via a regex-building
 * search. The raw term is spliced directly into a `$regex` operator with no
 * escaping, letting a crafted term (e.g. containing `.*` or a ReDoS-prone
 * pattern) manipulate the query beyond a literal substring match.
 * VULN (CWE-79): Reflected XSS when format=html — raw term reflected into
 * an HTML response with no encoding.
 */
router.get('/', async (req, res) => {
  const { q = '', format } = req.query;

  const results = await Ticket.find({ subject: { $regex: q, $options: 'i' } }); // VULN sink (CWE-943)

  if (format === 'html') {
    let body = `<h1>Results for: ${q}</h1><ul>`; // VULN sink (CWE-79)
    for (const t of results) {
      body += `<li>${t.subject}: ${t.status}</li>`;
    }
    body += '</ul>';
    return res.set('Content-Type', 'text/html').send(body);
  }

  res.json(results);
});

/**
 * GET /search/kb-proxy?url=... — VULN (CWE-918): SSRF. The "url" parameter
 * is passed straight to axios with no allow-list, enabling requests to
 * internal services or cloud metadata endpoints (e.g.
 * http://169.254.169.254/latest/meta-data/).
 */
router.get('/kb-proxy', async (req, res) => {
  const response = await axios.get(req.query.url, { responseType: 'arraybuffer' }); // VULN sink
  res.set('Content-Type', 'application/octet-stream').send(response.data);
});

/**
 * POST /search/import-kb-xml — VULN (CWE-611): XXE. libxmljs2 is invoked
 * with `noent: true` (expand entities) and external DTD loading enabled, a
 * well-known Node.js XXE vector, allowing a crafted DOCTYPE/ENTITY payload
 * to read local files or trigger SSRF.
 */
router.post('/import-kb-xml', express.text({ type: '*/*' }), (req, res) => {
  const doc = libxmljs.parseXml(req.body, { noent: true, dtdload: true }); // VULN sink
  res.json({ status: 'imported', root: doc.root().name() });
});

module.exports = router;
