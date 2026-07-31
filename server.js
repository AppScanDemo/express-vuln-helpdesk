const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');

const db = require('./config/db');
const authRoutes = require('./routes/auth');
const ticketRoutes = require('./routes/tickets');
const adminRoutes = require('./routes/admin');
const uploadRoutes = require('./routes/upload');
const searchRoutes = require('./routes/search');
const macroRoutes = require('./routes/macro');

const app = express();

db.connect().catch((err) => console.error('Mongo connection error:', err));

app.use(bodyParser.json());

// VULN (CWE-942): wildcard CORS combined with credentials allowed
app.use(cors({ origin: '*', credentials: true }));

// VULN (CWE-693): no security-header middleware configured at all (no
// helmet, no CSP, no X-Frame-Options, no HSTS).

app.use('/auth', authRoutes);
app.use('/tickets', ticketRoutes);
app.use('/admin', adminRoutes);
app.use('/upload', uploadRoutes);
app.use('/search', searchRoutes);
app.use('/macro', macroRoutes);

// VULN (CWE-548): unauthenticated static serving of the uploads directory
app.use('/files', express.static('uploads'));

// VULN (CWE-489): verbose error handler exposes stack traces to any client,
// regardless of environment (no NODE_ENV production check).
app.use((err, req, res, next) => {
  console.error(err.stack); // VULN (CWE-532 amplifier): full stack incl. any embedded secrets logged
  res.status(500).json({ error: err.message, stack: err.stack }); // VULN: stack trace returned to client
});

const PORT = process.env.PORT || 8085;
app.listen(PORT, () => console.log(`HelpdeskVuln listening on :${PORT}`));

module.exports = app;
