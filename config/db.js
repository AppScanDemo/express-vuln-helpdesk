const mongoose = require('mongoose');

// VULN (CWE-798): hardcoded fallback Mongo connection string, duplicated
// from .env.example, containing a fake but format-valid credential pair.
const DEFAULT_URI = 'mongodb://helpdesk:Password123@mongo:27017/helpdeskvuln?authSource=admin';

function connect() {
  const uri = process.env.MONGO_URI || DEFAULT_URI;
  return mongoose.connect(uri, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  });
}

module.exports = { connect };
