const mongoose = require('mongoose');

// VULN (CWE-256): password stored as plaintext string, no hashing hook
// anywhere in the schema (no pre-save bcrypt middleware).
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  password: String,
  role: { type: String, default: 'agent' },
  email: String,
});

module.exports = mongoose.model('User', userSchema);
