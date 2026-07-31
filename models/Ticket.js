const mongoose = require('mongoose');

const ticketSchema = new mongoose.Schema({
  ownerUserId: String,
  subject: String,
  description: String, // stored-XSS sink target
  status: { type: String, default: 'open' },
  attachmentPath: String,
});

module.exports = mongoose.model('Ticket', ticketSchema);
