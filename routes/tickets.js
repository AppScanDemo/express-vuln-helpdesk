const express = require('express');
const Ticket = require('../models/Ticket');
const { weakAuth } = require('../middleware/weakAuth');

const router = express.Router();

/**
 * GET /tickets/:id — VULN (CWE-639): IDOR. No check that req.user owns this
 * ticket or holds the "agent"/"admin" role — any authenticated caller can
 * view any other customer's ticket.
 */
router.get('/:id', weakAuth, async (req, res) => {
  const ticket = await Ticket.findById(req.params.id);
  if (!ticket) return res.status(404).json({ error: 'not found' });
  res.json(ticket);
});

router.post('/', weakAuth, async (req, res) => {
  const ticket = new Ticket({
    ownerUserId: req.user.username,
    subject: req.body.subject,
    description: req.body.description, // stored verbatim, see stored XSS in routes/search.js html view
    status: 'open',
  });
  await ticket.save();
  res.status(201).json(ticket);
});

/**
 * GET /tickets?status=... — VULN (CWE-943): NoSQL Injection. The "status"
 * query parameter is passed directly into the Mongoose filter object. A
 * client sending ?status[$ne]=null (Express's extended query-string parser
 * turns this into {status: {$ne: null}}) returns every ticket in the
 * collection instead of filtering by a literal status value.
 */
router.get('/', weakAuth, async (req, res) => {
  const filter = { status: req.query.status }; // VULN sink
  const tickets = await Ticket.find(filter);
  res.json(tickets);
});

module.exports = router;
