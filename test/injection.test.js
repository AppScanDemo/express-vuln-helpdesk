const { expect } = require('chai');
const _ = require('lodash');

describe('NoSQL injection surface (documented via query-shape assertions)', () => {
  it('demonstrates that an object operator bypasses a literal-value match', () => {
    // This mirrors what routes/auth.js does: `User.findOne({ username, password })`
    // where username/password come straight from req.body. If a client sends
    // {"username": {"$ne": null}}, Express/body-parser hands that through as
    // a real object, not a string — which is exactly the shape Mongo
    // interprets as an operator instead of a literal to match against.
    const attackerBody = { username: { $ne: null }, password: { $ne: null } };

    expect(typeof attackerBody.username).to.equal('object');
    expect(attackerBody.username).to.have.property('$ne');
    // A safe implementation must reject non-string username/password before
    // ever reaching Mongoose; the vulnerable route in routes/auth.js does not.
  });
});

describe('Prototype pollution surface (routes/admin.js settings/merge)', () => {
  afterEach(() => {
    // Clean up in case the assertion below actually pollutes the prototype,
    // so this test suite doesn't leak global state into other test files.
    delete Object.prototype.polluted;
  });

  it('documents that lodash.merge can write onto Object.prototype via __proto__', () => {
    const target = {};
    const maliciousPayload = JSON.parse('{"__proto__": {"polluted": true}}');

    _.merge(target, maliciousPayload); // same call shape as routes/admin.js

    // On a vulnerable lodash version, this now affects every plain object,
    // not just `target` — demonstrating why CWE-1321 is a process-wide risk.
    const freshObject = {};
    expect(freshObject.polluted).to.equal(true);
  });
});
