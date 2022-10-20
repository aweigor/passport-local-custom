/**
 * Module dependencies.
 */
 var passport = require('passport-strategy')
 , util = require('util')
 , lookup = require('./utils').lookup;


/**
* Creates an instance of `Strategy`.
*
* The anonymous authentication strategy passes authentication without verifying
* credentials.
*
* Applications typically use this as a fallback on endpoints that can respond
* to both authenticated and unauthenticated requests.  If credentials are not
* supplied, this stategy passes authentication while leaving `req.user` set to
* `undefined`, allowing the route to handle unauthenticated requests as
* desired.
*
* Examples:
*
*     passport.use(new AnonymousStrategy());
*
* @constructor
* @api public
*/
function Strategy(options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = {};
  }
  if (!verify) { throw new TypeError('JSONStrategy requires a verify callback'); }
  this._identityField = options.identityField || 'username';
  this._extraFields = options.extraFields || [];
  this._verify = verify;
  passport.Strategy.call(this);
  this.name = 'local';
}

/**
* Inherit from `passport.Strategy`.
*/
util.inherits(Strategy, passport.Strategy);

/**
 * `Strategy` constructor.
 *
 * The local authentication strategy authenticates requests based on the
 * credentials submitted through an HTML-based login form.
 *
 * Applications must supply a `verify` callback which accepts `username` and
 * `password` credentials, and then calls the `done` callback supplying a
 * `user`, which should be set to `false` if the credentials are not valid.
 * If an exception occured, `err` should be set.
 *
 * Optionally, `options` can be used to change the fields in which the
 * credentials are found.
 *
 * Options:
 *   - `usernameField`  field name where the username is found, defaults to _username_
 *   - `passwordField`  field name where the password is found, defaults to _password_
 *   - `passReqToCallback`  when `true`, `req` is the first argument to the verify callback (default: `false`)
 *
 * Examples:
 *
 *     passport.use(new LocalStrategy(
 *       function(username, password, done) {
 *         User.findOne({ username: username, password: password }, function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
Strategy.prototype.authenticate = function(req, options) {
  options = options || {};

  var identity = lookup(req.body, this._identityField) || lookup(req.query, this._identityField);
  var userData = this._extraFields.map( f => [f, lookup(req.body, f) || lookup(req.query, f)] );
  var user = Object.fromEntries( userData );
  user[this._identityField] = identity;
  
  if (!identity) {
    return this.fail({ message: options.badRequestMessage || 'Missing credentials' }, 400);
  }
  
  var self = this;
  
  function verified(err, user, info) {
    if (err) { return self.error(err); }
    if (!user) { return self.fail(info); }
    self.success(user, info);
  }
  
  try {
    this._verify(req, {user, identity}, verified);
  } catch (ex) {
    return self.error(ex);
  }
};


/**
* Expose `Strategy`.
*/
module.exports = Strategy;
