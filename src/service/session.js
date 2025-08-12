'use strict';

// TODO: Implement rolling session secret.
const MAX_SESSION_AGE_MS = 7 * 24 * 60 * 60 * 1000;  // 7 days in ms (was off by a day before)

var crypto = require('crypto');

module.exports = Session;

/**
 * @class Manages a long-lived client session.  Supports signed save/load for
 * storage offload to client.
 *
 * @param logger Winston instance.
 * @param properties Properties object containing configuration.
 */
function Session(logger, properties) {
    this.logger = logger;
    this.properties = properties;

    const firstId = crypto.randomBytes(16).toString('hex');

    this._contents = {
        clientId: firstId,  // kept for backward-compat; mirrors connectionId
        existingClientId: undefined,
        existingClientIds: undefined,
        deviceId: undefined,
        token: undefined,
        userId: undefined,
        mailboxId: 'M_' + firstId,      // stable
        connectionId: firstId           // rotating
    };

    this._dirty = true;
}

Session.content_keys = [
    'clientId',
    'existingClientId',
    'existingClientIds',
    'deviceId',
    'token',
    'userId',
    'mailboxId',
    'connectionId'
];

// Creates a getter/setter pair for each piece of session data.
Session.content_keys.forEach(function(key) {
    Object.defineProperty(Session.prototype, key, {
        enumerable: true,
        get: function(){ return this._contents[key] },
        set: function(value){ this._contents[key] = value; this._dirty=true; }
    });
});


Session.prototype.clone = function(copy) {
    copy = copy || {};
    Object.keys(this._contents).forEach(function(key) {
        copy[key] = this[key];
    }, this);
    return copy;
};

Session.prototype.signSession = function(encodedSession) {
    var hmac = crypto.createHmac('sha512', this.properties['frontend.session_secret'] || 'twothreefour');
    hmac.update(encodedSession);

    return hmac.digest('base64');
};

/**
 * Provides a signed copy of this session to the callback if this session is
 * dirty.  This session is dirty if it has been modified since it was last
 * saved (modification includes load()s).  Runs on the next tick so any
 * pending session changes are included.
 *
 */
Session.prototype.getSignedSession = function() {
    this._dirty = false;
    var jsonCopy = JSON.stringify(this.clone({ savedAt: Date.now() }));

    var encodedSession = Buffer.from(jsonCopy).toString('base64');
    return (encodedSession + ';' + this.signSession(encodedSession));
};

/**
 * Calls the callback with the current state of _isDirty. This allows
 * all pending updates to the session to take place before this check
 * is executed.
 *
 * @param callback {Function}
 */
Session.prototype.isDirtyAsync = function(callback){
    process.nextTick(function() {
        callback(this._dirty);
    }.bind(this));
}

/**
 * Validates this session string and, if valid, loads its contents into this
 * session.
 *
 * @param {String} signedSession
 * @returns {Boolean} True if valid and false if invalid.
 */
Session.prototype.load = function(signedSession) {
    if (!signedSession || typeof signedSession.split !== 'function') {
        this.logger.warn('Dropping invalid session (typeof signedSession.split !== function): ' + signedSession);
        return false;
    }
    const parts = signedSession.split(';');

    if (parts.length != 2) {
        this.logger.warn('Dropping invalid session (parts.length != 2): ' + signedSession);
        return false;
    }

    var encodedSession = parts[0];
    var signature = parts[1];

    if (signature != this.signSession(encodedSession)) {
        this.logger.warn('Dropping (potentially) tampered session: ' + signedSession);
        return false;
    }

    let copy;
    try {
        copy = JSON.parse(Buffer.from(encodedSession, 'base64').toString());
    } catch (e) {
        this.logger.warn('Dropping unparseable session: ' + signedSession);
        return false;
    }

    if (copy.savedAt < Date.now() - MAX_SESSION_AGE_MS) {
        this.logger.warn('Dropping expired session: ' + signedSession);
        return false;
    }
    delete copy.savedAt;

    // Merge only defined keys to avoid clobbering with undefined (backward compat)
    Session.content_keys.forEach(function (key) {
        if (Object.prototype.hasOwnProperty.call(copy, key) && typeof copy[key] !== 'undefined') {
            this[key] = copy[key];
            delete copy[key];
        }
    }, this);

    // --- Migration & invariants ---

    // Ensure we always have a stable mailboxId (for legacy tokens)
    if (!this.mailboxId) {
        const seed = this.clientId || this.connectionId || _randId();
        this.mailboxId = 'M_' + seed;
    }

    // Rotate the per-connection id on every load (reconnect),
    // and keep clientId mirroring it for legacy code paths.
    this.rotateConnection();

    // Mark dirty so the client gets a refreshed token (new savedAt)
    this._dirty = true;

    var leftovers = Object.keys(copy);
    if (leftovers.length > 0) {
        this.logger.warn('Dropping unexpected session keys ' +
        JSON.stringify(leftovers) + ': ' + signedSession);
    }

    this.logger.debug('Loaded session: ', this._contents);
    return true;
};

/**
 * Add the properties of this session to the given message.
 * Really just a synonym for clone
 * @param {Object} [message={}] The object to decorate.
 */
Session.prototype.populateMessage = function(message) {
    return this.clone(message);
};

/**
 * Clears the session properties pertaining to the logged in session.  This
 * will finalize on the next tick so anything currently running can finish
 * with the current session.
 */
Session.prototype.logout = function() {
    process.nextTick(function() {
        this.token = undefined;
        this.userId = undefined;
    }.bind(this));
};

/**
 * Validates the current session contains logged-in credentials.  The
 * credentials may be expired as we have no way of knowing here.
 *
 * @returns {Boolean} True if session appears to be logged-in.
 */
Session.prototype.isLoggedIn = function() {
    return !!this.userId;
};

/**
 * Rotate only the per-connection identity (keep mailboxId stable).
 * Mirrors clientId to connectionId for backward compatibility.
 */
Session.prototype.rotateConnection = function () {
  const next = crypto.randomBytes(16).toString('hex');
  this.connectionId = next;
  this.clientId = next;
  this._dirty = true;
  return next;
};