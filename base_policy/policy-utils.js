// Copyright (c) 2011 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/**
 * Check the validity of the policy extension manifest.
 *
 * This function is invoked by entd before the policy is loaded in order to
 * check the validity of the extension manifest.  If this function returns
 * false, entd exits and does not restart until the next user logs in.
 *
 * @param manifest {Object} The deserialized extension manifest for the
 *   enterprise policy.
 */

const Slot = entd.crypto.Pkcs11.Slot;
const Token = entd.crypto.Pkcs11.Token;
const Session = entd.crypto.Pkcs11.Session;
const PkObject = entd.crypto.Pkcs11.Object;
const CSR = entd.crypto.OpenSSL.CSR;
const X509 = entd.crypto.OpenSSL.X509;

// PKCS#11 to use for token management.
Policy.OPENSSL_ENGINE = 'pkcs11';

// PKCS#11 slot index to use.
Policy.PKCS11_SLOT = 0;

entd.verifyManifest =
function verifyManifest(manifest) {
  function fail(msg) {
    entd.syslog.error('verifyManifest: ' + msg);
    return false;
  };

  if (!('name' in manifest) || typeof manifest.name != 'string')
    return fail('Invalid or missing "name"');

  if (!manifest.name.match(/chrom(e|ium)\s?os enterprise policy/i))
    return fail('Invalid manifest name: ' + manifest.name);

  if (!('description' in manifest) || typeof manifest.description != 'string')
    return fail('Invalid or missing "description"');

  var ary = manifest.description.match(
      /chrom(?:e|ium)\s?os enterprise policy for (\S+)(\s+.*)?/i);
  if (!ary)
    return fail('Invalid manifest description: ' + manifest.description);

  try {
    entd.hostname = ary[1];
  } catch (ex) {
    return fail('Error setting hostname to "' + ary[1] + '": ' + ex);
  }

  if (manifest.permissions) {
    perms = manifest.permissions;
    if (typeof perms == "string")
      perms = [ perms ];

    if (!(perms instanceof Array))
      return fail('Invalid type for permissions: ' + perms);

    if (perms.length != 1 || perms[0].indexOf("http://127.0.0.1/") != 0)
      return fail('Invalid permissions: ' + perms);
  }

  return true;
}

entd.http.RESPONSE_OK = 200;

/**
 * Policy constructor.
 *
 * Constructs a new policy object.  The Policy class provides a framework
 * for entd security policies.  It allows a policy implementor to declare
 * most of their policy, without having to write too much JavaScript.
 *
 * A policy implementor may choose to ignore this class and create their
 * own policy infrastructure if necessary.  The Enterprise Daemon does not
 * require this specific class, or any class like it.
 *
 * @param {Object} manifest The extension manifest, as reported by entd.
 */
function Policy(manifest) {
  this.logMessages = [];

  this.info('Initializing: ' + manifest.description);
  this.info('Current user: ' + entd.username);

  // Certificate definitions to be populated later by this.addCertificate().
  this.certificates = {};

  // Save off the entire manifest in case we need it later.
  this.manifest = manifest;

  // Set the required magic header value for the callback server.
  if ('requestHeaderValue' in manifest)
    entd.callbackServer.requestHeaderValue = manifest.requestHeaderValue;

  this.variables_ = {};
  if (manifest.variables) {
    // The manifest may have set some parameters for this policy.  If
    // so, we want to copy them into the params object after making sure
    // the variable names are safe to use as keys.
    for (name in manifest.variables)
      this.setVariable(name, params[name]);
  }

  // The CSR definition can reference properties of the params object.  We
  // copy the user info there so that it can be substituted into the CSR fields.
  if (!entd.username)
    throw new Error('Unable to determine current username');

  var ary = entd.username.match(/([^@]+)@(.*)/);
  this.setVariable('userEmail', entd.username);
  this.setVariable('userName', ary[1]);
  this.setVariable('userDomain', ary[2]);

  this.callbacks = new Policy.Callbacks(this);

  // Load the browser policy settings from the manifest, if they're set.  Keep
  // track of whether or not the policy has changed, so that we can warn the
  // user that they need to restart.
  this.browserPolicyChanged = false;

  if (manifest.browser) {
    if (manifest.browser.managedPolicy) {
      if (this.setBrowserPolicy("managed", manifest.browser.managedPolicy))
        this.browserPolicyChanged = true;
    }

    if (manifest.browser.recommendedPolicy) {
      if (this.setBrowserPolicy("recommended",
                                manifest.browser.recommendedPolicy)) {
        this.browserPolicyChanged = true;
      }
    }
  }

  // Kick off PKCS11 initialization.
  this.pkcs11 = {
    api: null,
    error: null,
    initCount: 0
  };

  entd.setTimeout(util.bindp(this, 'initPkcs11'), 1);
}

// Security Officer PIN for the PKCS11 token.
Policy.PKCS11_SO_PIN = '000000';

// User PIN for the PKCS11 token.
Policy.PKCS11_USER_PIN = '111111';

/**
 * Log an information status message.
 *
 * @param  {string} str The informational message to log.
 * @return {string} The string logged.
 */
Policy.prototype.info =
function info(str) { return this.log_('info', str) };

/**
 * Log a warning status message.
 *
 * @param  {string} str The warning message to log.
 * @return {string} The string logged.
 */
Policy.prototype.warn =
function warn(str) { return this.log_('warn', str) };

/**
 * Log an error status message.
 *
 * @param  {string} str The error message to log.
 * @return {string} The string logged.
 */
Policy.prototype.error =
function error(str) { return this.log_('error', str) };

Policy.prototype.log_ =
function log_(type, str) {
  entd.syslog[type](str);
  this.logMessages.push(str);
};

/**
 * Return a log marker.
 *
 * The return value of this function can be passed back in to
 * Policy.prototype.getLog() to fetch the log messages that have occurred since
 * the mark.
 *
 * @return {int} A log marker.
 */
Policy.prototype.getLogMark =
function getLogMark() {
  return this.logMessages.length - 1;
}

/**
 * Get all of the log messages that have occurred since a given mark.
 *
 * Returns all log messages that have occurred since a given mark as a single
 * string.  If no mark is provided, all log messages are returned.
 *
 * @param {int} mark Optional. The mark representing the starting point in the
 *   log that you are interested in.
 * @return {string} Newline delimited log messages.
 */
Policy.prototype.getLog =
function getLog(mark) {
  if (!mark)
    return this.logMessages.join('\n');

  return this.logMessages.slice(mark + 1).join('\n');
}

/**
 * Record the starting point of an asynchronous operation on a given object.
 *
 * Use this in conjunction with Policy.prototype.stop() to record status and
 * log messages about an asynchronous operation pertaining to the given
 * object.
 *
 * The object in question should be considered unstable (because some
 * ongoing operation on the object has not completed) until a corresponding
 * stop() call is made.
 *
 * @param {Object} obj The object that is the subject of the operation.
 * @param {string} state A short identifier for the operation being started.
 * @param {string} msg Optional. An informational message to log.
 */
Policy.prototype.start =
function start(obj, state, msg) {
  obj.state = 'start:' + state;
  obj.log = "";
  obj.mark_ = this.getLogMark();

  if (msg)
    this.info(msg);
}

/**
 * Record the completion of an asynchrnous operation on a given object.
 *
 * Call this after an operation started with Policy.prototype.start() has
 * completed.  This indicates that the current state of the object is stable,
 * although the operation itself may not have been successful, or another
 * operation may be required before the object is ready for use.
 *
 * The stop state may be any short idenfitier, though by convention you should
 * use 'error' to mean that the operation completed with an error condition,
 * and 'ready' when the object is has been fully initialized and is ready for
 * general use.
 *
 * @param {Object} obj The object that is the subject of the operation.
 * @param {string} state A short identifier for the operation being started.
 * @param {string} msg Optional. A message to log.  If the state parameter is
 *  'error', then the message is logged with the error severity, otherwise it
 *  will be logged as an informational message.
 */
Policy.prototype.stop =
function stop(obj, state, msg) {
  if (msg) {
    if (state == 'error')
      this.error(msg);
    else
      this.info(msg);
  }

  obj.state = 'stop:' + state;
  obj.log = this.getLog(obj.mark);
  obj.mark_ = null;
}

/**
 * Set a variable for this policy.
 *
 * Variables can be referenced in various parts of the policy and
 * certificate configuration.  This function is used to assign a value to
 * a variable.
 *
 * @param {string} name The name of the variable.
 * @param {string} value The value of the variable.
 */
Policy.prototype.setVariable =
function setVariable(name, value) {
  this.variables_[util.toKey(name)] = value;
};

/**
 * Get a variable for this policy.
 *
 * Variables can be referenced in various parts of the policy and
 * certificate configuration.  This function is used to retrieve the value of
 * a variable.
 *
 * @param {string} name The name of the variable.
 * @param {string} opt_default Optional default value.
 */
Policy.prototype.getVariable =
function getVariable(name, opt_default) {
  var key = util.toKey(name);
  if (key in this.variables_)
    return this.variables_[key];

  return defval;
};

/**
 * Add a certificate definition to this policy.
 *
 * @param {string} type An identifier for the certificate definition.
 * @param {Object} params The parameters for this certificate.  See the
 *     documentation for the Policy.Certificate constructor for details.
 */
Policy.prototype.addCertificate =
function addCertificate(type, params) {
  var cert = new Policy.Certificate(this, type, params);
  this.certificates[util.toKey(type)] = cert;
  return cert;
};

/**
 * Initialize the PKCS#11 API.
 *
 * If the API fails to initialize, then this will retry every second until
 * initialization succeeds.
 */
Policy.prototype.initPkcs11 =
function initPkcs11() {
  if (this.pkcs11.api) {
    // Already initialized.
    return true;
  }

  this.start(this.pkcs11, 'init');

  ++this.pkcs11.initCount;

  this.info('Initializing PKCS#11 library, attempt: ' +
            this.pkcs11.initCount);

  if ('isTokenReady' in entd.tpm) {
    if (!entd.tpm.isTokenReady) {
      // The TPM token is not yet initialized by cryptohomed and we
      // must not load PKCS11 until it has finished.  Re-check again
      // in a second.
      this.info('TPM token not yet initialized, delaying library load.');
      entd.setTimeout(util.bindp(this, "initPkcs11"), 1000);
      return false;
    }
  }

  try {
    this.pkcs11.api = new entd.crypto.Pkcs11();
    this.info('entd.cryto.Pkcs11 initialized.');
  } catch (ex) {
    this.error('PKCS#11 library failed to initialize: ' + ex);
    this.pkcs11.error = ex;
  }

  if (!this.pkcs11.api) {
    // Initialization failed, try again in a second.
    entd.setTimeout(util.bindp(this, "initPkcs11"), 1000);
    return false;
  }

  for (var key in this.certificates) {
    this.info('checking certificate: ' + key);
    var cert = this.certificates[key];
    if (cert.isInstalled()) {
      cert.onInstall_(/* firstInstall: */ false);
    }
  }

  var pkcs11 = this.pkcs11.api;
  for (var i = 0; i < pkcs11.slots.length; ++i) {
    var token = pkcs11.slots[i].token;
    if (!token)
      continue;

    if (this.checkToken(token)) {
      this.stop(token, 'ready');
    } else {
      this.stop(token, 'unknown');
    }
  }

  var engine = new entd.crypto.OpenSSL.Engine(Policy.OPENSSL_ENGINE);
  this.engine = engine;

  this.stop(this.pkcs11, 'ready');
  this.info('pkcs#11 ready');

  return true;
}

/**
 * Check if a PKCS11 token appears to be ready for use.
 *
 * This method returns true if the given token has been initialized, both
 * PINs have been set, and neither PIN is locked.
 */
Policy.prototype.checkToken =
function checkToken(token) {
  token.refresh();
  return ((token.flags & Token.CKF_TOKEN_INITIALIZED) &&
          (token.flags & Token.CKF_USER_PIN_INITIALIZED) &&
          !(token.flags & (Token.CKF_SO_PIN_TO_BE_CHANGED ||
                           Token.CKF_USER_PIN_TO_BE_CHANGED ||
                           Token.CKF_SO_PIN_LOCKED ||
                           Token.CKF_USER_PIN_LOCKED)));
}

/**
 * Initialize a PKCS11 token.
 *
 * This performs *only* the token initialization.  Callers must also reset
 * the SO and User PINs before the token is usable.
 *
 * @param {entd.crypto.Pkcs11.Token} token The token to initialize.
 * @param {string} tokenLabel Optional.  The label to assign to the new token.
 */
Policy.prototype.initToken =
function initToken(token, tokenLabel) {
  if (!tokenLabel)
    tokenLabel = "Initialized by CrOS";

  this.start(token, 'init',
             'Initializing token: ' + tokenLabel);

  var sopin;

  token.refresh();

  if (token.flags & Token.CKF_SO_PIN_TO_BE_CHANGED) {
    // If the SO pin hasn't been initialized yet, then it's the one
    // assigned by opencryptoki.
    sopin = Token.DEFAULT_SO_PIN;
  } else {
    // Otherwise, it *should be* the one we assigned when we initialized it.
    sopin = Policy.PKCS11_SO_PIN;
  }

  try {
    token.initToken(sopin, tokenLabel);
  } catch (ex) {
    this.stop(token, 'error', 'Initialization failed: ' + ex);
    return false;
  }

  token.refresh();

  if (!(token.flags & Token.CKF_TOKEN_INITIALIZED)) {
    this.stop(token, 'error', 'Token did not initialize.');
    return;
  }

  // Also, all of the certificate objects need to have their state reset.
  for (var key in this.certificates)
    this.certificates[key].state = 'stop:unknown';

  this.stop(token, 'init', 'Token initialized.');
  this.info('token state: ' + token.state);
  return true;
}

/**
 * Set a PIN on a PKCS11 token.
 *
 * Logs in to the given token using oldPin, then resets the pin to newPin and
 * logs out.
 *
 * @param {entd.crypto.Pkcs11.Token} token The target token.
 * @param {int} userType The type of user to reset.  Either Session.CKU_SO or
 *   Session.CKU_USER.
 * @param {string} oldPin The current PIN for this user.
 * @param {string} newPin The new PIN for this user.
 *
 * @return {boolean} True if the operation succeeded, false otherwise.
 */
Policy.prototype.setTokenPin =
function setTokenPins(token, userType, oldPin, newPin) {
  var pinType = (userType == Session.CKU_SO ? 'so' : 'user') + '-pin';
  this.start(token, pinType, 'Resetting PIN: ' + pinType);

  if (oldPin == newPin) {
    if (this.checkToken(token)) {
      this.stop(token, 'ready');
    } else {
      this.stop(token, pinType);
    }
    return true;
  }

  try {
    session = this.loginToken(token, userType, oldPin);
    if (!session)
      this.stop(token, 'error', 'Failed to login to token');
  } catch (ex) {
    this.stop(token, 'error', 'Exception initializing PIN: ' + ex);
    session.logoutAndClose();
    return false;
  }

  this.info('PIN Reset for: ' + pinType);

  try {
    session.setPin(oldPin, newPin);
    this.info('PIN Reset complete.');
  } catch (ex) {
    this.stop(token, 'error', 'Exception changing PIN: ' + ex);
    session.logoutAndClose();
    return false;
  }

  if (this.checkToken(token)) {
    this.stop(token, 'ready');
  } else {
    this.stop(token, pinType);
  }

  session.logoutAndClose();
  return true;
}

/**
 * Generate a RSA key pair on the PKCS#11 token.
 *
 * 'label' and 'id' parameters are user-friendly values that will be applied
 * to the generated keys.  They can be used later for documentation and/or
 * key search/match.
 *
 * @param {Session} session An open read/write session to the device.
 * @param {Integer} id Object ID to apply to public and private keys.
 * @param {String} label Label to apply to public and private keys.
 *
 * @return {void} No return value. On failure function throws an exception.
 */
Policy.prototype.generateKeyPair =
function generateKeyPair(session, id, label) {
  this.info('Generating key pair id: ' + id + ' label: ' + label +
            ' bits:2048.');
  session.generateKeyPair(
    Session.CKM_RSA_PKCS_KEY_PAIR_GEN,
    [
      // Public key properties.
      [PkObject.CKA_ENCRYPT, true],
      [PkObject.CKA_VERIFY, true],
      [PkObject.CKA_WRAP, true],
      [PkObject.CKA_MODULUS_BITS, 2048],
    ],
    [
      // Private key properties.
      [PkObject.CKA_PRIVATE, true],
      [PkObject.CKA_SENSITIVE, true],
      [PkObject.CKA_SIGN, true],
      [PkObject.CKA_DECRYPT, true],
      [PkObject.CKA_UNWRAP, true],
    ],
    [
      // Common properties of public & private.
      [PkObject.CKA_TOKEN, true],
      [PkObject.CKA_LABEL, label],
      [PkObject.CKA_ID, id]
    ]
  );
}

/**
 * Certificate Definition constructor
 *
 * A Policy.Certificate defines the parameters required to generate a
 * CSR and store the resulting certificate.  It does *not* represent the actual
 * certificate itself.
 *
 * The params object should be a plain JavaScript object with the following
 * properties:
 *
 * - 'label': A string defining a human readable label that uniquely identifies
 *     this certificate.
 *
 * - 'onInstall': (optional) A function to invoke when the certificate is
 *     successfully installed, or when entd starts up after having already
 *     installed the certificate.  The function will receive a single boolean
 *     parameter which indicates whether or not this is the first install
 *     of the certificate (parameter is true), or a restart of entd.
 *
 * - 'csr': An object defining the parameters of the Certificate Signing
 *       Request.  The object may have the following properties:
 *     - 'subject': A string continaing the subject for the CSR.
 *     - 'host': The hostname where the CSR should be sent.  This must be
 *         the same as, or a subdomain of, entd.hostname.
 *     - 'port': (optional) The port on the target host where the CSR should
 *         be sent.  Defaults to 443.
 *     - 'auth': (optional) HTTP Basic authorization for the request.  Any
 *         variable references will be resolved before sending the request.
 *     - 'path': The path to where the CSR should be sent.  CSRs are
 *         sent using the HTTP POST method.  Any variable references in the
 *         path are resolved before sending the request.
 *     - 'post_params': An optional JavaScript object containing parameters
 *         that should be sent with the POST.  Variable references in the
 *         values will be resolved before sending the request.
 *
 * - 'issue': An object defining the parameters of the Certificate issue
 *       request.  The object may have the following properties:
 *     - 'host': The hostname where the Certificate issue request should
 *         be sent.  This must be the same as, or a subdomain of, entd.hostname.
 *     - 'port': (optional) The port on the target host where the Certificate
 *         issue request should be sent.  Defaults to 443.
 *     - 'auth': (optional) HTTP Basic authorization for the request.  Any
 *         variable references will be resolved before sending the request.
 *     - 'path': The path to where the Certificate issue request should be
 *         sent.  Certificate issue requests are sent using the HTTP GET
 *         method.  Any variable references in the path are resolved before
 *         sending the request.
 *
 * See entd.crypto.Certificate() for the conrete certificate class.
 *
 * @param {Policy} policy The parent policy of this certificate definition.
 * @param {string} type An identifier for the certificate definition.
 * @param {Object} params The parameters for this certificate definition.
 */
Policy.Certificate =
function PolicyCertificate(policy, type, params) {
  this.policy = policy;
  this.type = type;

  // Backwards compatibility.
  if (!('id' in params)) {
    params.id = params.key_identifier || 3;
  }

  util.ensureProperties(params, ['label', 'id', 'csr', 'issuer'], 'params');

  this.label = params.label;
  this.id = parseInt(params.id);
  this.onInstall = params.onInstall;

  util.ensureProperties(params.csr, ['subject', 'host', 'path'], 'params.csr');
  this.csr = params.csr;

  util.ensureProperties(params.issuer, ['host', 'path'], 'params.issuer');
  this.issuer = params.issuer;

  this.variables_ = util.clone(this.policy.variables_);

  if ('variables' in params) {
    for (var key in params.variables)
      this.setVariable(key, params.variables[key]);
  }

  this.userVariables = params.userVariables || null;

  this.state = 'stop:unknown';
};

/**
 * Get a variable for this certificate definition.
 *
 * Variables can be referenced in various parts of the policy and
 * certificate configuration.  This function is used to retrieve the value of
 * a variable.
 *
 * @param {string} name The name of the variable.
 * @param {string} opt_default Optional default value.
 */
Policy.Certificate.prototype.setVariable = Policy.prototype.setVariable;

/**
 * Set a variable for this certificate definition.
 *
 * Variables can be referenced in various parts of the policy and
 * certificate configuration.  This function is used to assign a value to
 * a variable.
 *
 * @param {string} name The name of the variable.
 * @param {string} value The value of the variable.
 */
Policy.Certificate.prototype.getVariable = Policy.prototype.getVariable;

/**
 * Replace variable references with their values.
 *
 * This function will replace zero or more variable references in the given
 * string with the variable values associated with this certificate
 * definition.
 *
 * See the documentation for util.replaceVars() for details on the variable
 * syntax.
 *
 * @param {string} str The string containing variable references.
 * @return {string} The source string with all variable references resolved.
 */
Policy.Certificate.prototype.replaceVars =
function cert_replaceVars(str) {
  return util.replaceVars(str, util.bindp(this, 'getVariable'));
};

/**
 * Log an information status message about this certificate definition.
 *
 * @param  {string} str The informational message to log.
 * @return {string} The string logged.
 */
Policy.Certificate.prototype.info =
function info(str) { return this.log_('info', str) };

/**
 * Log a warning status message about this certificate definition.
 *
 * @param  {string} str The warning message to log.
 * @return {string} The string logged.
 */
Policy.Certificate.prototype.warn =
function warn(str) { return this.log_('warn', str) };

/**
 * Log an error status message about this certificate definition.
 *
 * @param  {string} str The error message to log.
 * @return {string} The string logged.
 */
Policy.Certificate.prototype.error =
function error(str) {
  return this.log_('error', str);
};

/**
 * Log the fact that an asynchronous operation has started for this certificate.
 *
 * See Policy.prototype.start.
 */
Policy.Certificate.prototype.start =
function start(state, msg) {
  if (msg)
    this.info(msg);

  this.policy.start(this, state);
}

/**
 * Log the fact that an asynchronous operation has started for this certificate.
 *
 * See Policy.prototype.start.
 */
Policy.Certificate.prototype.stop =
function stop(state, msg) {
  if (msg) {
    if (state == 'error')
      this.error(msg);
    else
      this.info(msg);
  }

  return this.policy.stop(this, state);
}

Policy.Certificate.prototype.log_ =
function log_(type, str) {
  return this.policy[type]('Certificate ' + this.type + ': ' + str);
};

/**
 * Finalize certificate installation and invoke any user specific onInstall
 * function.
 *
 * @param {boolean} firstInstall True if this is the first time the certificate
 *   has been installed.  False if the certificate was already there when we
 *   started.
 */
Policy.Certificate.prototype.onInstall_ =
function onInstall(firstInstall) {
  this.start('install');

  this.path = 'SETTINGS:key_id=' + util.intToHex(this.id) +
    ',cert_id=' + util.intToHex(this.id) +
    ',pin=' + Policy.PKCS11_USER_PIN;

  this.info('Certificate installed to: ' + this.path);

  if (typeof this.onInstall == 'function') {
    try {
      this.onInstall(firstInstall);
    } catch (ex) {
      this.stop('error', 'Exception running post-install callback: ' + ex);
      return;
    }
  }

  this.stop('ready');
};

/*
 * Opens slot with a private session, using user's PIN.
 *
 * @param {Session.CKU_*} userType  Type of session to open.
 * @param {String} pin  PIN to open the device.
 * @returns {Session}  Opened session or null if operation failed.
 */
Policy.prototype.loginToken =
function loginToken(token, sessionType, pin) {
  var pkcs11 = this.pkcs11.api;

  if (!pin) {
    switch (sessionType) {
      case Session.CKU_USER:
        pin = Policy.PKCS11_USER_PIN;
        break;
      case Session.CKU_SO:
        pin = Policy.PKCS11_SO_PIN;
        break;
      default:
        this.error('Unknown user type');
        return null;
    }
  }

  var session = null;

  this.info('Opening session and logging into token.');

  try {
    token.closeAllSessions();
    session = token.openSession(Token.CKF_RW_SESSION);
  } catch (ex) {
    this.error('Unable to open session: ' + ex);
    return null;
  }

  try {
    if (!session.login(sessionType, pin)) {
      this.error('Unable to log in user into token.');
      session.logoutAndClose();
      return null;
    }
  } catch (ex) {
    this.error('Failed to login user into token: ' + ex);
    session.logoutAndClose();
    return null;
  }

  return session;
}

/**
 * Determine if this certificate definition has been successfully installed.
 *
 * @return {boolean} A boolean indicating whether or not this certificate
 *  definition has been successfully installed in the PKCS#11 device.
 */
Policy.prototype.findObjectById =
function findObjectById(session, type, id, typeString) {
  var objList = session.findObjects([[PkObject.CKA_CLASS, type],
                                     [PkObject.CKA_ID, id]]);
  if (objList) {
    switch (objList.length) {
      case 1:
        // Found matching object.
        return objList[0];
      case 0:
        // Object not found.
        return null;
      default:
        // Too many objects.
        this.error('Too many matching objects: ' + typeString);
        return null;
    }
  } else {
    this.error('error', 'Problem with PKCS#11 token.');
    return null;
  }
};

/**
 * Fetch a certificate by ID
 */
Policy.prototype.findCertificateById =
function findCertificateById(session, id) {
  return this.findObjectById(session, PkObject.CKO_CERTIFICATE, id,
                             'certificates');
};

/**
 * Fetch a private key by ID
 */
Policy.prototype.findPrivateKeyById =
function findPrivateKeyById(session, id) {
  return this.findObjectById(session, PkObject.CKO_PRIVATE_KEY, id,
                             'private keys');
};

/**
 * Remove certificate(s) and key(s) associated with the certificate type
 */
Policy.prototype.removeObjectsById =
function removeObjectsById(session, id) {
  var types = [PkObject.CKO_CERTIFICATE,
               PkObject.CKO_PUBLIC_KEY,
               PkObject.CKO_PRIVATE_KEY];

  this.info('Removing all objects for slot: ' + Policy.PKCS11_SLOT + ' id: ' +
            id);
  for (type in types) {
    var objList = session.findObjects([[PkObject.CKA_CLASS, types[type]],
                                       [PkObject.CKA_ID, id]]);
    if (!objList) {
      this.error('findObjects returned null.');
      return;
    }

    for (obj in objList)
      objList[obj].destroy();
  }
}

/**
 * Store a X.509 PEM encoded certificate in the PKCS#11 device.
 */
Policy.Certificate.prototype.storeCertificate =
function storeCertificate(session, id, label, subject, certificate) {
  session.createObject(
    [
      [PkObject.CKA_LABEL, label],
      [PkObject.CKA_ID, id],
      [PkObject.CKA_TOKEN, true],
      [PkObject.CKA_CLASS, PkObject.CKO_CERTIFICATE],
      [PkObject.CKA_SUBJECT, subject],
      [PkObject.CKA_CERTIFICATE_TYPE, PkObject.CKC_X_509],
      [PkObject.CKA_VALUE, certificate]
    ]
  );
}

/**
 * Determine if this certificate definition and matching private key has
 * been successfully installed.
 *
 * @return {boolean} A boolean indicating whether or not this certificate
 *  definition has been successfully installed in the PKCS#11 device.
 */
Policy.Certificate.prototype.isInstalled =
function isInstalled() {
  // Check if the corresponding token is accepting commands (this is
  // important to prevent race conditions when initializing the token,
  // such as interleaved calls to 'listCertificate' while performing
  // initialization asynchronously.)
  var pkcs11 = this.policy.pkcs11.api;
  var token = pkcs11.slots[Policy.PKCS11_SLOT].token;
  if (!this.policy.checkToken(token))
    return false;

  var session = null;
  try {
    session = this.policy.loginToken(token, Session.CKU_USER);
    if (!session)
      return this.error('Cannot login to token.');

    var cert = policy.findCertificateById(session, this.id);
    var key = policy.findPrivateKeyById(session, this.id);

    session.logoutAndClose();

    return (cert != null && key != null);
  } catch(ex) {
    session.logoutAndClose();
    this.error('Error checking certificate is installed: ', ex);
  }

  return false;
};

/**
 * Initiate the CSR process for this certificate definition.
 */
Policy.Certificate.prototype.initiateCSR =
function initiateCSR() {
  // Set up a request object.
  var r = new entd.http.Request(this.csr.host, this.replaceVars(this.csr.path));

  if ('port' in this.csr)
    r.port = this.csr.port;

  if ('auth' in this.csr)
    r.auth = this.replaceVars(this.csr.auth);

  // We use this property in the callbacks to make log messages more useful.
  r.description = 'Certificate Signing Request';

  // Stash this so that we can refer to it later in on onCSRComplete.
  r.certificate = this;

  this.start('key', 'Generating key pair');

  // Get the subject from the definition and replace any variable references.
  var subject = this.replaceVars(this.csr.subject);
  this.info('CSR Subject: ' + subject);

  var pkcs11 = this.policy.pkcs11.api;
  var token = pkcs11.slots[Policy.PKCS11_SLOT].token;
  var session = policy.loginToken(token, Session.CKU_USER);
  if (!session)
    return this.stop('error', 'Cannot login to token.');

  // Remove any existing entries matching this.id.
  this.policy.removeObjectsById(session, this.id);

  try {
    // Generate a key pair.
    this.policy.generateKeyPair(session, this.id, this.label);
  } catch(e) {
    session.logoutAndClose();
    return this.stop('error', 'Failed to create key on PKCS#11 device: ' + e);
  }

  this.stop('key', 'Key generation complete');

  session.logoutAndClose();

  this.start('csr', 'Initiating Certificate Signing Request');

  // create a CSR using the generated key pair.
  var engine = this.policy.engine;
  this.info('Generating CSR for id: ' + this.id + ' subject: ' + subject);
  var csr = engine.createCSR(this.id, subject);

  // Copy the CSR as a string to the environment.
  this.setVariable('csr', csr.toFormat(CSR.CSR_FORMAT_PEM_TEXT));

  // Copy all of the POST parameters after replacing the variable references.
  if ('post_params' in this.csr) {
    r.params = [];

    for (var key in this.csr.post_params) {
      var value = this.csr.post_params[key];
      var isRaw = util.isRawString(value);
      value = this.replaceVars(value);
      if (isRaw) {
        r.params.push(encodeURI(key) + '=' + value);
      } else {
        r.params.push(encodeURI(key) + '=' + encodeURI(value));
      }
    }
  }

  // Hook up our callbacks.
  r.onComplete = util.fwdp(this, 'onCSRComplete_');
  r.onTimeout = util.fwdp(this, 'onHTTPTimeout_');
  r.onError = util.fwdp(this, 'onHTTPError_');

  // Fire off the POST request.
  entd.http.POST(r);
  this.info('POSTing to ' + r.url);
};

/**
 * Called when a http request times out.
 */
Policy.Certificate.prototype.onHTTPTimeout_ =
function onHTTPTimeout(request) {
  this.stop('error', 'HTTP Timeout during ' + request.description);
};

/**
 * Called when a http request errors out.
 */
Policy.Certificate.prototype.onHTTPError_ =
function onHTTPError_(request, reason) {
  this.stop('error', 'Error sending request: ' + reason + ', during ' +
            request.description);
};

/**
 * Called when the CSR request completes with anything other than a timeout.
 */
Policy.Certificate.prototype.onCSRComplete_ =
function onCSRComplete_(request, response) {
  this.info('CSR completed with http status: ' + response.code);

  if (response.code != entd.http.RESPONSE_OK) {
    var reason;

    switch (response.code) {
      case 401:
        reason = 'Invalid password';
        break;
      case 500:
        reason = 'Internal server error';
        break;
      default:
        reason = 'HTTP Error ' + response.code;
    }

    this.stop('error', reason + ' during ' + request.description);
    return;
  }

  try {
    this.parseCSR(response);
  } catch (ex) {
    this.stop('error', 'Error parsing request id: ' + ex);
    return;
  }

  this.stop('csr');
};

/**
 * Fetch a cert that was just created for us as the result of a CSR.
 */
Policy.Certificate.prototype.getCert =
function getCert() {
  this.start('cert', 'Getting Certificate');

  var r = new entd.http.Request(this.issuer.host,
                                this.replaceVars(this.issuer.path));

  if ('port' in this.issuer)
    r.port = this.issuer.port;

  if ('auth' in this.issuer)
    r.auth = this.replaceVars(this.issuer.auth);

  // Stash this so that we can refer to it later in on onIssuanceComplete.
  r.certificate = this;

  // We use this property in the callbacks to make log messages more useful.
  r.description = 'Certificate Issue Request';

  r.onComplete = util.fwdp(this, 'onIssuanceComplete_');
  r.onTimeout = util.fwdp(this, 'onHTTPTimeout_');
  r.onError = util.fwdp(this, 'onHTTPError_');

  entd.http.GET(r);
  this.info('GETing from ' + r.url);
};

// Called when the certificate-issue request completes with anything
// other than a timeout.
Policy.Certificate.prototype.onIssuanceComplete_ =
function onIssuanceComplete(request, response) {
  if (response.code != entd.http.RESPONSE_OK) {
    this.stop('error', 'HTTP error ' + response.code + ' during ' +
              request.description);
    return;
  }

  // X.509 PEM encoded certificate response.
  var cert = response.content;

  // Open a session with the device.
  var pkcs11 = this.policy.pkcs11.api;
  var token = pkcs11.slots[Policy.PKCS11_SLOT].token;
  var session = this.policy.loginToken(token, Session.CKU_USER);
  if (!session)
    return this.stop('error', "Can't add certificate: missing session object");

  // Convert response to DER.
  var x509 = new entd.crypto.OpenSSL.X509(cert, X509.X509_FORMAT_PEM_TEXT);
  var x509_der = x509.toFormat(X509.X509_FORMAT_DER);

  // Store certificate in the PKCS#11 token.
  this.storeCertificate(session, this.id, this.label, this.subject, x509_der);

  this.stop('cert');

  session.logoutAndClose();
};

Policy.prototype.setBrowserPolicy =
function setBrowserPolicy(type, sourcePolicy) {
  var targetPolicy;
  if (type == "managed") {
    targetPolicy = entd.browser.managedPolicy;
  } else if (type == "recommended") {
    targetPolicy = entd.browser.recommendedPolicy;
  } else {
    throw "Invalid browser policy type: " + type;
  }

  this.info("Synchronizing browser policy: " + type);

  var changed = false;

  for (var p in targetPolicy) {
    if (!(p in sourcePolicy)) {
      delete targetPolicy[p];
      changed = true;
    }
  }

  for (var p in sourcePolicy) {
    if (targetPolicy[p] != sourcePolicy[p]) {
      targetPolicy[p] = sourcePolicy[p];
      changed = true;
    }
  }

  if (changed) {
    this.info("Browser restart is suggested.");
  } else {
    this.info("Browser policy has not changed.");
  }

  return changed;
}

/**
 * Policy.Callbacks constructor.
 *
 * Policy callbacks contain the functions that can be invoked through the
 * callback server.  Each function can take a single parameter which can
 * be any primitive JavaScript value (Object, Array, number, or string),
 * or any combination of primitive JavaScript values.
 *
 * Policy implementors may add their own callbacks by extending this object,
 * as in...
 *
 *   Policy.Callbacks.prototype['cb:my_awesome_callback'] = function (arg) {
 *     return 'I am awesome.';
 *   }
 *
 * Callbacks are not installed in the callback server by default.
 * Policy implementors that want to make use of these callbacks should
 * start the callback server in their policy, as in...
 *
 *   entd.onLoad = function (manifest) {
 *     var policy = new Policy(manifest);
 *     entd.callbackServer.start(policy.callbacks);
 *   }
 *
 * @param {Policy} policy The parent policy for these callbacks.
 */
Policy.Callbacks =
function PolicyCallbacks(policy) {
  this.policy = policy;
};

/**
 * Return information about the current policy.
 *
 * This policy callback returns the policy description, according to the
 * extension manifest,and the current username.
 *
 * @return {Object} An object with 'description' and 'username' properties.
 */
Policy.Callbacks.prototype['cb:info'] =
function cb_info() {
  var callback_data = {
   description: this.policy.manifest.description,
   version: this.policy.manifest.version,
   username: entd.username,
   browserPolicyChanged: this.policy.browserPolicyChanged,
   isLibcrosLoaded: entd.isLibcrosLoaded,
   tpm: {
     isReady: (entd.isLibcrosLoaded ? entd.tpm.isReady : true),
     isEnabled: (entd.isLibcrosLoaded ? entd.tpm.isEnabled : true),
     isOwned: (entd.isLibcrosLoaded ? entd.tpm.isOwned : true),
     isBeingOwned: (entd.isLibcrosLoaded ? entd.tpm.isBeingOwned : false),
     statusString: (entd.isLibcrosLoaded ? entd.tpm.statusString :
                    "libcros not loaded")
   },
   pkcs11: {
     state: this.policy.pkcs11.state,
     log: this.policy.getLog(this.policy.pkcs11)
   }
  }
  if ('isTokenReady' in entd.tpm) {
    callback_data.pkcs11.isTokenReady =
      (entd.isLibcrosLoaded ? entd.tpm.isTokenReady : false);
  }

  return Policy.CallbackSuccess(callback_data);
};

/**
 * Set the user PIN on a given token.
 *
 * This is a no-op if the oldPin and newPin are the same value.
 *
 * @param {Object} arg An object with the following properties:
 *  - 'slotId' An integer representing the slot that contains the target token.
 *  - 'oldPin' An optional string representing the current PIN.  Defaults to
 *      Token.DEFAULT_USER_PIN or Policy.PKCS11_USER_PIN, depending on the
 *      state of the token.
 *  - 'oldPin' An optional string representing the new PIN.  Defaults to
 *      Policy.PKCS11_USER_PIN.
 *
 * Setting the user pin is an asynchronous operation.  While the set is in
 * progress the token state will be 'start:user-pin'.  If the operation
 * completes successfully, the token state should become 'stop:ready', although
 * if the operation completes successfully but the token is not ready due to
 * some unexpected condition, it will become 'stop:user-pin'.  On error it will
 * become 'stop:error'.
 * TODO(crosbug.com/14277): Remove SetPIN functions.
 */
Policy.Callbacks.prototype['cb:setUserPin'] =
function cb_setUserPin(arg) {
  var pkcs11 = this.policy.pkcs11.api;
  if (!pkcs11)
    return Policy.CallbackError('Pkcs11 not initialized');

  if (!('slotId' in arg))
    return Policy.CallbackError('Missing required parameter: slotId');

  var token = pkcs11.slots[arg.slotId].token;
  if (!token)
    return Policy.CallbackError('Invalid slotId: ' + arg.slotId);

  if (!arg.oldPin) {
    token.refresh();
    if (token.flags & Token.CKF_USER_PIN_TO_BE_CHANGED) {
      arg.oldPin = Token.DEFAULT_USER_PIN;
    } else {
      arg.oldPin = Policy.PKCS11_USER_PIN;
    }
  }

  if (!arg.newPin)
    arg.newPin = Policy.PKCS11_USER_PIN;

  arg.userType = 'user';

  return this.setPin_(arg);
}

/**
 * Set the Security Officer PIN on a given token.
 *
 * This is a no-op if the oldPin and newPin are the same value.
 *
 * @param {Object} arg An object with the following properties:
 *  - 'slotId' An integer representing the slot that contains the target token.
 *  - 'oldPin' An optional string representing the current PIN.  Defaults to
 *      Token.DEFAULT_SO_PIN or Policy.PKCS11_SO_PIN, depending on the
 *      state of the token.
 *  - 'oldPin' An optional string representing the new PIN.  Defaults to
 *      Policy.PKCS11_SO_PIN.
 *
 * Setting the user pin is an asynchronous operation.  While the set is in
 * progress the token state will be 'start:so-pin'.  If the operation
 * completes successfully the token state will become 'stop:so-pin'.  On
 * error it will become 'stop:error'.
 */
Policy.Callbacks.prototype['cb:setSoPin'] =
function cb_setSoPin(arg) {
  var pkcs11 = this.policy.pkcs11.api;
  if (!pkcs11)
    return Policy.CallbackError('Pkcs11 not initialized');

  if (!('slotId' in arg))
    return Policy.CallbackError('Missing required parameter: slotId');

  var token = pkcs11.slots[arg.slotId].token;
  if (!token)
    return Policy.CallbackError('Invalid slotId: ' + arg.slotId);

  if (!arg.oldPin) {
    token.refresh();
    if (token.flags & Token.CKF_SO_PIN_TO_BE_CHANGED) {
      arg.oldPin = Token.DEFAULT_SO_PIN;
    } else {
      arg.oldPin = Policy.PKCS11_SO_PIN;
    }
  }

  if (!arg.newPin)
    arg.newPin = Policy.PKCS11_SO_PIN;

  arg.userType = 'so';

  return this.setPin_(arg);
}

/**
 * Common code for cb:setUserPin and cb:setSoPin.
 */
Policy.Callbacks.prototype.setPin_ =
function cb_setPin_(arg) {
  var pkcs11 = this.policy.pkcs11.api;
  if (!pkcs11)
    return Policy.CallbackError('Pkcs11 not initialized');

  if (!('slotId' in arg))
    return Policy.CallbackError('Missing required parameter: slotId');

  var token = pkcs11.slots[arg.slotId].token;
  if (!token)
    return Policy.CallbackError('Invalid slotId: ' + arg.slotId);

  if (!arg.oldPin)
    return Policy.CallbackError('Missing required parameter: oldPin');

  if (!arg.newPin)
    return Policy.CallbackError('Missing required parameter: newPin');

  if (!arg.userType)
    return Policy.CallbackError('Missing required parameter: userType');

  var userType;

  if (arg.userType == "user") {
    userType = Session.CKU_USER;
  } else if (arg.userType == "so") {
    userType = Session.CKU_SO;
  } else {
    return Policy.CallbackError('Invalid userType: ' + arg.userType);
  }

  var policy = this.policy;
  entd.setTimeout(function () {
      policy.setTokenPin(token, userType, arg.oldPin, arg.newPin);
    }, 1);

  return Policy.CallbackSuccess('Resetting so pin');
}

/**
 * Initialize a PKCS11 token.
 *
 * @param {Object} arg An object with the following properties:
 *  - 'slotId' An integer representing the slot that contains the target token.
 *
 * Initializing a PKCS11 token is an asynchronous operation.  While the
 * initialization is in progress the token state will be 'start:init'.  If the
 * operation completes successfully the token state will become 'stop:init'.
 * On error it will become 'stop:error'.
 * TODO(crosbug.com/14277): Remove initToken function.
 */
Policy.Callbacks.prototype['cb:initToken'] =
function cb_initToken(arg) {
  var pkcs11 = this.policy.pkcs11.api;
  if (!pkcs11)
    return Policy.CallbackError('Pkcs11 not initialized');

  if (!('slotId' in arg))
    return Policy.CallbackError('Mising parameter: slotId');

  if (!(arg.slotId in pkcs11.slots))
    return Policy.CallbackError('Invalid slotId: ' + arg.slotId);

  var token = pkcs11.slots[arg.slotId].token;
  if (!token)
    return Policy.CallbackError('Slot has no token: ' + arg.slotId);

  var policy = this.policy;
  entd.setTimeout(function () { policy.initToken(token, arg.tokenLabel) }, 1);

  return Policy.CallbackSuccess('Initializing token');
}

/**
 * Return a list known PKCS11 tokens.
 */
Policy.Callbacks.prototype['cb:listTokens'] =
function cb_listTokens() {
  var pkcs11 = this.policy.pkcs11.api;
  if (!pkcs11)
    return Policy.CallbackError('Pkcs11 not initialized');

  var tokenList = new Array();

  for (var i in pkcs11.slots) {
    var slot = pkcs11.slots[i];
    if (!slot.token)
      continue;

    var token = slot.token;
    token.refresh();

    var tokenData = { slotId: i, log: '' };

    for (var key in slot.token)
      tokenData[key] = slot.token[key];

    tokenData.uintFlags = tokenData.flags;

    tokenData.flags = new Object();

    for (var key in Token) {
      // The client doesn't have access to the constants in
      // entd.pkcs11.crypto.Token.CKF_*, so we copy the applicable flags
      // onto the tokenData, minus the "CKF_" prefix.
      if (key.match(/^CKF_/))
        tokenData.flags[key.substr(4)] = !!(token.flags & Token[key]);
    }

    tokenList.push(tokenData);
  }

  return Policy.CallbackSuccess({ tokenList: tokenList });
}

/**
 * Return the list of certificate definitions.
 *
 * This policy callback returns a list of certificate definitions, and their
 * status.
 *
 * Each returned certificate definition will be an object with the
 * following properties:
 *
 *   - 'id' String identifier for the certificate definition.
 *   - 'label' String label for the certificate definition.
 *   - 'userVariables' Object continaing the variables that must be
 *       provided by the user.
 *   - 'installed' Boolean indicating whether or not this certificate
 *       has been successfully installed.
 *   - 'status' String containing the last status message for this
 *       certificate definition.
 *
 * @return {Object} An object containing one property for each certificate
 *   definition.  Callers should assume the property names are opaque
 *   tokens.
 */
Policy.Callbacks.prototype['cb:listCertificates'] =
function cb_listCerts(arg) {
  var pkcs11 = this.policy.pkcs11.api;
  if (!pkcs11)
    return Policy.CallbackError('Pkcs11 not initialized');

  var rv = {};

  for (key in this.policy.certificates) {
    var cert = this.policy.certificates[key];
    var token = pkcs11.slots[Policy.PKCS11_SLOT].token;

    rv[key] = {
      id: cert.type,
      key: key,
      label: cert.label,
      userVariables: cert.userVariables,
      installed: cert.isInstalled() ? 1 : 0,
      log: cert.log,
      state: cert.state,
    };
  }

  return Policy.CallbackSuccess(rv);
};

/**
 * Initiate a Certificate Signing Request.
 *
 * This policy callback is used to initiate a Certificate Signing Request
 * for a given certificate definition.  If the certificate is already
 * installed, this will attempt to replace it.
 *
 * @param {Object} arg An object with the following properties:
 *  - 'certificateId' A string identifying the certificate.
 *  - 'variables' An object containing the user variables required for this
 *      certificate.
 *
 * The CSR is an asynchronous operation.  While the in progress the certificate
 * state will be 'start:csr'.  If the operation completes successfully the
 * certificate state will become 'stop:csr'. On error it will become
 * 'stop:error'.
 */
Policy.Callbacks.prototype['cb:initiateCSR'] =
function cb_initiateCSR(arg) {

  // If they forgot to reference a certificate, or we can't locate the
  // one they referenced, we return a hard CallbackError.  If the UI notices
  // a CallbackError, its only recourse is to show a generic alert message.
  if (!arg)
    return Policy.CallbackError('Missing arguments');

  var cert = this.policy.certificates[util.toKey(arg.certificateId)];
  if (!cert)
    return Policy.CallbackError('Unknown certificate: ' + arg.certificateId);

  // If we can find the cert, then we return a CallbackSuccess and set the
  // status of the cert, even on failure.  If the UI sees a CallbackSuccess,
  // it can associate the attached message with the certificate UI.
  // It will ultimately know the correct success or failure state of the CSR
  // from the "isInstalled" property returned by the listCertificates callback.
  if (cert.userVariables) {
    if (!arg.variables)
      return Policy.CallbackSuccess(cert.error('Missing parameter: variables'));

    for (name in cert.userVariables) {
      if (!(name in arg.variables)) {
        return Policy.CallbackSuccess(
            cert.error('Missing certificate variable: ' + name));
      }

      cert.setVariable(name, String(arg.variables[name]));
    }
  }

  // Create CSR asynchronously.
  entd.setTimeout(function() { cert.initiateCSR() }, 1);

  return Policy.CallbackSuccess(cert.info('Initiating CSR for: ' + cert.label));
};

/**
 * Retrieve a certificate.
 *
 * This policy callback is used to request a certificate after the successful
 * completion of a CSR.
 *
 * @param {Object} arg An object with the following properties:
 *  - 'certificateId' A string identifying the certificate.
 *
 * The certificate request is an asynchronous operation.  While the in progress
 * the certificate state will be 'start:cert'.  If the operation completes
 * successfully the certificate state will become 'stop:cert'.  On error it
 * will become 'stop:error'.
 */
Policy.Callbacks.prototype['cb:getCert'] =
function cb_getCert(arg) {

  // If they forgot to reference a certificate, or we can't locate the
  // one they referenced, we return a hard CallbackError.  If the UI notices
  // a CallbackError, its only recourse is to show a generic alert message.
  if (!arg)
    return Policy.CallbackError('Missing arguments');

  var cert = this.policy.certificates[util.toKey(arg.certificateId)];
  if (!cert)
    return Policy.CallbackError('Unknown certificate: ' + arg.certificateId);

  cert.getCert();

  return Policy.CallbackSuccess(cert.info('Fetching certificate for: ' +
                                          cert.label));
}

/**
 * Complete the installation of a certificate.
 *
 * This policy callback is used to complete the installation of a certificate
 * that has been successfully requested with cb:getCert.
 *
 * @param {Object} arg An object with the following properties:
 *  - 'certificateId' A string identifying the certificate.
 *
 * The certificate install is an asynchronous operation.  While the in progress
 * the certificate state will be 'start:init'.  If the operation completes
 * successfully the certificate state will become 'stop:ready'.  On error it
 * will become 'stop:error'.
 */
Policy.Callbacks.prototype['cb:installCert'] =
function cb_installCert(arg) {

  // If they forgot to reference a certificate, or we can't locate the
  // one they referenced, we return a hard CallbackError.  If the UI notices
  // a CallbackError, its only recourse is to show a generic alert message.
  if (!arg)
    return Policy.CallbackError('Missing arguments');

  var cert = this.policy.certificates[util.toKey(arg.certificateId)];
  if (!cert)
    return Policy.CallbackError('Unknown certificate: ' + arg.certificateId);

  cert.onInstall_(/* firstInstall: */ true);

  return Policy.CallbackSuccess(cert.info('Installing certificate: ' +
                                          cert.label));
}

Policy.Callbacks.prototype['cb:restart'] =
function cb_restart(arg) {
  entd.syslog.info("Restarting by client request.");
  // Exit code two means we haven't errored, but would like to be restarted.
  entd.scheduleShutdown(2);
  return Policy.CallbackSuccess('Restarting');
}

/**
 * Return an object indicating that a callback succeeded.
 */
Policy.CallbackSuccess =
function CallbackSuccess(data) {
  return { status: 'success', data: data };
};

/**
 * Return an object indicating that a callback encountered an error.
 */
Policy.CallbackError =
function CallbackError(data) {
  // Log the error to syslogs for further diagnosis.
  entd.syslog.error(data);
  return { status: 'error', data: data };
};

/**
 * Namespace for utility functions...
 */

var util = new Object();

/**
 * Returns a version of str with variable references replaced.
 *
 * Variables should be of the form %(name) or %FLAG(name).
 *
 * At the moment the only supported FLAG is 'uri', which uri encodes the value
 * before placing it in the string.  For example, if the value of
 * vars['percent'] is '%', then %uri(percent) would become '%25'.
 *
 * This function throws an error if an unknown variable is referenced or
 * an unknown FLAG is used.
 *
 * @param {string} str A string containing zero or more variable references.
 * @param {Object|function(string):string} vars An object containing the
 *     variables, or a function that returns a variable value given a name.
 */
util.replaceVars =
function replaceVars(str, vars) {
  function uriall_replace (ch) {
    // Replace EVERY character with a percent sign, followed by the character's
    // value in hex.  It's like an extreme uri encoding, and some CSR servers
    // seem to require it.
    rv = ch.charCodeAt(0).toString(16);
    return '%' + (rv.length > 1 ? rv : ('0' + rv));
  }

  function cb(m, flag, name) {
    if (typeof vars == 'function')
      value = vars(name);
    else
      value = vars[name];

    if (typeof value == 'undefined')
      throw new Error('replaceVars: Unknown variable name: ' + name);

    if (!flag)
      return value;

    switch (flag) {
      case 'uri': return encodeURI(value);

      case 'uriall':
        return value.replace(/.|\n/g, uriall_replace);

      default:
        throw new Error('replaceVars: Unknown flag: ' + flag +
                        ', while replacing variable: ' + name);
    }
  }

  return str.replace(/%([a-z]*)\(([^\)]+)\)/g, cb);
};

/**
 * Bind a function to an object.
 *
 * The function returned by util.bind will invoke obj.func(...), passing along
 * any parameters.  For example...
 *
 *   var f = util.bind(window, window.alert);
 *   f('hello world');
 *
 * This will create a new function f() which is an alias for window.alert().
 * This is especially useful for defining callbacks the should be invoked on
 * a particular object.
 *
 * @param  {Object} obj The object to bind to.
 * @param  {function} func The function to bind.
 * @return {function} A function that invokes obj.func().
 */
util.bind =
function bind(obj, func) {
  return function(var_args) { return func.apply(obj, arguments) }
};

/**
 * Bind a function to an object, where the function is already a property
 * of the target object.
 *
 * This is performs the same service as util.bind(), except the second
 * parameter is a string that refers to a function property on the object.
 * For example:
 *
 *   var f = util.bindp(window, 'alert');
 *   f('hello world');
 *
 * Compare this to the example in util.bind(), where 'window' was mentioned
 * twice.
 *
 * @param  {Object} obj The object to bind to.
 * @param  {string} prop The property containing the function to bind.
 * @return {function} A function that invokes obj.func().
 */
util.bindp =
function bindp(obj, prop) {
  if (typeof obj[prop] != 'function')
    throw new Error('Property is missing or not a function: ' + prop);

  return util.bind(obj, obj[prop]);
};

/**
 * Forward a method from one object to another object.
 *
 * The function returned by util.fwd() will invoke obj.func(this, ...), where
 * 'this' is the object that the function was originally applied to.
 * For example:
 *
 *   request.onComplete = util.fwd(obj, obj.onComplete);
 *   obj.onComplete = function(request, data) { ... }
 *
 * In this scenario, assume that the request is used as part of an asynchronous
 * API, and that the onComplete() method of the request is invoked when
 * the request completes.
 *
 * If we had used util.bind(), as in:
 *
 *   request.onComplete = util.bind(obj, obj.onComplete);
 *   obj.onComplete = function(data) { ... }
 *
 * Then the onComplete() method would have been applied to 'obj', but the
 * request object would have been lost.
 *
 * @param  {Object} obj The object to bind to.
 * @param  {function} func The function to bind.
 * @return {function} A function that invokes obj.func().
 */
util.fwd =
function fwd(obj, func) {
  return function(var_args) {
    var args = Array.apply(null, arguments);
    args.unshift(this);
    func.apply(obj, args);
  }
};

/**
 * Forward a method from one object to another object.
 *
 * This is performs the same service as util.fwd(), except the second
 * parameter is a string that refers to a function property on the object.
 * For example:
 *
 *   request.onComplete = util.fwdp(obj, 'onComplete');
 *   obj.onComplete = function(request, data) { ... }
 *
 * Compare this to the example in util.bind(), where 'obj' was mentioned
 * twice.
 *
 * @param  {Object} obj The object to bind to.
 * @param  {string} prop The property containing the function to bind.
 * @return {function} A function that invokes obj.func().
 */
util.fwdp =
function fwdp(obj, prop) {
  if (typeof obj[prop] != 'function')
    throw new Error('Property is missing or not a function: ' + prop);

  return util.fwd(obj, obj[prop]);
};


/**
 * Make a string safe to use as a key.
 *
 * When reading from a JavaScript object that is being used as a hash, it
 * it possible to clash with default properties (for example, 'toString')
 * in a way that may introduce bugs or security issues.
 *
 * Using util.toKey() and util.fromKey() can address this problem by ensuring
 * that every non-default property starts with a known prefix.
 *
 * This is not needed for basic object-as-hash usage, but should be used in
 * situations where a hash lookup could come from an untrusted source.
 */
util.toKey =
function toKey(str) {
  return 'key:' + str;
};

/**
 * Recovers the underlying string from a key.
 *
 * The is the conjugate of util.toKey().
 */
util.fromKey =
function fromKey(str) {
  if (str.substr(0, 4) != 'key:')
    throw new Error('Not a key: ' + str);

  return str.substr(4);
};

/**
 * Perform a shallow copy of an object.
 *
 * If multiple objects are provided then properties from all objects are
 * copied onto the new clone.
 *
 * @param  {...Object} var_args One or more objects to clone.
 * @return {Object} A new object with all of the properties of the source
 *    objects.
 */
util.clone =
function clone(var_args) {
  if (!arguments.length)
    throw new Error('util.clone: Missing argument');

  var rv = {};
  for (var i = 0; i < arguments.length; ++i) {
    for (var key in arguments[i])
      rv[key] = arguments[i][key];
  }

  return rv;
};

/**
 * Left pad a string to a given length, using a given character.
 *
 * @param {string} str The string to pad.
 * @param {int} len The desired string length.
 * @param {string} ch A single character to use as the padding.
 */
util.lpad =
function pad(str, len, ch) {
  if (typeof str != "string")
    str = str.toString();

  while (str.length < len);
    str = ch + str;

  return str;
}

/**
 * Ensures that an object has a set of required properties.
 *
 * This function throws an exception if the given object is missing any of the
 * specified properties.  It does not test the value of the property, only
 * that it exists.
 *
 * @param {Object} obj The object to check.
 * @param {Array} names The property names to check.
 * @param {string} opt_objname An optional name for the object being checked.
 *     Used as part of the exception message of the check fails.
 */
util.ensureProperties =
function ensureProperties(obj, names, opt_objname) {
  msg = 'Missing required property: ';
  if (opt_objname)
    msg += opt_objname + '.'

  for (var i = 0; i < names.length; ++i) {
    if (!(names[i] in obj))
      throw new Error(msg + names[i]);
  }
};

/**
 * Return a string which indicates that it should not be escaped.
 */
util.RawString =
function RawString(str) {
  if (!(str instanceof String))
    str = new String(str);

  str.isRaw_ = true;
  return str;
}

/**
 * Detect a raw string.
 */
util.isRawString =
function isRawString(str) {
  return str instanceof String && str.isRaw_ == true;
}

/**
 * Convert a number to hex format.
 */
util.intToHex =
function intToHex(val) {
  var hex = Number(val).toString(16);
  return hex;
}

/**
 * Convert a string into its binary representation.
 */
util.stringToBinaryString =
function stringToBinaryString(str) {
  var result = [];
  for (i = 0; i < str.length; i++) {
    var d = str.charCodeAt(i);
    var h = d.toString(16);
    if (h.length == 1)
      result.push('0');
    result.push(h);
  }
  return result.join('');
}
