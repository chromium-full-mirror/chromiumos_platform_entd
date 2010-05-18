// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/**
 * TODO(rginda): Remove these stubs as the native API gets implemented.
 */

entd.pkcs11 = new Object();

entd.pkcs11.slots = {};

entd.pkcs11.store =
function store(slotId, label, type, data) {
  var slot = entd.pkcs11.slots[slotId];
  if (!slot)
    slot = entd.pkcs11.slots[slotId] = {};

  slot[type] = { label: label, data: data };
};

entd.tpm = new Object();

entd.tpm.CSR =
function TPMCSR(subject) {
  this.subject = subject;
};

entd.tpm.CSR.prototype.toString =
function CSRToString() {
  return 'entd.tpm.CSR: subject: ' + this.subject;
};

entd.tpm.Certificate =
function TPMCertificate(bytes) {
  this.bytes = bytes;
};

entd.tpm.Certificate.prototype.toString =
function TPMCertToString() {
  return 'entd.tpm.Certificate: ' + bytes;
};

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
  entd.syslog.info('Init: ' + manifest.description);
  entd.syslog.info('current user: ' + entd.username);

  // Certificate definitions to be populated later by this.addCertificate()
  this.certificates = {};

  // Save off the entire manifest in case we need it later.
  this.manifest = manifest;

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
 * @param {string} id An identifier for the certificate definition.
 * @param {Object} params The parameters for this certificate.  See the
 *     documentation for the Polict.Certificate constructor for details.
 */
Policy.prototype.addCertificate =
function addCertificate(id, params) {
  var cert = new Policy.Certificate(this, id, params);
  this.certificates[util.toKey(id)] = cert;
  return cert;
};

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
 * - 'pkcs11slot': An integer defining the PKCS#11 slot identifier in which
 *     to store the certificate and key matter.
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
 * @param {string} id An identifier for the certificate definition.
 * @param {Object} params The parameters for this certificate definition.
 */
Policy.Certificate =
function PolicyCertificate(policy, id, params) {
  this.policy = policy;
  this.id = id;

  util.ensureProperties(params, ['label', 'pkcs11slot', 'csr', 'issuer'],
                        'params');

  this.label = params.label;
  this.onInstall = params.onInstall;
  this.pkcs11slot = params.pkcs11slot;

  util.ensureProperties(params.csr, ['subject', 'host', 'path'], 'params.csr');
  this.csr = params.csr;

  util.ensureProperties(params.issuer, ['host', 'path'], 'params.issuer');
  this.issuer = params.issuer;

  this.variables_ = util.clone(this.policy.variables_);

  if ('variables' in params) {
    for (var key in params.variables)
      this.setVariable(key, params.variables[key]);
  }

  this.userVariables = params.userVariables || {};

  this.status = this.isInstalled() ? 'Installed' : 'Not Installed';

  if (this.isInstalled() && typeof this.onInstall == "function") {
    try {
      this.onInstall(/* firstInstall: */ false);
    } catch (ex) {
      this.error('Exception re-running post-install callback: ' + ex);
    }
  }
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
 */
Policy.Certificate.prototype.info =
function info(str) { this.setStatus_('info', str) };

/**
 * Log a warning status message about this certificate definition.
 */
Policy.Certificate.prototype.warn =
function warn(str) { this.setStatus_('warn', str) };

/**
 * Log an error status message about this certificate definition.
 */
Policy.Certificate.prototype.error =
function error(str) { this.setStatus_('error', str) };

Policy.Certificate.prototype.setStatus_ =
function setStatus_(type, str) {
  this.status = type + ': ' + str;
  entd.syslog[type]('Certificate ' + this.id + ': ' + str);
};

/**
 * Determine if this certificate definition has been successfully installed.
 *
 * @return {boolean} A boolean indicating whether or not this certificate
 *  definition has been successfully installed in the PKCS#11 device.
 */
Policy.Certificate.prototype.isInstalled =
function isInstalled() {
  var slot = entd.pkcs11.slots[this.pkcs11slot];
  return (slot && 'cert' in slot && slot.cert.label == this.label)
};

/**
 * Initiate the CSR process for this certificate definition.
 */
Policy.Certificate.prototype.initiateCSR =
function initiateCSR() {
  this.info('Initiating Certificate Signing Request');

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

  // Get the subject from the definition and replace any variable references.
  var subject = this.replaceVars(this.csr.subject);
  this.info('CSR Subject: ' + subject);

  // Ask the TPM to make our CSR.
  var csr = new entd.tpm.CSR(subject);

  // Copy the CSR as a string to the environment.
  this.setVariable('csr', csr.toString());

  // Copy all of the POST parameters after replacing the variable references.
  if ('post_params' in this.csr) {
    r.params = [];

    for (var key in this.csr.post_params) {
      var value = this.replaceVars(this.csr.post_params[key]);
      r.params.push(key + '=' + encodeURI(value));
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

// Called when a http request times out.
Policy.Certificate.prototype.onHTTPTimeout_ =
function onHTTPTimeout(request) {
  this.error('HTTP Time out during ' + request.description);
};

// Called when a http request errors out.
Policy.Certificate.prototype.onHTTPError_ =
function onHTTPError_(request, reason) {
  this.error('Error sending request: ' + reason + ', during ' +
             request.description);
};

// Called when the CSR request completes with anything other than a timeout.
Policy.Certificate.prototype.onCSRComplete_ =
function onCSRComplete_(request, response) {
  this.info('CSR completed with http status: ' + response.code);

  if (response.code != entd.http.RESPONSE_OK) {
    this.error('HTTP error ' + response.code + ' during ' +
               request.description);
    return;
  }

  try {
    this.parseCSR(response);
  } catch (ex) {
    this.error('Error parsing request id: ' + ex);
    return;
  }

  this.getCert_();
};

// Fetch a cert that was just created for us as the result of a CSR.
Policy.Certificate.prototype.getCert_ =
function getCert_() {
  this.info('Getting Certificate');

  var r = new entd.http.Request(this.issuer.host,
                                this.replaceVars(this.issuer.path));

  if ('port' in this.issuer)
    r.port = this.issuer.port;

  if ('auth' in this.issuer)
    r.auth = this.replaceVars(this.issuer.auth);

  // Stash this so that we can refer to it later in on onIssuanceComplete
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
    this.error('HTTP error ' + response.code + ' during ' +
               request.description);
    return;
  }

  // Make a new certificate object from the response content.
  var cert = new entd.tpm.Certificate(response.content);

  // ...and store it in the TPM.
  entd.pkcs11.store(this.pkcs11slot, this.label, 'cert', cert);

  this.info('Certificate stored in slot: ' + this.pkcs11slot);

  if (typeof request.certificate.onInstall == "function") {
    try {
      request.certificate.onInstall(/* firstInstall: */ true);
    } catch (ex) {
      this.error('Exception running post-install callback: ' + ex);
    }
  }
};


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
  return Policy.CallbackSuccess({
   description: this.policy.manifest.description,
   username: entd.username,
  });
};

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
  var rv = {};

  for (key in this.policy.certificates) {
    var cert = this.policy.certificates[key];
    rv[key] = {
      id: cert.id,
      label: cert.label,
      userVariables: cert.userVariables,
      installed: cert.isInstalled() ? 1 : 0,
      status: cert.status,
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
 * @return {Policy.CallbackSuccess} If successful.  The data will be
 *   a string with a human readable status message.
 * @return {Policy.CallbackError} If unsuccessful.  The data will be a
 *   human readable string containing the reason for the error.
 */
Policy.Callbacks.prototype['cb:initiateCSR'] =
function cb_initiateCSR(arg) {
  if (!arg)
    return Policy.CallbackError('Missing arguments');

  var cert = this.policy.certificates[util.toKey(arg.certificateId)];
  if (!cert)
    return Policy.CallbackError('Unknown certificate: ' + arg.certificateId);

  if (cert.userVariables) {
    if (!arg.variables)
      return Policy.CallbackError('Missing parameter: variables');

    for (name in cert.userVariables) {
      if (!(name in arg.variables))
        return Policy.CallbackError('Missing certificate variable: ' + name);

      cert.setVariable(name, String(arg.variables[name]));
    }
  }

  cert.initiateCSR();
  return Policy.CallbackSuccess('Sending CSR for: ' + cert.id + ': ' +
                                cert.label)
};

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
 * Then the onComplete() method would have been property applied to 'obj',
 * but the request object would have been lost.
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
 * @return {object} A new object with all of the properties of the source
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
