// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/**
 * Namespace object for the client side code.
 */
var client = new Object();

/**
 * Port to contact the policy's callback server.
 */
client.policyCallbackPort = 5199;

/**
 * Initialize the client.
 */
client.onLoad =
function onLoad() {
  client.modal = document.getElementById('modal-shade');
  client.loadManifest();
  client.loadCertificates();
  setInterval('client.loadCertificates()', 5000);
};

/**
 * Get a url to a resource inside the extension.
 *
 * @param {string} url The path portion of the URL you are interested in.
 */
client.getURL =
function getURL(url) {
  if (typeof 'chrome' != undefined && chrome.extension)
    return chrome.extension.getURL(url);

  return url;
};

/**
 * Load the manifest.json file for this extension.
 *
 * Once it loads, set the title of the options page to match.
 */
client.loadManifest =
function loadManifest() {
  var xhr = new XMLHttpRequest();
  xhr.onreadystatechange = function () {
    if (this.readyState != 4)
      return;

    if (this.status == 0) {
      // Status is 0 rather than 200 for this.  I assume that's because we're
      // loading from the chrome-extension: scheme, rather than a real
      // web server.
      client.manifest = JSON.parse(this.responseText);
      console.log('manifest: ' + this.responseText);
      title = document.getElementById('title');
      while (title.firstChild)
        title.removeChild(title.firstChild);
      title.appendChild(document.createTextNode(client.manifest.description));
    } else {
      throw new Error('Error loading manifest: ' + this.status);
    }
  };

  xhr.open('GET', client.getURL('manifest.json'));
  xhr.send();
};

/**
 * Load the list of certificates for this policy.
 *
 * If the certificate list has not already been loaded, this create the initial
 * UI for each known certificate.  If it has been loaded, this will update
 * the UI to reflect the current state.
 */
client.loadCertificates =
function loadCertificates() {
  function oncomplete(retval) {
    if (retval instanceof client.CallbackSuccess) {
      if (client.certificates) {
        // If we've loaded certificates at least once, then just
        // update the existing UI.
        client.refreshCertificates(retval.data);
      } else {
        // Otherwise we have to create it from scratch.
        client.resetCertificates(retval.data);
      }
    } else {
      throw new Error('Callback failed: ' + retval);
    }
  }

  client.invokePolicyCallback('listCertificates', null, oncomplete);
};

client.initiateCSR =
function initiateCSR(cert, variables)
{
  client.invokePolicyCallback(
      'initiateCSR', { certificateId: cert.id, variables: variables },
      function oncomplete(retval) {
        if (retval instanceof client.CallbackError) {
          alert('Error installing certificate: ' + retval.data);
          return;
        }

        cert.status = retval.data;
        client.refreshCertificates(client.certificates);
      });
}

/**
 * Invoked when the 'Install' (sometimes shown as 'Reinstall') button is
 * clicked.
 *
 * @param {string} id The certificate id for the certificate whose button was
 *   clicked.
 */
client.onCertClick_ =
function onCertClick_(id) {
  var cert = client.certificates[id];
  if (!cert)
    throw 'no cert for cert id: ' + id;

  if (cert.userVariables)
    client.showModal(cert);
  else
    client.initiateCSR(cert);
};

/**
 * Show the modal dialog box used to collect user variables.
 *
 * @param {Object} cert The certificate object that should be associated with
 *  the modal dialog.
 */
client.showModal =
function showModal(cert) {
  client.modal.cert = cert;

  var list = document.getElementById('user-vars');
  while (list.firstChild)
    list.removeChild(list.firstChild);

  var firstInput;

  for (var key in cert.userVariables) {
    var uservar = cert.userVariables[key];
    var li = document.createElement('li');
    var input = document.createElement('input');

    if (!firstInput)
      firstInput = input;

    input.setAttribute('name', key);
    input.setAttribute('id', 'uservar:' + key);
    if (uservar.type == 'password')
      input.setAttribute('type', 'password');

    var label = uservar.label || key;

    list.appendChild(document.createTextNode(label + ' '));
    list.appendChild(input);
  }

  desc = document.getElementById('modal-desc');
  if (!desc.firstChild)
    desc.appendChild(document.createTextNode(''));

  desc.firstChild.data = cert.label;

  client.modal.style.display = 'block';

  setTimeout(function () {
      client.modal.style.top = '0%';
      firstInput.focus();
    }, 1);
};

/**
 * Hide the user variables modal dialog box.
 */
client.hideModal =
function hideModal() {
  client.modal.style.top = '-100%';
  client.modal.cert = null;
  setTimeout('client.modal.style.display = "none"', 500);
};

/**
 * Called when the 'Submit' button is clicked on the modal dialog.
 */
client.onModalSubmit_ =
function onModalCancel() {

  var cert = client.modal.cert;

  var variables = {};
  var valid = true;

  for (var key in cert.userVariables) {
    var input = document.getElementById('uservar:' + key);
    if (!input.value) {
      input.setAttribute('class', 'invalid');
      valid = false;
    } else {
      input.setAttribute('class', '');
      variables[key] = input.value;
    }
  }

  if (!valid)
    return;

  client.initiateCSR(cert, variables);
  client.hideModal();
};

/**
 * Called when the 'Cancel' button is clicked on the modal dialog.
 */
client.onModalCancel_ =
function onModalCancel() {
  client.hideModal();
};

/**
 * Create the UI for a list of certificates.
 *
 * This will destroy any existing cert UI before proceeding.
 *
 * @param {Array} certs The list of known certificates.
 */
client.resetCertificates =
function resetCertificates(certs) {
  console.log(JSON.stringify(certs));

  client.certificates = {};
  for (var key in certs) {
    // The certificates coming from the server have keys that don't match
    // their ids (key != cert.id), because the server is being careful not
    // to let keys and default object properties collide.  We don't care much
    // about the collisions here, and having key == cert.id is useful to us.
    var cert = certs[key];
    client.certificates[cert.id] = cert;
  }

  var list = document.getElementById('cert-list');
  while (list.firstChild)
    list.removeChild(list.firstChild);

  client.refreshCertificates(certs);
};

/**
 * Refresh the UI for a list of certificates.
 *
 * Creates the UI if it doesn't exist.
 *
 * @param {Array} certs The list of known certificates.
 */
client.refreshCertificates =
function refreshCertificates(certs) {
  for (var key in certs) {
    var cert = certs[key];
    var li = document.getElementById('cert:' + cert.id);
    if (li)
      client.refreshCertificate(li, cert);
    else
      client.renderCertificate(cert);
  }
};

/**
 * Refresh the UI for a given certificate.
 *
 * @param {DOMListItem} li The 'li' element containing the certificate UI.
 * @param {Object} cert The object representing the current state of the
 *    certificate.
 */
client.refreshCertificate =
function refreshCertificate(li, cert) {
  if (cert.installed != li.getAttribute('data-installed')) {
    // chrome doesn't seem to notice the attribute change, so we have to
    // poke at it.
    li.setAttribute('data-installed', cert.installed);
    li.style.visibility = 'hidden';
    setTimeout(function () { li.style.visibility = '' }, 1);
  }

  li.label.firstChild.data = cert.label;
  li.status.firstChild.data = cert.status;
  li.button.firstChild.data = cert.installed ? 'Reinstall' : 'Install';
};

/**
 * Create the UI for a given certificate.
 *
 * This code intentionally takes the long way around, building each
 * element by hand, rather than using innerHTML, in order to avoid some
 * potential content injection expoits.
 *
 * @param {Object} cert The object representing the current state of the
 *    certificate.
 */
client.renderCertificate =
function renderCertificate(cert) {
  // The placeholder text ('<label>', etc) gets replaced later by
  // refreshCertificate().
  var li = document.createElement('li');
  li.setAttribute('class', 'cert');
  li.setAttribute('id', 'cert:' + cert.id);
  li.setAttribute('data-installed', cert.installed);

  var table = document.createElement('table');
  table.setAttribute('width', '100%');
  li.appendChild(table);

  var tbody = document.createElement('tbody');
  table.appendChild(tbody);

  var tr = document.createElement('tr');
  tbody.appendChild(tr);

  var label = li.label = document.createElement('td');
  label.setAttribute('class', 'label');
  label.appendChild(document.createTextNode('<label>'));
  tr.appendChild(label);

  var td = document.createElement('td');
  td.setAttribute('rowspan', '2');
  td.setAttribute('valign', 'center');
  td.setAttribute('width', '1px');
  tr.appendChild(td);

  var button = li.button = document.createElement('button');
  button.appendChild(document.createTextNode('<Install,Uninstall>'));
  button.addEventListener('click',
                          function() { client.onCertClick_(cert.id) });
  td.appendChild(button);

  tr = document.createElement('tr');
  tbody.appendChild(tr);

  var status = li.status = document.createElement('td');
  status.setAttribute('class', 'status');
  status.appendChild(document.createTextNode('<status>'));
  tr.appendChild(status);

  document.getElementById('cert-list').appendChild(li);
  client.refreshCertificate(li, cert);
};

/**
 * Invoke a remote policy callback function.
 *
 * When the callback completes, the oncomplete function will be called with
 * a single parameter.  The parameter will be an instance of
 * client.CallbackSuccess or client.CallbackError, depending on the result
 * of the callback.  The 'data' property of that object will contain more
 * details.
 *
 * @param {string} name The name of the callback to invoke.
 * @param {Object} arg The argument object for the callback.
 * @param {function(object)} oncomplete A function to invoke when the callback
 *     is complete.
 */
client.invokePolicyCallback =
function invokePolicyCallback(name, arg, oncomplete) {
  var xhr = new XMLHttpRequest();

  xhr.onreadystatechange = function () {
    if (this.readyState != 4)
      return;

    if (this.status == 200) {
      var retval = JSON.parse(this.responseText);
      if (typeof retval == 'object') {
        var param;
        if (retval.status == 'success')
          param = new client.CallbackSuccess(name, arg, retval);
        else if (retval.status == 'error')
          param = new client.CallbackError(name, arg, retval);

        if (param) {
          if (oncomplete) {
            oncomplete(param);
          } else {
            console.log('callback done, no oncomplete handler: ' + param);
          }

          return;
        }
      }

      throw new Error('Unexpected response to callback: ' + name + ': ' +
                      JSON.stringify(retval));
    } else {
      throw new Error('Error invoking callback: ' + name + ': ' + this.status);
    }
  };

  xhr.open('POST', 'http://127.0.0.1:' + client.policyCallbackPort +
           '/dispatch');
  xhr.setRequestHeader('X-Entd-Request', 'magic');
  xhr.setRequestHeader('Content-Type', 'application/json; charset=UTF-8');
  xhr.send(JSON.stringify({'function': name, 'argument': arg}));
};

/**
 * client.CallbackSuccess constructor.
 *
 * An instance of this class holds the return value of a successful policy
 * callback.  The data property of this object will contain the return
 * value of the callback.
 *
 * @param {string} name The name of the callback that returned this data.
 * @param {Object} arg The argument object originally passed to the callback.
 * @param {Object} data The data returned by the callback.
 */
client.CallbackSuccess =
function CallbackSuccess(name, arg, data) {
  this.init_(name, arg, data)
};

client.CallbackSuccess.prototype.init_ =
function init_(name, arg, rv) {
  this.name_ = name;
  this.arg_ = arg;

  this.toString = function toString() {
    return '[' + this.constructor.name + ': ' + JSON.stringify(this) + ']';
  };

  for (var key in rv)
      this[key] = rv[key];
};

/**
 * client.CallbackError constructor.
 *
 * An instance of this class holds the return value of an unsuccessful policy
 * callback.  The data property of this object will contain the return
 * value of the callback.
 *
 * @param {string} name The name of the callback that returned this data.
 * @param {Object} arg The argument object originally passed to the callback.
 * @param {Object} data The data returned by the callback.
 */
client.CallbackError =
function CallbackError(name, arg, data) {
  this.init_(name, arg, data);
};

client.CallbackError.prototype.init_ = client.CallbackSuccess.prototype.init_;
