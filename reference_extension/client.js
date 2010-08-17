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
  client.modalShade = document.getElementById('modal-shade');
  client.loadManifest();
  client.loadInfo();
};

/**
 * Called when client.initPkcs11() completes successfully.
 */
client.onPkcs11Ready =
function onPkcs11Ready() {
  client.loadTokens();
  client.loadCertificates();
};

/**
 * Return the last line of a newline delimited log, skipping blank lines.
 */
client.getLastLogLine =
function getLastLogLine(log) {
  var ary = log.split(/\r?\n/);
  for (var i = 1; i < ary.length; ++i) {
    if (ary[ary.length - i])
      return ary[ary.length - i];
  }

  return '';
}

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
    }
  };

  xhr.open('GET', client.getURL('manifest.json'));
  xhr.send();
};

/**
 * Load the basic information from the enterprise daemon.
 *
 * This invokes cb:info and populates the user interface with the results.
 */
client.loadInfo =
function loadInfo() {
  var daemonError = false;
  var pkcs11Error = false;
  var tpmError = false;

  function oncomplete(retval) {
    var ready = false;

    if (retval instanceof client.CallbackSuccess) {
      $("#entd-status").
        text('Ready').
        attr('status', 'green');

      $('#policy-status').
        text(retval.data.description + ', ' + retval.data.version);

      $('#user-status').
        text(retval.data.username);

      var pkcs11 = retval.data.pkcs11;
      if (pkcs11.state != 'stop:ready') {
        $("#pkcs11-status").
          text('Waiting...').
          attr('status', 'red');

        if (!pkcs11Error) {
          pkcs11Error = true;
          client.showError(
              'PKCS#11 services have not started, you may need to clear your ' +
              'TPM to recover.', 'Error',
              { details: 'current state: ' + pkcs11.state + '\n' +
                    pkcs11.log });
        }
      } else {
        $("#pkcs11-status").
          text('Ready').
          attr('status', 'green');

        if (retval.data.isLibcrosLoaded && !retval.data.tpm.isEnabled) {
          if (!tpmError) {
            client.showError("Your TPM is not enabled.  Please enable " +
                             "it in the BIOS.");
            $('#entd-message').
              text('Please reboot and enable your TPM.').
              attr('status', 'red');
            tpmError = true;
          }
        } else if (retval.data.isLibcrosLoaded && !retval.data.tpm.isReady) {
          if (!tpmError) {
            client.showAlert("Your TPM is not owned.  If this message does " +
                             "not go away on its own after a minute, you " +
                             "should reboot and clear your TPM in the BIOS.");
            $('#entd-message').
              text('Waiting for TPM.').
              attr('status', 'red');
            tpmError = true;
          }
        } else {
          ready = true;
        }
      }

    } else {
      $("#entd-status").
          text('Waiting...').
          attr('status', 'red');

      if (!daemonError) {
        daemonError = true;
        client.showError(
            'The Enterprise Daemon has not started.  You must log out or ' +
            'reboot after installing the policy.  If the problem persists, ' +
            'try clearing your TPM in the BIOS.', 'Error',
            { details: JSON.stringify(retval)} );
      }
    }

    if (ready) {
      if (retval.data.browserPolicyChanged) {
        $('#entd-message').
            text('Your browser settings have been changed, you ' +
                 'must log out before they take effect.').
            attr('status', 'red');
      } else {
        $('#entd-message').text('');
      }

      client.hideModal();
      client.onPkcs11Ready();
    } else {
      setTimeout(function () {
          client.invokePolicyCallback('info', null, oncomplete);
      }, 2000);
    }
  }

  client.invokePolicyCallback('info', null, oncomplete);
};

/**
 * Load token information from the enterprise daemon and update the UI with
 * the results.
 */
client.loadTokens =
function loadTokens() {
  function oncomplete(retval) {
    if (retval instanceof client.CallbackSuccess) {
      if (client.tokens) {
        // If we've loaded certificates at least once, then just
        // update the existing UI.
        client.refreshTokens(retval.data.tokenList);
      } else {
        // Otherwise we have to create it from scratch.
        client.resetTokens(retval.data.tokenList);
      }
    } else {
      throw new Error('Callback failed: ' + retval);
    }
  }

  client.invokePolicyCallback('listTokens', null, oncomplete);
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

/**
 * Initiate a certificate installation.
 *
 * This causes the certificate progress dialog to be shown, and manages
 * the asynchronous installation of a certificate.
 */
client.installCert =
function installCert(cert, variables) {
  var key = cert.key;

  // Called for any kind of error from the enterprise daemon.
  function onerror(retval) {
    if (retval instanceof client.CallbackError) {
      client.hideModal(function () {
          if (retval && retval.arg_ && retval.arg_.variables &&
              retval.arg_.variables.password) {
            retval.arg_.variables.password = '** PASSWORD WAS HERE **';
          }
          client.showError(retval.data, 'Error',
                           { details: JSON.stringify(retval) });
        });
    }
  };

  // Called when we get an updated list of certificates.
  function oncomplete_list(retval) {
    if (retval instanceof client.CallbackError)
      return onerror(retval);

    client.refreshCertificates(retval.data);
    cert = retval.data[key];
    if (!cert)
      return alert("No cert: " + key);

    if (cert.state == 'stop:csr') {
      // CSR is done, now fetch the cert.
      $('#cert-status').find('.cert-csr').attr('status', 'green');
      $('#cert-status').find('.cert-request').attr('status', 'progress');
      client.invokePolicyCallback('getCert', { certificateId: cert.id },
                                  onerror);
    } else if (cert.state == 'stop:cert') {
      // Cert is fetched, configure the network
      $('#cert-status').find('.cert-request').attr('status', 'green');
      $('#cert-status').find('.cert-install').attr('status', 'progress');
      client.invokePolicyCallback('installCert', { certificateId: cert.id },
                                  onerror);
    } else if (cert.state == 'stop:ready') {
      $('#cert-status').find('.cert-install').attr('status', 'green');
      client.showSuccess('Your certificate has been installed',
                         'Certificate Installed');
      return;
    } else if (cert.state == 'stop:error') {
      client.showCertDetails(cert);
      return;
    }

    setTimeout(function () {
        client.invokePolicyCallback('listCertificates', null,
                                    oncomplete_list);
      }, 1000);
  };

  client.showCertProgress(cert);

  $('#cert-status').find('.cert-csr').attr('status', 'progress');

  client.invokePolicyCallback(
      'initiateCSR', { certificateId: cert.id, variables: variables },
      onerror);

  client.invokePolicyCallback('listCertificates', null, oncomplete_list);
}

/**
 * Initiate a token initialization.
 *
 * This causes the token initialization progress dialog to be shown, and manages
 * the asynchronous initialization of a token.
 */
client.initToken =
function initToken(token, force) {
  var slotId = token.slotId;

  // Called for any kind of error from the enterprise daemon.
  function onerror(retval) {
    if (retval instanceof client.CallbackError)
      client.showError('There was an error initializing your token. ' +
                       'If the problem persists, clear your TPM and try ' +
                       'again.', 'Error',
                       { details: JSON.stringify(retval) });
  };

  // Called when we get an updated list of tokens.
  function oncomplete_list(retval) {
    if (retval instanceof client.CallbackError)
      return onerror(retval);

    client.tokens = retval.data.tokenList;
    client.refreshTokens(client.tokens);

    token = retval.data.tokenList[slotId];
    if (!token)
      return alert("No token: " + slotId);

    if (token.state == 'stop:init') {
      // Initialization is done, reset the SO pin.
      $('.status.token-init').attr('status', 'green');
      $('.status.token-so').attr('status', 'progress');
      client.loadCertificates();
      client.invokePolicyCallback('setSoPin', { slotId: token.slotId },
                                  onerror);
    } else if (token.state == 'stop:so-pin') {
      // SO pin is set, set the user pin.
      $('.status.token-so').attr('status', 'green');
      $('.status.token-user').attr('status', 'progress');
      client.invokePolicyCallback('setUserPin', { slotId: token.slotId },
                                  onerror);
    } else if (token.state == 'stop:ready') {
      // User pin is set, all done.
      $('.status.token-user').attr('status', 'green');
      client.showSuccess('The PKCS#11 token has been successfully ' +
                         'initialized. You may now install certificates.',
                         'Token Initialized');
      return;
    } else if (token.state == 'stop:error') {
      client.showTokenDetails(token);
      return;
    }

    setTimeout(function () {
        client.invokePolicyCallback('listTokens', null,
                                    oncomplete_list);
      }, 1000);
  };

  if (!force && token.state == 'stop:ready') {
    client.showQuery('Re-initializing this token will remove all keys ' +
                     'and certificates from the device.  Would you like ' +
                     'to continue?', 'Re-Initialize?',
                     { okCallback: function () {
                         client.initToken(token, true);
                     }});
    return;
  }

  client.showTokenProgress(token);
  $('.status.token-init').attr('status', 'progress');
  client.invokePolicyCallback('initToken', { slotId: token.slotId },
                              onerror);

  // This needs to happen on a timeout, or sometimes the listTokens returns
  // before the initToken.
  setTimeout(function () {
    client.invokePolicyCallback('listTokens', null, oncomplete_list);
  }, 1000);
}

/**
 * Invoked when the 'Install' (sometimes shown as 'Reinstall') button is
 * clicked.
 *
 * @param {string} id The certificate id for the certificate whose button was
 *   clicked.
 */
client.onCertInstall_ =
function onCertInstall_(cert) {
  var tokenOk = false;

  for (var i = 0; i < client.tokens.length; ++i) {
    if (client.tokens[i].state == "stop:ready")
      tokenOk = true;
  }

  if (!tokenOk) {
    client.showAlert("Please initialize your token first");
    return;
  }

  if (cert.userVariables) {
    client.showCertQuery(cert);
  } else {
    client.installCert(cert);
  }
};

/**
 * Called when a user clicks on the 'Initialize' button on a token.
 */
client.onTokenClick_ =
function onTokenClick_(token) {
  client.initToken(token);
}

/**
 * Called when a user clicks on the 'Ok' button in an alert dialog.
 */
client.onAlertOk_ =
function onAlertOk() {
  client.hideModal(client.modalContext.okCallback);
}

/**
 * Called when a user clicks on the 'Cancel' button in an alert dialog.
 */
client.onAlertCancel_ =
function onAlertCancel() {
  client.hideModal(client.modalContext.cancelCallback);
}

client.isModalVisible =
function isModalVisible() {
  return $('#modal-shade').css('display') == 'inherit';
}

/**
 * Common code for showing different kinds of modal alerts.
 *
 * This animates the dialog on screen.  If you want to do something after the
 * animation completes, use the callback parameter.
 *
 * Don't call this directly.  Instead use client.showAlert(), showSuccess(),
 * showError(), showQuery(), or invent your own.
 *
 * @param {string} dialogQuery A jquery path to the dialog box to be shown.
 *   The element identified by this query should be a direct child of
 *   the #modal-shade element.
 * @param {function} callback The function to invoke when the dialog is shown.
 */
client.showModal_ =
function showModal_(dialogQuery, callback) {
  var container = $('#modal-shade');
  var dialog = $(dialogQuery, container)[0];

  if (!dialog)
    throw new Error('Unknown modal dialog: ' + dialogQuery);

  container.children().each(function(index, element) {
      $(element).css('display', (element == dialog ? 'inherit' : 'none'));
    });

  container.css('display', 'inherit');

  setTimeout(function () {
      container.css('top', '0%');
      var firstInput = $('input', dialog)[0];
      if (firstInput)
        firstInput.focus();

      if (typeof callback == 'function')
        callback();
    }, 1);
}

/**
 * Called when a user clicks the "Details" link in a modal alert.
 */
client.toggleDetails =
function toggleDetails() {
  var details = $('textarea.dialog-details')[0];
  if ($(details).css('display') == 'none') {
    $('a.dialog-details').text('Hide Details');
    $('textarea.dialog-details').css('display', 'inherit' );
    setTimeout(function () {
        $('textarea.dialog-details').css('height', '7em');
      }, 1);
  } else {
    $('a.dialog-details').text('Show Details');
    $('textarea.dialog-details').css('height', '0em' );
    setTimeout(function () {
        $('textarea.dialog-details').css('display', 'none');
      }, 250);
  }
}

/**
 * Hide any modal dialog box.
 *
 * This animates the dialog box off screen, rather than instantly hiding the
 * dialog.  If you want to do something after the dialog is hidden (like
 * display another dialog box) then you should make use of the callback
 * parameter.
 *
 * @param {function} callback The function to invoke once the dialog box is
 *   hidden.
 */
client.hideModal =
function hideModal(callback) {
  client.modalContext = null;

  var container = $('#modal-shade');

  container.css('left', '-100%');

  // There is a transition associated with the change in 'left', this timeout
  // waits until that's done before resetting the dialog.
  setTimeout(function () {
      var transition = container.css('-webkit-transition');

      // Clear the transition so we can move the dialog back to the top of
      // the page without waiting for the transition.
      container.css('-webkit-transition', '');

      // Setting webkit-transition doesn't take effect in chrome until this
      // call completes, so we need this 1ms timeout.
      setTimeout(function () {
       container.css({ display: 'none', top: '-100%', 'left': '0%',
                       '-webkit-transition': transition });
       if (typeof callback == "function") {
         // We reset the transition, so we need another 1ms time to make it
         // take effect.
         setTimeout(callback, 1);
       }
      }, 1);
    }, 250);
};

/**
 * Show a modal "Alert" style dialog box.
 *
 * Graphic is a yellow "!", box has a single "Ok" button.
 *
 * This function is also used as a base for the other alert-like dialogs,
 * showSuccess(), showError(), and showQuery().
 *
 * @param {string} message The message to be displayed in the main part of
 *   the dialog box.  This will be displayed in a large font, so should be
 *   kept relatively short.
 * @param {string} title Optional.  The title of the alert.  Defaults to
 *   'Alert'.
 * @param {Object} options Optional.  May contain the following properties:
 *   - okCallback {function} The function to call if the user clicks "Ok".
 *   - cancelCallback {function} The function to call if the user clicks
 *       "Cancel". (Only valid for client.showQuery).
 *   - details {string} A string containing a more detailed message.  This
 *       will enable the "Details" link in the dialog, which will reveal
 *       the detail message in a read-only textarea.
 */
client.showAlert =
function showAlert(message, title, options) {
  if (client.isModalVisible()) {
    client.hideModal(function () { client.showAlert(message, title, options) });
    return;
  }

  client.modalContext = {
    okCallback: (options && options.okCallback || null),
    cancelCallback: (options && options.cancelCallback || null),
  };

  options = options || {};

  var alertDialog = $('#alert-dialog');
  client.showModal_(alertDialog, options.showCallback);

  $('.dialog-title', alertDialog).text(title || 'Alert');
  $('.dialog-message', alertDialog).text(message || 'NO MESSAGE PROVIDED');
  $('.dialog-ok', alertDialog).css('display', 'inherit');
  $('.dialog-cancel', alertDialog).css('display', 'none');
  $('.dialog-graphic', alertDialog).text('!').attr('status', '');

  if (options.details) {
    $('a.dialog-details', alertDialog).
      css('display', 'inherit').
      text('Show Details');
  } else {
    $('a.dialog-details', alertDialog).css('display', 'none');
  }

  $('textarea.dialog-details', alertDialog).
    css({ display: 'none', height: '0em' }).
    text(options.details);
}

/**
 * Show a modal "Query" style dialog box.
 *
 * Graphic is a green "?", box has an "Ok" button and a "Cancel" button.
 */
client.showQuery =
function showQuery(message, title, options) {
  if (client.isModalVisible()) {
    client.hideModal(function () {
        client.showQuery(message, title, options)
    });
    return;
  }

  client.showAlert(message, title, options);

  $('#alert-dialog .dialog-graphic').
    html('?').
    attr('status', 'success');

  $('#alert-dialog .dialog-cancel').css('display', 'inherit');
}

/**
 * Show a modal "Success" style dialog box.
 *
 * Graphic is a green check mark, box has a single "Ok" button.
 */
client.showSuccess =
function showSuccess(message, title, options) {
  if (client.isModalVisible()) {
    client.hideModal(function () {
        client.showSuccess(message, title, options)
    });
    return;
  }

  client.showAlert(message, title, options);

  $('#alert-dialog .dialog-graphic').
    html('&#x2714;'). // unicode "heavy check"
    attr('status', 'success');
}

/**
 * Show a modal "Error" style dialog box.
 *
 * Graphic is a red "X", box has a single "Ok" button.
 */
client.showError =
function showError(message, title, options) {
  if (client.isModalVisible()) {
    client.hideModal(function () {
        client.showError(message, title, options)
    });
    return;
  }

  client.showAlert(message, title || 'Error', options);

  $('#alert-dialog .dialog-graphic').
    html('&#x2718;'). // unicode "heavy ballot x"
    attr('status', 'error');
}

/**
 * Show the details for a given token in a modal dialog box.
 *
 * Shows the token details in a modal Error, Success, or Alert box, depending
 * on the state of the token.
 */
client.showTokenDetails =
function showTokenDetails(token) {
  var options = { details: '' };
  if (token.log)
    options.details += token.log + '\n';

  options.details += 'current state: ' + token.state +
    '\nslotId: ' + token.slotId + '\nflags: ';

  for (var key in token.flags) {
    if (token.flags[key])
      options.details += '\n* ' + key;
  }

  if (token.state == 'stop:error') {
    var msg = client.getLastLogLine(token.log);
    if (!msg)
      msg = 'There was an error initializing your token';
    client.showError(msg, 'Error', options);
    return;
  }

  if (token.state == 'stop:init') {
    client.showSuccess('Token is initialized', 'Token Information', options);
    return;
  }

  client.showAlert('Token is not initialized: ' + token.state,
                   'Token Information', options);
}

/**
 * Shows the Token Progress dialog.
 */
client.showTokenProgress =
function showTokenProgress(token) {
  $('#token-status').find('.status').attr('status', 'pending');
  $('#token-desc').text(token.manufacturerID + ', ' + token.model);
  $('#token-slot').text(token.slotId);
  client.showModal_('#token-status');
}

/**
 * Show the details for a given certificate in a modal dialog box.
 *
 * Shows the certificate details in a modal Error, Success, or Alert box,
 * depending on the state of the certificate.
 */
client.showCertDetails =
function showCertDetails(cert) {
  var options = { details: '' };
  if (cert.log)
    options.details += cert.log + '\n';

  options.details += 'current state: ' + cert.state;

  if (cert.state == 'stop:error') {
    var msg = client.getLastLogLine(cert.log);
    if (!msg)
      msg = 'There was an error installing your certificate';
    client.showError(msg, 'Error', options);
    return;
  }

  if (cert.state == 'stop:install') {
    client.showSuccess('Certificate is installed', 'Certificate Information',
                       options);
    return;
  }

  client.showAlert('Certificate is not installed',
                   'Certificate Information', options);
}

/**
 * Shows the Certificate Progress dialog.
 */
client.showCertProgress =
function showCertProgress(cert) {
  $('#cert-status').find('.status').attr('status', 'pending');
  $('#cert-status-label').text(cert.label);
  client.showModal_('#cert-status');
}

/**
 * Show the modal dialog box used to collect user variables.
 *
 * @param {Object} cert The certificate object that should be associated with
 *  the modal dialog.
 */
client.showCertQuery =
function showCertQuery(cert) {
  client.modalContext = { cert: cert };

  $('#user-vars').empty();

  var firstInput;

  for (var key in cert.userVariables) {
    var uservar = cert.userVariables[key];

    var html = util.replaceVars(
        '<li>%(label) <input name="%(varname)" id="uservar:%(varname)" ' +
        'type="%(type)">',
        { label: uservar.label || key,
          varname: key,
          type: (uservar.type == 'password' ? 'password' : 'text')
        });

    $('#user-vars').append(html);
  }

  $('#cert-query-label').text(cert.label);

  client.showModal_('#cert-query');
};

/**
 * Called when the 'Submit' button is clicked on the cert dialog.
 */
client.onCertSubmit_ =
function onCertCancel() {
  var cert = client.modalContext.cert;

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

  client.hideModal(function () { client.installCert(cert, variables) });
};

/**
 * Called when the 'Cancel' button is clicked on the cert dialog.
 */
client.onCertCancel_ =
function onModalCancel() {
  client.hideModal();
};

/**
 * Clear the token list UI and repopulate it.
 *
 * @param {Array} tokens The list of known tokens.
 */
client.resetTokens =
function resetTokens(tokens) {
  client.tokens = tokens;

  $('#token-list').empty();
  client.refreshTokens(tokens);
};

/**
 * Synchronize the existing token list UI with the known list of tokens.
 *
 * @param {Array} tokens The list of known tokens.
 */
client.refreshTokens =
function refreshTokens(tokens) {
  for (var i = 0; i < tokens.length; ++i) {
    var rv = $('#token-' + tokens[i].slotId);

    if (rv[0]) {
      client.refreshToken(rv[0], tokens[i]);
    } else {
      client.renderToken(tokens[i]);
    }
  }
};

/**
 * Create UI for a given token.
 *
 * @param {Object} token The target token.
 */
client.renderToken =
function renderToken(token) {
  var li = document.createElement('li');
  li.className = 'token';
  li.setAttribute('id', 'token-' + token.slotId);

  $(li).html(
      '<table width="100%">' +
      '<tr><td><span class="desc"></span> (<span class="label"></span>)</td>' +
      '<td rowspan="2" width="1%"><button>Initialize</button></td></tr>' +
      '<tr><td class="status"></td></tr></table>');

  $(li).find('button').click(function () {
      client.onTokenClick_(client.tokens[token.slotId]);
  });

  $(li).find('.status').click(function () {
      client.showTokenDetails(client.tokens[token.slotId]);
  });

  client.refreshToken(li, token);

  $('#token-list').append(li);
}

/**
 * Refresh UI for a given token.
 *
 * @param {Object} token The target token.
 */
client.refreshToken =
function refreshToken(li, token) {
  var status;
  if (token.state == 'stop:ready') {
    color = 'green';
    status = 'Initialized.';
  } else if (!token.flags.TOKEN_INITIALIZED) {
    color = 'red';
    status = 'Not initialized.';
  } else if (token.flags.SO_PIN_TO_BE_CHANGED ||
             token.flags.USER_PIN_TO_BE_CHANGED) {
    color = 'red';
    status = 'PINs not initialized.';
  } else {
    color = 'red';
    status = 'Token error';
  }

  $('.desc', li).text(token.manufacturerID + ', ' + token.model);
  $('.label', li).text(token.label || 'Unlabeled');
  $('.status', li).attr('status', color);
  $('.status', li).text(status);
  $('button', li).text(color == 'red' ? 'Initialize' : 'Reinitialize');
}

/**
 * Create the UI for a list of certificates.
 *
 * This will destroy any existing cert UI before proceeding.
 *
 * @param {Array} certs The list of known certificates.
 */
client.resetCertificates =
function resetCertificates(certs) {
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
  var ok = false;
  var status;
  if (cert.state == 'stop:ready') {
    ok = true;
    status = 'Installed.';
  } else if (cert.state == 'stop:error') {
    status = 'Error installing certificate.';
  } else {
    status = 'Not installed.';
  }

  $('.label', li).text(cert.label);
  $('.status', li).text(status).
    attr('status', ok ? 'green' : 'red');
  $('button', li).text(ok ? 'Reinstall' : 'Install');

  return;
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

  li.innerHTML = '<table width="100%">' +
  '<tr><td class="label" width="100%"></td>' +
  '    <td rowspan="2" valign="center" align="right" width="1%"><button></td>' +
  '</tr><tr><td class="status" width="100%"></td></tr>';

  $('button', li).click(function() {
      client.onCertInstall_(client.certificates[cert.id])
  });

  $(li).find('.status').click(function () {
      client.showCertDetails(client.certificates[cert.id]);
  });

  $('#cert-list').append(li);
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
      console.log(this.responseText);
      var retval = JSON.parse(this.responseText);
      var param;

      if (typeof retval == 'object') {
        if (retval.status == 'success') {
          param = new client.CallbackSuccess(name, arg, retval);
        } else if (retval.status == 'error') {
          param = new client.CallbackError(name, arg, retval);
        }
      }

      if (!param) {
        param = new client.CallbackError
            (name, arg,
             'Unexpected response to callback: ' + name + ': ' +
             JSON.stringify(retval));
      }
    } else {
      param = new client.CallbackError(
          name, arg,
          { msg: 'Error invoking callback: ' + name + ': http status: ' +
            this.status } );
    }

    param.xhrStatus = xhr.status;
    oncomplete(param);
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
