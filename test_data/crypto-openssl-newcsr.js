// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This testcase expects that pkcsslotd is NOT running, so we won't be able to
// create the Pkcs11 object.

var Slot = entd.crypto.Pkcs11.Slot;
var Token = entd.crypto.Pkcs11.Token;
var Session = entd.crypto.Pkcs11.Session;
var Object = entd.crypto.Pkcs11.Object;
var CSR = entd.crypto.OpenSSL.CSR;

const ENGINE_ID = "pkcs11";

const KEY_ID = "2857967a"
const KEY_LABEL = "OPENSSL_CSR_TEST";
const TEST_USER_PIN = "111111";

function createTestKey(session, id, label) {
  session.generateKeyPair(
    Session.CKM_RSA_PKCS_KEY_PAIR_GEN,
    [
      // Public key properties.
      [Object.CKA_ENCRYPT, true],
      [Object.CKA_VERIFY, true],
      [Object.CKA_WRAP, true],
      [Object.CKA_MODULUS_BITS, 2048],
    ],
    [
      // Private key properties.
      [Object.CKA_PRIVATE, true],
      [Object.CKA_SENSITIVE, true],
      [Object.CKA_SIGN, true],
      [Object.CKA_DECRYPT, true],
      [Object.CKA_UNWRAP, true],
    ],
    [
      // Common properties of public & private.
      [Object.CKA_TOKEN, true],
      [Object.CKA_LABEL, label],
      [Object.CKA_ID, id]
    ]
  );
}

function findObjects(session, id, label, type) {
  return session.findObjects(
    [
      [Object.CKA_CLASS, type],
      [Object.CKA_ID, id],
      [Object.CKA_LABEL, label]
    ]
  );
}

function keyExists(session, key_to_find_id, key_to_find_label, key_type) {
  try {
    // Search for ID + label.
    var result = findObjects(session, key_to_find_id, key_to_find_label,
                             key_type) || null;
    if (result == null || result.length != 1)
      return false;
  } catch(ex) {
    return println("Failed to search for the key: " + ex);
  }

  return true;
}

// Ensures the necessary private key exists to perform the test.
// This function creates the key if it does not exist.
function ensureTestKeyExists() {
  var pkcs11 = new entd.crypto.Pkcs11();

  var slot = pkcs11.slots[0];

  if (!(slot.flags & Slot.CKF_TOKEN_PRESENT))
    return println("Expected slot 0 to have a token present");

  var token = slot.token;

  if (!(token instanceof Token))
    return println("Expected instanceof entd.Pkcs11.Token");

  var session = null;
  try {
    token.closeAllSessions();
    session = token.openSession(Token.CKF_RW_SESSION);
  } catch (ex) {
    println('Unable to open session: ' + ex);
    return false;
  }

  if (!(session instanceof Session))
    return println("Expected instanceof entd.Pkcs11.Session.");

  try {
    if (!session.login(Session.CKU_USER, TEST_USER_PIN)) {
      println('Unable to log in user into token.');
      session.close();
      return false;
    }
  } catch (ex) {
    println('Failed to login user into token: ' + ex);
    session.close();
    return false;
  }

  try {
    // If key exists, we are done.
    if (keyExists(session, KEY_ID, KEY_LABEL, Object.CKO_PRIVATE_KEY))
      return true;
  } catch(ex) {
    return println("Expected to create key pair: " + ex);
  }

  try {
    // Key does not exist, create it.
    createTestKey(session, KEY_ID, KEY_LABEL);
  } catch(ex) {
    return println("Expected to create key pair: " + ex);
  }

  try {
    // Key was created, we are done.
    if (keyExists(session, KEY_ID, KEY_LABEL, Object.CKO_PRIVATE_KEY))
      return true;
  } catch(ex) {
    return println("Expected to create key pair: " + ex);
  }

  return println("Did not create the necessary keys.");
}

entd.onLoad = function () {
  var engine = new entd.crypto.OpenSSL.Engine(ENGINE_ID);

  if (!ensureTestKeyExists())
    return println("Failed to ensure test key exists.");

  // Positive test.
  var csr = engine.createCSR("id_" + KEY_ID, "/CN=nelsona@google.com");
  if (!(csr instanceof CSR))
    return println("Failed to create X.509 certificate request.");

  var csrText = csr.toFormat(CSR.CSR_FORMAT_PEM_TEXT);
  if (csrText.indexOf("-BEGIN CERTIFICATE REQUEST-") == -1)
    return println("Invalid certificate request");

  // Clears object handles.
  csr.dispose();

  // Negative test.
  try {
    var csr = engine.createCSR("id_" + KEY_ID + "9999",
                               "/CN=nelsona@google.com");
    return println("Created request without corresponding key.");
  } catch(ex) {
    // Exception is expected.
  }

  engine.dispose();

  println("LOOKS OK");
}
