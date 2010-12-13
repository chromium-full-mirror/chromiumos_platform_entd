// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

var Slot = entd.crypto.Pkcs11.Slot;
var Token = entd.crypto.Pkcs11.Token;
var Session = entd.crypto.Pkcs11.Session;
var Object = entd.crypto.Pkcs11.Object;

const TEST_USER_PIN = "111111";

function findObjects(session, id, label, type) {
  if (id != null && label != null) {
    return session.findObjects(
      [
        [Object.CKA_CLASS, type],
        [Object.CKA_ID, id],
        [Object.CKA_LABEL, label]
      ]
    );
  } else if (id != null) {
    return session.findObjects(
      [
        [Object.CKA_CLASS, type],
        [Object.CKA_ID, id]
      ]
    );
  } else if (label != null) {
    return session.findObjects(
      [
        [Object.CKA_CLASS, type],
        [Object.CKA_LABEL, label]
      ]
    );
  } else {
    return println("Invalid test argument");
  }
}

function createKey(session, id, label) {
  session.generateKeyPair(
    Session.CKM_RSA_PKCS_KEY_PAIR_GEN,
    [
      // Public key properties.
      [Object.CKA_TOKEN, true],
      [Object.CKA_ENCRYPT, true],
      [Object.CKA_VERIFY, true],
      [Object.CKA_WRAP, true],
      [Object.CKA_MODULUS_BITS, 2048],
    ],
    [
      // Private key properties.
      [Object.CKA_TOKEN, true],
      [Object.CKA_PRIVATE, true],
      [Object.CKA_SENSITIVE, true],
      [Object.CKA_SIGN, true],
      [Object.CKA_DECRYPT, true],
      [Object.CKA_UNWRAP, true],
    ],
    [
      // Common properties of public & private.
      [Object.CKA_LABEL, label],
      [Object.CKA_ID, id]
    ]
  );
}

function testFindKey(session, key_to_find_id, key_to_find_label, key_type) {
  // Positive tests.
  try {
    // Search for ID + label.
    var result = findObjects(session, key_to_find_id, key_to_find_label,
                             key_type) || null;
    if (result == null || result.length != 1)
      return println("Did not find public key (id + label)");

    // Search for ID only.
    var result = findObjects(session, key_to_find_id, null, key_type) || null;
    if (result == null || result.length != 1)
      return println("Did not find public key (id)");

    // Search for label only.
    var result = findObjects(session, null, key_to_find_label,
                             key_type) || null;
    if (result == null || result.length != 1)
      return println("Did not find public key (label)");
  } catch(ex) {
    return println("Failed to search for the key: " + ex);
  }

  // Negative tests.
  try {
    // Fail search for ID + label.
    var result = findObjects(session, key_to_find_id + "AA",
                             key_to_find_label, key_type) || null;
    if (result != null && result.length != 0)
      return println("Expect not to find public key (bad id + label)");
    // Fail search for ID + label.
    var result = findObjects(session, key_to_find_id,
                             key_to_find_label + "BAD", key_type) || null;
    if (result != null && result.length != 0)
      return println("Expect not to find public key (id + bad label)");
    // Fail search for ID + label.
    var result = findObjects(session, key_to_find_id + "AA",
                             key_to_find_label + "BAD", key_type) || null;
    if (result != null && result.length != 0)
      return println("Expect not to find public key (bad id + bad label)");
  } catch(ex) {
    return println("Failed to search for the key: " + ex);
  }
  try {
    // Fail search for ID.
    var result = findObjects(session, key_to_find_id + "AA", null, key_type) || null;
    if (result != null && result.length != 0)
      return println("Expect not to find public key (bad id)");
  } catch(ex) {
    return println("Failed to search for the key: " + ex);
  }
  try {
    // Fail search for label.
    var result = findObjects(session, key_to_find_id, key_to_find_label + "BAD", key_type) || null;
    if (result != null && result.length != 0)
      return println("Expect not to find public key (bad label)");
  } catch(ex) {
    return println("Failed to search for the key: " + ex);
  }

  return true;
}

entd.onLoad = function () {

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
    return println("Expected instanceof entd.Pkcs11.Session");

  try {
    if (!session.login(Session.CKU_USER, TEST_USER_PIN)) {
      println('Unable to log in user into token');
      session.close();
      return false;
    }
  } catch (ex) {
    println('Failed to login user into token: ' + ex);
    session.close();
    return false;
  }

  var key_to_find_label = "KEY_TO_FIND";
  var key_to_find_id = "223344";

  try {
    createKey(session, key_to_find_id, key_to_find_label);
  } catch(ex) {
    return println("Expected to create key pair: " + ex);
  }

  // Exercise tests of the private key.
  if (!testFindKey(session, key_to_find_id, key_to_find_label,
                   Object.CKO_PRIVATE_KEY)) {
    return;
  }

  // Exercise tests of the public key.
  if (!testFindKey(session, key_to_find_id, key_to_find_label,
                   Object.CKO_PUBLIC_KEY)) {
    return;
  }

  println("LOOKS OK");
}
