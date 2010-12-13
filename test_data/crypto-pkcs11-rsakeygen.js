// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

var Slot = entd.crypto.Pkcs11.Slot;
var Token = entd.crypto.Pkcs11.Token;
var Session = entd.crypto.Pkcs11.Session;
var Object = entd.crypto.Pkcs11.Object;

const TEST_USER_PIN = "111111";

function createKeyWithCommon(session, id, label) {
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

function createKeyNoCommon(session, id, label) {
  session.generateKeyPair(
    Session.CKM_RSA_PKCS_KEY_PAIR_GEN,
    [
      // Public key properties.
      [Object.CKA_ENCRYPT, true],
      [Object.CKA_VERIFY, true],
      [Object.CKA_WRAP, true],
      [Object.CKA_MODULUS_BITS, 2048],
      [Object.CKA_TOKEN, true],
      [Object.CKA_LABEL, label],
      [Object.CKA_ID, id]
    ],
    [
      // Private key properties.
      [Object.CKA_PRIVATE, true],
      [Object.CKA_SENSITIVE, true],
      [Object.CKA_SIGN, true],
      [Object.CKA_DECRYPT, true],
      [Object.CKA_UNWRAP, true],
      [Object.CKA_TOKEN, true],
      [Object.CKA_LABEL, label],
      [Object.CKA_ID, id]
    ]
  );
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

  try {
    createKeyWithCommon(session, "010101", "GOOD_KEY");
  } catch(ex) {
    return println("Expected to create key pair (common): " + ex);
  }

  try {
    createKeyWithCommon(session, "ZZZ", "BAD_ID");
    return println("Expected to not create key pair BAD_ID (common): " + ex);
  } catch(ex) {
    // Failure is expected: PASS.
  }

  try {
    createKeyNoCommon(session, "010101CCCC", "GOOD_KEY_NC");
  } catch(ex) {
    return println("Expected to create key pair (n/common): " + ex);
  }

  try {
    createKeyNoCommon(session, "ZZZ", "BAD_ID_NC");
    return println("Expected to not create key pair BAD_ID (n/common): " + ex);
  } catch(ex) {
    // Failure is expected: PASS.
  }

  println("LOOKS OK");
}
