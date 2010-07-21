// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

const TEST_TOKEN_LABEL = "test token";
const TEST_SO_PIN = "000000";
const TEST_USER_PIN = "111111";

entd.onLoad = function () {
  var Slot = entd.crypto.Pkcs11.Slot;
  var Token = entd.crypto.Pkcs11.Token;
  var Session = entd.crypto.Pkcs11.Session;
  var pkcs11 = new entd.crypto.Pkcs11();

  var slot = pkcs11.slots[0];

  if (!(slot.flags & Slot.CKF_TOKEN_PRESENT))
    return println("Expected slot 0 to have a token present");

  var token = slot.token;

  if (!(token instanceof Token))
    return println("Expected instanceof entd.Pkcs11.Token");

  delete slot.token;
  if (!slot.token)
    return println("Didn't expect to be able to delete slot.token.");

  slot.token = 1;
  if (slot.token == 1)
    return println("Didn't expect to be able to change slot.token.");

  if (token.flags & Token.CKF_TOKEN_INITIALIZED)
    return println("Expected token to be uninitialized");

  if (!(token.flags & (Token.CKF_USER_PIN_TO_BE_CHANGED |
                       Token.CKF_SO_PIN_TO_BE_CHANGED))) {
    return println("Expected SO and User PINs would need to be changed.");
  }

  if (token.flags & Token.CKF_USER_PIN_INITIALIZED) {
    // openCryptoki sets the initial user pin to a known value, rather
    // than leaving it uninitialized.
    return println("Expected user PIN would not have been initialized");
  }

  token.initToken(Token.DEFAULT_SO_PIN, TEST_TOKEN_LABEL);

  token.refresh();
  if (!(token.flags & Token.CKF_TOKEN_INITIALIZED)) {
    return println("Expected token to be initialized after calling " +
                   "initToken()");
  }

  if (token.label != TEST_TOKEN_LABEL) {
    return println("Expected token label to be " + TEST_TOKEN_LABEL +
                   ", found: " + token.label);
  }

  var session = token.openSession(Token.CKF_RW_SESSION);
  if (!(session instanceof Session))
    return println("Expected instanceof entd.crypto.Pkcs11.Session");

  session.login(Session.CKU_SO, Token.DEFAULT_SO_PIN);
  session.setPin(Token.DEFAULT_SO_PIN, TEST_SO_PIN);
  session.logout();

  token.refresh();
  if (token.flags & Token.CKF_SO_PIN_TO_BE_CHANGED)
    return println("Expected SO pin would be ok after setPin()");

  session.login(Session.CKU_USER, Token.DEFAULT_USER_PIN);
  session.setPin(Token.DEFAULT_USER_PIN, TEST_USER_PIN);
  session.logout();

  token.refresh();
  if (token.flags & Token.CKF_USER_PIN_TO_BE_CHANGED)
    return println("Expected User pin would be ok after setPin()");

  if (!(token.flags & Token.CKF_USER_PIN_INITIALIZED))
    return println("Expected User pin would be initialized after setPin()");

  println("LOOKS OK");
}
