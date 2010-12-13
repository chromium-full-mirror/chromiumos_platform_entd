// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This testcase expects that pkcsslotd is NOT running, so we won't be able to
// create the Pkcs11 object.

const ENGINE_ID = "pkcs11";

entd.onLoad = function () {
  // Positive test.
  try {
    var engine = new entd.crypto.OpenSSL.Engine(ENGINE_ID);
    engine.dispose();
  } catch(e) {
    return println("Failed to create OpenSSL engine: " + e);
  }

  // Negative test.
  try {
    var engine = new entd.crypto.OpenSSL.Engine();
    engine.dispose();
    return println("Should have failed for missing required engine ID");
  } catch(e) {
    // Failure expected. Test OK.
  }

  println("LOOKS OK");
}
