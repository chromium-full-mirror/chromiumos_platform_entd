// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This testcase expects that pkcsslotd is NOT running, so we won't be able to
// create the Pkcs11 object.

entd.onLoad = function () {
  try {
    new entd.crypto.Pkcs11();
  } catch (ex) {
    if (ex.toString().match(/PKCS#11 error/i)) {
      println("LOOKS OK");
      return;
    }

    println("Got unexpected exception: " + ex);
    return;
  }

  println("Expected Pkcs11() constructor to fail.");
}
