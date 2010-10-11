// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This testcase expects that pkcsslotd is NOT running when it starts, but
// will become ready within 2 seconds.

function tryAgain() {
  var pkcs11 = new entd.crypto.Pkcs11();
  if (!(pkcs11 instanceof entd.crypto.Pkcs11))
    println("Got unexpected Pkcs11 object: " + pkcs11);

  var str = pkcs11.toString();
  if (str != "[object entd.crypto.Pkcs11]")
      println("pkcs11 has unexpected toString result: " + str);

  println("pkcs11: " + str);
  println("LOOKS OK");
}

entd.onLoad = function () {
  try {
    new entd.crypto.Pkcs11();
  } catch (ex) {
    if (!ex.toString().match(/PKCS#11 error/i)) {
      println("Got unexpected exception: " + ex);
      return;
    }
  }

  entd.setTimeout(tryAgain, 2000);
}
