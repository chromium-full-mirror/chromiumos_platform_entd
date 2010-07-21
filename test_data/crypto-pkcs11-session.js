// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

entd.onLoad = function () {
  var pkcs11 = new entd.crypto.Pkcs11();
  } catch (ex) {
    if (!ex.toString().match(/PKCS#11 error/i)) {
      println("Got unexpected exception: " + ex);
      return;
    }
  }

  entd.setTimeout(tryAgain, 3000);
}
