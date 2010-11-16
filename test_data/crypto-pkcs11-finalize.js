// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

entd.onLoad = function () {
  var pkcs11 = new entd.crypto.Pkcs11();
  println("pkcs11: " + pkcs11);

  // This test only watches for the "Finalizing PKCS11 API" message that should
  // appear on exit.  This has to happen in the test driver, since the message
  // is emitted after V8 is shut down.
}
