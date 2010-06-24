// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This test assumes that the host is in a state where the pkcs11 object
// is not ready.

var checkCount = 0;

function checkReady() {
  if (entd.pkcs11.isReady)
    throw "Didn't expect pkcs11 to be ready";

  if (++checkCount == 4)
    println("LOOKS OK");
}

entd.onLoad = function () {
    entd.setTimeout(checkReady, 250);
    entd.setTimeout(checkReady, 500);
    entd.setTimeout(checkReady, 750);
    entd.setTimeout(checkReady, 1000);
}
