// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

function tryConstructor(name) {
  if (!(name in entd.crypto.Pkcs11)) {
    println("Missing entd.crypto.Pkcs11." + name);
    return false;
  }

  if (typeof entd.crypto.Pkcs11[name] != "function") {
    println("Expected entd.crypto.Pkcs11." + name + " to be a function.");
    return false;
  }

  try {
    new entd.crypto.Pkcs11[name]();
  } catch (ex) {
    if (!ex.toString().match(/cannot be invoked from script/i)) {
      println("Unexpected exception constructing pkcs11." + name + ": " + ex);
      return false;
    }

    return true;
  }

  println("Expected an exception constructing pkcs11." + name + ": " + ex);
  return false;
}

entd.onLoad = function () {
  var ary = ["Slots", "Slot", "Token", "Session"];

  for (var i = 0; i < ary.length; ++i) {
    if (!tryConstructor(ary[i]))
        return;
  }

  println("LOOKS OK");
}
