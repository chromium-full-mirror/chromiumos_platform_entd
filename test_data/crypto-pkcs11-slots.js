// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

entd.onLoad = function () {
  var pkcs11 = new entd.crypto.Pkcs11();

  if (!("slots" in pkcs11))
    return println("Pkcs11 object is missing its 'slots' object");

  if (!(pkcs11.slots instanceof entd.crypto.Pkcs11.Slots))
    return println("Expected pkcs11.slots instanceof entd.crypto.Pkcs11.Slots");

  var str = pkcs11.slots.toString();
  if (str != "[object entd.crypto.Pkcs11.Slots]")
    return println("pkcs11.slots has unexpected toString result: " + str);

  var slots;

  slots = pkcs11.slots;

  var expectedProps = { 0: true, "length": true };

  for (var key in slots) {
    if (key in expectedProps)
      delete expectedProps[key];
    else
      return println("Unexpected property in slots object: " + key);
  }

  var hasMissingProps = false;
  for (var key in expectedProps) {
    println("Missing expected property in slots object: " + key);
    hasMissingProps = true;
  }

  if (hasMissingProps)
    return;

  delete slots.length;
  if (!("length" in slots))
    return println("Didn't expect to be able to delete slots.length.");

  if (slots.length != 1)
    return println("Expected one slot, found: " + slots.length);

  slots.length = 10;
  if (slots.length != 1)
    return println("Didn't expect to be able to change slots.length");

  var ex = null;

  try {
    delete slots[0];
  } catch (ex_) {
    ex = ex_;
  }

  if (!ex || !slots[0])
    return println("Expected exception deleting slot.");

  if (!ex.toString().match(/attempt to delete/i))
    return println("Got unexpected exception deleting slot.");

  if (!(0 in slots))
    return println("Expected '0 in pkcs11.slots' to return true");

  if ((1 in slots))
    return println("Expected '1 in pkcs11.slots' to return false");

  println("LOOKS OK");
}
