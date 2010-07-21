// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

entd.onLoad =
function onLoad(manifest) {
  entd.pkcs11.setUserPin("111111");

  var slot = new entd.pkcs11.SlotObject("slot1");
  if (!entd.pkcs11.slots["slot1"])
    throw "Missing entd.pkcs11.slots['slot1']";

  slot = new entd.pkcs11.SlotObject("slot2");
  if (!entd.pkcs11.slots["slot2"])
    throw "Missing entd.pkcs11.slots['slot2']";

  entd.pkcs11.remove("slot1");
  if (entd.pkcs11.slots["slot1"])
    throw "Expected not to find entd.pkcs11.slots['slot1']";

  if (!entd.pkcs11.slots["slot2"])
    throw "Missing entd.pkcs11.slots['slot2']";

  println("LOOKS OK");
}
