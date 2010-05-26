// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

entd.onLoad =
function onLoad(manifest) {
  entd.pkcs11.setUserPin("000000");
  var slot1 = new entd.pkcs11.SlotObject("slot1");
  entd.pkcs11.remove(slot1);

  print("Slots: ");
  println(JSON.stringify(entd.pkcs11.slots));
}
