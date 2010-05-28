// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

entd.onLoad =
function onLoad(manifest) {
  entd.pkcs11.setUserPin("000000");
  var slot1 = new entd.pkcs11.SlotObject("slot1");
  // Generate a keypair
  slot1.generateKeyPair("9999")
  // CSR construction may actually create the key in the TPM
  var csr1 = new slot1.CSR("/C=Test");
  // Now remove it
  entd.pkcs11.remove(slot1, "9999");

  print("Slots: ");
  println(JSON.stringify(entd.pkcs11.slots));
}
