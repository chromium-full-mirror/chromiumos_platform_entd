// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

entd.onLoad =
function onLoad(manifest) {
  entd.pkcs11.setUserPin("111111");
  var slot1 = new entd.pkcs11.SlotObject("slot1");
  // Generate a keypair and valid CSR so that we write them to the TPM
  slot1.generateKeyPair("9999");
  var subj1 = "/C=US/ST=California/L=Mountain View/O=Google Inc"
"/OU=ChromeOS/CN=user.onex.corp.google.com"
"/emailAddress=user@google.com";
  var csr1 = new slot1.CSR(subj1);
  entd.pkcs11.remove("slot1");

  print("Slots.slot1: ");
  println(JSON.stringify(entd.pkcs11.slots["slot1"]));
}
