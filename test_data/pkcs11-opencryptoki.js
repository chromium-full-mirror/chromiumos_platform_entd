// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

entd.onLoad =
function onLoad(manifest) {
  entd.pkcs11.setUserPin("111111");
  var slot1 = new entd.pkcs11.SlotObject("slot1");
  // println("slot1: " + slot1.toString());
  slot1.generateKeyPair("1234");
  var subj1 = "/C=US/ST=California/L=Mountain View/O=Google Inc"
"/OU=ChromeOS/CN=user.onex.corp.google.com"
"/emailAddress=user@google.com";
  var csr1 = new slot1.CSR(subj1);
  //println("CSR1:\n" + csr1.toString());
  //println("Public Key:\n" + slot1.publicKey.toString());

  var cert1 = new entd.pkcs11.Certificate("");  // Use test certificate
  // println("Adding cert1: " + cert1);
  slot1.addCertificate(cert1);
  // println("slot1: " + slot1.toString());

  println("Slots:");
  println(JSON.stringify(entd.pkcs11.slots));
}
