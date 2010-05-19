// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

entd.onLoad =
function onLoad(manifest) {
  var slot1 = new entd.pkcs11.SlotObject("slot1");
  // println("slot1: " + slot1.toString());
  slot1.generateKeyPair("key1");
  var csr1 = new slot1.CSR("subject1");
  // println("csr1: " + csr1.toString());
  var cert1 = new entd.pkcs11.Certificate("content1");
  // println("Adding cert1: " + cert1);
  slot1.addCertificate(cert1);
  // println("slot1: " + slot1.toString());

  var slot2 = new entd.pkcs11.SlotObject("slot2");
  slot2.generateKeyPair("key2");
  var csr2 = new slot2.CSR("subject2");
  // println("csr2: " + csr2.toString());
  var cert2 = new entd.pkcs11.Certificate("content2");
  // println("Adding cert2: " + cert2);
  slot2.addCertificate(cert2);

  println("Slots:");
  println(JSON.stringify(entd.pkcs11.slots));
}
