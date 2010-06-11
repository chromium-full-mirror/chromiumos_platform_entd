// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

entd.onLoad =
function onLoad(manifest) {
  entd.pkcs11.remove("slot1");

  var slot1 = new entd.pkcs11.SlotObject("slot1");
  slot1.generateKeyPair("1001");
  var csr1 = new slot1.CSR("subject1");
  var cert1 = new entd.pkcs11.Certificate("content1");
  slot1.addCertificate(cert1);

  var slot2 = new entd.pkcs11.SlotObject("slot2");
  slot2.generateKeyPair("1002");
  var csr2 = new slot2.CSR("subject2");
  var cert2 = new entd.pkcs11.Certificate("content2");
  slot2.addCertificate(cert2);

  entd.pkcs11.remove("slot1");

  println("Slot1: " + JSON.stringify(entd.pkcs11.slots["slot1"]));
  println("Slot2: " + JSON.stringify(entd.pkcs11.slots["slot2"]));
}
