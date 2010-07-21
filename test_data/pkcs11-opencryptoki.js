// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

entd.onLoad =
function onLoad(manifest) {
  entd.pkcs11.setUserPin("111111");
  var slot1 = new entd.pkcs11.SlotObject("slot1");
  // println("slot1: " + slot1.toString());
  slot1.generateKeyPair("1234");
  var subj1 = "/C=US/ST=California/L=Mountain View/O=Google Inc/" +
  "OU=ChromeOS/CN=stevenjb.onex.corp.google.com/" +
  "emailAddress=stevenjb@google.com";

  var cert_str = readFromFile("test_data/cert_test.pem");
  var cert1 = new entd.pkcs11.Certificate(cert_str);
  // println("Adding cert1: " + cert1);
  slot1.addCertificate(cert1);
  // println("slot1: " + slot1.toString());

  slot1 = entd.pkcs11.slots['slot1'];
  if (slot1.label != "slot1" ||
      slot1.keyIdentifier != "1234" ||
      slot1.certificate.subject != subj1) {
    return println("Unexpected value for entd.pkcs11.slots.slot1: " +
                   JSON.stringify(slot1));
  }

  println("LOOKS OK");

}
