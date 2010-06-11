// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

entd.onLoad =
function onLoad(manifest) {
  var slot1 = new entd.pkcs11.SlotObject("slot1");
  var cert_str = readFromFile("test_data/cert_test.pem");
  var cert1 = new entd.pkcs11.Certificate(cert_str);
  slot1.addCertificate(cert1);
  println(JSON.stringify(entd.pkcs11.slots));
}
