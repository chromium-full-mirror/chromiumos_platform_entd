// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

entd.onLoad =
function onLoad(manifest) {
  var cert_str = readFromFile("test_data/cert_test.pem");
  var cert = new entd.pkcs11.Certificate(cert_str);
  if (cert.subject == "/C=US/ST=California/L=Mountain View/O=Google Inc/" +
      "OU=ChromeOS/CN=stevenjb.onex.corp.google.com/" +
      "emailAddress=stevenjb@google.com") {
    println("LOOKS OK");
  } else {
    println("Unexpected certificate subject: " + cert.subject);
  }
}
