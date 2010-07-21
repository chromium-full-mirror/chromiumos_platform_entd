// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Sample CSR:
// -----BEGIN CERTIFICATE REQUEST-----
// MIIC7DCCAdQCAQAwgaYxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlh
// MRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRMwEQYDVQQKEwpHb29nbGUgSW5jMREw
// DwYDVQQLEwhDaHJvbWVPUzEiMCAGA1UEAxMZdXNlci5vbmV4LmNvcnAuZ29vZ2xl
// LmNvbTEeMBwGCSqGSIb3DQEJARYPdXNlckBnb29nbGUuY29tMIIBIjANBgkqhkiG
// 9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzEgmsaXzXhamFBg6AmXYy3wZ9bJgXmXte2B8
// 322nFIGRRxjtWkdRH2VSoMi395XDou1kujQUpHHwUOOwWjE1ICF+/bQ2duhvWe44
// uDcCIjoSa8ZMZCcTpvk9yuk7ahJvBtR+DRQepcAh+O6TpVXfetORxGzLHMxGNMh8
// aERSR4rMciiFBSg/Nc4HUlmDT86DhqHNCSRjVrg5lmoq/eMOngxuMewobp/oZWvO
// uZ3Mvmi2FU/KFXkx2dRBlrKVgaQ23eqKg/RW+xKJmK2wICQEpYX2XmS+J37f5Mxp
// +IMJZ0BuXDrEmb1G6Ys3gfX9T3CLGMMC6sjqCf8oS/hhbSupQwIDAQABoAAwDQYJ
// KoZIhvcNAQEFBQADggEBACehWegogBwomcKSRGY1gZWKXZQ7EecrtIejW4IdLVdQ
// ghNtP5qK6NxPNJrUi0fpHioCdGCHJDltLC7jhBPRGREXwSnEkPr3fziMxKxODVqw
// bNjauNs22I3tG0wkmsXV2+gfqcsC1ZGO3ppQ68zjuMhg4IEo/eA9deJ/CTNYPc9j
// gYjeLSTTY/8FFwYbtuFf5E2gmG2j9DamykogFBTyDgYVFM30tkljs7V8cWt82qjw
// gTM8DhDo3dvvRimXZEnzKoVosogILhsJv9OZ5wL6nWNWdb+dQP2sVbytrz1eVtrG
// 4VfHK/ixUdlIIwDFNLCoetlk/DuY6JqPzvl6ZQrlCmM=
// -----END CERTIFICATE REQUEST-----

entd.onLoad =
function onLoad(manifest) {
  entd.pkcs11.setUserPin("111111");

  var slot = new entd.pkcs11.SlotObject("test-label");
  slot.generateKeyPair(3, "label");
  var csr = new slot.CSR("/C=US/ST=California/L=Mountain View/O=Google Inc" +
                         "/OU=ChromeOS/CN=user.onex.corp.google.com" +
                         "/emailAddress=user@google.com");

  var str = csr.toString();
  var ary = str.split("\n");
  if (!ary || ary.length < 18)
    throw "Invalid certificate size";

  if (ary[ary.length - 1] == "")
    ary.pop();

  if (ary[0] != "-----BEGIN CERTIFICATE REQUEST-----")
    throw "Invalid certificate start: " + ary[0];

  if (ary[ary.length - 1] != "-----END CERTIFICATE REQUEST-----")
    throw "Invalid certificate end: " + ary[ary.length - 1];

  println("LOOKS OK");
}
