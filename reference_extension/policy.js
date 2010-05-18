// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This is a sample policy file for a bogus company.  It shows how to create
// a policy that requests a single certificate to be used to establish
// 802.11x.  Eventually it will also show how to configure the network to use
// that policy.

var policy = null;

entd.onLoad =
function onLoad(manifest) {
  // Instantiate our policy.  The Policy object is defined by policy-utils.js,
  // which should be located in the same directory as this file.
  policy = new Policy(manifest || {});

  // Set up some certs we might be interested in.  We don't automatically set
  // these up, this is only the menu of certs that can be mentioned in the
  // manifest file.  The list of certs we set up is stored in
  // the array located at manifest.policyParams.certs.  The array
  // should contain a list of "local identifiers" as defined below.
  policy.addCertificate(
      // Local identifier for the certificate, not persisted to the TPM
      "wifi",
      { // Human readable label associated with this cert in the TPM
        label: "802.11x Wireless",

        // This function will be called when the certificate is successfully
        // installed.
        "onInstall": util.fwdp(policy, "onWifiCertInstalled"),

        // The pkcs#11 slot id to store the cert in.
        pkcs11slot: "1",

        // List of variables that the user may provide.  Value is a list of
        // attributes that will be used to render the input widget for
        // the variable.
        userVariables: {
          password: { type: "password", label: "Password" }
        },

        // Parameters for the "Certificate Signing Request" request.
        csr: {
          subject: "/C=US/ST=Texas/L=Dallas/O=Example Inc/" +
              "OU=pcloadletter/CN=%(userName).corp.example.com/" +
              "emailAddress=%(userEmail)",

          // Used to build the URL where we should send the CSR.
          host: "localhost",
          port: 4343,
          auth: "%(userName):%(password)",
          path: "/csr",

          // HTTP POST parameters to use when submitting the request.
          post_params: {
            CertRequest: "%(csr)",
            CertAttribute: "CertificateTemplate:Wireless802.1xUser",
            email: "%(userEmail)",
            SAN: "upn=%(userName)@corp.example.com",
          },
        },

        issuer: {
          // Used to build the URL where we should present the CSR in order
          // to get the cert.
          host: "localhost",
          port: 4343,
          auth: "%(userName):%(password)",
          path: "/issue?id=%(requestId)",
        }
      });

  policy.addCertificate(
      "vpn",
      { // Human readable label associated with this cert in the TPM
        label: "Virtual Private Network (VPN)",

        // The pkcs#11 slot id to store the cert in.
        pkcs11slot: "2",

        // List of variables that the user may provide.  Value is a list of
        // attributes that will be used to render the input widget for
        // the variable.
        userVariables: {
          password: { type: "password", label: "Password" }
        },

        // Parameters for the "Certificate Signing Request" request.
        csr: {
          subject: "/C=US/ST=Texas/L=Dallas/O=Example Inc/" +
              "OU=pcloadletter/CN=%(userName).corp.example.com/" +
              "emailAddress=%(userEmail)",

          // Used to build the URL where we should send the CSR.
          host: "localhost",
          port: 4343,
          auth: "%(userName):%(password)",
          path: "/csr",

          // HTTP POST parameters to use when submitting the request.
          post_params: {
            CertRequest: "%(csr)",
            CertAttribute: "CertificateTemplate:VPNUser",
            email: "%(userEmail)",
            SAN: "upn=%(userName)@corp.example.com",
          },
        },

        issuer: {
          // Used to build the URL where we should present the CSR in order
          // to get the cert.
          host: "localhost",
          port: 4343,
          auth: "%(userName):%(password)",
          path: "/issue?id=%(requestId)",
        }
      });

  entd.callbackServer.start(policy.callbacks);
}

// Called when entd stops for any reason.  You might perform some cleanup like
// unconfiguring wireless networks here.
entd.onUnload =
function onUnload() {
  entd.syslog.info("onUnload called.");
}

// This function will be called after a successful CSR request.  It should
// inspect the repsponse (most likely response.content) and extract any
// variables that might be needed to form the certificate issue request.
Policy.Certificate.prototype.parseCSR =
function parseCSR(response) {
  // Scrape the result looking for a ReqID...
  var ary = response.content.match(/\WReqID=([^&]+)/i);
  if (!ary)
    throw "Unable to locate request id in CSR reply.";

  this.info("Parsed request id: " + ary[1]);
  this.setVariable("requestId", ary[1]);
}

// Called when the wifi certificate is successfully installed for the first
// time, and every time entd starts up and notices that this certificate has
// already been installed.  If the firstInstall parameter is true, then
// this is the first time the certificate has been installed.
//
// This is hooked up in the addCertificate() call above.
Policy.prototype.onWifiCertInstalled =
function onWifiCertInstalled(cert, firstInstall) {
  entd.syslog.info("onWifiCertInstalled called: firstInstall: " + firstInstall);

  // This is where you might make use of the recently acquired certificate
  // to set up a network.
}
