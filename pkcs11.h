// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ENTD_PKCS11_H_
#define ENTD_PKCS11_H_

#include <string>
#include <vector>

#include <base/basictypes.h>
#include <base/scoped_ptr.h>
#include <chromeos/utility.h>
#include <v8.h>

#include "entd/js_object_wrapper.h"

namespace entd {

class Certificate;
class CSR;
class Pkcs11CertificateHandler;
class Pkcs11SlotHandler;

// Implementation class for interfacing with pkcs11 devices,
// including generation of Certificate Service Requests (CSR)
// with a hidden private key (e.g. stored in a TPM), and
// storage of encrypted Certificates in a device associated
// with a public/private key pair.


// Pure Interface class for defining PKCS11 slot handlers
class Pkcs11SlotHandler {
 public:
  virtual ~Pkcs11SlotHandler() {}
  virtual bool Initialize() = 0;
  virtual bool SetUserPin(const std::string& pin) = 0;
  virtual bool SetKeyIdentifier(const std::string& label,
                                const std::string& keyid) = 0;
  virtual bool BuildSlotObject(const std::string& label) = 0;
  virtual bool GenerateKeyPair(const std::string& label,
                               const std::string& passphrase) = 0;
  virtual bool AddPrivateKey(const std::string& label,
                             const std::string& subject,
                             const chromeos::Blob& key) = 0;
  virtual bool AddCertificate(const std::string& label,
                              const chromeos::Blob& cert,
                              const std::string& subject) = 0;
  virtual bool RemoveObjects(const std::string& label,
                             const std::string& keyid) = 0;
  virtual std::string GetKeyIdentifier(const std::string& label) const = 0;
  virtual std::string GetPassphrase(const std::string& label) const = 0;
  virtual std::string GetPublicKey(const std::string& label) const = 0;
  virtual std::vector<std::string> GetObjectNames() const = 0;
};

// Pure Interface class for defining certificate handlers.
class Pkcs11CertificateHandler {
 public:
  Pkcs11CertificateHandler() : slot_handler_(NULL) {}
  virtual ~Pkcs11CertificateHandler() {}
  virtual bool Initialize() = 0;
  virtual bool BuildCSR(const std::string& label,
                        const std::string& subject,
                        std::string* csr) = 0;
  virtual bool BuildCertificate(const std::string& content,
                                chromeos::Blob* certificate,
                                std::string* subject) = 0;
  // SetSlotHandler() is called from Pkcs11::Initialize with its
  // Pkcs11SlotHandler implementation for the benefit of certificate handlers
  // that need access to the slot handler (e.g. for encryption).
  void SetSlotHandler(Pkcs11SlotHandler* slot_handler) {
    slot_handler_ = slot_handler;
  }
  Pkcs11SlotHandler* slot_handler() { return slot_handler_; }
 private:
  Pkcs11SlotHandler* slot_handler_;
};

// Pkcs11 JavaScript Interface class.
//
// This class wraps a V8 singleton object to handle the PKCS11 interface.
class Pkcs11 : public JSObjectWrapper<Pkcs11> {
 public:
  // The constructor takes two handlers:
  // * cert_handler builds CSRs and certificates.
  // * slot_handler handles the interface with a pkcs11 device:
  //   - generates public/private key pairs
  //   - adds certificates
  //   - retrieves a list of slot labels and the contents of a named slot.
  //
  // If cert_handler is NULL, a Pkcs11CertificateHandlerLocalFile is built,
  // with empty filenames (see below).
  // If slot_handler is NULL, a Pkcs11SlotHandlerInMemory is built
  // (see code).
  Pkcs11(Pkcs11CertificateHandler* cert_handler,
         Pkcs11SlotHandler* slot_handler);
  virtual ~Pkcs11();
  virtual bool Initialize();
  // Call this *instead of* Initialize() to use opencryptoki with openssl
  bool InitializeOpenCryptoki(const std::string& test_cert,
                              const std::string& engine);
  // Call this *instead of* Initialize() to use openssl to generate keys
  // and to store the private key in the tpm (like glaptop does)
  bool InitializeGLaptop(const std::string& test_cert);
  // Call this *instead of* Initialize() to use openssl without opencryptoki
  bool InitializeOpenSSL(const std::string& test_cert);
  // Call this *instead of* Initialize() to use local files
  bool InitializeLocalFiles(const std::string& csr, const std::string& cert);

  // JSObjectWrapper functions
  static const char* GetClassName() { return "pkcs11"; }
  static void SetTemplateBindings(
      v8::Handle<v8::ObjectTemplate> template_object);

  // Accessors for V8 callbacks
  Pkcs11CertificateHandler* certificate_handler() {
    return certificate_handler_.get();
  }
  Pkcs11SlotHandler* slot_handler() {
    return slot_handler_.get();
  }

 private:
  scoped_ptr<Pkcs11CertificateHandler> certificate_handler_;
  scoped_ptr<Pkcs11SlotHandler> slot_handler_;

  DISALLOW_COPY_AND_ASSIGN(Pkcs11);
};

} // namespace entd

#endif // ENTD_PKCS11_H_
