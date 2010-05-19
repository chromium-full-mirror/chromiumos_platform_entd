// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ENTD_PKCS11_H_
#define ENTD_PKCS11_H_

#include <string>
#include <vector>

#include <base/basictypes.h>
#include <base/scoped_ptr.h>
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
  virtual bool BuildSlotObject(const std::string& label) = 0;
  virtual bool GenerateKeyPair(const std::string& label,
                               const std::string& keyid,
                               const std::string& passphrase) = 0;
  virtual bool AddCertificate(const std::string& label,
                              const std::string& cert) = 0;
  virtual bool RemoveCertificate(const std::string& label) = 0;
  virtual std::string GetCertificate(const std::string& label) const = 0;
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
  virtual std::string BuildCSR(const std::string& label,
                               const std::string& subject) = 0;
  virtual std::string BuildCertificate(const std::string& content) = 0;
  // InitSlotHandler() is called from Pkcs11::Initialize with its
  // Pkcs11SlotHandler implementation for the benefit of certificate handlers
  // that need access to the slot handler (e.g. for encryption).
  void SetSlotHandler(Pkcs11SlotHandler* slot_handler) {
    slot_handler_ = slot_handler;
  }
  Pkcs11SlotHandler* slot_handler() { return slot_handler_; }
 private:
  Pkcs11SlotHandler* slot_handler_;
};

// Test Certificate handler that returns the contents of a file.
//
// If the csr or cert file exists, the contents of the file is returned
// in BuildCSR or BuildCertificate; subject or content arguments are ignored.
// If the filename is empty or the file does not exist, a string
// containing the subject or content is returned instead.
class Pkcs11CertificateHandlerLocalFile : public Pkcs11CertificateHandler {
 public:
  Pkcs11CertificateHandlerLocalFile(const std::string& csr,
                                 const std::string& cert);
  virtual ~Pkcs11CertificateHandlerLocalFile() {}
  virtual bool Initialize() { return true; }
  virtual std::string BuildCSR(const std::string& label,
                               const std::string& subject);
  virtual std::string BuildCertificate(const std::string& content);
 private:
  std::string csr_filename_;
  std::string certificate_filename_;
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
