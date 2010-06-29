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
class CertificateHandler;
class SlotHandler;
class SlotObject;
class Pkcs11;

// Implementation class for interfacing with pkcs11 devices,
// including generation of Certificate Service Requests (CSR)
// with a hidden private key (e.g. stored in a TPM), and
// storage of encrypted Certificates in a device associated
// with a public/private key pair.


// Pure Interface class for defining PKCS11 slot handlers
class SlotHandler {
 public:
  virtual ~SlotHandler() {}
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
  virtual bool ReadObjectsFromSlot(Pkcs11* pkcs11) = 0;
  virtual bool RemoveObjects(const std::string& label) = 0;
  virtual std::string GetKeyIdentifier(const std::string& label) const = 0;
  virtual std::string GetPassphrase(const std::string& label) const = 0;
  virtual std::string GetPublicKey(const std::string& label) const = 0;
  virtual std::vector<std::string> GetObjectNames() const = 0;
};

// Pure Interface class for defining certificate handlers.
class CertificateHandler {
 public:
  CertificateHandler() : slot_handler_(NULL) {}
  virtual ~CertificateHandler() {}
  virtual bool Initialize() = 0;
  virtual bool BuildCSR(const std::string& label,
                        const std::string& subject,
                        std::string* csr) = 0;
  virtual bool BuildCertificate(const std::string& content,
                                chromeos::Blob* certificate,
                                std::string* subject) = 0;
  // SetSlotHandler() is called from Pkcs11::Initialize with its
  // SlotHandler implementation for the benefit of certificate handlers
  // that need access to the slot handler (e.g. for encryption).
  void SetSlotHandler(SlotHandler* slot_handler) {
    slot_handler_ = slot_handler;
  }
  SlotHandler* slot_handler() { return slot_handler_; }
 private:
  SlotHandler* slot_handler_;
};

// Pkcs11 JavaScript Interface class.
//
// This class wraps a V8 singleton object to handle the PKCS11 interface.
class Pkcs11 : public JSObjectWrapper<Pkcs11> {
 public:
  Pkcs11();

  virtual ~Pkcs11();

  // Initialize the instance (Must be called before using other methods.)
  //
  // Returns false if initialization fails fatally, in which case you should
  // discard the object.  May return true without fully initializing the
  // object in the case that the requisite crypto libraries fail to
  // initialize.
  //
  // If that happens IsReady() will return false.  You should then
  // invoke InitializeCrypto() later, before invoking any other functions.
  virtual bool Initialize();

  // Initialize the chosen crypto mode.  Returns true if it is able to
  // initialize crypto, false otherwise.  You may call this multiple times.
  // It's a no-op if crypto is already loaded, but will retry initialization
  // if not.
  bool InitializeCrypto();

  // True if the crypto has been properly set up and the object is ready to
  // use.
  bool IsReady() { return handlers_ready_; }

  // Adds slot_object to "pkcs11.slots"
  bool AddJSSlotObject(const SlotObject* slot_object);
  bool RemoveJSSlotObject(const std::string& label);

  // JSObjectWrapper functions
  static const char* GetClassName() { return "pkcs11"; }
  static void SetTemplateBindings(
      v8::Handle<v8::ObjectTemplate> template_object);

  // Accessors for V8 callbacks
  CertificateHandler* certificate_handler() {
    return certificate_handler_.get();
  }

  SlotHandler* slot_handler() {
    return slot_handler_.get();
  }

  // globals
  static bool enable_opencryptoki;

 private:
  scoped_ptr<CertificateHandler> certificate_handler_;
  scoped_ptr<SlotHandler> slot_handler_;

  bool handlers_ready_;

  DISALLOW_COPY_AND_ASSIGN(Pkcs11);
};

} // namespace entd

#endif // ENTD_PKCS11_H_
