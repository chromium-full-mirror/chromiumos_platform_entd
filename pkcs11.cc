// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "entd/pkcs11.h"

#include <iostream>
#include <map>
#include <string>

#include <base/basictypes.h>
#include <base/logging.h>
#include <base/scoped_ptr.h>
#include <curl/curl.h>

#include "entd/utils.h"

namespace entd {

// class Pkcs11CertificateHandlerLocalFile
// Use local files as a CSR and/or Certificate.
// If either file is undefined, supply some default text.

Pkcs11CertificateHandlerLocalFile::Pkcs11CertificateHandlerLocalFile(
    const std::string& csr, const std::string& cert)
    : csr_filename_(csr), certificate_filename_(cert) {
  if (!csr_filename_.empty())
    LOG(INFO) << "Using local CSR file: " << csr_filename_;
  if (!certificate_filename_.empty())
    LOG(INFO) << "Using local Cert file: " << certificate_filename_;
}

// virtual
std::string Pkcs11CertificateHandlerLocalFile::BuildCSR(
    const std::string& subject) {
  std::string csr;
  if (!csr_filename_.empty())
    csr = utils::ReadFileToUtf8String(csr_filename_);
  if (csr.empty())
    csr =  std::string("<CSR subject=") + subject + " />";
  return csr;
}

// virtual
std::string Pkcs11CertificateHandlerLocalFile::BuildCertificate(
    const std::string& content) {
  std::string cert;
  if (!certificate_filename_.empty())
    cert = utils::ReadFileToUtf8String(certificate_filename_);
  if (cert.empty())
    cert = std::string("<Certificate content=") + content + " />";
  return cert;
}


// Class Pkcs11SlotHandlerInMemory
// Stores the contents of slots in memory, used for testing the interface.
class Pkcs11SlotHandlerInMemory : public Pkcs11SlotHandler {
 private:
  // Forward declarations and private typedefs.
  struct Slot;
  typedef std::map<std::string, Slot*> SlotMap;

 public:
  Pkcs11SlotHandlerInMemory() { }
  virtual bool Initialize() { return true; }

  virtual bool BuildSlotToken(const std::string& label) {
    if (GetSlot(label) != NULL) {
      return false;
    } else {
      AddSlot(label);
      return true;
    }
  }

  // No-op (just save the keyIdentifier)
  virtual bool GenerateKeyPair(const std::string& label,
                               const std::string& keyid) {
    Slot* slot = GetSlot(label);
    if (!slot) {
      LOG(WARNING) << "BuildSlotToken must be called before GenerateKeyPair";
      return false;
    }
    slot->keyIdentifier_ = keyid;
    slot->publicKey_ = "<This is a public key>";
    return true;
  }

  virtual bool AddCertificate(const std::string& label,
                              Certificate* cert) {
    Slot* slot = GetSlot(label);
    if (!slot) {
      LOG(WARNING) << "BuildSlotToken must be called before AddCertificate";
      return false;
    }
    slot->cert_ = cert;
    return true;
  }

  virtual bool RemoveCertificate(const std::string& label) {
    Slot* slot = GetSlot(label);
    if (!slot) {
      LOG(WARNING) << "RemoveCertificate called on nonexistant slot";
      return false;
    }
    slot->cert_ = NULL;
    return true;
  }

  virtual Certificate* GetCertificate(const std::string& label) const {
    const Slot* slot = GetSlot(label);
    if (!slot) {
      LOG(WARNING) << "GetCertificate called on nonexistant slot";
      return NULL;
    }
    return slot->cert_;
  }

  virtual std::string GetKeyIdentifier(const std::string& label) const {
    const Slot* slot = GetSlot(label);
    if (!slot) {
      LOG(WARNING) << "GetKeyIdentifier called on nonexistant slot";
      return NULL;
    }
    return slot->keyIdentifier_;
  }

  virtual std::string GetPublicKey(const std::string& label) const {
    const Slot* slot = GetSlot(label);
    if (!slot) {
      LOG(WARNING) << "GetPublicKey called on nonexistant slot";
      return NULL;
    }
    return slot->publicKey_;
  }

  virtual std::vector<std::string> GetSlots() const {
    std::vector<std::string> slotnames;
    for (SlotMap::const_iterator iter = slots_.begin();
         iter != slots_.end(); ++iter) {
      slotnames.push_back(iter->first);
    }
    return slotnames;
  }

 private:
  struct Slot {
    Slot() : cert_(NULL) {}
    std::string keyIdentifier_;
    std::string publicKey_;
    Certificate* cert_;
  };

  const Slot* GetSlot(const std::string& label) const {
    SlotMap::const_iterator iter = slots_.find(label);
    if (iter == slots_.end())
      return NULL;
    else
      return iter->second;
  }

  Slot* GetSlot(const std::string& label) {
    SlotMap::iterator iter = slots_.find(label);
    if (iter == slots_.end())
      return NULL;
    else
      return iter->second;
  }

  Slot* AddSlot(const std::string& label) {
    SlotMap::iterator iter = slots_.find(label);
    if (iter != slots_.end()) {
      return iter->second;
    } else {
      Slot* slot = new Slot;
      slots_[label] = slot;
      return slot;
    }
  }

  bool RemoveSlot(const std::string& label) {
    SlotMap::iterator iter = slots_.find(label);
    if (iter == slots_.end()) {
      return false;
    } else {
      Slot* slot = iter->second;
      delete slot;
      slots_.erase(iter);
      return true;
    }
  }

  SlotMap slots_;
  DISALLOW_COPY_AND_ASSIGN(Pkcs11SlotHandlerInMemory);
};


// Class CSR
// CSR JavaScript interface wrapper around Pkcs11CertificateHandler.
class CSR : public JSObjectWrapper<CSR> {
 public:
  CSR() { }
  virtual ~CSR() {}

  // JSObjectWrapper Interface
  virtual void ParseConstructorArgs(
      v8::Handle<v8::Object> obj, const v8::Arguments& args);
  static void SetTemplateBindings(
      v8::Handle<v8::ObjectTemplate> template_object);
  static const char* GetClassName() { return "CSR"; }

  // Accessor
  const std::string& request() const { return request_; }

  // Certificate handler management
  static void InitCertificateHandler(Pkcs11CertificateHandler* cert_handler) {
    certificate_handler_ = cert_handler;
  }
  static Pkcs11CertificateHandler* certificate_handler() {
    return certificate_handler_;
  }

 private:
  std::string request_;
  static Pkcs11CertificateHandler* certificate_handler_;

  DISALLOW_COPY_AND_ASSIGN(CSR);
};

// static
Pkcs11CertificateHandler* CSR::certificate_handler_;

// Base64 encoded version of the CSR
static v8::Handle<v8::Value> dispatch_CSRToString(const v8::Arguments& args) {
  CSR* csr = CSR::Unwrap(args.This());
  if (csr == NULL) {
    utils::ThrowV8Exception("Method called on incorrect object type.");
    return v8::False();
  }
  v8::Local<v8::String> res = v8::String::New(csr->request().c_str());
  return res;
}

// static
void CSR::SetTemplateBindings(
    v8::Handle<v8::ObjectTemplate> template_object) {
  template_object->Set(v8::String::NewSymbol("toString"),
                       v8::FunctionTemplate::New(dispatch_CSRToString),
                       v8::ReadOnly);
}

// virtual
void CSR::ParseConstructorArgs(
    v8::Handle<v8::Object> obj, const v8::Arguments& args) {
  if (args.Length() < 1) {
    utils::ThrowV8Exception("Not enough parameters.");
    return;
  }

  // Argument is the subject
  v8::Handle<v8::Value> subject = args[0];
  obj->Set(v8::String::NewSymbol("subject"), subject->ToString());

  // Build the CSR request
  request_ = certificate_handler()->BuildCSR(utils::ValueAsUtf8String(subject));
}


// Class Certificate
// Certificate JavaScript interface wrapper around Pkcs11CertificateHandler.
class Certificate : public JSObjectWrapper<Certificate> {
 public:
  Certificate() {}
  virtual ~Certificate() {}

  // JSObjectWrapper Interface
  virtual void ParseConstructorArgs(
      v8::Handle<v8::Object> obj, const v8::Arguments& args);
  static void SetTemplateBindings(
      v8::Handle<v8::ObjectTemplate> template_object);
  static const char* GetClassName() { return "Certificate"; }

  // Accessor
  const std::string& certificate() const { return certificate_; }

  // Certificate handler management
  static void InitCertificateHandler(Pkcs11CertificateHandler* handler) {
    certificate_handler_ = handler;
  }
  static Pkcs11CertificateHandler* certificate_handler() {
    return certificate_handler_;
  }

 private:
  std::string certificate_;
  static Pkcs11CertificateHandler* certificate_handler_;

  DISALLOW_COPY_AND_ASSIGN(Certificate);
};

// static
Pkcs11CertificateHandler* Certificate::certificate_handler_;

// Base64 encoded version of the Certificate
static v8::Handle<v8::Value> dispatch_CertificateToString(
    const v8::Arguments& args) {
  Certificate* cert = Certificate::Unwrap(args.This());
  v8::Local<v8::String> res = v8::String::New(cert->certificate().c_str());
  return res;
}

// static
void Certificate::SetTemplateBindings(
    v8::Handle<v8::ObjectTemplate> template_object){
  template_object->Set(v8::String::NewSymbol("toString"),
                       v8::FunctionTemplate::New(dispatch_CertificateToString),
                       v8::ReadOnly);
}

// virtual
void Certificate::ParseConstructorArgs(v8::Handle<v8::Object> obj,
                                       const v8::Arguments& args) {
  if (args.Length() < 1) {
    utils::ThrowV8Exception("Not enough parameters.");
    return;
  }
  // Argument is the contents (passed to BuildCertificate)
  v8::Handle<v8::Value> content = args[0];

  // Build the Certificate string
  certificate_ = certificate_handler()->BuildCertificate(
      utils::ValueAsUtf8String(content));

  // Set the 'content' property to the certificate string
  obj->Set(v8::String::NewSymbol("content"),
           v8::String::New(certificate_.c_str()));
}


// Class SlotToken
// SlotToken JavaScript interface wrapper around Pkcs11SlotHandler.
class SlotToken : public JSObjectWrapper<SlotToken> {
 public:
  SlotToken() : slot_handler_(NULL) { }
  virtual ~SlotToken() {}

  // JSObjectWrapper Interface
  virtual void ParseConstructorArgs(
      v8::Handle<v8::Object> obj, const v8::Arguments& args);
  static void SetTemplateBindings(
      v8::Handle<v8::ObjectTemplate> template_object);
  static const char* GetClassName() { return "SlotToken"; }

  // Accessors
  const std::string& label() const { return label_; }
  const std::string& keyIdentifier() const { return keyIdentifier_; }
  std::string publicKey() const {
    return slot_handler()->GetPublicKey(label_);
  }
  Certificate* certificate() const {
    return slot_handler()->GetCertificate(label_);
  }

  // Setter
  const void SetKeyIdentifier(const std::string& id) {
    keyIdentifier_ = id;
  }

  void SetSlotHandler(Pkcs11SlotHandler* slot_handler) {
    slot_handler_ = slot_handler;
  }
  Pkcs11SlotHandler* slot_handler() const { return slot_handler_; }

 private:
  std::string label_;
  std::string keyIdentifier_;
  Pkcs11SlotHandler* slot_handler_;

  DISALLOW_COPY_AND_ASSIGN(SlotToken);
};

static v8::Handle<v8::Value> dispatch_generateKeyPair(
    const v8::Arguments& args) {
  // Get the arguments.
  SlotToken* slot = SlotToken::Unwrap(args.This());
  if (slot == NULL) {
    utils::ThrowV8Exception("Method called on incorrect object type.");
    return v8::False();
  }
  if (args.Length() < 1) {
    utils::ThrowV8Exception("Not enough parameters.");
    return v8::False();
  }

  // Argument is the key identifier
  v8::Handle<v8::Value> v8keyid = args[0];
  slot->obj()->Set(v8::String::NewSymbol("keyIdentifier"), v8keyid->ToString());
  std::string keyid = utils::ValueAsUtf8String(v8keyid);
  slot->SetKeyIdentifier(keyid);

  // Access the slot handler and generate the public/private key pair
  bool res = slot->slot_handler()->GenerateKeyPair(slot->label(), keyid);
  if (!res) {
    LOG(ERROR) << "Unable to build key pair with label: " << keyid;
    return v8::False();
  }

  // Set the JS publicKey property
  v8::Handle<v8::String> v8_public_key =
      v8::String::New(slot->publicKey().c_str());
  slot->obj()->Set(v8::String::NewSymbol("publicKey"), v8_public_key);

  return v8::True();
}

static v8::Handle<v8::Value> dispatch_addCertificate(
    const v8::Arguments& args) {
  // Get the arguments.
  SlotToken* slot = SlotToken::Unwrap(args.This());
  if (slot == NULL) {
    utils::ThrowV8Exception("Method called on incorrect object type.");
    return v8::False();
  }
  if (args.Length() < 1) {
    utils::ThrowV8Exception("Not enough parameters.");
    return v8::False();
  }

  // Argument is the Certificate object.
  Certificate* cert = Certificate::GetFromArg(args, 0);
  if (cert == NULL) {
    utils::ThrowV8Exception(
        "Second argument must be a Certificate object");
    return v8::False();
  }

  // Access the slot handler and add the Certificate
  slot->slot_handler()->AddCertificate(slot->label(), cert);

  // Add the certificate to the JS object
  slot->obj()->Set(v8::String::NewSymbol("certificate"), cert->obj());

  return v8::True();
}

// static
void SlotToken::SetTemplateBindings(
    v8::Handle<v8::ObjectTemplate> template_object) {
  template_object->Set(v8::String::NewSymbol("generateKeyPair"),
                       v8::FunctionTemplate::New(dispatch_generateKeyPair),
                       v8::ReadOnly);
  template_object->Set(v8::String::NewSymbol("CSR"),
                       v8::FunctionTemplate::New(CSR::Construct),
                       v8::ReadOnly);
  template_object->Set(v8::String::NewSymbol("addCertificate"),
                       v8::FunctionTemplate::New(dispatch_addCertificate),
                       v8::ReadOnly);
}

// virtual
void SlotToken::ParseConstructorArgs(
    v8::Handle<v8::Object> obj, const v8::Arguments& args) {
  if (args.Length() < 1) {
    utils::ThrowV8Exception("Not enough parameters.");
    return;
  }

  // Extract the pkcs11 object
  Pkcs11* pkcs11 =
      reinterpret_cast<Pkcs11*>(v8::External::Unwrap(args.Data()));
  if (!pkcs11) {
    utils::ThrowV8Exception("Data argument is not a Pkcs11 object.");
    return;
  }
  SetSlotHandler(pkcs11->slot_handler());

  // Argument is the label; make it ReadOnly so it can not be changed later.
  v8::Handle<v8::String> v8label = args[0]->ToString();
  obj->Set(v8::String::NewSymbol("label"), v8label, v8::ReadOnly);
  label_ = std::string(*v8::String::Utf8Value(v8label));

  // Build the SlotToken
  bool res = pkcs11->slot_handler()->BuildSlotToken(label_);
  if (!res) {
    LOG(ERROR) << "Unable to build slot token with label: " << label_;
    return;
  }

  // Add a this to pkcs11.slots ("slots.{label} = {cert}")
  v8::Local<v8::Value> slotsvalue =
      pkcs11->obj()->Get(v8::String::NewSymbol("slots"));
  if (slotsvalue.IsEmpty() || !slotsvalue->IsObject()) {
    LOG(ERROR) << "'slots' is not an object in pkcs11";
    return;
  }
  v8::Local<v8::Object> slots = v8::Local<v8::Object>::Cast(slotsvalue);
  slots->Set(v8label->ToString(), obj);
}


// Class Pkcs11
Pkcs11::Pkcs11(Pkcs11CertificateHandler* cert_handler,
               Pkcs11SlotHandler* slot_handler)
    : JSObjectWrapper<Pkcs11>(),
      certificate_handler_(cert_handler),
      slot_handler_(slot_handler) {
}

Pkcs11::~Pkcs11() {
  CleanupTemplate();  // We only have one Pkcs11 instance.
}

bool Pkcs11::Initialize() {
  if (slot_handler_.get() == NULL) {
    // Default slot handler
    slot_handler_.reset(new Pkcs11SlotHandlerInMemory());
    slot_handler_->Initialize();
  }
  if (certificate_handler_.get() == NULL) {
    // Default certificate handler.
    certificate_handler_.reset(new Pkcs11CertificateHandlerLocalFile("", ""));
    certificate_handler_->Initialize();
  }
  // The certificate handler may need access to the slot handler
  certificate_handler()->SetSlotHandler(slot_handler());

  // Set up the CSR and Certificate sub-classes with the certificate handler.
  CSR::InitCertificateHandler(certificate_handler());
  Certificate::InitCertificateHandler(certificate_handler());

  // Initialize the pkcs11 template specially
  v8::Handle<v8::FunctionTemplate> t = Pkcs11::GetTemplate();
  v8::Handle<v8::ObjectTemplate> t_obj = t->InstanceTemplate();
  t_obj->Set(v8::String::NewSymbol("SlotToken"),
             v8::FunctionTemplate::New(SlotToken::Construct,
                                       v8::External::Wrap(this)),
             v8::ReadOnly);

  // Build and initialize the V8 object.
  return JSObjectWrapper<Pkcs11>::Initialize();
}

static v8::Handle<v8::Value> dispatch_removeSlotToken(
    const v8::Arguments& args) {
  // Get the arguments.
  Pkcs11* pkcs11 = Pkcs11::Unwrap(args.This());
  if (pkcs11 == NULL) {
    utils::ThrowV8Exception("Method called on incorrect object type.");
    return v8::False();
  }
  if (args.Length() < 1) {
    utils::ThrowV8Exception("Not enough parameters.");
    return v8::False();
  }

  // Argument is a SlotToken object
  SlotToken* slottoken = SlotToken::GetFromArg(args, 0);
  if (!slottoken) {
    utils::ThrowV8Exception("First argument must be a SlotToken.");
    return v8::False();
  }

  // Remove the contents of the slot in the slot handler.
  v8::Local<v8::Value> slotlabel =
      slottoken->obj()->Get(v8::String::NewSymbol("label"));
  std::string label = utils::ValueAsUtf8String(slotlabel);
  pkcs11->slot_handler()->RemoveCertificate(label);

  // Remove the certificate entry from pkcs11.slots ("delete slots.{label}")
  v8::Local<v8::Value> slotsvalue =
      pkcs11->obj()->Get(v8::String::NewSymbol("slots"));
  if (slotsvalue.IsEmpty() || !slotsvalue->IsObject()) {
    LOG(ERROR) << "'slots' is not an object in pkcs11";
    return v8::False();
  }
  v8::Local<v8::Object> slots = v8::Local<v8::Object>::Cast(slotsvalue);
  slots->Delete(slotlabel->ToString());

  return v8::True();
}


// static
void Pkcs11::SetTemplateBindings(
    v8::Handle<v8::ObjectTemplate> template_object) {
  // "SlotToken" gets setup specially in Initialize();
  template_object->Set(v8::String::NewSymbol("Certificate"),
                       v8::FunctionTemplate::New(Certificate::Construct),
                       v8::ReadOnly);
  template_object->Set(v8::String::NewSymbol("remove"),
                       v8::FunctionTemplate::New(dispatch_removeSlotToken),
                       v8::ReadOnly);
  template_object->Set(v8::String::NewSymbol("slots"),
                       v8::Object::New(),
                       v8::ReadOnly);
}

} // namespace entd
