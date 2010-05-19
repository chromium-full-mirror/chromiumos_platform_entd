// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "entd/pkcs11.h"

#include <iostream>
#include <map>
#include <string>
#include <tr1/memory>

#include <base/basictypes.h>
#include <base/file_util.h>
#include <base/logging.h>
#include <base/scoped_ptr.h>
#include <curl/curl.h>

#include "entd/utils.h"

namespace entd {

// Class SlotObject declaration (implementation below)
// SlotObject JavaScript interface wrapper around Pkcs11SlotHandler.
class SlotObject : public JSObjectWrapper<SlotObject> {
 public:
  SlotObject() : slot_handler_(NULL) { }
  virtual ~SlotObject() {}

  virtual bool Initialize();

  // JSObjectWrapper Interface
  virtual void ParseConstructorArgs(
      v8::Handle<v8::Object> obj, const v8::Arguments& args);
  static void SetTemplateBindings(
      v8::Handle<v8::ObjectTemplate> template_object);
  static const char* GetClassName() { return "SlotObject"; }

  // Accessors
  const std::string& label() const { return label_; }
  const std::string& keyIdentifier() const { return key_identifier_; }
  const std::string& passphrase() const { return passphrase_; }
  std::string publicKey() const {
    return slot_handler()->GetPublicKey(label_);
  }
  std::string certificate() const {
    return slot_handler()->GetCertificate(label_);
  }
  Pkcs11SlotHandler* slot_handler() const { return slot_handler_; }

  // Setters
  const void SetKeyIdentifier(const std::string& id) {
    key_identifier_ = id;
  }
  const void SetPassphrase(const std::string& passphrase) {
    passphrase_ = passphrase;
  }
  void SetSlotHandler(Pkcs11SlotHandler* slot_handler) {
    slot_handler_ = slot_handler;
  }

 private:
  std::string label_;
  std::string key_identifier_;
  std::string passphrase_;
  Pkcs11SlotHandler* slot_handler_;

  DISALLOW_COPY_AND_ASSIGN(SlotObject);
};


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
    const std::string& label, const std::string& subject) {
  std::string csr;
  if (!csr_filename_.empty())
    file_util::ReadFileToString(FilePath(csr_filename_), &csr);
  if (csr.empty())
    csr =  std::string("<CSR subject=") + subject + " />";
  return csr;
}

// virtual
std::string Pkcs11CertificateHandlerLocalFile::BuildCertificate(
    const std::string& content) {
  std::string cert;
  if (!certificate_filename_.empty())
    file_util::ReadFileToString(FilePath(certificate_filename_), &cert);
  if (cert.empty())
    cert = std::string("<Certificate content=") + content + " />";
  return cert;
}

// Class Pkcs11CertificateHandlerOpenSsl
// Implements CSR generation using 'system("openssl req...")'.
class Pkcs11CertificateHandlerOpenSsl : public Pkcs11CertificateHandler {
 public:
  Pkcs11CertificateHandlerOpenSsl() {}

  virtual ~Pkcs11CertificateHandlerOpenSsl() {}

  virtual bool Initialize() { return true; }

  virtual std::string BuildCSR(const std::string& label,
                               const std::string& subject) {
    // temporary filenames
    const std::string private_key_filename = "privkey";
    const std::string csr_filename = "csr";

    // Get the passphrase for the private key from the slot handler
    std::string passphrase = slot_handler()->GetPassphrase(label);

    // build the openssl command
    std::string cmd =
        std::string("openssl req -new -batch -newkey rsa:2048 -nodes")
        + " -keyout " + private_key_filename
        + " -subj \"" + subject + "\""
        + " -pubkey -out " + csr_filename;
    if (!passphrase.empty())
      cmd += " -passout pass:" + passphrase;

    // execute the openssl command
    int res = system(cmd.c_str());
    if (res != 0) {
      LOG(WARNING) << "Error executing open ssl command. result = " << res;
    }

    // get the results from the temporary files
    std::string csr_output;
    if (file_util::ReadFileToString(FilePath(csr_filename), &csr_output)) {
      csr_ = GetCertSection(csr_output,
                            "-----BEGIN CERTIFICATE REQUEST-----",
                            "-----END CERTIFICATE REQUEST-----");
      public_key_ = GetCertSection(csr_output,
                                   "-----BEGIN PUBLIC KEY-----",
                                   "-----END PUBLIC KEY-----");
    }
    file_util::ReadFileToString(FilePath(private_key_filename), &private_key_);

    // remove temporary files
    unlink(csr_filename.c_str());
    unlink(private_key_filename.c_str());

    return csr_;
  }

  // Include the private key (encoded with the SlotObject's passphrase)
  // with the certificate so that it can be decoded with the passphrase.
  virtual std::string BuildCertificate(const std::string& content) {
    certificate_ = content + private_key_;
    return certificate_;
  }

 private:
  // Return the substring of 's'
  // starting with 'begin' and ending with 'end' (inclusive)
  std::string GetCertSection(const std::string& s,
                             const std::string& begin,
                             const std::string& end) {
    std::string::size_type idx0 = s.find(begin);
    std::string::size_type idx1 = s.find(end);
    if (idx0 == std::string::npos || idx1 == std::string::npos) {
      LOG(WARNING) << "Unable to find section: ["
                   << begin << ", " << end << "]";
      LOG(WARNING) << "In:\n" << s;
      return std::string();
    }
    return s.substr(idx0, (idx1 + end.length()) - idx0);
  }

  std::string csr_;
  std::string certificate_;
  std::string private_key_;
  std::string public_key_;
};

// Class Pkcs11SlotHandlerInMemory
// Stores the contents of slots in memory, used for testing the interface.
class Pkcs11SlotHandlerInMemory : public Pkcs11SlotHandler {
 private:
  // Forward declarations and private typedefs.
  struct Object;
  typedef std::map<std::string, std::tr1::shared_ptr<Object> > ObjectMap;

 public:
  Pkcs11SlotHandlerInMemory() { }
  virtual bool Initialize() { return true; }

  virtual bool BuildSlotObject(const std::string& label) {
    if (label.empty()) {
      LOG(ERROR) << "BuildSlotObject called with empty label.";
      return false;
    }
    if (GetObject(label) != NULL) {
      LOG(ERROR) << "BuildSlotObject called on existing object: " << label;
      return false;
    } else {
      AddObject(label);
      return true;
    }
  }

  // No-op (just save the key identifier and passphrase)
  virtual bool GenerateKeyPair(const std::string& label,
                               const std::string& keyid,
                               const std::string& passphrase) {
    Object* obj = GetObject(label);
    if (!obj) {
      LOG(WARNING) << "BuildSlotObject must be called before GenerateKeyPair";
      return false;
    }
    obj->key_identifier_ = keyid;
    obj->passphrase_ = passphrase;
    obj->publicKey_ = "<This is a public key>";
    return true;
  }

  virtual bool AddCertificate(const std::string& label,
                              const std::string& cert) {
    Object* obj = GetObject(label);
    if (!obj) {
      LOG(WARNING) << "BuildSlotObject must be called before AddCertificate";
      return false;
    }
    obj->cert_ = cert;
    return true;
  }

  virtual bool RemoveCertificate(const std::string& label) {
    Object* obj = GetObject(label);
    if (!obj) {
      LOG(WARNING) << "RemoveCertificate called on nonexistant object";
      return false;
    }
    obj->cert_.clear();
    return true;
  }

  virtual std::string GetCertificate(const std::string& label) const {
    const Object* obj = GetObject(label);
    if (!obj) {
      LOG(WARNING) << "GetCertificate called on nonexistant object";
      return NULL;
    }
    return obj->cert_;
  }

  virtual std::string GetKeyIdentifier(const std::string& label) const {
    const Object* obj = GetObject(label);
    if (!obj) {
      LOG(WARNING) << "GetKeyIdentifier called on nonexistant object";
      return NULL;
    }
    return obj->key_identifier_;
  }

  virtual std::string GetPassphrase(const std::string& label) const {
    const Object* obj = GetObject(label);
    if (!obj) {
      LOG(WARNING) << "GetPassphrase called on nonexistant object";
      return NULL;
    }
    return obj->passphrase_;
  }

  virtual std::string GetPublicKey(const std::string& label) const {
    const Object* obj = GetObject(label);
    if (!obj) {
      LOG(WARNING) << "GetPublicKey called on nonexistant object";
      return NULL;
    }
    return obj->publicKey_;
  }

  virtual std::vector<std::string> GetObjectNames() const {
    std::vector<std::string> objnames;
    for (ObjectMap::const_iterator iter = objects_.begin();
         iter != objects_.end(); ++iter) {
      objnames.push_back(iter->first);
    }
    return objnames;
  }

 private:
  struct Object {
    std::string key_identifier_;
    std::string passphrase_;
    std::string publicKey_;
    std::string cert_;
  };

  const Object* GetObject(const std::string& label) const {
    ObjectMap::const_iterator iter = objects_.find(label);
    if (iter == objects_.end())
      return NULL;
    else
      return iter->second.get();
  }

  Object* GetObject(const std::string& label) {
    ObjectMap::iterator iter = objects_.find(label);
    if (iter == objects_.end())
      return NULL;
    else
      return iter->second.get();
  }

  Object* AddObject(const std::string& label) {
    ObjectMap::iterator iter = objects_.find(label);
    if (iter != objects_.end()) {
      return iter->second.get();
    } else {
      Object* obj = new Object;
      objects_.insert(std::make_pair(label, obj));
      return obj;
    }
  }

  bool RemoveObject(const std::string& label) {
    ObjectMap::iterator iter = objects_.find(label);
    if (iter == objects_.end()) {
      return false;
    } else {
      objects_.erase(iter);  // Will delete Object
      return true;
    }
  }

  ObjectMap objects_;
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

  // Extract the SlotObject
  SlotObject* slot_object =
      reinterpret_cast<SlotObject*>(v8::External::Unwrap(args.Data()));
  if (!slot_object) {
    utils::ThrowV8Exception("Data argument is not a SlotObject.");
    return;
  }

  // Argument 0 is the subject
  v8::Handle<v8::Value> subject = args[0];
  obj->Set(v8::String::NewSymbol("subject"), subject->ToString());

  // Build the CSR request
  request_ = certificate_handler()->BuildCSR(slot_object->label(),
                                             utils::ValueAsUtf8String(subject));
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


// Class SlotObject Implementation

bool SlotObject::Initialize() {
  // Bind "CSR" here so we can associate this with it
  v8::Handle<v8::FunctionTemplate> t = GetTemplate();
  v8::Handle<v8::ObjectTemplate> t_obj = t->InstanceTemplate();
  t_obj->Set(v8::String::NewSymbol("CSR"),
             v8::FunctionTemplate::New(CSR::Construct,
                                       v8::External::Wrap(this)),
             v8::ReadOnly);

  // Build and initialize the V8 object.
  return JSObjectWrapper<SlotObject>::Initialize();
}

static v8::Handle<v8::Value> dispatch_generateKeyPair(
    const v8::Arguments& args) {
  // Get the arguments.
  SlotObject* slot = SlotObject::Unwrap(args.This());
  if (slot == NULL) {
    utils::ThrowV8Exception("Method called on incorrect object type.");
    return v8::False();
  }
  if (args.Length() < 1) {
    utils::ThrowV8Exception("Not enough parameters.");
    return v8::False();
  }

  // Argument 0 is the key identifier
  v8::Handle<v8::Value> v8keyid = args[0];
  slot->obj()->Set(v8::String::NewSymbol("keyIdentifier"), v8keyid->ToString());
  std::string keyid = utils::ValueAsUtf8String(v8keyid);
  slot->SetKeyIdentifier(keyid);

  // Argumnet 1 is the passphrase (optional)
  std::string passphrase;  // defaults to empty
  if (args.Length() >= 2) {
    passphrase = utils::ValueAsUtf8String(args[1]);
  }
  slot->SetPassphrase(passphrase);

  // Access the slot handler and generate the public/private key pair
  bool res = slot->slot_handler()->GenerateKeyPair(
      slot->label(), keyid, passphrase);
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
  SlotObject* slot = SlotObject::Unwrap(args.This());
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
  slot->slot_handler()->AddCertificate(slot->label(), cert->certificate());

  // Add the certificate to the JS object
  slot->obj()->Set(v8::String::NewSymbol("certificate"), cert->obj());

  return v8::True();
}

// static
void SlotObject::SetTemplateBindings(
    v8::Handle<v8::ObjectTemplate> template_object) {
  // "CSR" is set in Initialize so it can include
  // a pointer back to the SlotObject.
  template_object->Set(v8::String::NewSymbol("generateKeyPair"),
                       v8::FunctionTemplate::New(dispatch_generateKeyPair),
                       v8::ReadOnly);
  template_object->Set(v8::String::NewSymbol("addCertificate"),
                       v8::FunctionTemplate::New(dispatch_addCertificate),
                       v8::ReadOnly);
}

// virtual
void SlotObject::ParseConstructorArgs(
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

  // Build the SlotObject
  bool res = pkcs11->slot_handler()->BuildSlotObject(label_);
  if (!res) {
    LOG(ERROR) << "Unable to build SlotObject with label: " << label_;
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
    certificate_handler_.reset(new Pkcs11CertificateHandlerOpenSsl());
    certificate_handler_->Initialize();
  }
  // The certificate handler may need access to the slot handler
  certificate_handler()->SetSlotHandler(slot_handler());

  // Set up the CSR and Certificate sub-classes with the certificate handler.
  CSR::InitCertificateHandler(certificate_handler());
  Certificate::InitCertificateHandler(certificate_handler());

  // Initialize the pkcs11 template specially
  v8::Handle<v8::FunctionTemplate> t = GetTemplate();
  v8::Handle<v8::ObjectTemplate> t_obj = t->InstanceTemplate();
  t_obj->Set(v8::String::NewSymbol("SlotObject"),
             v8::FunctionTemplate::New(SlotObject::Construct,
                                       v8::External::Wrap(this)),
             v8::ReadOnly);

  // Build and initialize the V8 object.
  return JSObjectWrapper<Pkcs11>::Initialize();
}

static v8::Handle<v8::Value> dispatch_removeSlotObject(
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

  // Argument is a SlotObject object
  SlotObject* slotobject = SlotObject::GetFromArg(args, 0);
  if (!slotobject) {
    utils::ThrowV8Exception("First argument must be a SlotObject.");
    return v8::False();
  }

  // Remove the contents of the slot in the slot handler.
  v8::Local<v8::Value> slotlabel =
      slotobject->obj()->Get(v8::String::NewSymbol("label"));
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
  // "SlotObject" gets setup specially in Initialize();
  template_object->Set(v8::String::NewSymbol("Certificate"),
                       v8::FunctionTemplate::New(Certificate::Construct),
                       v8::ReadOnly);
  template_object->Set(v8::String::NewSymbol("remove"),
                       v8::FunctionTemplate::New(dispatch_removeSlotObject),
                       v8::ReadOnly);
  template_object->Set(v8::String::NewSymbol("slots"),
                       v8::Object::New(),
                       v8::ReadOnly);
}

} // namespace entd
