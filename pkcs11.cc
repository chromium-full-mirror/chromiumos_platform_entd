// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "entd/pkcs11.h"

#include <algorithm>
#include <iostream>
#include <map>
#include <string>
#include <tr1/memory>

#include <base/basictypes.h>
#include <base/file_util.h>
#include <base/logging.h>
#include <base/scoped_ptr.h>
#include <chromeos/utility.h>
#include <curl/curl.h>
#include <opencryptoki/pkcs11.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include "entd/utils.h"

namespace entd {

// Class SlotObject declaration (implementation below)
// SlotObject JavaScript interface wrapper around Pkcs11SlotHandler.
class SlotObject : public JSObjectWrapper<SlotObject> {
 public:
  SlotObject() : slot_handler_(NULL) {}
  SlotObject(const std::string& label, const std::string& key_id)
      : label_(label), key_identifier_(key_id), slot_handler_(NULL) {}
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
  const std::string& key_identifier() const { return key_identifier_; }
  const std::string& passphrase() const { return passphrase_; }
  std::string GetPublicKey() const {
    return slot_handler()->GetPublicKey(label_);
  }
  Pkcs11SlotHandler* slot_handler() const { return slot_handler_; }

  // Setters

  // Stores the key identifier and passes it to the slot handler.
  bool SetKeyIdentifier(const std::string& id) {
    key_identifier_ = id;
    return slot_handler_->SetKeyIdentifier(label_, id);
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

// Class Certificate declaration (implementation below)
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

  // Accessors
  const chromeos::Blob& certificate() const { return certificate_; }
  const std::string& subject() const { return subject_; }

  // Certificate handler management
  static void InitCertificateHandler(Pkcs11CertificateHandler* handler) {
    certificate_handler_ = handler;
  }
  static Pkcs11CertificateHandler* certificate_handler() {
    return certificate_handler_;
  }

 private:
  // The certificate may contain binary data, so store it as an array of bytes
  // instead of a string.
  chromeos::Blob certificate_;
  std::string subject_;
  static Pkcs11CertificateHandler* certificate_handler_;

  DISALLOW_COPY_AND_ASSIGN(Certificate);
};

// class Pkcs11TestCertificateHandler
// Test Certificate handler
class Pkcs11TestCertificateHandler : public Pkcs11CertificateHandler {
 public:
  Pkcs11TestCertificateHandler() {}
  virtual ~Pkcs11TestCertificateHandler() {}
  virtual bool Initialize() { return true; }

  virtual bool BuildCSR(const std::string& label,
                        const std::string& subject,
                        std::string* csr) {
    // Use the subject as the CSR string.
    *csr = subject;
    return true;
  }

  virtual bool BuildCertificate(const std::string& content,
                                chromeos::Blob* certificate,
                                std::string* subject) {
    // Use the unmodified content for the certificate.
    certificate->resize(content.length());
    memcpy(&(certificate->front()), content.c_str(), content.length());
    *subject = "Test";

    return true;
  }

 private:
  DISALLOW_COPY_AND_ASSIGN(Pkcs11TestCertificateHandler);
};

// Class Pkcs11CertificateHandlerLibOpenSsl
// Implements CSR generation using the openssl crypto library
class Pkcs11CertificateHandlerLibOpenSsl : public Pkcs11CertificateHandler {
 public:
  Pkcs11CertificateHandlerLibOpenSsl() {}

  virtual ~Pkcs11CertificateHandlerLibOpenSsl() {}

  virtual bool Initialize() { return true; }

  virtual bool BuildCSR(const std::string& label,
                        const std::string& subject,
                        std::string* csr) {
    LOG(INFO) << "Generating CSR.";

    // Equivalent to:
    // openssl req -new -batch -newkey rsa:2048 -subj {subject}
    // -keyout {private_key} -pubkey -out {csr}
    // -passout pass:{passphrase}

    // Generate a private key in DER format and pass it to the slot handler
    EVP_PKEY* pkey = EVP_PKEY_new();
    RSA* rsa = NULL;  // NOTE: This gets freed with pkey
    bool res = pkey && GeneratePrivateKey(pkey, &rsa)
        && rsa && PrivateKeyToDER(rsa, &private_key_der_);

    if (!res) {
      LOG(ERROR) << "Error generating RSA key.";
      EVP_PKEY_free(pkey);
      return false;
    }

    // Generate a CSR request using the private key
    X509_REQ* req = X509_REQ_new();
    res = req && SetX509Req(pkey, subject, req);

    EVP_PKEY_free(pkey);

    if (!res) {
      LOG(ERROR) << "Error generating X509 Request.";
      X509_REQ_free(req);
      return false;
    }

    // Extract the CSR and Public Key components in PEM format
    res = X509ReqPublicKeyToPEM(req, &public_key_)
        && X509ReqToPEM(req, &csr_);

    X509_REQ_free(req);

    if (!res) {
      LOG(ERROR) << "Error extracting data from X509 Request.";
      return false;
    }

    // Store the private key in the slot handler (e.g. TPM device)
    if (!slot_handler()->AddPrivateKey(label, subject, private_key_der_))
      return false;

    *csr = csr_;

    return true;
  }

  virtual bool BuildCertificate(const std::string& content,
                                chromeos::Blob* certificate,
                                std::string* subject) {
    LOG(INFO) << "Building Certificate.";

    // Equivalent to:
    // openssl x509 -inform PEM -in content -outform DER -subject subject
    if (content.empty()) {
      LOG(ERROR) << "BuildCertificate called with empty content";
      return false;
    }

    // Convert 'content' to a DER Blob and extract the subject
    X509* cert = NULL;
    bool res = X509CertificateToDER(content, &cert, certificate)
        && X509CertificateToSubject(cert, subject);
    X509_free(cert);

    if (!res) {
      LOG(ERROR) << "Error in X509 Certificate parsing.";
      return false;
    }

    return true;
  }

 private:
  // Utility class and functions for interfacing with the openssl BIO interface

  // BioMem allocates an in-memory BIO instance and frees it on destruction.
  class BioMem {
   public:
    static BioMem* Create() {
      BioMem* biomem = new BioMem();
      if (!biomem || !biomem->InitBio()) {
        LOG(ERROR) << "Error initializing BIO";
        delete biomem;
        return NULL;
      }
      return biomem;
    }
    static BioMem* CreateFromString(const std::string& data) {
      BioMem* biomem = new BioMem();
      if (!biomem || !biomem->InitBioFromString(data)) {
        LOG(ERROR) << "Error initializing BIO from string";
        delete biomem;
        return NULL;
      }
      return biomem;
    }
    ~BioMem() {
      BIO_free(bio_);
    }
    // Extract a std::string from the BIO instance
    bool GetBIOString(std::string* str) {
      char* mem = 0;
      long bytes = BIO_get_mem_data(bio(), &mem);
      if (bytes == 0 || !mem) {
        return false;
      }
      *str = std::string(mem, mem + bytes);
      return true;
    }

    // Extract a Blob from the BIO instance
    bool GetBIOBlob(chromeos::Blob* der) {
      char* mem = 0;
      long bytes = BIO_get_mem_data(bio(), &mem);
      if (bytes == 0 || !mem) {
        return false;
      }
      unsigned char* umem = reinterpret_cast<unsigned char*>(mem);
      *der = chromeos::Blob(umem, umem + bytes);
      return true;
    }
    BIO* bio() const { return bio_; }
   private:
    BioMem() : bio_(NULL) {};
    // The default init is typically used to receive then extract data
    bool InitBio() {
      bio_ = BIO_new(BIO_s_mem());
      return (bio_ != NULL);
    }
    // The string init creates a BIO instance with the string contents
    // to pass to openssl functions
    bool InitBioFromString(const std::string& data) {
      char* bytes = const_cast<char*>(data.c_str());
      bio_ = BIO_new_mem_buf(bytes, data.size());
      return (bio_ != NULL);
    }
    BIO* bio_;
  };

  // Private key related functions.

  bool GeneratePrivateKey(EVP_PKEY* pkey, RSA** rsap) {
    // Get the default RAND file name from the crypto library (~/.rnd)
    char rand_file_name[kMaxFilePath];
    if (RAND_file_name(rand_file_name, kMaxFilePath) == NULL)
      return false;
    // Expand the filename ($USERNAME -> user)
    std::string rand_file_name_exp = utils::ExpandFilePath(rand_file_name);

    // First try to load the filename returned.
    // If that fails (e.g. it doesn't exist), use /dev/urandom
    if (RAND_load_file(rand_file_name_exp.c_str(), -1) == 0) {
      const char* urandom_filename = "/dev/urandom";
      LOG(WARNING) << "Unable to load RAND file: " << rand_file_name_exp
                   << " trying " << urandom_filename;
      if (RAND_load_file(urandom_filename, -1) == 0) {
        LOG(ERROR) << "Unable to load " << urandom_filename;
        return false;
      }
    }

    // Generate the RSA key and an EVP_PKEY wrapper
    RSA* rsa = RSA_generate_key(kRsaKeyLength, kRsaKeyExponent, NULL, NULL);
    if (!rsa)
      return false;
    if (!EVP_PKEY_assign_RSA(pkey, rsa)) {
      RSA_free(rsa);  // rsa won't be freed with pkey if assign failed.
      return false;
    }

    // Write to the RAND file
    LOG(INFO) << "Writing to RAND file: " << rand_file_name_exp;
    if (RAND_write_file(rand_file_name_exp.c_str()) == 0) {
      LOG(ERROR) << "Unable to write to RAND file: " << rand_file_name_exp;
      return false;
    }

    *rsap = rsa;

    return true;
  }

  bool PrivateKeyToDER(RSA* rsa, chromeos::Blob* der) {
    scoped_ptr<BioMem> bio_mem(BioMem::Create());
    if (!bio_mem.get())
      return false;
    bool res = i2d_RSAPrivateKey_bio(bio_mem->bio(), rsa)
        && bio_mem->GetBIOBlob(der);
    return res;
  }

  // X509 Request generation helper functions

  // Find the first instance of 'c' in string 's', skipping over escape
  // sequences (e.g if c == '/' skip '\/')
  std::string::size_type FindUnescaped(const std::string& s,
                                       char c,
                                       std::string::size_type start) {
    if (start >= s.length())
      return std::string::npos;
    for (std::string::const_iterator iter = s.begin() + start;
         iter != s.end(); ++iter) {
      char c1 = *iter;
      if (c1 == '\\') {
        ++iter;  // skip the '\', the loop will skip the next char
        if (iter == s.end())
          break;
      } else {
        if (c1 == c)
          return iter - s.begin();
      }
    }
    return std::string::npos;
  }

  // Custom tokenizer that handles escaped characters
  // Sample subject:
  // /C=US/ST=SF\/California/emailAddress=user@google.com"

  // Parse the subject and add the name/type pairs to an X509_NAME.
  bool ParseSubject(const std::string& subject, X509_NAME* name) {
    if (subject.empty())
      return false;

    std::string::size_type start = 0;
    while (start != std::string::npos) {
      if (subject[start] != '/') {
        LOG(ERROR) << "Subject must start with '/'";
        return false;
      }
      ++start;  // skip leading '/'

      // Find the next '/' (or npos to indicate the end of the string)
      std::string::size_type end = FindUnescaped(subject, '/', start);

      // Build the token amd split it at '=' into type/value
      std::string token;
      if (end == std::string::npos)
        token = subject.substr(start);
      else
        token = subject.substr(start, end - start);
      if (token.empty()) {
        LOG(ERROR) << "Subject contains an invalid entry at: " << start;
        return false;
      }
      std::string::size_type eq = FindUnescaped(token, '=', 0);
      if (eq == std::string::npos) {
        LOG(ERROR) << "Subject entry is missing '=': '" << token << "'";
        return false;
      }
      std::string type = token.substr(0, eq);
      std::string value = token.substr(eq+1);

      if (type.length() == 0) {
        LOG(ERROR) << "Subject entry has no type: '" << token << "'";
        return false;
      }

      // Add the type/value pair to the X509_NAME
      const unsigned char* bytes =
          reinterpret_cast<const unsigned char*>(value.c_str());
      if (!X509_NAME_add_entry_by_txt(name, type.c_str(), MBSTRING_ASC,
                                      bytes, value.size(), -1, 0)) {
        return false;
      }

      start = end;  // start at next '/' (or npos)
    }

    return true;
  }

  // X509 Request functions

  bool SetX509Req(EVP_PKEY* pkey, const std::string& subject,
                  X509_REQ* req) {
    if (!X509_REQ_set_version(req, 0L))  // version 1
      return false;
    X509_NAME* name = X509_NAME_new();
    if (!name)
      return false;
    bool res = ParseSubject(subject, name)
        && X509_REQ_set_subject_name(req, name)
        && X509_REQ_set_pubkey(req, pkey)
        && X509_REQ_sign(req, pkey, EVP_sha1());
    X509_NAME_free(name);
    return res;
  }

  bool X509ReqPublicKeyToPEM(X509_REQ* req, std::string* pub_key_str) {
    scoped_ptr<BioMem> bio_mem(BioMem::Create());
    if (!bio_mem.get())
      return false;
    EVP_PKEY* pub_key = X509_REQ_get_pubkey(req);
    if (!pub_key)
      return false;
    bool res = PEM_write_bio_PUBKEY(bio_mem->bio(), pub_key)
        &&  bio_mem->GetBIOString(pub_key_str);
    EVP_PKEY_free(pub_key);
    return res;
  }

  bool X509ReqToPEM(X509_REQ* req, std::string* req_str) {
    scoped_ptr<BioMem> bio_mem (BioMem::Create());
    if (!bio_mem.get())
      return false;
    bool res = PEM_write_bio_X509_REQ(bio_mem->bio(), req)
        && bio_mem->GetBIOString(req_str);
    return res;
  }

  // X509 Certificte functions

  bool X509CertificateToDER(const std::string& content,
                          X509** cert, chromeos::Blob* der) {
    scoped_ptr<BioMem> bio_content(BioMem::CreateFromString(content));
    if (!bio_content.get())
      return false;
    bool res = PEM_read_bio_X509(bio_content->bio(), cert, NULL, NULL);
    if (!res)
      return false;
    scoped_ptr<BioMem> bio_cert(BioMem::Create());
    if (!bio_cert.get())
      return false;
    res = i2d_X509_bio(bio_cert->bio(), *cert)
        && bio_cert->GetBIOBlob(der);
    return res;
  }

  bool X509CertificateToSubject(X509* cert, std::string* subject) {
    X509_NAME* name = X509_get_subject_name(cert);
    const int NAME_BUF_LEN = 1024;
    char name_buf[NAME_BUF_LEN];
    if (!X509_NAME_oneline(name, name_buf, NAME_BUF_LEN))
      return false;
    subject->assign(name_buf);
    return true;
  }

  static const long kRsaKeyLength;
  static const long kRsaKeyExponent;
  static const long kMaxFilePath;

  std::string csr_;
  std::string certificate_;
  std::string public_key_;
  chromeos::Blob private_key_der_;

  DISALLOW_COPY_AND_ASSIGN(Pkcs11CertificateHandlerLibOpenSsl);
};

// Use 2048 bits for the key length, and an exponent of 0x10001.
const long Pkcs11CertificateHandlerLibOpenSsl::kRsaKeyLength = 2048;
const long Pkcs11CertificateHandlerLibOpenSsl::kRsaKeyExponent = 0x10001;
// Max number of chars for local array allocation for file paths.
const long Pkcs11CertificateHandlerLibOpenSsl::kMaxFilePath = 1024;


// Class Pkcs11SlotHandlerInMemory
// Stores the contents of slots in memory, used for testing the interface.
class Pkcs11SlotHandlerInMemory : public Pkcs11SlotHandler {
 protected:
  // Forward declarations and typedefs.
  struct Object;
  typedef std::map<std::string, std::tr1::shared_ptr<Object> > ObjectMap;

 public:
  Pkcs11SlotHandlerInMemory() { }
  virtual bool Initialize() { return true; }

  virtual bool SetUserPin(const std::string& pin) { return true; }

  virtual bool SetKeyIdentifier(const std::string& label,
                                const std::string& keyid) {
    Object* obj = GetObject(label);
    if (!obj) {
      LOG(WARNING) << "BuildSlotObject must be called before SetKeyIdentifier";
      return false;
    }
    obj->key_identifier_ = keyid;
    return true;
  }

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
                               const std::string& passphrase) {
    Object* obj = GetObject(label);
    if (!obj) {
      LOG(WARNING) << "BuildSlotObject must be called before GenerateKeyPair";
      return false;
    }
    obj->passphrase_ = passphrase;
    obj->public_key_ = "<This is a public key>";
    return true;
  }

  virtual bool AddCertificate(const std::string& label,
                              const chromeos::Blob& cert,
                              const std::string& subject) {
    Object* obj = GetObject(label);
    if (!obj) {
      LOG(WARNING) << "BuildSlotObject must be called before AddCertificate";
      return false;
    }
    obj->subject_ = subject;
    obj->cert_ = cert;
    return true;
  }

  virtual bool AddPrivateKey(const std::string& label,
                             const std::string& subject,
                             const chromeos::Blob& key) {
    // Don't store the private key in memory
    return true;
  }

  virtual bool RemoveObjects(const std::string& label) {
    DeleteObject(label);
    return true;
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
    return obj->public_key_;
  }

  virtual std::vector<std::string> GetObjectNames() const {
    std::vector<std::string> objnames;
    for (ObjectMap::const_iterator iter = objects_.begin();
         iter != objects_.end(); ++iter) {
      objnames.push_back(iter->first);
    }
    return objnames;
  }

 protected:
  struct Object {
    Object(const std::string& label) : label_(label) {}
    std::string label_;
    std::string key_identifier_;
    std::string passphrase_;
    std::string subject_;
    std::string public_key_;
    chromeos::Blob cert_;
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
      Object* obj = new Object(label);
      objects_.insert(std::make_pair(label, obj));
      return obj;
    }
  }

  bool DeleteObject(const std::string& label) {
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


// Class Pkcs11SlotHandlerOpenCryptoki
// Inherits from Pkcs11SlotHandlerInMemory to share memory mapping of objects
class Pkcs11SlotHandlerOpenCryptoki : public Pkcs11SlotHandlerInMemory {
 public:
  Pkcs11SlotHandlerOpenCryptoki()
      : user_pin_(""), slot_index_(0), slot_id_(0) { }

  ~Pkcs11SlotHandlerOpenCryptoki() {
    C_Finalize(NULL);
  }

  virtual bool Initialize() {
    CK_RV rv;

    // Initialize opencryptoki
    rv = C_Initialize(NULL);
    if (rv != CKR_OK) {
      // Note: This will happen if pkcs11_startup has not been started.
      LOG(ERROR) << "C_Initialize failed: " << rv;
      return false;
    }

    CK_ULONG num_slots = 0;
    CK_SLOT_ID_PTR slot_list = NULL;

    // Get the list of slots
    // The first call to C_GetSlotList fills in the number of slots.
    rv = C_GetSlotList(0, NULL, &num_slots);
    if (rv != CKR_OK) {
      LOG(ERROR) << "C_GetSlotList(&num_slots) failed: " << rv;
      return false;
    }
    if (num_slots == 0) {
      LOG(ERROR) << "C_GetSlotList: 0 slots.";
      return false;
    }

    slot_list = static_cast<CK_SLOT_ID_PTR>(
        malloc(num_slots * sizeof (CK_SLOT_ID)));
    if (slot_list == NULL) {
      LOG(ERROR) << "Unable to allocate slots: " << num_slots;
      return false;
    }

    // The second call to C_GetSlotList fills in the actual slot info.
    rv = C_GetSlotList(0, slot_list, &num_slots);
    if (rv != CKR_OK) {
      LOG(ERROR) << "C_GetSlotList(&slot_list) failed. rv=" << rv
                 << " num_slots=" << num_slots;
      free(slot_list);
      return false;
    }

    // Find a valid slot
    slot_index_ = num_slots;
    CK_MECHANISM_TYPE x509_mech_type = CKM_RSA_X_509;
    CK_MECHANISM_INFO mech_info;
    for (CK_ULONG i = 0; i < num_slots; ++i) {
      CK_SLOT_ID slot_id = slot_list[i];
      CK_TOKEN_INFO info;

      rv = C_GetTokenInfo(i, &info);
      if (rv != CKR_OK) {
        LOG(INFO) << "Slot " << i << ": C_GetTokenInfo failed: " << rv;
        continue;
      }
      // Skip any slots that can't handle RSA X.509 certificates.
      if (C_GetMechanismInfo(slot_id, x509_mech_type, &mech_info) != CKR_OK) {
        LOG(INFO) << "Slot " << i << ": C_GetMechanismInfo failed: " << rv;
        continue;
      }
      // TODO (stevenjb):
      // Here is where we would check any criteria other than support for x509.
      // if ((mech_info.flags & CKF_HW) == 0) {
      //   LOG(INFO) << "Slot " << i << ": is not a hardware device, skipping.";
      //   continue;
      // }

      std::string label = std::string(reinterpret_cast<char*>(info.label));
      std::string::size_type labeln = label.find_last_not_of(' ');
      if (labeln != std::string::npos) ++labeln;
      label = label.substr(0, labeln);
      if (slot_index_ == num_slots) {
        slot_index_ = i;
        slot_id_ = slot_id;
        LOG(INFO) << "*Slot " << i << ": '" << label << "'";
      } else {
        break;  // Use the first valid slot we find
      }
    }

    bool res;
    if (slot_index_ == num_slots) {
      LOG(ERROR) << "Pkcs11SlotHandlerOpenCryptoki Faied to find a valid slot.";
      res = false;
    } else {
      LOG(INFO) << "Pkcs11SlotHandlerOpenCryptoki Initialized. Using slot: "
                << slot_index_;
      res = true;
    }

    free(slot_list);
    if (res) {
      res = Pkcs11SlotHandlerInMemory::Initialize();
    }

    return res;
  }

  bool ReadObjectsFromSlot(Pkcs11* pkcs11) {
    CK_SESSION_HANDLE session_handle = NULL;
    CK_RV rv = C_OpenSession(slot_id_,
                             CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL, NULL,
                             &session_handle);
    if (rv != CKR_OK) {
      LOG(ERROR) << "C_OpenSession failed, error: " << rv
                 << ", slot: " << slot_index_;
      return false;
    }

    // Gather a list of objects in the slot
    int num_objects = 0;

    rv = C_FindObjectsInit(session_handle, NULL, 0);
    if (rv != CKR_OK) {
      LOG(ERROR) << "C_FindObjectsInit failed: " << rv;
      C_CloseSession(session_handle);
      return false;
    }

    while (1) {
      CK_ULONG count;
      CK_OBJECT_HANDLE object;
      rv = C_FindObjects(session_handle, &object, 1, &count);
      if (rv != CKR_OK) {
        LOG(ERROR) << "C_FindObjects failed: " << rv;
        C_CloseSession(session_handle);
        return false;
      }
      if (count == 0) {
        // No more objects to read, exit loop.
        break;
      }
      ++num_objects;

      const size_t LABEL_MAX_LENGTH = 256;
      const size_t IDSTR_MAX_LENGTH = 8;
      const size_t SUBJECT_MAX_LENGTH = 1024;

      // Define a template with the values we are interested in
      CK_OBJECT_CLASS obj_class;
      char obj_label[LABEL_MAX_LENGTH];
      CK_BYTE idstr[IDSTR_MAX_LENGTH];
      CK_BYTE subject[SUBJECT_MAX_LENGTH];

      CK_ATTRIBUTE obj_template[] = {
        { CKA_CLASS, &obj_class, sizeof(obj_class) },
        { CKA_LABEL, obj_label, LABEL_MAX_LENGTH },
        { CKA_ID, idstr, IDSTR_MAX_LENGTH },
        { CKA_SUBJECT, subject, SUBJECT_MAX_LENGTH },
      };
      int n_attr = sizeof(obj_template) / sizeof(CK_ATTRIBUTE);

      // Read values into obj_template
      rv = C_GetAttributeValue(session_handle, object, obj_template, n_attr);
      if (rv != CKR_OK) {
        LOG(ERROR) << "C_GetAttributeValue failed: " << rv
                   << " obj: " << num_objects;
      }
      obj_class = *(static_cast<CK_OBJECT_CLASS*>(obj_template[0].pValue));
      if (obj_class == CKO_CERTIFICATE ||
          obj_class == CKO_PUBLIC_KEY ||
          obj_class == CKO_PRIVATE_KEY) {
        if (obj_template[1].ulValueLen > 0) {
          // Only parse certificate and key objects with a valid label
          std::string label = TemplateToString(obj_template[1]);
          std::string idstr = GetKeyFromId(
              static_cast<CK_BYTE*>(obj_template[2].pValue),
              obj_template[2].ulValueLen);
          std::string subject = TemplateToString(obj_template[3]);
          Object* obj = AddObject(label);
          if (!obj->key_identifier_.empty() && obj->key_identifier_ != idstr) {
            LOG(WARNING) << "Object '" << label << "' "
                         << "with mismatched key identifers: "
                         << "'" << obj->key_identifier_ << "'"
                         << " != '" << idstr << "'";
          } else {
            obj->key_identifier_ = idstr;
            obj->subject_ = subject;
          }
        }
      }
    }

    C_FindObjectsFinal(session_handle);

    LOG(INFO) << "Found " << num_objects << " distinct objects in slot.";

    // Iterate through the list of objects and generate
    // SlotObject objects and insert them into pkcs11.slots.
    for (ObjectMap::iterator iter = objects_.begin();
         iter != objects_.end(); ++iter) {
      Object* object = iter->second.get();

      // Build a slot object
      SlotObject* slot_object = new SlotObject(object->label_,
                                               object->key_identifier_);
      slot_object->Initialize();
      slot_object->SetSlotHandler(pkcs11->slot_handler());
      slot_object->obj()->Set(v8::String::NewSymbol("label"),
                              v8::String::New(object->label_.c_str()),
                              v8::ReadOnly);
      slot_object->obj()->Set(v8::String::NewSymbol("keyIdentifier"),
                              v8::String::New(object->key_identifier_.c_str()));

      // Build a certificate
      Certificate* certificate = new Certificate();
      certificate->Initialize();
      certificate->obj()->Set(v8::String::NewSymbol("subject"),
                              v8::String::New(object->subject_.c_str()));

      // Add the certificate to the slot object
      slot_object->obj()->Set(v8::String::NewSymbol("certificate"),
                              certificate->obj());

      // Add the object to pkcs11.slots ("slots[label] = obj")
      pkcs11->AddJSSlotObject(slot_object);
    }
    C_CloseSession(session_handle);
    return true;
  }

  // Returns false if the key is longer than a reasonable maximum length.
  virtual bool SetKeyIdentifier(const std::string& label,
                                const std::string& keyid) {
    const std::size_t MAX_KEY_LENGTH = 16;
    if (keyid.length() > MAX_KEY_LENGTH)
        return false;
    return Pkcs11SlotHandlerInMemory::SetKeyIdentifier(label, keyid);
  }

  virtual bool SetUserPin(const std::string& pin) {
    user_pin_ = pin;
    return true;
  }

  virtual bool BuildSlotObject(const std::string& label) {
    if (label.empty()) {
      LOG(ERROR) << "BuildSlotObject called with empty label.";
      return false;
    }
    if (GetObject(label) != NULL) {
      LOG(INFO) << "Using existing SlotObject label: " << label;
      return true;
    } else {
      AddObject(label);
      LOG(INFO) << "New SlotObject label: " << label;
      return true;
    }
  }

  virtual bool GenerateKeyPair(const std::string& label,
                               const std::string& passphrase) {
    LOG(INFO) << "Generating Key Pair.";

    Object* object = GetObject(label);
    if (!object) {
      LOG(ERROR) << "BuildSlotObject must be called before GenerateKeyPair.";
      return false;
    }
    SessionHandle session(OpenSession(label));
    if (!session.handle())
      return false;

    CK_OBJECT_CLASS pubkey_class = CKO_PUBLIC_KEY;
    CK_BBOOL is_token = TRUE;
    CK_BBOOL can_encrypt = TRUE;
    CK_BBOOL can_verify = TRUE;
    CK_BBOOL can_wrap = TRUE;
    CK_ULONG modulusBits = 2048;
    CK_BYTE publicExponent[] = { 0x01, 0x00, 0x01 };  // 65537 in bytes

    const size_t IDSTR_MAX_LENGTH = 8;
    CK_BYTE idstr[IDSTR_MAX_LENGTH];
    CK_ULONG idstrlen;
    if (!GetKeyIdStr(object->key_identifier_,
                     &idstr[0], &idstrlen, IDSTR_MAX_LENGTH)) {
      return false;
    }

    int public_key_n_attr = 0;
    CK_ATTRIBUTE public_key_template[16];
    FillAttr(&public_key_template[public_key_n_attr++], CKA_CLASS,
             &pubkey_class, sizeof(pubkey_class));
    FillAttr(&public_key_template[public_key_n_attr++], CKA_TOKEN,
             &is_token, sizeof(is_token));
    FillAttr(&public_key_template[public_key_n_attr++], CKA_ENCRYPT,
             &can_encrypt, sizeof(can_encrypt));
    FillAttr(&public_key_template[public_key_n_attr++], CKA_VERIFY,
             &can_verify, sizeof(can_verify));
    FillAttr(&public_key_template[public_key_n_attr++], CKA_WRAP,
             &can_wrap, sizeof(can_wrap));
    FillAttr(&public_key_template[public_key_n_attr++], CKA_MODULUS_BITS,
             &modulusBits, sizeof(modulusBits));
    FillAttr(&public_key_template[public_key_n_attr++], CKA_PUBLIC_EXPONENT,
             publicExponent, sizeof(publicExponent));
    FillStringAttr(&public_key_template[public_key_n_attr++], CKA_LABEL,
                   label);
    FillAttr(&public_key_template[public_key_n_attr++], CKA_ID,
             idstr, idstrlen);


    CK_OBJECT_CLASS privkey_class = CKO_PRIVATE_KEY;
    CK_BBOOL is_private = TRUE;
    CK_BBOOL is_sensitive = TRUE;
    CK_BBOOL can_decrypt = TRUE;
    CK_BBOOL can_sign = TRUE;
    CK_BBOOL can_unwrap = TRUE;

    int private_key_n_attr = 0;
    CK_ATTRIBUTE private_key_template[16];
    FillAttr(&private_key_template[private_key_n_attr++], CKA_CLASS,
             &privkey_class, sizeof(privkey_class));
    FillAttr(&private_key_template[private_key_n_attr++], CKA_TOKEN,
             &is_token, sizeof(is_token));
    FillAttr(&private_key_template[private_key_n_attr++], CKA_PRIVATE,
             &is_private, sizeof(is_private));
    FillAttr(&private_key_template[private_key_n_attr++], CKA_SENSITIVE,
             &is_sensitive, sizeof(is_sensitive));
    FillAttr(&private_key_template[private_key_n_attr++], CKA_DECRYPT,
             &can_decrypt, sizeof(can_decrypt));
    FillAttr(&private_key_template[private_key_n_attr++], CKA_SIGN,
             &can_sign, sizeof(can_sign));
    FillAttr(&private_key_template[private_key_n_attr++], CKA_UNWRAP,
             &can_unwrap, sizeof(can_unwrap));
    FillStringAttr(&private_key_template[private_key_n_attr++], CKA_LABEL,
                   label);
    FillAttr(&private_key_template[private_key_n_attr++], CKA_ID,
             idstr, idstrlen);


    CK_MECHANISM mechanism = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};
    CK_OBJECT_HANDLE public_key_handle;
    CK_OBJECT_HANDLE private_key_handle;

    CK_RV rv = C_GenerateKeyPair(session.handle(), &mechanism,
                                 public_key_template, public_key_n_attr,
                                 private_key_template, private_key_n_attr,
                                 &public_key_handle, &private_key_handle);

    if (rv != CKR_OK) {
      LOG(ERROR) << "C_GenerateKeyPair() failed. rv=" << rv;
      return false;
    }

    return true;
  }

  virtual bool AddCertificate(const std::string& label,
                              const chromeos::Blob& cert,
                              const std::string& subject) {
    LOG(INFO) << "Adding Certificate.";

    Object* object = GetObject(label);
    if (!object) {
      LOG(ERROR) << "BuildSlotObject must be called before AddCertificate.";
      return false;
    }
    SessionHandle session(OpenSession(label));
    if (!session.handle())
      return false;

    object->cert_ = cert;
    object->subject_ = subject;

    const size_t IDSTR_MAX_LENGTH = 8;
    CK_BYTE idstr[IDSTR_MAX_LENGTH];
    CK_ULONG idstrlen;
    if (!GetKeyIdStr(object->key_identifier_,
                     &idstr[0], &idstrlen, IDSTR_MAX_LENGTH)) {
      return false;
    }

    // Add the certifiacte object
    CK_OBJECT_CLASS cert_class = CKO_CERTIFICATE;
    CK_CERTIFICATE_TYPE cert_type = CKC_X_509;
    CK_BBOOL is_token = TRUE;

    CK_ATTRIBUTE cert_template[16];
    int n_attr = 0;
    FillAttr(&cert_template[n_attr++], CKA_CLASS,
             &cert_class, sizeof(cert_class));
    FillAttr(&cert_template[n_attr++], CKA_CERTIFICATE_TYPE,
             &cert_type, sizeof(cert_type));
    FillAttr(&cert_template[n_attr++], CKA_TOKEN,
             &is_token, sizeof(is_token));
    FillStringAttr(&cert_template[n_attr++], CKA_LABEL, label);
    FillStringAttr(&cert_template[n_attr++], CKA_SUBJECT, subject);
    FillAttr(&cert_template[n_attr++], CKA_ID,
             idstr, idstrlen);
    FillAttr(&cert_template[n_attr++], CKA_VALUE,
             (CK_VOID_PTR)(&(cert.front())), cert.size());

    CK_OBJECT_HANDLE cert_obj;
    CK_RV rv = C_CreateObject(session.handle(),
                              cert_template, n_attr, &cert_obj);
    if (rv != CKR_OK) {
      LOG(ERROR) << "C_CreateObject error: " << rv;
      return false;
    }

    return true;
  }

  virtual bool AddPrivateKey(const std::string& label,
                             const std::string& subject,
                             const chromeos::Blob& key) {
    LOG(INFO) << "Adding Private Key.";

    Object* object = GetObject(label);
    if (!object){
      LOG(ERROR) << "BuildSlotObject must be called before AddPrivateKey.";
      return false;
    }
    SessionHandle session(OpenSession(label));
    if (!session.handle())
      return false;

    const size_t IDSTR_MAX_LENGTH = 8;
    CK_BYTE idstr[IDSTR_MAX_LENGTH];
    CK_ULONG idstrlen;
    if (!GetKeyIdStr(object->key_identifier_,
                     &idstr[0], &idstrlen, IDSTR_MAX_LENGTH)) {
      return false;
    }

    // Add the private key object
    CK_OBJECT_CLASS key_class = CKO_PRIVATE_KEY;
    CK_CERTIFICATE_TYPE key_type = CKK_RSA;
    CK_BBOOL is_token = TRUE;
    CK_BBOOL is_private = TRUE;
    CK_BBOOL is_sensitive = TRUE;

    RsaKeyInfo rsa;
    if (!ParseRSAPrivateKey(key, &rsa)) {
      return false;
    }

    CK_ATTRIBUTE key_template[32];
    int n_attr = 0;
    FillAttr(&key_template[n_attr++], CKA_CLASS,
             &key_class, sizeof(key_class));
    FillAttr(&key_template[n_attr++], CKA_KEY_TYPE,
             &key_type, sizeof(key_type));
    FillAttr(&key_template[n_attr++], CKA_TOKEN,
             &is_token, sizeof(is_token));
    FillAttr(&key_template[n_attr++], CKA_PRIVATE,
             &is_token, sizeof(is_private));
    FillAttr(&key_template[n_attr++], CKA_SENSITIVE,
             &is_token, sizeof(is_sensitive));
    FillStringAttr(&key_template[n_attr++], CKA_LABEL, label);
    FillAttr(&key_template[n_attr++], CKA_ID,
             idstr, idstrlen);
    FillStringAttr(&key_template[n_attr++], CKA_SUBJECT, subject);
    FillAttr(&key_template[n_attr++], CKA_MODULUS,
             rsa.modulus, rsa.modulus_len);
    FillAttr(&key_template[n_attr++], CKA_PUBLIC_EXPONENT,
             rsa.public_exp, rsa.public_exp_len);
    FillAttr(&key_template[n_attr++], CKA_PRIVATE_EXPONENT,
             rsa.private_exp, rsa.private_exp_len);
    FillAttr(&key_template[n_attr++], CKA_PRIME_1,
             rsa.prime_1, rsa.prime_1_len);
    FillAttr(&key_template[n_attr++], CKA_PRIME_2,
             rsa.prime_2, rsa.prime_2_len);
    FillAttr(&key_template[n_attr++], CKA_EXPONENT_1,
             rsa.exp_1, rsa.exp_1_len);
    FillAttr(&key_template[n_attr++], CKA_EXPONENT_2,
             rsa.exp_2, rsa.exp_2_len);
    FillAttr(&key_template[n_attr++], CKA_COEFFICIENT,
             rsa.coefficient, rsa.coefficient_len);

    CK_OBJECT_HANDLE key_obj;
    CK_RV rv = C_CreateObject(session.handle(),
                              key_template, n_attr, &key_obj);
    if (rv != CKR_OK) {
      LOG(ERROR) << "C_CreateObject error: " << rv;
      return false;
    }

    return true;
  }

  // Removes all objects in the slot matching 'label'
  // Note: may be called before BuildSlotObject(), but we still need to
  // be logged in so that we can remove matching private keys.
  virtual bool RemoveObjects(const std::string& label) {
    LOG(INFO) << "Removing Objects matching: " << label;

    SessionHandle session(OpenSession(label));
    if (!session.handle())
      return false;

    CK_ATTRIBUTE object_template[4];
    int n_attr = 0;
    FillStringAttr(&object_template[n_attr++], CKA_LABEL, label);
    CK_RV rv = C_FindObjectsInit(session.handle(), object_template, n_attr);
    if (rv != CKR_OK) {
      LOG(ERROR) << "C_FindObjectsInit failed: " << rv;
      return false;
    }

    bool res = true;
    int num_objects = 0;
    while (1) {
      CK_ULONG count;
      CK_OBJECT_HANDLE object;
      rv = C_FindObjects(session.handle(), &object, 1, &count);
      if (rv != CKR_OK) {
        LOG(ERROR) << "C_FindObjects failed: " << rv;
        res = false;
        break;
      }
      if (count == 0) {
        break;
      }
      ++num_objects;
      rv = C_DestroyObject(session.handle(), object);
      if (rv != CKR_OK) {
        LOG(ERROR) << "C_DestroyObject failed: " << rv
                   << " obj: " << num_objects;
        res = false;
        break;
      }
    }
    LOG(INFO) << " Removed " << num_objects << " objects.";

    C_FindObjectsFinal(session.handle());

    return res;
  }

 private:
  // Class to close sessions we have opened on destruction
  class SessionHandle {
   public:
    SessionHandle(CK_SESSION_HANDLE handle) : handle_(handle) {}
    ~SessionHandle() {
      if (handle_)
        C_CloseSession(handle_);
    }
    CK_SESSION_HANDLE handle() { return handle_; }
   private:
    CK_SESSION_HANDLE handle_;
  };

  CK_SESSION_HANDLE OpenSession(const std::string& label) {
    CK_SESSION_HANDLE handle = NULL;
    CK_RV rv = C_OpenSession(slot_id_,
                             CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL, NULL,
                             &handle);
    if (rv != CKR_OK) {
      LOG(ERROR) << "C_OpenSession failed, error: " << rv
                 << " label: " << label << " slot: " << slot_index_;
      return NULL;
    }
    CK_UTF8CHAR* pin_ptr =
        reinterpret_cast<unsigned char*>(const_cast<char*>(user_pin_.c_str()));
    rv = C_Login(handle, CKU_USER,
                 pin_ptr, user_pin_.length());
    if (rv != CKR_OK) {
      LOG(ERROR) << "C_Login failed, error: " << rv
                 << " label: " << label << " pin: " << user_pin_;
      return NULL;
    }

    return handle;
  }

  std::string TemplateToString(const CK_ATTRIBUTE& attr) {
    const char* value = static_cast<const char*>(attr.pValue);
    return std::string(value, attr.ulValueLen);
  }

  // openssl crypto library interface

  struct RsaKeyInfo {
    unsigned char *modulus;
    int modulus_len;
    unsigned char *public_exp;
    int public_exp_len;
    unsigned char *private_exp;
    int private_exp_len;
    unsigned char *prime_1;
    int prime_1_len;
    unsigned char *prime_2;
    int prime_2_len;
    unsigned char *exp_1;
    int exp_1_len;
    unsigned char *exp_2;
    int exp_2_len;
    unsigned char *coefficient;
    int coefficient_len;
  };

  bool RSAGetBN(const BIGNUM* component , unsigned char** dest, int* len) {
    unsigned char* vec = NULL;
    int bytes = BN_num_bytes(component);
    if (bytes) {
      vec = static_cast<unsigned char*>(malloc(bytes));
    }
    if (!vec) {
      LOG(ERROR) << "Error allocating memory while parsing RSA key.";
      return false;
    }
    int length = BN_bn2bin(component, vec);
    if (!length) {
      LOG(ERROR) << "Error parsing component in RSA key.";
      return false;
    }
    *len = length;
    *dest = vec;
    return true;
  }

  bool ParseRSAPrivateKey(const chromeos::Blob& data, RsaKeyInfo* info) {
    const unsigned char *p = &(data.front());
    RSA* key = d2i_RSAPrivateKey(NULL, &p, data.size());
    if (!key) {
      LOG(ERROR) << "OpenSSL error during RSA private key parsing.";
      return false;
    }
    bool res =
        RSAGetBN(key->n, &info->modulus, &info->modulus_len) &&
        RSAGetBN(key->e, &info->public_exp, &info->public_exp_len) &&
        RSAGetBN(key->d, &info->private_exp, &info->private_exp_len) &&
        RSAGetBN(key->p, &info->prime_1, &info->prime_1_len) &&
        RSAGetBN(key->q, &info->prime_2, &info->prime_2_len) &&
        RSAGetBN(key->dmp1, &info->exp_1, &info->exp_1_len) &&
        RSAGetBN(key->dmq1, &info->exp_2, &info->exp_2_len) &&
        RSAGetBN(key->iqmp, &info->coefficient, &info->coefficient_len);
    return res;
  }

  // Note: use casting to store const values as non const.
  // This avoids using lots of casts or needlessly copying the contents
  // of strings, but be careful not to use this to receive data
  // into a string or other const array.
  void FillStringAttr(CK_ATTRIBUTE* attr, CK_ATTRIBUTE_TYPE type,
                      const std::string& str) {
    attr->type = type;
    attr->pValue = const_cast<char*>(str.c_str());
    attr->ulValueLen = str.length();
  }

  void FillAttr(CK_ATTRIBUTE* attr, CK_ATTRIBUTE_TYPE type,
                void* value, CK_ULONG length) {
    attr->type = type;
    attr->pValue = value;
    attr->ulValueLen = length;
  }

  // Converts the string "0123abcd" to CK_BYTE[] { 01,23,ab,cd }
  // If the string is too long, *idstrlenp is set to 0 and false is returned.
  // Invalid characters are clamped to [a,f]. "123abz@" -> { 01,23,ab,ff }
  bool GetKeyIdStr(const std::string& keyid_in,
                   CK_BYTE* idstrp, CK_ULONG *idstrlenp, size_t max_length) {
    std::string keyid;
    if (keyid_in.size() & 1) {
      keyid.push_back('0');
      keyid.append(keyid_in);
    } else {
      keyid = keyid_in;
    }
    chromeos::Blob bytes = chromeos::AsciiDecode(keyid);
    if (bytes.size() > max_length) {
      LOG(ERROR) << "Too many characters in key: " << keyid;
      *idstrlenp = 0;
      return false;
    }
    memcpy(idstrp, &bytes.front(), bytes.size());
    *idstrlenp = bytes.size();
    return true;
  }

  // Inverse of GetKeyIdStr
  std::string GetKeyFromId(CK_BYTE* idstrp, CK_ULONG idstrlen) {
    chromeos::Blob bytes = chromeos::Blob(idstrp, idstrp+idstrlen);
    return chromeos::AsciiEncode(bytes);
  }

  std::string user_pin_;
  CK_ULONG slot_index_;
  CK_SLOT_ID slot_id_;

  DISALLOW_COPY_AND_ASSIGN(Pkcs11SlotHandlerOpenCryptoki);
};

// Pkcs11CertificateHandlerLibOpenSsl generates its own key pair,
// which is what we would prefer to use. However, engine_pkcs11
// is not currently working correctly, and there is no known
// implementation that can generate a CSR using the TPM generated key pair.
// (The current implementaiton of Pkcs11CertificateHandlerLibOpenSsl calls
// AddPrivateKey() instead).
// Rather than eliminate the poentially useful (and non-trivial) code in
// Pkcs11SlotHandlerOpenCryptoki, override the class with a GenerateKeyPair()
// method that just sets the passphrase and ensures that the object exists.
class Pkcs11SlotHandlerOpenCryptokiNoKeyGen :
      public Pkcs11SlotHandlerOpenCryptoki {
 public:
  Pkcs11SlotHandlerOpenCryptokiNoKeyGen() {}

  // Don't actually generate a key pair; rely on AddPrivateKey() getting
  // called instead.
  virtual bool GenerateKeyPair(const std::string& label,
                               const std::string& passphrase) {
    Object* obj = GetObject(label);
    if (!obj) {
      LOG(WARNING) << "BuildSlotObject must be called before GenerateKeyPair";
      return false;
    }
    obj->passphrase_ = passphrase;
    return true;
  };

 private:
  DISALLOW_COPY_AND_ASSIGN(Pkcs11SlotHandlerOpenCryptokiNoKeyGen);
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
Pkcs11CertificateHandler* CSR::certificate_handler_ = NULL;

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
  if (!certificate_handler()->BuildCSR(slot_object->label(),
                                       utils::ValueAsUtf8String(subject),
                                       &request_)) {
    utils::ThrowV8Exception("Error building CSR.");
    return;
  }
}


// Class Certificate Implementation

// static
Pkcs11CertificateHandler* Certificate::certificate_handler_ = NULL;

// Returns the contents of the Certificate as a string.
// Note: if this is binary and not Base64, results may be unexpected.
// (i.e. don't call this unles you expect the contents to be a string)
static v8::Handle<v8::Value> dispatch_CertificateToString(
    const v8::Arguments& args) {
  Certificate* cert = Certificate::Unwrap(args.This());
  const chromeos::Blob& certdata = cert->certificate();
  const char* certstrptr = reinterpret_cast<const char*>(&(certdata.front()));
  v8::Local<v8::String> res = v8::String::New(certstrptr);
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

  // Generate the Certificate data
  bool res = certificate_handler()->BuildCertificate(
      utils::ValueAsUtf8String(content), &certificate_, &subject_);
  if (!res) {
    utils::ThrowV8Exception("Unable to build certificate.");
    return;
  }

  // Set the 'subject' property to the certificate subject
  obj->Set(v8::String::NewSymbol("subject"),
           v8::String::New(subject_.c_str()));
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
  v8::Handle<v8::String> v8keyid = args[0]->ToString();
  std::string keyid = std::string(*v8::String::Utf8Value(v8keyid));
  bool res = slot->SetKeyIdentifier(keyid);
  if (!res) {
    utils::ThrowV8Exception(std::string("Invalid key id: ") + keyid);
    return v8::False();
  }
  // Set the JS keyIdentifier property
  slot->obj()->Set(v8::String::NewSymbol("keyIdentifier"), v8keyid);

  // Argumnet 1 is the passphrase (optional)
  std::string passphrase;  // defaults to empty
  if (!args[1]->IsUndefined()) {
    passphrase = utils::ValueAsUtf8String(args[1]);
    slot->SetPassphrase(passphrase);
  }

  // Access the slot handler and generate the public/private key pair
  if (!slot->slot_handler()->GenerateKeyPair(slot->label(),
                                             slot->passphrase())) {
    LOG(ERROR) << "Unable to build key pair with id: " << keyid;
    return v8::False();
  }

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
  if (!slot->slot_handler()->AddCertificate(slot->label(),
                                            cert->certificate(),
                                            cert->subject())) {
    utils::ThrowV8Exception("Error adding certificate to PKCS11 device.");
    return v8::False();
  }

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
  if (!pkcs11->slot_handler()->BuildSlotObject(label_)) {
    LOG(ERROR) << "Unable to build SlotObject with label: " << label_;
    return;
  }

  // Add this to pkcs11.slots ("slots[label] = obj")
  pkcs11->AddJSSlotObject(this);
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

// Called any time slot_handler_ or certificate_handler_ gets set.
void Pkcs11::SetupHandlers() {
 // The certificate handler may need access to the slot handler
  certificate_handler()->SetSlotHandler(slot_handler());

  // Set up the CSR and Certificate sub-classes with the certificate handler.
  CSR::InitCertificateHandler(certificate_handler());
  Certificate::InitCertificateHandler(certificate_handler());
}

bool Pkcs11::Initialize() {
  // Initialize the SlotObject template here so that we can embed 'this'.
  v8::Handle<v8::FunctionTemplate> t = GetTemplate();
  v8::Handle<v8::ObjectTemplate> t_obj = t->InstanceTemplate();
  t_obj->Set(v8::String::NewSymbol("SlotObject"),
             v8::FunctionTemplate::New(SlotObject::Construct,
                                       v8::External::Wrap(this)),
             v8::ReadOnly);

  // Build and initialize the V8 object.
  if (!JSObjectWrapper<Pkcs11>::Initialize())
    return false;

  // Default handlers
  if (certificate_handler_.get() == NULL) {
    certificate_handler_.reset(new Pkcs11TestCertificateHandler());
    if (!certificate_handler_->Initialize())
      return false;
  }
  if (slot_handler_.get() == NULL) {
    slot_handler_.reset(new Pkcs11SlotHandlerInMemory());
    if (!slot_handler_->Initialize())
      return false;
  }
  SetupHandlers();

  return true;
}

// Used for testing the OpenSSL functionality without requiring
// opencryptoki to be configured in the OS.
bool Pkcs11::SetOpenSSLHandlers() {
  Pkcs11CertificateHandlerLibOpenSsl* cert_handler =
      new Pkcs11CertificateHandlerLibOpenSsl();
  if (!cert_handler->Initialize())
    return false;
  certificate_handler_.reset(cert_handler);

  SetupHandlers();

  return true;
}

// Requires opencryptoki to be configured properly in the OS,
// otherwise C_Initialize() will fail.
bool Pkcs11::SetOpenCryptokiHandlers() {
  Pkcs11CertificateHandlerLibOpenSsl* cert_handler =
      new Pkcs11CertificateHandlerLibOpenSsl();
  if (!cert_handler->Initialize())
    return false;
  certificate_handler_.reset(cert_handler);

  Pkcs11SlotHandlerOpenCryptokiNoKeyGen* slot_handler =
      new Pkcs11SlotHandlerOpenCryptokiNoKeyGen();
  slot_handler_.reset(slot_handler);
  if (!slot_handler->Initialize())
    return false;
  slot_handler->ReadObjectsFromSlot(this);

  SetupHandlers();

  return true;
}

// pkcs11[slot_object->label()] = slot_object->obj()
bool Pkcs11::AddJSSlotObject(const SlotObject* slot_object) {
  v8::Local<v8::Value> slotsvalue = obj()->Get(v8::String::NewSymbol("slots"));
  if (slotsvalue.IsEmpty() || !slotsvalue->IsObject()) {
    LOG(ERROR) << "'slots' is not an object in pkcs11";
    return false;
  }
  v8::Local<v8::Object> slots = v8::Local<v8::Object>::Cast(slotsvalue);
  v8::Local<v8::String> v8label = v8::String::New(slot_object->label().c_str());
  slots->Set(v8label, slot_object->obj());
  return true;
}

// delete pkcs11.slots[label]")
bool Pkcs11::RemoveJSSlotObject(const std::string& label) {
  v8::Local<v8::Value> slotsvalue = obj()->Get(v8::String::NewSymbol("slots"));
  if (slotsvalue.IsEmpty() || !slotsvalue->IsObject()) {
    LOG(ERROR) << "'slots' is not an object in pkcs11";
    return false;
  }
  v8::Local<v8::Object> slots = v8::Local<v8::Object>::Cast(slotsvalue);
  v8::Local<v8::String> v8label = v8::String::New(label.c_str());
  slots->Delete(v8label);
  return true;
}

static v8::Handle<v8::Value> dispatch_setUserPin(
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

  // Argument is the pin
  std::string pin = utils::ValueAsUtf8String(args[0]);
  if (!pkcs11->slot_handler()->SetUserPin(pin)) {
    utils::ThrowV8Exception("Error setting PIN for PKCS11 device.");
    return v8::False();
  }
  return v8::True();
}

static v8::Handle<v8::Value> dispatch_removeSlotObject(
    const v8::Arguments& args) {
  // Get the pkcs11 object.
  Pkcs11* pkcs11 = Pkcs11::Unwrap(args.This());
  if (pkcs11 == NULL) {
    utils::ThrowV8Exception("Method called on incorrect object type.");
    return v8::False();
  }
  if (args.Length() < 1) {
    utils::ThrowV8Exception("Not enough parameters.");
    return v8::False();
  }

  // Argument 0 is a label.
  std::string label = utils::ValueAsUtf8String(args[0]);

  // Remove the contents of the slot in the slot handler.
  if (!pkcs11->slot_handler()->RemoveObjects(label)) {
    utils::ThrowV8Exception("Error removing objects from PKCS11 device.");
    return v8::False();
  }

  // Remove entry from pkcs11.slots
  pkcs11->RemoveJSSlotObject(label);

  return v8::True();
}

// static
void Pkcs11::SetTemplateBindings(
    v8::Handle<v8::ObjectTemplate> template_object) {
  // "SlotObject" gets setup specially in Initialize();
  template_object->Set(v8::String::NewSymbol("setUserPin"),
                       v8::FunctionTemplate::New(dispatch_setUserPin),
                       v8::ReadOnly);
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
