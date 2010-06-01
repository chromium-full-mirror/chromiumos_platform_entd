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
#include <openssl/rsa.h>
#include <openssl/bn.h>

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
  const std::string& key_identifier() const { return key_identifier_; }
  const std::string& passphrase() const { return passphrase_; }
  std::string GetPublicKey() const {
    return slot_handler()->GetPublicKey(label_);
  }
  Pkcs11SlotHandler* slot_handler() const { return slot_handler_; }

  // Setters

  // Stores the key identifier and passes it to the slot handler.
  const bool SetKeyIdentifier(const std::string& id) {
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


// class Pkcs11CertificateHandlerLocalFile
// Test Certificate handler that returns the contents of a file.
//
// If the csr or cert file exists, the contents of the file is returned
// in BuildCSR or BuildCertificate; subject or content arguments are ignored.
// If the filename is empty or the file does not exist, a string
// containing the subject or content is returned instead.
class Pkcs11CertificateHandlerLocalFile : public Pkcs11CertificateHandler {
 public:
  Pkcs11CertificateHandlerLocalFile(const std::string& csr,
                                    const std::string& cert)
      : csr_filename_(csr), certificate_filename_(cert) {
    if (!csr_filename_.empty())
      LOG(INFO) << "Using local CSR file: " << csr_filename_;
    if (!certificate_filename_.empty())
      LOG(INFO) << "Using local Cert file: " << certificate_filename_;
  }
  virtual ~Pkcs11CertificateHandlerLocalFile() {}
  virtual bool Initialize() { return true; }

  virtual bool BuildCSR(const std::string& label,
                        const std::string& subject,
                        std::string* csr) {
    if (!csr_filename_.empty())
      file_util::ReadFileToString(FilePath(csr_filename_), csr);
    if (csr->empty()) {
      // Default CSR string if not read from a file
      *csr = std::string("<CSR subject=") + subject + " />";
    }
    return true;
  }

  virtual bool BuildCertificate(const std::string& content,
                                chromeos::Blob* certificate,
                                std::string* subject) {
    std::string subjectstr;

    if (!certificate_filename_.empty()) {
      // Try reading the certificate from the filename set at construction.
      FilePath filepath(certificate_filename_);
      int64 filesize;
      bool file_read = file_util::GetFileSize(filepath, &filesize);
      if (file_read) {
        certificate->resize(filesize);
        char* dest = reinterpret_cast<char*>(&(certificate->front()));
        int res = file_util::ReadFile(filepath, dest, filesize);
        if (res == filesize) {
          *subject = std::string("File: ") + certificate_filename_;
        } else {
          file_read = false;
        }
      }
      if (!file_read) {
        LOG(ERROR) << "Error reading file: " << filepath.value();
        return false;
      }
    } else {
      // Use a test string for debugging.
      std::string certstr =
          std::string("<Certificate content=") + content + " />";
      LOG(INFO) << "Setting certificate = " << certstr;
      certificate->resize(certstr.length());
      memcpy(&(certificate->front()), certstr.c_str(), certstr.length());
      *subject = "Content";
    }
    return true;
  }

 private:
  std::string csr_filename_;
  std::string certificate_filename_;
};

// Class Pkcs11CertificateHandlerOpenSsl
// Implements CSR generation using 'system("openssl req...")'.
class Pkcs11CertificateHandlerOpenSsl : public Pkcs11CertificateHandler {
 public:
  Pkcs11CertificateHandlerOpenSsl() : use_DER_format_(false) {}

  virtual ~Pkcs11CertificateHandlerOpenSsl() {}

  virtual bool Initialize() { return true; }

  // If called, openssl will be told to convert the certificate to DER format.
  // DER is the format that opencryptoki expects.
  void SetOutputDER() { use_DER_format_ = true; }

  void SetTestCertificate(const std::string& certfile) {
    test_certfile_ = certfile;
  }

  virtual bool BuildCSR(const std::string& label,
                        const std::string& subject,
                        std::string* csr) {
    // temporary filenames
    FilePath temp_dir;
    file_util::GetTempDir(&temp_dir);
    FilePath private_key_fp = temp_dir.Append("privkey");
    FilePath csr_fp = temp_dir.Append("csr");

    // Get the passphrase for the private key from the slot handler
    std::string passphrase = slot_handler()->GetPassphrase(label);

    // *TODO: replace with calls to libopenssl to avoid system() call.
    if (!CheckString(subject) ||
        !CheckString(passphrase)) {
      return false;
    }
    std::string cmd =
        std::string("openssl req -new -batch -newkey rsa:2048")
        + " -keyout " + private_key_fp.value()
        + " -subj \"" + subject + "\""
        + " -pubkey -out " + csr_fp.value();
    if (!passphrase.empty())
      cmd += " -passout pass:" + passphrase;
    else
      cmd += " -nodes";
    CallSystem(cmd);

    // get the results from the temporary files
    std::string csr_output;
    if (file_util::ReadFileToString(csr_fp, &csr_output)) {
      csr_ = GetCertSection(csr_output,
                            "-----BEGIN CERTIFICATE REQUEST-----",
                            "-----END CERTIFICATE REQUEST-----");
      public_key_ = GetCertSection(csr_output,
                                   "-----BEGIN PUBLIC KEY-----",
                                   "-----END PUBLIC KEY-----");
    }
    file_util::ReadFileToString(private_key_fp, &private_key_);

    // remove temporary files
    file_util::Delete(private_key_fp, false);
    file_util::Delete(csr_fp, false);

    // Convert the pivate key to DER format and pass it to the slot handler.
    if (use_DER_format_ && !private_key_.empty()) {
      chromeos::Blob key_der;
      if (!ConvertToDER(private_key_, passphrase, &key_der))
        return false;
      slot_handler()->AddPrivateKey(label, subject, key_der);
    }

    *csr = csr_;

    return true;
  }

  // Include the private key (encoded with the SlotObject's passphrase)
  // with the certificate so that it can be decoded with the passphrase.
  virtual bool BuildCertificate(const std::string& content,
                                chromeos::Blob* certificate,
                                std::string* subject) {
    FilePath temp_dir;
    file_util::GetTempDir(&temp_dir);
    FilePath cert_pem_fp = temp_dir.Append("cert.pem");
    FilePath cert_der_fp = temp_dir.Append("cert.der");
    FilePath subject_fp = temp_dir.Append("subject");

    if (!content.empty()) {
      // Write the content string to a temporary file
      // to use as the certificate contents.
      int res = file_util::WriteFile(
          cert_pem_fp, content.c_str(), content.length());
      if (res < 0) {
        LOG(ERROR) << "Unable to write temporary file: " << cert_pem_fp.value();
        return false;
      }
    } else if (!test_certfile_.empty()) {
      // Use the test certifcate file set at initialization.
      cert_pem_fp = FilePath(test_certfile_);
    }

    {
      // Use openssl to write the subject and (if needed)
      // the DER version of the certificate
      // *TODO: replace with calls to libopenssl to avoid system() call.
      std::string cmd("openssl x509");
      cmd += " -inform PEM -in " + cert_pem_fp.value();
      if (use_DER_format_)
        cmd += " -outform DER -out " + cert_der_fp.value();
      else
        cmd += " -noout";
      cmd += " -subject > " + subject_fp.value();
      bool res = CallSystem(cmd);

      if (cert_pem_fp != FilePath(test_certfile_)) {
        file_util::Delete(cert_pem_fp, false);
      }
      if (!res) {
        file_util::Delete(cert_der_fp, false);
        file_util::Delete(subject_fp, false);
        return false;
      }
    }

    if (use_DER_format_) {
      // read in the DER version of the certificate.
      int64 certlen;
      int res = -1;
      if (file_util::GetFileSize(cert_der_fp, &certlen)) {
        certificate->resize(certlen);
        char* dest = reinterpret_cast<char*>(&(certificate->front()));
        res = file_util::ReadFile(cert_der_fp, dest, certlen);
      }
      file_util::Delete(cert_der_fp, false);
      if (res != certlen) {
        LOG(ERROR) << "Unable to read DER file: " << cert_der_fp.value();
        file_util::Delete(subject_fp, false);
        certificate->clear();
        return false;
      }
    } else {
      std::string certstr;
      if (!content.empty()) {
        // Include content provided by script.
        certstr = content;
      } else {
        // Include the (test) certificate file.
        int64 certlen;
        int res = -1;
        if (file_util::GetFileSize(cert_pem_fp, &certlen)) {
          const int cert_max_length = 256*1024;
          if (certlen < cert_max_length) {
            char* certvec = new char[certlen];
            res = file_util::ReadFile(cert_pem_fp, &certvec[0], certlen);
            if (res == certlen) {
              certstr = std::string(certvec, certlen);
            }
          }
        }
      }
      // Append the private key.
      certstr += private_key_;
      // Copy to certificate.
      certificate->resize(certstr.length());
      memcpy(&(certificate->front()), certstr.c_str(), certstr.length());
    }

    {
      // read in the subject
      int64 subjectlen;
      int res = -1;
      if (file_util::GetFileSize(subject_fp, &subjectlen)) {
        const int subject_max_length = 4096;
        if (subjectlen < subject_max_length) {
          char* subjectvec = new char[subjectlen];
          res = file_util::ReadFile(subject_fp, &subjectvec[0], subjectlen);
          if (res == subjectlen) {
            const std::string headerstr("subject= ");
            std::string subjstr(subjectvec, subjectlen);
            std::string::size_type idx = subjstr.find(headerstr);
            if (idx != std::string::npos)
              subject->assign(subjstr.substr(idx + headerstr.length()));
            else
              subject->assign(subjstr);
          }
        }
      }
      file_util::Delete(subject_fp, false);
      if (res != subjectlen) {
        LOG(ERROR) << "Unable to read subject file: " << subject_fp.value();
        return false;
      }
    }

    return true;
  }

 protected:
  bool ConvertToDER(const std::string& key,
                    const std::string& passphrase,
                    chromeos::Blob* key_der) {
    FilePath temp_dir;
    file_util::GetTempDir(&temp_dir);
    FilePath key_pem_fp = temp_dir.Append("key.pem");
    FilePath key_der_fp = temp_dir.Append("key.der");

    // Write the key to a temporary file
    int res = file_util::WriteFile(key_pem_fp, key.c_str(), key.length());
    if (res < 0) {
      LOG(ERROR) << "Unable to write temporary file: " << key_pem_fp.value();
      return false;
    }

    // Use openssl to write the the DER version of the key
    // *TODO: replace with calls to libopenssl to avoid system() call.
    if (!CheckString(passphrase)) {
      return false;
    }
    std::string cmd = std::string("openssl rsa")
        + " -inform PEM -in " + key_pem_fp.value()
        + " -outform DER -out " + key_der_fp.value();
    if (!passphrase.empty())
      cmd += " -passin pass:" + passphrase;
    CallSystem(cmd);

    // read in the DER version of the key.
    int64 keylen;
    res = -1;
    if (file_util::GetFileSize(key_der_fp, &keylen)) {
      key_der->resize(keylen);
      char* dest = reinterpret_cast<char*>(&(key_der->front()));
      res = file_util::ReadFile(key_der_fp, dest, keylen);
    }

    file_util::Delete(key_pem_fp, false);
    file_util::Delete(key_der_fp, false);

    if (res != keylen) {
      LOG(ERROR) << "Unable to read key DER file: " << key_der_fp.value();
      return false;
    }
    return true;
  }

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

  bool CheckString(const std::string& instr) {
    for (std::string::const_iterator iter = instr.begin();
         iter != instr.end(); ++iter) {
      char c = *iter;
      if (c == '"') {
        LOG(ERROR) << "Invalid string: " << instr;
        return false;
      }
    }
    return true;
  }

  bool CallSystem(const std::string& cmd) {
    LOG(INFO) << "Calling system(" << cmd << ");";
    int res = system(cmd.c_str());
    if (res != 0) {
      LOG(WARNING) << "Error executing command: '" << cmd << "'\n"
                   << " result = " << res;
      return false;
    }
    return true;
  }

  bool use_DER_format_;
  std::string test_certfile_;

  std::string csr_;
  std::string certificate_;
  std::string private_key_;
  std::string public_key_;
};

// In this implementation, instead of generating a public/private key pair,
// use engine_pkcs11 to get the keys from the TPM.
class Pkcs11CertificateHandlerOpenSslPkcs11Engine :
      public Pkcs11CertificateHandlerOpenSsl {

 public:
  void SetEngineConfigFile(const std::string& filename) {
    engine_config_file_ = filename;
  }

  virtual bool BuildCSR(const std::string& label,
                        const std::string& subject,
                        std::string* csr) {
    FilePath temp_dir;
    file_util::GetTempDir(&temp_dir);
    FilePath csr_fp = temp_dir.Append("csr");

    csr_.clear();

    if (engine_config_file_.empty()) {
      LOG(ERROR) << "BuildCSR called with no engine config file specified.";
      return false;
    }

    // *TODO: replace with calls to libopenssl to avoid system() call.
    std::string keyid = slot_handler()->GetKeyIdentifier(label);
    std::stringstream cmd;
    if (!CheckString(subject)) {
      return false;
    }
    cmd << "openssl req -new -batch"
        << " -config " << engine_config_file_ << " -engine pkcs11"
        << " -key " << keyid << " -keyform engine"
        << " -subj \"" << subject << "\""
        << " -out " << csr_fp.value();
    CallSystem(cmd.str());

    bool res = file_util::ReadFileToString(csr_fp, &csr_);
    if (!res) {
      LOG(ERROR) << "Unable to read CSR file: " << csr_fp.value();
      return false;
    }

    // remove temporary files
    file_util::Delete(csr_fp, false);

    *csr = csr_;

    return true;
  }

  // BuildCertificate() is the same as in the parent class,
  // but note that private_key_ will be empty, so nothing will be
  // appended to the certificate contents (as desired).

 private:
  std::string engine_config_file_;
};


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

  virtual bool RemoveObjects(const std::string& label,
                             const std::string& keyid) {
    Object* obj = GetObject(label);
    if (!obj) {
      LOG(WARNING) << "RemoveObjects called on nonexistant slot object";
      return false;
    }
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

  // TODO(stevenjb): read existing objects into objects_

    return res;
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
    Object* object;
    SessionHandle session(OpenSession(label, &object));
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

    LOG(INFO) << "Calling C_GenerateKeyPair().";
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
    Object* object;
    SessionHandle session(OpenSession(label, &object));
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

    LOG(INFO) << "Calling C_CreateObject for certificate.";
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
    Object* object;
    SessionHandle session(OpenSession(label, &object));
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

    LOG(INFO) << "Calling C_CreateObject for private key.";
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
  virtual bool RemoveObjects(const std::string& label,
                             const std::string& keyid) {
    SessionHandle session(OpenSession(label, NULL));
    if (!session.handle())
      return false;

    LOG(INFO) << "Removing Objects matching: " << label
              << ", ID='" << keyid << "'";

    const size_t IDSTR_MAX_LENGTH = 8;
    CK_BYTE idstr[IDSTR_MAX_LENGTH];
    CK_ULONG idstrlen;
    if (!GetKeyIdStr(keyid, &idstr[0], &idstrlen, IDSTR_MAX_LENGTH)) {
      return false;
    }

    CK_ATTRIBUTE object_template[4];
    int n_attr = 0;
    FillStringAttr(&object_template[n_attr++], CKA_LABEL, label);
    FillAttr(&object_template[n_attr++], CKA_ID, idstr, idstrlen);
    CK_RV rv = C_FindObjectsInit(session.handle(), object_template, n_attr);
    if (rv != CKR_OK) {
      LOG(ERROR) << "C_FindObjectsInit failed: " << rv;
      return false;
    }

    int num_objects = 0;
    while (1) {
      CK_ULONG count;
      CK_OBJECT_HANDLE object;
      rv = C_FindObjects(session.handle(), &object, 1, &count);
      if (rv != CKR_OK) {
        LOG(ERROR) << "C_FindObjects failed: " << rv;
        return false;
      }
      if (count == 0) {
        break;
      }
      ++num_objects;
      rv = C_DestroyObject(session.handle(), object);
      if (rv != CKR_OK) {
        LOG(ERROR) << "C_DestroyObject failed: " << rv
                   << " obj: " << num_objects;
      }
    }
    LOG(INFO) << " Removed " << num_objects << " objects.";

    C_FindObjectsFinal(session.handle());

    return true;
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

  CK_SESSION_HANDLE OpenSession(const std::string& label, Object** objectp) {
    CK_SESSION_HANDLE handle = NULL;
    ObjectMap::iterator iter = objects_.find(label);
    if (iter == objects_.end()) {
      LOG(ERROR) << "BuildSlotObject must be called first.";
      return NULL;
    }

    if (objectp) {
      *objectp = iter->second.get();
    }

    CK_RV rv = C_OpenSession(slot_id_,
                             CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL, NULL,
                             &handle);
    if (rv != CKR_OK) {
      LOG(ERROR) << "C_OpenSession failed, error: " << rv
                 << " label: " << label << " slot: " << slot_index_;
    }
    CK_UTF8CHAR* pin_ptr =
        reinterpret_cast<unsigned char*>(const_cast<char*>(user_pin_.c_str()));
    rv = C_Login(handle, CKU_USER,
                 pin_ptr, user_pin_.length());
    if (rv != CKR_OK) {
      LOG(ERROR) << "C_Login failed, error: " << rv
                 << " label: " << label << " pin: " << user_pin_;
    }

    return handle;
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

  std::string user_pin_;
  CK_ULONG slot_index_;
  CK_SLOT_ID slot_id_;

  DISALLOW_COPY_AND_ASSIGN(Pkcs11SlotHandlerOpenCryptoki);
};

// In "GLaptop mode" we generate the key pair using openssl, and call
// AddPrivateKey() instead, so GenerateKeyPair() needs to be a no-op.
class Pkcs11SlotHandlerGLaptop : public Pkcs11SlotHandlerOpenCryptoki {
 public:
  Pkcs11SlotHandlerGLaptop() {}

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
  DISALLOW_COPY_AND_ASSIGN(Pkcs11SlotHandlerGLaptop);
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
  if (!certificate_handler()->BuildCSR(slot_object->label(),
                                       utils::ValueAsUtf8String(subject),
                                       &request_)) {
    utils::ThrowV8Exception("Error building CSR.");
    return;
  }
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

// static
Pkcs11CertificateHandler* Certificate::certificate_handler_;

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

  // Set the 'content' property to the input content
  obj->Set(v8::String::NewSymbol("content"),
           content->ToString());
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
  slot->obj()->Set(v8::String::NewSymbol("keyIdentifier"), v8keyid);
  std::string keyid = std::string(*v8::String::Utf8Value(v8keyid));
  bool res = slot->SetKeyIdentifier(keyid);
  if (!res) {
    utils::ThrowV8Exception(std::string("Invalid key id: ") + keyid);
    return v8::False();
  }

  // Argumnet 1 is the passphrase (optional)
  std::string passphrase;  // defaults to empty
  if (!args[1]->IsUndefined()) {
    passphrase = utils::ValueAsUtf8String(args[1]);
    slot->SetPassphrase(passphrase);
  }

  // Access the slot handler and generate the public/private key pair
  res = slot->slot_handler()->GenerateKeyPair(slot->label(),
                                              slot->passphrase());
  if (!res) {
    LOG(ERROR) << "Unable to build key pair with id: " << keyid;
    return v8::False();
  }

  // Set the JS publicKey property
  v8::Handle<v8::String> v8_public_key =
      v8::String::New(slot->GetPublicKey().c_str());
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
  slot->slot_handler()->AddCertificate(slot->label(),
                                       cert->certificate(), cert->subject());

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
    certificate_handler_.reset(new Pkcs11CertificateHandlerLocalFile("", ""));
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

bool Pkcs11::InitializeOpenCryptoki(const std::string& test_cert,
                                    const std::string& engine) {
  LOG(INFO) << "Initializing pkcs11 with opencryptoki and engine:" << engine;

  slot_handler_.reset(new Pkcs11SlotHandlerOpenCryptoki());
  slot_handler_->Initialize();

  Pkcs11CertificateHandlerOpenSslPkcs11Engine* cert_handler =
      new Pkcs11CertificateHandlerOpenSslPkcs11Engine();
  cert_handler->Initialize();
  cert_handler->SetTestCertificate(test_cert);
  cert_handler->SetEngineConfigFile(engine);
  cert_handler->SetOutputDER();
  certificate_handler_.reset(cert_handler);

  return Initialize();
}

bool Pkcs11::InitializeGLaptop(const std::string& test_cert) {
  LOG(INFO) << "Initializing pkcs11 with opencryptoki, no ssl engine.";

  slot_handler_.reset(new Pkcs11SlotHandlerGLaptop());
  slot_handler_->Initialize();

  Pkcs11CertificateHandlerOpenSsl* cert_handler =
      new Pkcs11CertificateHandlerOpenSsl();
  cert_handler->Initialize();
  cert_handler->SetTestCertificate(test_cert);
  cert_handler->SetOutputDER();
  certificate_handler_.reset(cert_handler);

  return Initialize();
}

bool Pkcs11::InitializeOpenSSL(const std::string& test_cert) {
  LOG(INFO) << "Initializing pkcs11 with openssl.";

  slot_handler_.reset(new Pkcs11SlotHandlerInMemory());
  slot_handler_->Initialize();

  Pkcs11CertificateHandlerOpenSsl* cert_handler =
      new Pkcs11CertificateHandlerOpenSsl();
  cert_handler->Initialize();
  cert_handler->SetTestCertificate(test_cert);
  certificate_handler_.reset(cert_handler);

  return Initialize();
}

bool Pkcs11::InitializeLocalFiles(const std::string& csr,
                                  const std::string& cert) {
  slot_handler_.reset(new Pkcs11SlotHandlerInMemory());
  slot_handler_->Initialize();

  certificate_handler_.reset(
      new Pkcs11CertificateHandlerLocalFile(csr, cert));
  certificate_handler_->Initialize();

  return Initialize();
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
  pkcs11->slot_handler()->SetUserPin(pin);

  return v8::True();
}

static v8::Handle<v8::Value> dispatch_clearSlotObject(
    const v8::Arguments& args) {
  // Get the pkcs11 object.
  Pkcs11* pkcs11 = Pkcs11::Unwrap(args.This());
  if (pkcs11 == NULL) {
    utils::ThrowV8Exception("Method called on incorrect object type.");
    return v8::False();
  }
  if (args.Length() < 2) {
    utils::ThrowV8Exception("Not enough parameters.");
    return v8::False();
  }

  // Argument 0 is a SlotObject object.
  SlotObject* slotobject = SlotObject::GetFromArg(args, 0);
  if (!slotobject) {
    utils::ThrowV8Exception("First argument must be a SlotObject.");
    return v8::False();
  }

  // Argument 1 is a key identifier
  std::string keyid = utils::ValueAsUtf8String(args[1]);

  // Remove the contents of the slot in the slot handler.
  v8::Local<v8::Value> slotlabel =
      slotobject->obj()->Get(v8::String::NewSymbol("label"));
  std::string label = utils::ValueAsUtf8String(slotlabel);
  pkcs11->slot_handler()->RemoveObjects(label, keyid);

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
  template_object->Set(v8::String::NewSymbol("clear"),
                       v8::FunctionTemplate::New(dispatch_clearSlotObject),
                       v8::ReadOnly);
  template_object->Set(v8::String::NewSymbol("slots"),
                       v8::Object::New(),
                       v8::ReadOnly);
}

} // namespace entd
