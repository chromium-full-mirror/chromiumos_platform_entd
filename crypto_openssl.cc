// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <chromeos/utility.h>

#include <openssl/bio.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include "entd/crypto_openssl.h"
#include "entd/utils.h"

// Reflect OpenSSL constants into JavaScript.
#define SET_CK_CONST(self, name)                                            \
  self->Set(v8::String::New(#name),                                         \
            v8::Integer::NewFromUnsigned(name), v8::ReadOnly)

namespace entd {

namespace crypto {

// Helper functions.
std::string ValueToHex(const v8::Handle<v8::Value>& option_value);

// static
bool OpenSSL::InitializeTemplate(v8::Handle<v8::FunctionTemplate> ctor_t) {
  ctor_t->Set(v8::String::NewSymbol("Engine"),
              OpenSSL::Engine::constructor_template());
  ctor_t->Set(v8::String::NewSymbol("CSR"),
              OpenSSL::CSR::constructor_template());
  ctor_t->Set(v8::String::NewSymbol("X509"),
              OpenSSL::X509::constructor_template());

  return true;
}

// static
bool OpenSSL::StaticInitialize(const char* config_name) {
  OPENSSL_config(config_name);
  LOG(INFO) << "OpenSSL initialized: " << config_name;
  return true;
}

// static
bool OpenSSL::StaticFinalize() {
  CONF_modules_free();
  LOG(INFO) << "OpenSSL uninitialized.";
  return true;
}

// static
bool OpenSSL::Engine::InitializeTemplate(
  v8::Handle<v8::FunctionTemplate> ctor_t) {
  v8::Handle<v8::ObjectTemplate> instance_t = ctor_t->InstanceTemplate();

  BindMethod(instance_t, &OpenSSL::Engine::CreateCSR, "createCSR");
  BindMethod(instance_t, &OpenSSL::Engine::Dispose, "dispose");

  return true;
}

v8::Handle<v8::Value> OpenSSL::Engine::Construct(const v8::Arguments& args) {
  if (args.Length() < 1)
    return ThrowException("Missing required parameter: engine_id.");
  if (!args[0]->IsString())
    return ThrowException("Invalid parameter type: engine_id.");

  v8::String::AsciiValue engine_id(args[0]);

  OpenSSL::Engine::Reference engine(args.This());
  if (!engine->Initialize(*engine_id))
    return ThrowException("Cannot create OpenSSL object");

  return engine->js_object();
}

// Initialize OpenSSL engine.
bool OpenSSL::Engine::Initialize(const char* engine_id) {
  engine_id_.assign(engine_id);

  // Retrieve SSL engine.
  engine_ = ENGINE_by_id(engine_id_.c_str());
  if (!engine_) {
    LOG(ERROR) << "Cannot access OpenSSL engine for PKCS#11: " << engine_id;
    ThrowException("Cannot access OpenSSL engine for PKCS#11");
    return false;
  }

  // Initialize engine.
  if (!ENGINE_init(engine_)) {
    ENGINE_free(engine_);
    engine_ = NULL;
    LOG(ERROR) << "Cannot initialize OpenSSL engine for PKCS#11";
    ThrowException("Cannot initialize OpenSSL engine for PKCS#11");
    return false;
  }

  return true;
}

v8::Handle<v8::Value> OpenSSL::Engine::Dispose(const v8::Arguments& args) {
  if (engine_ != NULL) {
    ENGINE_free(engine_);
    engine_ = NULL;
    return v8::True();
  }

  return v8::False();
}

// Find the first instance of 'c' in string 's', skipping over escape
// sequences (e.g if c == '/' skip '\/').
std::string::size_type FindUnescaped(const std::string& s, char c,
                                     std::string::size_type start) {
  if (start >= s.length())
    return std::string::npos;
  for (std::string::const_iterator iter = s.begin() + start;
       iter != s.end(); ++iter) {
    char c1 = *iter;
    if (c1 == '\\') {
      ++iter;  // skip the '\', the loop will skip the next char.
      if (iter == s.end())
        break;
    } else if (c1 == c) {
      return iter - s.begin();
    }
  }
  return std::string::npos;
}

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
    ++start;  // skip leading '/'.

    // Find the next '/' (or npos to indicate the end of the string).
    std::string::size_type end = FindUnescaped(subject, '/', start);

    // Build the token amd split it at '=' into type/value.
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

    // Add the type/value pair to the X509_NAME.
    const unsigned char* bytes =
        reinterpret_cast<const unsigned char*>(value.c_str());
    if (!X509_NAME_add_entry_by_txt(name, type.c_str(), MBSTRING_ASC,
                                    bytes, value.size(), -1, 0)) {
      return false;
    }

    start = end;  // start at next '/' (or npos).
  }

  return true;
}

// Creates a new Certificate Request.
//
// $1 = Private Key path to load.
// $2 = Subject Distinguished Name.
//
// Returns: True if successful, False otherwise.
v8::Handle<v8::Value> OpenSSL::Engine::CreateCSR(const v8::Arguments& args) {
  if (args.Length() < 1)
    return ThrowException("Missing required parameter: key");

  std::string key = utils::ValueAsUtf8String(args[0]);

  if (args.Length() < 2)
    return ThrowException("Missing required parameter: X.509 DN");

  v8::String::AsciiValue dn(args[1]);

  v8::Handle<v8::Value> result;
  CSR::Reference csr;
  v8::Handle<v8::Value> csr_object = v8::Undefined();
  EVP_PKEY* private_key = NULL;
  X509_NAME* name = NULL;
  X509_REQ* req = NULL;

  // Retrieve a handle to the private key.
  private_key = ENGINE_load_private_key(engine_, key.c_str(), NULL, NULL);
  if (!private_key) {
    result = ThrowException("Cannot load private key: " + key);
    goto create_csr_done;
  }

  // Construct subject DN.
  name = X509_NAME_new();
  if (!name) {
    result = ThrowException("Cannot create X.509 name.");
    goto create_csr_done;
  }
  if (!ParseSubject(*dn, name)) {
    result = ThrowException("Invalid subject: " + std::string(*dn));
    goto create_csr_done;
  }

  // Generate a new X.509 CSR.
  req = X509_REQ_new();
  if (!req) {
    result = ThrowException("Cannot create X.509 request.");
    goto create_csr_done;
  }
  if (!X509_REQ_set_version(req, 0)) {
    result = ThrowException("Cannot set request version.");
    goto create_csr_done;
  }
  if (!X509_REQ_set_subject_name(req, name)) {
    result = ThrowException("Cannot set request name.");
    goto create_csr_done;
  }
  if (!X509_REQ_set_pubkey(req, private_key)) {
    result = ThrowException("Cannot set public key.");
    goto create_csr_done;
  }
  if (!X509_REQ_sign(req, private_key, EVP_sha1())) {
    result = ThrowException("Cannot sign request.");
    goto create_csr_done;
  }

  // Create CSR object to return.
  csr = CSR::New();

  // Ownership of request is relinquished to CSR object. DO NOT free the
  // object in this context.
  if (!csr->Initialize(req)) {
    result = ThrowException("Cannot allocate CSR result.");
    goto create_csr_done;
  }

  csr_object = csr->js_object();
  result = csr_object;

create_csr_done:
  if (private_key)
    EVP_PKEY_free(private_key);
  if (name)
    X509_NAME_free(name);
  if (result != csr_object)
    X509_REQ_free(req);

  return result;
}

// static
bool OpenSSL::CSR::InitializeTemplate(v8::Handle<v8::FunctionTemplate> ctor_t) {
  v8::Handle<v8::ObjectTemplate> instance_t = ctor_t->InstanceTemplate();

  // export flags.
  SET_CK_CONST(ctor_t, CSR_FORMAT_PEM_TEXT);

  BindMethod(instance_t, &OpenSSL::CSR::Dispose, "dispose");
  BindMethod(instance_t, &OpenSSL::CSR::ToFormat, "toFormat");

  return true;
}

bool OpenSSL::CSR::Initialize(X509_REQ* request) {
  request_ = request;
  return (request_ != NULL);
}

v8::Handle<v8::Value> OpenSSL::CSR::Dispose(const v8::Arguments& args) {
  if (request_ != NULL) {
    X509_REQ_free(request_);
    request_ = NULL;
    return v8::True();
  }

  return v8::False();
}

v8::Handle<v8::Value> OpenSSL::CSR::ToFormat(const v8::Arguments& args) {
  RequestType target_format = CSR_FORMAT_PEM_TEXT;

  if (args.Length() > 0)
    target_format = static_cast<RequestType>(args[0]->Uint32Value());

  OpenSSL::CSR* csr = OpenSSL::CSR::UnwrapOrThrow(args.This(), "this");
  if (!csr)
    return v8::Undefined();

  if (target_format != CSR_FORMAT_PEM_TEXT)
    return ThrowException("Unsupported request target format.");

  BIO* mem = BIO_new(BIO_s_mem());
  if (!mem)
    return ThrowException("Cannot allocate memory.");

  if (!PEM_write_bio_X509_REQ(mem, csr->request_)) {
    BIO_free(mem);
    return ThrowException("Cannot serialize request");
  }

  char* csrText = NULL;
  long csrSize = BIO_get_mem_data(mem, &csrText);
  if (!csrSize || !csrText) {
    BIO_free(mem);
    return ThrowException("Cannot read serialized request");
  }

  // Prepare result contents.
  std::string csrTextPem = std::string(csrText, csrSize);
  v8::Handle<v8::String> result = v8::String::New(csrText, csrSize);

  BIO_free(mem);

  return result;
}

// static
bool OpenSSL::X509::InitializeTemplate(
  v8::Handle<v8::FunctionTemplate> ctor_t) {
  v8::Handle<v8::ObjectTemplate> instance_t = ctor_t->InstanceTemplate();

  // export flags.
  SET_CK_CONST(ctor_t, X509_FORMAT_PEM);
  SET_CK_CONST(ctor_t, X509_FORMAT_PEM_TEXT);
  SET_CK_CONST(ctor_t, X509_FORMAT_DER);

  BindMethod(instance_t, &OpenSSL::X509::Dispose, "dispose");
  BindMethod(instance_t, &OpenSSL::X509::ToFormat, "toFormat");

  return true;
}

::X509* PEMStringToX509(const v8::String::AsciiValue& pem_string,
                        OpenSSL::X509::CertificateType certificate_type) {
  chromeos::Blob pem;
  const char* cert_data;

  if (certificate_type == OpenSSL::X509::X509_FORMAT_PEM_TEXT) {
    cert_data = *pem_string;
  } else {
    pem = chromeos::AsciiDecode(*pem_string);
    cert_data = reinterpret_cast<char*>(&pem[0]);
  }

  BIO* mem = BIO_new(BIO_s_mem());
  if (!mem) {
    LOG(ERROR) << "Cannot allocate memory.";
    utils::ThrowV8Exception("Cannot allocate memory.");
    return NULL;
  }
  if (!BIO_puts(mem, cert_data)) {
    BIO_free(mem);
    LOG(ERROR) << "Cannot deserialize certificate.";
    utils::ThrowV8Exception("Cannot deserialize certificate.");
    return NULL;
  }

  ::X509* cert = PEM_read_bio_X509(mem, NULL, 0, NULL);
  if (!cert) {
    BIO_free(mem);
    LOG(ERROR) << "Failed to read certificate.";
    utils::ThrowV8Exception("Failed to read certificate.");
    return NULL;
  }

  BIO_free(mem);

  return cert;
}

::X509* DERStringToX509(const v8::String::AsciiValue& der_string) {
  chromeos::Blob pem = chromeos::AsciiDecode(*der_string);
  const unsigned char* pem_data = &pem[0];

  ::X509* cert = X509_new();
  if (!cert) {
    LOG(ERROR) << "Cannot allocate memory for certificate.";
    utils::ThrowV8Exception("Cannot allocate memory for certificate.");
    return NULL;
  }
  if (!d2i_X509(&cert, &pem_data, pem.size())) {
    X509_free(cert);
    LOG(ERROR) << "Cannot extract certificate.";
    utils::ThrowV8Exception("Cannot extract certificate.");
    return NULL;
  }

  return cert;
}

v8::Handle<v8::Value> OpenSSL::X509::Construct(const v8::Arguments& args) {
  if (args.Length() < 1)
    return ThrowException("Missing required parameter: certificate.");
  if (!args[0]->IsString())
    return ThrowException("Invalid parameter type: certificate.");

  v8::String::AsciiValue certificate_input(args[0]);

  if (args.Length() < 2)
    return ThrowException("Missing required parameter: certificate type.");

  ::X509* certificate = NULL;
  CertificateType certificate_type =
    static_cast<CertificateType>(args[1]->Uint32Value());

  switch( certificate_type ) {
    case X509_FORMAT_PEM:
    case X509_FORMAT_PEM_TEXT:
      certificate = PEMStringToX509(certificate_input, certificate_type);
      break;

    case X509_FORMAT_DER:
      certificate = DERStringToX509(certificate_input);
      break;

    default:
      return ThrowException("Unknown certificate type.");
  }

  if (certificate != NULL) {
    OpenSSL::X509::Reference x509(args.This());
    if (!x509->Initialize(certificate))
      return ThrowException("Cannot create X.509 certificate object");

    return x509->js_object();
  }

  return ThrowException("Cannot create X.509 certificate object");
}

bool OpenSSL::X509::Initialize(::X509* certificate) {
  certificate_ = certificate;
  return true;
}

v8::Handle<v8::Value> OpenSSL::X509::Dispose(const v8::Arguments& args) {
  if (certificate_ != NULL) {
    X509_free(certificate_);
    certificate_ = NULL;
    return v8::True();
  }

  return v8::False();
}

v8::Handle<v8::Value> X509ToPEMString(::X509* certificate,
                                      OpenSSL::X509::CertificateType format) {
  BIO* mem = BIO_new(BIO_s_mem());
  if (!mem)
    return utils::ThrowV8Exception("Cannot allocate memory.");

  if (!PEM_write_bio_X509(mem, certificate)) {
    BIO_free(mem);
    return utils::ThrowV8Exception("Cannot serialize certificate.");
  }

  char* certText = NULL;
  long certSize = BIO_get_mem_data(mem, &certText);
  if (!certSize || !certText) {
    BIO_free(mem);
    return utils::ThrowV8Exception("Cannot read serialized certificate");
  }

  // Prepare result contents.
  v8::Handle<v8::String> result;
  if (format == OpenSSL::X509::X509_FORMAT_PEM_TEXT) {
    std::string certTextPem = std::string(certText, certSize);
    result = v8::String::New(certText, certSize);
  } else {
    chromeos::Blob resultBlob(certText, certText + certSize);
    std::string certTextHex = chromeos::AsciiEncode(resultBlob);
    result = v8::String::New(certTextHex.c_str(), certTextHex.length());
  }

  BIO_free(mem);

  return result;
}

v8::Handle<v8::Value> X509ToDERString(::X509* certificate) {
  unsigned char* certBytes = NULL;
  int certBytesLen = i2d_X509(certificate, &certBytes);
  if (!certBytesLen || !certBytes)
    return utils::ThrowV8Exception("Cannot serialize certificate.");

  // Prepare result contents.
  chromeos::Blob certBlob(certBytes, certBytes + certBytesLen);
  std::string certTextDer = chromeos::AsciiEncode(certBlob);
  return v8::String::New(certTextDer.c_str(), certTextDer.length());
}

v8::Handle<v8::Value> OpenSSL::X509::ToFormat(const v8::Arguments& args) {
  CertificateType target_format = X509_FORMAT_PEM_TEXT;

  if (args.Length() > 0)
    target_format = static_cast<CertificateType>(args[0]->Uint32Value());

  switch( target_format ) {
    case X509_FORMAT_PEM:
    case X509_FORMAT_PEM_TEXT:
      return X509ToPEMString(certificate_, target_format);

    case X509_FORMAT_DER:
      return X509ToDERString(certificate_);

    default:
      return ThrowException("Unknown format target type.");
  }
}

}  // namespace crypto

}  // namespace entd
