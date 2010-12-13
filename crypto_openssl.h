// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ENTD_CRYPTO_OPENSSL_H_
#define ENTD_CRYPTO_OPENSSL_H_

#include <string>
#include <map>
#include <openssl/engine.h>
#include <openssl/x509.h>

#include "base/basictypes.h"
#include "v8.h"

#include "entd/scriptable.h"

namespace entd {

namespace crypto {

class OpenSSL : public Scriptable<OpenSSL> {
 public:
  static const std::string class_name() {
    return "entd.crypto.OpenSSL";
  };
  static bool InitializeTemplate(v8::Handle<v8::FunctionTemplate> ctor_t);
  static bool StaticInitialize(const char* config_name);
  static bool StaticFinalize();

  v8::Handle<v8::Value> Construct(const v8::Arguments& args) {
    return ThrowNoScriptableConstructor();
  }

  class Engine : public Scriptable<Engine> {
   public:
    static const std::string class_name() {
      return "entd.crypto.OpenSSL.Engine";
    };

    Engine() : engine_id_(""), engine_(NULL) {}
    ~Engine() {}

    static bool InitializeTemplate(v8::Handle<v8::FunctionTemplate> ctor_t);
    v8::Handle<v8::Value> Construct(const v8::Arguments& args);
    bool Initialize(const char* engine_id);

    v8::Handle<v8::Value> CreateCSR(const v8::Arguments& args);
    v8::Handle<v8::Value> Dispose(const v8::Arguments& args);

   private:
    std::string engine_id_;
    ENGINE* engine_;
  };

  class CSR : public Scriptable<CSR> {
   public:
    static const std::string class_name() {
      return "entd.crypto.OpenSSL.CSR";
    };

    // Request type.
    typedef enum {
      CSR_FORMAT_UNKNOWN,
      CSR_FORMAT_PEM_TEXT,
    } RequestType;

    CSR() : request_(NULL) {}

    bool Initialize(X509_REQ* request);
    static bool InitializeTemplate(v8::Handle<v8::FunctionTemplate> ctor_t);

    v8::Handle<v8::Value> Construct(const v8::Arguments& args) {
      return ThrowNoScriptableConstructor();
    }

    v8::Handle<v8::Value> ToFormat(const v8::Arguments& args);
    v8::Handle<v8::Value> Dispose(const v8::Arguments& args);

   private:
    X509_REQ* request_;
  };

  class X509 : public Scriptable<X509> {
   public:
    static const std::string class_name() {
      return "entd.crypto.OpenSSL.X509";
    };

    // Certificate type.
    //
    // A certificate can be encoded in either DER or PEM. As PEM is already
    // a text representation and other functions might require a binary
    // representation, X509_FORMAT_PEM_TEXT can be used to input or output
    // the certificate in the original textual representation instead of
    // default binary hexadecimal text form.
    typedef enum {
      X509_FORMAT_UNKNOWN,
      X509_FORMAT_PEM,
      X509_FORMAT_PEM_TEXT,
      X509_FORMAT_DER,
    } CertificateType;

    X509() : certificate_(NULL) {}

    bool Initialize(::X509* certificate);
    static bool InitializeTemplate(v8::Handle<v8::FunctionTemplate> ctor_t);

    v8::Handle<v8::Value> Construct(const v8::Arguments& args);

    v8::Handle<v8::Value> ToFormat(const v8::Arguments& args);
    v8::Handle<v8::Value> Dispose(const v8::Arguments& args);

   private:
    CertificateType certificate_type_;
    ::X509* certificate_;
  };
};

} // namespace crypto

} // namespace entd

#endif // ENTD_CRYPTO_OPENSSL_H_
