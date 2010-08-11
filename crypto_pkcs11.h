// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ENTD_CRYPTO_PKCS11_H_
#define ENTD_CRYPTO_PKCS11_H_

#include <string>
#include <map>

#include "base/basictypes.h"
#include "opencryptoki/pkcs11.h"
#include "v8.h"

#include "entd/scriptable.h"

namespace entd {

namespace crypto {

class Pkcs11 : public Scriptable<Pkcs11> {
 public:
  static const std::string class_name() { return "entd.crypto.Pkcs11"; };

  class Token : public Scriptable<Token> {
   public:
    static const std::string class_name() {
      return "entd.crypto.Pkcs11.Token";
    };

    bool Initialize(CK_SLOT_ID slot_id);
    static bool InitializeTemplate(v8::Handle<v8::FunctionTemplate> ctor_t);

    v8::Handle<v8::Value> Construct(const v8::Arguments& args) {
      return ThrowNoScriptableConstructor();
    }

    // Call C_GetTokenInfo(), and copy the results to the js_object().
    bool Refresh();

    // Stubs for PKCS#11 C_* functions of the same name.
    v8::Handle<v8::Value> InitToken(const v8::Arguments& args);
    v8::Handle<v8::Value> InitPin(const v8::Arguments& args);
    v8::Handle<v8::Value> OpenSession(const v8::Arguments& args);
    v8::Handle<v8::Value> CloseAllSessions(const v8::Arguments& args);

    // Invoke the 'bool Refresh()' method from script.
    v8::Handle<v8::Value> CallRefresh(const v8::Arguments& args);

   private:
    CK_SLOT_ID slot_id_;
  };

  class Slot : public Scriptable<Slot> {
   public:
    static const std::string class_name() {
      return "entd.crypto.Pkcs11.Slot";
    };

    bool Initialize(CK_SLOT_ID slot_id);
    static bool InitializeTemplate(v8::Handle<v8::FunctionTemplate> ctor_t);

    v8::Handle<v8::Value> Construct(const v8::Arguments& args) {
      return ThrowNoScriptableConstructor();
    }

    // Call C_GetSlotInfo(), and copy the results to the js_object().
    bool Refresh();

    // Invoke the 'bool Refresh()' method from script.
    v8::Handle<v8::Value> CallRefresh(const v8::Arguments& args);

    // Property Accessor for slot.token.
    static v8::Handle<v8::Value> GetToken(v8::Local<v8::String> property,
                                          const v8::AccessorInfo& info);

   private:
    CK_SLOT_ID slot_id_;
    Pkcs11::Token::Reference token_;
  };

  class Slots : public Scriptable<Slots> {
   public:
    typedef std::map<uint32_t, Pkcs11::Slot::Reference> SlotMap;

    static const std::string class_name() {
      return "entd.crypto.Pkcs11.Slots";
    };

    bool Initialize();
    static bool InitializeTemplate(v8::Handle<v8::FunctionTemplate> ctor_t);

    v8::Handle<v8::Value> Construct(const v8::Arguments& args) {
      return ThrowNoScriptableConstructor();
    }

    // Various methods to support lazy indexed properties (eg, slots[0].)
    static v8::Handle<v8::Value> GetIndexedProperty(
        uint32_t index, const v8::AccessorInfo& info);
    static v8::Handle<v8::Value> SetIndexedProperty(
        uint32_t index, v8::Local<v8::Value> value,
        const v8::AccessorInfo& info);
    static v8::Handle<v8::Boolean> QueryIndexedProperty(
        uint32_t index, const v8::AccessorInfo& info);
    static v8::Handle<v8::Boolean> DeleteIndexedProperty(
        uint32_t index, const v8::AccessorInfo& info);
    static v8::Handle<v8::Array> EnumerateIndexedProperties(
        const v8::AccessorInfo& info);

    // Property Accessor for slots.length.
    static v8::Handle<v8::Value> GetLength(v8::Local<v8::String> property,
                                           const v8::AccessorInfo& info);

   private:
    SlotMap slot_map_;
  };

  class Session : public Scriptable<Session> {
   public:
    static const std::string class_name() {
      return "entd.crypto.Pkcs11.Session";
    };

    Session() : session_handle_(0) {}
    ~Session() {
      if (session_handle_)
        C_CloseSession(session_handle_);
    }

    bool Initialize(CK_SLOT_ID slot_id, CK_SESSION_HANDLE session_handle);
    static bool InitializeTemplate(v8::Handle<v8::FunctionTemplate> ctor_t);

    v8::Handle<v8::Value> Construct(const v8::Arguments& args) {
      return ThrowNoScriptableConstructor();
    }

    // Call C_GetSessionInfo(), and copy the results to the js_object().
    bool Refresh();

    // Stubs for PKCS#11 C_* functions of the same name.
    v8::Handle<v8::Value> Close(const v8::Arguments& args);
    v8::Handle<v8::Value> Login(const v8::Arguments& args);
    v8::Handle<v8::Value> Logout(const v8::Arguments& args);
    v8::Handle<v8::Value> InitPin(const v8::Arguments& args);
    v8::Handle<v8::Value> SetPin(const v8::Arguments& args);
    v8::Handle<v8::Value> FindObjects(const v8::Arguments& args);
    v8::Handle<v8::Value> CreateObject(const v8::Arguments& args);

    // Invoke the 'bool Refresh()' method from script.
    v8::Handle<v8::Value> CallRefresh(const v8::Arguments& args);

   private:
    CK_SLOT_ID slot_id_;
    CK_SESSION_HANDLE session_handle_;
  };

  bool Initialize();
  static bool InitializeTemplate(v8::Handle<v8::FunctionTemplate> ctor_t);

  v8::Handle<v8::Value> Construct(const v8::Arguments& args);

 private:
  // Initialize the PKCS#11 API, used by ::Initialize() and ::Construct().
  //
  // This can be called multiple times.  It will keep trying to initialize the
  // library until it succeeds, then it will become a no-op.
  static CK_RV InitializeLibrary();
};

} // namespace crypto

} // namespace entd

#endif // ENTD_CRYPTO_PKCS11_H_
