// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "entd/crypto_pkcs11.h"

#include "base/logging.h"
#include "base/string_util.h"

#include "entd/utils.h"

namespace entd {

namespace crypto {

// Dirty little macros to make copying things from PKCS#11 structs a little
// cleaner...
#define SET_CK_STRING(self, record, field)                                  \
  self->Set(v8::String::New(#field),                                        \
            v8::String::New(reinterpret_cast<char *>(&record.field[0]),     \
                            CkStringLength(record.field,                    \
                                           sizeof(record.field))))

#define SET_CK_ULONG(self, record, field)                                   \
  self->Set(v8::String::New(#field),                                        \
            v8::Integer::NewFromUnsigned(record.field))

// Reflect PKCS#11 constants into JavaScript
#define SET_CK_CONST(self, name)                                            \
  self->Set(v8::String::New(#name),                                         \
            v8::Integer::NewFromUnsigned(name), v8::ReadOnly)

// Check that a CK_RV value is CKR_OK, throw a V8 exception if it is not.
bool OkOrThrow(CK_RV rv) {
  if (rv != CKR_OK) {
    unsigned int urv = rv;
    utils::ThrowV8Exception("PKCS#11 Error: 0x" + StringPrintf("%08X", urv));
    return false;
  }

  return true;
}

// Check that a CK_RV value is CKR_OK, log a warning if it is not.
bool OkOrWarn(CK_RV rv) {
  if (rv != CKR_OK) {
    unsigned int urv = rv;
    LOG(WARNING) << "PKCS#11 Error: 0x" << StringPrintf("%08X", urv);
    return false;
  }

  return true;
}

// Most strings returned by the PKCS#11 API are padded with spaces to a
// known length.  This function returns the length of a string minus the
// trailing space.  Some fields seem to ignore the spec and null pad rather
// than space pad, so we deal with those here too.
int CkStringLength(CK_CHAR_PTR value, CK_ULONG length) {
  for (CK_ULONG i = length; i > 0; --i) {
    if (value[i - 1] != ' ' && value[i - 1] != '\0')
      return i;
  }

  return 0;
}

bool Pkcs11::Slots::Initialize() {
  return true;
}

// static
bool Pkcs11::Slots::InitializeTemplate(
    v8::Handle<v8::FunctionTemplate> ctor_t) {
  LOG(INFO) << "Initialize slots template";

  v8::Handle<v8::ObjectTemplate> instance_t = ctor_t->InstanceTemplate();

  instance_t->SetAccessor(v8::String::New("length"),
                          GetLength,
                          0,  // Length is readonly, so setter is NULL
                          v8::Handle<v8::Value>(),  // Don't need any data.
                          v8::DEFAULT,  // DEFAULT AccessControl
                          v8::DontDelete);

  instance_t->SetIndexedPropertyHandler(GetIndexedProperty,
                                        SetIndexedProperty,
                                        QueryIndexedProperty,
                                        DeleteIndexedProperty,
                                        EnumerateIndexedProperties);

  return true;
}

// static
v8::Handle<v8::Value> Pkcs11::Slots::GetIndexedProperty(
    uint32_t index, const v8::AccessorInfo& info) {
  Pkcs11::Slots* slots = Pkcs11::Slots::UnwrapOrThrow(info.This(), "this");
  if (!slots)
    return v8::Undefined();

  CK_ULONG num_slots = 0;
  CK_RV rv = C_GetSlotList(FALSE, NULL, &num_slots);
  if (!OkOrThrow(rv))
    return v8::Undefined();

  if (index >= num_slots)
    return ThrowException("Index out of range");

  SlotMap::iterator it = slots->slot_map_.find(index);
  if (it == slots->slot_map_.end()) {
    // We haven't created a Pkcs11::Slot for this slot id yet, time to make one.
    Pkcs11::Slot::Reference slot(Pkcs11::Slot::New());
    if (slot.IsEmpty() || !slot->Initialize(index))
      return ThrowException("Error initializing slot");

    slots->slot_map_[index] = slot;
    return slot->js_object();
  }

  return it->second->js_object();
}

// static
v8::Handle<v8::Value> Pkcs11::Slots::SetIndexedProperty(
    uint32_t index, v8::Local<v8::Value> value, const v8::AccessorInfo& info) {
  Pkcs11::Slots* slots = Pkcs11::Slots::UnwrapOrThrow(info.This(), "this");
  if (!slots)
    return v8::Undefined();

  return ThrowException("Attempt to write to read only property");
}

// static
v8::Handle<v8::Boolean> Pkcs11::Slots::QueryIndexedProperty(
    uint32_t index, const v8::AccessorInfo& info) {
  Pkcs11::Slots* slots = Pkcs11::Slots::UnwrapOrWarn(info.This(), "this");
  if (!slots)
    return v8::False();

  CK_ULONG num_slots = 0;
  CK_RV rv = C_GetSlotList(FALSE, NULL, &num_slots);
  if (!OkOrWarn(rv))
    return v8::False();

  if (index >= num_slots)
    return v8::False();

  return v8::True();
}

// static
v8::Handle<v8::Boolean> Pkcs11::Slots::DeleteIndexedProperty(
    uint32_t index, const v8::AccessorInfo& info) {
  Pkcs11::Slots* slots = Pkcs11::Slots::UnwrapOrThrow(info.This(), "this");
  if (!slots)
    return v8::False();

  ThrowException("Attempt to delete read only property");
  return v8::False();
}

// static
v8::Handle<v8::Array> Pkcs11::Slots::EnumerateIndexedProperties(
    const v8::AccessorInfo& info) {
  Pkcs11::Slots* slots = Pkcs11::Slots::UnwrapOrWarn(info.This(), "this");
  if (!slots)
    return v8::Array::New();

  CK_ULONG num_slots = 0;
  CK_RV rv = C_GetSlotList(FALSE, NULL, &num_slots);
  if (!OkOrThrow(rv))
    return v8::Array::New();

  v8::Handle<v8::Array> ary = v8::Array::New(num_slots);

  for (uint32_t i = 0; i < num_slots; ++i)
    ary->Set(i, v8::Integer::New(i));

  return ary;
}

// static
v8::Handle<v8::Value> Pkcs11::Slots::GetLength(v8::Local<v8::String> property,
                                               const v8::AccessorInfo& info) {
  Pkcs11::Slots* slots = Pkcs11::Slots::UnwrapOrThrow(info.This(), "this");
  if (!slots)
    return v8::Undefined();

  CK_ULONG num_slots = 0;
  CK_RV rv = C_GetSlotList(FALSE, NULL, &num_slots);
  if (!OkOrThrow(rv))
    return v8::Undefined();

  return v8::Integer::NewFromUnsigned(num_slots);
}

bool Pkcs11::Slot::Initialize(CK_SLOT_ID slot_id) {
  slot_id_ = slot_id;
  return Refresh();
}

// static
bool Pkcs11::Slot::InitializeTemplate(v8::Handle<v8::FunctionTemplate> ctor_t) {
  v8::Handle<v8::ObjectTemplate> instance_t = ctor_t->InstanceTemplate();

  SET_CK_CONST(ctor_t, CKF_TOKEN_PRESENT);
  SET_CK_CONST(ctor_t, CKF_REMOVABLE_DEVICE);
  SET_CK_CONST(ctor_t, CKF_HW_SLOT);

  BindMethod(instance_t, &Pkcs11::Slot::CallRefresh, "refresh");
  instance_t->SetAccessor(v8::String::New("token"),
                          GetToken,
                          0,  // Token is readonly, so setter is NULL
                          v8::Handle<v8::Value>(),  // Don't need any data.
                          v8::DEFAULT,  // DEFAULT AccessControl
                          v8::DontDelete);

  return true;
}

v8::Handle<v8::Value> Pkcs11::Slot::CallRefresh(const v8::Arguments& args) {
  if (!Refresh())
    return ThrowException("Unexpected error");

  return v8::Undefined();
}

bool Pkcs11::Slot::Refresh() {
  CK_SLOT_INFO slot_info;
  CK_RV rv = C_GetSlotInfo(slot_id_, &slot_info);
  if (!OkOrWarn(rv))
    return false;

  v8::Handle<v8::Object> self = js_object();
  if (self.IsEmpty())
    return false;

  SET_CK_STRING(self, slot_info, slotDescription);
  SET_CK_STRING(self, slot_info, manufacturerID);

  SET_CK_ULONG(self, slot_info, flags);

  if (slot_info.flags & CKF_TOKEN_PRESENT) {
    if (!token_.Copy(Pkcs11::Token::New()) || !token_->Initialize(slot_id_)) {
      LOG(ERROR) << "Error creating Pkcs11::Token instance";
      return false;
    }
  } else {
    token_.set_native_ptr(NULL);
  }

  return true;
}

// static
v8::Handle<v8::Value> Pkcs11::Slot::GetToken(v8::Local<v8::String> property,
                                             const v8::AccessorInfo& info) {
  Pkcs11::Slot* slot = Pkcs11::Slot::UnwrapOrThrow(info.This(), "this");
  if (!slot)
    return v8::Undefined();

  if (slot->token_.IsEmpty())
    return v8::Null();

  return slot->token_.js_object();
}

bool Pkcs11::Token::Initialize(CK_SLOT_ID slot_id) {
  slot_id_ = slot_id;
  return Refresh();
}

// static
bool Pkcs11::Token::InitializeTemplate(
    v8::Handle<v8::FunctionTemplate> ctor_t) {

  // Opencryptoki defaults, as per their README: http://tinyurl.com/2cafmsp
  ctor_t->Set(v8::String::New("DEFAULT_SO_PIN"),
              v8::String::New("87654321"));
  ctor_t->Set(v8::String::New("DEFAULT_USER_PIN"),
              v8::String::New("12345678"));

  // openSession() flags...
  SET_CK_CONST(ctor_t, CKF_RW_SESSION);

  // token flags...
  SET_CK_CONST(ctor_t, CKF_RNG);
  SET_CK_CONST(ctor_t, CKF_WRITE_PROTECTED);
  SET_CK_CONST(ctor_t, CKF_LOGIN_REQUIRED);
  SET_CK_CONST(ctor_t, CKF_USER_PIN_INITIALIZED);
  SET_CK_CONST(ctor_t, CKF_RESTORE_KEY_NOT_NEEDED);
  SET_CK_CONST(ctor_t, CKF_CLOCK_ON_TOKEN);
  SET_CK_CONST(ctor_t, CKF_PROTECTED_AUTHENTICATION_PATH);
  SET_CK_CONST(ctor_t, CKF_DUAL_CRYPTO_OPERATIONS);
  SET_CK_CONST(ctor_t, CKF_TOKEN_INITIALIZED);
  SET_CK_CONST(ctor_t, CKF_USER_PIN_COUNT_LOW);
  SET_CK_CONST(ctor_t, CKF_USER_PIN_FINAL_TRY);
  SET_CK_CONST(ctor_t, CKF_USER_PIN_LOCKED);
  SET_CK_CONST(ctor_t, CKF_USER_PIN_TO_BE_CHANGED);
  SET_CK_CONST(ctor_t, CKF_SO_PIN_COUNT_LOW);
  SET_CK_CONST(ctor_t, CKF_SO_PIN_FINAL_TRY);
  SET_CK_CONST(ctor_t, CKF_SO_PIN_LOCKED);
  SET_CK_CONST(ctor_t, CKF_SO_PIN_TO_BE_CHANGED);

  v8::Handle<v8::ObjectTemplate> instance_t = ctor_t->InstanceTemplate();

  BindMethod(instance_t, &Pkcs11::Token::CallRefresh, "refresh");
  BindMethod(instance_t, &Pkcs11::Token::InitToken, "initToken");
  BindMethod(instance_t, &Pkcs11::Token::OpenSession, "openSession");

  return true;
}

bool Pkcs11::Token::Refresh() {
  CK_TOKEN_INFO token_info;
  CK_RV rv = C_GetTokenInfo(slot_id_, &token_info);
  if (!OkOrWarn(rv))
    return false;

  v8::Handle<v8::Object> self = js_object();
  if (self.IsEmpty())
    return false;

  SET_CK_STRING(self, token_info, label);
  SET_CK_STRING(self, token_info, manufacturerID);
  SET_CK_STRING(self, token_info, model);
  SET_CK_STRING(self, token_info, serialNumber);

  SET_CK_ULONG(self, token_info, flags);

  SET_CK_ULONG(self, token_info, ulMaxSessionCount);
  SET_CK_ULONG(self, token_info, ulSessionCount);
  SET_CK_ULONG(self, token_info, ulMaxRwSessionCount);
  SET_CK_ULONG(self, token_info, ulRwSessionCount);
  SET_CK_ULONG(self, token_info, ulMaxPinLen);
  SET_CK_ULONG(self, token_info, ulMinPinLen);
  SET_CK_ULONG(self, token_info, ulTotalPublicMemory);
  SET_CK_ULONG(self, token_info, ulFreePublicMemory);
  SET_CK_ULONG(self, token_info, ulTotalPrivateMemory);
  SET_CK_ULONG(self, token_info, ulFreePrivateMemory);

  return true;
}

v8::Handle<v8::Value> Pkcs11::Token::InitToken(const v8::Arguments& args) {
  if (args.Length() < 1)
    return ThrowException("Missing required parameter: soPin");

  v8::String::AsciiValue ascii_pin(args[0]);

  if (args.Length() < 2)
    return ThrowException("Missing required parameter: label");

  v8::String::AsciiValue ascii_label(args[1]);
  if (ascii_label.length() > 32)
    return ThrowException("Label must be 32 characters or less");

  CK_CHAR ck_label[32];
  memset(ck_label, ' ', sizeof(ck_label));
  memcpy(ck_label, *ascii_label, ascii_label.length());

  OkOrThrow(C_InitToken(slot_id_,
                        reinterpret_cast<CK_CHAR_PTR>(*ascii_pin),
                        ascii_pin.length(), ck_label));

  return v8::Undefined();
}

v8::Handle<v8::Value> Pkcs11::Token::OpenSession(const v8::Arguments& args) {
  if (args.Length() < 1)
    return ThrowException("Missing required parameter: sessionFlags");

  uint32_t session_flags = args[0]->Uint32Value();

  CK_SESSION_HANDLE session_handle;

  if (!OkOrThrow(C_OpenSession(slot_id_, session_flags | CKF_SERIAL_SESSION,
                               NULL, NULL, &session_handle))) {
    return v8::Undefined();
  }

  Pkcs11::Session::Reference session = Pkcs11::Session::New();
  if (!session->Initialize(slot_id_, session_handle))
    return ThrowException("Unexpected error");

  return session->js_object();
}

v8::Handle<v8::Value> Pkcs11::Token::CallRefresh(const v8::Arguments& args) {
  if (!Refresh())
    return ThrowException("Unexpected error");

  return v8::Undefined();
}

bool Pkcs11::Session::Initialize(CK_SLOT_ID slot_id,
                                 CK_SESSION_HANDLE session_handle) {
  slot_id_ = slot_id;
  session_handle_ = session_handle;
  return true;
}

// static
bool Pkcs11::Session::InitializeTemplate(
    v8::Handle<v8::FunctionTemplate> ctor_t) {
  // User types for login()...
  SET_CK_CONST(ctor_t, CKU_SO);
  SET_CK_CONST(ctor_t, CKU_USER);

  v8::Handle<v8::ObjectTemplate> instance_t = ctor_t->InstanceTemplate();

  BindMethod(instance_t, &Pkcs11::Session::Close,   "close");
  BindMethod(instance_t, &Pkcs11::Session::Login,   "login");
  BindMethod(instance_t, &Pkcs11::Session::Logout,  "logout");
  BindMethod(instance_t, &Pkcs11::Session::InitPin, "initPin");
  BindMethod(instance_t, &Pkcs11::Session::SetPin,  "setPin");

  //BindMethod(instance_t, &Pkcs11::Session::FindObjects, "findObjects");
  //BindMethod(instance_t, &Pkcs11::Session::CreateObject, "createObject");

  return true;
}

v8::Handle<v8::Value> Pkcs11::Session::InitPin(const v8::Arguments& args) {
  if (args.Length() < 1)
    return ThrowException("Missing required parameter: pin");

  v8::String::AsciiValue ascii_pin(args[0]);

  OkOrThrow(C_InitPIN(slot_id_,
                      reinterpret_cast<CK_CHAR_PTR>(*ascii_pin),
                      ascii_pin.length()));

  return v8::Undefined();
}

v8::Handle<v8::Value> Pkcs11::Session::Close(const v8::Arguments& args) {
  OkOrThrow(C_CloseSession(session_handle_));
  return v8::Undefined();
}

v8::Handle<v8::Value> Pkcs11::Session::Login(const v8::Arguments& args) {
  if (args.Length() < 1)
    return ThrowException("Missing required parameter: userType");

  uint32_t user_type = args[0]->Uint32Value();
  if (user_type != CKU_USER && user_type != CKU_SO)
    return ThrowException("Invalid value for parameter: userType");

  if (args.Length() < 2)
    return ThrowException("Missing required parameter: pin");

  v8::String::AsciiValue ascii_pin(args[1]);

  CK_RV rv = C_Login(session_handle_, user_type,
                     reinterpret_cast<CK_CHAR_PTR>(*ascii_pin),
                     ascii_pin.length());
  if (rv == CKR_PIN_INCORRECT)
    return v8::False();

  if (!OkOrThrow(rv))
    return v8::Undefined();

  return v8::True();
}

v8::Handle<v8::Value> Pkcs11::Session::Logout(const v8::Arguments& args) {
  OkOrThrow(C_Logout(session_handle_));
  return v8::Undefined();
}

v8::Handle<v8::Value> Pkcs11::Session::SetPin(const v8::Arguments& args) {
  if (args.Length() < 1)
    return ThrowException("Missing required parameter: oldPin");

  v8::String::AsciiValue old_pin(args[0]);

  if (args.Length() < 2)
    return ThrowException("Missing required parameter: newPin");

  v8::String::AsciiValue new_pin(args[1]);

  OkOrThrow(C_SetPIN(session_handle_,
                     reinterpret_cast<CK_CHAR_PTR>(*old_pin), old_pin.length(),
                     reinterpret_cast<CK_CHAR_PTR>(*new_pin), new_pin.length())
            );

  return v8::Undefined();
}

v8::Handle<v8::Value> Pkcs11::Session::FindObjects(const v8::Arguments& args) {
  // TODO(rginda): implement this.
  return v8::Undefined();
}

v8::Handle<v8::Value> Pkcs11::Construct(const v8::Arguments& args) {
  if (!OkOrThrow(InitializeLibrary()))
    return v8::Undefined();

  if (!Initialize())
    return ThrowException("Error initializing Pkcs11 object");

  return args.This();
}

// static
CK_RV Pkcs11::InitializeLibrary() {
  static CK_RV rv = CKR_CANCEL;

  if (rv != CKR_OK)
    rv = C_Initialize(NULL);

  if (rv == CKR_CRYPTOKI_ALREADY_INITIALIZED)
    rv = CKR_OK;

  OkOrWarn(rv);

  return rv;
}

bool Pkcs11::Initialize() {
  if (!OkOrWarn(InitializeLibrary()))
    return false;

  v8::Handle<v8::Object> self = js_object();

  Pkcs11::Slots::Reference slots = Pkcs11::Slots::New();
  slots->Initialize();
  self->Set(v8::String::New("slots"), slots->js_object());

  return true;
}

// static
bool Pkcs11::InitializeTemplate(v8::Handle<v8::FunctionTemplate> ctor_t) {
  ctor_t->Set(v8::String::NewSymbol("Slots"),
              Pkcs11::Slots::constructor_template());
  ctor_t->Set(v8::String::NewSymbol("Slot"),
              Pkcs11::Slot::constructor_template());
  ctor_t->Set(v8::String::NewSymbol("Token"),
              Pkcs11::Token::constructor_template());
  ctor_t->Set(v8::String::NewSymbol("Session"),
              Pkcs11::Session::constructor_template());

  return true;
}

// static
v8::Handle<v8::Value> Pkcs11::ThrowNoScriptableConstructor(
    std::string class_name) {
  return ThrowException(class_name + "() cannot be invoked from script");
}

}  // namespace crypto

}  // namespace entd
