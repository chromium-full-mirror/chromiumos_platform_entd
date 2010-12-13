// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "entd/crypto_pkcs11.h"

#include "base/logging.h"
#include "base/string_util.h"
#include "base/string_number_conversions.h"
#include <chromeos/utility.h>
#include <openssl/bn.h>

#include "entd/utils.h"

namespace entd {

namespace crypto {

// PKCS#11 Helper Constants.
static const CK_OBJECT_CLASS kPublicKeyClass = CKO_PUBLIC_KEY;
static const CK_OBJECT_CLASS kPrivateKeyClass = CKO_PRIVATE_KEY;
static const CK_BBOOL kCkTrue = TRUE;
static const CK_BBOOL kCkFalse = FALSE;
static const CK_BYTE kPublicExponent[] = { 0x01, 0x00,
                                           0x01 }; // 65537 in bytes.
static const CK_ULONG kDefaultKeySize = 2048; // in bits.

typedef std::vector<CK_ATTRIBUTE> TemplateAttributes;
typedef std::map<CK_ATTRIBUTE_TYPE, CK_BBOOL> TemplateBoolValues;
typedef std::map<CK_ATTRIBUTE_TYPE, CK_ULONG> TemplateUlongValues;
typedef std::map<CK_ATTRIBUTE_TYPE, chromeos::Blob> TemplateBinaryValues;
typedef std::map<CK_ATTRIBUTE_TYPE, std::string> TemplateStringValues;

// PKCS#11 structures uses pointers to buffers. This structure holds the
// buffers result of translation of user's input, required to complete
// the request.
typedef struct {
  TemplateBoolValues bool_values;
  TemplateUlongValues ulong_values;
  TemplateBinaryValues binary_values;
  TemplateStringValues string_values;
} TemplateValueStore;

// Dirty little macros to make copying things from PKCS#11 structs a little
// cleaner.
#define SET_CK_STRING(self, record, field)                                  \
  self->Set(v8::String::New(#field),                                        \
            v8::String::New(reinterpret_cast<char*>(&record.field[0]),      \
                            CkStringLength(record.field,                    \
                                           sizeof(record.field))))

#define SET_CK_ULONG(self, record, field)                                   \
  self->Set(v8::String::New(#field),                                        \
            v8::Integer::NewFromUnsigned(record.field))

// Reflect PKCS#11 constants into JavaScript.
#define SET_CK_CONST(self, name)                                            \
  self->Set(v8::String::New(#name),                                         \
            v8::Integer::NewFromUnsigned(name), v8::ReadOnly)

bool CKRVToString(CK_RV rv, std::string* rv_string) {
  v8::Handle<v8::Function> ctor = Pkcs11::constructor_template()->GetFunction();

  v8::Handle<v8::Array> ary = ctor->GetPropertyNames();
  for (uint32_t i = 0; i < ary->Length(); ++i) {
    v8::String::AsciiValue name(ary->Get(i));
    if (strncmp("CKR_", *name, 4) == 0) {
      uint32_t value = ctor->Get(ary->Get(i))->Uint32Value();
      if (value == rv) {
        rv_string->assign(*name, name.length());
        return true;
      }
    }
  }

  unsigned int urv = rv;
  rv_string->assign(StringPrintf("0x%08X", urv));

  return false;
}

// Check that a CK_RV value is CKR_OK, throw a V8 exception if it is not.
bool OkOrThrow(CK_RV rv) {
  if (rv != CKR_OK) {
    std::string rv_string;
    CKRVToString(rv, &rv_string);
    utils::ThrowV8Exception("PKCS#11 Error: " + rv_string);
    return false;
  }

  return true;
}

// Check that a CK_RV value is CKR_OK, log a warning if it is not.
bool OkOrWarn(CK_RV rv) {
  if (rv != CKR_OK) {
    std::string rv_string;
    CKRVToString(rv, &rv_string);
    LOG(WARNING) << "PKCS#11 Error: " << rv_string;
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

// static.
bool Pkcs11::Slots::InitializeTemplate(
    v8::Handle<v8::FunctionTemplate> ctor_t) {
  v8::Handle<v8::ObjectTemplate> instance_t = ctor_t->InstanceTemplate();

  instance_t->SetAccessor(v8::String::New("length"),
                          GetLength,
                          0,  // Length is readonly, so setter is NULL.
                          v8::Handle<v8::Value>(),  // Don't need any data.
                          v8::DEFAULT,  // DEFAULT AccessControl.
                          v8::DontDelete);

  instance_t->SetIndexedPropertyHandler(GetIndexedProperty,
                                        SetIndexedProperty,
                                        QueryIndexedProperty,
                                        DeleteIndexedProperty,
                                        EnumerateIndexedProperties);

  return true;
}

// static.
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
    return v8::Undefined();

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

// static.
v8::Handle<v8::Value> Pkcs11::Slots::SetIndexedProperty(
    uint32_t index, v8::Local<v8::Value> value, const v8::AccessorInfo& info) {
  Pkcs11::Slots* slots = Pkcs11::Slots::UnwrapOrThrow(info.This(), "this");
  if (!slots)
    return v8::Undefined();

  return ThrowException("Attempt to write to read only property");
}

// static.
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

// static.
v8::Handle<v8::Boolean> Pkcs11::Slots::DeleteIndexedProperty(
    uint32_t index, const v8::AccessorInfo& info) {
  Pkcs11::Slots* slots = Pkcs11::Slots::UnwrapOrThrow(info.This(), "this");
  if (!slots)
    return v8::False();

  ThrowException("Attempt to delete read only property");
  return v8::False();
}

// static.
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

// static.
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

// static.
bool Pkcs11::Slot::InitializeTemplate(v8::Handle<v8::FunctionTemplate> ctor_t) {
  v8::Handle<v8::ObjectTemplate> instance_t = ctor_t->InstanceTemplate();

  SET_CK_CONST(ctor_t, CKF_TOKEN_PRESENT);
  SET_CK_CONST(ctor_t, CKF_REMOVABLE_DEVICE);
  SET_CK_CONST(ctor_t, CKF_HW_SLOT);

  BindMethod(instance_t, &Pkcs11::Slot::CallRefresh, "refresh");
  instance_t->SetAccessor(v8::String::New("token"),
                          GetToken,
                          0,  // Token is readonly, so setter is NULL.
                          v8::Handle<v8::Value>(),  // Don't need any data.
                          v8::DEFAULT,  // DEFAULT AccessControl.
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
    if (token_.IsEmpty()) {
      if (!token_.Copy(Pkcs11::Token::New()) || !token_->Initialize(slot_id_)) {
        LOG(ERROR) << "Error creating Pkcs11::Token instance";
        return false;
      }
    }
  } else {
    token_.set_native_ptr(NULL);
  }

  return true;
}

// static.
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

  js_object()->Set(v8::String::NewSymbol("slotId"),
                   v8::Integer::NewFromUnsigned(slot_id_));

  return Refresh();
}

// static.
bool Pkcs11::Token::InitializeTemplate(
    v8::Handle<v8::FunctionTemplate> ctor_t) {

  // Opencryptoki defaults, as per their README: http://tinyurl.com/2cafmsp.
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
  BindMethod(instance_t, &Pkcs11::Token::CloseAllSessions, "closeAllSessions");

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

  CK_SESSION_HANDLE session_handle = 0;

  if (!OkOrThrow(C_OpenSession(slot_id_, session_flags | CKF_SERIAL_SESSION,
                               NULL, NULL, &session_handle))) {
    return v8::Undefined();
  }

  Pkcs11::Session::Reference session = Pkcs11::Session::New();
  if (!session->Initialize(slot_id_, session_handle))
    return ThrowException("Unexpected error");

  return session->js_object();
}

v8::Handle<v8::Value> Pkcs11::Token::CloseAllSessions(
    const v8::Arguments& args) {
  OkOrThrow(C_CloseAllSessions(slot_id_));
  return v8::Undefined();
}

v8::Handle<v8::Value> Pkcs11::Token::CallRefresh(const v8::Arguments& args) {
  if (!Refresh())
    return ThrowException("Unexpected error");

  return v8::Undefined();
}

bool Pkcs11::Session::Initialize(const CK_SLOT_ID slot_id,
                                 const CK_SESSION_HANDLE& session_handle) {
  slot_id_ = slot_id;
  session_handle_ = session_handle;

  return Refresh();
}

// static.
bool Pkcs11::Session::InitializeTemplate(
    v8::Handle<v8::FunctionTemplate> ctor_t) {

  // Session states...
  SET_CK_CONST(ctor_t, CKU_SO);
  SET_CK_CONST(ctor_t, CKS_RO_PUBLIC_SESSION);
  SET_CK_CONST(ctor_t, CKS_RO_USER_FUNCTIONS);
  SET_CK_CONST(ctor_t, CKS_RW_PUBLIC_SESSION);
  SET_CK_CONST(ctor_t, CKS_RW_USER_FUNCTIONS);
  SET_CK_CONST(ctor_t, CKS_RW_SO_FUNCTIONS);

  // Session flags...
  SET_CK_CONST(ctor_t, CKF_RW_SESSION);
  SET_CK_CONST(ctor_t, CKF_SERIAL_SESSION);

  // User types for login()...
  SET_CK_CONST(ctor_t, CKU_SO);
  SET_CK_CONST(ctor_t, CKU_USER);

  // Keypair generation.
  SET_CK_CONST(ctor_t, CKM_RSA_PKCS_KEY_PAIR_GEN);

  v8::Handle<v8::ObjectTemplate> instance_t = ctor_t->InstanceTemplate();

  BindMethod(instance_t, &Pkcs11::Session::CallRefresh, "refresh");
  BindMethod(instance_t, &Pkcs11::Session::Close, "close");
  BindMethod(instance_t, &Pkcs11::Session::Login, "login");
  BindMethod(instance_t, &Pkcs11::Session::Logout, "logout");
  BindMethod(instance_t, &Pkcs11::Session::InitPin, "initPin");
  BindMethod(instance_t, &Pkcs11::Session::SetPin, "setPin");
  BindMethod(instance_t, &Pkcs11::Session::GenerateKeyPair, "generateKeyPair");
  BindMethod(instance_t, &Pkcs11::Session::FindObjects, "findObjects");
  BindMethod(instance_t, &Pkcs11::Session::CreateObject, "createObject");

  return true;
}

bool Pkcs11::Session::Refresh() {
  CK_SESSION_INFO session_info;
  CK_RV rv = C_GetSessionInfo(session_handle_, &session_info);
  if (!OkOrWarn(rv))
    return false;

  v8::Handle<v8::Object> self = js_object();
  if (self.IsEmpty())
    return false;

  SET_CK_ULONG(self, session_info, slotID);
  SET_CK_ULONG(self, session_info, state);
  SET_CK_ULONG(self, session_info, flags);

  return true;
}

v8::Handle<v8::Value> Pkcs11::Session::CallRefresh(const v8::Arguments& args) {
  if (!Refresh())
    return ThrowException("Unexpected error");

  return v8::Undefined();
}

v8::Handle<v8::Value> Pkcs11::Session::InitPin(const v8::Arguments& args) {
  if (args.Length() < 1)
    return ThrowException("Missing required parameter: pin");

  v8::String::AsciiValue ascii_pin(args[0]);

  OkOrThrow(C_InitPIN(session_handle_,
                      reinterpret_cast<CK_CHAR_PTR>(*ascii_pin),
                      ascii_pin.length()));

  return v8::Undefined();
}

v8::Handle<v8::Value> Pkcs11::Session::Close(const v8::Arguments& args) {
  if (!session_handle_)
    return ThrowException("Not open");

  OkOrThrow(C_CloseSession(session_handle_));
  session_handle_ = 0;
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

// Returns true if specified attribute exists in the template.
bool HasAttribute(const TemplateValueStore& store,
                  const CK_ATTRIBUTE_TYPE value) {
  if (store.bool_values.find(value) != store.bool_values.end())
    return true;
  if (store.ulong_values.find(value) != store.ulong_values.end())
    return true;
  if (store.binary_values.find(value) != store.binary_values.end())
    return true;
  if (store.string_values.find(value) != store.string_values.end())
    return true;

  return false;
}

// Retrieves a ULONG attribute from the template.
// returns true if value was found. false otherwise.
bool GetUlongAttribute(const TemplateValueStore& store,
                       const CK_ATTRIBUTE_TYPE name,
                       CK_ULONG* value) {
  TemplateUlongValues::const_iterator finder = store.ulong_values.find(name);
  if (finder != store.ulong_values.end()) {
    *value = finder->second;
    return true;
  }
  return false;
}

// Copy all attributes from source to destination.
void CopyAttributes(const TemplateValueStore& source,
                    TemplateValueStore* target) {
  target->bool_values.insert(source.bool_values.begin(),
                             source.bool_values.end());
  target->ulong_values.insert(source.ulong_values.begin(),
                             source.ulong_values.end());
  target->binary_values.insert(source.binary_values.begin(),
                               source.binary_values.end());
  target->string_values.insert(source.string_values.begin(),
                               source.string_values.end());
}

// Add a BOOL attribute to the template.
bool AddBoolAttribute(const uint32_t option_code, const CK_BBOOL value,
                      TemplateValueStore* store) {
  if (HasAttribute(*store, option_code)) {
    utils::ThrowV8Exception("Attribute specified more than once: " +
                            base::IntToString(option_code));
    return false;
  }

  store->bool_values[option_code] = value;
  return true;
}

// Add an ULONG attribute to the template.
bool AddUlongAttribute(const uint32_t option_code, const CK_ULONG value,
                       TemplateValueStore* store) {
  if (HasAttribute(*store, option_code)) {
    utils::ThrowV8Exception("Attribute specified more than once: " +
                            base::IntToString(option_code));
    return false;
  }

  store->ulong_values[option_code] = value;
  return true;
}

// Adds a BYTE* attribute to the template (from a binary buffer).
bool AddBinaryAttribute(const uint32_t option_code,
                        const chromeos::Blob& value,
                        TemplateValueStore* store) {
  if (HasAttribute(*store, option_code)) {
    utils::ThrowV8Exception("Attribute specified more than once: " +
                            base::IntToString(option_code));
    return false;
  }

  store->binary_values[option_code] = value;
  return true;
}

// Converts the argument based on its type:
//   type == number -- converts to hex.
//   type != number -- assume is hex.
std::string ValueToHex(const v8::Handle<v8::Value>& option_value) {
  std::string value_hex;

  if (option_value->IsNumber()) {
    // Input is numeric. Convert to hex format.
    uint32_t value = option_value->Uint32Value();
    std::stringstream value_stream;
    value_stream << std::hex << value;
    value_hex.assign(value_stream.str());
  } else {
    // Input is non-numeric. Assume hex format.
    v8::String::AsciiValue value_ascii(option_value);
    value_hex.assign(*value_ascii);
  }

  if (value_hex.length() & 1)
    value_hex.insert(0, "0");

  return value_hex;
}

// Adds a BYTE* attribute to the template (from an HEX string).
bool AddBinaryAttribute(const uint32_t option_code,
                        const v8::Handle<v8::Value>& option_value,
                        TemplateValueStore* store) {
  std::string value_hex;
  value_hex = ValueToHex(option_value);

  chromeos::Blob value_binary;
  if (!base::HexStringToBytes(value_hex, &value_binary)) {
    utils::ThrowV8Exception("Invalid binary object");
    return false;
  }

  return AddBinaryAttribute(option_code, value_binary, store);
}

// Adds a STRING attribute to the template.
bool AddStringAttribute(const uint32_t option_code,
                        const v8::Handle<v8::Value>& option_value,
                        TemplateValueStore* store) {
  if (HasAttribute(*store, option_code)) {
    utils::ThrowV8Exception("Attribute specified more than once: " +
                            base::IntToString(option_code));
    return false;
  }

  std::string value = utils::ValueAsUtf8String(option_value);
  store->string_values[option_code] = value;
  return true;
}

// Parses the template from user input parameters, converting them
// into the appropriate buffers and storing into the template store.
//
// Once all parsing is done and all attributes are added to the store,
// BuildTemplate should be called to create the PKCS#11 compatible
// input structure.
bool ParseTemplate(const std::string& template_type,
                   const v8::Handle<v8::Value>& args,
                   TemplateValueStore* store) {
  if (!args->IsArray()) {
    utils::ThrowV8Exception("Expected array for parameter: " + template_type);
    return false;
  }

  v8::Local<v8::Array> options = v8::Array::Cast(*args);
  for (unsigned int i = 0; i < options->Length(); i++) {
    v8::Local<v8::Value> option = options->Get(i);
    if (!option->IsArray()) {
      utils::ThrowV8Exception("Expected array for parameter " +
                              template_type + " [" + base::IntToString(i) +
                              "]");
      return false;
    }
    v8::Local<v8::Array> option_values = v8::Array::Cast(*option);
    if (option_values->Length() != 2) {
      utils::ThrowV8Exception("Incorrect input parameter " +
                              base::IntToString(i) +
                              ": expected format is [name, value]");
      return false;
    }

    // Parse [name, value] pair.
    v8::Local<v8::Value> cka_name = option_values->Get(0);
    v8::Local<v8::Value> cka_value = option_values->Get(1);

    if (!cka_name->IsNumber()) {
      utils::ThrowV8Exception("Incorrect input parameter " +
                              base::IntToString(i) +
                              ": name has to be a Object.CKA* constant");
      return false;
    }

    bool ret;
    uint32_t cka_attrib = cka_name->Uint32Value();

    switch (cka_attrib) {
      // BOOL values.
      case CKA_DECRYPT:
      case CKA_ENCRYPT:
      case CKA_PRIVATE:
      case CKA_SENSITIVE:
      case CKA_SIGN:
      case CKA_TOKEN:
      case CKA_UNWRAP:
      case CKA_VERIFY:
      case CKA_WRAP: {
        CK_BBOOL value = cka_value->ToBoolean()->Value();
        ret = AddBoolAttribute(cka_attrib, value, store);
        break;
      }

      // ULONG values.
      case CKA_CLASS:
      case CKA_KEY_TYPE:
      case CKA_CERTIFICATE_TYPE:
      case CKA_MODULUS_BITS: {
        CK_ULONG value = cka_value->Uint32Value();
        ret = AddUlongAttribute(cka_attrib, value, store);
        break;
      }

      // BINARY values.
      case CKA_ID:
      case CKA_COEFFICIENT:
      case CKA_EXPONENT_1:
      case CKA_EXPONENT_2:
      case CKA_PRIME_1:
      case CKA_PRIME_2:
      case CKA_PUBLIC_EXPONENT:
      case CKA_PRIVATE_EXPONENT:
      case CKA_VALUE:
      case CKA_MODULUS: {
        ret = AddBinaryAttribute(cka_attrib, cka_value, store);
        break;
      }

      // STRING values.
      case CKA_SUBJECT:
      case CKA_LABEL: {
        ret = AddStringAttribute(cka_attrib, cka_value, store);
        break;
      }

      default:
        utils::ThrowV8Exception("Incorrect input parameter " +
                                base::IntToString(i) +
                                ": name is invalid");
        ret = false;
    }

    if (!ret)
      return false;
  }

  return true;
}

// Builds a template using the skeleton defined in the TemplateValueStore.
//
// This function should be called once per pair (Store, Attribs). Best if
// all parameters are added to the store prior to calling this function,
// and call it just once.
void BuildTemplate(const TemplateValueStore& store,
                   TemplateAttributes* attribs) {
  TemplateBoolValues::const_iterator bool_item;
  for (bool_item = store.bool_values.begin();
       bool_item != store.bool_values.end(); bool_item++) {
    CK_ATTRIBUTE attrib = { bool_item->first,
                            const_cast<CK_BBOOL*>(&bool_item->second),
                            sizeof(bool_item->second) };
    attribs->push_back(attrib);
  }

  TemplateUlongValues::const_iterator ulong_item;
  for (ulong_item = store.ulong_values.begin();
       ulong_item != store.ulong_values.end(); ulong_item++) {
    CK_ATTRIBUTE attrib = { ulong_item->first,
                            const_cast<CK_ULONG*>(&ulong_item->second),
                            sizeof(ulong_item->second) };
    attribs->push_back(attrib);
  }

  TemplateBinaryValues::const_iterator binary_item;
  for (binary_item = store.binary_values.begin();
       binary_item != store.binary_values.end(); binary_item++) {
    CK_ATTRIBUTE attrib = { binary_item->first,
                            const_cast<CK_BYTE*>(&binary_item->second[0]),
                            binary_item->second.size() };
    attribs->push_back(attrib);
  }

  TemplateStringValues::const_iterator string_item;
  for (string_item = store.string_values.begin();
       string_item != store.string_values.end(); string_item++) {
    CK_ATTRIBUTE attrib = { string_item->first,
                            const_cast<char*>(string_item->second.c_str()),
                            string_item->second.length() };
    attribs->push_back(attrib);
  }
}

v8::Handle<v8::Value> Pkcs11::Session::FindObjects(const v8::Arguments& args) {
  if (args.Length() < 1)
    return ThrowException("Missing required parameter: search template");

  // Template attributes.
  TemplateAttributes find_template;
  TemplateValueStore find_store;

  // Parse template arguments.
  if (!ParseTemplate("template", args[0], &find_store))
     return v8::Undefined();

  BuildTemplate(find_store, &find_template);

  CK_RV rv = C_FindObjectsInit(session_handle_, &find_template[0],
                               find_template.size());

  if (!OkOrThrow(rv))
    return v8::Undefined();

  CK_ULONG object_count;
  CK_OBJECT_HANDLE object_handle;
  std::vector<Object::Reference> objects_found;
  while (true) {
    rv = C_FindObjects(session_handle_, &object_handle, 1, &object_count);
    if (!OkOrThrow(rv))
      return v8::Undefined();
    if (object_count == 0)
      break;

    Object::Reference object = Object::New();
    if (object.IsEmpty() ||
        !object->Initialize(session_handle_, object_handle)) {
      return ThrowException("Error initializing result object");
    }
    objects_found.push_back(object);
  }

  rv = C_FindObjectsFinal(session_handle_);
  if (!OkOrThrow(rv))
    return v8::Undefined();

  // Construct result array.
  v8::Handle<v8::Array> result = v8::Array::New(objects_found.size());
  for (size_t i = 0; i < objects_found.size(); ++i)
    result->Set(i, objects_found[i]->js_object());

  return result;
}

void AddPublicExponent(TemplateValueStore* store) {
  if (!HasAttribute(*store, CKA_PUBLIC_EXPONENT)) {
    chromeos::Blob public_exponent;
    public_exponent.assign(kPublicExponent,
                           kPublicExponent + sizeof(kPublicExponent));
    AddBinaryAttribute(CKA_PUBLIC_EXPONENT, public_exponent,store);
  }
}

v8::Handle<v8::Value> Pkcs11::Session::CreateObject(const v8::Arguments& args) {
  if (args.Length() < 1)
    return ThrowException("Missing required parameter: create template");

  // Template attributes.
  TemplateAttributes create_template;
  TemplateValueStore create_store;

  // Parse template arguments.
  if (!ParseTemplate("template", args[0], &create_store))
     return v8::Undefined();

  // Check for required parameters.
  if (!HasAttribute(create_store, CKA_CLASS))
    return ThrowException("Missing required parameter: Object.CKA_CLASS");

  CK_OBJECT_CLASS object_class;
  if (!GetUlongAttribute(create_store, CKA_CLASS, &object_class))
    return ThrowException("Cannot retrieve object class");
  if (object_class == CKO_PUBLIC_KEY || object_class == CKO_PRIVATE_KEY)
    AddPublicExponent(&create_store);
  BuildTemplate(create_store, &create_template);

  CK_OBJECT_HANDLE object_handle;
  CK_RV rv = C_CreateObject(session_handle_, &create_template[0],
                            create_template.size(), &object_handle);
  if (!OkOrThrow(rv))
    return v8::Undefined();

  // Construct result object.
  Object::Reference result = Object::New();
  if (result.IsEmpty() || !result->Initialize(session_handle_, object_handle))
    return ThrowException("Error initializing result object");

  return result->js_object();
}

v8::Handle<v8::Value> Pkcs11::Session::GenerateKeyPair(
    const v8::Arguments& args) {
  if (args.Length() < 1)
    return ThrowException("Missing required parameter: mechanism");
  if (!args[0]->IsNumber() && !args[0]->IsNull())
    return ThrowException("Invalid value for parameter: mechanism");

  // Default parameters.
  uint32_t mech_type = CKM_RSA_PKCS_KEY_PAIR_GEN;

  // Parse mechanism arguments.
  if (args[0]->IsNumber())
    mech_type = args[0]->Uint32Value();

  if (args.Length() < 2)
    return ThrowException("Missing required parameter: public");

  // Public key attributes.
  TemplateValueStore public_key_store;
  TemplateAttributes public_key_template;

  // Parse public template arguments.
  if (!ParseTemplate("public", args[1], &public_key_store))
     return v8::Undefined();

  if (args.Length() < 3)
    return ThrowException("Missing required parameter: private");

  // Private key attributes.
  TemplateValueStore private_key_store;
  TemplateAttributes private_key_template;

  // Parse private template arguments.
  if (!ParseTemplate("private", args[2], &private_key_store))
     return v8::Undefined();

  // Optional common attributes.
  if (args.Length() >= 4) {
    // Common attributes.
    TemplateAttributes common_key_template;
    TemplateValueStore common_key_store;

    // Parse common template arguments.
    if (!ParseTemplate("common", args[3], &common_key_store))
       return v8::Undefined();

    // Add common values to private and public templates.
    CopyAttributes(common_key_store, &public_key_store);
    CopyAttributes(common_key_store, &private_key_store);
  }

  // Add default template values.
  if (!HasAttribute(public_key_store, CKA_CLASS))
    AddUlongAttribute(CKA_CLASS, kPublicKeyClass, &public_key_store);
  AddPublicExponent(&public_key_store);
  if (!HasAttribute(public_key_store, CKA_MODULUS_BITS))
    AddUlongAttribute(CKA_MODULUS_BITS, kDefaultKeySize, &public_key_store);
  if (!HasAttribute(private_key_store, CKA_CLASS))
    AddUlongAttribute(CKA_CLASS, kPrivateKeyClass, &private_key_store);

  // Build key templates.
  BuildTemplate(public_key_store, &public_key_template);
  BuildTemplate(private_key_store, &private_key_template);

  // Define key generation mechanism attributes.
  CK_MECHANISM key_mechanism = { mech_type, NULL_PTR, 0 };

  CK_OBJECT_HANDLE public_key;
  CK_OBJECT_HANDLE private_key;

  CK_RV rv = C_GenerateKeyPair(session_handle_, &key_mechanism,
                               &public_key_template[0],
                               public_key_template.size(),
                               &private_key_template[0],
                               private_key_template.size(),
                               &public_key, &private_key);

  if (!OkOrThrow(rv))
    return v8::Undefined();

  return v8::True();
}

bool Pkcs11::Object::Initialize(const CK_SESSION_HANDLE& session_handle,
                                const CK_OBJECT_HANDLE& object_handle) {
  session_handle_ = session_handle;
  object_handle_ = object_handle;
  return true;
}

// static.
bool Pkcs11::Object::InitializeTemplate(
    v8::Handle<v8::FunctionTemplate> ctor_t) {
  // Attributes.
  SET_CK_CONST(ctor_t, CKA_CLASS);
  SET_CK_CONST(ctor_t, CKA_CERTIFICATE_TYPE);
  SET_CK_CONST(ctor_t, CKA_COEFFICIENT);
  SET_CK_CONST(ctor_t, CKA_DECRYPT);
  SET_CK_CONST(ctor_t, CKA_ENCRYPT);
  SET_CK_CONST(ctor_t, CKA_EXPONENT_1);
  SET_CK_CONST(ctor_t, CKA_EXPONENT_2);
  SET_CK_CONST(ctor_t, CKA_ID);
  SET_CK_CONST(ctor_t, CKA_KEY_TYPE);
  SET_CK_CONST(ctor_t, CKA_LABEL);
  SET_CK_CONST(ctor_t, CKA_MODULUS);
  SET_CK_CONST(ctor_t, CKA_MODULUS_BITS);
  SET_CK_CONST(ctor_t, CKA_PRIME_1);
  SET_CK_CONST(ctor_t, CKA_PRIME_2);
  SET_CK_CONST(ctor_t, CKA_PRIVATE);
  SET_CK_CONST(ctor_t, CKA_PRIVATE_EXPONENT);
  SET_CK_CONST(ctor_t, CKA_PUBLIC_EXPONENT);
  SET_CK_CONST(ctor_t, CKA_SENSITIVE);
  SET_CK_CONST(ctor_t, CKA_SIGN);
  SET_CK_CONST(ctor_t, CKA_SUBJECT);
  SET_CK_CONST(ctor_t, CKA_TOKEN);
  SET_CK_CONST(ctor_t, CKA_UNWRAP);
  SET_CK_CONST(ctor_t, CKA_VALUE);
  SET_CK_CONST(ctor_t, CKA_VERIFY);
  SET_CK_CONST(ctor_t, CKA_WRAP);

  // Key types.
  SET_CK_CONST(ctor_t, CKK_AES);
  SET_CK_CONST(ctor_t, CKK_BATON);
  SET_CK_CONST(ctor_t, CKK_CAST);
  SET_CK_CONST(ctor_t, CKK_CAST128);
  SET_CK_CONST(ctor_t, CKK_CAST3);
  SET_CK_CONST(ctor_t, CKK_CAST5);
  SET_CK_CONST(ctor_t, CKK_CDMF);
  SET_CK_CONST(ctor_t, CKK_DES);
  SET_CK_CONST(ctor_t, CKK_DES2);
  SET_CK_CONST(ctor_t, CKK_DES3);
  SET_CK_CONST(ctor_t, CKK_DH);
  SET_CK_CONST(ctor_t, CKK_DSA);
  SET_CK_CONST(ctor_t, CKK_EC);
  SET_CK_CONST(ctor_t, CKK_ECDSA);
  SET_CK_CONST(ctor_t, CKK_GENERIC_SECRET);
  SET_CK_CONST(ctor_t, CKK_IDEA);
  SET_CK_CONST(ctor_t, CKK_JUNIPER);
  SET_CK_CONST(ctor_t, CKK_KEA);
  SET_CK_CONST(ctor_t, CKK_RC2);
  SET_CK_CONST(ctor_t, CKK_RC4);
  SET_CK_CONST(ctor_t, CKK_RC5);
  SET_CK_CONST(ctor_t, CKK_RSA);
  SET_CK_CONST(ctor_t, CKK_SKIPJACK);
  SET_CK_CONST(ctor_t, CKK_VENDOR_DEFINED);
  SET_CK_CONST(ctor_t, CKK_X9_42_DH);

  // Object types.
  SET_CK_CONST(ctor_t, CKO_CERTIFICATE);
  SET_CK_CONST(ctor_t, CKO_DATA);
  SET_CK_CONST(ctor_t, CKO_DOMAIN_PARAMETERS);
  SET_CK_CONST(ctor_t, CKO_HW_FEATURE);
  SET_CK_CONST(ctor_t, CKO_PRIVATE_KEY);
  SET_CK_CONST(ctor_t, CKO_PUBLIC_KEY);
  SET_CK_CONST(ctor_t, CKO_SECRET_KEY);
  SET_CK_CONST(ctor_t, CKO_VENDOR_DEFINED);

  // Certificate types.
  SET_CK_CONST(ctor_t, CKC_X_509);
  SET_CK_CONST(ctor_t, CKC_VENDOR_DEFINED);

  v8::Handle<v8::ObjectTemplate> instance_t = ctor_t->InstanceTemplate();

  BindMethod(instance_t, &Pkcs11::Object::DestroyObject, "destroy");

  return true;
}

v8::Handle<v8::Value> Pkcs11::Object::DestroyObject(const v8::Arguments& args) {
  CK_RV rv = C_DestroyObject(session_handle_, object_handle_);
  if (!OkOrThrow(rv))
    return v8::Undefined();

  return v8::True();
}

v8::Handle<v8::Value> Pkcs11::Construct(const v8::Arguments& args) {
  if (!OkOrThrow(InitializeLibrary()))
    return v8::Undefined();

  if (!Initialize())
    return ThrowException("Error initializing Pkcs11 object");

  return args.This();
}

// static.
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

// static.
bool Pkcs11::InitializeTemplate(v8::Handle<v8::FunctionTemplate> ctor_t) {
  ctor_t->Set(v8::String::NewSymbol("Slots"),
              Pkcs11::Slots::constructor_template());
  ctor_t->Set(v8::String::NewSymbol("Slot"),
              Pkcs11::Slot::constructor_template());
  ctor_t->Set(v8::String::NewSymbol("Token"),
              Pkcs11::Token::constructor_template());
  ctor_t->Set(v8::String::NewSymbol("Session"),
              Pkcs11::Session::constructor_template());
  ctor_t->Set(v8::String::NewSymbol("Object"),
              Pkcs11::Object::constructor_template());

  // These are in the order they appear in opencryptoki/pkcs11types.h.
  SET_CK_CONST(ctor_t, CKR_OK);
  SET_CK_CONST(ctor_t, CKR_CANCEL);
  SET_CK_CONST(ctor_t, CKR_HOST_MEMORY);
  SET_CK_CONST(ctor_t, CKR_SLOT_ID_INVALID);
  SET_CK_CONST(ctor_t, CKR_GENERAL_ERROR);
  SET_CK_CONST(ctor_t, CKR_FUNCTION_FAILED);
  SET_CK_CONST(ctor_t, CKR_ARGUMENTS_BAD);
  SET_CK_CONST(ctor_t, CKR_NO_EVENT);
  SET_CK_CONST(ctor_t, CKR_NEED_TO_CREATE_THREADS);
  SET_CK_CONST(ctor_t, CKR_CANT_LOCK);
  SET_CK_CONST(ctor_t, CKR_ATTRIBUTE_READ_ONLY);
  SET_CK_CONST(ctor_t, CKR_ATTRIBUTE_SENSITIVE);
  SET_CK_CONST(ctor_t, CKR_ATTRIBUTE_TYPE_INVALID);
  SET_CK_CONST(ctor_t, CKR_ATTRIBUTE_VALUE_INVALID);
  SET_CK_CONST(ctor_t, CKR_DATA_INVALID);
  SET_CK_CONST(ctor_t, CKR_DATA_LEN_RANGE);
  SET_CK_CONST(ctor_t, CKR_DEVICE_ERROR);
  SET_CK_CONST(ctor_t, CKR_DEVICE_MEMORY);
  SET_CK_CONST(ctor_t, CKR_DEVICE_REMOVED);
  SET_CK_CONST(ctor_t, CKR_ENCRYPTED_DATA_INVALID);
  SET_CK_CONST(ctor_t, CKR_ENCRYPTED_DATA_LEN_RANGE);
  SET_CK_CONST(ctor_t, CKR_FUNCTION_CANCELED);
  SET_CK_CONST(ctor_t, CKR_FUNCTION_NOT_PARALLEL);
  SET_CK_CONST(ctor_t, CKR_FUNCTION_NOT_SUPPORTED);
  SET_CK_CONST(ctor_t, CKR_KEY_HANDLE_INVALID);
  SET_CK_CONST(ctor_t, CKR_KEY_SIZE_RANGE);
  SET_CK_CONST(ctor_t, CKR_KEY_TYPE_INCONSISTENT);
  SET_CK_CONST(ctor_t, CKR_KEY_NOT_NEEDED);
  SET_CK_CONST(ctor_t, CKR_KEY_CHANGED);
  SET_CK_CONST(ctor_t, CKR_KEY_NEEDED);
  SET_CK_CONST(ctor_t, CKR_KEY_INDIGESTIBLE);
  SET_CK_CONST(ctor_t, CKR_KEY_FUNCTION_NOT_PERMITTED);
  SET_CK_CONST(ctor_t, CKR_KEY_NOT_WRAPPABLE);
  SET_CK_CONST(ctor_t, CKR_KEY_UNEXTRACTABLE);
  SET_CK_CONST(ctor_t, CKR_MECHANISM_INVALID);
  SET_CK_CONST(ctor_t, CKR_MECHANISM_PARAM_INVALID);
  SET_CK_CONST(ctor_t, CKR_OBJECT_HANDLE_INVALID);
  SET_CK_CONST(ctor_t, CKR_OPERATION_ACTIVE);
  SET_CK_CONST(ctor_t, CKR_OPERATION_NOT_INITIALIZED);
  SET_CK_CONST(ctor_t, CKR_PIN_INCORRECT);
  SET_CK_CONST(ctor_t, CKR_PIN_INVALID);
  SET_CK_CONST(ctor_t, CKR_PIN_LEN_RANGE);
  SET_CK_CONST(ctor_t, CKR_PIN_EXPIRED);
  SET_CK_CONST(ctor_t, CKR_PIN_LOCKED);
  SET_CK_CONST(ctor_t, CKR_SESSION_CLOSED);
  SET_CK_CONST(ctor_t, CKR_SESSION_COUNT);
  SET_CK_CONST(ctor_t, CKR_SESSION_HANDLE_INVALID);
  SET_CK_CONST(ctor_t, CKR_SESSION_PARALLEL_NOT_SUPPORTED);
  SET_CK_CONST(ctor_t, CKR_SESSION_READ_ONLY);
  SET_CK_CONST(ctor_t, CKR_SESSION_EXISTS);
  SET_CK_CONST(ctor_t, CKR_SESSION_READ_ONLY_EXISTS);
  SET_CK_CONST(ctor_t, CKR_SESSION_READ_WRITE_SO_EXISTS);
  SET_CK_CONST(ctor_t, CKR_SIGNATURE_INVALID);
  SET_CK_CONST(ctor_t, CKR_SIGNATURE_LEN_RANGE);
  SET_CK_CONST(ctor_t, CKR_TEMPLATE_INCOMPLETE);
  SET_CK_CONST(ctor_t, CKR_TEMPLATE_INCONSISTENT);
  SET_CK_CONST(ctor_t, CKR_TOKEN_NOT_PRESENT);
  SET_CK_CONST(ctor_t, CKR_TOKEN_NOT_RECOGNIZED);
  SET_CK_CONST(ctor_t, CKR_TOKEN_WRITE_PROTECTED);
  SET_CK_CONST(ctor_t, CKR_UNWRAPPING_KEY_HANDLE_INVALID);
  SET_CK_CONST(ctor_t, CKR_UNWRAPPING_KEY_SIZE_RANGE);
  SET_CK_CONST(ctor_t, CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT);
  SET_CK_CONST(ctor_t, CKR_USER_ALREADY_LOGGED_IN);
  SET_CK_CONST(ctor_t, CKR_USER_NOT_LOGGED_IN);
  SET_CK_CONST(ctor_t, CKR_USER_PIN_NOT_INITIALIZED);
  SET_CK_CONST(ctor_t, CKR_USER_TYPE_INVALID);
  SET_CK_CONST(ctor_t, CKR_USER_ANOTHER_ALREADY_LOGGED_IN);
  SET_CK_CONST(ctor_t, CKR_USER_TOO_MANY_TYPES);
  SET_CK_CONST(ctor_t, CKR_WRAPPED_KEY_INVALID);
  SET_CK_CONST(ctor_t, CKR_WRAPPED_KEY_LEN_RANGE);
  SET_CK_CONST(ctor_t, CKR_WRAPPING_KEY_HANDLE_INVALID);
  SET_CK_CONST(ctor_t, CKR_WRAPPING_KEY_SIZE_RANGE);
  SET_CK_CONST(ctor_t, CKR_WRAPPING_KEY_TYPE_INCONSISTENT);
  SET_CK_CONST(ctor_t, CKR_RANDOM_SEED_NOT_SUPPORTED);
  SET_CK_CONST(ctor_t, CKR_RANDOM_NO_RNG);
  SET_CK_CONST(ctor_t, CKR_DOMAIN_PARAMS_INVALID);
  SET_CK_CONST(ctor_t, CKR_BUFFER_TOO_SMALL);
  SET_CK_CONST(ctor_t, CKR_SAVED_STATE_INVALID);
  SET_CK_CONST(ctor_t, CKR_INFORMATION_SENSITIVE);
  SET_CK_CONST(ctor_t, CKR_STATE_UNSAVEABLE);
  SET_CK_CONST(ctor_t, CKR_CRYPTOKI_NOT_INITIALIZED);
  SET_CK_CONST(ctor_t, CKR_CRYPTOKI_ALREADY_INITIALIZED);
  SET_CK_CONST(ctor_t, CKR_MUTEX_BAD);
  SET_CK_CONST(ctor_t, CKR_MUTEX_NOT_LOCKED);
  SET_CK_CONST(ctor_t, CKR_VENDOR_DEFINED);

  return true;
}

}  // namespace crypto

}  // namespace entd
