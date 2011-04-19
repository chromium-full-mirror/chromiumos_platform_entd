// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "entd/tpm.h"

#include "cros/chromeos_cryptohome.h"
#include "entd/entd.h"

namespace entd {

bool Tpm::cryptohome_init_pkcs11 = false;

bool Tpm::Initialize() {
  return true;
}

// static
bool Tpm::InitializeTemplate(
    v8::Handle<v8::FunctionTemplate> ctor_t) {
  v8::Handle<v8::ObjectTemplate> instance_t = ctor_t->InstanceTemplate();

  instance_t->SetAccessor(v8::String::New("isEnabled"),
                          Tpm::IsEnabled,
                          0,  // readonly, so setter is NULL
                          v8::Handle<v8::Value>(),  // Don't need any data.
                          v8::DEFAULT,  // DEFAULT AccessControl
                          v8::DontDelete);

  instance_t->SetAccessor(v8::String::New("isReady"),
                          Tpm::IsReady,
                          0,  // readonly, so setter is NULL
                          v8::Handle<v8::Value>(),  // Don't need any data.
                          v8::DEFAULT,  // DEFAULT AccessControl
                          v8::DontDelete);

  instance_t->SetAccessor(v8::String::New("isOwned"),
                          Tpm::IsOwned,
                          0,  // readonly, so setter is NULL
                          v8::Handle<v8::Value>(),  // Don't need any data.
                          v8::DEFAULT,  // DEFAULT AccessControl
                          v8::DontDelete);

  instance_t->SetAccessor(v8::String::New("isBeingOwned"),
                          Tpm::IsBeingOwned,
                          0,  // readonly, so setter is NULL
                          v8::Handle<v8::Value>(),  // Don't need any data.
                          v8::DEFAULT,  // DEFAULT AccessControl
                          v8::DontDelete);

  instance_t->SetAccessor(v8::String::New("statusString"),
                          Tpm::GetStatusString,
                          0,  // readonly, so setter is NULL
                          v8::Handle<v8::Value>(),  // Don't need any data.
                          v8::DEFAULT,  // DEFAULT AccessControl
                          v8::DontDelete);
  if (cryptohome_init_pkcs11) {
    instance_t->SetAccessor(v8::String::New("isTokenReady"),
                            Tpm::IsTokenReady,
                            0,  // readonly, so setter is NULL
                            v8::Handle<v8::Value>(),  // Don't need any data.
                            v8::DEFAULT,  // DEFAULT AccessControl
                            v8::DontDelete);
  }

  return true;
}

// static
v8::Handle<v8::Value> Tpm::IsEnabled(v8::Local<v8::String> property,
                                     const v8::AccessorInfo& info) {
  if (!Entd::LibcrosLoadedOrThrow())
    return v8::False();

  return v8::Boolean::New(chromeos::CryptohomeTpmIsEnabled());
}

// static
v8::Handle<v8::Value> Tpm::IsReady(v8::Local<v8::String> property,
                                   const v8::AccessorInfo& info) {
  if (!Entd::LibcrosLoadedOrThrow())
    return v8::False();

  return v8::Boolean::New(chromeos::CryptohomeTpmIsReady());
}

// static
v8::Handle<v8::Value> Tpm::IsOwned(v8::Local<v8::String> property,
                                   const v8::AccessorInfo& info) {
  if (!Entd::LibcrosLoadedOrThrow())
    return v8::False();

  return v8::Boolean::New(chromeos::CryptohomeTpmIsOwned());
}

// static
v8::Handle<v8::Value> Tpm::IsBeingOwned(v8::Local<v8::String> property,
                                        const v8::AccessorInfo& info) {
  if (!Entd::LibcrosLoadedOrThrow())
    return v8::False();

  return v8::Boolean::New(chromeos::CryptohomeTpmIsBeingOwned());
}

// static
v8::Handle<v8::Value> Tpm::GetStatusString(v8::Local<v8::String> property,
                                           const v8::AccessorInfo& info) {
  if (!Entd::LibcrosLoadedOrThrow())
    return v8::Undefined();

  std::string status;
  chromeos::CryptohomeGetStatusString(&status);
  return v8::String::New(status.c_str());
}

// static
v8::Handle<v8::Value> Tpm::IsTokenReady(v8::Local<v8::String> property,
                                        const v8::AccessorInfo& info) {
  return v8::Boolean::New(chromeos::CryptohomePkcs11IsTpmTokenReady());
}

}  // namespace entd
