// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "entd/browser.h"

#include "base/file_util.h"
#include "base/logging.h"

#include "entd/entd.h"
#include "entd/utils.h"

namespace entd {

Browser::Policy::Policy()
    : entd_(NULL),
      policy_path_("/") {
}

bool Browser::Policy::Initialize(Entd *entd, PolicyType policy_type) {
  entd_ = entd;

  char* home = getenv("HOME");
  if (!home) {
    LOG(ERROR) << "HOME is not set.";
    return false;
  }

  policy_path_ = FilePath(home).Append(kPolicySubdirectory);

  if (policy_type == kManagedPolicy) {
    policy_path_ = policy_path_.Append(kPolicyNameManaged);
  } else {
    policy_path_ = policy_path_.Append(kPolicyNameRecommended);
  }

  policy_path_ = policy_path_.Append(kPolicyFilename);

  // We ignore the return value of Load, since we don't want to fail all of
  // entd startup just because we couldn't read the previous policy.
  Load();

  return true;
}

// static
bool Browser::Policy::InitializeTemplate(
    v8::Handle<v8::FunctionTemplate> ctor_t) {
  v8::Handle<v8::ObjectTemplate> instance_t = ctor_t->InstanceTemplate();

  instance_t->SetNamedPropertyHandler(0, // GetNamedProperty,
                                      SetNamedProperty,
                                      0, // QueryNamedProperty,
                                      DeleteNamedProperty,
                                      0); // EnumerateNamedProperties);

  return true;
}

// static
v8::Handle<v8::Value> Browser::Policy::SetNamedProperty(
    v8::Local<v8::String> name, v8::Local<v8::Value> value,
    const v8::AccessorInfo& info) {
  Browser::Policy* policy = Browser::Policy::UnwrapOrThrow(info.This(), "this");
  if (!policy)
    return v8::Undefined();

  v8::Handle<v8::Object> self = policy->js_object();
  v8::Handle<v8::Value> old_value = self->Get(name);

  self->ForceSet(name, value);

  v8::Handle<v8::Value> serialized_object;
  if (!policy->entd_->JsonStringify(self, &serialized_object)) {
    self->ForceSet(name, old_value);
    return ThrowException("Invalid value");
  }

  v8::String::Utf8Value utf8_object(serialized_object);
  if (!policy->Persist(std::string(*utf8_object, utf8_object.length()))) {
    self->ForceSet(name, old_value);
    return ThrowException("Error persisting policy");
  }

  return value;
}

// static
v8::Handle<v8::Boolean> Browser::Policy::DeleteNamedProperty(
    v8::Local<v8::String> name, const v8::AccessorInfo& info) {
  Browser::Policy* policy = Browser::Policy::UnwrapOrThrow(info.This(), "this");
  if (!policy)
    return v8::False();

  v8::Handle<v8::Object> self = policy->js_object();
  v8::Handle<v8::Value> old_value = self->Get(name);

  self->ForceDelete(name);

  v8::Handle<v8::Value> serialized_object;
  if (!policy->entd_->JsonStringify(self, &serialized_object)) {
    self->ForceSet(name, old_value);

    // v8 doesn't like you to throw exceptions from `delete`.
    LOG(ERROR) << "Error serializing browser policy";
    return v8::False();
  }

  v8::String::Utf8Value utf8_object(serialized_object);
  if (!policy->Persist(std::string(*utf8_object, utf8_object.length()))) {
    self->ForceSet(name, old_value);
    return v8::False();
  }

  return v8::True();
}

bool Browser::Policy::Load() {
  if (!file_util::PathExists(policy_path_))
    return true;

  LOG(INFO) << "Loading browser policy file: " << policy_path_.value();

  std::string serialized_object;

  if (!file_util::ReadFileToString(policy_path_, &serialized_object)) {
    PLOG(ERROR) << "Error loading browser policy file: " <<
        policy_path_.value();
    return false;
  }

  v8::Handle<v8::Value> value;
  if (!entd_->JsonParse(v8::String::New(serialized_object.c_str()), &value)) {
    LOG(ERROR) << "Error parsing browser policy file";
    return false;
  }

  if (!value->IsObject()) {
    LOG(ERROR) << "Browser policy file did not represent an object";
    return false;
  }

  v8::Handle<v8::Object> policy_values = value->ToObject();
  v8::Handle<v8::Object> self = js_object();

  v8::Local<v8::Array> ary = policy_values->GetPropertyNames();
  for (uint32_t i = 0; i < ary->Length(); ++i) {
    v8::Local<v8::Value> name = ary->Get(i);
    self->Set(name, policy_values->Get(name));
  }

  return true;
}

bool Browser::Policy::Persist(const std::string& serialized_object) {
  FilePath base_dir = policy_path_.DirName();
  if (!file_util::CreateDirectory(base_dir)) {
    PLOG(ERROR) << "Error creating path: " << base_dir.value();
    return false;
  }

  if (file_util::WriteFile(
          policy_path_, serialized_object.c_str(),
          serialized_object.length()) == -1) {
    PLOG(ERROR) << "Error saving browser policy file: " <<
        policy_path_.value();
    return false;
  }

  return true;
}

bool Browser::Initialize(Entd* entd) {
  v8::Handle<v8::Object> self = js_object();

  Browser::Policy::Reference managed_policy = Browser::Policy::New();
  if (!managed_policy->Initialize(entd, kManagedPolicy))
    return false;

  Browser::Policy::Reference recommended_policy = Browser::Policy::New();
  if (!recommended_policy->Initialize(entd, kRecommendedPolicy))
    return false;

  self->Set(v8::String::New("managedPolicy"),
            managed_policy->js_object());
  self->Set(v8::String::New("recommendedPolicy"),
            recommended_policy->js_object());

  return true;
}

bool Browser::InitializeTemplate(v8::Handle<v8::FunctionTemplate> ctor_t) {
  ctor_t->Set(v8::String::New("Policy"),
              Policy::constructor_template()->GetFunction());

  return true;
}


}  // namespace entd
