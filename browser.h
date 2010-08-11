// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ENTD_BROWSER_H_
#define ENTD_BROWSER_H_

#include "entd/scriptable.h"
#include "base/file_path.h"

namespace entd {

class Entd;

// Relative to $HOME
static const std::string kPolicySubdirectory = "var/browser-policies/";
static const std::string kPolicyNameManaged = "managed";
static const std::string kPolicyNameRecommended = "recommended";
static const std::string kPolicyFilename = "01-entd-policy.json";

class Browser : public Scriptable<Browser> {
 public:
  enum PolicyType {
    kManagedPolicy,
    kRecommendedPolicy
  };

  class Policy : public Scriptable<Policy> {
   public:
    Policy();

    static const std::string class_name() { return "entd.Browser.Policy"; };

    bool Initialize(Entd* entd, PolicyType policy_type);
    static bool InitializeTemplate(v8::Handle<v8::FunctionTemplate> ctor_t);

    v8::Handle<v8::Value> Construct(const v8::Arguments& args) {
      return ThrowNoScriptableConstructor();
    }

    // Named property sets and deletes are hooked so we can persist the
    // new policy to disk (or raise an error if the new value can't be
    // serialized.)
    static v8::Handle<v8::Value> SetNamedProperty(
        v8::Local<v8::String> name, v8::Local<v8::Value> value,
        const v8::AccessorInfo& info);
    static v8::Handle<v8::Boolean> DeleteNamedProperty(
        v8::Local<v8::String> name, const v8::AccessorInfo& info);

    // Load a browser policy from disk.
    bool Load();

    // Save the serialized policy to disk.
    bool Persist(const std::string& serialized_oject);

   private:
    Entd* entd_;
    FilePath policy_path_;
  };

  static const std::string class_name() { return "entd.Browser"; };

  v8::Handle<v8::Value> Construct(const v8::Arguments& args) {
    return ThrowNoScriptableConstructor();
  }

  bool Initialize(Entd* entd);
  static bool InitializeTemplate(v8::Handle<v8::FunctionTemplate> ctor_t);

};

}  // namespace entd

#endif  // ENTD_BROWSER_H_
