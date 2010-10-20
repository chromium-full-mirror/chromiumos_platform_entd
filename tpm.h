// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ENTD_TPM_H_
#define ENTD_TPM_H_

#include "entd/scriptable.h"

namespace entd {

class Tpm : public Scriptable<Tpm> {
 public:
  static const std::string class_name() { return "entd.Tpm"; };

  v8::Handle<v8::Value> Construct(const v8::Arguments& args) {
    return ThrowNoScriptableConstructor();
  }

  bool Initialize();
  static bool InitializeTemplate(v8::Handle<v8::FunctionTemplate> ctor_t);

  static v8::Handle<v8::Value> IsEnabled(v8::Local<v8::String> property,
                                         const v8::AccessorInfo& info);
  static v8::Handle<v8::Value> IsReady(v8::Local<v8::String> property,
                                       const v8::AccessorInfo& info);
  static v8::Handle<v8::Value> IsOwned(v8::Local<v8::String> property,
                                       const v8::AccessorInfo& info);
  static v8::Handle<v8::Value> IsBeingOwned(v8::Local<v8::String> property,
                                            const v8::AccessorInfo& info);
  static v8::Handle<v8::Value> GetStatusString(v8::Local<v8::String> property,
                                               const v8::AccessorInfo& info);
};

}  // namespace entd

#endif  // ENTD_BROWSER_H_
