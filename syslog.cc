// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Provides the implementation of Syslog.

#include "entd/syslog.h"

#include <iostream>
#include <string>
#include <list>
#include <vector>

#include <base/basictypes.h>
#include <base/logging.h>
#include <curl/curl.h>

#include "entd/utils.h"

namespace entd {


Syslog::~Syslog() {
  CleanupTemplate();  // We only have one Syslog instance
}

static v8::Handle<v8::Value> dispatch_Info(const v8::Arguments& args) {
  std::string msg;
  for (int i = 0; i < args.Length(); ++i) {
    if (i != 0) msg += '\n';
    msg += utils::ValueAsUtf8String(args[i]);
  }
  LOG(INFO) << msg;
  return v8::True();
}

static v8::Handle<v8::Value> dispatch_Warn(const v8::Arguments& args) {
  std::string msg;
  for (int i = 0; i < args.Length(); ++i) {
    if (i != 0) msg += '\n';
    msg += utils::ValueAsUtf8String(args[i]);
  }
  LOG(WARNING) << msg;
  return v8::True();
}

static v8::Handle<v8::Value> dispatch_Error(const v8::Arguments& args) {
  std::string msg;
  for (int i = 0; i < args.Length(); ++i) {
    if (i != 0) msg += '\n';
    msg += utils::ValueAsUtf8String(args[i]);
  }
  LOG(ERROR) << msg;
  return v8::True();
}

// static
void Syslog::SetTemplateBindings(
    v8::Handle<v8::ObjectTemplate> template_object) {
  template_object->Set(v8::String::NewSymbol("info"),
                       v8::FunctionTemplate::New(dispatch_Info));
  template_object->Set(v8::String::NewSymbol("warn"),
                       v8::FunctionTemplate::New(dispatch_Warn));
  template_object->Set(v8::String::NewSymbol("error"),
                       v8::FunctionTemplate::New(dispatch_Error));
}

} // namespace entd
