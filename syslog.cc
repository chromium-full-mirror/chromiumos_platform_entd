// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Provides the implementation of Syslog.

#include "entd/syslog.h"

#include <iostream>
#include <string>
#include <list>
#include <vector>

#include <curl/curl.h>

#include "base/basictypes.h"
#include "base/logging.h"

#include "entd/utils.h"

namespace entd {

using namespace v8;

Syslog::~Syslog() {
  CleanupTemplate();  // We only have one Syslog instance
}

static Handle<Value> dispatch_Info(const Arguments& args) {
  std::string msg;
  for (int i = 0; i < args.Length(); ++i) {
    if (i != 0) msg += '\n';
    msg += utils::ValueAsUtf8String(args[i]);
  }
  LOG(INFO) << msg;
  return v8::True();
}

static Handle<Value> dispatch_Warn(const Arguments& args) {
  std::string msg;
  for (int i = 0; i < args.Length(); ++i) {
    if (i != 0) msg += '\n';
    msg += utils::ValueAsUtf8String(args[i]);
  }
  LOG(WARNING) << msg;
  return v8::True();
}

static Handle<Value> dispatch_Error(const Arguments& args) {
  std::string msg;
  for (int i = 0; i < args.Length(); ++i) {
    if (i != 0) msg += '\n';
    msg += utils::ValueAsUtf8String(args[i]);
  }
  LOG(ERROR) << msg;
  return v8::True();
}

// static
void Syslog::SetTemplateBindings(Handle<ObjectTemplate> template_object) {
  template_object->Set(String::NewSymbol("info"),
                       FunctionTemplate::New(dispatch_Info));
  template_object->Set(String::NewSymbol("warn"),
                       FunctionTemplate::New(dispatch_Warn));
  template_object->Set(String::NewSymbol("error"),
                       FunctionTemplate::New(dispatch_Error));
}

} // namespace entd
