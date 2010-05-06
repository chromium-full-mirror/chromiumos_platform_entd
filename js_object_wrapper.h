// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ENTD_JS_OBJECT_WRAPPER_H_
#define ENTD_JS_OBJECT_WRAPPER_H_

#include <string>
#include <v8.h>
#include <base/basictypes.h>

#include "entd/utils.h"

namespace entd {

// Template class to bind a C++ object to a V8 object.
// The class builds a single global Persistent template object and
// reserves a single internal field to hold a pointer to the C++ object.
// Each C++ object constructs a V8 object and binds itself to it.
// Additional bindings happen in SetTemplateBindings().
//
// NOTE: This uses the "curiously recurring template pattern"
// to implement singleton behavior for function templates.
//
// Example usage:
//  class JSSyslog : public JSObjectWrapper<JSSyslog>
//  {
//  };

template<typename T>
class JSObjectWrapper {
 public:
  virtual ~JSObjectWrapper() {
    obj_.Dispose();
  }

  // JS Object instance management...

  // Make sure to call JSObjectWrapper<Foo>::Initialize() if overridden by Foo
  virtual bool Initialize();

  // Builds an instance and passes args to ParseConstructorArgs()
  static v8::Handle<v8::Value> Construct(const v8::Arguments& args);

  // Override this to parse the args and set instance properties
  virtual void ParseConstructorArgs(v8::Handle<v8::Object> obj,
                                    const v8::Arguments& args) {
  }

  // Extract the C++ object pointer from the V8 object internal field 0
  static T* Unwrap(v8::Handle<v8::Object> obj);

  // Unwrap the C++ object pointer from args[index]
  static T* GetFromArg(const v8::Arguments& args, int index);

  // JS Function Template management...

  // GetClassName() must be defined for the derived class:
  // static const char* GetClassName() { return "foo"; }

  // Return the V8 template. ManageTemplete will build it if necessary.
  // Define SetTemplateBindings() to bind JS methods to C++ (see below)
  static v8::Handle<v8::FunctionTemplate> GetTemplate() {
    return ManageTemplate(true);
  }

  // Call ManageTemplate() with 'false' to destroy the template
  static void CleanupTemplate() {
    ManageTemplate(false);
  }

  // Accessors
  v8::Handle<v8::Object> obj() { return obj_; }

 private:

  // ManageTemplate handles construction and destruction of a
  // singleton function template instance.
  //
  // If build is true, construct the template object if necessary, otherwise
  // dispose of the template if it exists.
  //
  // Returns the function template handle (undefined if build is false)
  static v8::Handle<v8::FunctionTemplate> ManageTemplate(bool build);

  // Override this to bind methods or data to the template. e.g.:
  // tmpl_obj->Set(String::New("bar"), FunctionTemplate::New(dispatch_Bar));
  static void SetTemplateBindings(v8::Handle<v8::ObjectTemplate> tmpl_obj) {}

  // V8 Object bound to this C++ instance
  v8::Persistent<v8::Object> obj_;
};

#include "entd/js_object_wrapper-inl.h"

} // namespace entd

#endif // ENTD_JS_OBJECT_WRAPPER_
