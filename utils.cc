// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "entd/utils.h"

#include <fcntl.h>
#include <iostream>
#include <stdlib.h>

#include <base/basictypes.h>
#include <base/logging.h>

namespace entd {

namespace utils {

using namespace v8;

void* malloc(size_t size) {
  void* rv = ::malloc(size);
  if (!rv)
    exit(2);

  return rv;
}

void free(void *buf) {
  ::free(buf);
}

// Extracts a C string from a V8 Utf8Value.
const char* ToCString(const v8::String::Utf8Value& value) {
  return *value ? *value : "<string conversion failed>";
}

// Reads a file into a v8 string.
v8::Handle<v8::String> ReadFile(const std::string& name) {
  v8::Handle<v8::String> result = v8::Handle<v8::String>();

  int fd = open(name.c_str(), O_RDONLY);
  if (fd == -1)
    return result;

  struct stat buf;
  fstat(fd, &buf);

  if (buf.st_size > 1) {
    char* chars = new char[buf.st_size + 1];
    chars[buf.st_size] = '\0';
    if (read(fd, &chars[0], buf.st_size) == buf.st_size)
      result = v8::String::New(chars, buf.st_size);

    delete[] chars;
  }

  close(fd);
  return result;
}

std::string ValueAsUtf8String(v8::Handle<v8::Value> value) {
  Local<String> s = value->ToString();
  return std::string(*String::Utf8Value(s));
}

std::string GetPropertyAsString(v8::Handle<v8::Object> obj,
                                const std::string& name) {
  std::string res;
  Handle<String> jsname = String::New(name.c_str());
  if (obj->Has(jsname)) {
    res = ValueAsUtf8String(obj->Get(jsname));
  }
  return res;
}

// "delim" only applies to object properties; it is ignored for Arrays
StringList GetPropertyAsStringList(v8::Handle<v8::Object> obj,
                                   const std::string& name,
                                   const std::string& delim) {
  StringList result;
  Handle<String> jsname = String::New(name.c_str());
  if (obj->Has(jsname)) {
    Local<Value> jsvalue = obj->Get(jsname);
    if (jsvalue->IsArray()) {
      Local<Array> jsarray = Local<Array>::Cast(obj->Get(jsname));
      for (size_t i = 0; i < jsarray->Length(); i++) {
        std::string s = ValueAsUtf8String(jsarray->Get(i));
        result.push_back(s);
      }
    } else if (jsvalue->IsObject()) {
      Local<Object> paramobj = Local<Object>::Cast(obj->Get(jsname));
      Local<Array> props = paramobj->GetPropertyNames();
      for (size_t i = 0; i < props->Length(); ++i) {
        Handle<Value> propname = props->Get(i);
        std::string name = ValueAsUtf8String(propname);
        std::string value = ValueAsUtf8String(paramobj->Get(propname));
        std::string s = name + delim + value;
        result.push_back(s);
      }
    }
  }
  return result;
}

void ThrowV8Exception(const std::string& err) {
  ThrowException(String::New(err.c_str()));
}

void ReportV8Exception(TryCatch* try_catch) {
  std::cerr << "V8 Exception:\n";
  HandleScope handle_scope;
  String::Utf8Value exception(try_catch->Exception());
  const char* exception_string = utils::ToCString(exception);
  Handle<Message> message = try_catch->Message();

  if (message.IsEmpty()) {
    // V8 didn't provide any extra information about this error; just
    // print the exception.
    std::cerr << exception_string << '\n';
  } else {
    // Print (filename):(line number): (message).
    String::Utf8Value filename(message->GetScriptResourceName());
    const char* filename_string = utils::ToCString(filename);
    int linenum = message->GetLineNumber();
    std::cerr << filename_string << ':' << linenum << ": " <<
        exception_string << '\n';

    // Print line of source code.
    String::Utf8Value sourceline(message->GetSourceLine());
    const char* sourceline_string = utils::ToCString(sourceline);
    std::cerr << sourceline_string << '\n';

    // Print wavy underline (GetUnderline is deprecated).
    int start = message->GetStartColumn();
    for (int i = 0; i < start; i++) {
      std::cerr << ' ';
    }

    int end = message->GetEndColumn();
    for (int i = start; i < end; i++) {
      std::cerr << '^';
    }

    std::cerr << '\n';
  }
}

// Note: This assumes it is not getting called from inside a JS
// stack (current use cases), so it users LOG(ERROR)
// instead of ThrowException
// If called from a JS stack, the caller should throw an
// exception if this returns an empty handle.
Handle<Value> CallV8Function(Handle<Object> obj,
                             const std::string& cb_name,
                             int argc, Handle<Value> argv[]) {
  if (obj.IsEmpty() || !obj->IsObject()) {
    LOG(ERROR) << "Invalid object when trying to call: " << cb_name;
    return Handle<Value>();
  }
  Handle<Value> cb = obj->Get(String::New(cb_name.c_str()));
  if (cb->IsUndefined()) {
    LOG(ERROR) << "Object does not have property: "<< cb_name;
    return Handle<Value>();
  }
  if (!cb->IsFunction()) {
    LOG(ERROR) << "Property is not a function: " << cb_name;
    return Handle<Value>();
  }
  return Handle<Function>::Cast(cb)->Call(obj, argc, argv);
}

}  // namespace utils

}  // namespace entd
