// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "entd/utils.h"

#include <fcntl.h>
#include <stdlib.h>

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
                                const std::string& desc) {
  std::string res;
  Handle<String> jsdesc = String::New(desc.c_str());
  if (obj->Has(jsdesc)) {
    res = ValueAsUtf8String(obj->Get(jsdesc));
  }
  return res;
}

StringList GetPropertyAsStringList(v8::Handle<v8::Object> obj,
                                   const std::string& desc) {
  StringList result;
  Handle<String> jsdesc = String::New(desc.c_str());
  if (obj->Has(jsdesc)) {
    Local<Array> jsarray = Local<Array>::Cast(obj->Get(jsdesc));
    if (!jsarray->IsUndefined()) {
      for (size_t i = 0; i < jsarray->Length(); i++) {
        std::string s = ValueAsUtf8String(jsarray->Get(i));
        result.push_back(s);
      }
    }
  }
  return result;
}

void ThrowV8Exception(const std::string& err) {
  ThrowException(String::New(err.c_str()));
}

}  // namespace utils

}  // namespace entd
