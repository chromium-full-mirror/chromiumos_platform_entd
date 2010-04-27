// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ENTD_UTILS_H_
#define ENTD_UTILS_H_

#include <list>
#include <string>
#include <v8.h>

namespace entd {

namespace utils {

// malloc some memory, exit(2) if OOM.  Used to create things libevent might
// want to free.
void* malloc(size_t size);

// free some memory allocated by utils::malloc()
void free(void *buf);

// Extracts a C string from a V8 Utf8Value.
const char* ToCString(const v8::String::Utf8Value& value);

// Reads a file into a v8 string.
v8::Handle<v8::String> ReadFile(const std::string& name);

// Convert a V8 Value to a std::string
std::string ValueAsUtf8String(v8::Handle<v8::Value> value);

// Retrieve the named JS parameter from the V8 object
//  and convert it to a std::string
std::string GetPropertyAsString(v8::Handle<v8::Object> obj,
                                const std::string& desc);

typedef std::list<std::string> StringList;
StringList GetPropertyAsStringList(v8::Handle<v8::Object> obj,
                                   const std::string& desc);

void ThrowV8Exception(const std::string& err);

}  // namespace utils

}  // namespace entd

#endif // ENTD_UTILS_H_
