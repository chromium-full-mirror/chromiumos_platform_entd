// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ENTD_UTILS_H_
#define ENTD_UTILS_H_

#include <list>
#include <string>
#include <vector>
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

// Checks to see if the string contains only characters legal in a domain name
bool CheckHostnameCharset(const std::string& str);

// Reads a file into a V8 String.
v8::Handle<v8::String> ReadFile(const std::string& name);

// Reads the contents of a directory into an array of file/dir names.
std::vector<std::string> ReadDirectory(const std::string& path);

// Expands any environment variables, including ~ and ~user
// Asumes that path is a single word.
std::string ExpandFilePath(const std::string& path);

// Convert a V8 Value to a std::string
std::string ValueAsUtf8String(v8::Handle<v8::Value> value);

// Retrieve the named JS parameter from the V8 object
// and convert it to a std::string
std::string GetPropertyAsString(v8::Handle<v8::Object> obj,
                                const std::string& name);

// Returns the named property "desc" in object "obj" as a StringList.
// "desc" can be either:
// * an Array, in which case each element is added to the result
//   as its String representation
// * an Object, in which case each property is added to the result
//   as "property + delim + property value"
typedef std::list<std::string> StringList;
StringList GetPropertyAsStringList(v8::Handle<v8::Object> obj,
                                   const std::string& name,
                                   const std::string& delim);

void ThrowV8Exception(const std::string& err);

// Prints the exception described in 'try_catch'
void ReportV8Exception(v8::TryCatch* try_catch);

// Call the V8 method in 'obj' associated with the property 'cb_name'
// 'argc' and 'arcv' specify arguments to the V8 method.
// Returns the result of the function if successfully called,
// or an empty handle if the function is not called.
v8::Handle<v8::Value> CallV8Function(
    v8::Handle<v8::Object> obj, const std::string& cb_name,
    int argc, v8::Handle<v8::Value> argv[]);

}  // namespace utils

}  // namespace entd

#endif // ENTD_UTILS_H_
