// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ENTD_UTILS_H_
#define ENTD_UTILS_H_

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

}  // namespace utils

}  // namespace entd

#endif // ENTD_UTILS_H_
