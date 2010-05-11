// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ENTD_EXTENSIONS_H_
#define ENTD_EXTENSIONS_H_

#include <map>
#include <string>

#include <base/basictypes.h>

namespace entd {

namespace extensions {

// Look for a valid extension at base_path or a default path if unspecified.
//
// Always examines the highest numbered version subdirectory for each
// directory in base_path. Older versions are ignored (i.e. not checked).
//
// The definition of a valid extension is defined by
// class Extension in the code.
//
// If no valid extensions exist, or more than one exists, return false.
// Otherwise sets extension_path and returns true.
bool FindValidPolicy(const std::string& base_path, std::string* extension_path);

}  // namespace extensions

}  // namespace entd

#endif  // ENTD_EXTENSIONS_H_
