// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ENTD_SYSLOG_H_
#define ENTD_SYSLOG_H_

#include <string>

#include <base/basictypes.h>
#include <v8.h>

#include "entd/js_object_wrapper.h"

namespace entd {

// Very simple JS bindings for sending output to the syslog
//  entd.info("foo") -> LOG(INFO)
//  entd.warn("foo") -> LOG(WARNING)
//  entd.error("foo") -> LOG(ERROR)
class Syslog : public JSObjectWrapper<Syslog> {
 public:
  Syslog() {}
  virtual ~Syslog();

  static const char* GetClassName() { return "syslog"; }

  // Binds "info", "warn", and "error" functions.
  static void SetTemplateBindings(
      v8::Handle<v8::ObjectTemplate> template_object);

 private:
  DISALLOW_COPY_AND_ASSIGN(Syslog);
};

} // namespace entd

#endif // ENTD_SYSLOG_H_
