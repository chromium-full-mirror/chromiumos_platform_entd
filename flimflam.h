// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ENTD_FLIMFLAM_H_
#define ENTD_FLIMFLAM_H_

#include <string>

#include <base/basictypes.h>
#include <v8.h>

#include "entd/js_object_wrapper.h"

namespace entd {

class Flimflam : public JSObjectWrapper<Flimflam> {
 public:
  Flimflam() {}
  virtual ~Flimflam();

  static const char* GetClassName() { return "flimflam"; }

  // Binds "configNetwork" method.
  static void SetTemplateBindings(
      v8::Handle<v8::ObjectTemplate> template_object);

  static const char kLibcrosPath[];

 private:
  DISALLOW_COPY_AND_ASSIGN(Flimflam);
};

} // namespace entd

#endif // ENTD_FLIMFLAM_H_
