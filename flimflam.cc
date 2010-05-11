// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "entd/flimflam.h"

#include <string>
#include <list>
#include <vector>

#include "base/basictypes.h"
#include "base/logging.h"
#include "base/string_util.h"
#include "cros/chromeos_cros_api.h"
#include "cros/chromeos_network.h"
#include "entd/utils.h"

namespace entd {
using chromeos::FreeServiceInfo;
using chromeos::GetWifiService;
using chromeos::ServiceInfo;

const char Flimflam::kLibcrosPath[] =
    "/opt/google/chrome/chromeos/libcros.so";

Flimflam::~Flimflam() {
  CleanupTemplate();  // We only have one Flimflam instance
}

bool Load(std::string* load_error_string) {
  static bool loaded = false;
  if (loaded) {
    LOG(INFO) << "Already loaded libcros...";
    return true;
  }

  loaded = chromeos::LoadLibcros(Flimflam::kLibcrosPath, *load_error_string);

  if (!loaded) {
    LOG(ERROR) << "Problem loading chromeos shared object: "
               << *load_error_string;
  }
  return loaded;
}

static v8::Handle<v8::Value> v8_fail(const std::string& err) {
  utils::ThrowV8Exception(err);
  return v8::Undefined();
}

// bool configNetwork(const char* ssid,
//                    const char* pass,
//                    const char* user,
//                    const char* cert_path);
static v8::Handle<v8::Value> dispatch_configNetwork(const v8::Arguments& args) {
  if (args.Length() != 4)
    return v8_fail("Incorrect number of args to ConfigNetwork");

  std::string ssid;
  std::string pass;
  std::string user;
  std::string cert_path;
  std::string tmp;

  ssid = utils::ValueAsUtf8String(args[0]);
  if (!IsStringASCII(ssid)) {
    return v8_fail("ssid contains illegal characters in call to ConfigNetwork");
  }

  pass = utils::ValueAsUtf8String(args[1]);
  if (!IsStringASCII(pass)) {
    return v8_fail("pass contains illegal characters in call to ConfigNetwork");
  }

  user = utils::ValueAsUtf8String(args[2]);
  if (!IsStringASCII(user)) {
    return v8_fail("user contains illegal characters in call to ConfigNetwork");
  }

  cert_path = utils::ValueAsUtf8String(args[3]);
  if (!IsStringASCII(cert_path)) {
    return v8_fail(
        "cert_path contains illegal characters in call to ConfigNetwork");
  }

  std::string error;
  if (!Load(&error))
    return v8_fail(error);

  ServiceInfo* ssid_info = GetWifiService(ssid.c_str(),
                                          chromeos::SECURITY_8021X);
  if (ssid_info) {
    if (!chromeos::SetIdentity(ssid_info->service_path, user.c_str())) {
      FreeServiceInfo(ssid_info);
      return v8_fail("Failed to set identity");
    }
    if (!chromeos::SetPassphrase(ssid_info->service_path, pass.c_str())) {
      FreeServiceInfo(ssid_info);
      return v8_fail("Failed to set passphrase");
    }
    if (!chromeos::SetCertPath(ssid_info->service_path, cert_path.c_str())) {
      FreeServiceInfo(ssid_info);
      return v8_fail("Failed to set cert path");
    }
    return v8::True();
  }
  return v8::False();
}

// static
void Flimflam::SetTemplateBindings(
    v8::Handle<v8::ObjectTemplate> template_object) {
  template_object->Set(v8::String::NewSymbol("configNetwork"),
                       v8::FunctionTemplate::New(dispatch_configNetwork));
}

} // namespace entd
