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
#include "cros/chromeos_network.h"
#include "entd/entd.h"
#include "entd/utils.h"

namespace entd {
using chromeos::FreeServiceInfo;
using chromeos::GetWifiService;
using chromeos::ConfigureWifiService;
using chromeos::ServiceInfo;

Flimflam::~Flimflam() {
  CleanupTemplate();  // We only have one Flimflam instance
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
    return v8_fail("Incorrect number of args to configNetwork");

  std::string ssid;
  std::string pass;
  std::string user;
  std::string cert_path;

  ssid = utils::ValueAsUtf8String(args[0]);
  if (!IsStringASCII(ssid)) {
    return v8_fail("ssid contains illegal characters in call to configNetwork");
  }

  pass = utils::ValueAsUtf8String(args[1]);
  if (!IsStringASCII(pass)) {
    return v8_fail("pass contains illegal characters in call to configNetwork");
  }

  user = utils::ValueAsUtf8String(args[2]);
  if (!IsStringASCII(user)) {
    return v8_fail("user contains illegal characters in call to configNetwork");
  }

  cert_path = utils::ValueAsUtf8String(args[3]);
  if (!IsStringASCII(cert_path)) {
    return v8_fail(
        "cert_path contains illegal characters in call to configNetwork");
  }

  if (!Entd::LibcrosLoadedOrThrow())
    return v8::Undefined();

  if (!ConfigureWifiService(ssid.c_str(),chromeos::SECURITY_8021X,
                            pass.c_str(), user.c_str(), cert_path.c_str()))
    return v8_fail("Failed to configure wifi service");

  return v8::True();
}

// bool disconnectNetwork(const char* ssid);
static v8::Handle<v8::Value> dispatch_disconnectNetwork(
    const v8::Arguments& args) {
  if (args.Length() != 1)
    return v8_fail("Incorrect number of args to disconnectNetwork");

  std::string ssid;

  ssid = utils::ValueAsUtf8String(args[0]);
  if (!IsStringASCII(ssid)) {
    return v8_fail("ssid contains illegal characters in call to "
                   "disconnectNetwork");
  }

  if (!Entd::LibcrosLoadedOrThrow())
    return v8::Undefined();

  ServiceInfo* ssid_info = GetWifiService(ssid.c_str(),
                                          chromeos::SECURITY_8021X);
  if (ssid_info) {
    if (!chromeos::DisconnectFromNetwork(ssid_info->service_path)) {
      FreeServiceInfo(ssid_info);
      return v8_fail("Failed to disconnect from network");
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
  template_object->Set(v8::String::NewSymbol("disconnectNetwork"),
                       v8::FunctionTemplate::New(dispatch_disconnectNetwork));
}

} // namespace entd
