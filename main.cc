// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdio.h>

#include <string>

#include <base/command_line.h>
#include <base/logging.h>

#include "entd/entd.h"
#include "entd/extensions.h"
#include "entd/utils.h"

namespace switches {
// Path to search for extensions; can contain ~ or env variables (e.g. ${HOME})
static const char *kExtensionPath = "extension-path";
// User Name
static const char *kUsername = "username";
// Policy files
static const char *kManifest = "manifest";
static const char *kPolicy =   "policy";
static const char *kUtility =  "utility";
// Certificate files
static const char *kCsrFile = "csr-file";
static const char *kCertFile = "cert-file";
}  // namespace switches

int main(int argc, char** argv) {
  LOG(INFO) << "Starting entd";

  std::string manifest, policy, utility;

  CommandLine::Init(argc, argv);
  CommandLine* cl = CommandLine::ForCurrentProcess();
  std::string base_extension_path
      = cl->GetSwitchValueASCII(switches::kExtensionPath);
  std::string username = cl->GetSwitchValueASCII(switches::kUsername);
  std::string csr_file = cl->GetSwitchValueASCII(switches::kCsrFile);
  std::string cert_file = cl->GetSwitchValueASCII(switches::kCertFile);

  // Get file paths from a valid policy extension if it exists
  std::string extension_path;
  bool valid_policy = false;
  if (!base_extension_path.empty()) {
    valid_policy = entd::extensions::FindValidPolicy(base_extension_path,
                                                     &extension_path);
  }

  if (valid_policy) {
    policy = extension_path + "policy.js";
    if (!entd::utils::FileExists(policy))
      policy.clear();
    manifest = extension_path + "manifest.json";
    if (!entd::utils::FileExists(manifest))
      manifest.clear();
  }

  // Command line switches for policy files override extension filepaths
  if (cl->HasSwitch(switches::kPolicy))
    policy = cl->GetSwitchValueASCII(switches::kPolicy);
  if (cl->HasSwitch(switches::kManifest))
    manifest = cl->GetSwitchValueASCII(switches::kManifest);
  if (cl->HasSwitch(switches::kUtility))
    utility = cl->GetSwitchValueASCII(switches::kUtility);

  entd::Entd d;
  d.Initialize();

  if (!username.empty())
    d.SetUsername(username);

  if (!utility.empty())
    d.SetUtilityFile(utility);

  if (!manifest.empty())
    d.SetManifestFile(manifest);

  if (!policy.empty())
    d.SetPolicyFile(policy);

  if (!csr_file.empty() || !cert_file.empty())
    d.SetCertificateFiles(csr_file, cert_file);

  bool rv = d.Run();
  LOG(INFO) << "Exiting entd";
  return rv ? 0 : 1;
}
