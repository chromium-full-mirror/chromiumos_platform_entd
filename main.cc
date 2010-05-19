// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdio.h>

#include <string>

#include <base/command_line.h>
#include <base/file_util.h>
#include <base/logging.h>

#include "entd/entd.h"
#include "entd/extensions.h"
#include "entd/http.h"
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

// If specified, then self-signed server certs are ok for HTTPS
static const char *kAllowSelfSigned = "allow-self-signed";

// If specified, don't watch for signals.  This allows the process to exit
// automatically when all events have been processed.  See the comment in
// entd.h for a little more info.
static const char *kAllowDirtyExit = "allow-dirty-exit";

}  // namespace switches

// Return values:
//   0: Entd completed successfully and should not be restarted.
//   1: Entd encountered a failure, but will probably fail again if restarted,
//      so please don't.
//   2: Entd has NOT encountered a failure, but would like to be restarted.
//  >2: Entd has encountered a failure, restarting may help.
//
// So, exit with a zero or one means leave it down, otherwise restart.
//
int main(int argc, char** argv) {
  LOG(INFO) << "Starting entd";

  std::string manifest, policy, utility;

  CommandLine::Init(argc, argv);
  CommandLine* cl = CommandLine::ForCurrentProcess();
  std::string base_extension_path =
      cl->GetSwitchValueASCII(switches::kExtensionPath);
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
    FilePath policy_path = FilePath(extension_path).Append("policy.js");
    if (file_util::PathExists(policy_path))
      policy = policy_path.value();
    FilePath manifest_path = FilePath(extension_path).Append("manifest.json");
    if (file_util::PathExists(manifest_path))
      manifest = manifest_path.value();
  }

  // Command line switches for policy files override extension filepaths
  if (cl->HasSwitch(switches::kPolicy))
    policy = cl->GetSwitchValueASCII(switches::kPolicy);
  if (cl->HasSwitch(switches::kManifest))
    manifest = cl->GetSwitchValueASCII(switches::kManifest);
  if (cl->HasSwitch(switches::kUtility))
    utility = cl->GetSwitchValueASCII(switches::kUtility);

  if (cl->HasSwitch(switches::kAllowSelfSigned))
    entd::Http::allow_self_signed_certs = true;

  if (cl->HasSwitch(switches::kAllowDirtyExit))
    entd::Entd::allow_dirty_exit = true;

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

  uint32_t rv = d.Run();
  LOG(INFO) << "Exiting entd with code: " << rv;
  return rv;
}
