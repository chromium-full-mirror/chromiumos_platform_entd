// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdio.h>
#include <iostream>
#include <string>

#include <base/command_line.h>
#include <base/file_util.h>
#include <chromeos/syslog_logging.h>

#include "entd/entd.h"
#include "entd/extensions.h"
#include "entd/callback_server.h"
#include "entd/http.h"
#include "entd/tpm.h"
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

// Root CA for HTTPS requests.
static const char *kRootCAFile = "root-ca-file";

// If specified, then self-signed server certs are ok for HTTPS
static const char *kAllowSelfSigned = "allow-self-signed";

// If specified, then file operations are allowed (e.g. for testing)
static const char *kAllowFileIO = "allow-file-io";

// If specified, don't watch for signals.  This allows the process to exit
// automatically when all events have been processed.  See the comment in
// entd.h for a little more info.
static const char *kAllowDirtyExit = "allow-dirty-exit";

// Syslogging is enabled by default if stdout is not a tty.  These flags can
// be used to override the default logic.
static const char *kEnableSyslog = "enable-syslog";
static const char *kDisableSyslog = "disable-syslog";

static const char *kLibcrosLocation = "libcros-location";

static const char *kCallbackOrigin = "callback-origin";

static const char *kSessionId = "session-id";

// TODO(crosbug.com/14277): Remove option and assume it is true.
static const char *kCryptohomeInitPkcs11 =
    "cryptohome-init-pkcs11";

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
  std::string manifest, policy, utility;

  CommandLine::Init(argc, argv);
  CommandLine* cl = CommandLine::ForCurrentProcess();
  int log_flags = chromeos::kLogToStderr;

  if (cl->HasSwitch(switches::kEnableSyslog) ||
      (!isatty(STDOUT_FILENO) && !cl->HasSwitch(switches::kDisableSyslog))) {
    // If syslog was explicitly enabled, or stdout is not a tty and syslog
    // was not explicitly disabled, then send all LOG(...) messages to syslog.
    log_flags |= chromeos::kLogToSyslog;
  }

  chromeos::InitLog(log_flags);

  LOG(INFO) << "Starting entd";

  std::string base_extension_path =
      cl->GetSwitchValueASCII(switches::kExtensionPath);
  std::string username = cl->GetSwitchValueASCII(switches::kUsername);
  std::string root_ca_file = cl->GetSwitchValueASCII(switches::kRootCAFile);

  // Get file paths from a valid policy extension if it exists
  std::string extension_path;
  bool valid_policy = false;
  if (!base_extension_path.empty()) {
    valid_policy = entd::extensions::FindValidPolicy(base_extension_path,
                                                     &extension_path);
  }

  if (valid_policy) {
    FilePath path = FilePath(extension_path).Append("policy.js");
    if (file_util::PathExists(path))
      policy = path.value();

    path = FilePath(extension_path).Append("manifest.json");
    if (file_util::PathExists(path))
      manifest = path.value();

    path = FilePath(extension_path).Append("root-ca.pem");
    if (file_util::PathExists(path)) {
      root_ca_file = path.value();
    } else {
      // Backwards compatibility for old filename with underscore.
      path = FilePath(extension_path).Append("root_ca.pem");
      if (file_util::PathExists(path))
        root_ca_file = path.value();
    }
  }

  // Command line switches for policy files override extension filepaths
  if (cl->HasSwitch(switches::kPolicy))
    policy = cl->GetSwitchValueASCII(switches::kPolicy);
  if (cl->HasSwitch(switches::kManifest))
    manifest = cl->GetSwitchValueASCII(switches::kManifest);
  if (cl->HasSwitch(switches::kUtility))
    utility = cl->GetSwitchValueASCII(switches::kUtility);

  if (cl->HasSwitch(switches::kAllowSelfSigned)) {
    LOG(INFO) << "Allowing self-signed certs.";
    entd::Http::allow_self_signed_certs = true;
  }

  if (cl->HasSwitch(switches::kLibcrosLocation)) {
    entd::Entd::libcros_location = cl->GetSwitchValueASCII(
        switches::kLibcrosLocation);
    LOG(INFO) << "Setting libcros location: " << entd::Entd::libcros_location;
  }

  if (cl->HasSwitch(switches::kCryptohomeInitPkcs11)) {
    LOG(INFO) << "Expecting cryptohome to initialize the TPM token";
    entd::Tpm::cryptohome_init_pkcs11 = true;
  }

  if (cl->HasSwitch(switches::kAllowFileIO)) {
    LOG(INFO) << "Allowing File IO.";
    entd::Entd::allow_file_io = true;
  }

  if (!root_ca_file.empty()) {
    LOG(INFO) << "Setting root CA file: " << root_ca_file;
    entd::Http::root_ca_file = root_ca_file;
  }

  if (cl->HasSwitch(switches::kAllowDirtyExit)) {
    LOG(INFO) << "Allowing dirty exits.";
    entd::Entd::allow_dirty_exit = true;
  }

  if (cl->HasSwitch(switches::kCallbackOrigin)) {
    entd::CallbackServer::required_origin = cl->GetSwitchValueASCII(
        switches::kCallbackOrigin);
    LOG(INFO) << "Setting callback origin: " <<
        entd::CallbackServer::required_origin;
  }

  if (cl->HasSwitch(switches::kSessionId)) {
    entd::CallbackServer::set_session_id(cl->GetSwitchValueASCII(
        switches::kSessionId));
    LOG(INFO) << "Setting session id: " <<
        entd::CallbackServer::session_id();
  }

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

  uint32_t rv = d.Run();
  LOG(INFO) << "Exiting entd with code: " << rv;
  return rv;
}
