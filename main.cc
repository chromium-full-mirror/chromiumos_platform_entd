// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/command_line.h>
#include <stdio.h>

#include "base/logging.h"
#include "entd/entd.h"

namespace switches {
// Location of the policy file
static const char *kManifest = "manifest";
static const char *kPolicy = "policy";
static const char *kUsername = "username";
static const char *kUtility = "utility";
}

int main(int argc, char** argv) {
  LOG(INFO) << "Starting entd";
  CommandLine::Init(argc, argv);
  CommandLine* cl = CommandLine::ForCurrentProcess();
  std::string manifest = cl->GetSwitchValueASCII(switches::kManifest);
  std::string policy = cl->GetSwitchValueASCII(switches::kPolicy);
  std::string username = cl->GetSwitchValueASCII(switches::kUsername);
  std::string utility = cl->GetSwitchValueASCII(switches::kUtility);

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

  bool rv = d.Run();
  LOG(INFO) << "Exiting entd";
  return rv ? 0 : 1;
}
