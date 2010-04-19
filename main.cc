// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/command_line.h>
#include <stdio.h>

#include "base/logging.h"
#include "entd/entd.h"

namespace switches {
// Location of the policy file
static const char *kPolicy = "policy";
}

int main(int argc, char** argv) {
  LOG(INFO) << "Starting entd";
  CommandLine::Init(argc, argv);
  CommandLine* cl = CommandLine::ForCurrentProcess();
  std::string policy = cl->GetSwitchValueASCII(switches::kPolicy);

  entd::Entd d;
  d.Initialize();

  if (!policy.empty())
    d.SetPolicyFile(policy);

  bool rv = d.Run();
  LOG(INFO) << "Exiting entd";
  return rv ? 0 : 1;
}
