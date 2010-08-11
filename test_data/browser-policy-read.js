// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

entd.onLoad = function () {
  if (entd.browser.managedPolicy["test-managed-policy"] != "test 1")
    return println("Unexpected value for test-managed-policy");

  if (entd.browser.recommendedPolicy["test-recommended-policy"] != "test 2")
    return println("Unexpected value for test-recommended-policy");

  if ("managed-deleteme" in entd.browser.managedPolicy)
    return println("Expected managed-deleteme to have been deleted");

  println("LOOKS OK");
}
