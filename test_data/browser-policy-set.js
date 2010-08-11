// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

entd.onLoad = function () {
  if (!(entd.browser instanceof entd.Browser))
    return println("Unexpected type for entd.browser");

  if (!(entd.browser.managedPolicy instanceof entd.Browser.Policy))
    return println("Unexpected type for entd.browser.managedPolicy");

  if (!(entd.browser.recommendedPolicy instanceof entd.Browser.Policy))
    return println("Unexpected type for entd.browser.recommendedPolicy");

  try {
    entd.browser.managedPolicy["test-managed-policy"] = "test 1";
    entd.browser.recommendedPolicy["test-recommended-policy"] = "test 2";
    entd.browser.managedPolicy["managed-deleteme"] = "deleteme";
  } catch (ex) {
    return println("Unexpected exception setting policy value: " + ex);
  }

  if (entd.browser.managedPolicy["test-managed-policy"] != "test 1")
    return println("Unexpected value for test-managed-policy");

  if (entd.browser.managedPolicy["managed-deleteme"] != "deleteme")
    return println("Unexpected value for managed-deleteme");

  if (entd.browser.recommendedPolicy["test-recommended-policy"] != "test 2")
    return println("Unexpected value for test-recommended-policy");

  delete entd.browser.managedPolicy["managed-deleteme"];
  if ("managed-deleteme" in entd.browser.managedPolicy)
    return println("Expected managed-deleteme to have been deleted");

  // Create a structure with a circular reference and watch it fail to
  // serialize.
  var o = new Object();
  o.o = o;

  var ex;

  try {
    entd.browser.managedPolicy["test-managed-policy"] = o;
  } catch (ex_) {
    ex = ex_;
  }

  if (!ex)
    return println("Expected exception storing circular object");

  if (entd.browser.managedPolicy["test-managed-policy"] != "test 1")
    return println("Unexpected value for test-managed-policy");


  println("LOOKS OK");
}
