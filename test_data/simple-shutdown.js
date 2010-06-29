// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

var timeoutFired = false;

entd.onLoad = function() {
  // Start the callback server so we can be sure entd wouldn't stop on its
  // own.
  entd.callbackServer.start({}, 5200);
  entd.setTimeout('timeoutFired = true', 250);
  entd.scheduleShutdown(0, 500);
}

entd.onUnload = function() {
  if (timeoutFired) {
    println("LOOKS OK");
  } else {
    println("timeout didn't fire before shutdown.");
  }
}
