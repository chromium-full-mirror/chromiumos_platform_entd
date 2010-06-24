// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

var timeoutFired = false;

function t1() {
  timeoutFired = true;
  println("This timeout was supposed to be cancelled");
}

function t2() {
  if (!timeoutFired)
    println("LOOKS OK");
}

entd.onLoad = function () {
  println("starting timeouts");

  var h = entd.setTimeout(t1, 500);
  entd.setTimeout(t2, 750);
  entd.clearTimeout(h);
}
