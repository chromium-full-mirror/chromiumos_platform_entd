// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

entd.onLoad = function () {
  println("starting timeouts");

  var h = entd.setTimeout("println('string timeout')", 500);
  var h2 = entd.setTimeout(function () { println('function timeout') }, 750);
  entd.clearTimeout(h);
}
