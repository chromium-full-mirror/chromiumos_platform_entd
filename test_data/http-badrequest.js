// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Pass a bad request object to GET() and make sure it bombs.

entd.onLoad =
function onLoad(manifest)
{
  try {
    entd.http.GET({});
  } catch (ex) {
    if (ex.toString().match(/expected.*Request/i)) {
      println("LOOKS OK");
      return;
    }

    println("Got unexpected exception: " + ex);
    return;
  }

  println("Expected bogus entd.http.GET() to fail.");
}
