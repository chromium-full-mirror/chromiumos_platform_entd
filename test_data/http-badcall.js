// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

entd.onLoad =
function onLoad(manifest)
{
  try {
    entd.http.GET.apply({});
  } catch (ex) {
    if (ex.toString().match(/expected.*'entd\.http'/i)) {
      println("LOOKS OK");
      return;
    }

    println("Got unexpected exception: " + ex);
    return;
  }

  println("Expected entd.http.GET applied to wrong object to fail.");
}
