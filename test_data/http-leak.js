// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Make a bunch of entd.http.Request objects and make sure they are properly
// garbage collected.

// Number of Requests to make in each batch.
var batchSize = 10;
// Number of batches to make.
var batchCount = 10;

// Test result.
var ok = true;

function makeBatch(i) {
  var x;

  println("Making batch: " + i);

  for (var j = 0; j < batchSize; ++j)
    x = new entd.http.Request();

  if (i != batchCount) {
    GC();

    // 'x' is still referring to a Request, so there should be one instance
    // left after the GC.
    if (entd.http.Request.instanceCount != 1) {
      ok = false;
      println("Expected 1 instance after iteration " + i);
    }

    entd.setTimeout(function () { makeBatch(i + 1) }, 500);

  } else {
    // Clear out 'x' after the last batch and check that the instanceCount
    // goes to 0.
    x = null;

    GC();

    if (entd.http.Request.instanceCount != 0) {
      ok = false;
      println("Expected 0 instances after iteration " + i +
              ", found: " + entd.http.Request.instanceCount);
    }

    if (ok)
      println("LOOKS OK");
  }
}

entd.onLoad = function onLoad() {
  entd.setTimeout(function () { makeBatch(1) }, 0);
}
