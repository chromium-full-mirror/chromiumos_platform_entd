// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Pass a bad request object to GET() and make sure it bombs.

entd.onLoad =
function onLoad(manifest) {
  var r = new entd.http.Request("www.google.com");

  r.port = "hi";
  if (!test(r))
    return;

  r.port = "123hi";
  if (!test(r))
    return;

  r.port = "hi123";
  if (!test(r))
    return;

  r.port = -123;
  if (!test(r))
    return;

  r.port = 50000;
  if (!test(r))
    return;

  r.port = 3.14;
  if (!test(r))
    return;

  r.port = Number.MAX_VALUE;
  if (!test(r))
    return;

  println("LOOKS OK");
}

function test(r) {
  try {
    entd.http.GET(r);
  } catch (ex) {
    if (ex == "Invalid port") {
      println("port failed as expected: " + r.port);
      return true;
    }
  }

  println("expected request to fail: " + r.url);
  return false;
}
