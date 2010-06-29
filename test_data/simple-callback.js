// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

entd.onLoad =
function onLoad(manifest) {
  entd.callbackServer.requestHeaderValue = "test-magic";
  entd.callbackServer.start(callbacks, 5200);
}

callbacks = new Object();

callbacks["cb:ping"] = function(args) {
  return { "pong": (new Date()).toString(),
           "args": args
  };
}

callbacks["cb:throw_error"] = function(args) {
  // When a callback throws an exception we should generate an internal
  // server error.
  throw "error message";
}

callbacks["cb:serialize_error"] = function(args) {
  // We shoudn't be able to serialize the print function into json, so this
  // should cause an internal server error.
  return print;
}

callbacks["cb:stop"] = function(args) {
  // Stop the server after the call completes.
  entd.setTimeout("entd.callbackServer.stop()", 0);
  return "Stopping.";
}

callbacks["cb:stop_now"] = function(args) {
  // This should throw an exception about the fact that the server is busy.
  entd.callbackServer.stop();
  return "Stopped.";
}
