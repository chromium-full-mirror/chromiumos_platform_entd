// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Simple test to check that we can do a GET and POST.  This adds some
// parameters and headers, but doesn't actually verify that that work :/
var host = "www.google.com";
var path = "/accounts/ServiceLogin";
var params = ["foo=1","bar=2"];
var headers = {foo: "bar"};

var req = new entd.http.Request(host, path, params, headers);
req.onComplete = function onComplete(response) {
  println("HTTP COMPLETE. URL=" + response.url +
	  ", CODE=" + response.code +
	  ", CONTENT SIZE=" + response.content.length +
	  ", HEADERS: " + response.headers.length);

  if (response.url != "https://" + host + path + "?foo=1&bar=2") {
    println("Unexpected url");
    return;
  }

  println("LOOKS OK");
}

req.onTimeout = function onTimeout() {
  println("HTTP TIMEOUT");
}

req.onError = function onError(errcode) {
  println("HTTP ERROR: " + errcode);
}

entd.onLoad = function onLoad(manifest) {
  entd.http.GET(req);
}
