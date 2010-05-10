// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

var url = "www.google.com";
var params = new Array("name=me");
var headers = new Array("foo: bar");

var req = new entd.http.Request(url, params, headers);
req.onComplete = function complete(response)
{
  println("HTTP COMPLETE. URL=" + response.url +
	  ", CODE=" + response.code +
	  ", CONTENT SIZE=" + response.content.length +
	  ", HEADERS: " + response.headers.length);
  // println("CONTENT:");
  // println(response.content);
}
req.onTimeout = function timeout()
{
  println("HTTP TIMEOUT");
}
req.onError = function error(errcode)
{
  println("HTTP ERROR: " + errcode);
}

entd.onLoad =
function onLoad(manifest)
{
  entd.http.GET(req);
}
