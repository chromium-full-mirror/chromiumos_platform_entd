// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

var req;
foo = entd.http.GET;
//foo(req);
//entd.http.GET();
entd.onLoad =
function onLoad(manifest)
{
  entd.http.GET(req);
}
