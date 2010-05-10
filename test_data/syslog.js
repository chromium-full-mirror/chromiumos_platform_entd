// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

entd.onLoad =
function onLoad(manifest)
{
  entd.syslog.info("entd.syslog.info");
  entd.syslog.warn("entd.syslog.warn");
  entd.syslog.error("entd.syslog.error");
}
