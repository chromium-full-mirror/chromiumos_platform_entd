// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

println("starting timeouts");

entd.setTimeout("println('string timeout')", 500);

entd.setTimeout(function () { println('function timeout') }, 750);
