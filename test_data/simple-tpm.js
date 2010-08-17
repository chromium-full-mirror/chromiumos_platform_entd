// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

entd.onLoad = function() {
  if (!(entd.tpm instanceof entd.Tpm))
    return println("Expected entd.tpm instanceof entd.Tpm");

  if (!("isLibcrosLoaded" in entd))
    return println("Missing entd.isLibcrosLoaded");

  if (!("isEnabled" in entd.tpm))
    return println("Missing entd.tpm.isEnabled");

  if (!("isReady" in entd.tpm))
    return println("Missing entd.tpm.isReady");

  if (entd.isLibcrosLoaded) {
    if (!entd.tpm.isEnabled)
        return println("Expected tpm to be enabled");

    if (!entd.tpm.isReady)
        return println("Expected tpm to be ready");

  } else {
    var ex;

    try {
      entd.tpm.isEnabled;
    } catch (ex_) {
      ex = ex_;
    }

    if (!ex)
      return println("Expected entd.tpm.isEnabled to throw");

    try {
      entd.tpm.isReady;
    } catch (ex_) {
      ex = ex_;
    }

    if (!ex)
      return println("Expected entd.tpm.isReady to throw");

  }

  println("LOOKS OK");
}
