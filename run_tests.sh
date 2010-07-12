#!/bin/bash

# Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# TODO: Get these tests running in a cross-platform fashion from the src_test
# stanza of the entd ebuild.

USERNAME="user@google.com"
ALLOW_DIRTY_EXIT=1
ALLOW_FILE_IO=1
ENABLE_OPENCRYPTOKI=0
grep "Chromium OS" /etc/lsb-release
if [ $? == 0 ]; then
  CHROMEOS=1
  ENTD="/usr/sbin/entd"
else
  CHROMEOS=0
  ENTD="../../scripts/run_32bit.sh out/i686-pc-linux-gnu/entd --"
fi

# If non-zero, print test output on failure
VERBOSE=1
# Count of tests run
TESTS=0
# Count of failed test
FAILURES=0

function logfail {
  echo "FAILED: $*"
  FAILURES=$(($FAILURES + 1))
}

function logpass {
  echo "PASS: $*"
}

function greptest {
  # Test by running entd with some command line options and grepping the
  # output for an expected pattern.
  local args="$1"
  local pattern="$2"
  local name="$3"

  if [ -z "$name" ]; then
    name=$args
  fi

  local expected_result="$4"

  if [ -z "$expected_result" ]; then
    expected_result=0
  fi


  if [ ${args:0:2} != "--" ]; then
    # allow callers to just pass the name of the js file if that's all they need
    args="--policy=test_data/$args"
  fi

  local cmd="$ENTD --username=$USERNAME $args"
  if [ "$ALLOW_DIRTY_EXIT" == "1" ]; then
    cmd="$cmd --allow-dirty-exit"
  fi

  if [ "$ALLOW_FILE_IO" == "1" ]; then
    cmd="$cmd --allow-file-io"
  fi

  if [ "$ENABLE_OPENCRYPTOKI" != "1" ]; then
    cmd="$cmd --disable-opencryptoki"
  fi

  local out
  out=$($cmd 2>&1)
  local code=$?

  TESTS=$(($TESTS +1))

  passed=1

  if [ $code != $expected_result ]; then
    logfail "$name: exited with $code"
    passed=0
  elif ! grep -q "$pattern" <(echo $out); then
    logfail "$name: pattern not found: '$pattern'"
    passed=0
  fi

  if [[ "$passed" == "0" && ! -z "$VERBOSE" ]]; then
    echo
    echo $cmd
    echo
    echo "=== OUTPUT START"
    echo $out
    echo "=== OUTPUT END"
    echo
  else
    logpass "$name"
  fi
}

# Basic tests.
greptest "hello-world.js" 'hello world'
greptest "bad-onload.js" 'throw "expected exception"' '' 1
greptest "print-username.js" "username: $USERNAME"
greptest "throw-exception.js" 'throw "goodbye world"' '' 1
greptest "syslog.js" "entd.syslog.error"
greptest "simple-hostname.js" "LOOKS OK"
greptest "simple-onunload.js" "LOOKS OK"

# Basic tests with longer command lines.
greptest "--policy=test_data/print-manifest.js \
  --manifest=test_data/simple-manifest.json" '{"foo":1,"bar":2}' \
  "print-manifest.js"
greptest "--policy=test_data/simple-utility.js \
  --utility=test_data/simple-utility.js" 'utility is set' "simple-utility.js"
greptest "--extension-path=test_data/Extensions" '{"foo":1,"bar":2}'

# Http tests.
greptest "http-good.js" "HTTP COMPLETE"
greptest "http-badcall.js" "LOOKS OK"
greptest "http-badhost.js" "HTTP ERROR: Couldn't resolve"
greptest "http-badport.js" "LOOKS OK"
greptest "http-evilhost.js" "Invalid hostname" '' 1
greptest "http-badrequest.js" "LOOKS OK"
greptest "http-leak.js" "LOOKS OK"
greptest "http-redirect.js" "HTTP COMPLETE"

# Pkcs11 tests.
greptest "pkcs11-csr.js" "LOOKS OK"
greptest "pkcs11-cert.js" "LOOKS OK"
greptest "pkcs11-remove.js" "LOOKS OK"
greptest "pkcs11-ready.js" "LOOKS OK"

ENABLE_OPENCRYPTOKI=1

if [ "$CHROMEOS" == 1 ]; then
  # These tests requires a properly configured opencryptoki environment,
  # so chromeos only.
  greptest 'pkcs11-opencryptoki.js '\
'"slot1":{"label":"slot1","keyIdentifier":"1234",'\
'"certificate":{'\
'"subject":"/C=US/ST=California/L=Mountain View/O=Google Inc/OU=ChromeOS' \
"pkcs11-opencryptoki.js"
  greptest 'pkcs11-opencryptoki-delete.js '\
'Slots.slot1: undefined' \
"pkcs11-opencryptoki-delete.js"
else
  # This test assumes that opencryotoki is *not* configured.
  greptest "pkcs11-notready.js" "LOOKS OK"
fi

ENABLE_OPENCRYPTOKI=0

# Slightly longer running tests.
greptest "settimeout.js" "string timeout function timeout"
greptest "cleartimeout.js" "LOOKS OK"

greptest "simple-shutdown.js" "LOOKS OK"

# Fire off this bg task to make an http request
(sleep 2; \
  curl --data-binary '{"function": "stop"}' \
  -H "Content-Type: application/json; charset=UTF-8" \
  -H "X-Entd-Request: test-magic" \
  localhost:5200/dispatch -so /dev/null) &

# Then start up the callback server before the timeout fires.
greptest "simple-callback.js" "Stopping callback server"

echo
echo "Tests completed: $TESTS"

if [ $FAILURES -gt 0 ]; then
  echo "TESTS FAILED: $FAILURES"
  echo
  exit 1
fi

echo "All tests passed."
echo
exit 0
