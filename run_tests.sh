#!/bin/bash

# Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# TODO: Get these tests running in a cross-platform fashion from the src_test
# stanza of the entd ebuild.

USERNAME="user@google.com"
ALLOW_DIRTY_EXIT=1
ALLOW_FILE_IO=1
ENABLE_OPENCRYPTOKI="1"
SYSROOT="/build/x86-generic"
RUN32="../../scripts/run_32bit.sh"
ENTD="$RUN32 out/i686-pc-linux-gnu/entd --"
PKCSSLOTD="$RUN32 $SYSROOT/usr/sbin/pkcsslotd --"
PKCS_SLOT="$RUN32 $SYSROOT/usr/sbin/pkcs_slot --"

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

function basic_tests() {
  greptest "hello-world.js" 'hello world'
  greptest "bad-onload.js" 'throw "expected exception"' '' 1
  greptest "print-username.js" "username: $USERNAME"
  greptest "throw-exception.js" 'throw "goodbye world"' '' 1
  greptest "syslog.js" "entd.syslog.error"
  greptest "simple-hostname.js" "LOOKS OK"
  greptest "simple-onunload.js" "LOOKS OK"
  greptest "simple-tpm.js" "LOOKS OK"
  greptest "browser-policy-set.js" "LOOKS OK"
  greptest "browser-policy-read.js" "LOOKS OK"

  greptest "--policy=test_data/print-manifest.js \
    --manifest=test_data/simple-manifest.json" '{"foo":1,"bar":2}' \
    "print-manifest.js"
  greptest "--policy=test_data/simple-utility.js \
    --utility=test_data/simple-utility.js" 'utility is set' "simple-utility.js"
  greptest "--extension-path=test_data/Extensions" '{"foo":1,"bar":2}'
}

function http_tests() {
  greptest "http-good.js" "HTTP COMPLETE"
  greptest "http-badcall.js" "LOOKS OK"
  greptest "http-badhost.js" "HTTP ERROR: Couldn't resolve"
  greptest "http-badport.js" "LOOKS OK"
  greptest "http-evilhost.js" "Invalid hostname" '' 1
  greptest "http-badrequest.js" "LOOKS OK"
  greptest "http-leak.js" "LOOKS OK"
  greptest "http-redirect.js" "HTTP COMPLETE"
}

function pkcs11_tests() {
  # First test expects pkcs11 won't be ready.
  sudo killall pkcsslotd
  greptest "pkcs11-notready.js" "LOOKS OK"

  # The remaining tests expect it to be ready, and to have a SO pin of 111111,
  # and a user pin of 000000.  This will be true if the crypto_pkcs11 tests
  # pass.
  sudo $PKCSSLOTD

  greptest "pkcs11-csr.js" "LOOKS OK"
  greptest "pkcs11-cert.js" "LOOKS OK"
  greptest "pkcs11-remove.js" "LOOKS OK"
  greptest "pkcs11-ready.js" "LOOKS OK"
  greptest 'pkcs11-opencryptoki.js' "LOOKS OK"
  greptest 'pkcs11-opencryptoki-delete.js' "LOOKS OK"
}

function init_pkcs11() {
  if [ ! -d "/var/lib/opencryptoki/tpm/" ]; then
    sudo $PKCS_SLOT 0 tpm
  fi

  if [ ! -f "/usr/sbin/pkcsslotd" ]; then
    sudo ln -s "$SYSROOT/usr/sbin/pkcsslotd" "/usr/sbin/pkcsslotd"
  fi

  if ! groups | grep -q pkcs11; then
    echo "*** The user '$USER' is not in the pkcs11 group."
    echo "*** Please run: sudo /usr/sbin/usermod -a -G pkcs11 $USER"
    echo "*** Then exit the chroot and come back."
    exit 1
  fi
}

function crypto_pkcs11_tests() {
  # First test expects pkcs11 won't be ready.
  sudo killall pkcsslotd
  init_pkcs11

  greptest "crypto-pkcs11-notready.js" "LOOKS OK"

  # The remaining tests expect it to be ready, and to start off totally
  # unitialized.

  sudo rm -rf "/var/lib/opencryptoki/tpm/$USER"
  (sleep 1; sudo $PKCSSLOTD) &

  # This one specifically expects it won't be ready right away, but will
  # become ready.
  greptest "crypto-pkcs11-waitready.js" "LOOKS OK"

  greptest "crypto-pkcs11-ctors.js" "LOOKS OK"
  greptest "crypto-pkcs11-slots.js" "LOOKS OK"
  greptest "crypto-pkcs11-inittoken.js" "LOOKS OK"
  greptest "crypto-pkcs11-finalize.js" "Finalizing PKCS11 API"

  # The old-skool pkcs11 tests rely on the inittoken test to set the SO and
  # user PINs correctly.
}

function slow_tests() {
  # Slightly longer running tests.
  greptest "settimeout.js" "string timeout function timeout"
  greptest "cleartimeout.js" "LOOKS OK"

  greptest "simple-shutdown.js" "LOOKS OK"

  # Fire off this bg task to make an http request
  (sleep 2; \
    curl --data-binary '{"function": "stop"}' \
    -H "Content-Type: application/json; charset=UTF-8" \
    -H "X-Entd-Request: test-magic" \
    -H "Origin: test-origin" \
    localhost:5200/dispatch -so /dev/null) &

  # Then start up the callback server before the timeout fires.  This tests
  # that we can successfully talk to the callback server, and that it respects
  # valid X-Entd-Request and Origin headers.
  greptest "simple-callback.js --callback-origin=test-origin" \
    "Stopping callback server"

  # Now fire off a bg task to make an http request with a bogus Origin header.
  (sleep 2; \
    curl --data-binary '{"function": "stop"}' \
    -H "Content-Type: application/json; charset=UTF-8" \
    -H "X-Entd-Request: test-magic" \
    -H "Origin: bogus-origin" \
    localhost:5200/dispatch -so /dev/null) &

  # And another one that will actually stop the process.
  (sleep 3; \
    curl --data-binary '{"function": "stop"}' \
    -H "Content-Type: application/json; charset=UTF-8" \
    -H "X-Entd-Request: test-magic" \
    -H "Origin: test-origin" \
    localhost:5200/dispatch -so /dev/null) &

  # Then start up the callback server before the timeouts fire.  This tests
  # that the bogus Origin header is properly rejected.
  greptest "simple-callback.js --callback-origin=test-origin" \
    "Bad or missing Origin header"
}

function all_tests() {
  basic_tests
  http_tests
  crypto_pkcs11_tests
  pkcs11_tests
  slow_tests
}

all_tests

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
