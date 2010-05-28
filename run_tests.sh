#!/bin/bash

# Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# TODO: Get these tests running in a cross-platform fashion from the src_test
# stanza of the entd ebuild.

USERNAME="user@google.com"
ALLOW_DIRTY_EXIT=1
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

  if [ ${args:0:2} != "--" ]; then
    # allow callers to just pass the name of the js file if that's all they need
    args="--policy=test_data/$args"
  fi

  local cmd="$ENTD --username=$USERNAME $args"
  if [ ! -z "$ALLOW_DIRTY_EXIT" ]; then
    cmd="$cmd --allow-dirty-exit"
  fi

  local out=$($cmd 2>&1)
  local code=$?

  TESTS=$(($TESTS +1))

  if [ $code != 0 ]; then
    logfail "$name: exited with $code"
    return
  fi

  grep -q "$pattern" <(echo $out)
  if [ $? != 0 ]; then
    logfail "$name: pattern not found"
    if [ ! -z "$VERBOSE" ]; then
      echo
      echo $cmd
      echo
      echo "=== OUTPUT START"
      echo $out
      echo "=== OUTPUT END"
      echo
    fi
  else
    logpass "$name"
  fi
}

# Basic tests.
greptest "hello-world.js" 'hello world'
greptest "bad-onload.js" 'throw "expected exception"'
greptest "print-username.js" "username: $USERNAME"
greptest "throw-exception.js" 'throw "goodbye world"'
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
greptest "http-badhost.js" "HTTP ERROR: Couldn't resolve"
greptest "http-badport.js" "LOOKS OK"
greptest "http-evilhost.js" "Invalid hostname"
greptest "http-badrequest.js" "First argument must be a Request object"
greptest "http-redirect.js" "HTTP COMPLETE"

# Pkcs11 tests.
greptest "--policy=test_data/pkcs11.js --csr-file=test_data/csr_test.pem" \
'{"slot1":{"label":"slot1","keyIdentifier":"key1",'\
'"publicKey":"<This is a public key>",'\
'"certificate":{"content":"content1","subject":"Content"}},'\
'"slot2":{"label":"slot2","keyIdentifier":"key2",'\
'"publicKey":"<This is a public key>",'\
'"certificate":{"content":"content2","subject":"Content"}}}' \
"pkcs11.js"
greptest 'pkcs11-cert.js '\
'--csr-file=test_data/csr_test.pem --cert-file=test_data/cert_test.pem' \
'{"slot1":{"label":"slot1",'\
'"certificate":{"content":"content1",'\
'"subject":"File: test_data/cert_test.pem"}}}' \
"pkcs11-cert.js"
greptest 'pkcs11-openssl.js '\
'--pkcs11=openssl --cert-file=test_data/cert_test.pem --allow-write-to-file' \
'Subject:/C=US/ST=California/L=Mountain View/O=Google Inc/OU=ChromeOS' \
"pkcs11-openssl.js"
greptest "pkcs11-remove.js" "Slot1: undefined"

# Pkcs11 opencryptoki tests (chromeos only)
if [ 1 == "$CHROMEOS" ]; then
  greptest 'pkcs11-opencryptoki.js '\
'--pkcs11=glaptop --cert-file=test_data/cert_test.pem' \
'{"slot1":{"label":"slot1","keyIdentifier":"1234","publicKey":"",'\
'"certificate":{"content":"",'\
'"subject":"/C=US/ST=California/L=Mountain View/O=Google Inc/OU=ChromeOS' \
"pkcs11-opencryptoki.js"
  greptest 'pkcs11-opencryptoki-delete.js '\
'--pkcs11=glaptop --cert-file=test_data/cert_test.pem' \
'Slots: {}' \
"pkcs11-opencryptoki-delete.js"
fi
# Slightly longer running tests.
greptest "settimeout.js" "string timeout function timeout"
greptest "cleartimeout.js" "starting timeouts function timeout"
greptest "simple-shutdown.js" "LOOKS OK"

# Fire off this bg task to make an http request
(sleep 2; \
  curl --data-binary '{"function": "stop"}' \
    -H "Content-Type: application/json; charset=UTF-8" \
    -H "X-Entd-Request: magic" \
    localhost:5199/dispatch -so /dev/null) &

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
