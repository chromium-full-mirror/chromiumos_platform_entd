#!/bin/bash

# Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

USERNAME="user@example.com"
ENTD="../../scripts/run_32bit.sh out/i686-pc-linux-gnu/entd -- \
--username=$USERNAME "

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

  local cmd="$ENTD $args"
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
greptest "http-badrequest.js" "First argument must be a Request object"
greptest "http-redirect.js" "HTTP COMPLETE"

# Pkcs11 tests.
greptest "pkcs11.js" \
'{"slot1":{"label":"slot1","keyIdentifier":"key1",'\
'"publicKey":"<This is a public key>",'\
'"certificate":{"content":"<Certificate content=content1 />"}},'\
'"slot2":{"label":"slot2","keyIdentifier":"key2",'\
'"publicKey":"<This is a public key>",'\
'"certificate":{"content":"<Certificate content=content2 />"}}}'
greptest 'pkcs11-cert.js '\
'--csr-file=test_data/csr_test.pem --cert-file=test_data/cert_test.pem' \
'{"slot1":{"label":"slot1",'\
'"certificate":{"content":"-----BEGIN CERTIFICATE-----' \
"pkcs11-cert.js"
greptest "pkcs11-remove.js" "Slot1: undefined"

# Slightly longer running tests.
greptest "settimeout.js" "string timeout function timeout"
greptest "cleartimeout.js" "starting timeouts function timeout"

# Fire off this bg task to make an http request
(sleep 2; \
  curl --data-binary '{"function": "stop"}' \
    -H "Content-Type: application/json" -H "X-Entd-Request: magic" \
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
