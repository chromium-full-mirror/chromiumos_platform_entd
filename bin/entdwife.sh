#!/bin/sh
# Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# This script is temporary front-end to entd.  It validates the policy's
# signature before starting the daemon.  If the signing certificate or
# signature to not validate, then this script will log an error to syslog
# and exit without starting entd.
#

if [ -z "$HOME" ]; then
  HOME=/home/chronos/user
fi

SCRIPT="$(basename $0)"
SIGNING_CERT="signing-cert.pem"
SIGNED_DIGEST="signed-digest.sha1"
ROOT_CA_FILE="root-ca.pem"
REQUIRED_TO_SIGN="isa-cros-policy manifest.json policy.js $SIGNING_CERT"
REQUIRED_TO_START="$REQUIRED_FOR_SIGN $SIGNED_DIGEST"

. "/usr/lib/shflags" || (echo "error loading shflags"; exit 1)

DEFINE_string command "" \
  "Command to run; One of: sign, verify, or start" "c"
DEFINE_boolean verify_signature $FLAGS_TRUE \
  "Verify the authenticity of the signature" "v"
DEFINE_boolean allow_self_signed $FLAGS_FALSE \
  "Allow self signed certificates" "S"
DEFINE_string extension "" \
  "Location of the enterprise extension" "x"
DEFINE_string extension_path "${HOME}/Extensions" \
  "Location to search for extensions when --extension is not provided" "p"
DEFINE_string signing_key "" \
  "Location of the private key to use when signing." "K"
DEFINE_string crx_key "" \
  "Location of the private key to use when creating the crx file." "k"
DEFINE_string entd "/usr/sbin/entd" \
  "Path to the entd binary" "d"
DEFINE_string utility "/etc/entd/base-policy.js" \
  "Path to policy utility file" "t"
DEFINE_string username "$CHROMEOS_USER" \
  "ChromeOS Username (full email address)." "u"
DEFINE_string output "$(pwd)" \
  "Destination directory or filename for crx files" "o"

FLAGS "$@" || exit $?
eval set -- "${FLAGS_ARGV}"

main() {
  local extension="$FLAGS_extension"

  if [ -z "$FLAGS_command" ]; then
    log "Missing option: --command"
    exit 1
  fi

  if [ -z "$extension" ]; then
    # User didn't pick a particular extension, search one out.
    extension="$(find_extension "$FLAGS_extension_path")"
    if [ -z "$extension" ]; then
      return 1
    fi
  fi

  log "Using extension: $extension"

  local result
  if [ "$FLAGS_command" = "makecrx" ]; then
    # Sign an extension.
    cmd_makecrx "$extension" "$FLAGS_crx_key" "$FLAGS_signing_key"
    result=$?

  elif [ "$FLAGS_command" = "verify" ]; then
    # Verify a signature without starting entd.
    cmd_verify "$extension"
    result=$?
    if [ "$result" = "0" ]; then
      log "Extension verified: $extension"
    fi

  elif [ "$FLAGS_command" = "start" ]; then
    # Verify the signature, then start entd.
    cmd_start "$extension"
    result=$?

  else
    log "Unknown command: $FLAGS_command"
    result=1
  fi

  return $result
}

cmd_makecrx() {
  local extension="$1"
  local crx_key="$2"
  local signing_key="$3"

  if [ ! -d "$extension" ]; then
    log "Missing or invalid extension: $extension"
    return 1
  fi

  if [ ! -f "$crx_key" ]; then
    log "Missing or invalid crx key: $crx_key"
    return 1
  fi

  if [ ! -f "$signing_key" ]; then
    log "Missing or invalid signing key: $signing_key"
    return 1
  fi

  local chrome="$(which google-chrome)"
  if [ ! -x "$chrome" ]; then
    log "Unable to locate google-chrome executable"
    return 1
  fi

  local workdir="$(mktemp -d)"
  echo "workdir: $workdir"

  local signed="$workdir/signed"
  mkdir -p "$signed"
  cp -rL $extension/* "$signed"
  rm $(find "$signed" -name '*~')

  if ! cmd_sign "$signed" "$signing_key"; then
    log "Error signing"
    return 1
  fi

  local userdata="$workdir/userdata"
  mkdir -p "$userdata"

  "$chrome" --pack-extension="$signed" \
    --pack-extension-key="$crx_key" \
    --user-data-dir="$userdata" --no-message-box --no-first-run

  if [ ! -f "$workdir/signed.crx" ]; then
    log "Error creating crx"
    return 1
  fi

  local output="$FLAGS_output"

  if [ -d "$output" ]; then
    local cn="$(get_cn "$extension")"
    local version="$(get_version "$extension")"
    output="$output/$cn-policy-$version.crx"
  fi

  mv "$workdir/signed.crx" "$output"
  chmod a+r "$output"

  log "CRX file written to: $output"

  rm -rf "$workdir"
}

cmd_sign() {
  local extension="$1"
  local private_key="$2"

  log "Signing: $extension"

  if [ -z "$private_key" ]; then
    log "Missing private key"
    return 1
  fi

  if ! verify_files "$extension" "$REQUIRED_TO_SIGN"; then
    log "Invalid extension: $extension"
    return 1
  fi

  local catfile="$(make_catfile "$extension")"
  if [ -z "$catfile" ]; then
    return 1
  fi

  local output
  output="$(openssl dgst -sha1 -sign "$private_key" \
    -out "$extension/$SIGNED_DIGEST" "$catfile" 2>&1)"
  local result=$?

  rm "$catfile"

  # If openssl exited with code 0 and the signature file is not zero length,
  # then were probably successful.
  if [ $result = 0 -a -s "$extension/$SIGNED_DIGEST" ]; then
    cmd_verify "$extension"
    return $?
  fi

  log "Error signing extension: $output"
  return 1
}

cmd_verify() {
  local extension="$1"

  log "Verifying: $extension"

  if ! (verify_files "$extension" "$REQUIRED_TO_START"); then
    log "Invalid extension: $extension"
    return 1
  fi

  if [ "$FLAGS_verify_signature" = "$FLAGS_TRUE" ]; then
    if ! verify_cert "$extension"; then
      return 1
    fi

    if ! verify_signature "$extension"; then
      return 1
    fi

  else
    log "WARNING: Not verifying extension certificate"
  fi
}

cmd_start() {
  local extension="$1"

  if ! cmd_verify "$extension"; then
    return 1
  fi

  local cn="$(get_cn "$extension")"

  local hostname="$(echo "$FLAGS_username" | cut -f2 -d@)"

  if [ "$cn" != "$hostname" ]; then
    log "Certificate CN '$cn' does not match expected hostname '$hostname'"
    return 1
  fi

  local root_ca_option=""
  if [ -f "$extension/$ROOT_CA_FILE" ]; then
    root_ca_option="--root-ca-file=$ROOT_CA_FILE"
  fi

  exec "$FLAGS_entd" --utility="$FLAGS_utility" "$root_ca_option" \
    --policy="$extension/policy.js" --manifest="$extension/manifest.json" \
    --username="$FLAGS_username"
}

log() {
  if [ -t 2 ]; then
    echo "$@" >&2
  else
    logger -t SCRIPT -- "$@"
  fi
}

abspath() {
  if [ -d "$1" ]; then
    echo "$(cd $1; pwd)"
  else
    echo "$(cd $(dirname "$1"); pwd)/$(basename $1)"
  fi
}

get_cn() {
  local extension="$1"

  # Extract the CN from the certificate.
  openssl x509 -in "$extension/$SIGNING_CERT" -noout -subject | \
    sed 's:.*/CN=\([^/]\+\).*:\1:'
}

get_version() {
  local extension="$1"

  cat "$extension/manifest.json" | sed -n 's/\s*"version":\s*"\([^"]\+\).*/\1/p'
}

# Search through the given path for one and only one enterprise extension.
find_extension() {
  local path="$1"

  if [ ! -d "$path" ]; then
    log "Extension path is not a directory: $path"
    return
  fi

  local candidates="$(find -L "$path" -mindepth 3 -maxdepth 3 \
    -name isa-cros-policy)"

  if [ -z "$candidates" ]; then
    log "No enterprise policy extension found in $path";
    return
  fi

  
  if [ "$(echo "$candidates" | wc -w)" != "1" ]; then
    log "Multiple enterprise policies found in $path: $candidates";
    return
  fi

  dirname "$candidates"
}

# Verifies that the extension contains a list of files.  If the list is not
# specified, assume they mean the list of files require to start entd with
# this extension.
verify_files() {
  local extension="$1"
  local required_files="$2"

  if [ -z "$required_files" ]; then
    required_files="$REQUIRED_TO_START"
  fi

  local err=0

  for file in $required_files; do
    if [ ! -f "$extension/$file" ]; then
      log "Missing $extension/$file";
      err=1
    fi
  done

  return $err
}

# The "catfile" is the concatenation of all of the files from the extension
# into a single file.
#
# We locate all regular files in the extension, excluding any previous
# signature file, sort them in ascending order.  Then for each file, we
# append the filename and contents to the catfile.
#
# The hash of this file is what is actually signed.
#
make_catfile() {
  local extension="$1"

  local normalized_manifest="$(normalize_manifest "$extension")"
  if [ -z "$normalized_manifest" ]; then
    return 1
  fi

  cd "$extension" > /dev/null
  local filenames="$(find . -type f -not -wholename "./$SIGNED_DIGEST" | sort)"
  cd - > /dev/null

  if [ -z "$filenames" ]; then
    log "Error enumerating files"
    return 1
  fi

  local catfile="$(mktemp)"
  for filename in $filenames; do
    echo $filename >> "$catfile"
    if [ "$filename" = "./manifest.json" ]; then
      echo "$normalized_manifest" >> "$catfile"
    else
      cat "$extension/$filename" >> "$catfile"
    fi
  done

  
  echo "$catfile"
}

# Verify that a certificate is valid.
verify_cert() {
  local extension="$1"

  local output="$(openssl verify "$extension/$SIGNING_CERT")"

  if [ "$FLAGS_allow_self_signed" = "$FLAGS_TRUE" ]; then
    log "WARNING: Allowing self signed certificates"
    output="$(echo $output | grep -v "self signed certificate")"
  fi

  if [ ! -z "$(echo "$output" | grep "error")" ]; then
    # `openssl verify` exits with a success code even if verification fails,
    # so we have to grep the output to determine the result of verification.
    log "Unable to verify certificate: $output"
    return 1
  fi
}

# Verify the signature of a policy.
verify_signature() {
  local extension="$1"

  # This file contains the signature of the extension.
  local sigfile="$extension/$SIGNED_DIGEST"

  local catfile="$(make_catfile "$extension")"

  if [ -z "$catfile" ]; then
    return 1
  fi

  # Extract the public key from the certificate.
  local keyfile="$(mktemp)"

  log "Extracting public key from $extension/$SIGNING_CERT"
  openssl x509 -in "$extension/$SIGNING_CERT" -pubkey -noout > "$keyfile"
  local result=$?

  if [ "$result" != "0" ]; then
    log "Error extracting public key from certificate"
    rm "$catfile"
    return $result
  fi

  if [ ! -f "$keyfile" ]; then
    log "Unknown error extracting public key from certificate"
    return 1
  fi

  # Declare $output before assigning, so we don't lose the return code of
  # the openssl command.
  local output

  # Verify the signature.
  output="$(openssl dgst -sha1 -verify "$keyfile" \
    -signature "$extension/$SIGNED_DIGEST" "$catfile" 2>&1)"
  result=$?

  # Clean up the temporary files.
  rm "$catfile" "$keyfile"

  if [ "$result" != "0" ]; then
    log "Signature $sigfile did not validate: $output"
  else
    log "Signature $sigfile is valid"
  fi

  return $result
}

# Chrome takes liberties with the manifest file when it installs an extension.
# It deserializes it, adds the "key" if it is missing, and then re-serializes
# it.  There is no guaranteed ordering for the keys when the file is finally
# written to disk.  This royally screws up our recalculation of the signature.
#
# So, instead of signing the actual manifest source file, we pass it through
# a normalization procedure where we impose a guaranteed ordering on the keys,
# and remove the extra key (called "key") that Chrome adds during installation.
#
# For example, given { "name": "Foo", "browser": { "hello": "world" } }, we
# return:
#
#   manifest.browser.hello = "world"
#   manifest.name = "Foo"
#
# If we can, we use a small Python script to do the normalization.  If Python
# isn't available (say, on the device) then we use entd itself.
#
#
# TODO(rginda): Do better.
normalize_manifest() {
  local python="$(which python)"

  if [ -x "$python" ]; then
    normalize_manifest_py "$@"
  elif [ -x "$FLAGS_entd" ]; then
    normalize_manifest_js "$@"
  else
    log "Can't find python or entd, unable to normalize extension manifest"
    return 1
  fi
}

normalize_manifest_py() {
  local extension="$1"

  local scriptfile="$(mktemp)"
  cat <<EOF > "$scriptfile"
import sys

try:
  import json
except ImportError:
  json = None

if not json or not hasattr(json, 'loads'):
  # The contemporary version of the json module wasn't included until
  # Python 2.6.  If you want to build a policy extension on an earlier version,
  # you need to install the simplejson module.
  import simplejson
  json = simplejson

def to_str(name, value, ary = []):
  if type(value) == list:
    ary.append(name + ": []");
    for i in xrange(len(value)):
       to_str(name + "." + str(i), value[i], ary);
  elif type(value) == dict:
    ary.append(name + ": {}");
    for key in value.keys():
       to_str(name + "." + key, value[key], ary);
  else:
    ary.append(name + ": " + json.dumps(value));

  return ary

if __name__ == '__main__':
  fp = open(sys.argv[1])
  d = json.load(fp)
  # Remove the "key" possibly added by Chrome.
  if 'key' in d:
    del d['key']
  ary = to_str('manifest', d)
  ary.sort()
  ary.reverse()
  print '\n'.join(ary)

EOF

  python "$scriptfile" "$extension/manifest.json"

  rm "$scriptfile"
}

normalize_manifest_js() {
  local extension="$1"

  local scriptfile="$(mktemp)"
  cat <<EOF > "$scriptfile"
entd.onLoad = function(m) {
  // Remove the "key" possibly added by Chrome.
  delete m.key;
  var ary = str("manifest", m);
  // Sort the results so we can determine an ordering.
  println(ary.sort().reverse().join("\n"));
}

function str(name, value, ary) {
  ary = ary || [];

  if (value instanceof Array) {
    ary.push(name + ": []");
    for (var i = 0; i < value.length; ++i)
       str(name + "." + i, value[i], ary);
  } else if (value instanceof Object) {
    ary.push(name + ": {}");
    for (var key in value)
       str(name + "." + key, value[key], ary);
  } else {
    ary.push(name + ": " + JSON.stringify(value));
  }

  return ary
}
EOF

  "$FLAGS_entd" --policy="$scriptfile" --manifest="$extension/manifest.json" \
    --username=user@example.com --allow-dirty-exit 2>/dev/null

  rm "$scriptfile"
}

main "$@"
