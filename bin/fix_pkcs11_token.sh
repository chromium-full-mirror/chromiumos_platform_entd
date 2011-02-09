#!/bin/sh
# Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

if [ -z "$1" ]; then
  USERNAME="chronos"
else
  USERNAME="$1"
fi

PKCS11_GROUP="pkcs11"

OPENCRYPTOKI_DIR="/var/lib/opencryptoki"
USER_TOKEN_LINK="$OPENCRYPTOKI_DIR/tpm/$USERNAME"
ROOT_TOKEN_LINK="$OPENCRYPTOKI_DIR/tpm/root"

USER_TOKEN_DIR="/home/$USERNAME/user/.tpm"

log() {
  if [ -t 1 ]; then
    echo "$@" 1>&2
  else
    logger -t $(basename "$0") "$@"
  fi
}

is_token_broken() {
  if [ ! -e "/var/lib/.tpm_owned" ]; then
    log "TPM is not owned, token for $USERNAME can't be valid."
    return 0
  fi

  if [ ! -e "$USER_TOKEN_DIR/PRIVATE_ROOT_KEY.pem" -o \
       ! -e "$USER_TOKEN_DIR/TOK_OBJ/70000000" ]; then
    log "PKCS#11 token for $USERNAME is missing some files.  Possibly not yet"
    log "initialized?  TOK_OBJ contents were $(echo $USER_TOKEN_DIR/TOK_OBJ/*)."
    return 0
  fi

  log "PKCS#11 token for $USERNAME looks ok."
  return 1
}

if [ ! -e "$USER_TOKEN_DIR/NVTOK.DAT" ]; then
  log "No PKCS#11 token found for $USERNAME."
elif is_token_broken; then
  log "Removing $USER_TOKEN_DIR/*"
  rm -rf "$USER_TOKEN_DIR"/*
fi

# Ensure the directories exist
mkdir -p "$OPENCRYPTOKI_DIR/tpm"
chown -R "root:$PKCS11_GROUP" "$OPENCRYPTOKI_DIR"

# Ensure that they point to the user volume
[ -L "$USER_TOKEN_LINK" ] || \
  ln -sf "$USER_TOKEN_DIR" "$USER_TOKEN_LINK"
[ -L "$ROOT_TOKEN_LINK" ] || \
  ln -sf "./$USERNAME" "$ROOT_TOKEN_LINK"

# Always remove the old token entry.
rm -f /var/lib/opencryptoki/pk_config_data

# Creating this directory because if it's not there, token initialization
# will neither create it nor populate it.
mkdir -p "$USER_TOKEN_DIR/TOK_OBJ"

# Configure the tpm as a token
pkcs_slot 0 tpm

# Make sure the user can access their own data
chown -R "$USERNAME:$PKCS11_GROUP" "$USER_TOKEN_DIR"
