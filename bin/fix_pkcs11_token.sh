#!/bin/sh

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

if [ ! -e "$USER_TOKEN_DIR/NVTOK.DAT" ]; then
  log "No PKCS#11 token found for $USERNAME."
else
  if [ -e "$USER_TOKEN_DIR/PRIVATE_ROOT_KEY.pem" -a \
       -e "$USER_TOKEN_DIR/TOK_OBJ/70000000" ]; then
    log "PKCS#11 token for $USERNAME looks ok."
  else
    # If these files are missing, it's a sign that initialization timed out.
    # The only way to recover seems to be to wipe out the whole token and try
    # again.
    log "PKCS#11 token for $USERNAME appears to be broken, deleting:" \
      "$USER_TOKEN_DIR/*"
    rm -rf "$USER_TOKEN_DIR"/*
  fi
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
