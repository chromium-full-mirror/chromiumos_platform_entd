# -*- python -*-

# Copyright (c) 2009-2010 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import re

def build():
  vars = get_variables()

  env = get_environment(vars)

  env.AppendUnique(
    CCFLAGS=['-fPIC', '-fno-exceptions', '-Wall', '-Werror', '-ggdb'],
    LINKFLAGS=['-fPIC'],
    LIBS=['base',
          'rt',
          'dl',
          'pthread',
          'v8',
          'event',
          'curl',
          'crypto',
          'opencryptoki',
          'chromeos',
          'crosapi'],
  )

  env.Append(
    CCFLAGS=['-I..'],
    LINKFLAGS=['-L${V8_LIB}'],
   )

  env.ParseConfig('pkg-config --cflags --libs libcurl dbus-glib-1 libpcrecpp')

  end_program = env.Program(
      '${BUILD_DIR}/entd',
      [os.path.join("${BUILD_DIR}", fn) for fn in
       ("callback_server.cc",
        "browser.cc",
        "entd.cc",
        "extensions.cc",
        "flimflam.cc",
        "http.cc",
        "main.cc",
        "pkcs11.cc",
        "crypto_openssl.cc",
        "crypto_pkcs11.cc",
        "syslog.cc",
        "tpm.cc",
        "utils.cc",)]
      )

  env.Install('${SYSROOT}/usr/sbin/', end_program)
  env.Alias('install', '${SYSROOT}/usr/sbin/')


def get_variables():
  vars = Variables()

  # These variables consist of flags that need to be split into individual
  # strings.
  for name, desc, default in (
      ('CFLAGS', 'Extra Flags for ANSI C Compiler', ''),
      ('CCFLAGS', 'Extra Flags for C++ Compiler', ''),
      ('LDFLAGS', 'Extra Flags for Linker', '')):
    vars.Add(name, desc, Split(os.environ.get(name, default)))

  # These should be used as-is.
  for name, desc, default in (
      ('SYSROOT',
       'Root of filesystem, serves as a base for other relative paths', ''),
      ('PKG_CONFIG_PATH', 'Path to pkg-conf files',
       '/usr/lib/pkgconfig'),
      ('PKG_CONFIG_LIBDIR', 'Replace the default search directory', ''),
      ('LD_LIBRARY_PATH', 'Search path for dynamic libraries',
       '/usr/lib'),
      ('PREFIX', 'Installation prefix, relative to SYSROOT', '${SYSROOT}'),
      ('CHOST', 'Name of the toolchain, used to compute default ' +
       'toolchain executable names', ''),
      ('CC', 'ANSI C Compiler', '/usr/bin/${TC_PREFIX}gcc'),
      ('CXX', 'C++ Compiler', '/usr/bin/${TC_PREFIX}g++'),
      ('AR', 'Archiver', '/usr/bin/${TC_PREFIX}ar'),
      ('RANLIB', 'Archive Indexer', '/usr/bin/${TC_PREFIX}ranlib'),
      ('LD', 'Linker', '/usr/bin/${TC_PREFIX}ld'),
      ('NM', 'Symbol Extractor', '/usr/bin/${TC_PREFIX}nm'),
      ('BUILD_DIR', 'Path for intermediate build objects', 'out/${CHOST}'),
      ('V8_LIB', 'Path for v8 library', '${SYSROOT}/usr/lib')):
    vars.Add(name, desc, Split(os.environ.get(name, default)))

  return vars


def get_environment(vars):
  env = Environment(variables=vars)

  # If there is a CHOST specified, then set TC_PREFIX so our toolchain
  # related variables get sensible defaults.
  if env["CHOST"]:
    env["TC_PREFIX"] = "${CHOST}-"

  env.Append(CFLAGS=['--sysroot=${SYSROOT}'],
             CCFLAGS=['--sysroot=${SYSROOT}'])

  # copy all these vars to the build environment (UNIX process env, not just
  # scons "Environment").
  for key in vars.keys():
    env['ENV'][key] = env[key]

  env.VariantDir("${BUILD_DIR}", ".", duplicate=0)

  return env

build()
