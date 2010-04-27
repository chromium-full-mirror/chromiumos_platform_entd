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
    LIBS=['base', 'rt', 'pthread', 'v8', 'event', 'curl'],
  )

  env.Append(
    CCFLAGS=['-I..'],
    LINKFLAGS=['-L${V8_LIB}'],
   )

  end_program = env.Program(
      '${BUILD_DIR}/entd',
      [os.path.join("${BUILD_DIR}", fn) for fn in
       ("main.cc", "entd.cc", "utils.cc", "jshttp.cc")]
      )

  env.Install('${SYSROOT}/usr/sbin/', end_program)
  env.Alias('install', '${SYSROOT}/usr/sbin/')


def get_variables():
  vars = Variables()
  for tup in (
      ('SYSROOT',
       'Root of filesystem, serves as a base for other relative paths', ''),
      ('PKG_CONFIG_PATH', 'Path to pkg-conf files',
       '/usr/lib/pkgconfig'),
      ('PKG_CONFIG_LIBDIR', 'Replace the default search directory', ''),
      ('LD_LIBRARY_PATH', 'Search path for dynamic libraries',
       '/usr/lib'),
      ('CFLAGS', 'Extra Flags for ANSI C Compiler', ''),
      ('CCFLAGS', 'Extra Flags for C++ Compiler', ''),
      ('LDFLAGS', 'Extra Flags for Linker', ''),
      ('PREFIX', 'Installation prefix, relative to SYSROOT', '${SYSROOT}'),
      ('CHOST', 'Name of the toolchain, used to compute default ' +
       'toolchain executable names', ''),
      ('TC_PREFIX', 'Prefix used for toolchain commands', ''),
      ('CC', 'ANSI C Compiler', '/usr/bin/${TC_PREFIX}gcc'),
      ('CXX', 'C++ Compiler', '/usr/bin/${TC_PREFIX}g++'),
      ('AR', 'Archiver', '/usr/bin/${TC_PREFIX}ar'),
      ('RANLIB', 'Archive Indexer', '/usr/bin/${TC_PREFIX}ranlib'),
      ('LD', 'Linker', '/usr/bin/${TC_PREFIX}ld'),
      ('NM', 'Symbol Extractor', '/usr/bin/${TC_PREFIX}nm'),
      ('BUILD_DIR', 'Path for intermediate build objects', 'out/${CHOST}'),
      ('V8_LIB', 'Path for v8 library', '${SYSROOT}/usr/lib'),
     ):
    # These variables will default to the environment variable of the
    # same name, if one is set, otherwise they will take the default specified
    # above.
    vars.Add(tup[0], tup[1], os.environ.get(tup[0], tup[2]))

  return vars


def get_environment(vars):
  env = Environment(variables=vars)

  # If there is a CHOST specified, then set TC_PREFIX so our toolchain
  # related variables get sensible defaults.
  if env["CHOST"]:
    env["TC_PREFIX"] = "${CHOST}-"

  env.Append(CFLAGS='--sysroot=${SYSROOT}',
             CCFLAGS='--sysroot=${SYSROOT}',
             );

  # copy all these vars to the build environment (UNIX process env, not just
  # scons "Environment".)
  for key in vars.keys():
    env['ENV'][key] = env[key]

  env.VariantDir("${BUILD_DIR}", ".", duplicate=0)

  return env

build()
