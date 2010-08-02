// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/**
 * Namespace for utility functions...
 */

var util = new Object();

/**
 * Returns a version of str with variable references replaced.
 *
 * Variables should be of the form %(name) or %FLAG(name).
 *
 * At the moment the only supported FLAG is 'uri', which uri encodes the value
 * before placing it in the string.  For example, if the value of
 * vars['percent'] is '%', then %uri(percent) would become '%25'.
 *
 * This function throws an error if an unknown variable is referenced or
 * an unknown FLAG is used.
 *
 * @param {string} str A string containing zero or more variable references.
 * @param {Object|function(string):string} vars An object containing the
 *     variables, or a function that returns a variable value given a name.
 */
util.replaceVars =
function replaceVars(str, vars) {
  function uriall_replace (ch) {
    // Replace EVERY character with a percent sign, followed by the character's
    // value in hex.  It's like an extreme uri encoding, and some CSR servers
    // seem to require it.
    rv = ch.charCodeAt(0).toString(16);
    return "%" + (rv.length > 1 ? rv : ("0" + rv));
  }

  function cb(m, flag, name) {
    if (typeof vars == 'function')
      value = vars(name);
    else
      value = vars[name];

    if (typeof value == 'undefined')
      throw new Error('replaceVars: Unknown variable name: ' + name);

    if (!flag)
      return value;

    switch (flag) {
      case 'uri': return encodeURI(value);

      case 'uriall':
        return value.replace(/.|\n/g, uriall_replace);

      default:
        throw new Error('replaceVars: Unknown flag: ' + flag +
                        ', while replacing variable: ' + name);
    }
  }

  return str.replace(/%([a-z]*)\(([^\)]+)\)/g, cb);
};
