// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ENTD_ENTD_H_
#define ENTD_ENTD_H_

#include <map>
#include <string>
#include <vector>

#include <base/basictypes.h>
#include <base/logging.h>
#include <base/memory/scoped_ptr.h>
#include <v8.h>

#include "entd/js_object_wrapper.h"
#include "entd/utils.h"

namespace entd {

class CallbackServer;
class Flimflam;
class Http;
class NativeTimeout;
class Syslog;
class Timeout;
class Pkcs11;

class Entd : public JSObjectWrapper<Entd> {
 public:
  typedef bool(* NativeTimeoutCallback)(void*);

  Entd();
  virtual ~Entd();

  // If true, entd will automatically exit when all events are processed.
  // However, in order to support this entd will not watch for signal events.
  // This means that onUnload() won't get called for SIGTERM or other process
  // ending signals.
  //
  // It is useful for testing, to ensure that entd exits even if the testcase
  // fails, but not meant for production instances.
  static bool allow_dirty_exit;

  // If true then allow entd JS scripts to read and write to files.
  // This is useful for testing, and necessary for writing certificates
  // without the TPM.
  static bool allow_file_io;

  // True if we were able to load libcros.
  static bool libcros_loaded;

  // Location of the libcros library.
  static std::string libcros_location;

  void SetUsername(const std::string& username) {
    LOG(INFO) << "Username set to: " << username;
    username_ = username;
  }

  void SetUtilityFile(const std::string& filename) {
    LOG(INFO) << "Utility file set to: '" << filename << "'";
    utility_filename_ = filename;
  }

  void SetManifestFile(const std::string& filename) {
    LOG(INFO) << "Manifest file set to: '" << filename << "'";
    manifest_filename_ = filename;
  }

  void SetPolicyFile(const std::string& filename) {
    LOG(INFO) << "Policy file set to: '" << filename << "'";
    policy_filename_ = filename;
  }

  // Determines how the pkcs11 module will be setup.
  // See ConstructEntd() for details.
  void SetPkcs11Mode(const std::string& mode) {
    LOG(INFO) << "PKCS11 Mode: '" << mode << "'";
    pkcs11_mode_ = mode;
  }

  bool SetHostname(const std::string& hostname) {
    if (!CheckHostname(hostname)) {
      LOG(ERROR) << "Invalid hostname: " << hostname;
      return false;
    }

    LOG(INFO) << "Hostname set to: " << hostname;
    hostname_ = hostname;
    return true;
  }

  const std::string& GetHostname() {
    return hostname_;
  }

  static const char* GetClassName() { return "entd"; }

  // Bind functions / properties to the V8 template object
  static void SetTemplateBindings(
      v8::Handle<v8::ObjectTemplate> template_object);

  // Immediate Initializations (before parameters are set)
  virtual bool Initialize();

  // Returns true if libcros is loaded, throws a v8 exception and returns
  // false if not.
  static bool LibcrosLoadedOrThrow();

  // Load the policy script and start processing events.
  virtual uint32_t Run();

  // Set a timeout to fire in a specified number of milliseconds.  Takes a JS
  // function or string and a integer number of milliseconds to wait.  Returns
  // an integer handle to the timeout.
  virtual uint32_t SetTimeout(v8::Handle<v8::Value> value, uint32_t interval);

  // Remove a timeout from the list of timeouts.  This DOES NOT delete
  // the timeout.  It's up to the caller to ensure that happens somehow.
  virtual Timeout* ClearTimeout(uint32_t timeout_handle);

  // Schedule Entd to shutdown with the specified exit code, after the
  // specified number of milliseconds.
  virtual void ScheduleShutdown(uint32_t code, uint32_t interval);

  // Invoked when a signal has been detected.
  virtual void OnSignal(int signal);

  // Invoked when the timeout specified by timeout_handle fires.
  virtual void OnTimeout(const Timeout& timeout);

  // Call a native function at a specified interval specified in miliseconds
  // This sets up and starts the timeout.
  //
  // NativeTimeoutCallback is a typedef'd function that receives 'data'
  // as its argument and returns true if it needs to be called again or
  // false if it has completed. (Can be restarted with StartNativeTimeout())
  //
  // Returns an integer handle that can be used to cancel the timeout
  virtual uint32_t SetNativeTimeout(NativeTimeoutCallback cb, void *data,
                                    uint32_t interval_ms);

  // Start a native timeout after it has stopped. If the timeout is already
  // started this will reset the timer.
  //
  // Returns false if the timeout doesn't exist
  virtual bool StartNativeTimeout(uint32_t handle);

  // Cancels a native timeout function. This cancels any event timers,
  // removes the timeout from the list, and deletes the timeout.
  //
  // Returns false if the timeout doesn't exist
  virtual bool ClearNativeTimeout(uint32_t timeout_handle);

  // Returns true if the hostname the the same as, or more specific than, the
  // current hostname.  Always returns true if the hostname has not been set.
  virtual bool CheckHostname(const std::string& new_hostname);

  // Loads JSON from a file using the JSON.parse() function from the current
  // context.
  virtual bool JsonParseFromFile(const std::string& filename,
                                 v8::Handle<v8::Value>* result);

  // Loads JSON from a file using the JSON.parse() function from the current
  // context.
  virtual bool JsonParse(v8::Handle<v8::String> source,
                         v8::Handle<v8::Value>* result);

  // Turn a value into a JSON string using the JSON.stringify() function from
  // the current context.
  virtual bool JsonStringify(v8::Handle<v8::Value> value,
                             v8::Handle<v8::Value>* result);

  // Executes a file within the current v8 context.
  virtual bool ExecuteFile(const std::string& filename,
                           v8::Handle<v8::Value>* result);

  // Executes a string within the current v8 context.
  virtual bool ExecuteString(const v8::Handle<v8::String>& source,
                             const std::string& filename,
                             v8::Handle<v8::Value>* result);

 private:
  // Construct the Entd object.
  virtual v8::Handle<v8::Object> ConstructEntd();

  // Initialize entd state, load various scripts, and fire the onLoad event.
  virtual bool StartScriptingEnvironment();

  // Fire the onUnload event.
  virtual bool StopScriptingEnvironment();

  // Invoke some method on the global JSON object.
  bool CallJson(std::string method_name, v8::Handle<v8::Value> arg,
                v8::Handle<v8::Value>* result);

  std::string pkcs11_mode_;

  std::string utility_filename_;
  std::string manifest_filename_;
  std::string policy_filename_;

  // Starts out as just the hostname portion of the username, but may be
  // set to a subdomain of that by the manifest file.
  std::string hostname_;
  // The entire username: user@example.com
  std::string username_;

  // Exiting happens asynchronously.  This is where the exit code is stashed
  // until the daemon has finished shutting down.
  int exit_code_;

  uint32_t timeout_sequence_;
  std::vector<Timeout*> timeout_list_;
  std::map<uint32_t, NativeTimeout*> native_timeouts_;

  scoped_ptr<CallbackServer> callback_server_;
  scoped_ptr<Flimflam> flimflam_;
  scoped_ptr<Syslog> syslog_;
  scoped_ptr<Pkcs11> pkcs11_;
  v8::Persistent<v8::Context> context_;

  DISALLOW_COPY_AND_ASSIGN(Entd);
};

}  // namespace entd

#endif // ENTD_ENTD_H_
