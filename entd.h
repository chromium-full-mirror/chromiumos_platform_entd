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
#include "base/scoped_ptr.h"
#include <v8.h>

#include "entd/js_object_wrapper.h"
#include "entd/utils.h"

namespace entd {

class CallbackServer;
class Http;
class NativeTimeout;
class Syslog;
class Timeout;

class Entd : public JSObjectWrapper<Entd> {
 public:
  typedef bool(* NativeTimeoutCallback)(void*);

  Entd();
  virtual ~Entd();

  void SetUsername(const std::string& username) {
    LOG(INFO) << "Username set to: " << username;
    username_ = username;
  }

  void SetUtilityFile(const std::string& filename) {
    LOG(INFO) << "Utility file set to: " << filename;
    utility_filename_ = filename;
  }

  void SetManifestFile(const std::string& filename) {
    LOG(INFO) << "Manifest file set to: " << filename;
    manifest_filename_ = filename;
  }

  void SetPolicyFile(const std::string& filename) {
    LOG(INFO) << "Policy file set to: " << filename;
    policy_filename_ = filename;
  }

  static const char* GetClassName() { return "entd"; }

  // Bind functions / properties to the V8 template object
  static void SetTemplateBindings(
      v8::Handle<v8::ObjectTemplate> template_object);

  // Initialize the Entd object, call this first.
  virtual bool Initialize();

  // Load the policy script and start processing events.
  virtual bool Run();

  // Stop event processing and return from Run().
  virtual void Stop();

  // Set a timeout to fire in a specified number of milliseconds.  Takes a JS
  // function or string and a integer number of milliseconds to wait.  Returns
  // an integer handle to the timeout.
  virtual uint32_t SetTimeout(v8::Handle<v8::Value> value, uint32_t interval);

  // Remove a timeout from the list of timeouts.  This DOES NOT delete
  // the timeout.  It's up to the caller to ensure that happens somehow.
  virtual Timeout* ClearTimeout(uint32_t timeout_handle);

  // Invoked when the timeout specified by timeout_handle fires.
  virtual void OnTimeout(const Timeout& timeout);

  // Call a native function at a specified interval specified in miliseconds
  // This sets up and starts the timeout.
  // NativeTimeoutCallback is a typedef'd function that receives 'data'
  //  as its argument and returns true if it needs to be called again or
  //  false if it has completed. (Can be restarted with StartNativeTimeout())
  // Returns an integer handle that can be used to cancel the timeout
  virtual uint32_t SetNativeTimeout(NativeTimeoutCallback cb, void *data,
                                    uint32_t interval_ms);

  // Start a native timeout after it has stopped. If the timeout is already
  //  started this will reset the timer.
  // Returns false if the timeout doesn't exist
  virtual bool StartNativeTimeout(uint32_t handle);

  // Cancels a native timeout function. This cancels any event timers,
  //  removes the timeout from the list, and deletes the timeout.
  // Returns false if the timeout doesn't exist
  virtual bool ClearNativeTimeout(uint32_t timeout_handle);

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
  // Invoke some method on the global JSON object.
  bool CallJson(std::string method_name, v8::Handle<v8::Value> arg,
                v8::Handle<v8::Value>* result);

  std::string utility_filename_;
  std::string manifest_filename_;
  std::string policy_filename_;
  std::string username_;

  uint32_t timeout_sequence_;
  std::vector<Timeout*> timeout_list_;
  std::map<uint32_t, NativeTimeout*> native_timeouts_;

  scoped_ptr<Http> jshttp_;
  scoped_ptr<Syslog> jssyslog_;
  scoped_ptr<CallbackServer> callback_server_;
  v8::Persistent<v8::Context> context_;

  DISALLOW_COPY_AND_ASSIGN(Entd);
};

}  // namespace entd

#endif // ENTD_ENTD_H_
