// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ENTD_ENTD_H_
#define ENTD_ENTD_H_

#include <base/basictypes.h>
#include <base/logging.h>
#include <string>
#include <v8.h>
#include <vector>
#include "entd/utils.h"

namespace entd {

class Timeout;

class Entd {
 public:
  Entd();
  virtual ~Entd();

  virtual void SetPolicyFile(const std::string& filename);

  // Initialize the Entd object, call this first.
  virtual bool Initialize();

  // Return the singleton v8 function template for entd.
  static v8::Handle<v8::FunctionTemplate> GetEntdTemplate();

  // Return an instance of the v8 object for this entd instance.
  v8::Local<v8::Object> MakeEntd();

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

 private:
  // Executes a file within the current v8 context.
  virtual bool ExecuteFile(const std::string& filename,
                           v8::Handle<v8::Value>* result);

  // Executes a string within the current v8 context.
  virtual bool ExecuteString(const v8::Handle<v8::String>& source,
                             const std::string& filename,
                             v8::Handle<v8::Value>* result);

  // Print the current exception.
  virtual void ReportException(v8::TryCatch* try_catch);

  std::string policy_filename_;
  uint32_t timeout_sequence_;

  std::vector<Timeout*> timeout_list_;
  v8::Persistent<v8::Context> context_;

  static v8::Persistent<v8::FunctionTemplate> entd_template_;

  DISALLOW_COPY_AND_ASSIGN(Entd);
};

}  // namespace entd

#endif // ENTD_ENTD_H_
