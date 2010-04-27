// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ENTD_JSHTTP_H_
#define ENTD_JSHTTP_H_

#include <string>

#include <base/basictypes.h>
#include <v8.h>

namespace entd {

class Entd;
class NativeTimeout;

// Internal class for representing HTTP requests
class JSHttpRequest;

// Interface Class for sending actual HTTP requests
//  The default implementation uses libcurl.
//  The interface allows this to be stubbed out for testing or replaced.
class JSHttpMessengerInterface
{
 public:
  JSHttpMessengerInterface() {};
  virtual ~JSHttpMessengerInterface() {};
  virtual int Update() = 0;
  // Send a Request using HTTP.
  // If post==true, use HTTP POST instead of HTTP GET
  virtual bool HttpGet(JSHttpRequest* request) = 0;
  virtual bool HttpPost(JSHttpRequest* request) = 0;
 private:
  DISALLOW_COPY_AND_ASSIGN(JSHttpMessengerInterface);
};

// Defines an interface between V8 and a JSHttpMessengerInterface
// Example Usage:
//   jshttp_ = new JSHttp(NULL); // NULL = use default (Curl) Messenger
//   bool res = jshttp_->Initialize();
//   if (res)
//     my_v8_object->Set(String::New("http"), jshttp_->GetObject());
class JSHttp
{
 public:
  JSHttp(Entd* entd, JSHttpMessengerInterface* messenger);
  ~JSHttp();
  bool Initialize();

  // Accessors
  v8::Handle<v8::Object> GetObject() { return obj_; }
  JSHttpMessengerInterface* GetMessenger() { return messenger_; }

  // Builds a template if necessary and returns it
  static v8::Handle<v8::FunctionTemplate> GetTemplate();
  // Gets passed to entd_->SetNativeTimeout() to be called periodically
  static bool Update(void* data);

 private:

  // Internal data
  Entd* entd_;
  JSHttpMessengerInterface* messenger_;
  uint32_t timeout_;
  v8::Persistent<v8::Object> obj_;

  // Static/Persistant V8 template object for JSHttp.
  static v8::Persistent<v8::FunctionTemplate> s_http_template_;

  DISALLOW_COPY_AND_ASSIGN(JSHttp);
};

} // namespace entd

#endif // ENTD_JSHTTP_H_
