// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ENTD_HTTP_H_
#define ENTD_HTTP_H_

#include <string>

#include <base/basictypes.h>
#include <v8.h>

#include "entd/js_object_wrapper.h"

namespace entd {

class Entd;
class NativeTimeout;

// Internal class for representing HTTP requests
class HttpRequest;

// Interface Class for sending actual HTTP requests
//  The default implementation uses libcurl.
//  The interface allows this to be stubbed out for testing or replaced.
class HttpMessengerInterface {
 public:
  HttpMessengerInterface() {};
  virtual ~HttpMessengerInterface() {};
  virtual int Update() = 0;
  // Send a Request using HTTP.
  // If post==true, use HTTP POST instead of HTTP GET
  virtual bool HttpGet(HttpRequest* request) = 0;
  virtual bool HttpPost(HttpRequest* request) = 0;
 private:
  DISALLOW_COPY_AND_ASSIGN(HttpMessengerInterface);
};

// Defines an interface between V8 and a HttpMessengerInterface
// Example Usage:
//   jshttp_ = new Http(NULL);  // NULL = use default (Curl) Messenger
//   bool res = jshttp_->Initialize();
//   if (res)
//     my_v8_object->Set(String::New("http"), jshttp_->obj());
class Http : public JSObjectWrapper<Http> {
 public:
  Http(Entd* entd, HttpMessengerInterface* messenger);
  virtual ~Http();
  virtual bool Initialize();
  static const char* GetClassName() { return "http"; }

  // Bind functions / properties to the V8 template object:
  //  "GET", "POST", and "Request"
  static void SetTemplateBindings(
      v8::Handle<v8::ObjectTemplate> template_object);

  // Called when the update timer fires.
  bool OnNativeTimeout();

  bool HttpGet(HttpRequest* request);
  bool HttpPost(HttpRequest* request);

 private:
  Entd* entd_;
  HttpMessengerInterface* messenger_;
  uint32_t timeout_;

  DISALLOW_COPY_AND_ASSIGN(Http);
};

} // namespace entd

#endif // ENTD_HTTP_H_
