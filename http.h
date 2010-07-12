// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ENTD_HTTP_H_
#define ENTD_HTTP_H_

#include <string>

#include <base/basictypes.h>
#include <v8.h>

#include "entd/scriptable.h"

namespace entd {

class Entd;
class NativeTimeout;

// Internal class for representing HTTP requests
class HttpRequest;

// Interface Class for sending actual HTTP requests
// The default implementation uses libcurl.
// The interface allows this to be replaced or stubbed out for testing.
class HttpMessengerInterface {
 public:
  HttpMessengerInterface() {};
  virtual ~HttpMessengerInterface() {};
  virtual int Update() = 0;
  // Send a Request using HTTP to 'url',
  // and set up 'request' to receive the results.
  virtual bool HttpGet(HttpRequest* request) = 0;
  virtual bool HttpPost(HttpRequest* request) = 0;

 private:
  DISALLOW_COPY_AND_ASSIGN(HttpMessengerInterface);
};

// Defines an interface between V8 and a HttpMessengerInterface
// Example Usage:
//   Http::Reference http = Http::New();
//   // NULL = use default (Curl) Messenger
//   bool rv = http->Initialize(entd, NULL);
//   if (rv)
//     my_v8_object->Set(String::NewSymbol("http"), jshttp->js_object());
class Http : public Scriptable<Http> {
 public:
  // 'entd' and 'messenger' are non-const interfaces.
  Http();
  virtual ~Http();
  virtual bool Initialize(Entd* entd, HttpMessengerInterface* messenger);
  static const std::string class_name() { return "entd.http"; }

  Entd* GetEntd() { return entd_; };

  static bool InitializeTemplate(v8::Handle<v8::FunctionTemplate> t);

  // Called when the update timer fires.
  bool OnNativeTimeout();

  // Call the corresponding method in the messenger interface
  // and set the timer callback to handle the results.
  bool HttpGet(HttpRequest* request);
  bool HttpPost(HttpRequest* request);

  // globals
  static bool allow_self_signed_certs;
  static std::string root_ca_file;

 private:
  Entd* entd_;
  HttpMessengerInterface* messenger_;
  uint32_t timeout_;

  DISALLOW_COPY_AND_ASSIGN(Http);
};

} // namespace entd

#endif // ENTD_HTTP_H_
