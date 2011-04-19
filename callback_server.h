// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// The callback server listens for http connections on port 5199 (by default),
// and dispatches valid requests to javascript function registered by the
// policy.
//
// The incoming request must be an HTTP POST (libevent doesn't have an https
// server) to the uri "/dispatch".  It must have a content-type of
// "application/json", an "X-Entd-Request" header set to "magic", and a
// request entity no larger than 1k which represents a valid JSON object.
//
// The JSON object must have a property named "function" which contains the
// function name we want to dispatch, and may optionally contain an property
// named "argument", which is passed as the only argument to the target
// function.
//
// A policy can opt in to starting the callback server by calling
// "entd.callbackServer.start(callbacks[, port]). The callbacks parameter is
// required and must be a js object containing the callbacks to be served.
// The optional port can be used to specify the port to listen on. The server
// will bind to 120.7.7.1 only.

#ifndef ENTD_CALLBACK_SERVER_H_
#define ENTD_CALLBACK_SERVER_H_

#include <base/basictypes.h>
#include <base/logging.h>
#include <event.h>
#include <evhttp.h>
#include <v8.h>

#include "entd/js_object_wrapper.h"
#include "entd/utils.h"

namespace entd {

class Entd;

class CallbackServer : public JSObjectWrapper<CallbackServer> {
 public:
  explicit CallbackServer(Entd* entd);
  virtual ~CallbackServer();

  // JSObjectWrapper methods
  static const char* GetClassName() { return "CallbackServer"; }
  static void SetTemplateBindings(
      v8::Handle<v8::ObjectTemplate> template_object);

  // Initialize the CallbackServer instance.  Must be called before any
  // other method.
  virtual bool Initialize() {
    JSObjectWrapper<CallbackServer>::Initialize();
    return true;
  }

  // Start the callback server with a particular set of callbacks and
  // on a given port number.
  virtual bool Start(v8::Handle<v8::Object> callbacks, int port);

  // Stop the server.
  virtual void Stop();

  // Return true if the callback server has been started.
  virtual bool IsRunning();

  // Dispatch a given http request.
  virtual void OnRequest(struct evhttp_request* request);

  // Sets whether or not the server is busy.  While busy, it cannot be stopped.
  // This should only matter when someone attempts to stop the server from
  // script during a callback.  In other cases, the single threadedness of
  // entd should keep us from ever trying to stop while busy.  This is not
  // nestable.
  virtual void SetBusy(bool state) {
    if (state == busy_)
      LOG(WARNING) << "Busy status is already " << (state ? "set" : "clear");
    busy_ = state;
  };
  virtual bool IsBusy() { return busy_; }

  static void set_session_id(const std::string& session_id) {
    session_id_ = session_id;
  }

  static std::string session_id() {
    return session_id_;
  }

  static std::string required_origin;

 private:
  // State for SetBusy/IsBusy.
  bool busy_;

  // Parent entd object.
  Entd* entd_;

  // JS Object containing the callback functions we might dispatch to.
  v8::Persistent<v8::Object> callbacks_;

  // X-Entd-Session-Id that must come in every request.
  static std::string session_id_;

  // Non-null if the server is running.
  struct evhttp* evhttp_;

  // Port we're listening on, or 0 if not running.
  int port_;

  DISALLOW_COPY_AND_ASSIGN(CallbackServer);
};

}  // namespace entd

#endif  // ENTD_CALLBACK_SERVER_H_
