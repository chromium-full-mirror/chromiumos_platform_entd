// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "entd/callback_server.h"

#include <base/memory/scoped_ptr.h>

#include "entd/entd.h"

namespace entd {

using std::string;

std::string CallbackServer::session_id_;

namespace {
// Max 1k request entity
const int kMaxRequestSize = 1024;

// libevent defines some of these but not all, so we define what we need here
const int kHttpOk            = 200;
const int kHttpBadRequest    = 400;
const int kHttpNotFound      = 404;
const int kHttpBadMethod     = 405;
const int kHttpBadEntitySize = 413;
const int kHttpBadMedia      = 415;
const int kHttpServerError   = 500;

const uint32_t kDefaultPort  = 5199;  // Atomic weight of Cr, sorta
const uint32_t kMinPort      = 5000;
const uint32_t kMaxPort      = 5999;

// Incoming requests must have this content type
const std::string kContentType = "application/json; charset=UTF-8";

// Callback functions must have this prefix, so we can avoid dispatching
// against default properties that aren't actually intended to be callbacks.
const std::string kCallbackPrefix = "cb:";

// Called by libevent when it accepts an http request.
void dispatch_OnRequest(struct evhttp_request* request, void* data) {
  CallbackServer* cbs = reinterpret_cast<CallbackServer*>(data);
  cbs->SetBusy(true);
  cbs->OnRequest(request);
  cbs->SetBusy(false);
}

v8::Handle<v8::Value> dispatch_Start(const v8::Arguments& args) {
  CallbackServer* cs = CallbackServer::Unwrap(args.This());
  if (!cs) {
    utils::ThrowV8Exception("Method called on invalid object");
    return v8::Undefined();
  }

  if (cs->IsRunning()) {
    utils::ThrowV8Exception("Callback server is already running");
    return v8::Undefined();
  }

  if (args.Length() < 1 || !args[0]->IsObject()) {
    utils::ThrowV8Exception("Missing or invalid parameter: callbacks");
    return v8::Undefined();
  }

  v8::Handle<v8::Object> callbacks = v8::Handle<v8::Object>::Cast(args[0]);

  uint32_t port;

  if (args.Length() > 1)
    port = args[1]->Uint32Value();
  else
    port = kDefaultPort;

  if (port < kMinPort || port > kMaxPort) {
    utils::ThrowV8Exception("Invalid port");
    return v8::Undefined();
  }

  if (!cs->Start(callbacks, port)) {
    utils::ThrowV8Exception("Unable to start callback server");
    return v8::Undefined();
  }

  return v8::Undefined();
}

v8::Handle<v8::Value> dispatch_Stop(const v8::Arguments& args) {
  CallbackServer* cs = CallbackServer::Unwrap(args.This());
  if (!cs) {
    utils::ThrowV8Exception("Method called on invalid object");
    return v8::Undefined();
  }

  if (!cs->IsRunning()) {
    utils::ThrowV8Exception("Callback server is not running");
    return v8::Undefined();
  }

  if (cs->IsBusy()) {
    utils::ThrowV8Exception("Can't stop server while busy");
    return v8::Undefined();
  }

  cs->Stop();

  return v8::Undefined();
}

}  // namespace

std::string CallbackServer::required_origin = "";

CallbackServer::CallbackServer(Entd* entd)
    : busy_(false),
      entd_(entd),
      evhttp_(NULL)
{}

CallbackServer::~CallbackServer() {
  CleanupTemplate();
  Stop();
}

// static
void CallbackServer::SetTemplateBindings(
    v8::Handle<v8::ObjectTemplate> template_object) {
  template_object->Set(v8::String::NewSymbol("start"),
                       v8::FunctionTemplate::New(dispatch_Start));
  template_object->Set(v8::String::NewSymbol("stop"),
                       v8::FunctionTemplate::New(dispatch_Stop));
}

void CallbackServer::OnRequest(struct evhttp_request* request) {
  const char* uri = evhttp_request_uri(request);

  // It might be nicer (certainly more RESTful) if the function were part
  // of the URI, but that would be more parsing which might add to the
  // exploitability of this code.  Instead we only accept requests for
  // "/dispatch", and leave the parsing to v8's native JSON parser.
  if (strcmp("/dispatch", uri) != 0) {
    LOG(ERROR) << "Not found: " << uri;
    evhttp_send_error(request, kHttpNotFound, "Not found");
    return;
  }

  // All requests must be POSTs, since it's a little harder to sneak those
  // into other web pages.
  if (request->type != EVHTTP_REQ_POST) {
    LOG(ERROR) << "Invalid HTTP method";
    evhttp_send_error(request, kHttpBadMethod, "Method not allowed");
    return;
  }

  // Content type must be json.  We won't be doing any form parsing,
  // multipart or otherwise.
  const char* header = evhttp_find_header(request->input_headers,
                                          "Content-Type");
  if (!header || strcmp(kContentType.c_str(), header) != 0) {
    LOG(ERROR) << "Invalid Content-Type: " << header;
    evhttp_send_error(request, kHttpBadMedia, "Bad Content-Type");
    return;
  }

  // Check the session ID.
  header = evhttp_find_header(request->input_headers, "X-Entd-Session-Id");
  if (!header || header != session_id_) {
    LOG(ERROR) << "Bad or missing X-Entd-Session-Id header: " << header;
    evhttp_send_error(request, kHttpBadRequest,
                      "Bad or missing session id header");
    return;
  }

  if (!CallbackServer::required_origin.empty()) {
    header = evhttp_find_header(request->input_headers, "Origin");
    if (!header ||
        strcmp(CallbackServer::required_origin.c_str(), header) != 0) {
      LOG(ERROR) << "Bad or missing Origin header: " << header;
      evhttp_send_error(request, kHttpBadRequest,
                        "Bad or missing Origin header");
      return;
    }
  }

  // Check the length of the request entity.  Libevent has already read it
  // into memory, but we can at least refuse to parse it if it's too large.
  int length = EVBUFFER_LENGTH(request->input_buffer);
  if (length > kMaxRequestSize) {
    LOG(ERROR) << "Request entity too large: " << length;
    evhttp_send_error(request, kHttpBadEntitySize, "Request too large");
    return;
  }

  scoped_array<char> body(new char[length + 1]);
  if (!body.get()) {
    LOG(ERROR) << "Error allocating input buffer";
    evhttp_send_error(request, kHttpServerError, "Internal server error");
    return;
  }

  // Read the request entity into body
  evbuffer_remove(request->input_buffer, reinterpret_cast<void*>(body.get()),
                  length);
  body[length] = '\0';

  v8::HandleScope handle_scope;

  // Parse the body as JSON.
  v8::Handle<v8::Value> value;
  if (!entd_->JsonParse(v8::String::New(body.get()), &value)) {
    LOG(WARNING) << "Could not parse request entity as JSON.";
    evhttp_send_error(request, kHttpBadRequest, "Invalid JSON syntax");
    return;
  }

  // The JSON must have parsed into an Object.  Arrays and scalars are
  // rejected.
  if (!value->IsObject()) {
    LOG(WARNING) << "JSON did not represent an object.";
    evhttp_send_error(request, kHttpBadRequest, "Invalid JSON value");
    return;
  }

  v8::Handle<v8::Object> params = v8::Handle<v8::Object>::Cast(value);

  // Pull the function name out of the parsed json.  It must be a string.
  value = params->Get(v8::String::NewSymbol("function"));
  if (!value->IsString()) {
    LOG(WARNING) << "Missing or invalid function name.";
    evhttp_send_error(request, kHttpBadRequest,
                      "Missing or invalid function name");
    return;
  }

  // Append the callback prefix to the specified function name.
  v8::Local<v8::String> function_key = v8::String::Concat(
      v8::String::NewSymbol(kCallbackPrefix.c_str()), value->ToString());

  LOG(INFO) << "Dispatching: " << *v8::String::Utf8Value(function_key);

  // Check the callbacks object for a matching function.
  value = callbacks_->Get(function_key);
  if (!value->IsFunction()) {
    LOG(WARNING) << "Not found: " <<
        std::string(*v8::String::Utf8Value(function_key));
    evhttp_send_error(request, kHttpBadRequest, "Unknown function");
    return;
  }

  // Pull out the optional argument from the JSON.
  v8::Handle<v8::Function> function = v8::Handle<v8::Function>::Cast(value);
  value = params->Get(v8::String::NewSymbol("argument"));

  // Dispatch the function.
  v8::TryCatch try_catch;
  v8::Handle<v8::Value> return_value = function->Call(callbacks_, 1, &value);

  // Any exception is reported to the client only as a generic 500 server
  // error.  Policies can invent their own ways to report soft failures.
  if (try_catch.HasCaught()) {
    utils::ReportV8Exception(&try_catch);
    evhttp_send_error(request, kHttpServerError, "Internal server error");
    return;
  }

  // Stringify any result of the callback into JSON.
  if (!entd_->JsonStringify(return_value, &value)) {
    LOG(WARNING) << "Could not stringify response value.";
    evhttp_send_error(request, kHttpServerError, "Error stringifying result");
    return;
  }

  // Allocate this buffer as late as possible, since we have to make sure
  // to free it before returning.
  struct evbuffer* output = evbuffer_new();
  if (!output) {
    LOG(ERROR) << "Error allocating output buffer";
    evhttp_send_error(request, 500, "Internal server error");
    return;
  }

  // Copy the stringification to the reply and send it to the client.
  std::string result = *v8::String::Utf8Value(value);
  evbuffer_add(output, result.c_str(), result.length());
  evhttp_send_reply(request, kHttpOk, "OK", output);

  evbuffer_free(output);
}

bool CallbackServer::Start(v8::Handle<v8::Object> callbacks, int port) {
  if (evhttp_)
    Stop();

  LOG(INFO) << "Starting callback server on port " << port;

  evhttp_ = evhttp_new(NULL);
  if (!evhttp_) {
    LOG(ERROR) << "Error creating callback server.";
    return false;
  }

  evhttp_set_gencb(evhttp_, dispatch_OnRequest, reinterpret_cast<void*>(this));

  int rv = evhttp_bind_socket(evhttp_, "127.0.0.1", port);
  if (rv == -1) {
    LOG(ERROR) << "Error binding to port.";
    Stop();
    return false;
  }

  callbacks_ = v8::Persistent<v8::Object>::New(callbacks);
  port_ = port;

  return true;
}

void CallbackServer::Stop() {
  if (!evhttp_)
    return;

  LOG(INFO) << "Stopping callback server.";

  evhttp_free(evhttp_);
  evhttp_ = NULL;
  port_ = 0;
  callbacks_.Dispose();
}

bool CallbackServer::IsRunning() {
  return evhttp_ != NULL;
}

}  // namespace entd
