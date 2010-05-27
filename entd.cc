// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "entd/entd.h"

#include <stdio.h>

#include <iostream>

#include <base/file_util.h>
#include <event.h>
#include <glib-object.h>
#include <v8.h>

#include "entd/callback_server.h"
#include "entd/flimflam.h"
#include "entd/http.h"
#include "entd/pkcs11.h"
#include "entd/syslog.h"
#include "entd/utils.h"

namespace entd {

using std::string;

void dispatch_OnTimeout(int fd, short flags, void* arg);

// Class to represent a pending timeout event.
class Timeout {
 public:
  Timeout()
      : entd_(NULL), event_(NULL) {
  }

  virtual ~Timeout() {
    v8_value_.Dispose();
    delete event_;
  }

  virtual bool Initialize(Entd* entd, v8::Handle<v8::Value> v8_value,
                          uint32_t interval) {
    entd_ = entd;
    v8_value_ = v8::Persistent<v8::Value>::New(v8_value);

    // Least significant half (on 32bit x86 :P) of the address of the timeout
    // data, shifted left 16 bytes and or'd with the timeout sequence
    // should give us unique timeout handles that are difficult to guess.
    handle_ = (((0xFFFF & reinterpret_cast<size_t>(this)) << 16) |
               ++Timeout::sequence);

    struct timeval tv = { 0, interval * 1000 };
    event_ = new struct event;
    event_set(event_, 0, 0, &dispatch_OnTimeout, this);
    event_add(event_, &tv);

    return true;
  }

  virtual uint32_t GetHandle() const {
    return handle_;
  }

  virtual v8::Local<v8::Value> GetValue() const {
    return v8::Local<v8::Value>::New(v8_value_);
  }

  virtual Entd* GetEntd() const {
    return entd_;
  }

  virtual void CancelEvent() {
    event_del(event_);
  }

 private:
  // Count of timeouts created so far, used to ensure globally unique handles.
  static uint32_t sequence;

  // Pointer to the daemon instance.
  Entd* entd_;
  // Integer handle used to identify this timeout to JavaScript.
  uint32_t handle_;
  // JS value to execute when the timeout fires.
  v8::Persistent<v8::Value> v8_value_;
  // libevent structure for this timeout event.
  struct event* event_;

  DISALLOW_COPY_AND_ASSIGN(Timeout);
};

uint32_t Timeout::sequence = 0;

// Class to handle calling native timeouts. Implemented using libevent.
class NativeTimeout
{
 public:
  NativeTimeout(Entd::NativeTimeoutCallback cb, void* data,
                uint32_t interval_ms)
      : callback_(cb), data_(data),
        interval_(interval_ms * 1000),
        handle_(0), event_(NULL) {
  }

  ~NativeTimeout() {
    event_del(event_);
    delete event_;
  }

  void Initialize() {
    handle_ = s_handle_counter_++;
    event_ = new struct event;
    event_set(event_, 0, 0, &EventCallback, this);
    Start();
  }

  // Calling Start on a running timeout will simply reset the timer
  void Start() {
    struct timeval tv = { 0, interval_ };
    event_add(event_, &tv);
  }

  uint32_t GetHandle() { return handle_; }

 private:
  // Calls the set callback. If the callback returns 'true', start it again.
  static void EventCallback(int fd, short flags, void* arg) {
    NativeTimeout* timeout = reinterpret_cast<NativeTimeout*>(arg);
    bool res = timeout->callback_(timeout->data_);
    if (res) {
      timeout->Start();
    }
  }

  // Callback data
  Entd::NativeTimeoutCallback callback_;
  void* data_;

  uint32_t interval_;

  // Handle identifier (simple integer incrementing from 1)
  uint32_t handle_;

  // libevent data
  struct event* event_;

  // Global handle counter
  static uint32_t s_handle_counter_;

  DISALLOW_COPY_AND_ASSIGN(NativeTimeout);
};

uint32_t NativeTimeout::s_handle_counter_ = 1;

// Called by libevent when a signal is detected.
void dispatch_OnSignal(int fd, short flags, void* arg) {
  Entd* entd = reinterpret_cast<Entd*>(arg);
  entd->OnSignal(fd);
}

// Called by libevent when a timeout fires.
void dispatch_OnTimeout(int fd, short flags, void* arg) {
  Timeout* timeout = reinterpret_cast<Timeout*>(arg);
  // LOG(INFO) << "Fire timeout: " << timeout->GetHandle();
  timeout->GetEntd()->OnTimeout(*timeout);
  delete timeout;
}

// Called by v8 for entd.setTimeout().
v8::Handle<v8::Value> dispatch_SetTimeout(const v8::Arguments& args) {
  Entd* entd = Entd::Unwrap(args.This());
  if (!entd)
    return v8::Undefined();

  if (args.Length() < 2) {
    ThrowException(v8::String::New("Not enough parameters"));
    return v8::Undefined();
  }

  if (!(args[0]->IsString() || args[0]->IsFunction())) {
    ThrowException(v8::String::New(
        "First argument must be string or function"));
    return v8::Undefined();
  }

  return v8::Uint32::New(entd->SetTimeout(args[0], args[1]->Uint32Value()));
}

// Called by v8 for entd.clearTimeout().
v8::Handle<v8::Value> dispatch_ClearTimeout(const v8::Arguments& args) {
  Entd* entd = Entd::Unwrap(args.This());
  if (!entd)
    return v8::Undefined();

  if (args.Length() < 1) {
    ThrowException(v8::String::New("Not enough parameters"));
    return v8::Undefined();
  }

  Timeout* timeout = entd->ClearTimeout(args[0]->Uint32Value());
  if (!timeout)
    return v8::False();

  delete timeout;
  return v8::True();
}

// Called by v8 for entd.scheduleShutdown().
v8::Handle<v8::Value> dispatch_ScheduleShutdown(const v8::Arguments& args) {
  Entd* entd = Entd::Unwrap(args.This());
  if (!entd)
    return v8::Undefined();

  uint32_t code = 0;
  if (args.Length() > 0)
    code = args[0]->Uint32Value();

  uint32_t interval = 0;
  if (args.Length() > 1)
    interval = args[1]->Uint32Value();

  entd->ScheduleShutdown(code, interval);

  return v8::True();
}

// Called by v8 when someone trys to read from entd.hostname
v8::Handle<v8::Value> dispatch_GetHostname(v8::Local<v8::String> name,
                                           const v8::AccessorInfo& info) {
  Entd* entd = Entd::Unwrap(info.Holder());
  return v8::String::New(entd->GetHostname().c_str());
}

// Called by v8 when someone trys to assign to entd.hostname
void dispatch_SetHostname(v8::Local<v8::String> name,
                          v8::Local<v8::Value> value,
                          const v8::AccessorInfo& info) {
  Entd* entd = Entd::Unwrap(info.Holder());
  if (!entd->SetHostname(*v8::String::Utf8Value(value)))
    utils::ThrowV8Exception("Invalid hostname");
}

// Called by v8 for the global object's print() method.
v8::Handle<v8::Value> dispatch_Print(const v8::Arguments& args) {
  for (int i = 0; i < args.Length(); ++i) {
    v8::Handle<v8::Value> arg = args[i];
    v8::String::Utf8Value value(arg);
    std::cout << *value;
  }

  std::cout.flush();
  return v8::Undefined();
}

// Called by v8 for the global object's print() method.
v8::Handle<v8::Value> dispatch_PrintLn(const v8::Arguments& args) {
  for (int i = 0; i < args.Length(); ++i) {
    v8::Handle<v8::Value> arg = args[i];
    v8::String::Utf8Value value(arg);
    std::cout << *value;
  }
  std::cout << "\n";
  std::cout.flush();
  return v8::Undefined();
}

// Called by v8 for the global object's writeToFile() method.
v8::Handle<v8::Value> dispatch_WriteToFile(const v8::Arguments& args) {
  if (args.Length() != 2) {
    utils::ThrowV8Exception("Usage: writeToFile(string, filepath)");
    return v8::False();
  }
  std::string s = utils::ValueAsUtf8String(args[0]);
  std::string file = utils::ValueAsUtf8String(args[1]);
  int slen = s.length();
  int res = -1;
  if (slen > 0) {
    res = file_util::WriteFile(FilePath(file), s.c_str(), slen);
  }
  if (res < 0 || res != slen) {
    utils::ThrowV8Exception(std::string("Unable to write file: ") + file);
    return v8::False();
  }
  return v8::True();
}

Entd::Entd()
    : callback_server_(NULL),
      flimflam_(new Flimflam()),
      syslog_(new Syslog()) {
  ::g_type_init();
}

Entd::~Entd() {
  // Clean up any pending timeouts.
  for (unsigned int i = 0; i < timeout_list_.size(); ++i) {
    Timeout* timeout = timeout_list_[i];
    timeout->CancelEvent();
    delete timeout;
  }
  CleanupTemplate();
  context_.Dispose();
}

bool Entd::allow_dirty_exit = false;

// Bind "setTimeout" and "clearTimeout" to the entd template object.
void Entd::SetTemplateBindings(v8::Handle<v8::ObjectTemplate> template_object) {
  template_object->Set(v8::String::NewSymbol("setTimeout"),
                       v8::FunctionTemplate::New(dispatch_SetTimeout),
                       v8::ReadOnly);
  template_object->Set(v8::String::NewSymbol("clearTimeout"),
                       v8::FunctionTemplate::New(dispatch_ClearTimeout),
                       v8::ReadOnly);
  template_object->Set(v8::String::NewSymbol("scheduleShutdown"),
                       v8::FunctionTemplate::New(dispatch_ScheduleShutdown),
                       v8::ReadOnly);

  template_object->SetAccessor(v8::String::NewSymbol("hostname"),
                               dispatch_GetHostname,
                               dispatch_SetHostname);
}

bool Entd::Initialize() {
  if (!context_.IsEmpty()) {
    LOG(ERROR) << "Entd initialized twice.";
    return false;
  }

  event_init();
  LOG(INFO) << "Initialized libevent " << event_get_version();

  return true;
}

v8::Handle<v8::Object> Entd::ConstructEntd() {
  v8::HandleScope handle_scope;

  // Build the entd object.
  JSObjectWrapper<Entd>::Initialize();
  v8::Handle<v8::Object> entd = obj();

  // Build the flimflam object.
  flimflam_->Initialize();
  entd->Set(v8::String::NewSymbol("flimflam"),
            flimflam_->obj(), v8::ReadOnly);

  // Build the http object.
  http_.reset(new Http(this, NULL));
  http_->Initialize();
  entd->Set(v8::String::NewSymbol("http"),
            http_->obj(), v8::ReadOnly);

  // Build the syslog object.
  syslog_->Initialize();
  entd->Set(v8::String::NewSymbol("syslog"),
            syslog_->obj(), v8::ReadOnly);

  // Build the callbackServer object.
  callback_server_.reset(new CallbackServer(this));
  callback_server_->Initialize();
  entd->Set(v8::String::NewSymbol("callbackServer"),
            callback_server_->obj(), v8::ReadOnly);

  // Build the pkcs11 object
  pkcs11_.reset(new Pkcs11(NULL, NULL));
  if (pkcs11_mode_ == "opencryptoki") {
    pkcs11_->InitializeOpenCryptoki(certificate_filename_,
                                    pkcs11_config_filename_);
  } else if (pkcs11_mode_ == "glaptop") {
    pkcs11_->InitializeGLaptop(certificate_filename_);
  } else if (pkcs11_mode_ == "openssl") {
    pkcs11_->InitializeOpenSSL(certificate_filename_);
  } else if (!pkcs11_mode_.empty()) {
    LOG(ERROR) << "Unrecognized pkcs11 mode: " << pkcs11_mode_;
    exit(1);
  } else {
    pkcs11_->InitializeLocalFiles(csr_filename_, certificate_filename_);
  }
  entd->Set(v8::String::New("pkcs11"),
            pkcs11_->obj(), v8::ReadOnly);

  return handle_scope.Close(entd);
}

bool Entd::StartScriptingEnvironment() {
  v8::HandleScope handle_scope;

  // Create the global object.
  v8::Handle<v8::ObjectTemplate> global_template = v8::ObjectTemplate::New();
  global_template->Set(v8::String::NewSymbol("print"),
                       v8::FunctionTemplate::New(dispatch_Print),
                       v8::ReadOnly);
  global_template->Set(v8::String::NewSymbol("println"),
                       v8::FunctionTemplate::New(dispatch_PrintLn),
                       v8::ReadOnly);
  global_template->Set(v8::String::NewSymbol("writeToFile"),
                       v8::FunctionTemplate::New(dispatch_WriteToFile),
                       v8::ReadOnly);
  context_ = v8::Context::New(NULL, global_template);

  v8::Context::Scope context_scope(context_);

  v8::Handle<v8::Object> global = context_->Global();

  // Construct the global entd object.
  v8::Handle<v8::Object> entd = ConstructEntd();

  // Set the "entd" property of the global object.
  global->Set(v8::String::NewSymbol("entd"), entd, v8::ReadOnly);

  // Temporary storage for the generic values used below.
  v8::Handle<v8::Value> value;

  // Set entd.username and entd.hostname.
  entd->Set(v8::String::NewSymbol("username"),
            v8::String::New(username_.c_str()), v8::ReadOnly);

  size_t at_pos = username_.find("@");
  if (at_pos == std::string::npos || at_pos == username_.length() - 1) {
    LOG(ERROR) << "Can't determine hostname from username: " << username_;
    return false;
  }

  if (!SetHostname(username_.substr(at_pos + 1))) {
    LOG(ERROR) << "Unable to set host name.";
    return false;
  }

  // Load manifest file, if one was provided.
  v8::Handle<v8::Object> manifest;

  if (manifest_filename_.empty()) {
    LOG(WARNING) << "No manifest file.";
  } else {
    if (!JsonParseFromFile(manifest_filename_, &value) || !value->IsObject()) {
      LOG(ERROR) << "Error loading manifest file: " << manifest_filename_;
      return false;
    }

    manifest = v8::Handle<v8::Object>::Cast(value);
  }

  // Load utility file, if one was provided.
  if (!utility_filename_.empty()) {
    LOG(INFO) << "Executing utility file: " << utility_filename_;
    if (!ExecuteFile(utility_filename_, &value)) {
      LOG(ERROR) << "Error in utility file.";
      return false;
    }

    if (entd->Has(v8::String::NewSymbol("verifyManifest"))) {
      v8::TryCatch try_catch;

      v8::Handle<v8::Value> arg;
      if (manifest.IsEmpty()) {
        arg = v8::Null();
      } else {
        arg = manifest;
      }

      value = utils::CallV8Function(entd, "verifyManifest", 1, &arg);
      if (try_catch.HasCaught()) {
        // Failed due to V8 exception
        utils::ReportV8Exception(&try_catch);
        return false;
      } else if (value.IsEmpty()) {
        // Failed for other reasons
        return false;
      }

      if (!value->IsBoolean() || value->BooleanValue() != true) {
        LOG(ERROR) << "Utility file vetoed the extension manifest.";
        return false;
      }
    }
  }

  // Load the policy file.
  if (policy_filename_.empty()) {
    LOG(ERROR) << "No policy file.";
    return false;
  }

  if (!ExecuteFile(policy_filename_, &value)) {
    LOG(ERROR) << "Error in policy file.";
    return false;
  }

  LOG(INFO) << "Policy loaded.";

  // Fire the onLoad event.
  if (entd->Has(v8::String::NewSymbol("onLoad"))) {
    v8::TryCatch try_catch;

    v8::Handle<v8::Value> arg;
    if (manifest.IsEmpty()) {
      arg = v8::Null();
    } else {
      arg = manifest;
    }

    value = utils::CallV8Function(entd, "onLoad", 1, &arg);
    if (try_catch.HasCaught()) {
      // Failed due to V8 exception
      utils::ReportV8Exception(&try_catch);
      return false;
    } else if (value.IsEmpty()) {
      // Failed for other reasons
      return false;
    }
  }

  return true;
}

bool Entd::StopScriptingEnvironment() {
  // Temporary storage for the a generic value used in this function.
  v8::Handle<v8::Value> value;

  value = context_->Global()->Get(v8::String::NewSymbol("entd"));
  if (value.IsEmpty() || !value->IsObject()) {
    LOG(ERROR) << "Global entd missing or not an object";
    return false;
  }

  v8::Handle<v8::Object> entd = v8::Handle<v8::Object>::Cast(value);

  if (entd->Has(v8::String::NewSymbol("onUnload"))) {
    v8::TryCatch try_catch;

    value = utils::CallV8Function(entd, "onUnload", 0, NULL);
    if (try_catch.HasCaught()) {
      // Failed due to V8 exception
      utils::ReportV8Exception(&try_catch);
      return false;
    } else if (value.IsEmpty()) {
      // Failed for other reasons
      return false;
    }
  }

  return true;
}

// See comments in main.cc about the return values.
uint32_t Entd::Run() {
  exit_code_ = 0;

  if (!StartScriptingEnvironment())
    return 1;

  struct event ev_SIGHUP;
  struct event ev_SIGINT;
  struct event ev_SIGTERM;

  if (!Entd::allow_dirty_exit) {
    event_set(&ev_SIGHUP, SIGHUP, EV_SIGNAL | EV_PERSIST, &dispatch_OnSignal,
              reinterpret_cast<void*>(this));
    event_add(&ev_SIGHUP, NULL);
    event_set(&ev_SIGINT, SIGINT, EV_SIGNAL | EV_PERSIST, &dispatch_OnSignal,
              reinterpret_cast<void*>(this));
    event_add(&ev_SIGINT, NULL);
    event_set(&ev_SIGTERM, SIGTERM, EV_SIGNAL | EV_PERSIST, &dispatch_OnSignal,
              reinterpret_cast<void*>(this));
    event_add(&ev_SIGTERM, NULL);
  }

  // Set up the handle and context scope for JavaScript run from event handlers,
  // or from StopScriptingEnvironment().
  v8::HandleScope handle_scope;
  v8::Context::Scope context_scope(context_);

  event_loop(0);

  if (!Entd::allow_dirty_exit) {
    event_del(&ev_SIGHUP);
    event_del(&ev_SIGINT);
    event_del(&ev_SIGTERM);
  }

  if (!StopScriptingEnvironment()) {
    if (exit_code_ == 2) {
      // The policy was asking for a restart.  We failed to shut down for some
      // reason, but would still like to honor the restart.
      return 3;
    }

    if (exit_code_ < 2) {
      // We weren't going to restart anyway.
      return 1;
    }
  }

  return exit_code_;
}

void Entd::OnSignal(int signal) {
  LOG(INFO) << "Responding to signal: " << signal;
  event_loopbreak();
}

uint32_t Entd::SetTimeout(v8::Handle<v8::Value> value, uint32_t interval) {
  Timeout* timeout = new Timeout();
  if (!timeout->Initialize(this, value, interval))
    return 0;

  timeout_list_.push_back(timeout);
  return timeout->GetHandle();
}

Timeout* Entd::ClearTimeout(uint32_t timeout_handle) {
  for (unsigned int i = 0; i < timeout_list_.size(); ++i) {
    Timeout* timeout = timeout_list_[i];
    if (timeout->GetHandle() == timeout_handle) {
      // LOG(INFO) << "Remove timeout handle: " << timeout_handle;
      timeout->CancelEvent();
      timeout_list_.erase(timeout_list_.begin() + i);
      return timeout;
    }
  }

  return NULL;
}

void Entd::ScheduleShutdown(uint32_t code, uint32_t interval) {
  exit_code_ = code;
  struct timeval tv = { 0, interval * 1000 };
  event_loopexit(&tv);
}

void Entd::OnTimeout(const Timeout& timeout) {
  v8::Context::Scope context_scope(context_);
  v8::HandleScope handle_scope;

  uint32_t timeout_handle = timeout.GetHandle();
  // LOG(INFO) << "OnTimeout: " << timeout_handle;

  // Remove this from our active timeouts list first, so any attempt to
  // call clearTimeout from script doesn't cause trouble.  If we can't clear
  // the timeout for some reason then something strange is going on.  A
  // timeout should only get removed from the list of timeouts by firing
  // (this case) or through a ClearTimeout, which should prevent it from
  // firing.
  if (!ClearTimeout(timeout_handle))
    LOG(ERROR) << "Failed to clear the current timeout, something is fishy.";

  v8::Local<v8::Value> value = timeout.GetValue();
  if (value->IsString()) {
    v8::Handle<v8::String> script = v8::Handle<v8::String>::Cast(value);
    v8::Handle<v8::Value> result;
    char filename[20];
    snprintf(&filename[0], sizeof(filename), "(timeout %u)", timeout_handle);
    ExecuteString(script, filename, &result);

  } else if (value->IsFunction()) {
    v8::Handle<v8::Function> func = v8::Handle<v8::Function>::Cast(value);
    func->Call(context_->Global(), 0, NULL);
  }
}

// Initialize and start a timeout
uint32_t Entd::SetNativeTimeout(NativeTimeoutCallback cb, void* data,
                                uint32_t interval_ms) {
  NativeTimeout* timeout = new NativeTimeout(cb, data, interval_ms);
  uint32_t handle = timeout->GetHandle();
  native_timeouts_[handle] = timeout;
  timeout->Initialize();
  return handle;
}

// Start an existing timeout (resets timer if already started)
// Returns false if timeout doesn't exist
bool Entd::StartNativeTimeout(uint32_t handle) {
  std::map<uint32_t, NativeTimeout*>::iterator iter =
      native_timeouts_.find(handle);
  if (iter != native_timeouts_.end()) {
    iter->second->Start();
    return true;
  }
  return false;
}

// Cancel and delete an existing timeout
// Returns false if timeout doesn't exist
bool Entd::ClearNativeTimeout(uint32_t handle) {
  std::map<uint32_t, NativeTimeout*>::iterator iter =
      native_timeouts_.find(handle);
  if (iter != native_timeouts_.end()) {
    delete iter->second;
    native_timeouts_.erase(iter);
    return true;
  }
  return false;
}

bool Entd::CheckHostname(const string& new_hostname) {
  if (hostname_.empty())
    return utils::CheckHostnameCharset(new_hostname);

  size_t new_len = new_hostname.length();
  size_t current_len = hostname_.length();

  if (new_len < current_len) {
    // New hostname is shorter than the existing hostname, can't possibly
    // be right.
    return false;
  }

  size_t starts_at = new_len - current_len;

  if (new_hostname.compare(starts_at, current_len, hostname_) != 0) {
    // New host doesn't match existing one.
    return false;
  }

  if (starts_at == 0) {
    // New host and old host are exactly the same.
    return true;
  }

  // Otherwise, the new hostname must more specific than the existing one.

  if (starts_at < 2) {
    // It takes at least two characters to be more specific (eg: add "a." to
    // the existing hostname.)
    return false;
  }

  if (new_hostname[starts_at - 1] != '.')
    return false;

  return utils::CheckHostnameCharset(new_hostname);
}

bool Entd::JsonParseFromFile(const string& filename,
                             v8::Handle<v8::Value>* result) {
  if (!result) {
    LOG(ERROR) << "Null pointer passed for result";
    return false;
  }

  v8::Handle<v8::String> source = utils::ReadFile(filename);
  if (source.IsEmpty()) {
    LOG(ERROR) << "Error reading json file: " << filename;
    return false;
  }

  return JsonParse(source, result);
}

bool Entd::JsonParse(v8::Handle<v8::String> source,
                     v8::Handle<v8::Value>* result) {
  return CallJson("parse", source, result);
}

bool Entd::JsonStringify(v8::Handle<v8::Value> source,
                         v8::Handle<v8::Value>* result) {
  return CallJson("stringify", source, result);
}

bool Entd::CallJson(string method_name, v8::Handle<v8::Value> arg,
                    v8::Handle<v8::Value>* result) {
  if (!result) {
    LOG(ERROR) << "Null pointer passed for result";
    return false;
  }

  v8::Handle<v8::Value> value =
      context_->Global()->Get(v8::String::NewSymbol("JSON"));
  if (value.IsEmpty() || !value->IsObject()) {
    LOG(ERROR) << "Global JSON property missing or not an object.";
    return false;
  }

  v8::Handle<v8::Object> json = v8::Handle<v8::Object>::Cast(value);

  value = json->Get(v8::String::NewSymbol(method_name.c_str()));
  if (value.IsEmpty() || !value->IsFunction()) {
    LOG(ERROR) << "JSON method missing or not a function: " << method_name;
    return false;
  }

  v8::Handle<v8::Function> fun = v8::Handle<v8::Function>::Cast(value);

  v8::TryCatch try_catch;
  v8::Handle<v8::Value> call_result =
      utils::CallV8Function(json, method_name, 1, &arg);
  if (try_catch.HasCaught()) {
    // Failed due to V8 exception
    utils::ReportV8Exception(&try_catch);
    return false;
  } else if (call_result.IsEmpty()) {
    // Failed for other reasons
    return false;
  }

  *result = call_result;

  return true;
}

bool Entd::ExecuteFile(const std::string& filename,
                       v8::Handle<v8::Value>* result) {
  v8::HandleScope handle_scope;
  v8::Handle<v8::String> source = utils::ReadFile(filename);
  if (!source.IsEmpty()) {
    return ExecuteString(source, filename, result);
  } else {
    LOG(WARNING) << "Error reading source file: " << filename;
    return false;
  }
}

bool Entd::ExecuteString(const v8::Handle<v8::String>& source,
                         const std::string& filename,
                         v8::Handle<v8::Value>* result) {
  v8::HandleScope handle_scope;
  v8::TryCatch try_catch;

  v8::Handle<v8::Script> script =
      v8::Script::Compile(source, v8::String::New(filename.c_str()));

  if (script.IsEmpty()) {
    utils::ReportV8Exception(&try_catch);
    return false;
  }

  *result = script->Run();
  if (!result || result->IsEmpty()) {
    utils::ReportV8Exception(&try_catch);
    return false;
  }

  return true;
}

}  // namespace entd
