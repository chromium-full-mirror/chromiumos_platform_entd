// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "entd/entd.h"

#include <event.h>
#include <iostream>
#include <stdio.h>
#include <v8.h>
#include "entd/utils.h"
#include "entd/http.h"
#include "entd/syslog.h"

namespace entd {

using std::string;
using namespace v8;

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

  virtual bool Initialize(Entd* entd, Handle<Value> v8_value,
                          uint32_t interval) {
    entd_ = entd;
    v8_value_ = Persistent<Value>::New(v8_value);

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

  virtual Local<Value> GetValue() const {
    return Local<Value>::New(v8_value_);
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
  Persistent<Value> v8_value_;
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

// Called by libevent when a timeout fires.
void dispatch_OnTimeout(int fd, short flags, void* arg) {
  Timeout* timeout = reinterpret_cast<Timeout*>(arg);
  // LOG(INFO) << "Fire timeout: " << timeout->GetHandle();
  timeout->GetEntd()->OnTimeout(*timeout);
  delete timeout;
}

// Called by v8 for entd.setTimeout().
Handle<Value> dispatch_SetTimeout(const Arguments& args) {
  Entd* entd = Entd::Unwrap(args.This());
  if (!entd)
    return Undefined();

  if (args.Length() < 2) {
    ThrowException(String::New("Not enough parameters"));
    return Undefined();
  }

  if (!(args[0]->IsString() || args[0]->IsFunction())) {
    ThrowException(String::New("First argument must be string or function"));
    return Undefined();
  }

  return Uint32::New(entd->SetTimeout(args[0], args[1]->Uint32Value()));
}

// Called by v8 for entd.clearTimeout().
Handle<Value> dispatch_ClearTimeout(const Arguments& args) {
  Entd* entd = Entd::Unwrap(args.This());
  if (!entd)
    return Undefined();

  if (args.Length() < 1) {
    ThrowException(String::New("Not enough parameters"));
    return Undefined();
  }

  Timeout* timeout = entd->ClearTimeout(args[0]->Uint32Value());
  if (!timeout)
    return False();

  delete timeout;
  return True();
}

// Called by v8 for the global object's print() method.
Handle<Value> dispatch_Print(const Arguments& args) {
  for (int i = 0; i < args.Length(); ++i) {
    Handle<Value> arg = args[i];
    String::Utf8Value value(arg);
    std::cout << *value;
  }

  std::cout.flush();
  return Undefined();
}

// Called by v8 for the global object's print() method.
Handle<Value> dispatch_PrintLn(const Arguments& args) {
  for (int i = 0; i < args.Length(); ++i) {
    Handle<Value> arg = args[i];
    String::Utf8Value value(arg);
    std::cout << *value;
  }
  std::cout << "\n";
  std::cout.flush();
  return Undefined();
}

Entd::Entd()
    : jshttp_(NULL),  // allocate after we are constructed
      jssyslog_(new Syslog()) {
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

// Bind "setTimeout" and "clearTimeout" to the entd template object
void Entd::SetTemplateBindings(Handle<ObjectTemplate> template_object) {
  template_object->Set(String::New("setTimeout"),
                       FunctionTemplate::New(dispatch_SetTimeout), ReadOnly);
  template_object->Set(String::New("clearTimeout"),
                       FunctionTemplate::New(dispatch_ClearTimeout), ReadOnly);
}

bool Entd::Initialize() {
  if (!context_.IsEmpty()) {
    LOG(ERROR) << "Entd initialized twice.";
    return false;
  }

  event_init();
  LOG(INFO) << "Initialized libevent " << event_get_version();

  HandleScope handle_scope;

  Handle<ObjectTemplate> global_template = ObjectTemplate::New();
  global_template->Set(String::NewSymbol("print"),
                       FunctionTemplate::New(dispatch_Print), ReadOnly);
  global_template->Set(String::NewSymbol("println"),
                       FunctionTemplate::New(dispatch_PrintLn), ReadOnly);
  context_ = Context::New(NULL, global_template);

  // Switch to our context and instantiate the entd object.
  Context::Scope context_scope(context_);
  Handle<Object> global = context_->Global();

  // Build the entd object
  JSObjectWrapper<Entd>::Initialize();
  Handle<Object> entd_object = obj();

  // Build the http object
  jshttp_.reset(new Http(this, NULL));
  jshttp_->Initialize();
  entd_object->Set(String::New("http"), jshttp_->obj(), ReadOnly);

  // Build the syslog object
  jssyslog_->Initialize();
  entd_object->Set(String::New("syslog"), jssyslog_->obj(), ReadOnly);

  // Bind entd to the global object
  global->Set(String::New("entd"), entd_object, ReadOnly);

  return true;
}

bool Entd::Run() {
  HandleScope handle_scope;

  // Make sure we're running on our context
  Context::Scope context_scope(context_);

  Handle<Value> value;

  if (!utility_filename_.empty()) {
    LOG(INFO) << "Executing utility file: " << utility_filename_;
    if (!ExecuteFile(utility_filename_, &value)) {
      LOG(ERROR) << "Error in utility file.";
      return false;
    }
  }

  Handle<Value> manifest;

  if (manifest_filename_.empty()) {
    LOG(WARNING) << "No manifest file.";
    manifest = Null();
  } else {
    if (!LoadJson(manifest_filename_, &manifest)) {
      LOG(ERROR) << "Error loading manifest file: " << manifest_filename_;
      return false;
    }
  }

  if (policy_filename_.empty()) {
    LOG(ERROR) << "No policy file.";
    return false;
  }

  if (!ExecuteFile(policy_filename_, &value)) {
    LOG(ERROR) << "Error in policy file.";
    return false;
  }

  LOG(INFO) << "Policy loaded.";

  value = context_->Global()->Get(String::NewSymbol("entd"));
  if (value.IsEmpty() || !value->IsObject()) {
    LOG(ERROR) << "Global entd missing or not an object";
    return false;
  }

  TryCatch try_catch;
  Handle<Object> entd = Handle<Object>::Cast(value);
  entd->Set(String::NewSymbol("username"), String::New(username_.c_str()));
  value = utils::CallV8Function(entd, "onLoad", 1, &manifest);
  if (try_catch.HasCaught()) {
    // Failed due to V8 exception
    utils::ReportV8Exception(&try_catch);
    return false;
  } else if (value.IsEmpty()) {
    // Failed for other reasons
    return false;
  }

  event_dispatch();

  return true;
}

void Entd::Stop() {
  event_loopbreak();
}

uint32_t Entd::SetTimeout(Handle<Value> value, uint32_t interval) {
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

void Entd::OnTimeout(const Timeout& timeout) {
  Context::Scope context_scope(context_);
  HandleScope handle_scope;

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

  Local<Value> value = timeout.GetValue();
  if (value->IsString()) {
    Handle<String> script = Handle<String>::Cast(value);
    Handle<Value> result;
    char filename[20];
    snprintf(&filename[0], sizeof(filename), "(timeout %u)", timeout_handle);
    ExecuteString(script, filename, &result);

  } else if (value->IsFunction()) {
    Handle<Function> func = Handle<Function>::Cast(value);
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

bool Entd::LoadJson(const string& filename, Handle<Value>* result) {
  if (!result) {
    LOG(ERROR) << "Null pointer passed for result";
    return false;
  }

  Handle<String> source = utils::ReadFile(filename);
  if (source.IsEmpty()) {
    LOG(ERROR) << "Error reading json file: " << filename;
    return false;
  }

  Handle<Value> value = context_->Global()->Get(String::NewSymbol("JSON"));
  if (value.IsEmpty() || !value->IsObject()) {
    LOG(ERROR) << "Global JSON property missing or not an object.";
    return false;
  }

  Handle<Object> json = Handle<Object>::Cast(value);
  value = source;

  TryCatch try_catch;
  Handle<Value> parse_result = utils::CallV8Function(json, "parse", 1, &value);
  if (try_catch.HasCaught()) {
    // Failed due to V8 exception
    utils::ReportV8Exception(&try_catch);
    return false;
  } else if (parse_result.IsEmpty()) {
    // Failed for other reasons
    return false;
  }
  *result = parse_result;

  return true;
}

bool Entd::ExecuteFile(const std::string& filename,
                       Handle<Value>* result) {
  HandleScope handle_scope;
  Handle<String> source = utils::ReadFile(filename);
  if (!source.IsEmpty()) {
    return ExecuteString(source, filename, result);
  } else {
    LOG(WARNING) << "Error reading source file: " << filename;
    return false;
  }
}

bool Entd::ExecuteString(const Handle<String>& source,
                         const std::string& filename,
                         Handle<Value>* result) {
  HandleScope handle_scope;
  TryCatch try_catch;

  Handle<Script> script =
      Script::Compile(source, String::New(filename.c_str()));

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
