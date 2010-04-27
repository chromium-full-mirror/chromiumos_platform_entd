// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.


// Integrate HTTP GET / POST with V8.
// Current implementations include: libcurl

// Example js usage:

//   var desc = "google cert";
//   var url = "https://ra.corp.google.com/";

//   var httpRequest = new entd.http.Request(url);

//   httpRequest.params.push("username", entd.username);
//   httpRequest.params.push("desc", desc);
//   httpRequest.onComplete = function(r) { onRequestComplete(desc, r) };
//   httpRequest.onTimeout =
//     function() { onHTTPTimeout("cert-request: " + desc) };
//   httpRequest.onError =
//     function(reason) { onHTTPError(reason, "cert-request: " + desc) };

//   entd.http.GET(httpRequest);


#include "entd/jshttp.h"

#include <iostream>
#include <list>
#include <string>
#include <vector>

#include <base/basictypes.h>
#include <base/logging.h>
#include <curl/curl.h>

#include <entd/entd.h>

namespace entd {

using namespace v8;

//==============================================================================
// Helper functions

// Extract the C++ object pointer from the V8 object internal field 0
template<typename T> T* Unwrap(Handle<Object> obj) {
  if (obj.IsEmpty() || !obj->IsObject())// Make sure the argument is valid
    return NULL;
  if (!T::GetTemplate()->HasInstance(obj)) // Make sure it's of the right type
    return NULL;
  if (obj->InternalFieldCount() < 1)    // Paranoia; Should always be true
    return NULL;
  T* result = reinterpret_cast<T*>(obj->GetPointerFromInternalField(0));
  return result;
}

//==============================================================================
// Class JSHttpRequest

class JSHttpRequest
{
 public:
  JSHttpRequest();
  ~JSHttpRequest();
  void Initialize();

  // Initialize the http object template
  static Handle<FunctionTemplate> GetTemplate();
  // Construct a JSHttpRequest and associated v8 Object
  static Handle<Value> MakeHttpRequest(const Arguments& args);
  // Extract the JSHttpRequest* from v8
  static JSHttpRequest* GetRequestFromArgs(const Arguments& args);

  // Accessors
  Handle<Object> GetObject() { return obj_; }
  std::string GetString(const std::string& desc);
  utils::StringList GetStringList(const std::string& desc);

  // Interface for HTTP (JSHttpMessengerInterface class)
  void SetUrl(const std::string& url) { url_ = url; }
  std::string GetUrl() { return url_; }
  void AppendBuffer(const char* data, size_t bytes);
  void AppendHeader(const std::string& header);
  void CallComplete(int http_code);
  void CallTimeout();
  void CallError(const std::string& errdesc);

 private:
  // Call the V8 method associated with the property 'cbname' 
  //  argc and arcv specify arguments to the V8 function.
  bool CallV8Function(const std::string& cbname,
                      int argc, Handle<Value> argv[]);

  // One V8 template object for all JSHttpRequests.
  static Persistent<FunctionTemplate> s_request_template_;

  // Member Variables
  Persistent<Object> obj_; // js object
  std::string url_; // actual url the request was sent to, including params
  std::vector<char> buffer_; // input buffer to hold request results
  utils::StringList headers_;

  DISALLOW_COPY_AND_ASSIGN(JSHttpRequest);
};

// === JSHttpRequest Globals ===

Persistent<FunctionTemplate> JSHttpRequest::s_request_template_;

// === JSHttpRequest Member Functions ===

JSHttpRequest::JSHttpRequest() {
}

JSHttpRequest::~JSHttpRequest() {
  obj_.Dispose();
}

void JSHttpRequest::Initialize() {
  // Get the template, builiding it if necessary
  Handle<FunctionTemplate> t = GetTemplate();
  // Create a v8 Object from the template
  obj_ = Persistent<Object>::New(t->GetFunction()->NewInstance());
  // Define expected variables
  obj_->Set(String::NewSymbol("url"), String::New(""));
  obj_->Set(String::NewSymbol("params"), Array::New(0));
  obj_->Set(String::NewSymbol("headers"), Array::New(0));
  // Associate it with the C++ Object
  obj_->SetPointerInInternalField(0, this);
}

// Append received bytes to std::vector<char> buffer_
void JSHttpRequest::AppendBuffer(const char* data, size_t bytes) {
  size_t old_size = buffer_.size();
  if (old_size == 0) ++old_size; // Make room for a NULL terminator
  size_t new_size = old_size + bytes;
  buffer_.resize(new_size);
  char* dest = &(buffer_[old_size-1]); // Overwrite NULL
  memcpy(dest, data, bytes);
  buffer_[new_size-1] = 0; // NULL terminate
}

// Append received header to internal list of headers
void JSHttpRequest::AppendHeader(const std::string& header) {
  std::string new_header(header);
  // Trim trailing newline and CR
  while (new_header.size() > 0) {
    int last = new_header.size()-1;
    if (new_header[last] == '\n' || new_header[last] == '\r')
      new_header.erase(last);
    else
      break;
  }
  headers_.push_back(new_header);
}

// Retrieve the named JS property from the associated V8 object
//  and convert it to a std::string
std::string JSHttpRequest::GetString(const std::string& desc) {
  return utils::GetPropertyAsString(obj_, desc);
}

// Retrieve the named JS property from the associated V8 object
//  and convert it to a StringList
utils::StringList JSHttpRequest::GetStringList(const std::string& desc) {
  return utils::GetPropertyAsStringList(obj_, desc);
}

// Set the following JS properties and call 'onComplete' if defined
//  response.url= the actual url the request was sent to (including parameters)
//  response.code= the HTTP code (e.g. 200) as an Integer
//  response.content= the body of request as a single String
//  response.headers= the headers as an Array of Strings
void JSHttpRequest::CallComplete(int http_code) {
  Local<Object> response = Object::New();
  response->Set(String::NewSymbol("url"),
                String::New(&url_[0], url_.length()));
  response->Set(String::NewSymbol("code"),
                Integer::New(http_code));
  response->Set(String::NewSymbol("content"),
                String::New(&buffer_[0], buffer_.size()));
  Local<Array> jsheaders = Array::New(headers_.size());
  utils::StringList::iterator iter = headers_.begin();
  for (int i=0; iter != headers_.end(); ++iter, ++i) {
    const std::string& h = *iter;
    Local<String> jsh = String::New(&h[0], h.length());
    jsheaders->Set(i, jsh);
  }
  response->Set(String::NewSymbol("headers"), jsheaders);
  Local<Value> arg = response;
  CallV8Function("onComplete", 1, &arg);
}

void JSHttpRequest::CallTimeout() {
  CallV8Function("onTimeout", 0, NULL);
}

void JSHttpRequest::CallError(const std::string& errdesc) {
  Local<Value> errobj = String::New(errdesc.c_str());
  CallV8Function("onError", 1, &errobj);
}

bool JSHttpRequest::CallV8Function(const std::string& cb_name,
                                   int argc, Handle<Value> argv[]) {
  Handle<String> cb_str = String::NewSymbol(cb_name.c_str());
  if (obj_->Has(cb_str)) {
    Handle<Value> cb = obj_->GetRealNamedProperty(cb_str);
    if (!cb.IsEmpty() && cb->IsFunction()) {
      Handle<Function>::Cast(cb)->Call(obj_, argc, argv);
      return true;
    }
  }
  return false;
}

// === JSHttpRequest Static Functions ===

// Construct a JSHttpRequest and return the V8 object
//static
Handle<Value> JSHttpRequest::MakeHttpRequest(const Arguments& args) {
  if (!args.IsConstructCall()) {
    utils::ThrowV8Exception("Request() called in non constructor.");
    return v8::Undefined();
  }

  // Construct the JSHttpRequest and initialize it
  JSHttpRequest* request = new JSHttpRequest();
  request->Initialize();
  Handle<Object> obj = request->GetObject();

  // Initialize any properties in the V8 object based on input arguments
  //  args[N] will return Undefined if N is out of range
  Handle<Value> url = args[0];
  if (!url->IsUndefined() && url->IsString())
    obj->Set(String::NewSymbol("url"), url);
  Handle<Array> params = Handle<Array>::Cast(args[1]);
  if (!params->IsUndefined() && params->Length() > 0)
    obj->Set(String::NewSymbol("params"), params);
  Handle<Array> headers = Handle<Array>::Cast(args[2]);
  if (!headers->IsUndefined() && headers->Length() > 0)
    obj->Set(String::NewSymbol("headers"), headers);

  // Return the V8 object so that JS can bind the result
  return obj;
}

// Build the Request template once and return it
//static
Handle<FunctionTemplate> JSHttpRequest::GetTemplate() {
  if (s_request_template_.IsEmpty()) {
    s_request_template_ =
        Persistent<FunctionTemplate>::New(FunctionTemplate::New());
    s_request_template_->SetClassName(String::NewSymbol("Request"));
    Local<ObjectTemplate> template_object =
        s_request_template_->InstanceTemplate();
    template_object->SetInternalFieldCount(1);
  }
  return s_request_template_;
}

//static
JSHttpRequest* JSHttpRequest::GetRequestFromArgs(const Arguments& args) {
  JSHttpRequest* request = NULL;
  if (args.Length() >= 1) {
    // Unwrap checks that the argument is really an object
    request = Unwrap<JSHttpRequest>(Handle<Object>::Cast(args[0]));
  }
  return request;
}

//==============================================================================
// Class JSHttpCurlEasy
// Implements JSHttpMessengerInterface with libcurl
class JSHttpCurlEasy : public JSHttpMessengerInterface
{
 public:
  JSHttpCurlEasy() {}
  virtual ~JSHttpCurlEasy() {}
  bool Initialize();
  /*virtual*/ int Update();
  /*virtual*/ bool HttpGet(JSHttpRequest* request);
  /*virtual*/ bool HttpPost(JSHttpRequest* request);

 private:
  static CURL* CurlInit();
  static void CurlCleanup(CURL* handle);
  static bool CurlSetupRequest(JSHttpRequest* request, CURL* handle);
  static bool CurlSendRequest(JSHttpRequest* request, CURL* handle);
  static size_t HttpWriteCallback(void *ptr, size_t size,
                                  size_t count, void *data);
  static size_t HttpHeaderCallback(void *ptr, size_t size,
                                   size_t count, void *data);

  static bool s_curl_initialized_;
  static const int s_timeout_secs_;

  class CurlRequest
  {
   public:
    CurlRequest(JSHttpRequest* req, CURL* h) : request_(req), handle_(h) {}
    JSHttpRequest* request_;
    CURL* handle_;
  };
  typedef std::list<CurlRequest> RequestList;
  RequestList requests_;
};

// === JSHttpCurlEasy Globals ===

bool JSHttpCurlEasy::s_curl_initialized_ = false;
const int JSHttpCurlEasy::s_timeout_secs_(5);

// === JSHttpCurlEasy Functions ===

bool JSHttpCurlEasy::Initialize() {
  // Only call curl_global_init() once
  CURLcode res;
  if (s_curl_initialized_) {
    res = CURLE_OK;
  } else {
    res = curl_global_init(CURL_GLOBAL_SSL);
    s_curl_initialized_ = true;
  }
  return (res == CURLE_OK) ? true : false;
}

// Update returns the number of pending requests
// This implementation always processes all requests, so always returns 0
int JSHttpCurlEasy::Update() {
  for (RequestList::iterator iter = requests_.begin();
       iter != requests_.end();
       ++iter) {
    CurlRequest& curlreq = *iter;
    JSHttpRequest* request = curlreq.request_;
    CURL* handle = curlreq.handle_;
    CurlSendRequest(request, handle);
  }
  requests_.clear();
  return 0; // no pending updates
}

CURL* JSHttpCurlEasy::CurlInit() {
  CURL* handle = curl_easy_init();
  if (handle == NULL) {
    LOG(ERROR) << "Error calling curl_easy_init.";
    utils::ThrowV8Exception("CurlInit() failed.");
  }
  return handle;
}

void JSHttpCurlEasy::CurlCleanup(CURL* handle) {
  if (handle)
      curl_easy_cleanup(handle);
}

// Prepares a curl request to be sent, but does not issue it
bool JSHttpCurlEasy::CurlSetupRequest(JSHttpRequest* request, CURL* handle) {
  CURLcode code;
  // Set the url, callback, timeout, and other options
  code = curl_easy_setopt(handle, CURLOPT_URL, request->GetUrl().c_str());
  if (code == CURLE_OK)
    code = curl_easy_setopt(handle, CURLOPT_TIMEOUT, s_timeout_secs_);
  if (code == CURLE_OK)
    code = curl_easy_setopt(handle, CURLOPT_FAILONERROR, 0);
  if (code == CURLE_OK)
    code = curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, HttpWriteCallback);
  if (code == CURLE_OK)
    code = curl_easy_setopt(handle, CURLOPT_WRITEDATA, (void*)request);
  if (code == CURLE_OK)
    code = curl_easy_setopt(handle, CURLOPT_HEADERFUNCTION, HttpHeaderCallback);
  if (code == CURLE_OK)
    code = curl_easy_setopt(handle, CURLOPT_HEADERDATA, (void*)request);
  if (code != CURLE_OK) {
    LOG(WARNING) << "Error setting curl options: " << code;
    return false;
  }
  // Set headers defined by the request object
  utils::StringList headers = request->GetStringList("headers");
  if (headers.size() > 0) {
    struct curl_slist *curl_headers = NULL;
    for (utils::StringList::iterator iter = headers.begin();
         iter != headers.end();
         ++iter) {
      std::string h = *iter;
      if (h.find(':') == std::string::npos)
        utils::ThrowV8Exception(std::string("Badly formatted header: ") + h);
      curl_headers = curl_slist_append(curl_headers, h.c_str());
    }
    CURLcode code = curl_easy_setopt(handle, CURLOPT_HTTPHEADER, curl_headers);
    if (code != CURLE_OK) {
      utils::ThrowV8Exception(std::string("Error setting curl headers."));
      return false;
    }
  }
  return true;
}

// Use curl to send the request.
// BLOCKING! curl_easy_perform() blocks until a response is received
//  or the request times out.
bool JSHttpCurlEasy::CurlSendRequest(JSHttpRequest* request, CURL* handle) {
  bool res = true;
  CURLcode code = curl_easy_perform(handle);
  long http_code = 0;
  curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &http_code);
  if (code != CURLE_OK) {
    if (code == CURLE_OPERATION_TIMEDOUT) {
      request->CallTimeout();
    } else if (code == CURLE_HTTP_RETURNED_ERROR) {
      // Will only get triggered if CURLOPT_FAILONERROR is set to 1
      //  in CurlSetupRequest()
      std::stringstream errstream;
      errstream << curl_easy_strerror(code) << ": " << http_code;
      request->CallError(errstream.str());
    } else if (code == CURLE_COULDNT_RESOLVE_HOST ||
               code == CURLE_COULDNT_CONNECT) {
      request->CallError(std::string(curl_easy_strerror(code)));
    } else {
      LOG(WARNING) << "Error in curl_easy_perform: " << code;
      request->CallError(std::string(curl_easy_strerror(code)));
    }
    res = false;
  }
  if (res)
    request->CallComplete(http_code);
  CurlCleanup(handle);
  return res;
}

// Sets up the curl GET request and adds it to the request list.
// The request will get sent the next time Update() is called.
bool JSHttpCurlEasy::HttpGet(JSHttpRequest* request) {
  if (!request)
    return false;
  CURL* handle = CurlInit();
  //  Set parameter string
  std::string url = request->GetString("url");
  utils::StringList params = request->GetStringList("params");
  std::string paramstr;
  if (url.find('?') == std::string::npos)
    paramstr = "?";
  else
    paramstr = "&";
  for (utils::StringList::iterator iter = params.begin();
       iter != params.end();
       ++iter) {
    std::string p = *iter;
    if (iter != params.begin())
      paramstr += "&";
    paramstr += p;
  }
  // Append parameters to the url string
  url += paramstr;
  request->SetUrl(url);
  bool res = CurlSetupRequest(request, handle);
  requests_.push_back(CurlRequest(request, handle));
  return res;
}

// Sets up the curl POST request and adds it to the request list.
// The request will get sent the next time Update() is called.
bool JSHttpCurlEasy::HttpPost(JSHttpRequest* request) {
  if (!request)
    return false;
  CURL* handle = CurlInit();
  //  Set form data
  utils::StringList params = request->GetStringList("params");
  struct curl_httppost *formpost=NULL;
  struct curl_httppost *lastptr=NULL;
  for (utils::StringList::iterator iter = params.begin();
       iter != params.end();
       ++iter) {
    std::string p = *iter;
    size_t sep = p.find('=');
    std::string pname = p.substr(0,sep);
    std::string pvalue = p.substr(sep+1);
    curl_formadd(&formpost, &lastptr,
                 CURLFORM_COPYNAME, pname.c_str(),
                 CURLFORM_COPYCONTENTS, pvalue.c_str(),
                 CURLFORM_END);
  }
  CURLcode code = curl_easy_setopt(handle, CURLOPT_HTTPPOST, formpost);
  if (code != CURLE_OK) {
    utils::ThrowV8Exception(std::string("Error setting curl form data."));
    return false;
  }
  std::string url = request->GetString("url");
  request->SetUrl(url);
  bool res = CurlSetupRequest(request, handle);
  requests_.push_back(CurlRequest(request, handle));
  return res;
}

// === JSHttpCurlEasy Static Functions ===

//static
size_t JSHttpCurlEasy::HttpWriteCallback(void *ptr, size_t size,
                                         size_t count, void *data)
{
  // Unfortunately, no straightfowrard way to do typesafe params with libcurl
  JSHttpRequest* request = reinterpret_cast<JSHttpRequest*>(data);
  size_t bytes_received = size * count;
  request->AppendBuffer((char*)ptr, bytes_received);

  return count;
}

//static
size_t JSHttpCurlEasy::HttpHeaderCallback(void *ptr, size_t size,
                                          size_t count, void *data)
{
  // Unfortunately, no straightfowrard way to do typesafe params with libcurl
  JSHttpRequest* request = reinterpret_cast<JSHttpRequest*>(data);
  size_t bytes_received = size * count;
  request->AppendHeader(std::string((char*)ptr, bytes_received));

  return count;
}

//==============================================================================
// Class JSHttp

// static
Persistent<FunctionTemplate> JSHttp::s_http_template_;

JSHttp::JSHttp(Entd* entd, JSHttpMessengerInterface* messenger)
    : entd_(entd), messenger_(messenger) {
}

JSHttp::~JSHttp() {
  obj_.Dispose();
  entd_->ClearNativeTimeout(timeout_);
}

bool JSHttp::Initialize() {
  if (messenger_ == NULL) {
    // Default messenger uses libcurl
    JSHttpCurlEasy* easy_messenger = new JSHttpCurlEasy;
    easy_messenger->Initialize();
    messenger_ = easy_messenger;
  }
  const int CURL_POLL_INTERVAL_MS = 500;
  timeout_ = entd_->SetNativeTimeout(Update, this, CURL_POLL_INTERVAL_MS);

  // Get the template, builiding it if necessary
  Handle<FunctionTemplate> t = GetTemplate();
  // Create a v8 Object from the template
  obj_ = Persistent<Object>::New(t->GetFunction()->NewInstance());
  // Associate it with the C++ Object
  obj_->SetPointerInInternalField(0, this);

  return true;
}

// returns true if we should continue calling Update()
//static
bool JSHttp::Update(void *data) {
  JSHttp* jshttp = reinterpret_cast<JSHttp*>(data);
  int pending = jshttp->messenger_->Update();
  return pending ? true : false;
}

static Handle<Value> dispatch_HttpGet(const Arguments& args);
static Handle<Value> dispatch_HttpPost(const Arguments& args);

//static
Handle<FunctionTemplate> JSHttp::GetTemplate() {
  if (s_http_template_.IsEmpty()) {
    HandleScope handle_scope;
    s_http_template_ =
        Persistent<FunctionTemplate>::New(FunctionTemplate::New());
    s_http_template_->SetClassName(String::NewSymbol("http"));
    Handle<ObjectTemplate> template_object =
        s_http_template_->InstanceTemplate();
    template_object->SetInternalFieldCount(1);

    template_object->Set(String::NewSymbol("Request"),
                         FunctionTemplate::New(JSHttpRequest::MakeHttpRequest),
                         ReadOnly);
    template_object->Set(String::NewSymbol("GET"),
                         FunctionTemplate::New(dispatch_HttpGet),
                         ReadOnly);
    template_object->Set(String::NewSymbol("POST"),
                         FunctionTemplate::New(dispatch_HttpPost),
                         ReadOnly);
  }
  return s_http_template_;
}

//==== local dispatch fucntions for JSHttp template bindings ====

static bool dispatch_get_request(const Arguments& args,
                                 JSHttp*& jshttp, JSHttpRequest*& request) {
  jshttp = Unwrap<JSHttp>(args.This());
  if (!jshttp) {
    utils::ThrowV8Exception("Method called on incorrect object type.");
    return false;
  }
  if (args.Length() < 1) {
    utils::ThrowV8Exception("Not enough parameters.");
    return false;
  }
  request = JSHttpRequest::GetRequestFromArgs(args);
  if (!request) {
    utils::ThrowV8Exception("First argument must be a Request object.");
    return false;
  }
  return true;
}

static Handle<Value> dispatch_HttpGet(const Arguments& args) {
  JSHttp* jshttp;
  JSHttpRequest* request;
  bool res = false;
  if (dispatch_get_request(args, jshttp, request)) {
    res = jshttp->GetMessenger()->HttpGet(request);
  }
  return res ? v8::True() : v8::False();
}

static Handle<Value> dispatch_HttpPost(const Arguments& args) {
  JSHttp* jshttp;
  JSHttpRequest* request;
  bool res = false;
  if (dispatch_get_request(args, jshttp, request)) {
    res = jshttp->GetMessenger()->HttpPost(request);
  }
  return res ? v8::True() : v8::False();
}

} // namespace entd
