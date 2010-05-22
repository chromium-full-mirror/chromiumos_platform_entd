// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Integrate HTTP GET / POST with V8.
// Current implementations include: libcurl
//
// Example js usage:
//
//   var desc = "google cert";
//   var url = "https://ra.corp.google.com/";
//
//   var httpRequest = new entd.http.Request(url);
//
//   httpRequest.params.push("username", entd.username);
//   httpRequest.params.push("desc", desc);
//   httpRequest.onComplete = function(r) { onRequestComplete(desc, r) };
//   httpRequest.onTimeout =
//     function() { onHTTPTimeout("cert-request: " + desc) };
//   httpRequest.onError =
//     function(reason) { onHTTPError(reason, "cert-request: " + desc) };
//
//   entd.http.GET(httpRequest);

#include "entd/http.h"

#include <iostream>
#include <list>
#include <string>
#include <vector>

#include <base/basictypes.h>
#include <base/logging.h>
#include <curl/curl.h>
#include <stdlib.h>

#include "entd/entd.h"

namespace entd {

static const std::string kHttpsScheme = "https://";

// Default starting ephemeral port on Linux.
static const long kEphemeralStart = 32768;

// Class HttpRequest...

class HttpRequest : public JSObjectWrapper<HttpRequest> {
 public:
  HttpRequest() {}
  virtual ~HttpRequest() {}

  static const char* GetClassName() { return "Request"; }

  // JSObjectWrapper methods
  static void SetTemplateBindings(
      v8::Handle<v8::ObjectTemplate> template_object);
  virtual void ParseConstructorArgs(
      v8::Handle<v8::Object> obj, const v8::Arguments& args);

  // Accessors
  std::string GetString(const std::string& name);
  utils::StringList GetStringList(const std::string& name,
                                  const std::string& delim);
  std::string GetUrlEncodedParams();

  // Interface for HTTP (HttpMessengerInterface class)
  void SetUrl(const std::string& url) { url_ = url; }

  std::string GetUrl() { return url_; }
  void AppendBuffer(const char* data, size_t bytes);
  void AppendHeader(const std::string& header);
  void CallComplete(int http_code);
  void CallTimeout();
  void CallError(const std::string& errdesc);

 private:
  // Member Variables
  std::string url_;  // actual url the request was sent to, including params
  std::vector<char> buffer_;  // input buffer to hold request results
  utils::StringList headers_;

  DISALLOW_COPY_AND_ASSIGN(HttpRequest);
};

// HttpRequest Member Functions...

// static
void HttpRequest::SetTemplateBindings(
    v8::Handle<v8::ObjectTemplate> template_object){
  // Add named properties to the template object so that they always
  //  exist, even if they are not specified explicitly in a Request
  template_object->Set(v8::String::NewSymbol("url"), v8::String::New(""));
  template_object->Set(v8::String::NewSymbol("params"), v8::Object::New());
  template_object->Set(v8::String::NewSymbol("headers"), v8::Object::New());
}

// Append received bytes to std::vector<char> buffer_
void HttpRequest::AppendBuffer(const char* data, size_t bytes) {
  size_t old_size = buffer_.size();
  if (old_size == 0) ++old_size;  // Make room for a NULL terminator
  size_t new_size = old_size + bytes;
  buffer_.resize(new_size);
  char* dest = &(buffer_[old_size-1]);  // Overwrite NULL
  memcpy(dest, data, bytes);
  buffer_[new_size-1] = 0;  // NULL terminate
}

// Append received header to internal list of headers
void HttpRequest::AppendHeader(const std::string& header) {
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
// and convert it to a std::string
std::string HttpRequest::GetString(const std::string& name) {
  return utils::GetPropertyAsString(obj(), name);
}

// Retrieve the named JS property from the associated V8 object
// and convert it to a StringList
utils::StringList HttpRequest::GetStringList(const std::string& name,
                                             const std::string& delim) {
  return utils::GetPropertyAsStringList(obj(), name, delim);
}

std::string HttpRequest::GetUrlEncodedParams() {
  // Set parameter string
  utils::StringList params = GetStringList("params", "=");

  if (params.size()) {
    std::string paramstr;

    for (utils::StringList::iterator iter = params.begin();
         iter != params.end(); ++iter) {
      std::string p = *iter;
      if (iter != params.begin())
        paramstr += "&";
      paramstr += p;
    }

    return paramstr;
  }

  return "";
}

// Set the following JS properties and call 'onComplete' if defined
// response.url     = the actual url the request was sent to (including
//                    parameters)
// response.code    = the HTTP code (e.g. 200) as an Integer
// response.content = the body of request as a single String
// response.headers = the headers as an Array of Strings
void HttpRequest::CallComplete(int http_code) {
  v8::Local<v8::Object> response = v8::Object::New();

  response->Set(v8::String::NewSymbol("url"),
                v8::String::New(&url_[0], url_.length()));
  response->Set(v8::String::NewSymbol("code"),
                v8::Integer::New(http_code));
  response->Set(v8::String::NewSymbol("content"),
                v8::String::New(&buffer_[0], buffer_.size()));

  v8::Local<v8::Array> jsheaders = v8::Array::New(headers_.size());
  utils::StringList::iterator iter = headers_.begin();

  for (int i=0; iter != headers_.end(); ++iter, ++i) {
    const std::string& h = *iter;
    v8::Local<v8::String> jsh = v8::String::New(&h[0], h.length());
    jsheaders->Set(i, jsh);
  }

  response->Set(v8::String::NewSymbol("headers"), jsheaders);
  v8::Local<v8::Value> arg = response;
  utils::CallV8Function(obj(), "onComplete", 1, &arg);
}

// Call 'onTimeout' if it exists.
void HttpRequest::CallTimeout() {
  utils::CallV8Function(obj(), "onTimeout", 0, NULL);
}

// Call 'onError' if it exists with 'errdesc' as an argument.
void HttpRequest::CallError(const std::string& errdesc) {
  v8::Local<v8::Value> errobj = v8::String::New(errdesc.c_str());
  utils::CallV8Function(obj(), "onError", 1, &errobj);
}

// HttpRequest Static Functions...

// virtual
void HttpRequest::ParseConstructorArgs(v8::Handle<v8::Object> obj,
                                       const v8::Arguments& args) {
  // args[N] will return v8::Undefined if N is out of range.
  v8::Handle<v8::Value> value = args[0];
  if (!value->IsUndefined() && value->IsString())
    obj->Set(v8::String::NewSymbol("hostname"), value);

  value = args[1];
  if (!value->IsUndefined() && value->IsString())
    obj->Set(v8::String::NewSymbol("path"), value);

  value = args[2];
  if (!value->IsUndefined() && (value->IsObject() || value->IsArray()))
    obj->Set(v8::String::NewSymbol("params"), value);

  value = args[3];
  if (!value->IsUndefined() && (value->IsObject() || value->IsArray()))
    obj->Set(v8::String::NewSymbol("headers"), value);
}

// Class HttpCurlEasy
// Implements HttpMessengerInterface with libcurl
class HttpCurlEasy : public HttpMessengerInterface
{
 public:
  HttpCurlEasy() {}
  virtual ~HttpCurlEasy() {}
  bool Initialize();
  virtual int Update();
  virtual bool HttpGet(HttpRequest* request);
  virtual bool HttpPost(HttpRequest* request);

 private:
  static CURL* CurlInit();
  static void CurlCleanup(CURL* handle);
  static bool CurlSetupMultipartPost(HttpRequest* request, CURL* handle);
  static bool CurlSetupRequest(HttpRequest* request, CURL* handle);
  static bool CurlSendRequest(HttpRequest* request, CURL* handle);
  static size_t HttpWriteCallback(void *ptr, size_t size,
                                  size_t count, void *data);
  static size_t HttpHeaderCallback(void *ptr, size_t size,
                                   size_t count, void *data);

  static bool s_curl_initialized_;
  static const int s_timeout_secs_;

  class CurlRequest
  {
   public:
    CurlRequest(HttpRequest* req, CURL* h) : request_(req), handle_(h) {}
    HttpRequest* request_;
    CURL* handle_;
  };

  typedef std::list<CurlRequest> RequestList;
  RequestList requests_;
};

// HttpCurlEasy Globals

bool HttpCurlEasy::s_curl_initialized_ = false;
const int HttpCurlEasy::s_timeout_secs_(5);

// HttpCurlEasy Functions

bool HttpCurlEasy::Initialize() {
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
int HttpCurlEasy::Update() {
  for (RequestList::iterator iter = requests_.begin();
       iter != requests_.end(); ++iter) {
    CurlRequest& curlreq = *iter;
    HttpRequest* request = curlreq.request_;
    CURL* handle = curlreq.handle_;
    CurlSendRequest(request, handle);
  }

  requests_.clear();
  return 0;
}

CURL* HttpCurlEasy::CurlInit() {
  CURL* handle = curl_easy_init();

  if (handle == NULL) {
    LOG(ERROR) << "Error calling curl_easy_init.";
    utils::ThrowV8Exception("CurlInit() failed.");
  }

  return handle;
}

void HttpCurlEasy::CurlCleanup(CURL* handle) {
  if (handle)
      curl_easy_cleanup(handle);
}

// Prepares a curl request to be sent, but does not issue it
bool HttpCurlEasy::CurlSetupRequest(HttpRequest* request, CURL* handle) {
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
    code = curl_easy_setopt(handle, CURLOPT_WRITEDATA,
                            reinterpret_cast<void*>(request));
  if (code == CURLE_OK)
    code = curl_easy_setopt(handle, CURLOPT_HEADERFUNCTION, HttpHeaderCallback);
  if (code == CURLE_OK)
    code = curl_easy_setopt(handle, CURLOPT_HEADERDATA,
                            reinterpret_cast<void*>(request));
  if (code == CURLE_OK) {
    long verify_peer = Http::allow_self_signed_certs ? 0L : 1L;
    code = curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER,
                            reinterpret_cast<void*>(verify_peer));
  }

  if (code == CURLE_OK && !Http::root_ca_file.empty()) {
    code = curl_easy_setopt(
        handle, CURLOPT_CAINFO,
        reinterpret_cast<const void*>(Http::root_ca_file.c_str()));
  }

  if (code == CURLE_OK) {
    std::string auth = request->GetString("auth");
    if (auth.length() > 0) {
      code = curl_easy_setopt(handle, CURLOPT_USERPWD,
                              reinterpret_cast<const void*>(auth.c_str()));
    }
  }

  if (code != CURLE_OK) {
    LOG(WARNING) << "Error setting curl options: " << code;
    return false;
  }

  // Set headers defined by the request object
  utils::StringList headers = request->GetStringList("headers", ": ");
  if (headers.size() > 0) {
    struct curl_slist *curl_headers = NULL;

    for (utils::StringList::iterator iter = headers.begin();
         iter != headers.end(); ++iter) {
      std::string h = *iter;
      if (h.find(':') == std::string::npos) {
        utils::ThrowV8Exception(std::string("Badly formatted header: ") + h);
        return false;
      }

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
// or the request times out.
bool HttpCurlEasy::CurlSendRequest(HttpRequest* request, CURL* handle) {
  bool res = true;
  CURLcode code = curl_easy_perform(handle);
  long http_code = 0;

  curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &http_code);

  if (code != CURLE_OK) {
    if (code == CURLE_OPERATION_TIMEDOUT) {
      request->CallTimeout();

    } else if (code == CURLE_HTTP_RETURNED_ERROR) {
      // Will only get triggered if CURLOPT_FAILONERROR is set to 1
      // in CurlSetupRequest()
      std::stringstream errstream;
      errstream << curl_easy_strerror(code) << ": " << http_code;
      request->CallError(errstream.str());

    } else if (code == CURLE_COULDNT_RESOLVE_HOST ||
               code == CURLE_COULDNT_CONNECT) {
      request->CallError(std::string(curl_easy_strerror(code)));

    } else {
      LOG(WARNING) << "Error in curl_easy_perform: "
                   << curl_easy_strerror(code)
                   << " (" << code << ")";
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
bool HttpCurlEasy::HttpGet(HttpRequest* request) {
  if (!request)
    return false;

  CURL* handle = CurlInit();
  if (!handle)
    return false;

  // Set parameter string
  std::string params = request->GetUrlEncodedParams();
  if (params.size()) {
    // Append parameters to the url string
    std::string url = request->GetUrl();
    if (url.find('?') == std::string::npos) {
      url.append("?");
    } else {
      url.append("&");
    }

    request->SetUrl(url + params);
  }

  if (!CurlSetupRequest(request, handle))
    return false;

  requests_.push_back(CurlRequest(request, handle));
  return true;
}

// TODO(rginda): This should be hooked back up and retested so that policies
// can optionally perform multipart posts.  It's dead code at the moment.
// static
bool HttpCurlEasy::CurlSetupMultipartPost(HttpRequest* request, CURL* handle) {
  // Set form data
  utils::StringList params = request->GetStringList("params", "=");
  struct curl_httppost *formpost = NULL;
  struct curl_httppost *lastptr = NULL;

  for (utils::StringList::iterator iter = params.begin();
       iter != params.end(); ++iter) {
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
  return (code == CURLE_OK);
}

// Sets up the curl POST request and adds it to the request list.
// The request will get sent the next time Update() is called.
bool HttpCurlEasy::HttpPost(HttpRequest* request) {
  if (!request)
    return false;

  CURL* handle = CurlInit();
  if (!handle)
    return false;

  std::string paramstr = request->GetUrlEncodedParams();
  if (paramstr.length() > 0) {
    CURLcode code = curl_easy_setopt(handle, CURLOPT_COPYPOSTFIELDS,
                                     paramstr.c_str());
    if (code != CURLE_OK) {
      utils::ThrowV8Exception(std::string("Error setting curl form data."));
      return false;
    }
  }

  if (!CurlSetupRequest(request, handle))
    return false;

  requests_.push_back(CurlRequest(request, handle));
  return true;
}

// HttpCurlEasy Static Functions

// static
size_t HttpCurlEasy::HttpWriteCallback(void *ptr, size_t size,
                                       size_t count, void *data) {
  // Unfortunately, no straightfowrard way to do typesafe params with libcurl
  HttpRequest* request = reinterpret_cast<HttpRequest*>(data);
  size_t bytes_received = size * count;
  request->AppendBuffer((char*)ptr, bytes_received);

  return count;
}

// static
size_t HttpCurlEasy::HttpHeaderCallback(void *ptr, size_t size,
                                        size_t count, void *data) {
  // Unfortunately, no straightfowrard way to do typesafe params with libcurl
  HttpRequest* request = reinterpret_cast<HttpRequest*>(data);
  size_t bytes_received = size * count;
  request->AppendHeader(std::string((char*)ptr, bytes_received));

  return count;
}

// Class Http

Http::Http(Entd* entd, HttpMessengerInterface* messenger)
    : JSObjectWrapper<Http>(),
      entd_(entd),
      messenger_(messenger),
      timeout_(0) {
}

Http::~Http() {
  if (timeout_)
    entd_->ClearNativeTimeout(timeout_);

  HttpRequest::CleanupTemplate();
  CleanupTemplate();
}

bool Http::allow_self_signed_certs = false;
std::string Http::root_ca_file = "";

bool Http::Initialize() {
  if (messenger_ == NULL) {
    // Default messenger uses libcurl
    HttpCurlEasy* easy_messenger = new HttpCurlEasy;
    easy_messenger->Initialize();
    messenger_ = easy_messenger;
  }

  // Build and initialize the V8 object
  return JSObjectWrapper<Http>::Initialize();
}

static bool dispatch_OnNativeTimeout(void *data) {
  Http* jshttp = reinterpret_cast<Http*>(data);
  return jshttp->OnNativeTimeout();
}

bool Http::OnNativeTimeout() {
  timeout_ = 0;
  return (messenger_->Update() > 0);
}

static v8::Handle<v8::Value> dispatch_HttpGet(const v8::Arguments& args);
static v8::Handle<v8::Value> dispatch_HttpPost(const v8::Arguments& args);

// static
void Http::SetTemplateBindings(v8::Handle<v8::ObjectTemplate> template_object) {
  template_object->Set(v8::String::NewSymbol("Request"),
                       v8::FunctionTemplate::New(HttpRequest::Construct),
                       v8::ReadOnly);
  template_object->Set(v8::String::NewSymbol("GET"),
                       v8::FunctionTemplate::New(dispatch_HttpGet),
                       v8::ReadOnly);
  template_object->Set(v8::String::NewSymbol("POST"),
                       v8::FunctionTemplate::New(dispatch_HttpPost),
                       v8::ReadOnly);
}

bool Http::HttpGet(HttpRequest* request) {
  if (!timeout_)
    timeout_ = entd_->SetNativeTimeout(dispatch_OnNativeTimeout, this, 0);

  if (!messenger_->HttpGet(request))
    return false;

  request->obj()->Set(v8::String::NewSymbol("url"),
                      v8::String::New(request->GetUrl().c_str()));
  return true;
}

bool Http::HttpPost(HttpRequest* request) {
  if (!timeout_)
    timeout_ = entd_->SetNativeTimeout(dispatch_OnNativeTimeout, this, 0);

  if (!messenger_->HttpPost(request))
    return false;

  request->obj()->Set(v8::String::NewSymbol("url"),
                      v8::String::New(request->GetUrl().c_str()));
  return true;
}

// Local dispatch fucntions for Http template bindings.

static bool CheckRequestArgs(const v8::Arguments& args,
                             Http*& http, HttpRequest*& request) {
  http = Http::Unwrap(args.This());
  if (!http) {
    utils::ThrowV8Exception("Method called on incorrect object type.");
    return false;
  }

  if (args.Length() < 1) {
    utils::ThrowV8Exception("Not enough parameters.");
    return false;
  }

  request = HttpRequest::GetFromArg(args, 0);
  if (!request) {
    utils::ThrowV8Exception("First argument must be a Request object.");
    return false;
  }

  std::string hostname = request->GetString("hostname");
  if (!http->GetEntd()->CheckHostname(hostname)) {
    utils::ThrowV8Exception("Invalid hostname");
    return false;
  }

  std::string path = request->GetString("path");

  if (path.length() == 0) {
    path = "/";
  } else if (path[0] != '/') {
    path = "/" + path;
  }

  std::string port_str = request->GetString("port");
  if (port_str.length() > 0) {
    char *endptr;
    long port = strtol(port_str.c_str(), &endptr, 10);
    if (*endptr != '\0' || port <= 0 || port >= kEphemeralStart) {
      utils::ThrowV8Exception("Invalid port");
      return false;
    }

    hostname.append(":" + port_str);
  }

  request->SetUrl(kHttpsScheme + hostname + path);

  return true;
}

static v8::Handle<v8::Value> dispatch_HttpGet(const v8::Arguments& args) {
  Http* http;
  HttpRequest* request;
  bool res = false;

  if (CheckRequestArgs(args, http, request))
    res = http->HttpGet(request);

  return res ? v8::True() : v8::False();
}

static v8::Handle<v8::Value> dispatch_HttpPost(const v8::Arguments& args) {
  Http* http;
  HttpRequest* request;
  bool res = false;

  if (CheckRequestArgs(args, http, request))
    res = http->HttpPost(request);

  return res ? v8::True() : v8::False();
}

}  // namespace entd
