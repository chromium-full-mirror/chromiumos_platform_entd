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
#include "entd/scriptable.h"

namespace entd {

// Curl uses 'CURL*' values as handles; typedef for better readability.
// (Note: CURL is typedefed to void, so -> access is already invalid).
typedef CURL* CurlHandle;

static const std::string kHttpsScheme = "https://";

// Default starting ephemeral port on Linux.
static const long kEphemeralStart = 32768;

// Class HttpRequest...

class HttpRequest : public Scriptable<HttpRequest> {
 public:
  HttpRequest() {}
  virtual ~HttpRequest() {}

  static const std::string class_name() { return "entd.http.Request"; }
  static bool InitializeTemplate(v8::Handle<v8::FunctionTemplate> t);

  v8::Handle<v8::Value> Construct(const v8::Arguments& args);

  std::string GetString(const std::string& name) const;
  utils::StringList GetStringList(const std::string& name,
                                  const std::string& delim) const;
  std::string GetUrlEncodedParams();

  // Interface for HTTP (HttpMessengerInterface class)
  void SetUrl(const std::string& url) { url_ = url; }

  std::string GetUrl() const { return url_; }

  void AppendBuffer(const char* data, size_t bytes);
  void AppendHeader(const std::string& header);

  void CallComplete(int http_code);
  void CallTimeout();
  void CallError(const std::string& errdesc);

 private:
  // Variables set by the curl interface.
  std::string url_;  // actual url the request is sent to, including params.
  utils::StringList headers_;  // headers returned by the curl request
  std::vector<char> buffer_;  // buffer to hold request results

  DISALLOW_COPY_AND_ASSIGN(HttpRequest);
};

// static
bool HttpRequest::InitializeTemplate(v8::Handle<v8::FunctionTemplate> t){
  v8::Handle<v8::ObjectTemplate> object_t = t->InstanceTemplate();

  // Add named properties to the template object so that they always
  // exist, even if they are not specified explicitly in a Request.
  object_t->Set(v8::String::NewSymbol("url"), v8::String::New(""));
  object_t->Set(v8::String::NewSymbol("params"), v8::Object::New());
  object_t->Set(v8::String::NewSymbol("headers"), v8::Object::New());

  return true;
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
std::string HttpRequest::GetString(const std::string& name) const {
  return utils::GetPropertyAsString(js_object(), name);
}

// Retrieve the named JS property from the associated V8 object
// and convert it to a StringList
utils::StringList HttpRequest::GetStringList(const std::string& name,
                                             const std::string& delim) const {
  return utils::GetPropertyAsStringList(js_object(), name, delim);
}

std::string HttpRequest::GetUrlEncodedParams() {
  // Set params string
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
// response.url     = the actual url the request was sent to (includes params)
// response.code    = the HTTP code (e.g. 200) as an Integer
// response.content = the body of request as a single String
// response.headers = the headers as an Array of Strings
void HttpRequest::CallComplete(int http_code) {
  v8::Local<v8::Object> response = v8::Object::New();

  const std::string& url = GetUrl();
  response->Set(v8::String::NewSymbol("url"),
                v8::String::New(url.c_str(), url.length()));
  response->Set(v8::String::NewSymbol("code"),
                v8::Integer::New(http_code));
  response->Set(v8::String::NewSymbol("content"),
                v8::String::New(&buffer_[0], buffer_.size()));

  v8::Local<v8::Array> jsheaders = v8::Array::New(headers_.size());
  utils::StringList::const_iterator iter = headers_.begin();

  for (int i=0; iter != headers_.end(); ++iter, ++i) {
    const std::string& h = *iter;
    v8::Local<v8::String> jsh = v8::String::New(&h[0], h.length());
    jsheaders->Set(i, jsh);
  }

  response->Set(v8::String::NewSymbol("headers"), jsheaders);
  v8::Local<v8::Value> arg = response;
  utils::CallV8Function(js_object(), "onComplete", 1, &arg);
}

// Call 'onTimeout' if it exists.
void HttpRequest::CallTimeout() {
  utils::CallV8Function(js_object(), "onTimeout", 0, NULL);
}

// Call 'onError' if it exists with 'errdesc' as an argument.
void HttpRequest::CallError(const std::string& errdesc) {
  v8::Local<v8::Value> errobj = v8::String::New(errdesc.c_str());
  utils::CallV8Function(js_object(), "onError", 1, &errobj);
}

v8::Handle<v8::Value> HttpRequest::Construct(const v8::Arguments& args) {
  v8::Handle<v8::Object> self = js_object();

  // args[N] will return v8::Undefined if N is out of range.
  v8::Handle<v8::Value> value = args[0];
  if (!value->IsUndefined() && value->IsString())
    self->Set(v8::String::NewSymbol("hostname"), value);

  value = args[1];
  if (!value->IsUndefined() && value->IsString())
    self->Set(v8::String::NewSymbol("path"), value);

  value = args[2];
  if (!value->IsUndefined() && (value->IsObject() || value->IsArray()))
    self->Set(v8::String::NewSymbol("params"), value);

  value = args[3];
  if (!value->IsUndefined() && (value->IsObject() || value->IsArray()))
    self->Set(v8::String::NewSymbol("headers"), value);

  return self;
}

// Class HttpCurlEasy
// Implements HttpMessengerInterface with libcurl
// TODO(rginda): Kill this class.  Elevate the nested CurlRequest class into a
// top level class and get rid of "HttpMessengerInterface" and this subclass.
// Perhaps git rid of the "Curl" designation, since we're not likely to add
// a non-curl implementation without also removing the curl version.
class HttpCurlEasy : public HttpMessengerInterface
{
 public:
  HttpCurlEasy() {}
  virtual ~HttpCurlEasy() {}
  bool Initialize();
  virtual int Update();
  // Set up 'request' from 'url' for the specified operation.
  virtual bool HttpGet(HttpRequest* request);
  virtual bool HttpPost(HttpRequest* request);

 private:
  // Setup curl
  static CurlHandle CurlInit();
  static void CurlCleanup(CurlHandle handle);
  // Setup requests (modifies request)
  static bool CurlSetupMultipartPost(CurlHandle handle, HttpRequest* request);
  static bool CurlSetupRequest(CurlHandle handle, HttpRequest* request);
  // Send a request (may indirectly modify request)
  static bool CurlSendRequest(CurlHandle handle, HttpRequest* request);
  // Curl callbacks
  static size_t HttpWriteCallback(void *ptr, size_t size,
                                  size_t count, void *data);
  static size_t HttpHeaderCallback(void *ptr, size_t size,
                                   size_t count, void *data);

  static bool s_curl_initialized_;
  static const int s_timeout_secs_;

  class CurlRequest
  {
   public:
    CurlRequest(CurlHandle handle, HttpRequest* req)
        : handle_(handle), request_(req) {}
    CurlHandle handle_;
    HttpRequest::Reference request_;
  };

  typedef std::list<CurlRequest> RequestList;
  RequestList requests_;
};

// HttpCurlEasy Globals

bool HttpCurlEasy::s_curl_initialized_ = false;
const int HttpCurlEasy::s_timeout_secs_(5);

// HttpCurlEasy Public Functions

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
    CurlSendRequest(iter->handle_, iter->request_.native_ptr());
  }

  requests_.clear();
  return 0;
}

// Sets up the curl GET request and adds it to the request list.
// The request will get sent the next time Update() is called.
bool HttpCurlEasy::HttpGet(HttpRequest* request) {
  CurlHandle handle = CurlInit();
  if (!handle)
    return false;

  if (!CurlSetupRequest(handle, request))
    return false;

  requests_.push_back(CurlRequest(handle, request));

  return true;
}

// Sets up the curl POST request and adds it to the request list.
// The request will get sent the next time Update() is called.
bool HttpCurlEasy::HttpPost(HttpRequest* request) {
  CurlHandle handle = CurlInit();
  if (!handle)
    return false;

  std::string params = request->GetUrlEncodedParams();
  if (params.length() > 0) {
    CURLcode code = curl_easy_setopt(handle, CURLOPT_COPYPOSTFIELDS,
                                     params.c_str());
    if (code != CURLE_OK) {
      utils::ThrowV8Exception(std::string("Error setting curl form data."));
      return false;
    }
  }

  if (!CurlSetupRequest(handle, request))
    return false;

  requests_.push_back(CurlRequest(handle, request));

  return true;
}

// HttpCurlEasy Private Functions

CurlHandle HttpCurlEasy::CurlInit() {
  CurlHandle handle = curl_easy_init();

  if (handle == NULL) {
    LOG(ERROR) << "Error calling curl_easy_init.";
    utils::ThrowV8Exception("CurlInit() failed.");
  }

  return handle;
}

void HttpCurlEasy::CurlCleanup(CurlHandle handle) {
  if (handle != NULL)
      curl_easy_cleanup(handle);
}

// Prepares a curl request to be sent, but does not issue it
bool HttpCurlEasy::CurlSetupRequest(CurlHandle handle,
                                    HttpRequest* request) {
  CURLcode code;

  // Set the url, callback, timeout, and other options
  const std::string& url = request->GetUrl();
  code = curl_easy_setopt(handle, CURLOPT_URL, url.c_str());
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
bool HttpCurlEasy::CurlSendRequest(CurlHandle handle,
                                   HttpRequest* request) {
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

// TODO(rginda): This should be hooked back up and retested so that policies
// can optionally perform multipart posts.  It's dead code at the moment.
// static
bool HttpCurlEasy::CurlSetupMultipartPost(CurlHandle handle,
                                          HttpRequest* request) {
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

// HttpCurlEasy Static Functions

// static
size_t HttpCurlEasy::HttpWriteCallback(void *ptr, size_t size,
                                       size_t count, void *data) {
  HttpRequest* request = reinterpret_cast<HttpRequest*>(data);
  size_t bytes_received = size * count;
  request->AppendBuffer((char*)ptr, bytes_received);

  return count;
}

// static
size_t HttpCurlEasy::HttpHeaderCallback(void *ptr, size_t size,
                                        size_t count, void *data) {
  HttpRequest* request = reinterpret_cast<HttpRequest*>(data);
  size_t bytes_received = size * count;
  request->AppendHeader(std::string((char*)ptr, bytes_received));

  return count;
}

// Class Http

Http::Http()
    : entd_(NULL),
      messenger_(NULL),
      timeout_(0) {
}

Http::~Http() {
  if (timeout_)
    entd_->ClearNativeTimeout(timeout_);
}

bool Http::allow_self_signed_certs = false;
std::string Http::root_ca_file = "";

bool Http::Initialize(Entd* entd, HttpMessengerInterface* messenger) {
  entd_ = entd;
  messenger_ = messenger;

  if (messenger_ == NULL) {
    // Default messenger uses libcurl
    HttpCurlEasy* easy_messenger = new HttpCurlEasy;
    easy_messenger->Initialize();
    messenger_ = easy_messenger;
  }

  return true;
}

static bool dispatch_OnNativeTimeout(void *data) {
  Http* jshttp = reinterpret_cast<Http*>(data);
  return jshttp->OnNativeTimeout();
}

bool Http::OnNativeTimeout() {
  timeout_ = 0;
  return (messenger_->Update() > 0);
}

// static
bool Http::InitializeTemplate(v8::Handle<v8::FunctionTemplate> t) {
  v8::Handle<v8::ObjectTemplate> object_t = t->InstanceTemplate();

  object_t->Set(v8::String::NewSymbol("Request"),
                HttpRequest::constructor_template(),
                v8::ReadOnly);

  BindMethod(object_t, &Http::HttpGet, "GET");
  BindMethod(object_t, &Http::HttpPost, "POST");

  return true;
}

// TODO(rginda): Refactor this so it lives in the request class, perhaps
// as GetUrl().  There are issues around whether or not the params appear
// in the URL (they should in a GET, but not in a POST) which need to be worked
// out.
bool Http::ComputeRequestUrl(Entd* entd,
                             const HttpRequest& request,
                             std::string* url) {
  std::string hostname = request.GetString("hostname");
  if (!entd->CheckHostname(hostname)) {
    utils::ThrowV8Exception("Invalid hostname");
    return false;
  }

  std::string path = request.GetString("path");

  if (path.length() == 0) {
    path = "/";
  } else if (path[0] != '/') {
    path = "/" + path;
  }

  std::string port_str = request.GetString("port");
  if (port_str.length() > 0) {
    char *endptr;
    long port = strtol(port_str.c_str(), &endptr, 10);
    if (*endptr != '\0' || port <= 0 || port >= kEphemeralStart) {
      utils::ThrowV8Exception("Invalid port");
      return false;
    }

    hostname.append(":" + port_str);
  }

  *url = kHttpsScheme + hostname + path;
  return true;
}

v8::Handle<v8::Value> Http::HttpGet(const v8::Arguments& args) {
  HttpRequest* request =
      Scriptable<HttpRequest>::UnwrapOrThrow(args[0], "first argument");
  if (!request)
    return v8::Undefined();

  std::string url;
  if (!ComputeRequestUrl(GetEntd(), *request, &url))
    return v8::Undefined();

  // Set params string.
  std::string params = request->GetUrlEncodedParams();
  if (params.length()) {
    // Append params to the url string.
    if (url.find('?') == std::string::npos) {
      url.append("?");
    } else {
      url.append("&");
    }
    url += params;
  }

  request->SetUrl(url);
  request->js_object()->Set(v8::String::NewSymbol("url"),
                            v8::String::New(url.c_str()));

  if (!timeout_)
    timeout_ = entd_->SetNativeTimeout(dispatch_OnNativeTimeout, this, 0);

  if (!messenger_->HttpGet(request))
    return v8::False();

  return v8::True();
}

v8::Handle<v8::Value> Http::HttpPost(const v8::Arguments& args) {
  Http* http = Scriptable<Http>::UnwrapOrThrow(args.This(), "this");
  if (!http)
    return v8::Undefined();

  HttpRequest* request =
      Scriptable<HttpRequest>::UnwrapOrThrow(args[0], "first argument");
  if (!request)
    return v8::Undefined();

  std::string url;
  if (!ComputeRequestUrl(http->GetEntd(), *request, &url))
    return v8::Undefined();

  request->SetUrl(url);
  request->js_object()->Set(v8::String::NewSymbol("url"),
                            v8::String::New(url.c_str()));

  if (!timeout_)
    timeout_ = entd_->SetNativeTimeout(dispatch_OnNativeTimeout, this, 0);

  if (!messenger_->HttpPost(request))
    return v8::False();

  return v8::True();
}

}  // namespace entd
