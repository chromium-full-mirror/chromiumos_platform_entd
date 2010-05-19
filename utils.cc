// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "entd/utils.h"

#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <wordexp.h>

#include <iostream>

#include <base/basictypes.h>
#include <base/file_util.h>
#include <base/logging.h>

namespace entd {

namespace utils {


void* malloc(size_t size) {
  void* rv = ::malloc(size);
  if (!rv)
    exit(2);

  return rv;
}

void free(void *buf) {
  ::free(buf);
}

// Extracts a C string from a V8 Utf8Value.
const char* ToCString(const v8::String::Utf8Value& value) {
  return *value ? *value : "<string conversion failed>";
}

bool CheckHostnameCharset(const std::string& str) {
  for (std::string::const_iterator i = str.begin(); i < str.end(); ++i) {
    if (!(isalnum(*i) || *i == '.' || *i == '-')) {
      return false;
    }
  }

  return true;
}

// Reads a file into a v8 string.
v8::Handle<v8::String> ReadFile(const std::string& name) {
  std::string filestr;
  file_util::ReadFileToString(FilePath(name), &filestr);
  v8::Handle<v8::String> result =
      v8::String::New(filestr.c_str(), filestr.size());
  return result;
}

std::vector<std::string> ReadDirectory(const std::string& path) {
  std::vector<std::string> dirnames;
  DIR *dirp = opendir(path.c_str());

  if (dirp == NULL) {
    LOG(WARNING) << "Unable to open directory: " << path;
    return dirnames;
  }

  while (1) {
    struct dirent *direntp = readdir(dirp);
    if (direntp == NULL)
      break;
    std::string dirname(direntp->d_name);
    if (dirname == "." || dirname == "..")
      continue;
    dirnames.push_back(dirname);
  }

  closedir(dirp);
  return dirnames;
}

std::string ExpandFilePath(const std::string& path) {
  std::string res;
  wordexp_t path_exp;

  wordexp(path.c_str(), &path_exp, 0);

  if (path_exp.we_wordc > 0) {
    res = std::string(path_exp.we_wordv[0]);
  } else {
    res = path;
  }

  wordfree(&path_exp);
  return res;
}

std::string ValueAsUtf8String(v8::Handle<v8::Value> value) {
  v8::Local<v8::String> s = value->ToString();
  return std::string(*v8::String::Utf8Value(s));
}

std::string GetPropertyAsString(v8::Handle<v8::Object> obj,
                                const std::string& name) {
  std::string res;
  v8::Handle<v8::String> jsname = v8::String::New(name.c_str());
  if (obj->Has(jsname)) {
    res = ValueAsUtf8String(obj->Get(jsname));
  }
  return res;
}

// "delim" only applies to object properties; it is ignored for Arrays
StringList GetPropertyAsStringList(v8::Handle<v8::Object> obj,
                                   const std::string& name,
                                   const std::string& delim) {
  StringList result;
  v8::Handle<v8::String> jsname = v8::String::New(name.c_str());

  if (obj->Has(jsname)) {
    v8::Local<v8::Value> jsvalue = obj->Get(jsname);

    if (jsvalue->IsArray()) {
      v8::Local<v8::Array> jsarray =
          v8::Local<v8::Array>::Cast(obj->Get(jsname));

      for (size_t i = 0; i < jsarray->Length(); i++) {
        std::string s = ValueAsUtf8String(jsarray->Get(i));
        result.push_back(s);
      }

    } else if (jsvalue->IsObject()) {
      v8::Local<v8::Object> paramobj =
          v8::Local<v8::Object>::Cast(obj->Get(jsname));

      v8::Local<v8::Array> props = paramobj->GetPropertyNames();
      for (size_t i = 0; i < props->Length(); ++i) {
        v8::Handle<v8::Value> propname = props->Get(i);
        std::string name = ValueAsUtf8String(propname);
        std::string value = ValueAsUtf8String(paramobj->Get(propname));
        std::string s = name + delim + value;
        result.push_back(s);
      }
    }
  }
  return result;
}

void ThrowV8Exception(const std::string& err) {
  ThrowException(v8::String::New(err.c_str()));
}

void ReportV8Exception(v8::TryCatch* try_catch) {
  std::cerr << "V8 Exception:\n";
  v8::HandleScope handle_scope;
  v8::String::Utf8Value exception(try_catch->Exception());
  const char* exception_string = utils::ToCString(exception);
  v8::Handle<v8::Message> message = try_catch->Message();

  if (message.IsEmpty()) {
    // V8 didn't provide any extra information about this error; just
    // print the exception.
    std::cerr << exception_string << '\n';

  } else {
    // Print (filename):(line number): (message).
    v8::String::Utf8Value filename(message->GetScriptResourceName());
    const char* filename_string = utils::ToCString(filename);
    int linenum = message->GetLineNumber();
    std::cerr << filename_string << ':' << linenum << ": " <<
        exception_string << '\n';

    // Print line of source code.
    v8::String::Utf8Value sourceline(message->GetSourceLine());
    const char* sourceline_string = utils::ToCString(sourceline);
    std::cerr << sourceline_string << '\n';

    // Print wavy underline (GetUnderline is deprecated).
    int start = message->GetStartColumn();
    for (int i = 0; i < start; i++) {
      std::cerr << ' ';
    }

    int end = message->GetEndColumn();
    for (int i = start; i < end; i++) {
      std::cerr << '^';
    }

    std::cerr << '\n';
  }
}

// Note: This assumes it is not getting called from inside a JS
// stack (current use cases), so it users LOG(ERROR)
// instead of ThrowException
// If called from a JS stack, the caller should throw an
// exception if this returns an empty handle.
v8::Handle<v8::Value> CallV8Function(v8::Handle<v8::Object> obj,
                             const std::string& cb_name,
                             int argc, v8::Handle<v8::Value> argv[]) {
  if (obj.IsEmpty() || !obj->IsObject()) {
    LOG(ERROR) << "Invalid object when trying to call: " << cb_name;
    return v8::Handle<v8::Value>();
  }

  v8::Handle<v8::Value> cb = obj->Get(v8::String::New(cb_name.c_str()));
  if (cb->IsUndefined()) {
    LOG(ERROR) << "Object does not have property: "<< cb_name;
    return v8::Handle<v8::Value>();
  }

  if (!cb->IsFunction()) {
    LOG(ERROR) << "Property is not a function: " << cb_name;
    return v8::Handle<v8::Value>();
  }

  return v8::Handle<v8::Function>::Cast(cb)->Call(obj, argc, argv);
}

}  // namespace utils

}  // namespace entd
