// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Provides tools for searching for valid policy extensions.

#include "entd/extensions.h"

#include <algorithm>
#include <string>
#include <vector>

#include <base/basictypes.h>
#include <base/file_util.h>
#include <base/logging.h>

#include "entd/utils.h"

namespace entd {

namespace extensions {

const char* default_extensions_path =
    "${HOME}/.config/google-chrome/Default/Extensions";

// 1.1.2 > 1.1.1 > 1.1 > 0.9.9.9
static bool filename_greater(const std::string& a, const std::string& b) {
  std::string::size_type aidx=0, bidx=0;
  while(1) {
    std::string::size_type naidx = a.find_first_of(".", aidx);
    std::string::size_type nbidx = b.find_first_of(".", bidx);
    int alen = (naidx == std::string::npos ? std::string::npos : naidx-aidx);
    int blen = (nbidx == std::string::npos ? std::string::npos : nbidx-bidx);
    int aval = atoi(a.substr(aidx, alen).c_str());
    int bval = atoi(b.substr(bidx, blen).c_str());
    if (aval > bval)  // x.2 > x.1
      return true;
    if (aval < bval)  // x.1 < x.2
      return false;
    if (naidx == std::string::npos && nbidx == std::string::npos)
      return false;  // x == x
    if (nbidx == std::string::npos)
      return true;   // x.1 > x
    if (naidx == std::string::npos)
      return false;  // x < x.1
    aidx = naidx+1;
    bidx = nbidx+1;
  }
}

// Gather the names of files/dirs, in a directory, sort them,
// and return the first result.
static std::string find_latest_version_dir(const std::string& dirpath) {
  std::string result;
  std::vector<std::string> dirnames = utils::ReadDirectory(dirpath);
  if (dirnames.size() > 0) {
    std::nth_element(dirnames.begin(), dirnames.begin(), dirnames.end(),
                     filename_greater);
    result = dirpath + "/" + dirnames[0];
  }
  return result;
}

// Class for validating an existing extension directory.
class Extension {
 public:
  typedef std::vector<std::string> FileList;

  Extension(const std::string& path)
      : path_(path) {
    std::string::size_type slash2 = path_.find_last_of('/');
    std::string::size_type slash1 = path_.find_last_of('/', slash2-1);
    description_ = path_.substr(slash1+1, slash2-slash1-1);
    version_ = path_.substr(slash2+1);
  }

  // Set the list of requried policy files here
  static void InitPolicyFiles() {
    s_policy_files_.push_back("isa-cros-policy");
    s_policy_files_.push_back("policy.js");
    s_policy_files_.push_back("manifest.json");
  }

  // Look for required policy_files in the directory and if they exist,
  // call ValidatePolicy().
  bool ValidatePath() {
    if (s_policy_files_.empty())
      InitPolicyFiles();
    for (FileList::const_iterator iter = s_policy_files_.begin();
         iter != s_policy_files_.end(); ++iter) {
      FilePath filepath = FilePath(path_).Append(*iter);
      if (!file_util::PathExists(filepath)) {
        return false;
      }
    }
    return ValidatePolicy();
  }

  std::string path_;
  std::string description_;
  std::string version_;

 private:
  // Do specific policy validation here.
  bool ValidatePolicy() {
    // *TODO: Validate specific policy files.
    return true;
  }
  static FileList s_policy_files_;
};
// static
Extension::FileList Extension::s_policy_files_;


bool FindValidPolicy(const std::string& base_path,
                     std::string* extension_path) {
  std::string path = base_path;
  if (path.empty())
    path = default_extensions_path;
  // Expand "~" and any environment variables, e.g. "${HOME}"
  path = utils::ExpandFilePath(path);

  LOG(INFO) << "Looking for a policy extension in: " << path;

  // Generate a list of valid extensions
  std::vector<Extension> extensions;
  std::vector<std::string> dirnames = utils::ReadDirectory(path);
  for (std::vector<std::string>::iterator iter = dirnames.begin();
       iter != dirnames.end(); ++iter) {
    std::string dirpath = path + "/" + *iter;
    std::string latest_version_dir = find_latest_version_dir(dirpath);
    if (latest_version_dir.empty())
      continue;
    LOG(INFO) << " Considering: " << latest_version_dir;
    Extension e(latest_version_dir);
    if (e.ValidatePath())
      extensions.push_back(e);
  }

  // No extensions, return false
  if (extensions.size() == 0) {
    LOG(INFO) << "No valid policy extensions found in: " << path;
    return false;
  }

  // More than one extension, log an error and return false
  if (extensions.size() > 1) {
    LOG(ERROR) << "Multiple valid policy extensions found in: " << path;
    for (std::vector<Extension>::iterator iter = extensions.begin();
         iter != extensions.end(); ++iter) {
      LOG(ERROR) << "  " << (*iter).description_ << "/" << (*iter).version_;
    }
    return false;
  }

  // One extension found, set extension_path and return true
  LOG(INFO) << "Found policy extension: "
            << extensions[0].description_
            << ", Version: " << extensions[0].version_;

  std::string result = extensions[0].path_ + "/";
  *extension_path = result;
  return true;
}

}  // namespace extensions

}  // namespace entd
