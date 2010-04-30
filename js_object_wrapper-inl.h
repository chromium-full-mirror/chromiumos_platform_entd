// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ENTD_JS_OBJECT_WRAPPER_INL_H_
#define ENTD_JS_OBJECT_WRAPPER_INL_H_

//virtual
template<typename T>
bool JSObjectWrapper<T>::Initialize() {
  // Get the template, builiding it if necessary
  v8::Handle<v8::FunctionTemplate> t = GetTemplate();
  // Create a v8 Object from the template
  obj_ = v8::Persistent<v8::Object>::New(t->GetFunction()->NewInstance());
  // Associate it with the C++ Object
  obj_->SetPointerInInternalField(0, this);
  return true;
}

//static
template<typename T>
T* JSObjectWrapper<T>::Unwrap(v8::Handle<v8::Object> obj) {
  if (obj.IsEmpty() || !obj->IsObject())    // Make sure the argument is valid
    return NULL;
  if (!T::GetTemplate()->HasInstance(obj))  // Make sure it's of the right type
    return NULL;
  if (obj->InternalFieldCount() < 1)        // Paranoia; Should always be true
    return NULL;
  T* result = reinterpret_cast<T*>(obj->GetPointerFromInternalField(0));
  return result;
}

//static
template<typename T>
T* JSObjectWrapper<T>::GetFromArg(const v8::Arguments& args, int index) {
  T* result = NULL;
  if (args.Length() > index) {
    // Unwrap checks that the argument is really an object
    result = Unwrap(v8::Handle<v8::Object>::Cast(args[index]));
  }
  return result;
}

//static
template<typename T>
v8::Handle<v8::FunctionTemplate> JSObjectWrapper<T>::ManageTemplate(
    bool build) {
  // Store the template as a static function variable
  // This avoids the awkwardness of dealing with static template members
  static v8::Persistent<v8::FunctionTemplate> s_template;
  // Build the templete if necessary
  if (build && s_template.IsEmpty()) {
    v8::Handle<v8::FunctionTemplate> ft = v8::FunctionTemplate::New();
    s_template = v8::Persistent<v8::FunctionTemplate>::New(ft);
    s_template->SetClassName(v8::String::New(T::GetClassName()));
    v8::Handle<v8::ObjectTemplate> template_object =
        s_template->InstanceTemplate();
    template_object->SetInternalFieldCount(1);
    T::SetTemplateBindings(template_object);
  } else if (!build && !s_template.IsEmpty()) {
    s_template.Dispose();
  }
  return s_template;
}

#endif // ENTD_JS_OBJECT_WRAPPER_INL_H_
