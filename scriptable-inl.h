// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

namespace entd {

// static
template<typename T>
v8::Handle<v8::Value> Scriptable<T>::ThrowException(
    const std::string &msg) {
  v8::ThrowException(v8::Exception::Error(v8::String::New(msg.c_str())));
  return v8::Undefined();
}

// static
template<typename T>
typename Scriptable<T>::Reference Scriptable<T>::New() {
  T* native_ptr = new T();
  if (!native_ptr)
    return NULL;

  v8::Handle<v8::FunctionTemplate> ctor_t = T::constructor_template();

  // Swap out the InvocationCallback so we don't run the construct-from-script
  // logic for this.
  ctor_t->SetCallHandler(T::NativeConstruct);

  // Then construct the new JavaScript instance.
  v8::Handle<v8::Object> js_object = ctor_t->GetFunction()->NewInstance();

  // Finally, replace our InvocationCallback so script construction works
  // again.
  ctor_t->SetCallHandler(T::ScriptConstruct);

  if (js_object.IsEmpty()) {
    LOG(ERROR) << "Constructor for " << T::class_name() << " returned an "
        "empty instance.";
    return NULL;
  }

  if (!native_ptr->set_js_object(js_object)) {
    delete native_ptr;
    return NULL;
  }

  return Scriptable<T>::Reference(native_ptr);
}

// static
template<typename T>
bool Scriptable<T>::InitializeTemplate(
    v8::Handle<v8::FunctionTemplate> t) {
  LOG(WARNING) << "Base InitializeTemplate for " << T::class_name();
  return true;
}

// static
template<typename T>
void Scriptable<T>::BindMethod(v8::Handle<v8::Template> tpl,
                               Scriptable<T>::ScriptableMethod callback,
                               const char *name) {
  Dispatcher* dispatcher = new Dispatcher(callback);
  tpl->Set(v8::String::NewSymbol(name),
           v8::FunctionTemplate::New(Dispatcher::Callback,
                                     v8::External::Wrap(dispatcher)));
}

// static
template<typename T>
v8::Handle<v8::FunctionTemplate> Scriptable<T>::constructor_template() {
  // There's no way to know that we're done with this template.  At
  // any point someone could create a new instance of this class and
  // we'd need it again.  Therefore, it is never freed.
  static v8::Persistent<v8::FunctionTemplate> cached_template;

  if (cached_template.IsEmpty()) {
    cached_template =
        v8::Persistent<v8::FunctionTemplate>::New(
            v8::FunctionTemplate::New(T::ScriptConstruct));
    if (cached_template.IsEmpty())
      return cached_template;

    cached_template->SetClassName(v8::String::New(T::class_name().c_str()));
    cached_template->InstanceTemplate()->SetInternalFieldCount(1);

    if (!T::InitializeTemplate(cached_template)) {
      LOG(ERROR) << "Error setting up template for " << T::class_name();
      cached_template.Dispose();
    }

    v8::Handle<v8::Function> func = cached_template->GetFunction();
    func->SetAccessor(v8::String::New("instanceCount"),
                      Scriptable<T>::GetInstanceCount);

  }

  return cached_template;
}

// static
template<typename T>
v8::Handle<v8::Value> Scriptable<T>::NativeConstruct(
    const v8::Arguments& args) {
  return args.This();
}

// static
template<typename T>
v8::Handle<v8::Value> Scriptable<T>::ScriptConstruct(
    const v8::Arguments& args) {
  if (!args.IsConstructCall())
    return ThrowException("Function must be called as a constructor");

  v8::Handle<v8::Object> self = args.This();
  if (self.IsEmpty()) {
    return ThrowException("Error constructing " + T::class_name() +
                          ": 'this' object is missing");
  }

  T* native_object = new T();
  if (!native_object->set_js_object(self)) {
    // This should never happen.  It would mean that v8 constructed a `this`
    // object of the wrong class.  If you get here, you probably connected
    // this Construct function directly to a v8 function, with something
    // like...
    //
    //   obj->Set(String("Foo"), FunctionTemplate::New(Foo::Construct))
    //
    // DON'T DO THAT.  Instead, connect T::constructor_template(), as in...
    //
    //   obj->Set(String("Foo"), Foo::constructor_template())
    //
    delete native_object;
    ThrowException("Unexpected error initializing: " + T::class_name());
  }

  return native_object->Construct(args);
}

// static
template<typename T>
T* Scriptable<T>::Unwrap(const v8::Handle<v8::Value>& value) {
  if (value.IsEmpty() || !value->IsObject())
    return NULL;

  v8::Handle<v8::Object> object = value->ToObject();

  v8::Handle<v8::FunctionTemplate> t = T::constructor_template();
  if (t.IsEmpty() || !t->HasInstance(object))
    return NULL;

  return reinterpret_cast<T*>(object->GetPointerFromInternalField(0));
}

// static
template<typename T>
T* Scriptable<T>::UnwrapOrThrow(const v8::Handle<v8::Value>& value,
                                const std::string& desc) {
  T* rv = Unwrap(value);
  if (!rv) {
    std::string msg("Expected object of type '" + T::class_name() + "'");
    if (!desc.empty())
      msg.append(": " + desc);

    ThrowException(msg);
  }

  return rv;
}

// static
template<typename T>
T* Scriptable<T>::UnwrapOrWarn(const v8::Handle<v8::Value>& value,
                               const std::string& desc) {
  T* rv = Unwrap(value);
  if (!rv) {
    std::string msg("Expected object of type '" + T::class_name() + "'");
    if (!desc.empty())
      msg.append(": " + desc);

    LOG(WARNING) << msg;
  }

  return rv;
}

template<typename T>
bool Scriptable<T>::set_js_object(v8::Handle<v8::Object> js_object) {
  if (!js_object_.IsEmpty()) {
    LOG(ERROR) << "Attempt to change " << T::class_name() <<
        " js_object of existing instance.";
    return false;
  }

  if (js_object.IsEmpty()) {
    LOG(ERROR) << "Attempt to set " << T::class_name() <<
        " js_object to an empty handle.";
    return false;
  }

  v8::Handle<v8::FunctionTemplate> t = T::constructor_template();
  if (t.IsEmpty() || !t->HasInstance(js_object)) {
    LOG(ERROR) << "Attempt to set a js_object of the wrong class, " <<
        "expected: " << T::class_name();
    return false;
  }

  js_object_ = v8::Persistent<v8::Object>::New(js_object);
  js_object_->SetPointerInInternalField(0, this);
  js_object_.MakeWeak(NULL, Scriptable<T>::Harakiri);

  return true;
}

}  // namespace entd
