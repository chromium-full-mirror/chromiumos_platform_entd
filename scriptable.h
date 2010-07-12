// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ENTD_SCRIPTABLE_H_
#define ENTD_SCRIPTABLE_H_

#include "base/logging.h"
#include "v8.h"

namespace entd {

// Base class for objects that are scriptable from v8.
//
// Subclasses should use a pattern like...
//
//   class Foo : public Scriptable<Foo> {
//      static const std::string class_name() { return "Foo"; }
//      ...
//   }
//
// These classes need your help to stay alive!  The lifetime of the
// reference counted scriptable object and the lifetime of the native object
// are connected.  When there are no remaining references on the script side,
// the native object will be automatically deleted.
//
// Therefore:
//   * Never pass a bare pointer to a function unless you are also maintaining
//     a reference to the v8 object.  That function might trigger a V8 garbage
//     collection which might delete the scriptable object.
//
//   * Never hold on to a bare pointer to a scriptable object for longer than
//     a function call.  It may be deleted out from under you during the next
//     V8 garbage collection cycle.
//
//   * Never allocate a scriptable object on the stack.  If they are deleted
//     while JavaScript references remain, you'll crash.
//
//   * Never use the `delete` operator on a scriptable object.  See above.
//
// You can safely hold on to a Scriptable object using a Scriptable::Reference.
// Holding one of these reference objects ensures that you have a
// v8::Persistent handle keeping your object alive.  Some examples...
//
//   // Construct a new Foo instance, and return it in a Foo::Reference which
//   // will ensure that the instance is kept alive.
//   Foo::Reference foo = Foo::New();
//
//   // If the Foo class requires some additional initialization, do it now.
//   // The -> operator works on the underlying Foo*.
//   foo->Initialize(...);
//
//   ModifyFoo(foo.native_ptr());  // Pass a bare Foo* to ModifyFoo()
//   ReadFoo(foo.native_ref());    // Pass a const Foo& to ReadFoo()
//
//   // If you have a reference already, you can use the copy constructor to
//   // make another one.
//   Foo::Reference foo_2(foo);
//
//   // You can also pass a native object to the Reference constructor to get
//   // a new reference.
//   Foo* foo_ptr = foo.native_ptr();
//   Foo::Reference foo_3(foo_ptr);
//
// See the documentation for ::Construct() for an example of how to complete
// script-based instantiation of a Scriptable object, and how to unwrap the
// Foo* from a Handle<Object> containing one.
//
template<typename T>
class Scriptable {
 public:

  // Utility class to manage a reference to a Scriptable object.
  //
  // Use this class to ensure that you have a persistent handle keeping your
  // scriptable object alive.
  class Reference {
   public:
    // Construct from a JS Object.
    //
    // This may 'fail' if the provided value is not a JavaScript object or the
    // object is not an instance of Scriptable<T>::constructor_template.
    // Make sure to test IsEmpty() after construction.
    Reference(const v8::Handle<v8::Value>& js_object) {
      set_js_object(js_object);
    }

    // Construct from a native instance of a Scriptable<T>.
    Reference(T* native_ptr) { set_native_ptr(native_ptr); }

    // Copy constructor.
    Reference(const Reference& source) {
      set_native_ptr(source.native_ptr());
    }

    // Dispose of the persistent handle when the reference dies.
    ~Reference() { if (!js_object_.IsEmpty()) js_object_.Dispose(); }

    // Arrow operator gives quick access to the native pointer.
    T* operator->() const { return native_ptr_; }

    // Returns true if the reference has not been initialized.
    bool IsEmpty() const { return native_ptr_ == NULL; }

    // Change the referent by JavaScript value.
    //
    // Returns false if the provided value is not an object or is not
    // an instance of Scriptable<T>::constructor_template.
    //
    // Releives the previous referent, even if the assignment fails.
    bool set_js_object(v8::Handle<v8::Value> value) {
      if (!js_object_.IsEmpty())
        js_object_.Dispose();

      native_ptr_ = T::Unwrap(value);
      if (!native_ptr_)
        return false;

      js_object_ = v8::Persistent<v8::Object>::New(native_ptr_->js_object());
      return true;
    }

    // Return the JavaScript object referred to by this reference.
    v8::Handle<v8::Object> js_object() const { return js_object_; }

    // Change the referent by native pointer, Releiving the previous referent.
    void set_native_ptr(T* native_ptr) {
      if (!js_object_.IsEmpty())
        js_object_.Dispose();

      if (native_ptr)
        js_object_ = v8::Persistent<v8::Object>::New(native_ptr->js_object());
      native_ptr_ = native_ptr;
    }

    // Return the native pointer referred to by this reference.
    T* native_ptr() const { return native_ptr_; }

    // Return a const reference to the native object referred to by this
    // reference.
    const T& native_ref() const { return *native_ptr_; }

   private:
    Reference() {}

    T* native_ptr_ ;
    v8::Persistent<v8::Object> js_object_;
  };

  // Construct a new instance of this class.
  static Scriptable<T>::Reference New();

  // Convienence function to throw an exception object with a given
  // message.
  static v8::Handle<v8::Value> ThrowException(const std::string &msg);

  // Static method to give a name to this class for debugging purposes.
  // This should be defined to return a unique name for your class, such
  // as "Foo" for a class located on the global script object, or
  // "foo.bar.AwesomeClass" for one located further down the object model.
  static const std::string class_name() { return "MISSING_CLASS_NAME"; }

  // Returns a singleton reference to the v8 function template for this class.
  // If your object is intended to be constructed from JavaScript, you
  // should connect this template to the name of your constructor function.
  // For example, to allow `var foo = new Foo()` from JavaScript...
  //
  //  class Foo : public Scriptable<Foo> { ... }
  //
  //  Context cx Context::New();
  //  Handle<Object> global = cx->Global();
  //  global->Set(String::New("Foo"), Foo::constructor_template());
  //
  // Do not override this in your subclass.  In the likely event that you
  // want to customize your constructor, override (but call the default
  // implementation of) InitializeTemplate() instead.  See below for more
  // details.
  static v8::Handle<v8::FunctionTemplate> constructor_template();

  // Initialize the constructor template for this class.
  //
  // This static method will be called once, the first time someone tries to
  // construct an instance of this class.  You should perform one-time
  // initialization of the FunctionTemplate (or, more typically,
  // FunctionTemplate::InstanceTemplate()) here.
  //
  // If you need to perform instance specific initialization, override
  // T::Construct() instead.  See the Construct() method below for more
  // details.
  static bool InitializeTemplate(v8::Handle<v8::FunctionTemplate> ctor);

  // Fetch the native object associated with a JS value.
  //
  // Returns NULL if the given value is not a JavaScript Object, or is not
  // an instance of the constructor_template defined by this class.
  static T* Unwrap(const v8::Handle<v8::Value>& value);

  // Same as Unwrap, except throws a JS exception on failure.
  //
  // The `desc` parameter should be a string containing additional context
  // for the exception message.  For example, if desc was "second parameter",
  // then the exception message might be "Expected object of type 'Foo':
  // second parameter"
  static T* UnwrapOrThrow(const v8::Handle<v8::Value>& value,
                          const std::string& desc);

  // Return true if the given JavaScript value represents an instance of
  // this class.
  static bool IsInstance(const v8::Handle<v8::Value>& value) {
    return Unwrap(value) != NULL;
  }

  // Return the JavaScript object for this instance.
  virtual v8::Handle<v8::Object> js_object() const { return js_object_; }

  // Keep track of the number of instances of this class that are currently
  // alive.
  //
  // This is here to help detect leaks that can happen when these objects are
  // improperly handled.  This method is exposed to script as the
  // 'instanceCount' property of the constructor function.
  //
  // Pass +1 to increment the count, -1 to decrement, and 0 to read.  But
  // only if you know what you're doing.
  static int InstanceCount(int delta) {
    static int i = 0;
    return i += delta;
  }

  // Associate this instance with a given JavaScript Object.
  //
  // You should not have to call this function directly.  Leave the
  // details to T::New() or Scriptable::Construct() deal with it.
  //
  // Returns false if the the js_object is not an instance of the
  // constructor_template defined by this class, or if the instance has
  // already been associated with a JavaScript object.
  virtual bool set_js_object(v8::Handle<v8::Object> js_object);

 protected:
  // Complete the construction of a new instance of this class from JavaScript.
  //
  // You should override this if you need to parse constructor arguments, or if
  // you want to assign functions or properties that are specific to this
  // instance.
  //
  // Your custom Construct method might look something like...
  //
  // static Handle<Value> Foo::Construct(const Arguments& args) {
  //   if (args.Length > 0) {
  //     // Throw an exception and return Undefined() if things don't go
  //     // well.
  //     return ThrowException("Expected no arguments");
  //   }
  //
  //   // Get the JS Object representing `this`, so we can add properties
  //   // and stuff.
  //   v8::Handle<v8::Object> self = value->ToObject();
  //
  //   // Get the native object associated with `this`, so we can complete
  //   // its initialization.
  //   Foo* foo_ptr = Foo::Unwrap(self);
  //
  //   // Perform some Foo specific initialization...
  //   foo_ptr->Initialize(...);
  //
  //   // Make sure to return the new instance on success...
  //   return value;
  // }
  //
  static v8::Handle<v8::Value> Construct(const v8::Arguments& args) {
    return args.This();
  };

  // Set up the construction of a new instance of this class from JavaScript.
  //
  // This ensures that the constructor was called with the JavaScript 'new'
  // operator, and associates the new JavaScript object with a fresh native
  // instance of this class.  Once that's done, it calls T::Construct(args)
  // to perform any class specific initiation, and returns whatever
  // T::Construct returns.
  //
  // You won't need to override this unless you run into a case where you want
  // the constructor to also be callable as a normal function, without 'new'.
  //
  // This is hooked up to the InvocationCallback of T::constructor_template
  // by default.
  static v8::Handle<v8::Value> BaseConstruct(const v8::Arguments& args);

  // Called when the internal weak reference to the JavaScript face of this
  // object has indicated there are no more references.  This will delete
  // the native instance.
  static void Harakiri(v8::Persistent<v8::Value> object, void* parameter) {
    T* instance = Unwrap(object);
    delete instance;
  }

  Scriptable() { Scriptable<T>::InstanceCount(+1); }
  virtual ~Scriptable() { Scriptable<T>::InstanceCount(-1); }

 private:
  // Reference to the JavaScript notion of this instance.  This is a weak
  // reference and will not partake in keeping this object alive.
  v8::Persistent<v8::Object> js_object_;

  // This is hooked up to the constructor in JavaScript as Foo.instanceCount,
  // so that testcases can detect leaks.
  static v8::Handle<v8::Value> GetInstanceCount(v8::Local<v8::String> name,
                                                const v8::AccessorInfo& info) {
    return v8::Integer::New(Scriptable<T>::InstanceCount(0));
  }

  DISALLOW_COPY_AND_ASSIGN(Scriptable<T>);
};

}  // namespace entd

#include "scriptable-inl.h"

#endif  // ENTD_SCRIPTABLE_H_
