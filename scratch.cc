
#define V8_METHOD(className, method, argc)                                    \
static v8::Handle<v8::Value>                                                  \
   _v8_##method(const v8::Arguments &args) {                                  \
  void *ptr = ::entd::utils::CheckV8Method(args, #className, argc);           \
  if (!ptr) return ::v8::Undefined();                                         \
  return reinterpret_cast<className*>(ptr)->method(args);                     \
}                                                                             \
v8::Handle<v8::Value> method(const v8::Arguments &args);


// Verify that the v8 is invoking the method on the correct object and
// that it has the correct minimum number of arguments.  Returns a pointer
// to the instance object on success.  Throws a v8 exception and returns
// NULL on failure.
void* CheckV8Method(const v8::Arguments& args, const char *className,
                    int arg_count);


void* CheckV8Method(const Arguments& args, char *className, int arg_count) {
  if (args.This()->GetHiddenValue(v8::String::New(className)) != True()) {
    ThrowException(String::New("Method invoked on wrong object"));
    return NULL;
  }

  if (args.Length() < arg_count) {
    ThrowException(String::New("Not enough arguments"));
    return NULL;
  }

  return args.This()->GetPointerFromInternalField(0);
}
