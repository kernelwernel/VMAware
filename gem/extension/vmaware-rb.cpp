#include "vmaware-rb.hpp"
#include "vmaware.hpp"

/**
 * Two little wrappers so that the templated function is
 * compiled with this hardcoded option, and therefore
 * i dont need to use complex function overloading
 * when defining the ruby methods.
 **/
bool wrap_detect() {
  return VM::detect(VM::DEFAULT);
}

u_int8_t wrap_percentage() {
  return VM::percentage(VM::DEFAULT);
}



void Init_vmaware_rb() {
  Rice::Module rb_mVMAware = Rice::define_module("VMAware");

  Rice::Data_Type<VM> rb_cVM =  Rice::define_class_under<VM>(rb_mVMAware, "VM");
  
  rb_cVM.define_singleton_function("vm?", &wrap_detect);
  rb_cVM.define_singleton_function("confidence", &wrap_percentage);
}