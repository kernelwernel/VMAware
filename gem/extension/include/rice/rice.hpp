// This file is part of [rice](https://github.com/ruby-rice/rice).
//
// Copyright (C) 2025 Jason Roelofs <jasongroelofs@gmail.com>
//                    Paul Brannan <curlypaul924@gmail.com>,
//                    Charlie Savage
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
// OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
// IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
// NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
// THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#ifndef Rice__hpp_
#define Rice__hpp_

// Ruby

// =========   ruby.hpp   =========

/*! \file
 * \brief Hacks for addressing incompatibilities between various Ruby
 * versions.
 */

#include <cmath>

// Clang has to be first because on Windows it defines _MSC_VER too
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunknown-pragmas"
#pragma clang diagnostic ignored "-Wunused-parameter"
#elif defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable: 4100)  // unreferenced formal parameter
#pragma warning(disable: 4702)  // unreachable code
#elif defined(__GNUC__ )
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunknown-pragmas"
#endif

#include <ruby/version.h>
#include <ruby.h>
#include <ruby/encoding.h>
#include <ruby/thread.h>

// Clang has to be first because on Windows it defines _MSC_VER too
#if defined(__clang__)
#pragma clang diagnostic pop
#elif defined(_MSC_VER)
#pragma warning(pop)
#elif defined(__GNUC__ )
#pragma GCC diagnostic pop
#endif

// ruby.h has a few defines that conflict with Visual Studio's STL
#if defined(_MSC_VER)
#undef write
#undef read
#undef bind
#endif

// And some c library conflicts
#undef isnan
#undef snprintf
#undef vsnprintf

//! A function that takes a VALUE as a parameter and returns a VALUE.
// TODO: Casting from a C++ function to an extern "C" function won't
// work on all platforms.  I'm not sure what to do about this.
extern "C" typedef VALUE (*RUBY_VALUE_FUNC)(VALUE);

// Fix Ruby RUBY_METHOD_FUNC from macro to typedef
#if defined(RUBY_METHOD_FUNC)
# undef RUBY_METHOD_FUNC
  extern "C" typedef VALUE (*RUBY_METHOD_FUNC)(ANYARGS);
#endif



// C++ headers have to come after Ruby on MacOS for reasons I do not understand
#include <cstdio>
#include <cstring> // For std::memset
#include <map>
#include <string>
#include <typeinfo>
#include <typeindex>

#ifdef _MSC_VER
  // Prevent _strdup deprecated message on MSVC
  #define strdup _strdup 
#endif

// Traits

// =========   rice_traits.hpp   =========

#include <complex>
#include <ostream>
#include <tuple>
#include <type_traits>
#include <variant>
#include <vector>

namespace Rice
{
  namespace detail
  {
    // Get the base_type of T - without pointer, reference, const or volatile. We call remove_pointer_t twice 
    // for T**
    template<typename T>
    using intrinsic_type = typename std::remove_cv_t<std::remove_pointer_t<std::remove_pointer_t<std::remove_reference_t<T>>>>;

    template<typename T>
    constexpr bool is_const_any_v = std::is_const_v<std::remove_pointer_t<std::remove_pointer_t<std::remove_reference_t<T>>>>;

    // Helper to detect char types
    template<typename T>
    constexpr bool is_char_type_v = std::is_same_v<T, char> || std::is_same_v<T, signed char> || std::is_same_v<T, unsigned char>;

    // Recursively remove const/volatile
    template<typename T>
    struct remove_cv_recursive
    {
      using type = T;
    };

    template<typename T>
    struct remove_cv_recursive<T const volatile>
    {
      using type = typename remove_cv_recursive<T>::type;
    };

    template<typename T>
    struct remove_cv_recursive<T volatile>
    {
      using type = typename remove_cv_recursive<T>::type;
    };

    template<typename T>
    struct remove_cv_recursive<T const>
    {
      using type = typename remove_cv_recursive<T>::type;
    };

    template<typename T>
    struct remove_cv_recursive<T&>
    {
      using type = typename remove_cv_recursive<T>::type&;
    };

    template<typename T>
    struct remove_cv_recursive<T&&>
    {
      using type = typename remove_cv_recursive<T>::type&&;
    };

    template<typename T>
    struct remove_cv_recursive<T*>
    {
      using type = typename remove_cv_recursive<T>::type*;
    };

    template<typename T>
    using remove_cv_recursive_t = typename remove_cv_recursive<T>::type;

    // Does the Type work with ostreams? This is used to implement #to_s
    template<typename T, typename = void>
    struct is_ostreamable : std::false_type {};

    template<typename T>
    struct is_ostreamable<T, std::void_t<decltype(std::declval<std::ostream&>() << std::declval<const T>())>> : std::true_type {};

    template<typename T>
    constexpr bool is_ostreamable_v = is_ostreamable<T>::value;

    // Is the type comparable?
    template<typename T, typename SFINAE = void>
    struct is_comparable : std::false_type {};

    template<typename T>
    struct is_comparable<T, std::void_t<
      // Does the class implement operator== and does it return a boolean value?
      decltype(std::declval<T>() == std::declval<T>() && true)
      >> : std::true_type {};

    template<typename T>
    constexpr bool is_comparable_v = is_comparable<T>::value;

    template <typename U, typename V>
    struct is_comparable<std::pair<U, V>>
    {
      static const bool value = is_comparable_v<U> && is_comparable_v<V>;
    };

    template <typename T>
    struct is_comparable<std::vector<T>>
    {
      static const bool value = is_comparable_v<T>;
    };

    template<typename>
    struct is_std_vector : std::false_type {};

    template<typename T, typename A>
    struct is_std_vector<std::vector<T, A>> : std::true_type {};

    template <typename T>
    constexpr bool is_std_vector_v = is_std_vector<T>::value;

    template<typename>
    struct is_std_complex : std::false_type {};

    template<typename T>
    struct is_std_complex<std::complex<T>> : std::true_type {};

    template <typename T>
    constexpr bool is_std_complex_v = is_std_complex<T>::value;

    template<class T>
    struct is_pointer_pointer : std::false_type {};

    template<class T>
    struct is_pointer_pointer<T**> : std::true_type {};

    template<class T>
    struct is_pointer_pointer<T** const> : std::true_type {};

    template<class T>
    struct is_pointer_pointer<T* const * const> : std::true_type {};

    template<class T>
    struct is_pointer_pointer<const T* const* const> : std::true_type {};

    template<class T>
    constexpr bool is_pointer_pointer_v = is_pointer_pointer<T>::value;

    // See https://www.cppstories.com/2022/tuple-iteration-apply/
    template <typename Tuple_T, typename Function_T>
    void for_each_tuple(Tuple_T&& tuple, Function_T&& callable)
    {
      std::apply([&callable](auto&& ...args)
        {
          (callable(std::forward<decltype(args)>(args)), ...);
        }, std::forward<Tuple_T>(tuple));
    }

    // Detect if a type is complete (has a known size) or incomplete (forward-declared only)
    template<typename T, typename = void>
    struct is_complete : std::false_type {};

    template<typename T>
    struct is_complete<T, std::void_t<decltype(sizeof(T))>> : std::true_type {};

    template<typename T>
    constexpr bool is_complete_v = is_complete<T>::value;

    template<typename T, typename = void>
    struct is_wrapped : std::true_type {};

    template<typename T>
    struct is_wrapped<T, std::enable_if_t<std::is_fundamental_v<detail::intrinsic_type<T>> ||
                                          std::is_same_v<detail::intrinsic_type<T>, std::string> ||
                                          is_std_complex_v<T>>
                     >: std::false_type {};

    template<typename T>
    constexpr bool is_wrapped_v = is_wrapped<T>::value;

    // ---------- RubyKlass ------------
    template<typename, typename = std::void_t<>>
    struct has_ruby_klass : std::false_type
    {
    };

    template<typename T>
    struct has_ruby_klass<T, std::void_t<decltype(T::rubyKlass())>> : std::true_type
    {
    };

    // -- Tuple Helpers ---
    template<typename T>
    struct tuple_shift;

    template<typename T, typename...Parameter_Ts>
    struct tuple_shift<std::tuple<T, Parameter_Ts...>>
    {
      using type = std::tuple<Parameter_Ts...>;
    };

    template<typename T, typename...Parameter_Ts>
    struct tuple_unshift;

    template<typename T, typename...Parameter_Ts>
    struct tuple_unshift<T, std::tuple<Parameter_Ts...>>
    {
      using type = std::tuple<T, Parameter_Ts...>;
    };

    template<template<typename, typename...> typename T, typename...Parameter_Ts>
    struct tuple_map;

    template<template<typename, typename...> typename T, typename...Parameter_Ts>
    struct tuple_map<T, std::tuple<Parameter_Ts...>>
    {
      using type = std::tuple<T<Parameter_Ts>...>;
    };

    template<typename...Parameter_Ts>
    struct tuple_to_variant;

    template<typename...Parameter_Ts>
    struct tuple_to_variant<std::tuple<Parameter_Ts...>>
    {
      using type = std::variant<Parameter_Ts...>;
    };

    template <typename T, typename... List>
    struct is_one_of : std::disjunction<std::is_same<T, List>...> {};

    template <typename T, typename... List>
    constexpr bool is_one_of_v = is_one_of<T, List...>::value;

    template<typename... FilterTypes, typename... Arg_Ts>
    auto tuple_filter(const Arg_Ts&... args)
    {
      return std::tuple_cat([&args]()
        {
          if constexpr (is_one_of_v<Arg_Ts, FilterTypes...>)
          {
            return std::tuple<const Arg_Ts&>(args);
          }
          else
          {
            return std::tuple<>();
          }
        }()...);
    };

    // --- filter_types: recursively builds a new tuple of allowed types ---
    template <typename Tuple, typename... Allowed>
    struct tuple_filter_types;

    template <typename... Ts, typename... Allowed>
    struct tuple_filter_types<std::tuple<Ts...>, Allowed...>
    {
      using type = decltype(std::tuple_cat(std::declval<
        std::conditional_t<is_one_of_v<std::decay_t<Ts>, Allowed...>, std::tuple<Ts>, std::tuple<>>>()...));
    };

    template <typename Tuple, typename... Allowed>
    using tuple_filter_types_t = typename tuple_filter_types<Tuple, Allowed...>::type;

    template <typename T, std::size_t... Is>
    auto vector_to_tuple(const std::vector<T>& vec, std::index_sequence<Is...>)
    {
      return std::make_tuple(vec[Is]...);
    }

    template <typename Tuple, typename T, typename Seq>
    struct tuple_pad_type;

    template <typename... Ts, typename T, std::size_t... Is>
    struct tuple_pad_type<std::tuple<Ts...>, T, std::index_sequence<Is...>>
    {
      // Use Is only to repeat T N times.
      // std::conditional_t<true, T, something<Is>> is always T, but expands N times.
      using type = std::tuple<
        Ts...,
        std::conditional_t<true, T, std::integral_constant<std::size_t, Is>>...
      >;
    };

    template <typename Tuple, typename T, std::size_t N>
    using tuple_pad_type_t = typename tuple_pad_type<Tuple, T, std::make_index_sequence<N>>::type;

    // Pad tuple with values from a vector (vector size must match N)
    template <std::size_t N, typename T, typename... Ts>
    auto pad_tuple(const std::tuple<Ts...>& original, const std::vector<T>& padding)
    {
      if (padding.size() != N)
      {
        throw std::invalid_argument("Vector size doesn't match template parameter N");
      }

      auto padding_tuple = vector_to_tuple(padding, std::make_index_sequence<N>{});
      return std::tuple_cat(original, padding_tuple);
    }

    template <typename Tuple, typename... Ts>
    struct tuple_element_index_impl;

    template <typename... Ts>
    struct tuple_element_index_impl<std::tuple<>, Ts...>
    {
      static constexpr std::size_t value = 0;
    };

    template <typename First, typename... Rest, typename... Ts>
    struct tuple_element_index_impl<std::tuple<First, Rest...>, Ts...>
    {
      static constexpr bool matches = (std::is_same_v<std::decay_t<First>, Ts> || ...);
      static constexpr std::size_t value =
        matches ? 0 : 1 + tuple_element_index_impl<std::tuple<Rest...>, Ts...>::value;
    };

    template <typename Tuple, typename... Ts>
    struct tuple_element_index
    {
      static constexpr std::size_t value = tuple_element_index_impl<Tuple, Ts...>::value;
    };

    template <typename Tuple, typename... Ts>
    inline constexpr std::size_t tuple_element_index_v = tuple_element_index<Tuple, Ts...>::value;

    /* template<typename Target, typename T>
     constexpr auto tuple_predicate(T&& element)
     {
       using U = std::decay_t<T>;
       if constexpr (std::is_same_v<U, Target>)
       {
         return std::tuple<U>{ std::forward<T>(element) };
       }
       else
       {
         return std::tuple<>{};
       }
     }

     template<typename Class_T, typename... Ts>
     constexpr auto tuple_filter(Ts&&... args)
     {
       return std::tuple_cat(tuple_predicate<Class_T>(std::forward<Ts>(args))...);
     }*/



  } // detail
} // Rice


// =========   function_traits.hpp   =========

#include <tuple>

namespace Rice::detail
{
  // Base class
  template<typename Function_T>
  struct function_traits;

  template<typename Return_T, typename Class_T, typename...Parameter_Ts>
  struct function_traits<Return_T(Class_T, Parameter_Ts...)>
  {
    using arg_types = std::tuple<Parameter_Ts...>;

    static constexpr std::size_t arity = sizeof...(Parameter_Ts);

    template<std::size_t N>
    using nth_arg = typename std::tuple_element_t<N, arg_types>;

    using return_type = Return_T;
    using class_type = Class_T;
  };

  // Functors and lambdas with operator()
  template<typename Function_T>
  struct function_traits : public function_traits<decltype(&Function_T::operator())>
  {
  private:
    using functor_t = function_traits<decltype(&Function_T::operator())>;

  public:
    using arg_types = typename functor_t::arg_types;
    static constexpr std::size_t arity = functor_t::arity;
    using class_type = std::nullptr_t;
  };

  // Lvalue references to functors and lambdas - strip the reference and defer
  // to the base functor specialization. This allows named lambda variables (lvalues)
  // to be passed to define_method in addition to inline temporaries (rvalues).
  template<typename Function_T>
  struct function_traits<Function_T&> : public function_traits<Function_T>
  {
  };

  // C functions and static member functions passed by pointer
  template<typename Return_T, typename ...Parameter_Ts>
  struct function_traits<Return_T(*)(Parameter_Ts...)> : public function_traits<Return_T(std::nullptr_t, Parameter_Ts...)>
  {
    using Function_T = Return_T(*)(Parameter_Ts...);
  };

  // noexcept C functions and static member functions passed by pointer
  template<typename Return_T, typename ...Parameter_Ts>
  struct function_traits<Return_T(*)(Parameter_Ts...) noexcept> : public function_traits<Return_T(std::nullptr_t, Parameter_Ts...)>
  {
    using Function_T = Return_T(*)(Parameter_Ts...) noexcept;
  };

  // C functions passed by pointer that take one or more defined parameter than a variable
  // number of parameters (the second ...)
  template<typename Return_T, typename ...Parameter_Ts>
  struct function_traits<Return_T(*)(Parameter_Ts..., ...)> : public function_traits<Return_T(std::nullptr_t, Parameter_Ts...)>
  {
  };

  // C Functions or static member functions passed by reference
  template<typename Return_T, typename ...Parameter_Ts>
  struct function_traits<Return_T(&)(Parameter_Ts...)> : public function_traits<Return_T(std::nullptr_t, Parameter_Ts...)>
  {
  };

  // noexcept C functions or static member functions passed by reference
  template<typename Return_T, typename ...Parameter_Ts>
  struct function_traits<Return_T(&)(Parameter_Ts...) noexcept> : public function_traits<Return_T(std::nullptr_t, Parameter_Ts...)>
  {
  };

  // Member Functions on C++ classes
  template<typename Return_T, typename Class_T, typename...Parameter_Ts>
  struct function_traits<Return_T(Class_T::*)(Parameter_Ts...)> : public function_traits<Return_T(Class_T*, Parameter_Ts...)>
  {
  };

  // const member Functions on C++ classes
  template<typename Return_T, typename Class_T, typename...Parameter_Ts>
  struct function_traits<Return_T(Class_T::*)(Parameter_Ts...) const> : public function_traits<Return_T(Class_T*, Parameter_Ts...)>
  {
  };

  // noexcept member Functions on C++ classes
  template<typename Return_T, typename Class_T, typename...Parameter_Ts>
  struct function_traits<Return_T(Class_T::*)(Parameter_Ts...) noexcept> : public function_traits<Return_T(Class_T*, Parameter_Ts...)>
  {
  };


  // const noexcept member Functions on C++ classes
  template<typename Return_T, typename Class_T, typename...Parameter_Ts>
  struct function_traits<Return_T(Class_T::*)(Parameter_Ts...) const noexcept> : public function_traits<Return_T(Class_T*, Parameter_Ts...)>
  {
  };

  // ref-qualified member Functions on C++ classes (C++20 uses these for std library types)
  template<typename Return_T, typename Class_T, typename...Parameter_Ts>
  struct function_traits<Return_T(Class_T::*)(Parameter_Ts...) &> : public function_traits<Return_T(Class_T*, Parameter_Ts...)>
  {
  };

  template<typename Return_T, typename Class_T, typename...Parameter_Ts>
  struct function_traits<Return_T(Class_T::*)(Parameter_Ts...) const&> : public function_traits<Return_T(Class_T*, Parameter_Ts...)>
  {
  };

  template<typename Return_T, typename Class_T, typename...Parameter_Ts>
  struct function_traits<Return_T(Class_T::*)(Parameter_Ts...) & noexcept> : public function_traits<Return_T(Class_T*, Parameter_Ts...)>
  {
  };

  template<typename Return_T, typename Class_T, typename...Parameter_Ts>
  struct function_traits<Return_T(Class_T::*)(Parameter_Ts...) const& noexcept> : public function_traits<Return_T(Class_T*, Parameter_Ts...)>
  {
  };

  /*// Functors and lambdas
  template<class Function_T>
  struct function_traits<Function_T&> : public function_traits<Function_T>
  {
  };

  template<class Function_T>
  struct function_traits<Function_T&&> : public function_traits<Function_T>
  {
  };*/
}

// =========   method_traits.hpp   =========

#include <tuple>

namespace Rice::detail
{
  // Declare struct
  template<typename Function_T, typename = void>
  struct method_traits;

  /* Functions that have a self parameter and thus we treat them as free standing
    "methods" versus member functions. 
    
       doSomething(VALUE self, int a) */
  template<typename Function_T>
  struct method_traits<Function_T, std::enable_if_t<std::is_same_v<typename function_traits<Function_T>::class_type, std::nullptr_t>>>
  {
    using Return_T = typename function_traits<Function_T>::return_type;
    using Class_T = typename function_traits<Function_T>::template nth_arg<0>;
    using Parameter_Ts = typename tuple_shift<typename function_traits<Function_T>::arg_types>::type;
    static constexpr std::size_t arity = std::tuple_size_v<Parameter_Ts>;
  };

  // Member functions that have an implied self parameter of an object instance
  //   foo.doSomething(int a)
  template<typename Function_T>
  struct method_traits<Function_T, std::enable_if_t<!std::is_same_v<typename function_traits<Function_T>::class_type, std::nullptr_t>>>
  {
    using Return_T = typename function_traits<Function_T>::return_type;
    using Class_T = typename function_traits<Function_T>::class_type;
    using Parameter_Ts = typename function_traits<Function_T>::arg_types;
    static constexpr std::size_t arity = std::tuple_size_v<Parameter_Ts>;
  };
}

// =========   attribute_traits.hpp   =========

#include <tuple>

namespace Rice::detail
{
  // Base class
  template<typename Attribute_T>
  struct attribute_traits;

  template<typename Attribute_T>
  struct attribute_traits<Attribute_T*>
  {
    using attr_type = Attribute_T;
    using class_type = std::nullptr_t;
  };

  template<typename Attribute_T, typename Class_T>
  struct attribute_traits<Attribute_T(Class_T::*)>
  {
    using attr_type = Attribute_T;
    using class_type = Class_T;
  };
}

// Wrap C++ objects as Ruby objects

// =========   Wrapper.hpp   =========

namespace Rice::detail
{
  class WrapperBase
  {
  public:
    static void addKeepAlive(VALUE object, VALUE keepAlive);
    static bool isConst(VALUE object);

  public:
    WrapperBase(rb_data_type_t* rb_data_type);
    virtual ~WrapperBase() = default;
    virtual void* get(rb_data_type_t* requestedType) = 0;
    bool isConst();

    void ruby_mark();
    void addKeepAlive(VALUE value);
    const std::vector<VALUE>& getKeepAlive() const;
    void setKeepAlive(const std::vector<VALUE>& keepAlive);
    void setOwner(bool value);

  protected:
    rb_data_type_t* rb_data_type_;
    bool isOwner_ = false;
    bool isConst_ = false;

  private:
    // We use a vector for speed and memory locality versus a set which does
    // not scale well when getting to tens of thousands of objects (not expecting
    // that to happen...but just in case)
    std::vector<VALUE> keepAlive_;
  };

  template <typename T>
  class Wrapper : public WrapperBase
  {
  public:
    Wrapper(rb_data_type_t* rb_data_type, T& data);
    Wrapper(rb_data_type_t* rb_data_type, T&& data);
    ~Wrapper() = default;
    void* get(rb_data_type_t* requestedType) override;

  private:
    T data_;
  };

  template<typename T>
  class Wrapper<T&> : public WrapperBase
  {
  public:
    Wrapper(rb_data_type_t* rb_data_type, T& data);
    ~Wrapper();
    void* get(rb_data_type_t* requestedType) override;

  private:
    T& data_;
  };

  template <typename T>
  class Wrapper<T*> : public WrapperBase
  {
  public:
    Wrapper(rb_data_type_t* rb_data_type, T* data, bool isOwner);
    ~Wrapper();
    void* get(rb_data_type_t* requestedType) override;

  private:
    T* data_ = nullptr;
  };

  template <typename T>
  class Wrapper<T**> : public WrapperBase
  {
  public:
    Wrapper(rb_data_type_t* rb_data_type, T** data, bool isOwner);
    ~Wrapper();
    void* get(rb_data_type_t* requestedType) override;

  private:
    T** data_ = nullptr;
  };

  // ---- Helper Functions ---------
  template <typename T>
  Wrapper<T*>* wrapConstructed(VALUE value, rb_data_type_t* rb_data_type, T* data, VALUE source = Qnil);

  template <typename T>
  VALUE wrap(VALUE klass, rb_data_type_t* rb_data_type, T& data, bool isOwner);

  template <typename T>
  VALUE wrap(VALUE klass, rb_data_type_t* rb_data_type, T* data, bool isOwner);

  template <typename T>
  T* unwrap(VALUE value, rb_data_type_t* rb_data_type, bool takeOwnership);

  template <typename Wrapper_T = WrapperBase>
  Wrapper_T* getWrapper(VALUE value, rb_data_type_t* rb_data_type);

  WrapperBase* getWrapper(VALUE value);
}
 

// =========   Type.hpp   =========

namespace Rice::detail
{
  template<typename T>
  struct Type
  {
    static bool verify();
  };

  template<typename T>
  struct Type<T&>
  {
    static bool verify();
  };

  template<typename T>
  struct Type<T&&>
  {
    static bool verify();
  };

  template<typename T>
  struct Type<T*>
  {
    static bool verify();
  };

  template<typename T>
  struct Type<T**>
  {
    static bool verify();
  };

  template <typename T, int N>
  struct Type<T[N]>
  {
    static bool verify();
    static VALUE rubyKlass();
  };
    
  template<typename T>
  void verifyType();

  template<typename Tuple_T>
  void verifyTypes();
}


// =========   TypeIndexParser.hpp   =========

#include <regex>
#include <typeindex>

namespace Rice::detail
{
  class TypeIndexParser
  {
  public:
    TypeIndexParser(const std::type_index& typeIndex, bool isFundamental = false);
    std::string name();
    std::string simplifiedName();
    std::string rubyName(std::string rubyTypeName);

    // public only for testing
    std::string findGroup(std::string& string, size_t start = 0);

  protected:
    std::string demangle(char const* mangled_name);
    void removeGroup(std::string& string, std::regex regex);
    void replaceGroup(std::string& string, std::regex regex, std::string replacement);
    void capitalizeHelper(std::string& content, std::regex& regex);
    void replaceAll(std::string& string, std::regex regex, std::string replacement);

  protected:
    const std::type_index typeIndex_;
    bool isFundamental_ = false;
  };

  template<typename T>
  class TypeDetail
  {
  public:
    std::string name();
    std::string simplifiedName();

    VALUE rubyKlass();
    std::string rubyName();

  private:
    static std::type_index typeIndex();
    static bool isFundamental();
    std::string rubyTypeName();

  private:
    TypeIndexParser typeIndexParser_{ typeIndex(), isFundamental() };
  };
}


// Code to register Ruby objects with GC (declarations)

// =========   Anchor.hpp   =========

#include <ruby.h>

namespace Rice
{
  namespace detail
  {
    //! Internal GC anchor for a Ruby VALUE.
    /*!
     *  Anchor is a low-level adapter around the Ruby GC API.
     *  It owns a stable VALUE slot whose address is registered
     *  with the Ruby garbage collector.
     *
     *  This class encapsulates all GC registration logic and is
     *  not part of the public Rice API.
     */
    class Anchor
    {
    public:
      //! Construct an anchor for the given Ruby VALUE.
      /*!
       *  The address of the internal VALUE is registered with the
       *  Ruby GC, preventing collection while this Anchor exists.
       */
      explicit Anchor(VALUE value);

      //! Unregister the VALUE from the Ruby GC.
      ~Anchor();

      Anchor(const Anchor&) = delete;
      Anchor& operator=(const Anchor&) = delete;

      //! Retrieve the currently anchored VALUE.
      VALUE get() const;

    private:
      static void disable(VALUE);
      static void registerExitHandler();

      inline static bool enabled_ = true;
      inline static bool exitHandlerRegistered_ = false;

    private:
      bool registered_ = false;

      //! GC-visible Ruby VALUE slot.
      VALUE value_ = Qnil;
    };
  }
}

// =========   Pin.hpp   =========

namespace Rice
{
  //! Strong lifetime policy for a Ruby VALUE.
  /*!
   *  Pin represents a Ruby VALUE whose lifetime is explicitly
   *  extended by C++ code.
   *
   *  Internally, Pin uses a GC Anchor to keep the VALUE alive.
   *  Copying a Pin shares the underlying anchor; moving is cheap.
   *
   *  This type is intended for C++-owned objects that store Ruby
   *  values but are not themselves owned by Ruby and thus do not
   *  participate in the GC via a mark function.
   */
  class Pin
  {
  public:
    //! Construct a pin from a Ruby VALUE.
    Pin(VALUE value);

    // Copying
    Pin(const Pin&) = default;
    Pin& operator=(const Pin&) = default;

    // Moving
    Pin(Pin&&) noexcept = default;
    Pin& operator=(Pin&&) noexcept = default;

    //! Retrieve the pinned Ruby VALUE.
    VALUE value() const;

  private:
    //! Shared ownership of the internal GC anchor.
    std::shared_ptr<detail::Anchor> anchor_;
  };
}

// Code for C++ to call Ruby

// =========   Exception.hpp   =========

#include <stdexcept>

namespace Rice
{
  //! A placeholder for Ruby exceptions.
  /*! You can use this to safely throw a Ruby exception using C++ syntax:
   *  \code
   *    VALUE foo(VALUE self) {
   *      RUBY_TRY {
   *        throw Rice::Exception(rb_eMyException, "uh oh!");
   *      RUBY_CATCH
   *    }
   *  \endcode
   */
  class Exception
    : public std::exception
  {
  public:
    //! Construct a Exception with a Ruby exception instance
    explicit Exception(VALUE exception);

    //! Construct a Exception with printf-style formatting.
    /*! \param exc either an exception object or a class that inherits
     *  from Exception.
     *  \param fmt a printf-style format string
     *  \param ... the arguments to the format string.
     */
    template <typename... Parameter_Ts>
    Exception(const Exception& other, char const* fmt, Parameter_Ts&&...args);

    //! Construct a Exception with printf-style formatting.
    /*! \param exc either an exception object or a class that inherits
     *  from Exception.
     *  \param fmt a printf-style format string
     *  \param ... the arguments to the format string.
     */
    template <typename... Parameter_Ts>
    Exception(const VALUE exceptionType, char const* fmt, Parameter_Ts&&...args);

    //! Destructor
    virtual ~Exception() noexcept = default;

    //! Get message as a char const *.
    /*! If message is a non-string object, then this function will attempt
     *  to throw an exception (which it can't do because of the no-throw
     *  specification).
     *  \return the underlying C pointer of the underlying message object.
     */
    virtual char const* what() const noexcept override;

    //! Returns the Ruby exception class
    VALUE class_of() const;

    //! Returns an instance of a Ruby exception
    VALUE value() const;

  private:
    Pin exception_ = Qnil;
    mutable std::string message_;
  };
} // namespace Rice


// =========   JumpException.hpp   =========

namespace Rice
{
  //! A placeholder for Ruby longjmp data.
  /*! When a Ruby exception is caught, the tag used for the longjmp is stored in
   *  a Jump_Tag, then later passed to rb_jump_tag() when there is no more
   *  C++ code to pass over.
   */
  class JumpException : public std::exception
  {
  public:
    // Copied from vm_core.h
    enum ruby_tag_type {
      RUBY_TAG_NONE = 0x0,
      RUBY_TAG_RETURN = 0x1,
      RUBY_TAG_BREAK = 0x2,
      RUBY_TAG_NEXT = 0x3,
      RUBY_TAG_RETRY = 0x4,
      RUBY_TAG_REDO = 0x5,
      RUBY_TAG_RAISE = 0x6,
      RUBY_TAG_THROW = 0x7,
      RUBY_TAG_FATAL = 0x8,
      RUBY_TAG_MASK = 0xf
    };

  public:
    JumpException(ruby_tag_type tag);
    virtual const char* what() const noexcept override;

  public:
    //! The tag being held.
    ruby_tag_type tag;

  private:
    void createMessage();

  private:
    std::string message_;
  };
} // namespace Rice


// =========   JumpException.ipp   =========
namespace Rice
{
  inline JumpException::JumpException(ruby_tag_type tag) : tag(tag)
  {
    this->createMessage();
  }

  inline const char* JumpException::what() const noexcept
  {
    return this->message_.c_str();
  }

  inline void JumpException::createMessage()
  {
    switch (this->tag)
    {
      case RUBY_TAG_NONE:
        this->message_ = "No error";
        break;
      case RUBY_TAG_RETURN:
        this->message_ = "Unexpected return";
        break;
      case RUBY_TAG_NEXT:
        this->message_ = "Unexpected next";
        break;
      case RUBY_TAG_BREAK:
        this->message_ = "Unexpected break";
        break;
      case RUBY_TAG_REDO:
        this->message_ = "Unexpected redo";
        break;
      case RUBY_TAG_RETRY:
        this->message_ = "Retry outside of rescue clause";
        break;
      case RUBY_TAG_THROW:
        this->message_ = "Unexpected throw";
      case RUBY_TAG_RAISE:
        this->message_ = "Ruby exception was thrown";
        break;
      case RUBY_TAG_FATAL:
        this->message_ = "Fatal error";
        break;
      case RUBY_TAG_MASK:
        this->message_ = "Mask error";
        break;
    }
  }
} // namespace Rice

// =========   NativeInvoker.hpp   =========

#include <optional>

namespace Rice::detail
{
  template<typename Return_T>
  class ResultWrapper
  {
  public:
    std::exception_ptr exception;
    Return_T getResult();
		void setResult(Return_T&& value);
  private:
    std::optional<Return_T> result_;
  };

  template<typename Return_T>
  class ResultWrapper<Return_T&>
  {
  public:
    std::exception_ptr exception;
    Return_T& getResult();
    void setResult(Return_T& value);
  private:
    std::optional<std::reference_wrapper<Return_T>> result_;
  };

  template<typename Return_T>
  class ResultWrapper<Return_T*>
  {
  public:
    std::exception_ptr exception;

    Return_T* getResult();
    void setResult(Return_T* value);
  private:
    Return_T* result_;
  };

  template<>
  class ResultWrapper<void>
  {
  public:
    std::exception_ptr exception;
  };

  template<typename Return_T, typename Function_T, typename Tuple_T>
  class NativeInvoker
  {
  public:
    const Function_T func;
    Tuple_T args;
  public:
    NativeInvoker(const Function_T func, Tuple_T&& args);
    void invoke();
    Return_T result();
    std::exception_ptr exception();
  private:
    ResultWrapper<Return_T> resultWrapper;
  };

  template<typename Function_T, typename ...Parameter_Ts>
  auto protect(Function_T func, Parameter_Ts...args);

  template<typename Function_T, typename ...Parameter_Ts>
  typename function_traits<Function_T>::return_type no_gvl(Function_T func, Parameter_Ts...args);

  template<typename Function_T, typename Tuple_T>
  typename function_traits<Function_T>::return_type no_gvl(Function_T func, Tuple_T&& args);
}


// =========   NativeInvoker.ipp   =========
namespace Rice::detail
{
  // ----- ResultWrapper -------
  template<typename Return_T>
  inline Return_T ResultWrapper<Return_T>::getResult()
  {
    if constexpr (!std::is_copy_constructible_v<Return_T> && std::is_move_constructible_v<Return_T>)
    {
      return std::move(this->result_.value());
    }
    // std::is_copy_constructible_v<std::vector<std::unique_ptr<T>>>> returns true. Sigh.
    else if constexpr (detail::is_std_vector_v<Return_T> && std::is_copy_constructible_v<Return_T>)
    {
      if constexpr (!std::is_copy_constructible_v<typename Return_T::value_type>)
      {
        return std::move(this->result_.value());
      }
      else
      {
        return this->result_.value();
      }
    }
    else
    {
      return this->result_.value();
    }
	}

  template<typename Return_T>
  inline void ResultWrapper<Return_T>::setResult(Return_T&& value)
  {
    if constexpr(std::is_copy_assignable_v<Return_T> || std::is_move_assignable_v<Return_T>)
    {
      this->result_ = std::forward<Return_T>(value);
    }
    else if constexpr (std::is_copy_constructible_v<Return_T>)
    {
      this->result_.emplace(value);
    }
    else if constexpr (std::is_move_constructible_v<Return_T>)
    {
      this->result_.emplace(std::move(value));
    }
  }

  template<typename Return_T>
  inline Return_T& ResultWrapper<Return_T&>::getResult()
  {
    return this->result_.value().get();
  }

  template<typename Return_T>
  inline void ResultWrapper<Return_T&>::setResult(Return_T& value)
  {
    this->result_ = value;
  }

  template<typename Return_T>
  inline Return_T* ResultWrapper<Return_T*>::getResult()
  {
    return this->result_;
  }

  template<typename Return_T>
  inline void ResultWrapper<Return_T*>::setResult(Return_T* value)
  {
    this->result_ = value;
  }

  // ----- Invoker -------
  template<typename Return_T, typename Function_T, typename Tuple_T>
  inline NativeInvoker<Return_T, Function_T, Tuple_T>::NativeInvoker(const Function_T func, Tuple_T&& args)
    : func(func), args(std::forward<Tuple_T>(args))
  {
  }

  template<typename Return_T, typename Function_T, typename Tuple_T>
  inline void NativeInvoker<Return_T, Function_T, Tuple_T>::invoke()
  {
    try
    {
      if constexpr (std::is_void_v<Return_T>)
      {
        std::apply(this->func, std::forward<Tuple_T>(this->args));
      }
      else if constexpr (!std::is_pointer_v<Return_T> && !std::is_reference_v<Return_T> && !std::is_copy_assignable_v<Return_T> && std::is_move_assignable_v<Return_T>)
      {
        this->resultWrapper.setResult(std::move(std::apply(this->func, std::forward<Tuple_T>(this->args))));
      }
      else
      {
        this->resultWrapper.setResult(std::forward<Return_T>(std::apply(this->func, std::forward<Tuple_T>(this->args))));
      }
    }
    catch (...)
    {
      this->resultWrapper.exception = std::current_exception();
    }
  }

  template<typename Return_T, typename Function_T, typename Tuple_T>
  inline Return_T NativeInvoker<Return_T, Function_T, Tuple_T>::result()
  {
		return this->resultWrapper.getResult();
  }

  template<typename Return_T, typename Function_T, typename Tuple_T>
  inline std::exception_ptr NativeInvoker<Return_T, Function_T, Tuple_T>::exception()
  {
    return this->resultWrapper.exception;
  }

  // ------- Helper Methods --------
  // Create a functor for calling a Ruby function and define some aliases for readability.
  template<typename Function_T, typename ...Parameter_Ts>
  auto protect(Function_T func, Parameter_Ts...args)
  {
    using Return_T = typename function_traits<Function_T>::return_type;
    using Tuple_T = std::tuple<Parameter_Ts...>;
    using Invoker_T = NativeInvoker<Return_T, Function_T, Tuple_T>;

    Tuple_T argsTuple = std::forward_as_tuple(args...);
    Invoker_T invoker(func, std::forward<Tuple_T>(argsTuple));

    auto trampoline = [](VALUE value) -> VALUE
      {
        Invoker_T* function = (Invoker_T*)value;

        function->invoke();
        return Qnil;
      };

    // Create Invoker and call it via ruby
    int state = (int)JumpException::RUBY_TAG_NONE;
    rb_protect(trampoline, (VALUE)(&invoker), &state);

    // Did anything go wrong?
    if (state == JumpException::RUBY_TAG_NONE)
    {
      if constexpr (!std::is_same_v<Return_T, void>)
      {
        return invoker.result();
      }
    }
    else
    {
      VALUE err = rb_errinfo();
      if (state == JumpException::RUBY_TAG_RAISE && RB_TEST(err))
      {
        rb_set_errinfo(Qnil);
        throw Rice::Exception(err);
      }
      else
      {
        throw Rice::JumpException((Rice::JumpException::ruby_tag_type)state);
      }
    }
  }

  template<typename Function_T, typename ...Parameter_Ts>
  typename function_traits<Function_T>::return_type no_gvl(Function_T func, Parameter_Ts...args)
  {
    using Tuple_T = std::tuple<Parameter_Ts...>;
    Tuple_T argsTuple = std::forward_as_tuple(args...);
    return no_gvl(func, argsTuple);
  }

  template<typename Function_T, typename Tuple_T>
  typename function_traits<Function_T>::return_type no_gvl(Function_T func, Tuple_T&& args)
  {
    using Return_T = typename function_traits<Function_T>::return_type;
    using Invoker_T = NativeInvoker<Return_T, Function_T, Tuple_T>;

    Invoker_T invoker(func, std::forward<Tuple_T>(args));

    auto trampoline = [](void* functor) -> void*
      {
        Invoker_T* function = (Invoker_T*)functor;
        function->invoke();

        if (function->exception())
        {
          std::rethrow_exception(function->exception());
        }

        return nullptr;
      };

    // Create Invoker and call it via ruby
    rb_thread_call_without_gvl(trampoline, &invoker, nullptr, nullptr);

    if constexpr (!std::is_same_v<Return_T, void>)
    {
      return invoker.result();
    }
  }
}
// =========   to_ruby.hpp   =========

namespace Rice
{
  namespace detail
  {
    //! Convert a C++ object to Ruby.
    /*! If x is a pointer, wraps the pointee as a Ruby object.  If x is an
     *  Object, returns x.
     *
     *  If no conversion exists a compile-time error is generated.
     *
     *  \param x the object to convert.
     *  \return a Ruby representation of the C++ object.
     *
     *  Example:
     *  \code
     *    rb_p(to_ruby(42));
     *
     *    Foo * p_foo = new Foo();
     *    rb_p(to_ruby(p_foo));
     *  \endcode
     */
    template <typename T>
    class To_Ruby;
   
    // Helper template function that let's users avoid having to specify the template type - its deduced
    template <typename T>
    VALUE to_ruby(T&& x)
    {
      using Unqualified_T = remove_cv_recursive_t<T>;
      return To_Ruby<Unqualified_T>().convert(std::forward<T>(x));
    }

    // Helper template function that let's users avoid having to specify the template type - its deduced
    template <typename T>
    VALUE to_ruby(T* x)
    {
      using Unqualified_T = remove_cv_recursive_t<T>;
      return To_Ruby<Unqualified_T*>().convert(x);
    }
  } // detail
} // Rice


// Code for Ruby to call C++

// =========   Arg.hpp   =========

#include <any>

namespace Rice
{
  //! Helper for defining default arguments of a method
  /*! This class exposes the ability to define the default values of a
   *  wrapped method. Inspired by how Boost.Python handles keyword and
   *  default arguments, the syntax is simple:
   *
   *  \code
   *    define_method(
   *      "method",
   *      &method,
   *      Arg("arg1"), Arg("arg2") = 3, Arg("arg3") = true
   *    );
   *  \endcode
   *
   *  which means "for method &method, it takes 3 arguments
   *  [arg1, arg2, arg3]. Of these arguments, arg2's default is 3
   *  and arg3's default is true.
   *
   *  It may be required to explicitly cast the type of the default
   *  value to prevent compilation errors.
   */
  class Arg
  {
  public:
    //! Initialize a new Arg with the name of the argument
    /*! We require the name of the argument because 1) it makes code
     *  easier to read and 2) hopefully Ruby gets keyword arguments
     *  in the future and this means Rice will be ready for it.
     */
    Arg(std::string name);

    // Make Arg polymorphic so dynamic_cast works
    virtual ~Arg() = default;

    //! Set the default value for this Arg
    /*! Set the default value for this argument.
     *  If this isn't called on this Arg, then this
     *  Arg is required in the method call.
     *
     *  \param val the value to store as default
     */
    template<typename Arg_Type>
    Arg& operator=(Arg_Type val);

    //! Check if this Arg has a default value associated with it
    bool hasDefaultValue() const;

    //! Return a reference to the default value associated with this Arg
    /*! \return the type saved to this Arg
     */
    template<typename Arg_Type>
    Arg_Type defaultValue();

    //! Tell the receiving object to keep this argument alive
    //! until the receiving object is freed.
    virtual Arg& keepAlive();
    
    //! Returns if the argument should be kept alive
    bool isKeepAlive() const;

    //! Specifies if the argument should be treated as a value
    virtual Arg& setValue();

    //! Returns if the argument should be treated as a value
    bool isValue() const;

    //! Specifies if the argument is opaque and Rice should not convert it from Ruby to C++ or vice versa.
    //! This is useful for callbacks and user provided data paramameters.
    virtual Arg& setOpaque();

    //! Returns if the argument should be treated as a value
    bool isOpaque() const;

    //! Specifies C++ will take ownership of this value and Ruby should not free it
    virtual Arg& takeOwnership();
    bool isOwner();

  public:
    std::string name;

  private:
    //! Our saved default value
    std::any defaultValue_;
    bool isValue_ = false;
    bool isKeepAlive_ = false;
    bool isOwner_ = false;
    bool isOpaque_ = false;
  };

  class ArgBuffer : public Arg
  {
  public:
    ArgBuffer(std::string name);
    using Arg::operator=;  // Inherit the templated operator=
  };
} // Rice


// =========   Return.hpp   =========

namespace Rice
{
  //! Helper for defining Return argument of a method

  class Return: public Arg
  {
  public:
    Return();
    Return& keepAlive() override;
    Return& setValue() override;
    Return& setOpaque() override;
    Return& takeOwnership() override;
  };

  class ReturnBuffer : public Return
  {
  };
} // Rice


// =========   from_ruby.hpp   =========

namespace Rice::detail
{
  //! Convert a Ruby object to C++.
  /*! If the Ruby object can be converted to an immediate value, returns a
   *  copy of the Ruby object.  If the Ruby object is holding a C++
   *  object and the type specified is a pointer to that type, returns a
   *  pointer to that object.
   *
   *  Conversions from ruby to a pointer type are automatically generated
   *  when a type is bound using Data_Type.  If no conversion exists an
   *  exception is thrown.
   *
   *  \param T the C++ type to which to convert.
   *  \param x the Ruby object to convert.
   *  \return a C++ representation of the Ruby object.
   *
   *  Example:
   *  \code
   *    Object x = INT2NUM(42);
   *    std::cout << From_Ruby<int>::convert(x);
   *
   *    Data_Object<Foo> foo(new Foo);
   *    std::cout << *From_Ruby<Foo *>(foo) << std::endl;
   *  \endcode
   */

  template <typename T>
  class From_Ruby;

  // Overload resolution scoring constants
  struct Convertible
  {
    static constexpr double Exact = 1.0;           // Perfect type match
    static constexpr double None = 0.0;            // Cannot convert
    static constexpr double IntToFloat = 0.5;      // Domain change penalty when converting int to float
    static constexpr double SignedToUnsigned = 0.5;// Penalty for signed to unsigned (can't represent negatives)
    static constexpr double FloatToInt = 0.5;      // Domain change penalty when converting float to int (lossy)
    static constexpr double ConstMismatch = 0.99;  // Penalty for const mismatch
  };
}


// =========   RubyType.hpp   =========

#include <set>

namespace Rice::detail
{
  template <typename T>
  class RubyType
  {
  };
}


// =========   Parameter.hpp   =========

#include <optional>

namespace Rice::detail
{
  class ParameterAbstract
  {
  public:
    ParameterAbstract(std::unique_ptr<Arg>&& arg);
    virtual ~ParameterAbstract() = default;

    ParameterAbstract(const ParameterAbstract& other);
    ParameterAbstract(ParameterAbstract&& other) = default;
    ParameterAbstract& operator=(ParameterAbstract&& other) = default;

    virtual VALUE defaultValueRuby() = 0;
    virtual double matches(std::optional<VALUE>& valueOpt) = 0;
    virtual std::string cppTypeName() = 0;
    virtual VALUE klass() = 0;

    Arg* arg();

  private:
    std::unique_ptr<Arg> arg_;
  };

  template<typename T>
  class Parameter: public ParameterAbstract
  {
   public:
     using Type = T;

     Parameter(std::unique_ptr<Arg>&& arg);
     Parameter(const Parameter& other) = default;
     Parameter(Parameter&& other) = default;
     Parameter& operator=(Parameter&& other) = default;

     T convertToNative(std::optional<VALUE>& valueOpt);
     VALUE convertToRuby(T& object);
     VALUE defaultValueRuby() override;

     double matches(std::optional<VALUE>& valueOpt) override;
     std::string cppTypeName() override;
     VALUE klass() override;

    // std::string typeName() override;
  private:
    From_Ruby<remove_cv_recursive_t<T>> fromRuby_;
    To_Ruby<remove_cv_recursive_t<T>> toRuby_;
  };
}

// Code to register Ruby objects with GC (implementations)

// =========   Anchor.ipp   =========
namespace Rice
{
  namespace detail
  {
    inline Anchor::Anchor(VALUE value) : value_(value)
    {
      if (!RB_SPECIAL_CONST_P(value))
      {
        Anchor::registerExitHandler();
        detail::protect(rb_gc_register_address, &this->value_);
        this->registered_ = true;
      }
    }

    inline Anchor::~Anchor()
    {
      if (Anchor::enabled_ && this->registered_)
      {
        detail::protect(rb_gc_unregister_address, &this->value_);
      }
      // Ruby auto detects VALUEs in the stack, so make sure up in case this object is on the stack
      this->registered_ = false;
      this->value_ = Qnil;
    }

    inline VALUE Anchor::get() const
    {
      return this->value_;
    }

    // This will be called by ruby at exit - we want to disable further unregistering
    inline void Anchor::disable(VALUE)
    {
      Anchor::enabled_ = false;
    }

    inline void Anchor::registerExitHandler()
    {
      if (!Anchor::exitHandlerRegistered_)
      {
        detail::protect(rb_set_end_proc, &Anchor::disable, Qnil);
        Anchor::exitHandlerRegistered_ = true;
      }
    }
  }
}

// =========   Pin.ipp   =========
namespace Rice
{
  inline Pin::Pin(VALUE value)
    : anchor_(std::make_shared<detail::Anchor>(value))
  {
  }

  inline VALUE Pin::value() const
  {
    // Anchor can be nil after a move
    if (this->anchor_)
    {
      return this->anchor_->get();
    }
    else
    {
      return Qnil;
    }
  }
}

// C++ API declarations

// =========   Encoding.hpp   =========

namespace Rice
{
  //! A wrapper for a Ruby encoding
  class Encoding
  {
  public:
    static Encoding utf8();

    //! Wrap an existing encoding.
    Encoding(rb_encoding* encoding);

    //! Implicit conversion to VALUE.
    operator rb_encoding* () const
    {
      return this->encoding_;
    }

    operator VALUE () const
    {
      return detail::protect(rb_enc_from_encoding, this->encoding_);
    }

  private:
    rb_encoding* encoding_;
  };
} // namespace Rice



// =========   Identifier.hpp   =========

namespace Rice
{
  class Symbol;

  //! A wrapper for the ID type
  /*! An ID is ruby's internal representation of a Symbol object.
   */
  class Identifier
  {
  public:
    //! Construct a new Identifier from an ID.
    Identifier(ID id);

    //! Construct a new Identifier from a Symbol.
    Identifier(Symbol const& symbol);

    //! Construct a new Identifier from a c string.
    Identifier(char const* s, Encoding encoding = Encoding::utf8());

    //! Construct a new Identifier from a string.
    Identifier(std::string const& string, Encoding encoding = Encoding::utf8());

    //! Return a string representation of the Identifier.
    char const* c_str() const;

    //! Return a string representation of the Identifier.
    std::string str() const;

    //! Return the underlying ID
    ID id() const { return id_; }

    //! Return the underlying ID
    operator ID() const { return id_; }

    //! Return the ID as a Symbol
    VALUE to_sym() const;

  private:
    ID id_;
  };
} // namespace Rice


// =========   Identifier.ipp   =========
namespace Rice
{
  inline Identifier::Identifier(ID id) : id_(id)
  {
  }

  inline Identifier::Identifier(char const* name, Encoding encoding)
  {
    this->id_ = detail::protect(rb_intern3, name, (long)strlen(name), encoding);
  }

  inline Identifier::Identifier(const std::string& name, Encoding encoding)
  {
    this->id_ = detail::protect(rb_intern3, name.c_str(), (long)name.size(), encoding);
  }

  inline char const* Identifier::c_str() const
  {
    return detail::protect(rb_id2name, id_);
  }

  inline std::string Identifier::str() const
  {
    return c_str();
  }

  inline VALUE Identifier::to_sym() const
  {
    return ID2SYM(id_);
  }
}
// =========   Object.hpp   =========

/*! \file Object.hpp
 */

#include <iosfwd>

namespace Rice
{
  class Class;
  class Module;
  class String;
  class Array;

  //! The base class for all Objects
  /*! Perhaps the name "Object" is a misnomer, because this class really
   *  holds an object reference, not an object.
   */
  class Object
  {
  public:
    //! Construct an empty Object wrapper.
    Object();

    //! Encapsulate an existing ruby object.
    Object(VALUE value);

    //! Destructor
    virtual ~Object() = default;

    // Enable copying
    Object(const Object& other) = default;
    Object& operator=(const Object& other) = default;

    // Enable moving
    Object(Object&& other) = default;
    Object& operator=(Object&& other) = default;

    //! Implicit conversion to VALUE.
    operator VALUE() const;

    //! Explicitly get the encapsulated VALUE.
    VALUE value() const;

    //! Returns false if the object is nil or false; returns true
    //! otherwise.
    explicit operator bool() const;

    //! Returns true if the object is nil, false otherwise.
    bool is_nil() const;


    //! Get the class of an object.
    /*! \return the object's Class.
     */
    Class class_of() const;

    //! Compare this object to another object.
    /*! Gets the result of self <=> other and returns the result.  The
     *  result will be less than zero if self < other, greater than zero
     *  if self > other, and equal to zero if self == other.
     */
    int compare(Object const& other) const;

    //! Return a string representation of an object.
    /*! \return the result of calling to_s on the object.  A String is not
     *  returned, because it is not possible to return an instance of a
     *  derived class.
     */
    String to_s() const;

    //! Return the name of an object's class.
    String class_name() const;

    //! Inspect the object.
    /*! \return the result of calling inspect on the object.  A String is
     *  not returned, because it is not possible to return an instance of
     *  a derived class.
     */
    String inspect() const;

    //! Freeze the object.
    void freeze();

    //! Determine if the object is frozen.
    /*! \return true if the object is frozen, false otherwise.
     */
    bool is_frozen() const;

    //! Evaluate the given string in the context of the object.
    /*! This is equivalant to calling obj.instance_eval(s) from inside the
     *  interpreter.
     *  \return the result of the expression.
     */
    Object instance_eval(String const& s);

    //! Return the type of the underlying C object.
    /*! This is equivalent to calling rb_type(obj).
     * \return the type of the underlying C object (e.g. T_DATA, T_ARRAY,
     * etc.).
     */
    int rb_type() const;

    //! Return the object's id
    VALUE object_id() const;

    //! Determine whether the object is an instance of a class/module.
    /*! \param klass a class or module.
     *  \return true if the object is an instance of the given
     *  class/module or one of its descendants.
     */
    bool is_a(Object klass) const;

    //! Extend the object with a module.
    /*! \param mod the module to extend with.
     */
    void extend(Module const& mod);

    //! Determine if the objects responds to a method.
    /*! \param id the name of the method
     *  \return true if the objects responds to the method, false
     *  otherwise.
     */
    bool respond_to(Identifier id) const;

    //! Determine whether class is the object's class.
    /*! \param klass a class.
     *  \return true if the object is an instance of the given class.
     */
    bool is_instance_of(Object klass) const;

    //! Determine whether the Ruby VALUEs wrapped by this
    //! object are the same object. Maps to Object::equal?
    /*! \param other a Object.
     */
    bool is_equal(const Object& other) const;

    //! Determine whether the Ruby VALUEs wrapped by this
    //! object are equivalent. Maps to Object::eql?
    /*! \param other a Object.
     */
    bool is_eql(const Object& other) const;

    //! Set an instance variable.
    /*! \param name the name of the instance variable to set (including
     *  the leading @ sign)
     *  \param value the value of the variable, which will be converted to
     *  a Ruby type if necessary.
     */
    template<typename T>
    void iv_set(Identifier name, T const& value);

    //! Get the value of an instance variable.
    /*! \param name the name of the instance variable to get
     *  \return the value of the instance variable
     */
    Object iv_get(Identifier name) const;

    //! Get the value of an instance variable, but don't warn if it is
    //unset.
    /*! \param name the name of the instance variable to get
     *  \return the value of the instance variable
     */
    Object attr_get(Identifier name) const;

    //! Call the Ruby method specified by 'id' on object 'obj'.
    /*! Pass in arguments (arg1, arg2, ...).  The arguments will be converted to
    *  Ruby objects with to_ruby<>. To call methods expecting keyword arguments,
    *  use call_kw.
    *
    *  E.g.:
    *  \code
    *    Rice::Object obj = x.call("foo", "one", 2);
    *  \endcode
    *
    *  If a return type is specified, the return value will automatically be
    *  converted to that type as long as 'from_ruby' exists for that type.
    *
    *  E.g.:
    *  \code
    *    float ret = x.call<float>("foo", z, 42);
    *  \endcode
    */
    template<typename ...Parameter_Ts>
    Object call(Identifier id, Parameter_Ts... args) const;

    //! Call the Ruby method specified by 'id' on object 'obj'.
    /*! Pass in arguments (arg1, arg2, ...).  The arguments will be converted to
    *  Ruby objects with to_ruby<>. The final argument must be a Hash and will be treated
    *  as keyword arguments to the function.
    *
    *  E.g.:
    *  \code
    *    Rice::Hash kw;
    *    kw[":argument"] = String("one")
    *    Rice::Object obj = x.call_kw("foo", kw);
    *  \endcode
    *
    *  If a return type is specified, the return value will automatically be
    *  converted to that type as long as 'from_ruby' exists for that type.
    *
    *  E.g.:
    *  \code
    *    float ret = x.call_kw<float>("foo", kw);
    *  \endcode
    */
    template<typename ...Parameter_Ts>
    Object call_kw(Identifier id, Parameter_Ts... args) const;

    //! Vectorized call.
    /*! Calls the method identified by id with the list of arguments
     *  identified by args.
     *  \param id the name of the method to call
     *  \param args the arguments to the method
     *  \return the return value of the method call
     */
    Object vcall(Identifier id, Array args);

    //! Get a constant.
    /*! \param name the name of the constant to get.
     *  \return the value of the constant.
     */
    Object const_get(Identifier name) const;

    //! Determine whether a constant is defined.
    /*! \param name the name of the constant to check.
     *  \return true if the constant is defined in this module or false
     *  otherwise.
     */
    bool const_defined(Identifier name) const;

    //! Set a constant.
    /*! \param name the name of the constant to set.
      *  \param value the value of the constant.
      *  \return *this
      */
    inline Object const_set(Identifier name, Object value);

    //! Set a constant if it not already set.
    /*! \param name the name of the constant to set.
      *  \param value the value of the constant.
      *  \return *this
      */
    inline Object const_set_maybe(Identifier name, Object value);

    //! Remove a constant.
    /*! \param name the name of the constant to remove.
     */
    void remove_const(Identifier name);

  protected:
    //! Checks the encapsulated VALUE is not nil and returns it. If it is nil 
    //! an exception is thrown.
    VALUE validated_value() const;

    //! Set the encapsulated value.
    void set_value(VALUE value);

  private:
    Pin value_;
  };

  std::ostream& operator<<(std::ostream& out, Object const& obj);

  bool operator==(Object const& lhs, Object const& rhs);
  bool operator!=(Object const& lhs, Object const& rhs);
  bool operator<(Object const& lhs, Object const& rhs);
  bool operator>(Object const& lhs, Object const& rhs);
}


// =========   String.hpp   =========

namespace Rice
{
  //! A Wraper for the ruby String class.
  /*! This class provides a C++-style interface to ruby's String class and
   *  its associated rb_str_* functions.
   *
   *  Example:
   *  \code
   *    String s(String::format("%s: %d", "foo", 42));
   *    std::cout << s.length() << std::endl;
   *  \endcode
   */
  class String : public Object
  {
  public:
    //! Construct a new string.
    String();

    //! Wrap an existing string.
    String(VALUE v);

    //! Wrap an existing string.
    String(Object v);

    //! Construct a String from an Identifier.
    String(Identifier id);

    //! Construct a String from a null-terminated C string.
    String(char const* s);

    //! Construct a String from an std::string.
    String(std::string const& s);

    //! Construct a String from an std::string_view.
    String(std::string_view const& s);

    //! Format a string using printf-style formatting.
    template <typename... Parameter_Ts>
    static inline String format(char const* fmt, Parameter_Ts&&...args);

    //! Get the length of the String.
    /*! \return the length of the string.
     */
    size_t length() const;

    //! Get the character at the given index.
    /*! \param index the desired index.
     *  \return the character at the given index.
     */
    char operator[](ptrdiff_t index) const;

    //! Return a pointer to the beginning of the underlying C string.
    char const* c_str() const;

    //! Return a copy of the string as an std::string.
    std::string str() const;

    //! Return an array from a string by unpacking it
    template<typename T>
    Array unpack() const;

    //! Create an Identifier from the String.
    /*! Calls rb_intern to create an ID.
     *  \return an Identifier holding the ID returned from rb_intern.
     */
    Identifier intern() const;
  };
} // namespace Rice


// =========   Symbol.hpp   =========

namespace Rice
{
  //! A wrapper for ruby's Symbol class.
  /*! Symbols are internal identifiers in ruby.  They are singletons and
   *  can be thought of as frozen strings.  They differ from an Identifier
   *  in that they are in fact real Objects, but they can be converted
   *  back and forth between Identifier and Symbol.
   */
  class Symbol
    : public Object
  {
  public:
    //! Wrap an existing symbol.
    Symbol(VALUE v);

    //! Wrap an existing symbol.
    Symbol(Object v);

    //! Construct a Symbol from an Identifier.
    Symbol(Identifier id);

    //! Construct a Symbol from a null-terminated C string.
    Symbol(char const* s = "");

    //! Construct a Symbol from an std::string.
    Symbol(std::string const& s);

    //! Construct a Symbol from an std::string_view.
    Symbol(std::string_view const& s);

    //! Return a string representation of the Symbol.
    char const* c_str() const;

    //! Return a string representation of the Symbol.
    std::string str() const;

    //! Return the Symbol as an Identifier.
    Identifier to_id() const;
  };
} // namespace Rice



// =========   Array.hpp   =========

#include <iterator>
#include <memory>

namespace Rice
{
  //! A wrapper for the ruby Array class.
  /*! This class provides a C++-style interface to ruby's Array class and
   *  its associated rb_ary_* functions.
   *  Example:
   *  \code
   *    Array a;
   *    a.push(String("some string"), false);
   *    a.push(42, false);
   *  \endcode
   */
  class Array
    : public Object
  {
  public:
    //! Construct a new array
    Array();

    //! Construct a new array with specified size
    Array(long capacity);

    //! Wrap an existing array
    /*! \param v a ruby object, which must be of type T_ARRAY.
     */
    Array(Object v);

    //! Wrap an existing array
    /*! \param v a ruby object, which must be of type T_ARRAY.
     */
    Array(VALUE v);

    //! Construct an array from a sequence.
    /*! \param begin an iterator to the beginning of the sequence.
     *  \param end an iterator to the end of the sequence.
     */
    template<typename Iter_T>
    Array(Iter_T begin, Iter_T end);

    //! Construct an Array from a C array.
    /*! \param a a C array of type T and size n.
     */
    template<typename T, long n>
    Array(T (&a)[n]);

  public:
    //! Return the size of the array.
    long size() const;

    //! Return the element at the given index.
    /*! \param index The index of the desired element.  The index may be
     *  negative, to indicate an offset from the end of the array.  If the
     *  index is out of bounds, this function has undefined behavior.
     *  \return the element at the given index.
     */
    Object operator[](long index) const;

    //! Converts a Ruby Array into a C++ array where the elements are
    //! contiguous. This is similar to a std::vector, but instead a
    //! std::unique_ptr<T> is returned. This allows the calling code to
    //! pass ownership to its callers if needed (for exmaple, From_Ruby<T>#convert)
    //! Note this method is designed convenience, not for speed or efficieny.
    //! C++ APIs that take large chunks of memory should not be passed Ruby Arrrays.
    //! \return std::unique_ptr that is owned by the caller.
    template<typename T>
    String pack();

    // Join elements together
    String join(const char* separator);

  private:
    //! A helper class so array[index]=value can work.
    class Proxy;

  public:
    //! Return a reference to the element at the given index.
    /*! \param index The index of the desired element.  The index may be
     *  negative, to indicate an offset from the end of the array.  If the
     *  index is out of bounds, this function has undefined behavior.
     *  \return the element at the given index.
     */
    Proxy operator[](long index);

    //! Push an element onto the end of the array
    /*! \param v an object to push onto the array.
     *  \return the object which was pushed onto the array.
     */
    template<typename T>
    Object push(T&& obj, bool takeOwnership = false);

    //! Pop an element from the end of the array
    /*! \return the object which was popped from the array, or Qnil if
     *  the array was empty.
     */
    Object pop();

    //! Unshift an element onto the beginning of the array
    /*! \param v an object to unshift onto the array.
     *  \return the object which was unshifted onto the array.
     */
    template<typename T>
    Object unshift(T const& obj);

    //! Shift an element from the beginning of the array
    /*! \return the object which was shifted from the array.
     */
    Object shift();

  private:
    template<typename Array_Ptr_T, typename Value_T>
    class Iterator;

    // Friend declaration for non-member operator+
    template<typename Array_Ptr_T, typename Value_T>
    friend Iterator<Array_Ptr_T, Value_T> operator+(
      long n,
      Iterator<Array_Ptr_T, Value_T> const& it);

    long position_of(long index) const;

  public:
    //! An iterator.
    typedef Iterator<Array*, Proxy> iterator;

    //! A const iterator.
    typedef Iterator<Array const*, Object> const_iterator;

    //! Return an iterator to the beginning of the array.
    iterator begin();

    //! Return a const iterator to the beginning of the array.
    const_iterator begin() const;

    //! Return an iterator to the end of the array.
    iterator end();

    //! Return a const iterator to the end of the array.
    const_iterator end() const;

    //! Return the content of the array as a std::vector
    template<typename T>
    std::vector<T> to_vector();
  };

  //! A helper class so array[index]=value can work.
  class Array::Proxy
  {
  public:
    //! Construct a new Proxy
    Proxy(Array array, long index);

    //! Implicit conversion to VALUE.
    operator VALUE() const;

    //! Explicit conversion to VALUE.
    VALUE value() const;

    //! Assignment operator.
    template<typename T>
    Object operator=(T const& value);

  private:
    Array array_;
    long index_;
  };

  //! A random-access iterator for Array.
  template<typename Array_Ptr_T, typename Value_T>
  class Array::Iterator
  {
  public:
    using iterator_category = std::random_access_iterator_tag;
    using value_type = Value_T;
    using difference_type = long;
    using pointer = Object*;
    using reference = Value_T&;

    Iterator(Array_Ptr_T array, long index);

    template<typename Array_Ptr_T_, typename Value_T_>
    Iterator(Iterator<Array_Ptr_T_, Value_T_> const& rhs);

    template<typename Array_Ptr_T_, typename Value_T_>
    Iterator& operator=(Iterator<Array_Ptr_T_, Value_T_> const& rhs);

    // Forward iterator operations
    Iterator& operator++();
    Iterator operator++(int);
    Value_T operator*() const;
    Object* operator->();

    // Bidirectional iterator operations
    Iterator& operator--();
    Iterator operator--(int);

    // Random access iterator operations
    Iterator& operator+=(difference_type n);
    Iterator& operator-=(difference_type n);
    Iterator operator+(difference_type n) const;
    Iterator operator-(difference_type n) const;
    difference_type operator-(Iterator const& rhs) const;
    Value_T operator[](difference_type n) const;

    // Comparison operators
    template<typename Array_Ptr_T_, typename Value_T_>
    bool operator==(Iterator<Array_Ptr_T_, Value_T_> const& rhs) const;

    template<typename Array_Ptr_T_, typename Value_T_>
    bool operator!=(Iterator<Array_Ptr_T_, Value_T_> const& rhs) const;

    template<typename Array_Ptr_T_, typename Value_T_>
    bool operator<(Iterator<Array_Ptr_T_, Value_T_> const& rhs) const;

    template<typename Array_Ptr_T_, typename Value_T_>
    bool operator>(Iterator<Array_Ptr_T_, Value_T_> const& rhs) const;

    template<typename Array_Ptr_T_, typename Value_T_>
    bool operator<=(Iterator<Array_Ptr_T_, Value_T_> const& rhs) const;

    template<typename Array_Ptr_T_, typename Value_T_>
    bool operator>=(Iterator<Array_Ptr_T_, Value_T_> const& rhs) const;

    Array_Ptr_T array() const;
    long index() const;

  private:
    Array_Ptr_T array_;
    long index_;

    Object tmp_;
  };

  // Non-member operator+ for n + iterator (allows n + iterator syntax)
  template<typename Array_Ptr_T, typename Value_T>
  Array::Iterator<Array_Ptr_T, Value_T> operator+(
    long n,
    Array::Iterator<Array_Ptr_T, Value_T> const& it);
} // namespace Rice


// =========   Hash.hpp   =========

#include <iterator>
#include <type_traits>

namespace Rice
{
  //! A wrapper for the ruby Hash class.
  //! This class provides a C++-style interface to ruby's Hash class and
  //! its associated rb_hash_* functions.
  //! Example:
  //! \code
  //!   Hash h;
  //!   h[42] = String("foo");
  //!   h[10] = String("bar");
  //!   std::cout << String(h[42]) << std::endl;
  //! \endcode
  class Hash: public Object
  {
  public:
    //! Construct a new hash.
    Hash();

    //! Wrap an existing hash.
    /*! \param v the hash to wrap.
     */
    Hash(Object v);

    //! Return the number of elements in the hash.
    size_t size() const;

  private:
    //! A helper class so hash[key]=value can work.
    class Proxy;

  public:
    //! Get the value for the given key.
    /*! \param key the key whose value should be retrieved from the hash.
     *  \return the value associated with the given key.
     */
    template<typename Key_T>
    Proxy const operator[](Key_T const& key) const;

    //! Get the value for the given key.
    /*! \param key the key whose value should be retrieved from the hash.
     *  \return the value associated with the given key.
     */
    template<typename Key_T>
    Proxy operator[](Key_T const& key);

    //! Get the value for the given key
    /*! The returned value is converted to the type given by Value_T.
     *  \param key the key whose value should be retrieved from the hash.
     *  \return the value associated with the given key, converted to C++
     *  type Value_T.
     */
    template<typename Value_T, typename Key_T>
    Value_T get(Key_T const& key);

    //! A helper class for dereferencing iterators
    class Entry;

    //! A helper class for implementing iterators for a Hash.
    template<typename Hash_Ptr_T, typename Value_T>
    class Iterator;

  public:
    //! An iterator.
    typedef Iterator<Hash*, Entry> iterator;

    //! A const iterator.
    typedef Iterator<Hash const*, Entry const> const_iterator;

  public:
    //! Return an iterator to the beginning of the hash.
    iterator begin();

    //! Return a const iterator to the beginning of the hash.
    const_iterator begin() const;

    //! Return an iterator to the end of the hash.
    iterator end();

    //! Return a const to the end of the hash.
    const_iterator end() const;
  };

  //! A helper class so hash[key]=value can work.
  class Hash::Proxy
  {
  public:
    //! Construct a new Proxy.
    Proxy(Hash* hash, Object key);

    //! Implicit conversion to VALUE.
    operator VALUE() const;

    //! Explicit conversion to VALUE.
    VALUE value() const;

    //! Assignment operator.
    template<typename T>
    Object operator=(T const& value);

  private:
    Hash* hash_;
    Object key_;
  };

  //! A helper class for dereferencing iterators
  /*! This class is intended to look similar to an std::pair.
   */
  class Hash::Entry
  {
  public:
    //! Construct a new Entry.
    Entry(Hash* hash, Object key);

    //! Copy constructor.
    Entry(Entry const& entry);

    Object const key;          //!< The key
    Object const& first;      //!< An alias for the key

    Proxy value;              //!< The value
    Proxy& second;           //!< An alias for the value

    Entry& operator=(Entry const& rhs);

    friend bool operator<(Entry const& lhs, Entry const& rhs);
  };

  bool operator<(Hash::Entry const& lhs, Hash::Entry const& rhs);

  //! A helper class for implementing iterators for a Hash.
  template<typename Hash_Ptr_T, typename Value_T>
  class Hash::Iterator
  {
  public:
    using iterator_category = std::input_iterator_tag;
    using value_type = Value_T;
    using difference_type = long;
    using pointer = Object*;
    using reference = Value_T&;

    //! Construct a new Iterator.
    Iterator(Hash_Ptr_T hash);

    //! Construct a new Iterator with a given start-at index point
    Iterator(Hash_Ptr_T hash, int start_at);

    //! Construct an Iterator from another Iterator of a different const
    //! qualification.
    template<typename Iterator_T>
    Iterator(Iterator_T const& iterator);

    //! Preincrement operator.
    Iterator& operator++();

    //! Postincrement operator.
    Iterator operator++(int);

    //! Dereference operator.
    Value_T operator*();

    //! Dereference operator.
    Value_T* operator->();

    //! Equality operator.
    bool operator==(Iterator const& rhs) const;

    //! Inequality operator.
    bool operator!=(Iterator const& rhs) const;

    template<typename Hash_Ptr_T_, typename Value_T_>
    friend class Hash::Iterator;

  protected:
    Object current_key();

    Array hash_keys();

  private:
    Hash_Ptr_T hash_;
    long current_index_;
    VALUE keys_;

    mutable typename std::remove_const<Value_T>::type tmp_;
  };
} // namespace Rice



// =========   Module.hpp   =========

namespace Rice
{
  template <typename T>
  void validateType();

  //! A helper for defining a Module and its methods.
  /*! This class provides a C++-style interface to ruby's Module class and
   *  for defining methods on that module.
   *
   *  Many of the methods are defined in Module_impl.hpp so that they can
   *  return a reference to the most derived type.
   */
   // Module and Class both derive from Object to preserve Ruby's hierarchy.
  class Module : public Object
  {
  public:
    //! Default construct an empty Module wrapper.
    Module() = default;

    //! Construct a Module from an existing Module object.
    Module(VALUE v);

    //! Construct a Module from a string that references a Module
    Module(std::string name, Object under = rb_cObject);

    //! Return the name of the module.
    String name() const;

    //! Return an array containing the Module's ancestors.
    /*! You will need to include Array.hpp to use this function.
     */
    Array ancestors() const;

    //! Return the module's singleton class.
    /*! You will need to include Class.hpp to use this function.
     */
    Class singleton_class() const;

    //! Evaluate the given string in the context of the module.
    /*! This is equivalant to calling obj.module_eval(s) from inside the
     *  interpreter.
     *  \return the result of the expression.
     */
    Object module_eval(String const& s);

    // Include these methods to call methods from Module but return
// an instance of the current classes. This is an alternative to
// using CRTP.


//! Include a module.
/*! \param inc the module to be included.
*  \return *this
*/
inline auto& include_module(Module const& inc)
{
  detail::protect(rb_include_module, this->validated_value(), inc.value());
  return *this;
}

//! Define an instance method.
/*! The method's implementation can be a member function, plain function
 *  or lambda. The easiest case is a member function where the Ruby
 *  method maps one-to-one to the C++ method. In the case of a
 *  plain function or lambda, the first argument must be SELF - ie,
 *  the current object. If the type of the first argument is VALUE, then
 *  the current Ruby object is passed. If the type is a C++ class,
 *  then the C++ object is passed. If you don't want to include the
 *  SELF argument see define_function.
 *  Rice will automatically convert method parameters from Ruby to C++ and
 *  convert the return value from C++ to Ruby.
 *  \param name the name of the method
 *  \param func the implementation of the function, either a function
 *  pointer or a member function pointer.
 *  \param args a list of Arg instance used to define default parameters.
 *  \return *this
 */
template<typename Method_T, typename...Arg_Ts>
inline auto& define_method(std::string name, Method_T&& method, const Arg_Ts&...args)
{
  this->wrap_native_method(this->validated_value(), name, std::forward<Method_T>(method), args...);
  return *this;
}

//! Define a function.
/*! The function implementation is a plain function or a static
 *  member function.
 *  Rice will automatically convert method method from Ruby to C++ and
 *  then convert the return value from C++ to Ruby.
 *  \param name the name of the method
 *  \param func the implementation of the function, either a function
 *  pointer or a member function pointer.
 *  \param args a list of Arg instance used to define default parameters (optional)
 *  \return *this
 */
template<typename Function_T, typename...Arg_Ts>
inline auto& define_function(std::string name, Function_T&& func, const Arg_Ts&...args)
{
  this->wrap_native_function(this->validated_value(), name, std::forward<Function_T>(func), args...);
  return *this;
}

//! Define a singleton method.
/*! The method's implementation can be a static member function,
*   plain function or lambda. In all cases the first argument
*   must be SELF - ie, the current object. If it is specified as a VALUE, then
 *  the current Ruby object is passed. If it is specified as a C++ class,
 *  then the C++ object is passed. If you don't want to include the
 *  SELF argument see define_singleton_function.
 *  Rice will automatically convert method method from Ruby to C++ and
 *  then convert the return value from C++ to Ruby.
 *  \param name the name of the method
 *  \param func the implementation of the function, either a function
 *  pointer or a member function pointer.
 *  \param args a list of Arg instance used to define default parameters (optional)
 *  \return *this
 */
template<typename Method_T, typename...Arg_Ts>
inline auto& define_singleton_method(std::string name, Method_T&& method, const Arg_Ts&...args)
{
  this->wrap_native_method(rb_singleton_class(*this), name, std::forward<Method_T>(method), args...);
  return *this;
}

//! Define a singleton method.
/*! The method's implementation can be a static member function, plain
 *  function or lambda. A wrapper will be generated which will convert the method
 *  from ruby types to C++ types before calling the function.  The return
 *  value will be converted back to ruby.
 *  \param name the name of the method
 *  \param func the implementation of the function, either a function
 *  pointer or a member function pointer.
 *  \param args a list of Arg instance used to define default parameters (optional)
 *  \return *this
 */
template<typename Function_T, typename...Arg_Ts>
inline auto& define_singleton_function(std::string name, Function_T&& func, const Arg_Ts& ...args)
{
  this->wrap_native_function(rb_singleton_class(*this), name, std::forward<Function_T>(func), args...);
  return *this;
}

//! Define a module function.
/*! A module function is a function that can be accessed either as a
 *  singleton method or as an instance method. It wrap a plain
 *  function, static member function or lambda.
 *  Rice will automatically convert method method from Ruby to C++ and
 *  then convert the return value from C++ to Ruby.
 *  \param name the name of the method
 *  \param func the implementation of the function, either a function
 *  pointer or a member function pointer.
 *  \param args a list of Arg instance used to define default parameters (optional)
 *  \return *this
 */
template<typename Function_T, typename...Arg_Ts>
inline auto& define_module_function(std::string name, Function_T&& func, Arg_Ts&& ...args)
{
  if (this->rb_type() != T_MODULE)
  {
    throw std::runtime_error("can only define module functions for modules");
  }

  define_function(name, std::forward<Function_T>(func), args...);
  define_singleton_function(name, std::forward<Function_T>(func), args...);
  return *this;
}

//! Define a constant
template<typename Constant_T>
inline auto& define_constant(std::string name, Constant_T value)
{
  using Base_T = detail::remove_cv_recursive_t<Constant_T>;
  detail::protect(rb_define_const, this->validated_value(), name.c_str(), detail::To_Ruby<Base_T>().convert(value));
  return *this;
}
  protected:
    template<typename Function_T, typename ...Arg_Ts>
    void wrap_native_function(VALUE klass, std::string name, Function_T&& function, const Arg_Ts&...args);

    template<typename Class_T = VALUE, typename Method_T, typename ...Arg_Ts>
    void wrap_native_method(VALUE klass, std::string name, Method_T&& method, const Arg_Ts&...args);
  };

  //! Define a new module in the namespace given by module.
  /*! \param module the module in which to define the new module.
   *  \param name the name of the new module.
   */
  Module define_module_under(Object parent, char const * name);

  //! Define a new module in the default namespace.
  /*! \param name the name of the new module.
   */
  Module define_module(char const * name);

  //! Create a new anonymous module.
  /*! \return the new module.
   */
  Module anonymous_module();
}

// =========   Class.hpp   =========

namespace Rice
{
  //! A helper for defining a Class and its methods.
  /*! This class provides a C++-style interface to ruby's Class class and
   *  for defining methods on that class.
   */
  class Class: public Module
  {
  public:
    //! Default construct a new class wrapper and initialize it to
    //! rb_cObject.
    Class() = default;

    //! Construct a new class wrapper from a ruby object of type T_CLASS.
    Class(VALUE v);

    //! Disallow creation of an instance from Ruby code.
    /*! Undefines the singleton method allocate (or new, if using a
     *  version of ruby prior to 1.7) and the instance method initialize.
     */
    Class & undef_creation_funcs();

    // Create a new instance
    template<typename ...Parameter_Ts>
    Object create(Parameter_Ts ...args);

    //! Class name
    /*! \return std::string.
     */
    const std::string name() const;

    //! Base class name - does not include any parent modules
    /*! \return std::string.
     */
    const std::string base_name() const;

    //! Return the superclass of this class
    /*! \return Class.
     */
    Class superclass() const;

// Include these methods to call methods from Module but return
// an instance of the current classes. This is an alternative to
// using CRTP.


//! Include a module.
/*! \param inc the module to be included.
*  \return *this
*/
inline auto& include_module(Module const& inc)
{
  detail::protect(rb_include_module, this->validated_value(), inc.value());
  return *this;
}

//! Define an instance method.
/*! The method's implementation can be a member function, plain function
 *  or lambda. The easiest case is a member function where the Ruby
 *  method maps one-to-one to the C++ method. In the case of a
 *  plain function or lambda, the first argument must be SELF - ie,
 *  the current object. If the type of the first argument is VALUE, then
 *  the current Ruby object is passed. If the type is a C++ class,
 *  then the C++ object is passed. If you don't want to include the
 *  SELF argument see define_function.
 *  Rice will automatically convert method parameters from Ruby to C++ and
 *  convert the return value from C++ to Ruby.
 *  \param name the name of the method
 *  \param func the implementation of the function, either a function
 *  pointer or a member function pointer.
 *  \param args a list of Arg instance used to define default parameters.
 *  \return *this
 */
template<typename Method_T, typename...Arg_Ts>
inline auto& define_method(std::string name, Method_T&& method, const Arg_Ts&...args)
{
  this->wrap_native_method(this->validated_value(), name, std::forward<Method_T>(method), args...);
  return *this;
}

//! Define a function.
/*! The function implementation is a plain function or a static
 *  member function.
 *  Rice will automatically convert method method from Ruby to C++ and
 *  then convert the return value from C++ to Ruby.
 *  \param name the name of the method
 *  \param func the implementation of the function, either a function
 *  pointer or a member function pointer.
 *  \param args a list of Arg instance used to define default parameters (optional)
 *  \return *this
 */
template<typename Function_T, typename...Arg_Ts>
inline auto& define_function(std::string name, Function_T&& func, const Arg_Ts&...args)
{
  this->wrap_native_function(this->validated_value(), name, std::forward<Function_T>(func), args...);
  return *this;
}

//! Define a singleton method.
/*! The method's implementation can be a static member function,
*   plain function or lambda. In all cases the first argument
*   must be SELF - ie, the current object. If it is specified as a VALUE, then
 *  the current Ruby object is passed. If it is specified as a C++ class,
 *  then the C++ object is passed. If you don't want to include the
 *  SELF argument see define_singleton_function.
 *  Rice will automatically convert method method from Ruby to C++ and
 *  then convert the return value from C++ to Ruby.
 *  \param name the name of the method
 *  \param func the implementation of the function, either a function
 *  pointer or a member function pointer.
 *  \param args a list of Arg instance used to define default parameters (optional)
 *  \return *this
 */
template<typename Method_T, typename...Arg_Ts>
inline auto& define_singleton_method(std::string name, Method_T&& method, const Arg_Ts&...args)
{
  this->wrap_native_method(rb_singleton_class(*this), name, std::forward<Method_T>(method), args...);
  return *this;
}

//! Define a singleton method.
/*! The method's implementation can be a static member function, plain
 *  function or lambda. A wrapper will be generated which will convert the method
 *  from ruby types to C++ types before calling the function.  The return
 *  value will be converted back to ruby.
 *  \param name the name of the method
 *  \param func the implementation of the function, either a function
 *  pointer or a member function pointer.
 *  \param args a list of Arg instance used to define default parameters (optional)
 *  \return *this
 */
template<typename Function_T, typename...Arg_Ts>
inline auto& define_singleton_function(std::string name, Function_T&& func, const Arg_Ts& ...args)
{
  this->wrap_native_function(rb_singleton_class(*this), name, std::forward<Function_T>(func), args...);
  return *this;
}

//! Define a module function.
/*! A module function is a function that can be accessed either as a
 *  singleton method or as an instance method. It wrap a plain
 *  function, static member function or lambda.
 *  Rice will automatically convert method method from Ruby to C++ and
 *  then convert the return value from C++ to Ruby.
 *  \param name the name of the method
 *  \param func the implementation of the function, either a function
 *  pointer or a member function pointer.
 *  \param args a list of Arg instance used to define default parameters (optional)
 *  \return *this
 */
template<typename Function_T, typename...Arg_Ts>
inline auto& define_module_function(std::string name, Function_T&& func, Arg_Ts&& ...args)
{
  if (this->rb_type() != T_MODULE)
  {
    throw std::runtime_error("can only define module functions for modules");
  }

  define_function(name, std::forward<Function_T>(func), args...);
  define_singleton_function(name, std::forward<Function_T>(func), args...);
  return *this;
}

//! Define a constant
template<typename Constant_T>
inline auto& define_constant(std::string name, Constant_T value)
{
  using Base_T = detail::remove_cv_recursive_t<Constant_T>;
  detail::protect(rb_define_const, this->validated_value(), name.c_str(), detail::To_Ruby<Base_T>().convert(value));
  return *this;
}
  };

  //! Define a new class in the namespace given by module.
  /*! \param module the Module in which to define the class.
   *  \param name the name of the class.
   *  \param superclass the base class to use.
   *  \return the new class.
   */
  Class define_class_under(Object parent, char const * name, const Class& superclass = rb_cObject);
  Class define_class_under(Object parent, Identifier id, const Class& superclass = rb_cObject);

  //! Define a new class in the default namespace.
  /*! \param name the name of the class.
   *  \param superclass the base class to use.
   *  \return the new class.
   */
  Class define_class(char const * name, const Class& superclass = rb_cObject);

  //! Create a new anonymous class.
  /*! \return the new class.
   */
  Class anonymous_class();
} // namespace Rice



// =========   Native.hpp   =========

namespace Rice::detail
{
  class Native;

  class Resolved
  {
  public:
    inline bool operator<(Resolved other);
    inline bool operator>(Resolved other);

    double score;  // Combined score: minParameterScore * parameterMatch
    Native* native;
  };

  enum class NativeKind
  {
    Function,
    Method,
    Iterator,
    AttributeReader,
    AttributeWriter,
    Proc,
    Callback
  };

  class Native
  {
  public:
    static VALUE resolve(int argc, VALUE* argv, VALUE self);
  public:
    Native(std::string name);
    Native(std::string name, std::unique_ptr<Return>&& returnInfo);
    Native(std::string name, std::unique_ptr<Return>&& returnInfo, std::vector<std::unique_ptr<ParameterAbstract>>&& parameters);
    virtual ~Native() = default;

    Native(const Native&) = delete;
    Native(Native&&) = delete;
    void operator=(const Native&) = delete;
    void operator=(Native&&) = delete;

    virtual Resolved matches(std::map<std::string, VALUE>& values);
    virtual VALUE operator()(std::map<std::string, VALUE>& values, VALUE self) = 0;
    virtual std::string toString() = 0;

    // Ruby API access
    std::string name();
    std::vector<const ParameterAbstract*> parameters();
    virtual NativeKind kind() = 0;
    virtual VALUE returnKlass() = 0;

  protected:
    template<typename T, bool isBuffer>
    static void verify_type();

    static std::map<std::string, VALUE> readRubyArgs(size_t argc, const VALUE* argv);
    std::vector<std::optional<VALUE>> getRubyValues(std::map<std::string, VALUE> values, bool validate);
    ParameterAbstract* getParameterByName(std::string name);
    double matchParameters(std::vector<std::optional<VALUE>>& values, size_t argc);

    template<typename Parameter_Tuple, typename... Arg_Ts>
    static std::vector<std::unique_ptr<ParameterAbstract>> create_parameters(Arg_Ts&& ...args);

    template<typename... Arg_Ts>
    static std::unique_ptr<Return> create_return(Arg_Ts& ...args);

    // Do we need to keep alive any arguments?
    void checkKeepAlive(VALUE self, VALUE returnValue, std::vector<std::optional<VALUE>>& rubyValues);

  private:
    template<typename Parameter_Tuple, typename Arg_Tuple, std::size_t ...Indices>
    static inline void create_parameters_impl(std::vector<std::unique_ptr<ParameterAbstract>>& parameters, std::index_sequence<Indices...> indices, std::vector<std::unique_ptr<Arg>>&& args);

    template<typename Parameter_Tuple, typename Arg_Tuple, size_t I>
    static void verify_parameter();

  protected:
    std::string name_;
    std::unique_ptr<Return> returnInfo_;
    std::vector<std::unique_ptr<ParameterAbstract>> parameters_;
  };
}


// =========   NativeAttributeGet.hpp   =========

namespace Rice
{
  struct AttrAccess
  {
    struct ReadWriteType {};
    struct ReadType {};
    struct WriteType {};

    static constexpr ReadWriteType ReadWrite{};
    static constexpr ReadType Read{};
    static constexpr WriteType Write{};
  };

  namespace detail
  {
    template<typename Attribute_T>
    class NativeAttributeGet: Native
    {
    public:
      using NativeAttribute_T = NativeAttributeGet<Attribute_T>;

      using Attr_T = typename attribute_traits<Attribute_T>::attr_type;
      using Receiver_T = typename attribute_traits<Attribute_T>::class_type;
      using To_Ruby_T = remove_cv_recursive_t<Attr_T>;

    public:
      // Register attribute getter with Ruby
      template<typename...Arg_Ts>
      static void define(VALUE klass, std::string name, Attribute_T attribute, Arg_Ts&...args);

    public:
      // Disallow creating/copying/moving
      NativeAttributeGet() = delete;
      NativeAttributeGet(const NativeAttribute_T&) = delete;
      NativeAttributeGet(NativeAttribute_T&&) = delete;
      void operator=(const NativeAttribute_T&) = delete;
      void operator=(NativeAttribute_T&&) = delete;

      Resolved matches(std::map<std::string, VALUE>& values) override;
      VALUE operator()(std::map<std::string, VALUE>& values, VALUE self) override;
      std::string toString() override;

      NativeKind kind() override;
      VALUE returnKlass() override;

    protected:
      NativeAttributeGet(VALUE klass, std::string name, Attribute_T attr, std::unique_ptr<Return>&& returnInfo);

    private:
      VALUE klass_;
      Attribute_T attribute_;
    };
  } // detail
} // Rice


// =========   NativeAttributeSet.hpp   =========

namespace Rice
{
  namespace detail
  {
    template<typename Attribute_T>
    class NativeAttributeSet: Native
    {
    public:
      using NativeAttribute_T = NativeAttributeSet<Attribute_T>;
      using Attr_T = typename attribute_traits<Attribute_T>::attr_type;
      using T_Unqualified = remove_cv_recursive_t<Attr_T>;
      using Receiver_T = typename attribute_traits<Attribute_T>::class_type;

    public:
      // Register attribute setter with Ruby
      template<typename...Arg_Ts>
      static void define(VALUE klass, std::string name, Attribute_T attribute, Arg_Ts&...args);

    public:
      // Disallow creating/copying/moving
      NativeAttributeSet() = delete;
      NativeAttributeSet(const NativeAttribute_T&) = delete;
      NativeAttributeSet(NativeAttribute_T&&) = delete;
      void operator=(const NativeAttribute_T&) = delete;
      void operator=(NativeAttribute_T&&) = delete;

      Resolved matches(std::map<std::string, VALUE>& values) override;
      VALUE operator()(std::map<std::string, VALUE>& values, VALUE self) override;
      std::string toString() override;

      NativeKind kind() override;
      VALUE returnKlass() override;

    protected:
      NativeAttributeSet(VALUE klass, std::string name, Attribute_T attr, std::unique_ptr<Parameter<T_Unqualified>> parameter);

    private:
      VALUE klass_;
      Attribute_T attribute_;
      std::unique_ptr<Parameter<T_Unqualified>> parameter_;
    };
  } // detail
} // Rice


// =========   Data_Type.hpp   =========

#include <set>

namespace Rice
{
  //! A mechanism for binding ruby types to C++ types.
  /*! This class binds run-time types (Ruby VALUEs) to compile-time types
   *  (C++ types).  The binding can occur only once.
   */
  template<typename T>
  class Data_Type : public Class
  {
  public:
    using type = T;

    //! Default constructor which does not bind.
    /*! No member functions must be called on this Data_Type except bind,
     *  until the type is bound.
     */
    Data_Type();

    //! Constructor which takes a Module.
    /*! Binds the type to the given VALUE according to the rules given
     *  above.
     *  \param klass the module to which to bind.
     */
    Data_Type(Module const & v);

    //! Return the Ruby class.
    /*! \return the ruby class to which the type is bound.
     */
    static Class klass();

    //! Return the Ruby data type.
    static rb_data_type_t* ruby_data_type();

    //! Assignment operator which takes a Module
    /*! \param klass must be the class to which this data type is already
     *  bound.
     *  \return *this
     */
    Data_Type& operator=(Module const & klass);

    /*! Creates a singleton method allocate and an instance method called
     *  initialize which together create a new instance of the class.  The
     *  allocate method allocates memory for the object reference and the
     *  initialize method constructs the object.
     *  \param constructor an object that has a static member function
     *  construct() that constructs a new instance of T and sets the object's data
     *  member to point to the new instance.  A helper class Constructor
     *  is provided that does precisely this.
     *  \param args a list of Arg instance used to define default parameters (optional)
     *
     *  For example:
     *  \code
     *    define_class<Foo>("Foo")
     *      .define_constructor(Constructor<Foo>());
     *  \endcode
     */
    template<typename Constructor_T, typename...Rice_Arg_Ts>
    Data_Type<T>& define_constructor(Constructor_T constructor, Rice_Arg_Ts const& ...args);

    //! Register a Director class for this class.
    /*! For any class that uses Rice::Director to enable polymorphism
     *  across the languages, you need to register that director proxy
     *  class with this method. Not doing so will cause the resulting 
     *  library to die at run time when it tries to convert the base
     *  type into the Director proxy type.
     *
     *  This method needs the type of the Director proxy class.
     *
     *  For example:
     *  \code
     *    class FooDirector : public Foo, public Rice::Director {
     *      ...
     *    };
     *
     *    define_class<Foo>("Foo")
     *      .define_director<FooDirector>()
     *      .define_constructor(Constructor<FooDirector, Rice::Object>());
     *  \endcode
     */
    template<typename Director_T>
    Data_Type<T>& define_director();

    //! Determine if the type is bound.
    /*! \return true if the object is bound, false otherwise.
     */
    static bool is_bound();
    static void check_is_bound();
    static bool is_defined();
    static bool check_defined(const std::string& name, Object parent = rb_cObject);

    // This is only for testing - DO NOT USE!!!
    static void unbind();

    static bool is_descendant(VALUE value);
  
    //! Define an iterator.
    /*! Essentially this is a conversion from a C++-style begin/end
     *  iterator to a Ruby-style \#each iterator.
     *  \param begin a member function pointer to a function that returns
     *  an iterator to the beginning of the sequence.
     *  \param end a member function pointer to a function that returns an
     *  iterator to the end of the sequence.
     *  \param name the name of the iterator.
     *  \return *this
     */

    template<typename Iterator_Func_T>
    Data_Type<T>& define_iterator(Iterator_Func_T begin, Iterator_Func_T end, std::string name = "each");

    template <typename Attribute_T, typename Access_T = AttrAccess::ReadWriteType, typename...Arg_Ts>
    Data_Type<T>& define_attr(std::string name, Attribute_T attribute, Access_T access = {}, const Arg_Ts&...args);

    template <typename Attribute_T, typename Access_T = AttrAccess::ReadWriteType, typename...Arg_Ts>
    Data_Type<T>& define_singleton_attr(std::string name, Attribute_T attribute, Access_T access = {}, const Arg_Ts&...args);

    // Include these methods to call methods from Module but return
// an instance of the current classes. This is an alternative to
// using CRTP.


//! Include a module.
/*! \param inc the module to be included.
*  \return *this
*/
inline auto& include_module(Module const& inc)
{
  detail::protect(rb_include_module, this->validated_value(), inc.value());
  return *this;
}

//! Define an instance method.
/*! The method's implementation can be a member function, plain function
 *  or lambda. The easiest case is a member function where the Ruby
 *  method maps one-to-one to the C++ method. In the case of a
 *  plain function or lambda, the first argument must be SELF - ie,
 *  the current object. If the type of the first argument is VALUE, then
 *  the current Ruby object is passed. If the type is a C++ class,
 *  then the C++ object is passed. If you don't want to include the
 *  SELF argument see define_function.
 *  Rice will automatically convert method parameters from Ruby to C++ and
 *  convert the return value from C++ to Ruby.
 *  \param name the name of the method
 *  \param func the implementation of the function, either a function
 *  pointer or a member function pointer.
 *  \param args a list of Arg instance used to define default parameters.
 *  \return *this
 */
template<typename Method_T, typename...Arg_Ts>
inline auto& define_method(std::string name, Method_T&& method, const Arg_Ts&...args)
{
  this->wrap_native_method(this->validated_value(), name, std::forward<Method_T>(method), args...);
  return *this;
}

//! Define a function.
/*! The function implementation is a plain function or a static
 *  member function.
 *  Rice will automatically convert method method from Ruby to C++ and
 *  then convert the return value from C++ to Ruby.
 *  \param name the name of the method
 *  \param func the implementation of the function, either a function
 *  pointer or a member function pointer.
 *  \param args a list of Arg instance used to define default parameters (optional)
 *  \return *this
 */
template<typename Function_T, typename...Arg_Ts>
inline auto& define_function(std::string name, Function_T&& func, const Arg_Ts&...args)
{
  this->wrap_native_function(this->validated_value(), name, std::forward<Function_T>(func), args...);
  return *this;
}

//! Define a singleton method.
/*! The method's implementation can be a static member function,
*   plain function or lambda. In all cases the first argument
*   must be SELF - ie, the current object. If it is specified as a VALUE, then
 *  the current Ruby object is passed. If it is specified as a C++ class,
 *  then the C++ object is passed. If you don't want to include the
 *  SELF argument see define_singleton_function.
 *  Rice will automatically convert method method from Ruby to C++ and
 *  then convert the return value from C++ to Ruby.
 *  \param name the name of the method
 *  \param func the implementation of the function, either a function
 *  pointer or a member function pointer.
 *  \param args a list of Arg instance used to define default parameters (optional)
 *  \return *this
 */
template<typename Method_T, typename...Arg_Ts>
inline auto& define_singleton_method(std::string name, Method_T&& method, const Arg_Ts&...args)
{
  this->wrap_native_method(rb_singleton_class(*this), name, std::forward<Method_T>(method), args...);
  return *this;
}

//! Define a singleton method.
/*! The method's implementation can be a static member function, plain
 *  function or lambda. A wrapper will be generated which will convert the method
 *  from ruby types to C++ types before calling the function.  The return
 *  value will be converted back to ruby.
 *  \param name the name of the method
 *  \param func the implementation of the function, either a function
 *  pointer or a member function pointer.
 *  \param args a list of Arg instance used to define default parameters (optional)
 *  \return *this
 */
template<typename Function_T, typename...Arg_Ts>
inline auto& define_singleton_function(std::string name, Function_T&& func, const Arg_Ts& ...args)
{
  this->wrap_native_function(rb_singleton_class(*this), name, std::forward<Function_T>(func), args...);
  return *this;
}

//! Define a module function.
/*! A module function is a function that can be accessed either as a
 *  singleton method or as an instance method. It wrap a plain
 *  function, static member function or lambda.
 *  Rice will automatically convert method method from Ruby to C++ and
 *  then convert the return value from C++ to Ruby.
 *  \param name the name of the method
 *  \param func the implementation of the function, either a function
 *  pointer or a member function pointer.
 *  \param args a list of Arg instance used to define default parameters (optional)
 *  \return *this
 */
template<typename Function_T, typename...Arg_Ts>
inline auto& define_module_function(std::string name, Function_T&& func, Arg_Ts&& ...args)
{
  if (this->rb_type() != T_MODULE)
  {
    throw std::runtime_error("can only define module functions for modules");
  }

  define_function(name, std::forward<Function_T>(func), args...);
  define_singleton_function(name, std::forward<Function_T>(func), args...);
  return *this;
}

//! Define a constant
template<typename Constant_T>
inline auto& define_constant(std::string name, Constant_T value)
{
  using Base_T = detail::remove_cv_recursive_t<Constant_T>;
  detail::protect(rb_define_const, this->validated_value(), name.c_str(), detail::To_Ruby<Base_T>().convert(value));
  return *this;
}
  protected:
    //! Bind a Data_Type to a VALUE.
    /*! Throws an exception if the Data_Type is already bound to a
     *  different class.  Any existing instances of the Data_Type will be
     *  bound after this function returns.
     *  \param klass the ruby type to which to bind.
     *  \return *this
     */
    template <typename Base_T = void>
    static Data_Type<T> bind(const Module& klass);

    template<typename T_, typename Base_T>
    friend Rice::Data_Type<T_> define_class_under(Object parent, Identifier id, Class superKlass);

    template<typename T_, typename Base_T>
    friend Rice::Data_Type<T_> define_class_under(Object parent, char const * name);

    template<typename T_, typename Base_T>
    friend Rice::Data_Type<T_> define_class(char const * name);

    template<typename Method_T, typename...Arg_Ts>
    void wrap_native_method(VALUE klass, std::string name, Method_T&& function, const Arg_Ts&...args);

    template <typename Attribute_T, typename Access_T, typename...Arg_Ts>
    Data_Type<T>& define_attr_internal(VALUE klass, std::string name, Attribute_T attribute, Access_T access, const Arg_Ts&...args);

  private:
    template<typename T_>
    friend class Data_Type;

    static inline VALUE klass_ = Qnil;

    // Typed Data support
    static inline rb_data_type_t* rb_data_type_ = nullptr;

    static inline std::set<Data_Type<T>*>& unbound_instances();
  };

  //! Define a new data class in the namespace given by module.
  /*! This override allows you to specify a Ruby class as the base class versus a 
   *  wrapped C++ class. This functionality is rarely needed - but is essential for
   *  creating new custom Exception classes where the Ruby superclass should be
   *  rb_eStandard
   *  \param T the C++ type of the wrapped class.
   *  \param module the Module in which to define the class.
   *  \param name the name of the new class.
   *  \param superKlass the Ruby super class.
   *  \return the new class.
   */
  template<typename T, typename Base_T = void>
  Data_Type<T> define_class_under(Object parent, Identifier id, Class superKlass = rb_cObject);

  //! Define a new data class in the namespace given by module.
  /*! By default the class will inherit from Ruby's rb_cObject. This
   *  can be overriden via the Base_T template parameter. Note that
   *  Base_T must already have been registered.
   *  \param T the C++ type of the wrapped class.
   *  \param module the the Module in which to define the class.
   *  \return the new class.
   */
  template<typename T, typename Base_T = void>
  Data_Type<T> define_class_under(Object parent, char const* name);

  //! Define a new data class in the default namespace.
  /*! By default the class will inherit from Ruby's rb_cObject. This
   *  can be overriden via the Base_T template parameter. Note that
   *  Base_T must already have been registered.
   *  \param T the C++ type of the wrapped class.
   *  \param module the the Module in which to define the class.
   *  \return the new class.
   */
  template<typename T, typename Base_T = void>
  Data_Type<T> define_class(char const* name);
}


// =========   Data_Object.hpp   =========

/*! \file
 *  \brief Provides a helper class for wrapping and unwrapping C++
 *  objects as Ruby objects.
 */

namespace Rice
{
  //! A smartpointer-like wrapper for Ruby data objects.
  /*! A data object is a ruby object of type T_DATA, which is usually
   *  created by using the Data_Wrap_Struct or Data_Make_Struct macro.
   *  This class wraps creation of the data structure, providing a
   *  type-safe object-oriented interface to the underlying C interface.
   *  This class works in conjunction with the Data_Type class to ensure
   *  type safety.
   *
   *  Example:
   *  \code
   *    class Foo { };
   *    ...
   *    Data_Type<Foo> rb_cFoo = define_class("Foo");
   *    ...
   *    // Wrap:
   *    Data_Object<Foo> foo1(new Foo);
   *
   *    // Get value to return:
   *    VALUE v = foo1.value()
   *
   *    // Unwrap:
   *    Data_Object<Foo> foo2(v, rb_cFoo);
   *  \endcode
   */
  template<typename T>
  class Data_Object : public Object
  {
    static_assert(!std::is_pointer_v<T>);
    static_assert(!std::is_reference_v<T>);
    static_assert(!std::is_const_v<T>);
    static_assert(!std::is_volatile_v<T>);
    static_assert(!std::is_void_v<T>);

  public:
    //! Wrap a C++ object.
    /*! This constructor is analogous to calling Data_Wrap_Struct.  Be
     *  careful not to call this function more than once for the same
     *  pointer (in general, it should only be called for newly
     *  constructed objects that need to be managed by Ruby's garbage
     *  collector).
     *  \param obj the object to wrap.
     *  \param isOwner Should the Data_Object take ownership of the object?
     *  \param klass the Ruby class to use for the newly created Ruby
     *  object.
     */
    Data_Object(T* obj, bool isOwner = false, Class klass = Data_Type<T>::klass());
    Data_Object(T& obj, bool isOwner = false, Class klass = Data_Type<T>::klass());
    Data_Object(T&& obj, Class klass = Data_Type<T>::klass());
    Data_Object(const T& obj, bool isOwner = false, Class klass = Data_Type<T>::klass());

    //! Unwrap a Ruby object.
    /*! This constructor is analogous to calling Data_Get_Struct.  Uses
     *  Data_Type<T>::klass as the class of the object.
     *  \param value the Ruby object to unwrap.
     */
    Data_Object(Object value);
    Data_Object(VALUE value);

    T& operator*() const; //!< Return a reference to obj_
    T* operator->() const; //!< Return a pointer to obj_
    T* get() const;        //!< Return a pointer to obj_

  private:
    static void check_ruby_type(VALUE value);
  };
} // namespace Rice


// =========   RubyType.ipp   =========
namespace Rice::detail
{
  template<>
  class RubyType<bool>
  {
  public:
    using FromRuby_T = bool(*)(VALUE);

    static inline FromRuby_T fromRuby = RB_TEST;
    static inline std::string packTemplate = "not supported";
    static inline std::string name = "bool";
  };

  template<>
  class RubyType<char>
  {
  public:
    using FromRuby_T = char(*)(VALUE);

    static inline FromRuby_T fromRuby = rb_num2char_inline;
    static inline std::string packTemplate = CHAR_MIN < 0 ? "c*" : "C*";
    static inline std::string name = "String";
  };

  template<>
  class RubyType<signed char>
  {
  public:
    using FromRuby_T =  char(*)(VALUE);

    static inline FromRuby_T fromRuby = rb_num2char_inline;
    static inline std::string packTemplate = "c*";
    static inline std::string name = "String";
  };

  template<>
  class RubyType<unsigned char>
  {
  public:
    using FromRuby_T = char(*)(VALUE);

    static inline FromRuby_T fromRuby = rb_num2char_inline;
    static inline std::string packTemplate = "C*";
    static inline std::string name = "String";
  };

  template<>
  class RubyType<short>
  {
  public:
    using FromRuby_T = short(*)(VALUE);

    static inline FromRuby_T fromRuby = rb_num2short_inline;
    static inline std::string packTemplate = "s*";
    static inline std::string name = "Integer";
  };

  template<>
  class RubyType<unsigned short>
  {
  public:
    using FromRuby_T = unsigned short(*)(VALUE);

    static inline FromRuby_T fromRuby = rb_num2ushort;
    static inline std::string packTemplate = "S*";
    static inline std::string name = "Integer";
  };

  template<>
  class RubyType<int>
  {
  public:
    using FromRuby_T = int(*)(VALUE);

    static inline FromRuby_T fromRuby = rb_num2int_inline;
    static inline std::string packTemplate = "i*";
    static inline std::string name = "Integer";
  };

  template<>
  class RubyType<unsigned int>
  {
  public:
    using FromRuby_T = unsigned int(*)(VALUE);

    static inline FromRuby_T fromRuby = RB_NUM2UINT;
    static inline std::string packTemplate = "I*";
    static inline std::string name = "Integer";
  };

  template<>
  class RubyType<long>
  {
  public:
    using FromRuby_T = long(*)(VALUE);

    static inline FromRuby_T fromRuby = rb_num2long_inline;
    static inline std::string packTemplate = "l_*";
    static inline std::string name = "Integer";
  };

  template<>
  class RubyType<unsigned long>
  {
  public:
    using FromRuby_T = unsigned long(*)(VALUE);

    static inline FromRuby_T fromRuby = rb_num2ulong_inline;
    static inline std::string packTemplate = "L_*";
    static inline std::string name = "Integer";
  };

  template<>
  class RubyType<long long>
  {
  public:
    using FromRuby_T = long long(*)(VALUE);

    static inline FromRuby_T fromRuby = rb_num2ll_inline;
    static inline std::string packTemplate = "q_*";
    static inline std::string name = "Integer";
  };

  template<>
  class RubyType<unsigned long long>
  {
  public:
    using FromRuby_T = unsigned long long(*)(VALUE);

    static inline FromRuby_T fromRuby = RB_NUM2ULL;
    static inline std::string packTemplate = "Q_*";
    static inline std::string name = "Integer";
  };

  template<>
  class RubyType<float>
  {
  public:
    using FromRuby_T = double(*)(VALUE);

    static inline FromRuby_T fromRuby = rb_num2dbl;
    static inline std::string packTemplate = "f*";
    static inline std::string name = "Float";
  };

  template<>
  class RubyType<double>
  {
  public:
    using FromRuby_T = double(*)(VALUE);

    static inline FromRuby_T fromRuby = rb_num2dbl;
    static inline std::string packTemplate = "d*";
    static inline std::string name = "Float";
  };

  template<>
  class RubyType<long double>
  {
  public:
    using FromRuby_T = double(*)(VALUE);

    static inline FromRuby_T fromRuby = rb_num2dbl;
    static inline std::string packTemplate = "d*";
    static inline std::string name = "Float";
  };

  template<>
  class RubyType<void>
  {
  public:
    static inline std::string name = "void";
  };
}

// Registries

// =========   TypeRegistry.hpp   =========

#include <optional>
#include <unordered_map>
#include <set>
#include <regex>


/* The type registry keeps track of all C++ types wrapped by Rice. When a native function returns 
   an instance of a class/struct we look up its type to verity that it has been registered. 
   
   We have to do this to support C++ inheritance. If a C++ function returns a pointer/reference
   to an Abstract class, the actual returned object will be a Child class. However, all we know
   from the C++ method signature is that it is an Absract class - thus the need for a registry.*/

namespace Rice::detail
{
  class TypeRegistry
  {
  public:
    template <typename T>
    void add(VALUE klass, rb_data_type_t* rbType);

    template <typename T>
    void remove();

    template <typename T>
    bool isDefined();

    template <typename T>
    std::pair<VALUE, rb_data_type_t*> getType();

    template <typename T>
    bool verify();
      
    template <typename T>
    std::pair<VALUE, rb_data_type_t*> figureType(const T& object);

    // Validate types and throw if any types are unverified
    void validateTypes();

    // Clear unverified types. This is mostly for unit tests
    void clearUnverifiedTypes();

    // API for access from Ruby
    VALUE klasses();

  private:
    template <typename T>
    std::type_index key();

    std::optional<std::pair<VALUE, rb_data_type_t*>> lookup(std::type_index typeIndex);
    void raiseUnverifiedType(const std::string& typeName);

    std::unordered_map<std::type_index, std::pair<VALUE, rb_data_type_t*>> registry_{};
    std::set<std::type_index> unverified_{};
  };
}


// =========   InstanceRegistry.hpp   =========

#include <type_traits>

namespace Rice::detail
{
  class InstanceRegistry
  {
  public:
    enum class Mode
    {
      Off,
      Owned,
      All
    };

    template <typename T>
    VALUE lookup(T* cppInstance, bool isOwner);

    template <typename T>
    void add(T* cppInstance, VALUE rubyInstance, bool isOwner);

    void remove(void* cppInstance);
    void clear();

  public:
    Mode mode = Mode::Owned;

  private:
    bool shouldTrack(bool isOwner) const;

    std::map<void*, VALUE> objectMap_;
  };
} // namespace Rice::detail


// =========   DefaultHandler.hpp   =========

namespace Rice::detail
{
  class DefaultHandler
  {
  public:
    void operator()() const;
  };
}

// =========   HandlerRegistry.hpp   =========

#include <functional>

namespace Rice::detail
{
  class HandlerRegistry
  {
  public:
    HandlerRegistry();
    void set(std::function<void()> handler);
    std::function<void()> handler() const;

  private:
    std::function<void()> handler_;
  };
} // namespace Rice::detail



// =========   ModuleRegistry.hpp   =========

namespace Rice::detail
{
  class ModuleRegistry
  {
  public:
    void add(VALUE module);
    // API for access from Ruby
    VALUE modules();

  private:
    std::set<VALUE> modules_{};
  };
}


// =========   NativeRegistry.hpp   =========

#include <memory>
#include <utility>

/* The Native Registry tracks C++ instance that are used to invoke C++ methods for Ruby. 
   These objects include instances of the NativeFunction, NativeIterator, NativeAttributeGet
   and NativeAttributeSet Each instance is specialized to call a specific C++ function, method
   or attribute that is exposed to Ruby.
   
   The registry stores these C++ instances using a map of vectors. The map is keyed on the 
   the Ruby class (VALUE) and method id (ID). The value is a vector of Native pointers stored
   in a std::unique_ptr. Thus the registry takes ownership of the pointers when calling
   code adds them to the registry. The value is a vector to support C++ method overloading.
   
   Note - when an existing Ruby class is redefined using rb_define_class, its VALUE stays the same
   but all its methods and fields are reset. Thus any call to rb_define_class must be followed
   by calling the reset method on the registry. Although redefinition shouldn't happen in 
   production code it happens in many places in the unit tests. */
   
namespace Rice::detail
{
  class NativeRegistry
  {
  public:
    // std::is_copy_constructible returns true for std::vector<std::unique_ptr> - so we need
    // to force the issue
    NativeRegistry() = default;
    NativeRegistry(const NativeRegistry& other) = delete;
    NativeRegistry& operator=(const NativeRegistry& other) = delete;

    void add(VALUE klass, ID methodId, std::unique_ptr<Native>& native);
    void replace(VALUE klass, ID methodId, std::unique_ptr<Native>& native);
    void reset(VALUE klass);

    std::vector<Native*> lookup(VALUE klass);
    std::vector<std::unique_ptr<Native>>& lookup(VALUE klass, ID methodId);
    std::vector<Native*> lookup(VALUE klass, NativeKind kind);

  private:
    // Key - Ruby klass/method
    // Value - Vector of Native pointers owned by the registry (thus wrapped in std::unique_ptr)
    std::map<std::pair<VALUE, ID>, std::vector<std::unique_ptr<Native>>> natives_ = {};
  };
}


// =========   Registries.hpp   =========

namespace Rice::detail
{
  class Registries
  {
  public:
    static Registries instance;

  public:
    HandlerRegistry handlers;
    InstanceRegistry instances;
    ModuleRegistry modules;
    NativeRegistry natives;
    TypeRegistry types;
  };
}



// =========   Buffer.hpp   =========

namespace Rice
{
  template<typename T, typename = void>
  class Buffer;
    
  template<typename T>
  class Buffer<T, std::enable_if_t<!std::is_pointer_v<T> && !std::is_void_v<T>>>
  {
  public:
    Buffer(T* pointer);
    Buffer(T* pointer, size_t size);
    Buffer(VALUE value);
    Buffer(VALUE value, size_t size);

    ~Buffer();

    Buffer(const Buffer& other) = delete;
    Buffer(Buffer&& other);

    Buffer& operator=(const Buffer& other) = delete;
    Buffer& operator=(Buffer&& other);
    T& operator[](size_t index);

    T* ptr();
    T& reference();
    T* release();

    size_t size() const;

    // Ruby API
    VALUE toString() const;

    VALUE bytes() const;
    VALUE bytes(size_t count) const;

    Array toArray() const;
    Array toArray(size_t count) const;

    bool isOwner() const;
    void setOwner(bool value);

  private:
    void fromBuiltinType(VALUE value, size_t size);
    void fromWrappedType(VALUE value, size_t size);

    bool m_owner = false;
    size_t m_size = 0;
    // std::unique_ptr would be great but std::unique_ptr<void> isn't allowed. Mutable is needed to
    // support const T* buffers
    mutable T* m_buffer = nullptr;
  };

  template<typename T>
  class Buffer<T*, std::enable_if_t<!detail::is_wrapped_v<T> && !std::is_void_v<T>>>
  {
  public:
    Buffer(T** pointer);
    Buffer(T** pointer, size_t size);
    Buffer(VALUE value);
    Buffer(VALUE value, size_t size);

    ~Buffer();

    Buffer(const Buffer& other) = delete;
    Buffer(Buffer&& other);

    Buffer& operator=(const Buffer& other) = delete;
    Buffer& operator=(Buffer&& other);

    T* operator[](size_t index);

    T** ptr();
    T** release();

    size_t size() const;

    // Ruby API
    VALUE toString() const;

    VALUE bytes() const;
    VALUE bytes(size_t count) const;

    Array toArray() const;
    Array toArray(size_t count) const;

    void setOwner(bool value);
    bool isOwner() const;

  private:
    bool m_owner = false;
    size_t m_size = 0;
    T** m_buffer = nullptr;
  };

  template<typename T>
  class Buffer<T*, std::enable_if_t<detail::is_wrapped_v<T>>>
  {
  public:
    Buffer(T** pointer);
    Buffer(T** pointer, size_t size);
    Buffer(VALUE value);
    Buffer(VALUE value, size_t size);

    ~Buffer();

    Buffer(const Buffer& other) = delete;
    Buffer(Buffer&& other);

    Buffer& operator=(const Buffer& other) = delete;
    Buffer& operator=(Buffer&& other);

    T* operator[](size_t index);

    T** ptr();
    T** release();

    size_t size() const;

    // Ruby API
    VALUE toString() const;

    VALUE bytes() const;
    VALUE bytes(size_t count) const;

    Array toArray() const;
    Array toArray(size_t count) const;

    void setOwner(bool value);
    bool isOwner() const;

  private:
    bool m_owner = false;
    size_t m_size = 0;
    T** m_buffer = nullptr;
  };

  template<typename T>
  class Buffer<T, std::enable_if_t<std::is_void_v<T>>>
  {
  public:
    Buffer(T* pointer);
    Buffer(VALUE value);
    Buffer(VALUE value, size_t size);

    Buffer(const Buffer& other) = delete;
    Buffer(Buffer&& other);

    Buffer& operator=(const Buffer& other) = delete;
    Buffer& operator=(Buffer&& other);

    size_t size() const;

    VALUE bytes(size_t count) const;
    VALUE bytes() const;

    T* ptr();
    T* release();

  private:
    bool m_owner = false;
    size_t m_size = 0;
    T* m_buffer = nullptr;
  };

  // Specialization for void* - can't create arrays of void, so this is a minimal wrapper
  template<typename T>
  class Buffer<T*, std::enable_if_t<std::is_void_v<T>>>
  {
  public:
    Buffer(T** pointer);
    Buffer(T** pointer, size_t size);

    Buffer(const Buffer& other) = delete;
    Buffer(Buffer&& other);

    Buffer& operator=(const Buffer& other) = delete;
    Buffer& operator=(Buffer&& other);

    size_t size() const;

    T** ptr();
    T** release();

  private:
    bool m_owner = false;
    size_t m_size = 0;
    T** m_buffer = nullptr;
  };

  template<typename T>
  Data_Type<Buffer<T>> define_buffer(std::string klassName = "");
}


// =========   Pointer.hpp   =========

namespace Rice
{
  template<typename T>
  class Pointer
  {
  };

  template<typename T>
  Data_Type<Pointer<T>> define_pointer(std::string klassName = "");
}


// =========   Reference.hpp   =========

namespace Rice
{
  template<typename T>
  class Reference
  {
    static_assert(!detail::is_wrapped_v<detail::intrinsic_type<T>>,
      "Reference can only be used with fundamental types");

  public:
    Reference();
    Reference(T& data);
    Reference(VALUE value);
    T& get();

  private:
    T data_;
  };

  // Specialization needed when VALUE type matches T, causing constructor ambiguity
  // between Reference(T&) and Reference(VALUE). VALUE is unsigned long when
  // SIZEOF_LONG == SIZEOF_VOIDP (Linux/macOS) and unsigned long long when
  // SIZEOF_LONG_LONG == SIZEOF_VOIDP (Windows x64).
#if SIZEOF_LONG == SIZEOF_VOIDP
  template<>
  class Reference<unsigned long>
  {
  public:
    Reference();
    Reference(unsigned long value, bool isValue = true);
    unsigned long& get();

  private:
    unsigned long data_;
  };
#else
  template<>
  class Reference<unsigned long long>
  {
  public:
    Reference();
    Reference(unsigned long long value, bool isValue = true);
    unsigned long long& get();

  private:
    unsigned long long data_;
  };
#endif

  template<typename T>
  Data_Type<Reference<T>> define_reference(std::string klassName = "");
}


// To / From Ruby

// =========   Arg.ipp   =========
namespace Rice
{
  inline Arg::Arg(std::string name) : name(name)
  {
  }

  template<typename Arg_Type>
  inline Arg& Arg::operator=(Arg_Type val)
  {
    this->defaultValue_ = val;
    return *this;
  }

  //! Check if this Arg has a default value associated with it
  inline bool Arg::hasDefaultValue() const
  {
    return this->defaultValue_.has_value();
  }

  //! Return a reference to the default value associated with this Arg
  /*! \return the type saved to this Arg
    */
  template<typename Arg_Type>
  inline Arg_Type Arg::defaultValue()
  {
    return std::any_cast<Arg_Type>(this->defaultValue_);
  }

  inline Arg& Arg::keepAlive()
  {
    this->isKeepAlive_ = true;
    return *this;
  }

  inline bool Arg::isKeepAlive() const
  {
    return this->isKeepAlive_;
  }

  inline Arg& Arg::setValue()
  {
    isValue_ = true;
    return *this;
  }

  inline bool Arg::isValue() const
  {
    return isValue_;
  }

  inline Arg& Arg::setOpaque()
  {
    isOpaque_ = true;
    return *this;
  }

  inline bool Arg::isOpaque() const
  {
    return isOpaque_;
  }

  inline Arg& Arg::takeOwnership()
  {
    this->isOwner_ = true;
    return *this;
  }

  inline bool Arg::isOwner()
  {
    return this->isOwner_;
  }

  inline ArgBuffer::ArgBuffer(std::string name) : Arg(name)
  {
  }


} // Rice
// =========   Parameter.ipp   =========
namespace Rice::detail
{
  // -----------  ParameterAbstract ----------------
  inline ParameterAbstract::ParameterAbstract(std::unique_ptr<Arg>&& arg) : arg_(std::move(arg))
  {
  }

  inline ParameterAbstract::ParameterAbstract(const ParameterAbstract& other)
  {
    this->arg_ = std::make_unique<Arg>(*other.arg_);
  }

  inline Arg* ParameterAbstract::arg()
  {
    return this->arg_.get();
  }

  // -----------  Parameter ----------------
  template<typename T>
  inline Parameter<T>::Parameter(std::unique_ptr<Arg>&& arg) : ParameterAbstract(std::move(arg)), 
    fromRuby_(this->arg()), toRuby_(this->arg())
  {
  }

  template<typename T>
  inline double Parameter<T>::matches(std::optional<VALUE>& valueOpt)
  {
    if (!valueOpt.has_value())
    {
      return Convertible::None;
    }
    else if (this->arg()->isValue())
    {
      return Convertible::Exact;
    }

    VALUE value = valueOpt.value();

    // Check with FromRuby if the VALUE is convertible to C++
    double result = this->fromRuby_.is_convertible(value);

    // TODO this is ugly and hacky and probably doesn't belong here.
    // Some Ruby objects like Proc and Set (in Ruby 4+) are also RUBY_T_DATA so we have to check for them
    if (result == Convertible::Exact && rb_type(value) == RUBY_T_DATA)
    {
      bool isBuffer = dynamic_cast<ArgBuffer*>(this->arg()) ? true : false;
      if ((!isBuffer && Data_Type<detail::intrinsic_type<T>>::is_descendant(value)) ||
          (isBuffer && Data_Type<Pointer<detail::intrinsic_type<T>>>::is_descendant(value)))
      {
        bool isConst = WrapperBase::isConst(value);

        // Do not send a const value to a non-const parameter
        if (isConst && !is_const_any_v<T>)
        {
          result = Convertible::None;
        }
        // It is ok to send a non-const value to a const parameter but
        // prefer non-const to non-const by slightly decreasing the score
        else if (!isConst && is_const_any_v<T>)
        {
          result = Convertible::ConstMismatch;
        }
      }
    }

    return result;
  }

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4702)  // unreachable code
#endif

  template<typename T>
  inline T Parameter<T>::convertToNative(std::optional<VALUE>& valueOpt)
  {
    /* In general the compiler will convert T to const T, but that does not work for converting
       T** to const T** (see see https://isocpp.org/wiki/faq/const-correctness#constptrptr-conversion)
       which comes up in the OpenCV bindings.

       An alternative solution is updating From_Ruby#convert to become a templated function that specifies
       the return type. That works but requires a lot more code changes for this one case and is not
       backwards compatible. */

    if constexpr (is_pointer_pointer_v<T> && !std::is_convertible_v<remove_cv_recursive_t<T>, T>)
    {
      return (T)this->fromRuby_.convert(valueOpt.value());
    }
    else if (valueOpt.has_value())
    {
      return this->fromRuby_.convert(valueOpt.value());
    }
    // Remember std::is_copy_constructible_v<std::vector<std::unique_ptr<T>>>> returns true. Sigh.
    // So special case vector handling
    else if constexpr (detail::is_std_vector_v<detail::intrinsic_type<T>>)
    {
      if constexpr (std::is_copy_constructible_v<typename detail::intrinsic_type<T>::value_type>)
      {
        if (this->arg()->hasDefaultValue())
        {
          return this->arg()->template defaultValue<T>();
        }
      }
    }
    // Incomplete types can't have default values (std::any requires complete types)
    else if constexpr (!is_complete_v<intrinsic_type<T>>)
    {
      // No default value possible for incomplete types
    }
    else if constexpr (std::is_copy_constructible_v<T>)
    {
      if (this->arg()->hasDefaultValue())
      {
        return this->arg()->template defaultValue<T>();
      }
    }

    // This can be unreachable code
    throw std::invalid_argument("Could not convert Ruby value");
  }

#ifdef _MSC_VER
#pragma warning(pop)
#endif

  template<typename T>
  inline VALUE Parameter<T>::convertToRuby(T& object)
  {
    return this->toRuby_.convert(object);
  }

  template<typename T>
  inline VALUE Parameter<T>::defaultValueRuby()
  {
    using To_Ruby_T = remove_cv_recursive_t<T>;

    if (!this->arg()->hasDefaultValue())
    {
      throw std::runtime_error("No default value set for " + this->arg()->name);
    }

    if constexpr (!is_complete_v<intrinsic_type<T>>)
    {
      // Only pointers to incomplete types can have
      // default values (e.g., void* or Impl*), since the pointer itself is complete.
      // References and values of incomplete types cannot be stored in std::any.
      if constexpr (std::is_pointer_v<std::remove_reference_t<T>>)
      {
        T defaultValue = this->arg()->template defaultValue<T>();
        return this->toRuby_.convert((To_Ruby_T)defaultValue);
      }
      else
      {
        throw std::runtime_error("Default value not allowed for incomple type. Parameter " + this->arg()->name);
      }
    }
    else if constexpr (std::is_constructible_v<std::remove_cv_t<T>, std::remove_cv_t<std::remove_reference_t<T>>&>)
    {
      // Remember std::is_copy_constructible_v<std::vector<std::unique_ptr<T>>>> returns true. Sigh.
      // So special case vector handling
      if constexpr (detail::is_std_vector_v<detail::intrinsic_type<T>>)
      {
        if constexpr (std::is_copy_constructible_v<typename detail::intrinsic_type<T>::value_type>)
        {
          T defaultValue = this->arg()->template defaultValue<T>();
          return this->toRuby_.convert(defaultValue);
        }
        else
        {
          throw std::runtime_error("Default value not allowed for parameter " + this->arg()->name);
        }
      }
      else
      {
        T defaultValue = this->arg()->template defaultValue<T>();
        return this->toRuby_.convert((To_Ruby_T)defaultValue);
      }
    }
    else
    {
      throw std::runtime_error("Default value not allowed for parameter " + this->arg()->name);
    }
  }

  template<typename T>
  inline std::string Parameter<T>::cppTypeName()
  {
    detail::TypeDetail<T> typeDetail;
    return typeDetail.simplifiedName();
  }

  template<typename T>
  inline VALUE Parameter<T>::klass()
  {
    TypeDetail<T> typeDetail;
    return typeDetail.rubyKlass();
  }
}

// =========   NoGVL.hpp   =========

namespace Rice
{
  class NoGVL
  {
  public:
    NoGVL() = default;
  };
} // Rice


// =========   Return.ipp   =========
#include <any>

namespace Rice
{
  inline Return::Return(): Arg("Return")
  {
  }

  inline Return& Return::keepAlive()
  {
    Arg::keepAlive();
    return *this;
  }

  inline Return& Return::setValue()
  {
    Arg::setValue();
    return *this;
  }

  inline Return& Return::setOpaque()
  {
    Arg::setOpaque();
    return *this;
  }

  inline Return& Return::takeOwnership()
  {
    Arg::takeOwnership();
    return *this;
  }
}  // Rice

// =========   Constructor.hpp   =========

namespace Rice
{
  //! Define a Type's Constructor and it's arguments.
  /*! E.g. for the default constructor on a Type:
      \code
        define_class<Test>()
          .define_constructor(Constructor<Test>());
      \endcode
  *
  *  The first template argument must be the type being wrapped.
  *  Additional arguments must be the types of the parameters sent
  *  to the constructor.
  *
  *  For more information, see Rice::Data_Type::define_constructor.
  */
  template<typename T, typename...Parameter_Ts>
  class Constructor;
}

// =========   Buffer.ipp   =========
namespace Rice
{
  // ----  Buffer<T> ------- 
  template<typename T>
  inline Buffer<T, std::enable_if_t<!std::is_pointer_v<T> && !std::is_void_v<T>>>::Buffer(T* pointer) : m_buffer(pointer)
  {
  }

  template<typename T>
  inline Buffer<T, std::enable_if_t<!std::is_pointer_v<T> && !std::is_void_v<T>>>::Buffer(T* pointer, size_t size) : m_size(size), m_buffer(pointer)
  {
  }

  template <typename T>
  inline Buffer<T, std::enable_if_t<!std::is_pointer_v<T> && !std::is_void_v<T>>>::Buffer(VALUE value) : Buffer(value, 0)
  {
  }

  template <typename T>
  inline Buffer<T, std::enable_if_t<!std::is_pointer_v<T> && !std::is_void_v<T>>>::Buffer(VALUE value, size_t size)
  {
    if constexpr (std::is_fundamental_v<T>)
    {
      this->fromBuiltinType(value, size);
    }
    else
    {
      this->fromWrappedType(value, size);
    }
  }

  template <typename T>
  inline Buffer<T, std::enable_if_t<!std::is_pointer_v<T> && !std::is_void_v<T>>>::~Buffer()
  {
    if constexpr (std::is_destructible_v<T>)
    {
      if (this->m_owner)
      {
        delete[] this->m_buffer;
      }
    }
  }

  template <typename T>
  inline void Buffer<T, std::enable_if_t<!std::is_pointer_v<T> && !std::is_void_v<T>>>::fromBuiltinType(VALUE value, size_t size)
  {
    using Intrinsic_T = typename detail::intrinsic_type<T>;
    using RubyType_T = typename detail::RubyType<Intrinsic_T>;

    ruby_value_type valueType = rb_type(value);
    switch (valueType)
    {
      case RUBY_T_ARRAY:
      {
        Array array(value);
        this->m_size = array.size();
        this->m_buffer = new T[this->m_size]();

        if constexpr (std::is_fundamental_v<T>)
        {
          String packed = array.pack<Intrinsic_T>();
          memcpy((void*)this->m_buffer, RSTRING_PTR(packed.value()), RSTRING_LEN(packed.value()));
        }
        else
        {
          detail::From_Ruby<Intrinsic_T> fromRuby;
          for (int i = 0; i < array.size(); i++)
          {
            this->m_buffer[0] = fromRuby.convert(array[i]);
          }
        }
        this->m_owner = true;
        break;
      }
      case RUBY_T_STRING:
      {
        this->m_size = RSTRING_LEN(value);
        if constexpr (std::is_same_v<T, char>)
        {
          // Add 2 for null characters (string and wstring)
          this->m_buffer = new T[this->m_size + 2]();
        }
        else
        {
          this->m_buffer = new T[this->m_size]();
        }
        memcpy((void*)this->m_buffer, RSTRING_PTR(value), this->m_size);

        this->m_owner = true;
        break;
      }
      case RUBY_T_DATA:
      {
        if (Data_Type<Pointer<T>>::is_descendant(value))
        {
          this->m_buffer = detail::unwrap<T>(value, Data_Type<Pointer<T>>::ruby_data_type(), false);
          this->m_owner = false;
          this->m_size = size;
          break;
        }
        [[fallthrough]];
      }
      default:
      {
        if (detail::From_Ruby<detail::remove_cv_recursive_t<T>>().is_convertible(value))
        {
          // The Ruby method may return a different type - for example Ruby floats
          // are converted to double and not float - so we need a typecast.
          T data = (T)detail::protect(RubyType_T::fromRuby, value);
          this->m_size = 1;
          this->m_buffer = new T[this->m_size]();
          memcpy((void*)this->m_buffer, &data, sizeof(T));
          this->m_owner = true;
          break;
        }
        else
        {
          detail::TypeDetail<T> typeDetail;
          std::string typeName = typeDetail.name();
          throw Exception(rb_eTypeError, "wrong argument type %s (expected %s*)",
            detail::protect(rb_obj_classname, value), typeName.c_str());
        }
      }
    }
  }

  template <typename T>
  inline void Buffer<T, std::enable_if_t<!std::is_pointer_v<T> && !std::is_void_v<T>>>::fromWrappedType(VALUE value, size_t size)
  {
    using Intrinsic_T = typename detail::intrinsic_type<T>;

    switch (rb_type(value))
    {
      case RUBY_T_ARRAY:
      {
        Array array(value);
        this->m_size = array.size();

        // Use operator new[] to allocate memory but not call constructors.
        size_t memsize = sizeof(T) * this->m_size;
        this->m_buffer = static_cast<T*>(operator new[](memsize));

        detail::From_Ruby<Intrinsic_T> fromRuby;

        for (size_t i = 0; i < this->m_size; i++)
        {
          // Construct objects in allocated memory using move or copy construction
          if constexpr (std::is_move_constructible_v<T>)
          {
            new (&this->m_buffer[i]) T(std::move(fromRuby.convert(array[(long)i].value())));
          }
          else if constexpr (std::is_copy_constructible_v<T>)
          {
            new (&this->m_buffer[i]) T(fromRuby.convert(array[i].value()));
          }
          else
          {
            detail::TypeDetail<Intrinsic_T> typeDetail;
            throw Exception(rb_eTypeError, "Cannot construct object of type %s - type is not move or copy constructible",
              typeDetail.name().c_str());
          }
        }
        break;
      }
      case RUBY_T_DATA:
      {
        if (Data_Type<Pointer<Intrinsic_T>>::is_descendant(value))
        {
          this->m_buffer = detail::unwrap<T>(value, Data_Type<Pointer<Intrinsic_T>>::ruby_data_type(), false);
          this->m_owner = false;
          this->m_size = size;
          break;
        }
        else if (Data_Type<Intrinsic_T>::is_descendant(value))
        {
          this->m_buffer = detail::unwrap<T>(value, Data_Type<Intrinsic_T>::ruby_data_type(), false);
          this->m_owner = false;
          this->m_size = size;
          break;
        }
      }
      case RUBY_T_STRING:
      {
        // This special case is a bit ugly...
        if constexpr (std::is_same_v<detail::intrinsic_type<T>, std::string>)
        {
          // FromRuby owns the converted string so we need to keep it alive until we get to the copy constructor
          // two lines down
          detail::From_Ruby<T*> fromRuby;
          T* converted = fromRuby.convert(value);
          this->m_buffer = new T[1]{ *converted };
          this->m_owner = true;
          this->m_size = 1;
          break;
        }
        [[fallthrough]];
      }
      default:
      {
        detail::TypeDetail<T> typeDetail;
        std::string typeName = typeDetail.name();
        throw Exception(rb_eTypeError, "wrong argument type %s (expected %s*)",
          detail::protect(rb_obj_classname, value), typeName.c_str());
      }
    }
  }

  template <typename T>
  inline Buffer<T, std::enable_if_t<!std::is_pointer_v<T> && !std::is_void_v<T>>>::Buffer(Buffer<T, std::enable_if_t<!std::is_pointer_v<T> && !std::is_void_v<T>>>&& other) : m_owner(other.m_owner), m_size(other.m_size), m_buffer(other.m_buffer)
  {
    other.m_buffer = nullptr;
    other.m_size = 0;
    other.m_owner = false;
  }

  template <typename T>
  inline Buffer<T, std::enable_if_t<!std::is_pointer_v<T> && !std::is_void_v<T>>>& Buffer<T, std::enable_if_t<!std::is_pointer_v<T> && !std::is_void_v<T>>>::operator=(Buffer<T, std::enable_if_t<!std::is_pointer_v<T> && !std::is_void_v<T>>>&& other)
  {
    this->m_buffer = other.m_buffer;
    other.m_buffer = nullptr;

    this->m_size = other.m_size;
    other.m_size = 0;

    this->m_owner = other.m_owner;
    other.m_owner = false;

    return *this;
  }

  template <typename T>
  inline size_t Buffer<T, std::enable_if_t<!std::is_pointer_v<T> && !std::is_void_v<T>>>::size() const
  {
    return this->m_size;
  }

  template <typename T>
  inline T* Buffer<T, std::enable_if_t<!std::is_pointer_v<T> && !std::is_void_v<T>>>::ptr()
  {
    return this->m_buffer;
  }

  template <typename T>
  inline T& Buffer<T, std::enable_if_t<!std::is_pointer_v<T> && !std::is_void_v<T>>>::reference()
  {
    return *this->m_buffer;
  }

  template <typename T>
  inline T* Buffer<T, std::enable_if_t<!std::is_pointer_v<T> && !std::is_void_v<T>>>::release()
  {
    this->m_owner = false;
    return this->m_buffer;
  }

  template <typename T>
  inline bool Buffer<T, std::enable_if_t<!std::is_pointer_v<T> && !std::is_void_v<T>>>::isOwner() const
  {
    return this->m_owner;
  }

  template <typename T>
  inline void Buffer<T, std::enable_if_t<!std::is_pointer_v<T> && !std::is_void_v<T>>>::setOwner(bool value)
  {
    this->m_owner = value;
  }

  template<typename T>
  inline VALUE Buffer<T, std::enable_if_t<!std::is_pointer_v<T> && !std::is_void_v<T>>>::toString() const
  {
    detail::TypeDetail<T*> typeDetail;
    std::string description = "Buffer<type: " + typeDetail.simplifiedName() + ", size: " + std::to_string(this->m_size) + ">";

    // We can't use To_Ruby because To_Ruby depends on Buffer - ie a circular reference
    return detail::protect(rb_utf8_str_new_cstr, description.c_str());
  }

  template<typename T>
  inline VALUE Buffer<T, std::enable_if_t<!std::is_pointer_v<T> && !std::is_void_v<T>>>::bytes(size_t count) const
  {
    if (!this->m_buffer)
    {
      return Qnil;
    }
    else
    {
      long length = (long)(count * sizeof(T));
      return detail::protect(rb_str_new_static, (const char*)this->m_buffer, length);
    }
  }

  template<typename T>
  inline VALUE Buffer<T, std::enable_if_t<!std::is_pointer_v<T> && !std::is_void_v<T>>>::bytes() const
  {
    return this->bytes(this->m_size);
  }

  template<typename T>
  inline Array Buffer<T, std::enable_if_t<!std::is_pointer_v<T> && !std::is_void_v<T>>>::toArray(size_t count) const
  {
    if (!this->m_buffer)
    {
      return Qnil;
    }
    else if constexpr (std::is_fundamental_v<T>)
    {
      VALUE string = this->bytes(count);
      return String(string).unpack<T>();
    }
    else
    {
      Array result;

      T* ptr = this->m_buffer;
      T* end = this->m_buffer + count;

      for (; ptr < end; ptr++)
      {
        result.push(*ptr, false);
      }
      return result;
    }
  }

  template<typename T>
  inline Array Buffer<T, std::enable_if_t<!std::is_pointer_v<T> && !std::is_void_v<T>>>::toArray() const
  {
    return this->toArray(this->m_size);
  }

  template<typename T>
  inline T& Buffer<T, std::enable_if_t<!std::is_pointer_v<T> && !std::is_void_v<T>>>::operator[](size_t index)
  {
    if (index >= this->m_size)
    {
      throw Exception(rb_eIndexError, "index %ld outside of bounds: 0..%ld", index, this->m_size);
    }

    return this->m_buffer[index];
  }

  // ----  Buffer<T*> - Builtin ------- 
  template<typename T>
  inline Buffer<T*, std::enable_if_t<!detail::is_wrapped_v<T> && !std::is_void_v<T>>>::Buffer(T** pointer) : m_buffer(pointer)
  {
  }

  template<typename T>
  inline Buffer<T*, std::enable_if_t<!detail::is_wrapped_v<T> && !std::is_void_v<T>>>::Buffer(T** pointer, size_t size) : m_size(size), m_buffer(pointer)
  {
  }

  template <typename T>
  inline Buffer<T*, std::enable_if_t<!detail::is_wrapped_v<T> && !std::is_void_v<T>>>::Buffer(VALUE value) : Buffer(value, 0)
  {
  }
 
  template <typename T>
  inline Buffer<T*, std::enable_if_t<!detail::is_wrapped_v<T> && !std::is_void_v<T>>>::Buffer(VALUE value, size_t size)
  {
    using Intrinsic_T = typename detail::intrinsic_type<T>;

    ruby_value_type valueType = rb_type(value);
    switch (valueType)
    {
      case RUBY_T_ARRAY:
      {
        Array outer(value);

        // Allocate outer buffer
        this->m_size = outer.size();
        this->m_buffer = new T*[this->m_size]();

        for (size_t i = 0; i < this->m_size; i++)
        {
          // Check the inner value is also an array
          Array inner(outer[(long)i].value());

          // Allocate inner buffer
          this->m_buffer[i] = new T[inner.size()]();

          if constexpr (std::is_fundamental_v<Intrinsic_T>)
          {
            String packed = inner.pack<Intrinsic_T>();
            memcpy((void*)this->m_buffer[i], RSTRING_PTR(packed.value()), RSTRING_LEN(packed.value()));
          }
          // This is for std::string, should be a 1 length array
          else
          {
            detail::From_Ruby<Intrinsic_T*> fromRuby;
            if (inner.size() != 1)
            {
              throw Exception(rb_eTypeError, "Expected inner array size 1 for type %s* but got %ld",
                detail::TypeDetail<T>().name().c_str(), inner.size());
            }
            this->m_buffer[i] = fromRuby.convert(inner[0].value());
          }
        }

        this->m_owner = true;
        break;
      }
      case RUBY_T_DATA:
      {
        if (Data_Type<Pointer<T*>>::is_descendant(value))
        {
          this->m_buffer = detail::unwrap<T*>(value, Data_Type<Pointer<T*>>::ruby_data_type(), false);
          this->m_owner = false;
          this->m_size = size;
          break;
        }
        [[fallthrough]];
      }
      default:
      {
        detail::TypeDetail<T> typeDetail;
        std::string typeName = typeDetail.name();
        throw Exception(rb_eTypeError, "wrong argument type %s (expected %s*)",
          detail::protect(rb_obj_classname, value), typeName.c_str());
      }
    }
  }

  template <typename T>
  inline Buffer<T*, std::enable_if_t<!detail::is_wrapped_v<T> && !std::is_void_v<T>>>::~Buffer()
  {
    if (this->m_owner)
    {
      for (size_t i = 0; i < this->m_size; i++)
      {
        delete this->m_buffer[i];
      }

      delete[] this->m_buffer;
    }
  }

  template <typename T>
  inline Buffer<T*, std::enable_if_t<!detail::is_wrapped_v<T> && !std::is_void_v<T>>>::Buffer(Buffer<T*, std::enable_if_t<!detail::is_wrapped_v<T> && !std::is_void_v<T>>>&& other) : m_owner(other.m_owner), m_size(other.m_size),
                                                  m_buffer(other.m_buffer)
  {
    other.m_buffer = nullptr;
    other.m_size = 0;
    other.m_owner = false;
  }

  template <typename T>
  inline Buffer<T*, std::enable_if_t<!detail::is_wrapped_v<T> && !std::is_void_v<T>>>& Buffer<T*, std::enable_if_t<!detail::is_wrapped_v<T> && !std::is_void_v<T>>>::operator=(Buffer<T*, std::enable_if_t<!detail::is_wrapped_v<T> && !std::is_void_v<T>>>&& other)
  {
    this->m_buffer = other.m_buffer;
    other.m_buffer = nullptr;

    this->m_size = other.m_size;
    other.m_size = 0;

    this->m_owner = other.m_owner;
    other.m_owner = false;

    return *this;
  }

  template <typename T>
  inline T* Buffer<T*, std::enable_if_t<!detail::is_wrapped_v<T> && !std::is_void_v<T>>>::operator[](size_t index)
  {
    return this->m_buffer[index];
  }

  template <typename T>
  inline size_t Buffer<T*, std::enable_if_t<!detail::is_wrapped_v<T> && !std::is_void_v<T>>>::size() const
  {
    return this->m_size;
  }

  template <typename T>
  inline T** Buffer<T*, std::enable_if_t<!detail::is_wrapped_v<T> && !std::is_void_v<T>>>::ptr()
  {
    return this->m_buffer;
  }

  template <typename T>
  inline T** Buffer<T*, std::enable_if_t<!detail::is_wrapped_v<T> && !std::is_void_v<T>>>::release()
  {
    this->m_owner = false;
    return this->m_buffer;
  }

  template <typename T>
  inline bool Buffer<T*, std::enable_if_t<!detail::is_wrapped_v<T> && !std::is_void_v<T>>>::isOwner() const
  {
    return this->m_owner;
  }

  template <typename T>
  inline void Buffer<T*, std::enable_if_t<!detail::is_wrapped_v<T> && !std::is_void_v<T>>>::setOwner(bool value)
  {
    this->m_owner = value;
  }

  template<typename T>
  inline VALUE Buffer<T*, std::enable_if_t<!detail::is_wrapped_v<T> && !std::is_void_v<T>>>::toString() const
  {
    detail::TypeDetail<T*> typeDetail;
    std::string description = "Buffer<type: " + typeDetail.simplifiedName() + ", size: " + std::to_string(this->m_size) + ">";

    // We can't use To_Ruby because To_Ruby depends on Buffer - ie a circular reference
    return detail::protect(rb_utf8_str_new_cstr, description.c_str());
  }

  template<typename T>
  inline VALUE Buffer<T*, std::enable_if_t<!detail::is_wrapped_v<T> && !std::is_void_v<T>>>::bytes(size_t count) const
  {
    if (!this->m_buffer)
    {
      return Qnil;
    }
    else
    {
      T** begin = this->m_buffer;
      long length = (long)(count * sizeof(T*));
      return detail::protect(rb_str_new_static, (const char*)*begin, length);
    }
  }

  template<typename T>
  inline VALUE Buffer<T*, std::enable_if_t<!detail::is_wrapped_v<T> && !std::is_void_v<T>>>::bytes() const
  {
    return this->bytes(this->m_size);
  }

  template<typename T>
  inline Array Buffer<T*, std::enable_if_t<!detail::is_wrapped_v<T> && !std::is_void_v<T>>>::toArray(size_t count) const
  {
    if (!this->m_buffer)
    {
      return Qnil;
    }
    else
    {
      Array result;

      T** ptr = this->m_buffer;
      T** end = this->m_buffer + count;

      for (; ptr < end; ptr++)
      {
        Buffer<T> buffer(*ptr);
        result.push(std::move(buffer), true);
      }
      return result;
    }
  }

  template<typename T>
  inline Array Buffer<T*, std::enable_if_t<!detail::is_wrapped_v<T> && !std::is_void_v<T>>>::toArray() const
  {
    return this->toArray(this->m_size);
  }

  // ----  Buffer<T*> - Wrapped ------- 
  template<typename T>
  inline Buffer<T*, std::enable_if_t<detail::is_wrapped_v<T>>>::Buffer(T** pointer) : m_buffer(pointer)
  {
  }

  template<typename T>
  inline Buffer<T*, std::enable_if_t<detail::is_wrapped_v<T>>>::Buffer(T** pointer, size_t size) : m_size(size), m_buffer(pointer)
  {
  }

  template <typename T>
  inline Buffer<T*, std::enable_if_t<detail::is_wrapped_v<T>>>::Buffer(VALUE value) : Buffer(value, 0)
  {
  }
  
  template <typename T>
  inline Buffer<T*, std::enable_if_t<detail::is_wrapped_v<T>>>::Buffer(VALUE value, size_t size)
  {
    ruby_value_type valueType = rb_type(value);
    switch (valueType)
    {
      case RUBY_T_ARRAY:
      {
        Array array(value);
        this->m_size = array.size();
        this->m_buffer = new T * [this->m_size]();

        detail::From_Ruby<T*> fromRuby;

        for (size_t i = 0; i < this->m_size; i++)
        {
          this->m_buffer[i] = fromRuby.convert(array[(long)i].value());
        }

        this->m_owner = true;
        break;
      }
      case RUBY_T_DATA:
      {
        if (Data_Type<Pointer<T*>>::is_descendant(value))
        {
          this->m_buffer = detail::unwrap<T*>(value, Data_Type<Pointer<T*>>::ruby_data_type(), false);
          this->m_owner = false;
          this->m_size = size;
          break;
        }
      }
      default:
      {
        detail::TypeDetail<T> typeDetail;
        std::string typeName = typeDetail.name();
        throw Exception(rb_eTypeError, "wrong argument type %s (expected %s*)",
          detail::protect(rb_obj_classname, value), typeName.c_str());
      }
    }
  }

  template <typename T>
  inline Buffer<T*, std::enable_if_t<detail::is_wrapped_v<T>>>::~Buffer()
  {
    if (this->m_owner)
    {
      delete[] this->m_buffer;
    }
  }

  template <typename T>
  inline Buffer<T*, std::enable_if_t<detail::is_wrapped_v<T>>>::Buffer(Buffer<T*, std::enable_if_t<detail::is_wrapped_v<T>>>&& other) : m_owner(other.m_owner), m_size(other.m_size),
    m_buffer(other.m_buffer)
  {
    other.m_buffer = nullptr;
    other.m_size = 0;
    other.m_owner = false;
  }

  template <typename T>
  inline Buffer<T*, std::enable_if_t<detail::is_wrapped_v<T>>>& Buffer<T*, std::enable_if_t<detail::is_wrapped_v<T>>>::operator=(Buffer<T*, std::enable_if_t<detail::is_wrapped_v<T>>>&& other)
  {
    this->m_buffer = other.m_buffer;
    other.m_buffer = nullptr;

    this->m_size = other.m_size;
    other.m_size = 0;

    this->m_owner = other.m_owner;
    other.m_owner = false;

    return *this;
  }

  template <typename T>
  inline T* Buffer<T*, std::enable_if_t<detail::is_wrapped_v<T>>>::operator[](size_t index)
  {
    if (index >= this->m_size)
    {
      throw Exception(rb_eIndexError, "index %ld outside of bounds: 0..%ld", index, this->m_size);
    }
    return this->m_buffer[index];
  }

  template <typename T>
  inline size_t Buffer<T*, std::enable_if_t<detail::is_wrapped_v<T>>>::size() const
  {
    return this->m_size;
  }

  template <typename T>
  inline T** Buffer<T*, std::enable_if_t<detail::is_wrapped_v<T>>>::ptr()
  {
    return this->m_buffer;
  }

  template <typename T>
  inline T** Buffer<T*, std::enable_if_t<detail::is_wrapped_v<T>>>::release()
  {
    this->m_owner = false;
    return this->m_buffer;
  }

  template <typename T>
  inline bool Buffer<T*, std::enable_if_t<detail::is_wrapped_v<T>>>::isOwner() const
  {
    return this->m_owner;
  }

  template <typename T>
  inline void Buffer<T*, std::enable_if_t<detail::is_wrapped_v<T>>>::setOwner(bool value)
  {
    this->m_owner = value;
  }

  template<typename T>
  inline VALUE Buffer<T*, std::enable_if_t<detail::is_wrapped_v<T>>>::toString() const
  {
    detail::TypeDetail<T*> typeDetail;
    std::string description = "Buffer<type: " + typeDetail.simplifiedName() + ", size: " + std::to_string(this->m_size) + ">";

    // We can't use To_Ruby because To_Ruby depends on Buffer - ie a circular reference
    return detail::protect(rb_utf8_str_new_cstr, description.c_str());
  }

  template<typename T>
  inline VALUE Buffer<T*, std::enable_if_t<detail::is_wrapped_v<T>>>::bytes(size_t count) const
  {
    if (!this->m_buffer)
    {
      return Qnil;
    }
    else
    {
      T** begin = this->m_buffer;
      long length = (long)(count * sizeof(T*));
      return detail::protect(rb_str_new_static, (const char*)*begin, length);
    }
  }

  template<typename T>
  inline VALUE Buffer<T*, std::enable_if_t<detail::is_wrapped_v<T>>>::bytes() const
  {
    return this->bytes(this->m_size);
  }

  template<typename T>
  inline Array Buffer<T*, std::enable_if_t<detail::is_wrapped_v<T>>>::toArray(size_t count) const
  {
    if (!this->m_buffer)
    {
      return Qnil;
    }
    else
    {
      Array result;

      T** ptr = this->m_buffer;
      T** end = this->m_buffer + count;

      for (; ptr < end; ptr++)
      {
        result.push(*ptr, false);
      }
      return result;
    }
  }

  template<typename T>
  inline Array Buffer<T*, std::enable_if_t<detail::is_wrapped_v<T>>>::toArray() const
  {
    return this->toArray(this->m_size);
  }

  // ----  Buffer<void> ------- 
  template<typename T>
  inline Buffer<T, std::enable_if_t<std::is_void_v<T>>>::Buffer(VALUE value) : Buffer(value, 0)
  {
  }
  
  template<typename T>
  inline Buffer<T, std::enable_if_t<std::is_void_v<T>>>::Buffer(VALUE value, size_t)
  {
    ruby_value_type valueType = rb_type(value);

    switch (valueType)
    {
      case RUBY_T_STRING:
      {
        this->m_size = RSTRING_LEN(value);
        this->m_buffer = ::operator new(this->m_size);
        memcpy((void*)this->m_buffer, RSTRING_PTR(value), this->m_size);

        this->m_owner = true;
        break;
      }
      default:
      {
        detail::TypeDetail<T> typeDetail;
        std::string typeName = typeDetail.name();
        throw Exception(rb_eTypeError, "wrong argument type %s (expected %s*)",
          detail::protect(rb_obj_classname, value), typeName.c_str());
      }
    }
  }

  template<typename T>
  inline Buffer<T, std::enable_if_t<std::is_void_v<T>>>::Buffer(T* pointer) : m_buffer(pointer)
  {
  }

  template<typename T>
  inline Buffer<T, std::enable_if_t<std::is_void_v<T>>>::Buffer(Buffer<T, std::enable_if_t<std::is_void_v<T>>>&& other) : m_owner(other.m_owner), m_size(other.m_size), m_buffer(other.m_buffer)
  {
    other.m_buffer = nullptr;
    other.m_size = 0;
    other.m_owner = false;
  }

  template<typename T>
  inline Buffer<T, std::enable_if_t<std::is_void_v<T>>>& Buffer<T, std::enable_if_t<std::is_void_v<T>>>::operator=(Buffer<T, std::enable_if_t<std::is_void_v<T>>>&& other)
  {
    this->m_buffer = other.m_buffer;
    other.m_buffer = nullptr;

    return *this;
  }

  template<typename T>
  inline size_t Buffer<T, std::enable_if_t<std::is_void_v<T>>>::size() const
  {
    return this->m_size;
  }

  template<typename T>
  inline T* Buffer<T, std::enable_if_t<std::is_void_v<T>>>::ptr()
  {
    return this->m_buffer;
  }

  template <typename T>
  inline T* Buffer<T, std::enable_if_t<std::is_void_v<T>>>::release()
  {
    this->m_owner = false;
    return this->m_buffer;
  }

  template<typename T>
  inline VALUE Buffer<T, std::enable_if_t<std::is_void_v<T>>>::bytes(size_t count) const
  {
    if (!this->m_buffer)
    {
      return Qnil;
    }
    else
    {
      return detail::protect(rb_usascii_str_new, (const char*)this->m_buffer, (long)count);
    }
  }

  template<typename T>
  inline VALUE Buffer<T, std::enable_if_t<std::is_void_v<T>>>::bytes() const
  {
    return this->bytes(this->m_size);
  }

  // ----  Buffer<void*> -------
  template<typename T>
  inline Buffer<T*, std::enable_if_t<std::is_void_v<T>>>::Buffer(T** pointer) : m_buffer(pointer)
  {
  }

  template<typename T>
  inline Buffer<T*, std::enable_if_t<std::is_void_v<T>>>::Buffer(T** pointer, size_t size) : m_size(size), m_buffer(pointer)
  {
  }

  template<typename T>
  inline Buffer<T*, std::enable_if_t<std::is_void_v<T>>>::Buffer(Buffer<T*, std::enable_if_t<std::is_void_v<T>>>&& other) : m_owner(other.m_owner), m_size(other.m_size), m_buffer(other.m_buffer)
  {
    other.m_buffer = nullptr;
    other.m_size = 0;
    other.m_owner = false;
  }

  template<typename T>
  inline Buffer<T*, std::enable_if_t<std::is_void_v<T>>>& Buffer<T*, std::enable_if_t<std::is_void_v<T>>>::operator=(Buffer<T*, std::enable_if_t<std::is_void_v<T>>>&& other)
  {
    this->m_buffer = other.m_buffer;
    this->m_size = other.m_size;
    this->m_owner = other.m_owner;
    other.m_buffer = nullptr;
    other.m_size = 0;
    other.m_owner = false;

    return *this;
  }

  template<typename T>
  inline size_t Buffer<T*, std::enable_if_t<std::is_void_v<T>>>::size() const
  {
    return this->m_size;
  }

  template<typename T>
  inline T** Buffer<T*, std::enable_if_t<std::is_void_v<T>>>::ptr()
  {
    return this->m_buffer;
  }

  template <typename T>
  inline T** Buffer<T*, std::enable_if_t<std::is_void_v<T>>>::release()
  {
    this->m_owner = false;
    return this->m_buffer;
  }

  // ------  define_buffer ----------
  template<typename T>
  inline Data_Type<Buffer<T>> define_buffer(std::string klassName)
  {
    using Buffer_T = Buffer<T>;
    using Data_Type_T = Data_Type<Buffer_T>;

    if (klassName.empty())
    {
      detail::TypeDetail<Buffer_T> typeDetail;
      klassName = typeDetail.rubyName();
    }

    Module rb_mRice = define_module("Rice");

    if (Data_Type_T::check_defined(klassName, rb_mRice))
    {
      return Data_Type_T();
    }

    if constexpr (std::is_void_v<T>)
    {
      return define_class_under<Buffer_T>(rb_mRice, klassName).
        define_constructor(Constructor<Buffer_T, VALUE>(), Arg("value").setValue()).
        define_constructor(Constructor<Buffer_T, VALUE, size_t>(), Arg("value").setValue(), Arg("size")).
        define_method("size", &Buffer_T::size).
        template define_method<VALUE(Buffer_T::*)(size_t) const>("bytes", &Buffer_T::bytes, Return().setValue()).
        template define_method<VALUE(Buffer_T::*)() const>("bytes", &Buffer_T::bytes, Return().setValue()).
        define_method("data", &Buffer_T::ptr, ReturnBuffer()).
        define_method("release", &Buffer_T::release, ReturnBuffer());
    }
    // void* - minimal wrapper, no Ruby array conversion support
    else if constexpr (std::is_void_v<detail::intrinsic_type<T>>)
    {
      return define_class_under<Buffer_T>(rb_mRice, klassName).
        define_method("size", &Buffer_T::size).
        define_method("data", &Buffer_T::ptr, ReturnBuffer()).
        define_method("release", &Buffer_T::release, ReturnBuffer());
    }
    else
    {
      Data_Type<Buffer_T> klass = define_class_under<Buffer_T>(rb_mRice, klassName).
        define_constructor(Constructor<Buffer_T, VALUE>(), Arg("value").setValue()).
        define_constructor(Constructor<Buffer_T, VALUE, size_t>(), Arg("value").setValue(), Arg("size")).
        define_method("size", &Buffer_T::size).
        template define_method<VALUE(Buffer_T::*)() const>("to_s", &Buffer_T::toString, Return().setValue()).
        template define_method<VALUE(Buffer_T::*)(size_t) const>("bytes", &Buffer_T::bytes, Return().setValue()).
        template define_method<VALUE(Buffer_T::*)() const>("bytes", &Buffer_T::bytes, Return().setValue()).
        template define_method<Array(Buffer_T::*)(size_t) const>("to_ary", &Buffer_T::toArray, Return().setValue()).
        template define_method<Array(Buffer_T::*)() const>("to_ary", &Buffer_T::toArray, Return().setValue()).
        define_method("[]", &Buffer_T::operator[], Arg("index")).
        define_method("data", &Buffer_T::ptr, ReturnBuffer()).
        define_method("release", &Buffer_T::release, ReturnBuffer());

      if constexpr (detail::is_complete_v<detail::intrinsic_type<T>>)
      {
        if constexpr (!std::is_pointer_v<T> && !std::is_void_v<T> && !std::is_const_v<T> && std::is_copy_assignable_v<T>)
        {
          klass.define_method("[]=", [](Buffer_T& self, size_t index, T& value) -> void
          {
            self[index] = value;
          });
        }
        else if constexpr (std::is_pointer_v<T> && !std::is_const_v<std::remove_pointer_t<T>> && std::is_copy_assignable_v<std::remove_pointer_t<T>>)
        {
          klass.define_method("[]=", [](Buffer_T& self, size_t index, T value) -> void
          {
            *self[index] = *value;
          });
        }
      }

      return klass;
    }
  }
}

namespace Rice::detail
{
  template<typename T>
  struct Type<Buffer<T>>
  {
    static bool verify()
    {
      detail::verifyType<T>();
      define_buffer<T>();
      return true;
    }
  };
}

// =========   Pointer.ipp   =========
namespace Rice
{
  template<typename T>
  inline Data_Type<Pointer<T>> define_pointer(std::string klassName)
  {
    using Pointer_T = Pointer<T>;
    using Data_Type_T = Data_Type<Pointer_T>;

    if (klassName.empty())
    {
      detail::TypeDetail<Pointer_T> typeDetail;
      klassName = typeDetail.rubyName();
    }

    Module rb_mRice = define_module("Rice");

    if (Data_Type_T::check_defined(klassName, rb_mRice))
    {
      return Data_Type_T();
    }

    Data_Type<Pointer<T>> result = define_class_under<Pointer_T>(rb_mRice, klassName).
      define_method("buffer", [](VALUE self) -> Buffer<T>
      {
        T* ptr = detail::unwrap<T>(self, Data_Type<Pointer<T>>::ruby_data_type(), false);
        Buffer<T> buffer(ptr);
        return buffer;
      }, Arg("self").setValue());

    // Define a buffer to read the pointer's data
    define_buffer<T>();

    return result;
  }
}

namespace Rice::detail
{
  template<typename T>
  struct Type<Pointer<T>>
  {
    static bool verify()
    {
      detail::verifyType<T>();
      define_pointer<T>();
      return true;
    }
  };
}

// =========   Types.ipp   =========
namespace Rice::detail
{
  template<>
  struct Type<bool>
  {
    static bool verify()
    {
      return true;
    }

    static VALUE rubyKlass()
    {
      return rb_cTrueClass;
    }
  };

  template<>
  struct Type<char>
  {
    static bool verify()
    {
      return true;
    }

    static VALUE rubyKlass()
    {
      return rb_cString;
    }
  };

  template<int N>
  struct Type<char[N]>
  {
    static bool verify()
    {
      return true;
    }

    static VALUE rubyKlass()
    {
      return rb_cString;
    }
  };

  template<>
  struct Type<char*>
  {
    static bool verify()
    {
      return true;
    }

    static VALUE rubyKlass()
    {
      return rb_cString;
    }
  };

  template<>
  struct Type<signed char>
  {
    static bool verify()
    {
      return true;
    }

    static VALUE rubyKlass()
    {
      return rb_cString;
    }
  };
  
  template<int N>
  struct Type<signed char[N]>
  {
    static bool verify()
    {
      define_buffer<signed char>();
      return true;
    }

    static VALUE rubyKlass()
    {
      return rb_cString;
    }
  };

  template<>
  struct Type<unsigned char>
  {
    static bool verify()
    {
      return true;
    }

    static VALUE rubyKlass()
    {
      return rb_cString;
    }
  };

  template<int N>
  struct Type<unsigned char[N]>
  {
    static bool verify()
    {
      define_buffer<unsigned char>();
      return true;
    }

    static VALUE rubyKlass()
    {
      return rb_cString;
    }
  };
  
  template<>
  struct Type<short>
  {
    static bool verify()
    {
      return true;
    }

    static VALUE rubyKlass()
    {
      return rb_cInteger;
    }
  };

  template<int N>
  struct Type<short[N]>
  {
    static bool verify()
    {
      define_buffer<short>();
      return true;
    }

    static VALUE rubyKlass()
    {
      return rb_cString;
    }
  };
  
  template<>
  struct Type<unsigned short>
  {
    static bool verify()
    {
      return true;
    }

    static VALUE rubyKlass()
    {
      return rb_cInteger;
    }
  };

  template<int N>
  struct Type<unsigned short[N]>
  {
    static bool verify()
    {
      define_buffer<unsigned short>();
      return true;
    }

    static VALUE rubyKlass()
    {
      return rb_cString;
    }
  };

  template<>
  struct Type<int>
  {
    static bool verify()
    {
      return true;
    }

    static VALUE rubyKlass()
    {
      return rb_cInteger;
    }
  };

  template<int N>
  struct Type<int[N]>
  {
    static bool verify()
    {
      define_buffer<int>();
      return true;
    }

    static VALUE rubyKlass()
    {
      return rb_cString;
    }
  };

  template<>
  struct Type<unsigned int>
  {
    static bool verify()
    {
      return true;
    }

    static VALUE rubyKlass()
    {
      return rb_cInteger;
    }
  };

  template<int N>
  struct Type<unsigned int[N]>
  {
    static bool verify()
    {
      define_buffer<unsigned int>();
      return true;
    }

    static VALUE rubyKlass()
    {
      return rb_cString;
    }
  };

  template<>
  struct Type<long>
  {
    static bool verify()
    {
      return true;
    }

    static VALUE rubyKlass()
    {
      return rb_cInteger;
    }
  };

  template<int N>
  struct Type<long[N]>
  {
    static bool verify()
    {
      define_buffer<long>();
      return true;
    }

    static VALUE rubyKlass()
    {
      return rb_cString;
    }
  };

  template<>
  struct Type<unsigned long>
  {
    static bool verify()
    {
      return true;
    }

    static VALUE rubyKlass()
    {
      return rb_cInteger;
    }
  };

  template<int N>
  struct Type<unsigned long[N]>
  {
    static bool verify()
    {
      define_buffer<unsigned long>();
      return true;
    }

    static VALUE rubyKlass()
    {
      return rb_cString;
    }
  };
  
  template<>
  struct Type<long long>
  {
    static bool verify()
    {
      return true;
    }

    static VALUE rubyKlass()
    {
      return rb_cInteger;
    }
  };

  template<int N>
  struct Type<long long[N]>
  {
    static bool verify()
    {
      define_buffer<long long>();
      return true;
    }

    static VALUE rubyKlass()
    {
      return rb_cString;
    }
  };

  template<>
  struct Type<unsigned long long>
  {
    static bool verify()
    {
      return true;
    }

    static VALUE rubyKlass()
    {
      return rb_cInteger;
    }
  };

  template<int N>
  struct Type<unsigned long long[N]>
  {
    static bool verify()
    {
      define_buffer<unsigned long long>();
      return true;
    }

    static VALUE rubyKlass()
    {
      return rb_cString;
    }
  };

  template<>
  struct Type<float>
  {
    static bool verify()
    {
      return true;
    }

    static VALUE rubyKlass()
    {
      return rb_cFloat;
    }
  };

  template<int N>
  struct Type<float[N]>
  {
    static bool verify()
    {
      define_buffer<float>();
      return true;
    }

    static VALUE rubyKlass()
    {
      return rb_cString;
    }
  };

  template<>
  struct Type<double>
  {
    static bool verify()
    {
      return true;
    }

    static VALUE rubyKlass()
    {
      return rb_cFloat;
    }
  };

  template<int N>
  struct Type<double[N]>
  {
    static bool verify()
    {
      define_buffer<double>();
      return true;
    }

    static VALUE rubyKlass()
    {
      return rb_cString;
    }
  };

  template<>
  struct Type<long double>
  {
    static bool verify()
    {
      return true;
    }

    static VALUE rubyKlass()
    {
      return rb_cFloat;
    }
  };

  template<int N>
  struct Type<long double[N]>
  {
    static bool verify()
    {
      define_buffer<long double>();
      return true;
    }

    static VALUE rubyKlass()
    {
      return rb_cString;
    }
  };

  template<>
  struct Type<void>
  {
    static bool verify()
    {
      return true;
    }

    static VALUE rubyKlass()
    {
      return rb_cNilClass;
    }
  };

  template<>
  struct Type<void*>
  {
    static bool verify()
    {
      Type<Pointer<void>>::verify();
      return true;
    }
  };
}
// =========   to_ruby.ipp   =========

namespace Rice
{
  namespace detail
  {
    // ===========  bool  ============
    template<>
    class To_Ruby<bool>
    {
    public:
      To_Ruby() = default;

      explicit To_Ruby(Arg* arg) : arg_(arg)
      {
      }

      VALUE convert(const bool& native)
      {
        return native ? Qtrue : Qfalse;
      }

    private:
      Arg* arg_ = nullptr;
    };

    template<>
    class To_Ruby<bool&>
    {
    public:
      To_Ruby() = default;

      explicit To_Ruby(Arg* arg) : arg_(arg)
      {
      }

      VALUE convert(const bool& native)
      {
        return native ? Qtrue : Qfalse;
      }

    private:
      Arg* arg_ = nullptr;
    };

    template<bool N>
    class To_Ruby<bool[N]>
    {
    public:
      To_Ruby() = default;

      explicit To_Ruby(Arg* arg) : arg_(arg)
      {
      }

      VALUE convert(bool data[N])
      {
        Buffer<bool> buffer(data, N);
        Data_Object<Buffer<bool>> dataObject(std::move(buffer));
        return dataObject.value();
      }
    private:
      Arg* arg_ = nullptr;
    };

    // ===========  int  ============
    template<>
    class To_Ruby<int>
    {
    public:
      To_Ruby() = default;

      explicit To_Ruby(Arg* arg) : arg_(arg)
      {
      }

      VALUE convert(const int& native)
      {
#ifdef rb_int2num_inline
        return protect(rb_int2num_inline, (int)native);
#else
        return RB_INT2NUM(native);
#endif
      }

      VALUE convert(const volatile int& native)
      {
#ifdef rb_int2num_inline
        return protect(rb_int2num_inline, (int)native);
#else
        return RB_INT2NUM(native);
#endif
      }

    private:
      Arg* arg_ = nullptr;
    };

    template<>
    class To_Ruby<int&>
    {
    public:
      To_Ruby() = default;

      explicit To_Ruby(Arg* arg) : arg_(arg)
      {
      }

      VALUE convert(const int& native)
      {
#ifdef rb_int2num_inline
        return protect(rb_int2num_inline, (int)native);
#else
        return RB_INT2NUM(native);
#endif
      }

    private:
      Arg* arg_ = nullptr;
    };

    template<int N>
    class To_Ruby<int[N]>
    {
    public:
      To_Ruby() = default;

      explicit To_Ruby(Arg* arg) : arg_(arg)
      {
      }

      VALUE convert(int data[N])
      {
        Buffer<int> buffer(data, N);
        Data_Object<Buffer<int>> dataObject(std::move(buffer));
        return dataObject.value();
      }
    private:
      Arg* arg_ = nullptr;
    };

    // ===========  unsigned int  ============
    template<>
    class To_Ruby<unsigned int>
    {
    public:
      To_Ruby() = default;

      explicit To_Ruby(Arg* arg) : arg_(arg)
      {
      }

      VALUE convert(const unsigned int& native)
      {
#ifdef rb_int2num_inline
        return protect(rb_uint2num_inline, (unsigned int)native);
#else
        return RB_UINT2NUM(native);
#endif
      }

    private:
      Arg* arg_ = nullptr;
    };

    template<>
    class To_Ruby<unsigned int&>
    {
    public:
      To_Ruby() = default;

      explicit To_Ruby(Arg* arg) : arg_(arg)
      {
      }

      VALUE convert(const unsigned int& native)
      {
#ifdef rb_int2num_inline
        return protect(rb_uint2num_inline, (unsigned int)native);
#else
        return RB_UINT2NUM(native);
#endif
      }

    private:
      Arg* arg_ = nullptr;
    };

    template<int N>
    class To_Ruby<unsigned int[N]>
    {
    public:
      To_Ruby() = default;

      explicit To_Ruby(Arg* arg) : arg_(arg)
      {
      }

      VALUE convert(unsigned int data[N])
      {
        Buffer<unsigned int> buffer(data, N);
        Data_Object<Buffer<unsigned int>> dataObject(std::move(buffer));
        return dataObject.value();
      }
    private:
      Arg* arg_ = nullptr;
    };

    // ===========  char  ============
    template<>
    class To_Ruby<char>
    {
    public:
      To_Ruby() = default;

      explicit To_Ruby(Arg* arg) : arg_(arg)
      {
      }

      VALUE convert(const char& native)
      {
        return To_Ruby<int>().convert(native);
      }

    private:
      Arg* arg_ = nullptr;
    };

    template<>
    class To_Ruby<char&>
    {
    public:
      To_Ruby() = default;

      explicit To_Ruby(Arg* arg) : arg_(arg)
      {
      }

      VALUE convert(const char& native)
      {
        return To_Ruby<int>().convert(native);
      }

    private:
      Arg* arg_ = nullptr;
    };

    template<>
    class To_Ruby<char*>
    {
    public:
      To_Ruby() = default;

      explicit To_Ruby(Arg* arg) : arg_(arg)
      {
      }

      VALUE convert(const char* data)
      {
        if (!data)
        {
          return Qnil;
        }
        else if (strlen(data) > 0 && data[0] == ':')
        {
          size_t symbolLength = strlen(data) - 1;
          char* symbol = new char[symbolLength];
          strncpy(symbol, data + 1, symbolLength);
          ID id = protect(rb_intern2, symbol, (long)symbolLength);
          delete[] symbol;
          return protect(rb_id2sym, id);
        }
        else if (this->arg_ && this->arg_->isOwner())
        {
          // This copies the buffer but does not free it
          VALUE result = protect(rb_usascii_str_new_cstr, data);
          // And free the char* since we were told to take "ownership"
          // TODO - is this a good idea?
          //free(data);
          return result;
        }
        else
        {
          // Does NOT copy the passed in buffer and does NOT free it when the string is GCed
          long len = (long)strlen(data);
          VALUE result = protect(rb_str_new_static, data, len);
          // Freeze the object so Ruby can't modify the C string
          return rb_obj_freeze(result);
        }
      }

    private:
      Arg* arg_ = nullptr;
    };

    template<int N>
    class To_Ruby<char[N]>
    {
    public:
      To_Ruby() = default;

      explicit To_Ruby(Arg* arg) : arg_(arg)
      {
      }

      VALUE convert(const char buffer[])
      {
        if (N > 0 && buffer[0] == ':')
        {
          // N count includes a NULL character at the end of the string
          constexpr size_t symbolLength = N - 1;
          char symbol[symbolLength];
          strncpy(symbol, buffer + 1, symbolLength);
          ID id = protect(rb_intern, symbol);
          return protect(rb_id2sym, id);
        }
        else
        {
          long size = (long)strlen(buffer);
          return protect(rb_usascii_str_new_static, buffer, size);
        }
      }

    private:
      Arg* arg_ = nullptr;
    };

    // ===========  unsigned char  ============
    template<>
    class To_Ruby<unsigned char>
    {
    public:
      To_Ruby() = default;

      explicit To_Ruby(Arg* arg) : arg_(arg)
      {
      }

      VALUE convert(const unsigned char& native)
      {
        return To_Ruby<unsigned int>().convert(native);
      }

    private:
      Arg* arg_ = nullptr;
    };

    template<>
    class To_Ruby<unsigned char&>
    {
    public:
      To_Ruby() = default;

      explicit To_Ruby(Arg* arg) : arg_(arg)
      {
      }

      VALUE convert(const unsigned char& native)
      {
        return To_Ruby<unsigned int>().convert(native);
      }

    private:
      Arg* arg_ = nullptr;
    };

    template<int N>
    class To_Ruby<unsigned char[N]>
    {
    public:
      To_Ruby() = default;

      explicit To_Ruby(Arg* arg) : arg_(arg)
      {
      }

      VALUE convert(unsigned char data[N])
      {
        Buffer<unsigned char> buffer(data, N);
        Data_Object<Buffer<unsigned char>> dataObject(std::move(buffer));
        return dataObject.value();
      }
    private:
      Arg* arg_ = nullptr;
    };

    // ===========  signed char  ============
    template<>
    class To_Ruby<signed char>
    {
    public:
      To_Ruby() = default;

      explicit To_Ruby(Arg* arg) : arg_(arg)
      {
      }

      VALUE convert(const signed char& native)
      {
        return To_Ruby<signed int>().convert(native);
      }

    private:
      Arg* arg_ = nullptr;
    };

    template<>
    class To_Ruby<signed char&>
    {
    public:
      To_Ruby() = default;

      explicit To_Ruby(Arg* arg) : arg_(arg)
      {
      }

      VALUE convert(const signed char& native)
      {
        return To_Ruby<signed int>().convert(native);
      }

    private:
      Arg* arg_ = nullptr;
    };

    template<int N>
    class To_Ruby<signed char[N]>
    {
    public:
      To_Ruby() = default;

      explicit To_Ruby(Arg* arg) : arg_(arg)
      {
      }

      VALUE convert(signed char data[N])
      {
        Buffer<signed char> buffer(data, N);
        Data_Object<Buffer<signed char>> dataObject(std::move(buffer));
        return dataObject.value();
      }
    private:
      Arg* arg_ = nullptr;
    };

    // ===========  double  ============
    template<>
    class To_Ruby<double>
    {
    public:
      To_Ruby() = default;

      explicit To_Ruby(Arg* arg) : arg_(arg)
      {
      }

      VALUE convert(const double& native)
      {
        return protect(rb_float_new, native);
      }

    private:
      Arg* arg_ = nullptr;
    };

    template<>
    class To_Ruby<double&>
    {
    public:
      To_Ruby() = default;

      explicit To_Ruby(Arg* arg) : arg_(arg)
      {
      }

      VALUE convert(const double& native)
      {
        return protect(rb_float_new, native);
      }

    private:
      Arg* arg_ = nullptr;
    };

    template<int N>
    class To_Ruby<double[N]>
    {
    public:
      To_Ruby() = default;

      explicit To_Ruby(Arg* arg) : arg_(arg)
      {
      }

      VALUE convert(double data[N])
      {
        Buffer<double> buffer(data, N);
        Data_Object<Buffer<double>> dataObject(std::move(buffer));
        return dataObject.value();
      }
    private:
      Arg* arg_ = nullptr;
    };

    // ===========  long double  ============
    template<>
    class To_Ruby<long double>
    {
    public:
      To_Ruby() = default;

      explicit To_Ruby(Arg* arg) : arg_(arg)
      {}

      VALUE convert(const long double& native)
      {
        return protect(rb_float_new, native);
      }

    private:
      Arg* arg_ = nullptr;
    };

    template<>
    class To_Ruby<long double&>
    {
    public:
      To_Ruby() = default;

      explicit To_Ruby(Arg* arg) : arg_(arg)
      {}

      VALUE convert(const long double& native)
      {
        return protect(rb_float_new, native);
      }

    private:
      Arg* arg_ = nullptr;
    };

    template<int N>
    class To_Ruby<long double[N]>
    {
    public:
      To_Ruby() = default;

      explicit To_Ruby(Arg* arg) : arg_(arg)
      {}

      VALUE convert(long double data[N])
      {
        Buffer<long double> buffer(data, N);
        Data_Object<Buffer<long double>> dataObject(std::move(buffer));
        return dataObject.value();
      }
    private:
      Arg* arg_ = nullptr;
    };

    // ===========  float  ============
    template<>
    class To_Ruby<float>
    {
    public:
      To_Ruby() = default;

      explicit To_Ruby(Arg* arg) : arg_(arg)
      {
      }

      VALUE convert(const float& native)
      {
        return protect(rb_float_new, (double)native);
      }

    private:
      Arg* arg_ = nullptr;
    };

    template<>
    class To_Ruby<float&>
    {
    public:
      To_Ruby() = default;

      explicit To_Ruby(Arg* arg) : arg_(arg)
      {
      }

      VALUE convert(const float& native)
      {
        return protect(rb_float_new, (double)native);
      }

    private:
      Arg* arg_ = nullptr;
    };

    template<int N>
    class To_Ruby<float[N]>
    {
    public:
      To_Ruby() = default;

      explicit To_Ruby(Arg* arg) : arg_(arg)
      {
      }

      VALUE convert(float data[N])
      {
        Buffer<float> buffer(data, N);
        Data_Object<Buffer<float>> dataObject(std::move(buffer));
        return dataObject.value();
      }
    private:
      Arg* arg_ = nullptr;
    };

    // ===========  long  ============
    template<>
    class To_Ruby<long>
    {
    public:
      To_Ruby() = default;

      explicit To_Ruby(Arg* arg) : arg_(arg)
      {
      }

      VALUE convert(const long& native)
      {
        return protect(rb_long2num_inline, native);
      }

    private:
      Arg* arg_ = nullptr;
    };

    template<>
    class To_Ruby<long&>
    {
    public:
      To_Ruby() = default;

      explicit To_Ruby(Arg* arg) : arg_(arg)
      {
      }

      VALUE convert(const long& native)
      {
        return protect(rb_long2num_inline, native);
      }

    private:
      Arg* arg_ = nullptr;
    };

    template<int N>
    class To_Ruby<long[N]>
    {
    public:
      To_Ruby() = default;

      explicit To_Ruby(Arg* arg) : arg_(arg)
      {
      }

      VALUE convert(long data[N])
      {
        Buffer<long> buffer(data, N);
        Data_Object<Buffer<long>> dataObject(std::move(buffer));
        return dataObject.value();
      }
    private:
      Arg* arg_ = nullptr;
    };

    // ===========  unsigned long  ============
    template<>
    class To_Ruby<unsigned long>
    {
    public:
      To_Ruby() = default;

      explicit To_Ruby(Arg* arg) : arg_(arg)
      {
      }

      VALUE convert(const unsigned long& native)
      {
        if (this->arg_ && this->arg_->isValue())
        {
          return native;
        }
        else
        {
          return protect(rb_ulong2num_inline, native);
        }
      }

    private:
      Arg* arg_ = nullptr;
    };

    template<>
    class To_Ruby<unsigned long&>
    {
    public:
      To_Ruby() = default;

      explicit To_Ruby(Arg* arg) : arg_(arg)
      {
      }

      VALUE convert(const unsigned long& native)
      {
        if (this->arg_ && this->arg_->isValue())
        {
          return native;
        }
        else
        {
          return protect(rb_ulong2num_inline, native);
        }
      }

    private:
      Arg* arg_ = nullptr;
    };

    template<int N>
    class To_Ruby<unsigned long[N]>
    {
    public:
      To_Ruby() = default;

      explicit To_Ruby(Arg* arg) : arg_(arg)
      {
      }

      VALUE convert(unsigned long data[N])
      {
        Buffer<unsigned long> buffer(data, N);
        Data_Object<Buffer<unsigned long>> dataObject(std::move(buffer));
        return dataObject.value();
      }
    private:
      Arg* arg_ = nullptr;
    };

    // ===========  long long  ============
    template<>
    class To_Ruby<long long>
    {
    public:
      To_Ruby() = default;

      explicit To_Ruby(Arg* arg) : arg_(arg)
      {
      }

      VALUE convert(const long long& native)
      {
        return protect(rb_ll2inum, native);
      }

    private:
      Arg* arg_ = nullptr;
    };

    template<>
    class To_Ruby<long long&>
    {
    public:
      To_Ruby() = default;

      explicit To_Ruby(Arg* arg) : arg_(arg)
      {
      }

      VALUE convert(const long long& native)
      {
        return protect(rb_ll2inum, native);
      }

    private:
      Arg* arg_ = nullptr;
    };

    template<int N>
    class To_Ruby<long long[N]>
    {
    public:
      To_Ruby() = default;

      explicit To_Ruby(Arg* arg) : arg_(arg)
      {
      }

      VALUE convert(long long data[N])
      {
        Buffer<long long> buffer(data, N);
        Data_Object<Buffer<long long>> dataObject(std::move(buffer));
        return dataObject.value();
      }
    private:
      Arg* arg_ = nullptr;
    };

    // ===========  unsigned long long  ============
    template<>
    class To_Ruby<unsigned long long>
    {
    public:
      To_Ruby() = default;

      explicit To_Ruby(Arg* arg) : arg_(arg)
      {
      }

      VALUE convert(const unsigned long long& native)
      {
        if (this->arg_ && this->arg_->isValue())
        {
          return native;
        }
        else
        {
          return protect(rb_ull2inum, (unsigned long long)native);
        }
      }

      VALUE convert(const volatile unsigned long long& native)
      {
        if (this->arg_ && this->arg_->isValue())
        {
          return native;
        }
        else
        {
          return protect(rb_ull2inum, (unsigned long long)native);
        }
      }
    private:
      Arg* arg_ = nullptr;
    };

    template<>
    class To_Ruby<unsigned long long&>
    {
    public:
      To_Ruby() = default;

      explicit To_Ruby(Arg* arg) : arg_(arg)
      {
      }

      VALUE convert(const unsigned long long& native)
      {
        if (this->arg_ && this->arg_->isValue())
        {
          return native;
        }
        else
        {
          return protect(rb_ull2inum, (unsigned long long)native);
        }
      }

    private:
      Arg* arg_ = nullptr;
    };

    template<int N>
    class To_Ruby<unsigned long long[N]>
    {
    public:
      To_Ruby() = default;

      explicit To_Ruby(Arg* arg) : arg_(arg)
      {
      }

      VALUE convert(unsigned long long data[N])
      {
        Buffer<unsigned long long> buffer(data, N);
        Data_Object<Buffer<unsigned long long>> dataObject(std::move(buffer));
        return dataObject.value();
      }
    private:
      Arg* arg_ = nullptr;
    };

    // ===========  short  ============
    template<>
    class To_Ruby<short>
    {
    public:
      To_Ruby() = default;

      explicit To_Ruby(Arg* arg) : arg_(arg)
      {
      }

      VALUE convert(const short& native)
      {
#ifdef rb_int2num_inline
        return protect(rb_int2num_inline, (int)native);
#else
        return RB_INT2NUM(native);
#endif
      }

    private:
      Arg* arg_ = nullptr;
    };

    template<>
    class To_Ruby<short&>
    {
    public:
      To_Ruby() = default;

      explicit To_Ruby(Arg* arg) : arg_(arg)
      {
      }

      VALUE convert(const short& native)
      {
#ifdef rb_int2num_inline
        return protect(rb_int2num_inline, (int)native);
#else
        return RB_INT2NUM(native);
#endif
      }

    private:
      Arg* arg_ = nullptr;
    };

    template<int N>
    class To_Ruby<short[N]>
    {
    public:
      To_Ruby() = default;

      explicit To_Ruby(Arg* arg) : arg_(arg)
      {
      }

      VALUE convert(short data[N])
      {
        Buffer<short> buffer(data, N);
        Data_Object<Buffer<short>> dataObject(std::move(buffer));
        return dataObject.value();
      }
    private:
      Arg* arg_ = nullptr;
    };

    // ===========  unsigned short  ============
    template<>
    class To_Ruby<unsigned short>
    {
    public:
      To_Ruby() = default;

      explicit To_Ruby(Arg* arg) : arg_(arg)
      {
      }

      VALUE convert(const unsigned short& native)
      {
#ifdef rb_int2num_inline
        return protect(rb_uint2num_inline, (unsigned int)native);
#else
        return RB_UINT2NUM(native);
#endif
      }

    private:
      Arg* arg_ = nullptr;
    };

    template<>
    class To_Ruby<unsigned short&>
    {
    public:
      To_Ruby() = default;

      explicit To_Ruby(Arg* arg) : arg_(arg)
      {
      }

      VALUE convert(const unsigned short& native)
      {
#ifdef rb_int2num_inline
        return protect(rb_uint2num_inline, (unsigned int)native);
#else
        return RB_UINT2NUM(native);
#endif
      }

    private:
      Arg* arg_ = nullptr;
    };

    template<int N>
    class To_Ruby<unsigned short[N]>
    {
    public:
      To_Ruby() = default;

      explicit To_Ruby(Arg* arg) : arg_(arg)
      {
      }

      VALUE convert(unsigned short data[N])
      {
        Buffer<unsigned short> buffer(data, N);
        Data_Object<Buffer<unsigned short>> dataObject(std::move(buffer));
        return dataObject.value();
      }
    private:
      Arg* arg_ = nullptr;
    };

    // ===========  std::nullptr_t  ============
    template<>
    class To_Ruby<std::nullptr_t>
    {
    public:
      To_Ruby() = default;

      explicit To_Ruby(Arg* arg) : arg_(arg)
      {
      }

      VALUE convert(std::nullptr_t const)
      {
        return Qnil;
      }

    private:
      Arg* arg_ = nullptr;
    };

    // ===========  void  ============
    template<>
    class To_Ruby<void>
    {
    public:
      To_Ruby() = default;

      explicit To_Ruby(Arg* arg) : arg_(arg)
      {
      }

      VALUE convert(const void*)
      {
        throw std::runtime_error("Converting from void pointer is not implemented");
        return Qnil;
      }

    private:
      Arg* arg_ = nullptr;
    };
 
    template <>
    class To_Ruby<void*>
    {
    public:
      To_Ruby() = default;

      explicit To_Ruby(Arg* arg) : arg_(arg)
      {
      }

      VALUE convert(void* data)
      {
        if (data == nullptr)
        {
          return Qnil;
        }
        else if (this->arg_ && this->arg_->isOpaque())
        {
          return VALUE(data);
        }
        else
        {
          bool isOwner = this->arg_ && this->arg_->isOwner();
          return detail::wrap(Data_Type<Pointer<void>>::klass(), Data_Type<Pointer<void>>::ruby_data_type(), data, isOwner);
        }
      }

      VALUE convert(const void* data)
      {
        return convert((void*)data);
      }

    private:
      Arg* arg_ = nullptr;
    };
 }
}
// =========   from_ruby.ipp   =========
#include <limits>
#include <optional>
#include <stdexcept>

/* This file implements conversions from Ruby to native values fo fundamental types
   such as bool, int, float, etc. It also includes conversions for chars and strings */
namespace Rice::detail
{
  // Get precision bits for a Ruby numeric value
  inline int rubyPrecisionBits(VALUE value)
  {
    switch (rb_type(value))
    {
      // Ruby fixnums fit in long long (63 bits)
      case RUBY_T_FIXNUM:
        return std::numeric_limits<long long>::digits;

      // Ruby bignums can be arbitrarily large - return actual size
      case RUBY_T_BIGNUM:
      {
        int nlz = 0;
        size_t bytes = protect(rb_absint_size, value, &nlz);
        return static_cast<int>(bytes * CHAR_BIT - nlz);
      }

      // Ruby floats are C doubles (53 bit mantissa)
      case RUBY_T_FLOAT:
        return std::numeric_limits<double>::digits;
      
      // Everything else...
      default:
        return 0;
    }
  }

  // Precision score for converting Ruby numeric value to C++ type T
  template<typename T>
  inline double precisionScore(VALUE value)
  {
    int sourceBits = rubyPrecisionBits(value);
    if (sourceBits == 0)
    {
      return Convertible::None;
    }

    constexpr int targetBits = std::numeric_limits<T>::digits;
    return (targetBits >= sourceBits) ? Convertible::Exact : static_cast<double>(targetBits) / sourceBits;
  }

  // Primary template for integral types
  template<typename T, typename Enable = void>
  class FromRubyFundamental
  {
  public:
    static double is_convertible(VALUE value)
    {
      double score = precisionScore<T>(value);
      if (score > Convertible::None)
      {
        switch (rb_type(value))
        {
          case RUBY_T_BIGNUM:
          {
            constexpr int targetBits = std::numeric_limits<T>::digits;
            int sourceBits = rubyPrecisionBits(value);
            if (sourceBits > targetBits)
            {
              return Convertible::None;
            }
            [[fallthrough]];
          }
          case RUBY_T_FIXNUM:
          {
            if constexpr (std::is_unsigned_v<T>)
            {
              score *= Convertible::SignedToUnsigned;
            }
            break;
          }
          case RUBY_T_FLOAT:
          {
            score *= Convertible::FloatToInt;
            break;
          }
          default:
            break;
        }

        return score;
      }

      if constexpr (is_char_type_v<T>)
      {
        if (rb_type(value) == RUBY_T_STRING)
        {
          return Convertible::Exact;
        }
      }

      return Convertible::None;
    }

    static T convert(VALUE value)
    {
      return (T)protect(RubyType<T>::fromRuby, value);
    }
  };

  // Specialization for floating point types
  template<typename T>
  class FromRubyFundamental<T, std::enable_if_t<std::is_floating_point_v<T>>>
  {
  public:
    static double is_convertible(VALUE value)
    {
      double score = precisionScore<T>(value);
      if (score > Convertible::None && rb_type(value) != RUBY_T_FLOAT)
      {
        score *= Convertible::IntToFloat;
      }
      return score;
    }

    static T convert(VALUE value)
    {
      return (T)protect(RubyType<T>::fromRuby, value);
    }
  };

  template<typename T>
  class FromRubyFundamental<T*>
  {
  public:
    static double is_convertible(VALUE value)
    {
      ruby_value_type valueType = rb_type(value);

      switch (valueType)
      {
        case RUBY_T_NIL:
        {
          return Convertible::Exact;
        }
        case RUBY_T_DATA:
        {
          if (Data_Type<Pointer<T>>::is_descendant(value))
          {
            return Convertible::Exact;
          }
          [[fallthrough]];
        }
        default:
        {
          return Convertible::None;
        }
      }
    }

    static T* convert(VALUE value)
    {
      ruby_value_type valueType = rb_type(value);

      switch (valueType)
      {
        case RUBY_T_NIL:
        {
          return nullptr;
        }
        case RUBY_T_DATA:
        {
          if (Data_Type<Pointer<T>>::is_descendant(value))
          {
            return unwrap<T>(value, Data_Type<Pointer<T>>::ruby_data_type(), false);
          }
          [[fallthrough]];
        }
        default:
        {
          detail::TypeDetail<Pointer<T>> typeDetail;
          std::string expected = typeDetail.rubyName();
          throw Exception(rb_eTypeError, "wrong argument type %s (expected %s)",
            detail::protect(rb_obj_classname, value), expected.c_str());
        }
      }
    }
  };

  template<typename T>
  class FromRubyFundamental<T**>
  {
  public:
    static double is_convertible(VALUE value)
    {
      ruby_value_type valueType = rb_type(value);

      switch (valueType)
      {
        case RUBY_T_NIL:
        {
          return Convertible::Exact;
        }
        case RUBY_T_DATA:
        {
          if (Data_Type<Pointer<T*>>::is_descendant(value))
          {
            return Convertible::Exact;
          }
          [[fallthrough]];
        }
        default:
        {
          return Convertible::None;
        }
      }
    }

    static T** convert(VALUE value)
    {
      ruby_value_type valueType = rb_type(value);

      switch (valueType)
      {
        case RUBY_T_NIL:
        {
          return nullptr;
        }
        case RUBY_T_DATA:
        {
          if (Data_Type<Pointer<T*>>::is_descendant(value))
          {
            return unwrap<T*>(value, Data_Type<Pointer<T*>>::ruby_data_type(), false);
          }
          [[fallthrough]];
        }
        default:
        {
          detail::TypeDetail<Pointer<T*>> typeDetail;
          std::string expected = typeDetail.rubyName();
          throw Exception(rb_eTypeError, "wrong argument type %s (expected %s)",
            detail::protect(rb_obj_classname, value), expected.c_str());
        }
      }
    }
  };

  // ===========  bool  ============
  template<>
  class From_Ruby<bool>
  {
  public:
    From_Ruby() = default;

    explicit From_Ruby(Arg* arg) : arg_(arg)
    {
    }

    double is_convertible(VALUE value)
    {
      switch (rb_type(value))
      {
        case RUBY_T_TRUE:
        case RUBY_T_FALSE:
        case RUBY_T_NIL:
          return Convertible::Exact;
        default:
          return Convertible::None;
      }
    }

    bool convert(VALUE value)
    {
      return protect(RubyType<bool>::fromRuby, value);
    }

  private:
    Arg* arg_ = nullptr;
  };

  template<>
  class From_Ruby<bool&>
  {
  public:
    using Reference_T = Reference<bool>;

    From_Ruby() = default;

    explicit From_Ruby(Arg* arg) : arg_(arg)
    {
    }

    double is_convertible(VALUE value)
    {
      switch (rb_type(value))
      {
        case RUBY_T_DATA:
        {
          if (Data_Type<Reference_T>::is_descendant(value))
          {
            return Convertible::Exact;
          }
          [[fallthrough]];
        }
        default:
        {
          return this->from_.is_convertible(value);
        }
      }
    }

    bool& convert(VALUE value)
    {
      switch (rb_type(value))
      {
        case RUBY_T_DATA:
        {
          if (Data_Type<Reference_T>::is_descendant(value))
          {
            Reference_T* reference = unwrap<Reference_T>(value, Data_Type<Reference_T>::ruby_data_type(), false);
            return reference->get();
          }
          [[fallthrough]];
        }
        default:
        {
          this->reference_ = Reference<bool>(value);
          return this->reference_.get();
        }
      }
    }

  private:
    From_Ruby<bool> from_;
    Arg* arg_ = nullptr;
    Reference<bool> reference_;
  };

  // ===========  char  ============
  template<>
  class From_Ruby<char>
  {
  public:
    From_Ruby() = default;

    explicit From_Ruby(Arg* arg) : arg_(arg)
    {
    }

    double is_convertible(VALUE value)
    {
      return FromRubyFundamental<char>::is_convertible(value);
    }

    char convert(VALUE value)
    {
      return FromRubyFundamental<char>::convert(value);
    }

  private:
    Arg* arg_ = nullptr;
  };

  template<>
  class From_Ruby<char&>
  {
  public:
    using Reference_T = Reference<char>;

    From_Ruby() = default;

    explicit From_Ruby(Arg* arg) : arg_(arg)
    {
    }

    double is_convertible(VALUE value)
    {
      switch (rb_type(value))
      {
        case RUBY_T_DATA:
        {
          if (Data_Type<Reference_T>::is_descendant(value))
          {
            return Convertible::Exact;
          }
          [[fallthrough]];
        }
        default:
        {
          return FromRubyFundamental<char>::is_convertible(value);
        }
      }
    }

    char& convert(VALUE value)
    {
      switch (rb_type(value))
      {
        case RUBY_T_DATA:
        {
          if (Data_Type<Reference_T>::is_descendant(value))
          {
            Reference_T* reference = unwrap<Reference_T>(value, Data_Type<Reference_T>::ruby_data_type(), false);
            return reference->get();
          }
          [[fallthrough]];
        }
        default:
        {
          this->reference_ = Reference<char>(value);
          return this->reference_.get();
        }
      }
    }

  private:
    Arg* arg_ = nullptr;
    Reference<char> reference_;
  };

  template<>
  class From_Ruby<char*>
  {
  public:
    From_Ruby() = default;

    explicit From_Ruby(Arg* arg) : arg_(arg)
    {
    }

    double is_convertible(VALUE value)
    {
      switch (rb_type(value))
      {
      case RUBY_T_NIL:
      {
        return Convertible::Exact;
      }
      case RUBY_T_STRING:
      {
        return Convertible::Exact;
      }
      default:
      {
        return FromRubyFundamental<char*>::is_convertible(value);
      }
      }
    }

    char* convert(VALUE value)
    {
      switch (rb_type(value))
      {
        case RUBY_T_NIL:
        {
          return nullptr;
        }
        case RUBY_T_STRING:
        {
            if (this->arg_ && this->arg_->isOwner())
            {
              // Warning - the receiver needs to free this string!
              // TODO - raise an exception if the string has null values?
              long len = RSTRING_LEN(value);
              char* result = (char*)malloc(len + 1);
              memcpy(result, RSTRING_PTR(value), len);
              result[len] = '\0';
              return result;
            }
            else
            {
              // WARNING - this shares the Ruby string memory directly with C++. value really should be frozen.
              // Maybe we should enforce that? Note the user can always create a Buffer to allocate new memory.
              return rb_string_value_cstr(&value);
            }
        }
        default:
        {
          return FromRubyFundamental<char*>::convert(value);
        }
      }
    }

  private:
    Arg* arg_ = nullptr;
  };
  
  // ===========  unsigned char  ============
  template<>
  class From_Ruby<unsigned char>
  {
  public:
    From_Ruby() = default;

    explicit From_Ruby(Arg* arg) : arg_(arg)
    {
    }

    double is_convertible(VALUE value)
    {
      return FromRubyFundamental<unsigned char>::is_convertible(value);
    }

    unsigned char convert(VALUE value)
    {
      return FromRubyFundamental<unsigned char>::convert(value);
    }

  private:
    Arg* arg_ = nullptr;
  };

  template<>
  class From_Ruby<unsigned char&>
  {
  public:
    using Reference_T = Reference<unsigned char>;

    From_Ruby() = default;

    explicit From_Ruby(Arg* arg) : arg_(arg)
    {
    }

    double is_convertible(VALUE value)
    {
      switch (rb_type(value))
      {
        case RUBY_T_DATA:
        {
          if (Data_Type<Reference_T>::is_descendant(value))
          {
            return Convertible::Exact;
          }
          [[fallthrough]];
        }
        default:
        {
          return FromRubyFundamental<unsigned char>::is_convertible(value);
        }
      }
    }

    unsigned char& convert(VALUE value)
    {
      switch (rb_type(value))
      {
        case RUBY_T_DATA:
        {
          if (Data_Type<Reference_T>::is_descendant(value))
          {
            Reference_T* reference = unwrap<Reference_T>(value, Data_Type<Reference_T>::ruby_data_type(), false);
            return reference->get();
          }
          [[fallthrough]];
        }
        default:
        {
          this->reference_ = Reference<unsigned char>(value);
          return this->reference_.get();
        }
      }
    }

  private:
    Arg* arg_ = nullptr;
    Reference<unsigned char> reference_;
  };

  // ===========  signed char  ============
  template<>
  class From_Ruby<signed char>
  {
  public:
    From_Ruby() = default;

    explicit From_Ruby(Arg* arg) : arg_(arg)
    {
    }

    double is_convertible(VALUE value)
    {
      return FromRubyFundamental<signed char>::is_convertible(value);
    }

    signed char convert(VALUE value)
    {
      return FromRubyFundamental<signed char>::convert(value);
    }

  private:
    Arg* arg_ = nullptr;
  };

  template<>
  class From_Ruby<signed char&>
  {
  public:
    using Reference_T = Reference<signed char>;

    From_Ruby() = default;

    explicit From_Ruby(Arg* arg) : arg_(arg)
    {
    }

    double is_convertible(VALUE value)
    {
      switch (rb_type(value))
      {
        case RUBY_T_DATA:
        {
          if (Data_Type<Reference_T>::is_descendant(value))
          {
            return Convertible::Exact;
          }
          [[fallthrough]];
        }
        default:
        {
          return FromRubyFundamental<signed char>::is_convertible(value);
        }
      }
    }

    signed char& convert(VALUE value)
    {
      switch (rb_type(value))
      {
        case RUBY_T_DATA:
        {
          if (Data_Type<Reference_T>::is_descendant(value))
          {
            Reference_T* reference = unwrap<Reference_T>(value, Data_Type<Reference_T>::ruby_data_type(), false);
            return reference->get();
          }
          [[fallthrough]];
        }
        default:
        {
          this->reference_ = Reference<signed char>(value);
          return this->reference_.get();
        }
      }
    }

  private:
    Arg* arg_ = nullptr;
    Reference<signed char> reference_;
  };

  // ===========  double  ============
  template<>
  class From_Ruby<double>
  {
  public:
    From_Ruby() = default;

    explicit From_Ruby(Arg* arg) : arg_(arg)
    {
    }

    double is_convertible(VALUE value)
    {
      return FromRubyFundamental<double>::is_convertible(value);
    }

    double convert(VALUE value)
    {
      return FromRubyFundamental<double>::convert(value);
    }

  private:
    Arg* arg_ = nullptr;
  };

  template<>
  class From_Ruby<double&>
  {
  public:
    using Reference_T = Reference<double>;

    From_Ruby() = default;

    explicit From_Ruby(Arg* arg) : arg_(arg)
    {
    }

    double is_convertible(VALUE value)
    {
      switch (rb_type(value))
      {
        case RUBY_T_DATA:
        {
          if (Data_Type<Reference_T>::is_descendant(value))
          {
            return Convertible::Exact;
          }
          [[fallthrough]];
        }
        default:
        {
          return FromRubyFundamental<double>::is_convertible(value);
        }
      }
    }

    double& convert(VALUE value)
    {
      switch (rb_type(value))
      {
        case RUBY_T_DATA:
        {
          if (Data_Type<Reference_T>::is_descendant(value))
          {
            Reference_T* reference = unwrap<Reference_T>(value, Data_Type<Reference_T>::ruby_data_type(), false);
            return reference->get();
          }
          [[fallthrough]];
        }
        default:
        {
          this->reference_ = Reference<double>(value);
          return this->reference_.get();
        }
      }
    }

  private:
    Arg* arg_ = nullptr;
    Reference<double> reference_;
  };

  // ===========  long double  ============
  template<>
  class From_Ruby<long double>
  {
  public:
    From_Ruby() = default;

    explicit From_Ruby(Arg* arg) : arg_(arg)
    {}

    long double is_convertible(VALUE value)
    {
      return FromRubyFundamental<long double>::is_convertible(value);
    }

    long double convert(VALUE value)
    {
      return FromRubyFundamental<long double>::convert(value);
    }

  private:
    Arg* arg_ = nullptr;
  };

  template<>
  class From_Ruby<long double&>
  {
  public:
    using Reference_T = Reference<long double>;

    From_Ruby() = default;

    explicit From_Ruby(Arg* arg) : arg_(arg)
    {}

    long double is_convertible(VALUE value)
    {
      switch (rb_type(value))
      {
        case RUBY_T_DATA:
        {
          if (Data_Type<Reference_T>::is_descendant(value))
          {
            return Convertible::Exact;
          }
          [[fallthrough]];
        }
        default:
        {
          return FromRubyFundamental<long double>::is_convertible(value);
        }
      }
    }

    long double& convert(VALUE value)
    {
      switch (rb_type(value))
      {
        case RUBY_T_DATA:
        {
          if (Data_Type<Reference_T>::is_descendant(value))
          {
            Reference_T* reference = unwrap<Reference_T>(value, Data_Type<Reference_T>::ruby_data_type(), false);
            return reference->get();
          }
          [[fallthrough]];
        }
        default:
        {
          this->reference_ = Reference<long double>(value);
          return this->reference_.get();
        }
      }
    }

  private:
    Arg* arg_ = nullptr;
    Reference<long double> reference_;
  };

  // ===========  float  ============
  template<>
  class From_Ruby<float>
  {
  public:
    From_Ruby() = default;

    explicit From_Ruby(Arg* arg) : arg_(arg)
    {
    }

    double is_convertible(VALUE value)
    {
      return FromRubyFundamental<float>::is_convertible(value);
    }

    float convert(VALUE value)
    {
      return FromRubyFundamental<float>::convert(value);
    }

  private:
    Arg* arg_ = nullptr;
  };

  template<>
  class From_Ruby<float&>
  {
  public:
    using Reference_T = Reference<float>;

    From_Ruby() = default;

    explicit From_Ruby(Arg* arg) : arg_(arg)
    {
    }

    double is_convertible(VALUE value)
    {
      switch (rb_type(value))
      {
        case RUBY_T_DATA:
        {
          if (Data_Type<Reference_T>::is_descendant(value))
          {
            return Convertible::Exact;
          }
          [[fallthrough]];
        }
        default:
        {
          return FromRubyFundamental<float>::is_convertible(value);
        }
      }
    }

    float& convert(VALUE value)
    {
      switch (rb_type(value))
      {
        case RUBY_T_DATA:
        {
          if (Data_Type<Reference_T>::is_descendant(value))
          {
            Reference_T* reference = unwrap<Reference_T>(value, Data_Type<Reference_T>::ruby_data_type(), false);
            return reference->get();
          }
          [[fallthrough]];
        }
        default:
        {
          this->reference_ = Reference<float>(value);
          return this->reference_.get();
        }
      }
    }

  private:
    Arg* arg_ = nullptr;
    Reference<float> reference_;
  };

  // ===========  int  ============
  template<>
  class From_Ruby<int>
  {
  public:
    From_Ruby() = default;

    explicit From_Ruby(Arg* arg) : arg_(arg)
    {
    }

    double is_convertible(VALUE value)
    {
      double result = FromRubyFundamental<int>::is_convertible(value);

      // Is this an enum? If so we want to support converting it to an integer
      if (result == Convertible::None && rb_type(value) == RUBY_T_DATA)
      {
        static ID id = protect(rb_intern, "to_int");
        if (protect(rb_respond_to, value, id))
        {
          result = Convertible::Exact;
        }
      }
      return result;
    }

    int convert(VALUE value)
    {
      return FromRubyFundamental<int>::convert(value);
    }

  private:
    Arg* arg_ = nullptr;
  };

  template<>
  class From_Ruby<int&>
  {
  public:
    using Reference_T = Reference<int>;

    From_Ruby() = default;

    explicit From_Ruby(Arg* arg) : arg_(arg)
    {
    }

    double is_convertible(VALUE value)
    {
      switch (rb_type(value))
      {
        case RUBY_T_DATA:
        {
          if (Data_Type<Reference_T>::is_descendant(value))
          {
            return Convertible::Exact;
          }
          [[fallthrough]];
        }
        default:
        {
          return FromRubyFundamental<int>::is_convertible(value);
        }
      }
    }

    int& convert(VALUE value)
    {
      switch (rb_type(value))
      {
        case RUBY_T_DATA:
        {
          if (Data_Type<Reference_T>::is_descendant(value))
          {
            Reference_T* reference = unwrap<Reference_T>(value, Data_Type<Reference_T>::ruby_data_type(), false);
            return reference->get();
          }
          [[fallthrough]];
        }
        default:
        {
          this->reference_ = Reference<int>(value);
          return this->reference_.get();
        }
      }
    }

  private:
    Arg* arg_ = nullptr;
    Reference<int> reference_;
  };

  // ===========  unsigned int  ============
  template<>
  class From_Ruby<unsigned int>
  {
  public:
    From_Ruby() = default;

    explicit From_Ruby(Arg* arg) : arg_(arg)
    {
    }

    double is_convertible(VALUE value)
    {
      return FromRubyFundamental<unsigned int>::is_convertible(value);
    }

    unsigned int convert(VALUE value)
    {
      return FromRubyFundamental<unsigned int>::convert(value);
    }

  private:
    Arg* arg_ = nullptr;
  };

  template<>
  class From_Ruby<unsigned int&>
  {
  public:
    using Reference_T = Reference<unsigned int>;

    From_Ruby() = default;

    explicit From_Ruby(Arg* arg) : arg_(arg)
    {
    }

    double is_convertible(VALUE value)
    {
      switch (rb_type(value))
      {
        case RUBY_T_DATA:
        {
          if (Data_Type<Reference_T>::is_descendant(value))
          {
            return Convertible::Exact;
          }
          [[fallthrough]];
        }
        default:
        {
          return FromRubyFundamental<unsigned int>::is_convertible(value);
        }
      }
    }

    unsigned int& convert(VALUE value)
    {
      switch (rb_type(value))
      {
        case RUBY_T_DATA:
        {
          if (Data_Type<Reference_T>::is_descendant(value))
          {
            Reference_T* reference = unwrap<Reference_T>(value, Data_Type<Reference_T>::ruby_data_type(), false);
            return reference->get();
          }
          [[fallthrough]];
        }
        default:
        {
          this->reference_ = Reference<unsigned int>(value);
          return this->reference_.get();
        }
      }
    }

  private:
    Arg* arg_ = nullptr;
    Reference<unsigned int> reference_;
  };

  // ===========  long  ============
  template<>
  class From_Ruby<long>
  {
  public:
    From_Ruby() = default;

    explicit From_Ruby(Arg* arg) : arg_(arg)
    {
    }

    double is_convertible(VALUE value)
    {
      return FromRubyFundamental<long>::is_convertible(value);
    }

    long convert(VALUE value)
    {
      return FromRubyFundamental<long>::convert(value);
    }
  
  private:
    Arg* arg_ = nullptr;
  };

  template<>
  class From_Ruby<long&>
  {
  public:
    using Reference_T = Reference<long>;

    From_Ruby() = default;

    explicit From_Ruby(Arg* arg) : arg_(arg)
    {
    }

    double is_convertible(VALUE value)
    {
      switch (rb_type(value))
      {
        case RUBY_T_DATA:
        {
          if (Data_Type<Reference_T>::is_descendant(value))
          {
            return Convertible::Exact;
          }
          [[fallthrough]];
        }
        default:
        {
          return FromRubyFundamental<long>::is_convertible(value);
        }
      }
    }

    long& convert(VALUE value)
    {
      switch (rb_type(value))
      {
        case RUBY_T_DATA:
        {
          if (Data_Type<Reference_T>::is_descendant(value))
          {
            Reference_T* reference = unwrap<Reference_T>(value, Data_Type<Reference_T>::ruby_data_type(), false);
            return reference->get();
          }
          [[fallthrough]];
        }
        default:
        {
          this->reference_ = Reference<long>(value);
          return this->reference_.get();
        }
      }
    }

  private:
    Arg* arg_ = nullptr;
    Reference<long> reference_;
  };

  // ===========  unsigned long  ============
  template<>
  class From_Ruby<unsigned long>
  {
  public:
    From_Ruby() = default;

    explicit From_Ruby(Arg* arg) : arg_(arg)
    {
    }

    double is_convertible(VALUE value)
    {
      return FromRubyFundamental<unsigned long>::is_convertible(value);
    }

    unsigned long convert(VALUE value)
    {
      if (this->arg_ && this->arg_->isValue())
      {
        return (unsigned long)value;
      }
      else
      {
        return FromRubyFundamental<unsigned long>::convert(value);
      }
    }

  private:
    Arg* arg_ = nullptr;
  };

  template<>
  class From_Ruby<unsigned long&>
  {
  public:
    using Reference_T = Reference<unsigned long>;

    From_Ruby() = default;

    explicit From_Ruby(Arg* arg) : arg_(arg)
    {
    }

    double is_convertible(VALUE value)
    {
      switch (rb_type(value))
      {
        case RUBY_T_DATA:
        {
          if (Data_Type<Reference_T>::is_descendant(value))
          {
            return Convertible::Exact;
          }
          [[fallthrough]];
        }
        default:
        {
          return FromRubyFundamental<unsigned long>::is_convertible(value);
        }
      }
    }

    unsigned long& convert(VALUE value)
    {
      switch (rb_type(value))
      {
        case RUBY_T_DATA:
        {
          if (Data_Type<Reference_T>::is_descendant(value))
          {
            Reference_T* reference = unwrap<Reference_T>(value, Data_Type<Reference_T>::ruby_data_type(), false);
            return reference->get();
          }
          [[fallthrough]];
        }
        default:
        {
          this->reference_ = Reference<unsigned long>(value);
          return this->reference_.get();
        }
      }
    }

  private:
    Arg* arg_ = nullptr;
    Reference<unsigned long> reference_;
  };

  // ===========  unsigned long long  ============
  template<>
  class From_Ruby<unsigned long long>
  {
  public:
    From_Ruby() = default;

    explicit From_Ruby(Arg* arg) : arg_(arg)
    {
    }

    double is_convertible(VALUE value)
    {
      return FromRubyFundamental<unsigned long long>::is_convertible(value);
    }

    unsigned long long convert(VALUE value)
    {
      if (this->arg_ && this->arg_->isValue())
      {
        return value;
      }
      else
      {
        return FromRubyFundamental<unsigned long long>::convert(value);
      }
    }

  private:
    Arg* arg_ = nullptr;
  };

  template<>
  class From_Ruby<unsigned long long&>
  {
  public:
    using Reference_T = Reference<unsigned long long>;

    From_Ruby() = default;

    explicit From_Ruby(Arg* arg) : arg_(arg)
    {
    }

    double is_convertible(VALUE value)
    {
      switch (rb_type(value))
      {
        case RUBY_T_DATA:
        {
          if (Data_Type<Reference_T>::is_descendant(value))
          {
            return Convertible::Exact;
          }
          [[fallthrough]];
        }
        default:
        {
          return FromRubyFundamental<unsigned long long>::is_convertible(value);
        }
      }
    }

    unsigned long long& convert(VALUE value)
    {
      switch (rb_type(value))
      {
        case RUBY_T_DATA:
        {
          if (Data_Type<Reference_T>::is_descendant(value))
          {
            Reference_T* reference = unwrap<Reference_T>(value, Data_Type<Reference_T>::ruby_data_type(), false);
            return reference->get();
          }
          [[fallthrough]];
        }
        default:
        {
          this->converted_ = FromRubyFundamental<unsigned long long>::convert(value);
          return this->converted_;
        }
      }
    }

  private:
    Arg* arg_ = nullptr;
    unsigned long long converted_ = 0;
  };

  // ===========  long long  ============
  template<>
  class From_Ruby<long long>
  {
  public:
    From_Ruby() = default;

    explicit From_Ruby(Arg* arg) : arg_(arg)
    {
    }

    double is_convertible(VALUE value)
    {
      return FromRubyFundamental<long long>::is_convertible(value);
    }

    long long convert(VALUE value)
    {
      return FromRubyFundamental<long long>::convert(value);
    }
  
  private:
    Arg* arg_ = nullptr;
  };

  template<>
  class From_Ruby<long long&>
  {
  public:
    using Reference_T = Reference<long long>;

    From_Ruby() = default;

    explicit From_Ruby(Arg* arg) : arg_(arg)
    {
    }

    double is_convertible(VALUE value)
    {
      switch (rb_type(value))
      {
        case RUBY_T_DATA:
        {
          if (Data_Type<Reference_T>::is_descendant(value))
          {
            return Convertible::Exact;
          }
          [[fallthrough]];
        }
        default:
        {
          return FromRubyFundamental<long long>::is_convertible(value);
        }
      }
    }

    long long& convert(VALUE value)
    {
      switch (rb_type(value))
      {
        case RUBY_T_DATA:
        {
          if (Data_Type<Reference_T>::is_descendant(value))
          {
            Reference_T* reference = unwrap<Reference_T>(value, Data_Type<Reference_T>::ruby_data_type(), false);
            return reference->get();
          }
          [[fallthrough]];
        }
        default:
        {
          this->reference_ = Reference<long long>(value);
          return this->reference_.get();
        }
      }
    }

  private:
    Arg* arg_ = nullptr;
    Reference<long long> reference_;
  };

  // ===========  short  ============
  template<>
  class From_Ruby<short>
  {
  public:
    From_Ruby() = default;

    explicit From_Ruby(Arg* arg) : arg_(arg)
    {
    }

    double is_convertible(VALUE value)
    {
      return FromRubyFundamental<short>::is_convertible(value);
    }

    short convert(VALUE value)
    {
      return FromRubyFundamental<short>::convert(value);
    }

  private:
    Arg* arg_ = nullptr;
  };

  template<>
  class From_Ruby<short&>
  {
  public:
    using Reference_T = Reference<short>;

    From_Ruby() = default;

    explicit From_Ruby(Arg* arg) : arg_(arg)
    {
    }

    double is_convertible(VALUE value)
    {
      switch (rb_type(value))
      {
        case RUBY_T_DATA:
        {
          if (Data_Type<Reference_T>::is_descendant(value))
          {
            return Convertible::Exact;
          }
          [[fallthrough]];
        }
        default:
        {
          return FromRubyFundamental<short>::is_convertible(value);
        }
      }
    }

    short& convert(VALUE value)
    {
      switch (rb_type(value))
      {
        case RUBY_T_DATA:
        {
          if (Data_Type<Reference_T>::is_descendant(value))
          {
            Reference_T* reference = unwrap<Reference_T>(value, Data_Type<Reference_T>::ruby_data_type(), false);
            return reference->get();
          }
          [[fallthrough]];
        }
        default:
        {
          this->reference_ = Reference<short>(value);
          return this->reference_.get();
        }
      }
    }

  private:
    Arg* arg_ = nullptr;
    Reference<short> reference_;
  };

  // ===========  unsigned short  ============
  template<>
  class From_Ruby<unsigned short>
  {
  public:
    From_Ruby() = default;

    explicit From_Ruby(Arg* arg) : arg_(arg)
    {
    }

    double is_convertible(VALUE value)
    {
      return FromRubyFundamental<unsigned short>::is_convertible(value);
    }

    unsigned short convert(VALUE value)
    {
      return FromRubyFundamental<unsigned short>::convert(value);
    }
  
  private:
    Arg* arg_ = nullptr;
  };

  template<>
  class From_Ruby<unsigned short&>
  {
  public:
    using Reference_T = Reference<unsigned short>;

    From_Ruby() = default;

    explicit From_Ruby(Arg* arg) : arg_(arg)
    {
    }

    double is_convertible(VALUE value)
    {
      switch (rb_type(value))
      {
        case RUBY_T_DATA:
        {
          if (Data_Type<Reference_T>::is_descendant(value))
          {
            return Convertible::Exact;
          }
          [[fallthrough]];
        }
        default:
        {
          return FromRubyFundamental<unsigned short>::is_convertible(value);
        }
      }
    }

    unsigned short& convert(VALUE value)
    {
      switch (rb_type(value))
      {
        case RUBY_T_DATA:
        {
          if (Data_Type<Reference_T>::is_descendant(value))
          {
            Reference_T* reference = unwrap<Reference_T>(value, Data_Type<Reference_T>::ruby_data_type(), false);
            return reference->get();
          }
          [[fallthrough]];
        }
        default:
        {
          this->reference_ = Reference<unsigned short>(value);
          return this->reference_.get();
        }
      }
    }

  private:
    Arg* arg_ = nullptr;
    Reference<unsigned short> reference_;
  };

  // ===========  std::nullptr_t  ============
  template<>
  class From_Ruby<std::nullptr_t>
  {
  public:
    From_Ruby() = default;

    explicit From_Ruby(Arg* arg) : arg_(arg)
    {
      if (this->arg_->isOwner())
      {
        throw Exception(rb_eTypeError, "Cannot transfer ownership of C++ void pointer");
      }
    }

    double is_convertible(VALUE value)
    {
      if (this->arg_ && this->arg_->isOpaque())
      {
        return Convertible::Exact;
      }

      switch (rb_type(value))
      {
        case RUBY_T_NIL:
        {
          return Convertible::Exact;
          break;
        }
        default:
        {
          return Convertible::None;
        }
      }
    }

    std::nullptr_t convert(VALUE value)
    {
      if (value == Qnil)
      {
        return nullptr;
      }

      throw Exception(rb_eTypeError, "wrong argument type %s (expected %s)",
        detail::protect(rb_obj_classname, value), "nil");
    }
  private:
    Arg* arg_ = nullptr;
  };

  // ===========  void  ============
  template<>
  class From_Ruby<void>
  {
  public:
    From_Ruby()
    {
    };

    explicit From_Ruby(Arg* arg) : arg_(arg)
    {
      if (this->arg_->isOwner())
      {
        throw Exception(rb_eTypeError, "Cannot transfer ownership of C++ void pointer");
      }
    }

    double is_convertible(VALUE value)
    {
      switch (rb_type(value))
      {
        case RUBY_T_NIL:
        {
          return Convertible::Exact;
          break;
        }
        default:
        {
          return Convertible::None;
        }
      }
    }

    void convert(VALUE)
    {
      // Nothing to do
    }
  private:
    Arg* arg_ = nullptr;
  };

  template<>
  class From_Ruby<void*>
  {
  public:
    From_Ruby()
    {
    };

    explicit From_Ruby(Arg* arg) : arg_(arg)
    {
      if (this->arg_->isOwner())
      {
        throw Exception(rb_eTypeError, "Cannot transfer ownership of C++ void pointer");
      }
    }

    double is_convertible(VALUE value)
    {
      if (this->arg_ && this->arg_->isOpaque())
      {
        return Convertible::Exact;
      }

      switch (rb_type(value))
      {
        case RUBY_T_DATA:
        {
          return Convertible::Exact;
        }
        case RUBY_T_STRING:
        {
          if (RB_ENCODING_IS_ASCII8BIT(value))
          {
            return Convertible::Exact;
          }
          else
          {
            return Convertible::None;
          }
        }
        case RUBY_T_NIL:
        {
          return Convertible::Exact;
        }
        default:
        {
          return Convertible::None;
        }
      }
    }

    void* convert(VALUE value)
    {
      if (value == Qnil)
      {
        return nullptr;
      }

      if (this->arg_ && this->arg_->isOpaque())
      {
        return (void*)value;
      }

      switch (rb_type(value))
      {
        case RUBY_T_DATA:
        {
          // Since C++ is not telling us type information, we need to extract it
          // from the Ruby object.
          const rb_data_type_t* rb_type = RTYPEDDATA_TYPE(value);

          if (Data_Type<Pointer<void>>::is_descendant(value))
          {
            return unwrap<void>(value, Data_Type<Pointer<void>>::ruby_data_type(), false);
          }
          else 
          {
            return detail::unwrap<void>(value, (rb_data_type_t*)rb_type, this->arg_ && this->arg_->isOwner());
          }

          break;
        }
        case RUBY_T_STRING:
        {
          // String must be formatted in a way the receiver understands! This likely means it was created
          // by Array.pack. Once the underlying string goes away the passed in data becomes invalid!
          return (void*)RSTRING_PTR(value);
          break;
        }
        case RUBY_T_NIL:
        {
          return nullptr;
          break;
        }
        default:
        {
          throw Exception(rb_eTypeError, "wrong argument type %s (expected %s)",
            detail::protect(rb_obj_classname, value), "pointer");
        }
      }
    }
  private:
    Arg* arg_ = nullptr;
  };
}
// =========   Reference.ipp   =========
namespace Rice
{
  template<typename T>
  inline Reference<T>::Reference() : data_{}
  {
  }

  template<typename T>
  inline Reference<T>::Reference(T& data) : data_(data)
  {
  }

  template<typename T>
  inline Reference<T>::Reference(VALUE value) : data_(detail::FromRubyFundamental<T>::convert(value))
  {
  }

  template<typename T>
  inline T& Reference<T>::get()
  {
    return data_;
  }

  // Specialization implementations - only one is compiled per platform
#if SIZEOF_LONG == SIZEOF_VOIDP
  // VALUE is unsigned long on Linux/macOS
  inline Reference<unsigned long>::Reference() : data_{}
  {
  }

  inline Reference<unsigned long>::Reference(unsigned long value, bool isValue) :
    data_(isValue ? detail::FromRubyFundamental<unsigned long>::convert(value) : value)
  {
  }

  inline unsigned long& Reference<unsigned long>::get()
  {
    return data_;
  }
#else
  // VALUE is unsigned long long on Windows x64
  inline Reference<unsigned long long>::Reference() : data_{}
  {
  }

  inline Reference<unsigned long long>::Reference(unsigned long long value, bool isValue) :
    data_(isValue ? detail::FromRubyFundamental<unsigned long long>::convert(value) : value)
  {
  }

  inline unsigned long long& Reference<unsigned long long>::get()
  {
    return data_;
  }
#endif

  template<typename T>
  inline Data_Type<Reference<T>> define_reference(std::string klassName)
  {
    using Reference_T = Reference<T>;
    using Data_Type_T = Data_Type<Reference_T>;

    if (klassName.empty())
    {
      detail::TypeDetail<Reference_T> typeDetail;
      klassName = typeDetail.rubyName();
    }

    Module rb_mRice = define_module("Rice");

    if (Data_Type_T::check_defined(klassName, rb_mRice))
    {
      return Data_Type_T();
    }

    Data_Type<Reference<T>> result = define_class_under<Reference_T>(rb_mRice, klassName).
      define_constructor(Constructor<Reference_T, T>()).
      define_method("value", &Reference_T::get);

    return result;
  }
}

namespace Rice::detail
{
  template<typename T>
  struct Type<Reference<T>>
  {
    static bool verify()
    {
      detail::verifyType<T>();
      define_reference<T>();
      return true;
    }
  };
}

// =========   Proc.hpp   =========


// Registries

// =========   TypeRegistry.ipp   =========
#include <iostream>
#include <stdexcept>
#include <sstream>
#include <typeindex>


namespace Rice::detail
{
  template <typename T>
  inline std::type_index TypeRegistry::key()
  {
    if constexpr (is_complete_v<T>)
    {
      return std::type_index(typeid(T));
    }
    else if constexpr (std::is_reference_v<T>)
    {
      // For incomplete reference types, strip the reference and use pointer.
      // Can't form T* when T is a reference type (pointer-to-reference is illegal).
      return std::type_index(typeid(std::remove_reference_t<T>*));
    }
    else
    {
      return std::type_index(typeid(T*));
    }
  }

  template <typename T>
  inline void TypeRegistry::add(VALUE klass, rb_data_type_t* rbType)
  {
    registry_[key<T>()] = std::pair(klass, rbType);
  }

  template <typename T>
  inline void TypeRegistry::remove()
  {
    registry_.erase(key<T>());
  }

  template <typename T>
  inline bool TypeRegistry::isDefined()
  {
    auto iter = registry_.find(key<T>());
    return iter != registry_.end();
  }

  template <typename T>
  std::pair<VALUE, rb_data_type_t*> TypeRegistry::getType()
  {
    auto iter = registry_.find(key<T>());
    if (iter != registry_.end())
    {
      return iter->second;
    }
    else
    {
      this->raiseUnverifiedType(TypeDetail<T>().name());
      // Make compiler happy
      return std::make_pair(Qnil, nullptr);
    }
  }

  template <typename T>
  inline bool TypeRegistry::verify()
  {
    if (isDefined<T>())
    {
      return true;
    }
    else
    {
      this->unverified_.insert(key<T>());
      return false;
    }
  }

  inline std::optional<std::pair<VALUE, rb_data_type_t*>> TypeRegistry::lookup(std::type_index typeIndex)
  {
    auto iter = registry_.find(typeIndex);

    if (iter == registry_.end())
    {
      return std::nullopt;
    }
    else
    {
      return iter->second;
    }
  }

  template <typename T>
  inline std::pair<VALUE, rb_data_type_t*> TypeRegistry::figureType(const T& object)
  {
    std::optional<std::pair<VALUE, rb_data_type_t*>> result;

    // First check and see if the actual type of the object is registered.
    // This requires a complete type for typeid to work.
    if constexpr (is_complete_v<T>)
    {
      result = lookup(std::type_index(typeid(object)));

      if (result)
      {
        return result.value();
      }
    }

    // If not, then we are willing to accept an ancestor class specified by T. This is needed
    // to support Directors. Classes inherited from Directors are never actually registered
    // with Rice - and what we really want it to return the C++ class they inherit from.
    result = lookup(key<T>());
    if (result)
    {
      return result.value();
    }

    raiseUnverifiedType(TypeDetail<T>().name());

    // Make the compiler happy
    return std::pair<VALUE, rb_data_type_t*>(Qnil, nullptr);
  }

  inline void TypeRegistry::validateTypes()
  {
    // Loop over the unverified types and delete each on that is found in the registry
    // the registry and raise an exception for the first one that is not
    for (auto iter = this->unverified_.begin(); iter != this->unverified_.end(); )
    {
      const std::type_index& typeIndex = *iter;
      bool isDefined = this->registry_.find(typeIndex) != this->registry_.end();
      if (isDefined)
      {
        iter = this->unverified_.erase(iter);
      }
      else
      {
        iter++;
      }
    }

    if (this->unverified_.empty())
    {
      return;
    }

    std::stringstream stream;
    stream << "The following types are not registered with Rice:" << "\n";

    for (const std::type_index& typeIndex : this->unverified_)
    {
      detail::TypeIndexParser typeDetail(typeIndex);
      stream << "  " << typeDetail.name() << "\n";
    }

    throw std::invalid_argument(stream.str());
  }

  inline void TypeRegistry::clearUnverifiedTypes()
  {
    this->unverified_.clear();
  }

  inline void TypeRegistry::raiseUnverifiedType(const std::string& typeName)
  {
    std::string message = "Type is not registered with Rice: " + typeName;
    throw std::invalid_argument(message);
  }

  inline VALUE TypeRegistry::klasses()
  {
    Array result;

    for (auto& pair : this->registry_)
    {
      std::pair<VALUE, rb_data_type_t*>& value = pair.second;
      Class klass = value.first;
      result.push(klass, false);
    }
    return result;
  }
}
// =========   InstanceRegistry.ipp   =========
#include <memory>

namespace Rice::detail
{
  template <typename T>
  inline VALUE InstanceRegistry::lookup(T* cppInstance, bool isOwner)
  {
    if (!this->shouldTrack(isOwner))
    {
      return Qnil;
    }

    auto it = this->objectMap_.find((void*)cppInstance);
    return it != this->objectMap_.end() ? it->second : Qnil;
  }

  template <typename T>
  inline void InstanceRegistry::add(T* cppInstance, VALUE rubyInstance, bool isOwner)
  {
    if (!this->shouldTrack(isOwner))
    {
      return;
    }

    this->objectMap_[(void*)cppInstance] = rubyInstance;
  }

  inline void InstanceRegistry::remove(void* cppInstance)
  {
    this->objectMap_.erase(cppInstance);
  }

  inline void InstanceRegistry::clear()
  {
    this->objectMap_.clear();
  }

  inline bool InstanceRegistry::shouldTrack(bool isOwner) const
  {
    switch (this->mode)
    {
      case Mode::Off:
        return false;
      case Mode::Owned:
        return isOwner;
      case Mode::All:
        return true;
      default:
        return false;
    }
  }
}

// =========   DefaultHandler.ipp   =========
namespace Rice::detail
{
  inline void Rice::detail::DefaultHandler::operator()() const
  {
    // This handler does nothing, it just rethrows the exception so it can be handled
    throw;
  }
}
// =========   HandlerRegistry.ipp   =========
namespace Rice::detail
{
  inline HandlerRegistry::HandlerRegistry() : handler_(DefaultHandler())
  {
  }

  inline void HandlerRegistry::set(std::function<void()> handler)
  {
    this->handler_ = handler;
  }

  inline std::function<void()> HandlerRegistry::handler() const
  {
    return this->handler_;
  }
}
// =========   ModuleRegistry.ipp   =========
#include <iostream>
#include <stdexcept>
#include <sstream>
#include <typeindex>


namespace Rice::detail
{
  inline void ModuleRegistry::add(VALUE module)
  {
    this->modules_.insert(module);
  }

  inline VALUE ModuleRegistry::modules()
  {
    Array result;

    for (const VALUE& value : this->modules_)
    {
      Module module(value);
      result.push(module, false);
    }
    return result;
  }
}
// =========   NativeRegistry.ipp   =========

namespace Rice::detail
{
  inline void NativeRegistry::add(VALUE klass, ID methodId, std::unique_ptr<Native>& native)
  {
    // Lookup items for method
    std::vector<std::unique_ptr<Native>>& natives = NativeRegistry::lookup(klass, methodId);

    // Add new native
    natives.push_back(std::move(native));
  }

  inline void NativeRegistry::replace(VALUE klass, ID methodId, std::unique_ptr<Native>& native)
  {
    // Lookup items for method
    std::vector<std::unique_ptr<Native>>& natives = NativeRegistry::lookup(klass, methodId);

    // Clear existing natives
    natives.clear();
    // Add new native
    natives.push_back(std::move(native));
  }

  inline void NativeRegistry::reset(VALUE klass)
  {
    for (auto iter = this->natives_.begin(); iter != this->natives_.end();)
    {
      // Iter points to a std::pair<std::pair<VALUE, ID>, std::vector<NativeRegistryItem>
      if (iter->first.first == klass)
      {
        iter = this->natives_.erase(iter);
      }
      else
      {
        ++iter;
      }
    }
  }
  
  inline std::vector<Native*> NativeRegistry::lookup(VALUE klass)
  {
    std::vector<Native*> result;

    if (rb_type(klass) == T_ICLASS)
    {
      klass = detail::protect(rb_class_of, klass);
    }

    for (auto& pair : this->natives_)
    {
      const std::pair<VALUE, ID>& key = pair.first;

      if (klass == key.first)
      {
        const std::vector<std::unique_ptr<Native>>& value = pair.second;
        for (auto& native : value)
        {
          result.push_back(native.get());
        }
      }
    }

    return result;
  }

  inline std::vector<std::unique_ptr<Native>>& NativeRegistry::lookup(VALUE klass, ID methodId)
  {
    if (rb_type(klass) == T_ICLASS)
    {
      klass = detail::protect(rb_class_of, klass);
    }

    // Create the key
    std::pair<VALUE, ID> key = std::make_pair(klass, methodId);

    // Lookup items for method
    return this->natives_[key];
  }

  inline std::vector<Native*> NativeRegistry::lookup(VALUE klass, NativeKind kind)
  {
    std::vector<Native*> result;

    if (rb_type(klass) == T_ICLASS)
    {
      klass = detail::protect(rb_class_of, klass);
    }

    for (auto& pair : this->natives_)
    {
      const std::pair<VALUE, ID>& key = pair.first;

      if (klass == key.first)
      {
        const std::vector<std::unique_ptr<Native>>& natives = pair.second;
        for (auto& native : natives)
        {
          if (native->kind() == kind)
          {
            result.push_back(native.get());
          }
        }
      }
    }

    return result;
  }
}

// =========   Registries.ipp   =========
namespace Rice::detail
{
  //Initialize static variables here.
  inline Registries Registries::instance;
}


// =========   Type.ipp   =========
// Rice saves types either as the intrinsic type (MyObject) or pointer (MyObject*).
// It strips out references, const and volatile to avoid an explosion of template classes.
// Pointers are used for C function pointers used in callbacks and for the Buffer class.
namespace Rice::detail
{
  // ------ Type ----------------
  template<typename T>
  inline bool Type<T>::verify()
  {
    return Registries::instance.types.verify<intrinsic_type<T>>();
  }

  template<typename T>
  inline bool Type<T&>::verify()
  {
    return Type<T>::verify();
  }

  template<typename T>
  inline bool Type<T&&>::verify()
  {
    return Type<T>::verify();
  }

  template<typename T>
  inline bool Type<T*>::verify()
  {
    return Type<T>::verify();
  }

  template<typename T>
  inline bool Type<T**>::verify()
  {
    return Type<T>::verify();
  }

  template <typename T, int N>
  inline bool Type<T[N]>::verify()
  {
    return Type<T>::verify();
  }
  
  template <typename T, int N>
  inline VALUE Type<T[N]>::rubyKlass()
  {
    detail::TypeDetail<Pointer<T>> typeDetail;
    return typeDetail.rubyKlass();
  }

  template<typename T>
  void verifyType()
  {
    Type<remove_cv_recursive_t<T>>::verify();
  }

  template<typename Tuple_T, size_t...Is>
  void verifyTypesImpl(std::index_sequence<Is...> indexes)
  {
    (verifyType<std::tuple_element_t<Is, Tuple_T>>(), ...);
  }

  template<typename Tuple_T>
  void verifyTypes()
  {
    std::make_index_sequence<std::tuple_size_v<Tuple_T>> indexes;
    verifyTypesImpl<Tuple_T>(indexes);
  }
}

// =========   TypeIndexParser.ipp   =========
#ifdef __GNUC__
#include <cxxabi.h>
#include <cstdlib>
#include <cstring>
#endif

namespace Rice::detail
{
  // ---------- TypeIndexParser ------------
  inline TypeIndexParser::TypeIndexParser(const std::type_index& typeIndex, bool isFundamental) :
    typeIndex_(typeIndex), isFundamental_(isFundamental)
  {
  }

  inline std::string TypeIndexParser::demangle(char const* mangled_name)
  {
#ifdef __GNUC__
    int status = 0;
    char* name = abi::__cxa_demangle(mangled_name, 0, 0, &status);
    if (name)
    {
      return name;
    }
    else
    {
      return mangled_name;
    }
#else
    return mangled_name;
#endif
  }

  inline std::string TypeIndexParser::name()
  {
    return this->demangle(this->typeIndex_.name());
  }

  // Find text inside of < > taking into account nested groups.
  //
  // Example:
  //
  //   std::vector<std::vector<int>, std::allocator<std::vector, std::allocator<int>>>
  inline std::string TypeIndexParser::findGroup(std::string& string, size_t offset)
  {
    int depth = 0;

    auto begin = string.begin() + offset;
    auto start = begin;
    for (auto iter = begin; iter != string.end(); iter++)
    {
      if (*iter == '<')
      {
        if (depth == 0)
        {
          start = iter;
        }
        depth++;
      }
      else if (*iter == '>')
      {
        depth--;
        if (depth == 0)
        {
          // Add + 1 to include current ">" character
          return string.substr(offset + (start - begin), 1 + (iter - start));
        }
        else if (depth < 0)
        {
          throw std::runtime_error("Unbalanced Group");
        }
      }
    }
    throw std::runtime_error("Unbalanced Group");
  }

  inline void TypeIndexParser::replaceAll(std::string& string, std::regex regex, std::string replacement)
  {
    std::smatch match;
    while (std::regex_search(string, match, regex))
    {
      string = std::regex_replace(string, regex, replacement);
    }
  }

  inline void TypeIndexParser::removeGroup(std::string& string, std::regex regex)
  {
    std::smatch match;
    while (std::regex_search(string, match, regex))
    {
      std::string group = findGroup(string, match.position());
      group = match.str() + group;
      string.erase(match.position(), group.length());
    }
  }

  inline void TypeIndexParser::replaceGroup(std::string& string, std::regex regex, std::string replacement)
  {
    std::smatch match;
    while (std::regex_search(string, match, regex))
    {
      std::string group = findGroup(string, match.position());
      group = match.str() + group;
      string.replace(match.position(), group.length(), replacement);
    }
  }

  inline std::string TypeIndexParser::simplifiedName()
  {
    std::string base = this->name();

    // Remove void from Buffer<T, void> - the void comes from SFINAE
    std::regex fixBuffer = std::regex("(Buffer<.*),\\s?void>");
    base = std::regex_replace(base, fixBuffer, "$1>");

    // Remove class keyword
    std::regex classRegex = std::regex("class +");
    base = std::regex_replace(base, classRegex, "");

    // Remove struct keyword
    std::regex structRegex = std::regex("struct +");
    base = std::regex_replace(base, structRegex, "");

    // Remove std::__[^:]*::
    std::regex stdClangRegex = std::regex("std::__[^:]+::");
    base = std::regex_replace(base, stdClangRegex, "std::");

    // Remove allocators
    std::regex allocatorRegex(R"(,\s*std::allocator)");
    removeGroup(base, allocatorRegex);

    // Remove char_traits
    std::regex charTraitsRegex(R"(,\s*std::char_traits)");
    removeGroup(base, charTraitsRegex);

    // Remove less (std::map)
    std::regex lessRegex(R"(,\s*std::less)");
    removeGroup(base, lessRegex);

    // Remove hash (std::unordered_map)
    std::regex hashRegex(R"(,\s*std::hash)");
    removeGroup(base, hashRegex);

    // Remove equal_to (std::unordered_map)
    std::regex equalRegex(R"(,\s*std::equal_to)");
    removeGroup(base, equalRegex);

    // Remove default_delete (std::unique_ptr)
    std::regex defaultDeleteRegex(R"(,\s*std::default_delete)");
    removeGroup(base, defaultDeleteRegex);

    // Remove spaces before pointers
    std::regex ptrRegex = std::regex(R"(\s+\*)");
    base = std::regex_replace(base, ptrRegex, "*");

    // Remove spaces before left parentheses
    std::regex parenRegex = std::regex(R"(\s+\()");
    base = std::regex_replace(base, parenRegex, "(");

    // Remove __ptr64
    std::regex ptr64Regex(R"(\s*__ptr64\s*)");
    base = std::regex_replace(base, ptr64Regex, "");

    // Remove calling conventions (__cdecl, __stdcall, __fastcall, etc.)
    std::regex callingConventionRegex(R"(\s*__cdecl|__stdcall|__fastcall)");
    base = std::regex_replace(base, callingConventionRegex, "");

    // Replace " >" with ">"
    std::regex trailingAngleBracketSpaceRegex = std::regex(R"(\s+>)");
    replaceAll(base, trailingAngleBracketSpaceRegex, ">");

    // One space after a comma (MSVC has no spaces, GCC one space)
    std::regex commaSpaceRegex = std::regex(R"(,(\S))");
    replaceAll(base, commaSpaceRegex, ", $1");

    // Fix strings
    std::regex stringRegex = std::regex(R"(basic_string<char>)");
    replaceAll(base, stringRegex, "string");

    std::regex wstringRegex = std::regex(R"(basic_string<wchar_t>)");
    replaceAll(base, wstringRegex, "wstring");

    // Normalize Anonymous namespace
    std::regex anonymousNamespaceGcc = std::regex(R"(\(anonymous namespace\))");
    replaceAll(base, anonymousNamespaceGcc, "AnonymousNamespace");
    std::regex anonymousNamespaceMsvc = std::regex(R"(`anonymous namespace')");
    replaceAll(base, anonymousNamespaceMsvc, "AnonymousNamespace");

    return base;
  }

  inline std::string TypeIndexParser::rubyName(std::string rubyTypeName)
  {
    std::string base = rubyTypeName;

    // Remove std:: these could be embedded in template types
    auto stdRegex = std::regex("std::");
    base = std::regex_replace(base, stdRegex, "");

    // Remove leading namespaces. This will not remove namespaces
    // embedded in template types like std::vector<mynamespace::foo>
    auto leadingNamespacesRegex = std::regex("^[^<]*::");
    base = std::regex_replace(base, leadingNamespacesRegex, "");

    // Capitalize first letter
    base[0] = (char)std::toupper(base[0]);

    // Replace :: with unicode U+u02F8 (Modified Letter raised colon)
    auto colonRegex = std::regex(R"(:)");
    this->replaceAll(base, colonRegex, "\uA789");

    // Replace _ and capitalize the next letter
    std::regex underscoreRegex(R"(_(\w))");
    this->capitalizeHelper(base, underscoreRegex);

    if (this->isFundamental_)
    {
      // Replace space and capitalize the next letter
      std::regex spaceRegex(R"(\s+(\w))");
      this->capitalizeHelper(base, spaceRegex);
    }
    else
    {
      // Replace spaces with unicode U+u00A0 (Non breaking Space)
      std::regex spaceRegex = std::regex(R"(\s+)");
      this->replaceAll(base, spaceRegex, "\u00A0");
    }

    // Replace < with unicode U+227A (Precedes)
    auto lessThanRegex = std::regex("<");
    //replaceAll(base, lessThanRegex, "≺");
    this->replaceAll(base, lessThanRegex, "\u227A");

    // Replace > with unicode U+227B (Succeeds)
    auto greaterThanRegex = std::regex(">");
    //replaceAll(base, greaterThanRegex, "≻");
    this->replaceAll(base, greaterThanRegex, "\u227B");

    // Replace ( with Unicode Character (U+2768) - Medium Left Parenthesis Ornament
    // This happens in std::function
    auto leftParenRegex = std::regex(R"(\()");
    this->replaceAll(base, leftParenRegex, "\u2768");

    // Replace ) with Unicode Character (U+2769) - Medium Right Parenthesis Ornament
    // This happens in std::function
    auto rightParenRegex = std::regex(R"(\))");
    this->replaceAll(base, rightParenRegex, "\u2769");

    // Replace , with Unicode Character (U+066C) - Arabic Thousands Separator
    auto commaRegex = std::regex(R"(,\s*)");
    this->replaceAll(base, commaRegex, "\u201A");

    // Replace * with Unicode Character (U+2217) -	Asterisk Operator
    auto asteriskRegex = std::regex(R"(\*)");
    this->replaceAll(base, asteriskRegex, "\u2217");

    return base;
  }

  inline void TypeIndexParser::capitalizeHelper(std::string& content, std::regex& regex)
  {
    std::smatch match;
    while (std::regex_search(content, match, regex))
    {
      std::string replacement = match[1];
      std::transform(replacement.begin(), replacement.end(), replacement.begin(),
        [](unsigned char c) -> char
        {
          return static_cast<char>(std::toupper(c));
        });
      content.replace(match.position(), match.length(), replacement);
    }
  }

  // ---------- TypeDetail<T> ------------
  template<typename T>
  inline std::type_index TypeDetail<T>::typeIndex()
  {
    if constexpr (is_complete_v<T>)
    {
      return typeid(T);
    }
    else if constexpr (std::is_reference_v<T>)
    {
      // For incomplete reference types, strip the reference and use pointer.
      // Can't use typeid(T&) because it still requires complete type on MSVC.
      return typeid(std::remove_reference_t<T>*);
    }
    else
    {
      return typeid(T*);
    }
  }

  template<typename T>
  inline bool TypeDetail<T>::isFundamental()
  {
    if constexpr (is_complete_v<T>)
    {
      return std::is_fundamental_v<intrinsic_type<T>>;
    }
    else
    {
      return false;
    }
  }

  template<typename T>
  inline std::string TypeDetail<T>::name()
  {
    return this->typeIndexParser_.name();
  }

  template<typename T>
  inline std::string TypeDetail<T>::simplifiedName()
  {
    return this->typeIndexParser_.simplifiedName();
  }

  template<typename T>
  inline std::string TypeDetail<T>::rubyTypeName()
  {
    using Intrinsic_T = detail::intrinsic_type<T>;

    if constexpr (std::is_fundamental_v<T>)
    {
      return RubyType<Intrinsic_T>::name;
    }
    else if constexpr (std::is_same_v<std::remove_cv_t<T>, char*>)
    {
      return "String";
    }
    else
    {
      TypeDetail<Intrinsic_T> typeDetail;
      return typeDetail.simplifiedName();
    }
  }

  template<typename T>
  inline std::string TypeDetail<T>::rubyName()
  {
    std::string base = this->rubyTypeName();
    return this->typeIndexParser_.rubyName(base);
  }

  template<typename T>
  inline VALUE TypeDetail<T>::rubyKlass()
  {
    using Type_T = Type<std::remove_reference_t<detail::remove_cv_recursive_t<T>>>;
    using Intrinsic_T = detail::intrinsic_type<T>;

    if constexpr (has_ruby_klass<Type_T>::value)
    {
      return Type_T::rubyKlass();
    }
    else if constexpr (std::is_fundamental_v<Intrinsic_T> && std::is_pointer_v<T>)
    {
      using Pointer_T = Pointer<std::remove_pointer_t<remove_cv_recursive_t<T>>>;
      std::pair<VALUE, rb_data_type_t*> pair = Registries::instance.types.getType<Pointer_T>();
      return pair.first;
    }
    else
    {
      std::pair<VALUE, rb_data_type_t*> pair = Registries::instance.types.getType<Intrinsic_T>();
      return pair.first;
    }
  }
}

// Code for Ruby to call C++

// =========   Exception.ipp   =========

namespace Rice
{
  inline Exception::Exception(VALUE exception) : exception_(exception)
  {
  }

  template <typename... Parameter_Ts>
  inline Exception::Exception(const Exception& other, char const* fmt, Parameter_Ts&&...args)
    : Exception(other.class_of(), fmt, std::forward<Parameter_Ts>(args)...)
  {
  }

  template <typename... Parameter_Ts>
  inline Exception::Exception(const VALUE exceptionClass, char const* fmt, Parameter_Ts&&...args)
  {
    #if defined(__GNUC__) || defined(__clang__)
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wformat-security"
    #endif

    size_t size = std::snprintf(nullptr, 0, fmt, std::forward<Parameter_Ts>(args)...);
    this->message_ = std::string(size, '\0');

    // size+1 avoids truncating the string. Otherwise snprintf writes n - 1 characters
    // to allow space for null character but we don't need that since std::string
    // will add a null character internally at n + 1
    std::snprintf(&this->message_[0], size + 1, fmt, std::forward<Parameter_Ts>(args)...);

    #if defined(__GNUC__) || defined(__clang__)
    #pragma GCC diagnostic pop
    #endif

    // Now create the Ruby exception
    VALUE exception = detail::protect(rb_exc_new2, exceptionClass, this->message_.c_str());
    this->exception_ = Pin(exception);
  }

  inline char const* Exception::what() const noexcept
  {
    if (this->message_.empty())
    {
      // This isn't protected because if it fails then either we could eat the exception
      // (not good) or crash the program (better)
      VALUE rubyMessage = rb_funcall(this->exception_.value(), rb_intern("message"), 0);
      this->message_ = std::string(RSTRING_PTR(rubyMessage), RSTRING_LEN(rubyMessage));
    }
    return this->message_.c_str();
  }

  inline VALUE Exception::class_of() const
  {
    return detail::protect(rb_class_of, this->exception_.value());
  }

  inline VALUE Exception::value() const
  {
    return this->exception_.value();
  }
}

// =========   cpp_protect.hpp   =========

#include <regex>
#include <stdexcept>

#if __has_include(<filesystem>)
  #include <filesystem>
  namespace fs = std::filesystem;
#elif __has_include(<experimental/filesystem>)
  #include <experimental/filesystem>
  namespace fs = std::experimental::filesystem;
#else
  #error "no filesystem include found :'("
#endif


namespace Rice::detail
{
  template <typename Callable_T>
  auto cpp_protect(Callable_T&& func)
  {
    VALUE excValue = Qnil;
    int jumpTag = 0;

    try
    {
      return func();
    }
    catch (...)
    {
      try
      {
        std::function<void()> handler = detail::Registries::instance.handlers.handler();
        handler();
      }
      catch (::Rice::Exception const& ex)
      {
        excValue = ex.value();
      }
      catch (::Rice::JumpException const& ex)
      {
        jumpTag = ex.tag;
      }
      catch (std::bad_alloc const& ex)
      {
        /* This won't work quite right if the rb_exc_new2 fails; not
           much we can do about that, since Ruby doesn't give us access
           to a pre-allocated NoMemoryError object */
        excValue = rb_exc_new2(rb_eNoMemError, ex.what());
      }
      catch (std::domain_error const& ex)
      {
        excValue = rb_exc_new2(rb_eFloatDomainError, ex.what());
      }
      catch (std::invalid_argument const& ex)
      {
        excValue = rb_exc_new2(rb_eArgError, ex.what());
      }
      catch (fs::filesystem_error const& ex)
      {
        excValue = rb_exc_new2(rb_eIOError, ex.what());
      }
      catch (std::length_error const& ex)
      {
        excValue = rb_exc_new2(rb_eIndexError, ex.what());
      }
      catch (std::out_of_range const& ex)
      {
        excValue = rb_exc_new2(rb_eIndexError, ex.what());
      }
      catch (std::overflow_error const& ex)
      {
        excValue = rb_exc_new2(rb_eRangeError, ex.what());
      }
      catch (std::range_error const& ex)
      {
        excValue = rb_exc_new2(rb_eRangeError, ex.what());
      }
      catch (std::regex_error const& ex)
      {
        excValue = rb_exc_new2(rb_eRegexpError, ex.what());
      }
      catch (std::system_error const& ex)
      {
        excValue = rb_exc_new2(rb_eSystemCallError, ex.what());
      }
      catch (std::underflow_error const& ex)
      {
        excValue = rb_exc_new2(rb_eRangeError, ex.what());
      }
      catch (std::exception const& ex)
      {
        excValue = rb_exc_new2(rb_eRuntimeError, ex.what());
      }
      catch (...)
      {
        excValue = rb_exc_new2(rb_eRuntimeError, "Unknown C++ exception thrown");
      }
    }
    // All C++ exception objects and the handler are now destroyed.
    // It is safe to call rb_jump_tag/rb_exc_raise which use longjmp.
    if (jumpTag)
      rb_jump_tag(jumpTag);
    else
      rb_exc_raise(excValue);

    throw std::runtime_error("Should never get here - just making compilers happy");
  }
}

// =========   Wrapper.ipp   =========
#include <memory>

namespace Rice::detail
{
  inline void WrapperBase::addKeepAlive(VALUE object, VALUE keepAlive)
  {
    WrapperBase* wrapper = getWrapper(object);
    wrapper->addKeepAlive(keepAlive);
  }

  inline bool WrapperBase::isConst(VALUE object)
  {
    WrapperBase* wrapper = getWrapper(object);
    return wrapper->isConst();
  }

  inline WrapperBase::WrapperBase(rb_data_type_t* rb_data_type) : rb_data_type_(rb_data_type)
  {
  }

  inline bool WrapperBase::isConst()
  {
    return this->isConst_;
  }

  inline void WrapperBase::ruby_mark()
  {
    for (VALUE value : this->keepAlive_)
    {
      rb_gc_mark(value);
    }
  }

  inline void WrapperBase::addKeepAlive(VALUE value)
  {
    this->keepAlive_.push_back(value);
  }

  inline const std::vector<VALUE>& WrapperBase::getKeepAlive() const
  {
    return this->keepAlive_;
  }

  inline void WrapperBase::setKeepAlive(const std::vector<VALUE>& keepAlive)
  {
    this->keepAlive_ = keepAlive;
  }

  inline void WrapperBase::setOwner(bool value)
  {
    this->isOwner_ = value;
  }

  // ----  Wrapper -----
  template <typename T>
  inline Wrapper<T>::Wrapper(rb_data_type_t* rb_data_type, T& data) : WrapperBase(rb_data_type), data_(data)
  {
    this->isConst_ = std::is_const_v<std::remove_reference_t<T>>;
  }

  template <typename T>
  inline Wrapper<T>::Wrapper(rb_data_type_t* rb_data_type, T&& data) : WrapperBase(rb_data_type), data_(std::move(data))
  {
  }

  template <typename T>
  inline void* Wrapper<T>::get(rb_data_type_t* requestedType)
  {
    if (rb_typeddata_inherited_p(this->rb_data_type_, requestedType))
    {
      return (void*)&this->data_;
    }
    else
    {
      throw Exception(rb_eTypeError, "wrong argument type %s (expected %s)",
                      this->rb_data_type_->wrap_struct_name,
                      requestedType->wrap_struct_name);
    }
  }

  // ----  Wrapper& -----
  template <typename T>
  inline Wrapper<T&>::Wrapper(rb_data_type_t* rb_data_type, T& data) : WrapperBase(rb_data_type), data_(data)
  {
    this->isConst_ = std::is_const_v<std::remove_reference_t<T>>;
  }

  template <typename T>
  inline Wrapper<T&>::~Wrapper()
  {
    Registries::instance.instances.remove(this->get(this->rb_data_type_));
  }

  template <typename T>
  inline void* Wrapper<T&>::get(rb_data_type_t* requestedType)
  {
    if (rb_typeddata_inherited_p(this->rb_data_type_, requestedType))
    {
      return (void*)&this->data_;
    }
    else
    {
      throw Exception(rb_eTypeError, "wrong argument type %s (expected %s)",
                      this->rb_data_type_->wrap_struct_name,
                      requestedType->wrap_struct_name);
    }
  }

  // ----  Wrapper* -----
  template <typename T>
  inline Wrapper<T*>::Wrapper(rb_data_type_t* rb_data_type, T* data, bool isOwner) : WrapperBase(rb_data_type), data_(data)
  {
    this->isOwner_ = isOwner;
    this->isConst_ = std::is_const_v<std::remove_pointer_t<T>>;
  }

  template <typename T>
  inline Wrapper<T*>::~Wrapper()
  {
    Registries::instance.instances.remove(this->get(this->rb_data_type_));

    if constexpr (is_complete_v<T>)
    {
      // is_abstract_v requires a complete type, so nest inside is_complete_v.
      // Deleting an abstract class through a non-virtual destructor is UB,
      // but it is safe if the destructor is virtual.
      if constexpr (std::is_destructible_v<T> && (!std::is_abstract_v<T> || std::has_virtual_destructor_v<T>))
      {
        if (this->isOwner_)
        {
          delete this->data_;
        }
      }
    }
  }

  template <typename T>
  inline void* Wrapper<T*>::get(rb_data_type_t* requestedType)
  {
    if (rb_typeddata_inherited_p(this->rb_data_type_, requestedType))
    {
      return (void*)this->data_;
    }
    else
    {
      throw Exception(rb_eTypeError, "wrong argument type %s (expected %s)",
                      this->rb_data_type_->wrap_struct_name,
                      requestedType->wrap_struct_name);
    }
  }

  // ----  Wrapper** -----
  template <typename T>
  inline Wrapper<T**>::Wrapper(rb_data_type_t* rb_data_type, T** data, bool isOwner) : WrapperBase(rb_data_type), data_(data)
  {
    this->isOwner_ = isOwner;
    this->isConst_ = std::is_const_v<std::remove_pointer_t<std::remove_pointer_t<T>>>;
  }

  template <typename T>
  inline Wrapper<T**>::~Wrapper()
  {
    Registries::instance.instances.remove(this->get(this->rb_data_type_));

    if constexpr (is_complete_v<T>)
    {
      if constexpr (std::is_destructible_v<T>)
      {
        if (this->isOwner_)
        {
          delete this->data_;
        }
      }
    }
  }

  template <typename T>
  inline void* Wrapper<T**>::get(rb_data_type_t* requestedType)
  {
    if (rb_typeddata_inherited_p(this->rb_data_type_, requestedType))
    {
      return (void*)this->data_;
    }
    else
    {
      throw Exception(rb_eTypeError, "wrong argument type %s (expected %s)",
                      this->rb_data_type_->wrap_struct_name,
                      requestedType->wrap_struct_name);
    }
  }

  // ---- Helper Functions -------
  template <typename T>
  inline VALUE wrapLvalue(VALUE klass, rb_data_type_t* rb_data_type, T& data)
  {
    WrapperBase* wrapper = new Wrapper<T>(rb_data_type, data);
    return TypedData_Wrap_Struct(klass, rb_data_type, wrapper);
  }

  template <typename T>
  inline VALUE wrapRvalue(VALUE klass, rb_data_type_t* rb_data_type, T& data)
  {
    WrapperBase* wrapper = new Wrapper<T>(rb_data_type, std::move(data));
    return TypedData_Wrap_Struct(klass, rb_data_type, wrapper);
  }

  template <typename T>
  inline VALUE wrapReference(VALUE klass, rb_data_type_t* rb_data_type, T& data, bool isOwner)
  {
    VALUE result = Registries::instance.instances.lookup(&data, isOwner);
    if (result == Qnil)
    {
      WrapperBase* wrapper = new Wrapper<T&>(rb_data_type, data);
      result = TypedData_Wrap_Struct(klass, rb_data_type, wrapper);
      Registries::instance.instances.add(&data, result, isOwner);
    }
    return result;
  }

  template <typename T>
  inline VALUE wrap(VALUE klass, rb_data_type_t* rb_data_type, T& data, bool isOwner)
  {
    // Incomplete types can't be copied/moved, just wrap as reference
    if constexpr (!is_complete_v<T>)
    {
      return wrapReference(klass, rb_data_type, data, isOwner);
    }
    // If Ruby is not the owner then wrap the reference
    else if (!isOwner)
    {
      return wrapReference(klass, rb_data_type, data, isOwner);
    }
    // std::is_copy_constructible_v<std::vector<std::unique_ptr<T>>>> returns true. Sigh.
    else if constexpr (detail::is_std_vector_v<T>)
    {
      if constexpr (std::is_copy_constructible_v<typename T::value_type>)
      {
        return wrapLvalue(klass, rb_data_type, data);
      }
      else
      {
        return wrapRvalue(klass, rb_data_type, data);
      }
    }

    // Ruby is the owner so copy data
    else if constexpr (std::is_copy_constructible_v<T>)
    {
      return wrapLvalue(klass, rb_data_type, data);
    }

    // Ruby is the owner so move data
    else if constexpr (std::is_move_constructible_v<T>)
    {
      return wrapRvalue(klass, rb_data_type, data);
    }

    else
    {
      detail::TypeDetail<T> typeDetail;
      std::string message = "Rice was directed to take ownership of a C++ object but it does not have an accessible copy or move constructor. Type: " +
        typeDetail.name();
      throw std::runtime_error(message);
    }
  };

  template <typename T>
  inline VALUE wrap(VALUE klass, rb_data_type_t* rb_data_type, T* data, bool isOwner)
  {
    VALUE result = Registries::instance.instances.lookup(data, isOwner);

    if (result != Qnil)
      return result;

    WrapperBase* wrapper = new Wrapper<T*>(rb_data_type, data, isOwner);
    result = TypedData_Wrap_Struct(klass, rb_data_type, wrapper);

    Registries::instance.instances.add(data, result, isOwner);
    return result;
  };

  template <typename T>
  inline T* unwrap(VALUE value, rb_data_type_t* rb_data_type, bool takeOwnership)
  {
    if (!RTYPEDDATA_P(value))
    {
      std::string message = "The Ruby object does not wrap a C++ object. It is actually a " +
        std::string(detail::protect(rb_obj_classname, value)) + ".";
      throw std::runtime_error(message);
    }

    if (protect(rb_obj_is_kind_of, value, rb_cProc))
    {
      std::string message = "The Ruby object is a proc or lambda and does not wrap a C++ object";
      throw std::runtime_error(message);
    }

    WrapperBase* wrapper = static_cast<WrapperBase*>(RTYPEDDATA_DATA(value));

    if (wrapper == nullptr)
    {
      std::string message = "Wrapped C++ object is nil. Did you override " +
                            std::string(detail::protect(rb_obj_classname, value)) +
                            "#initialize and forget to call super?";

      throw std::runtime_error(message);
    }

    if (takeOwnership)
    {
      wrapper->setOwner(false);
    }

    return static_cast<T*>(wrapper->get(rb_data_type));
  }
    
  template <typename Wrapper_T>
  inline Wrapper_T* getWrapper(VALUE value, rb_data_type_t* rb_data_type)
  {
    WrapperBase* wrapper = nullptr;
    TypedData_Get_Struct(value, WrapperBase, rb_data_type, wrapper);
    return dynamic_cast<Wrapper_T*>(wrapper);
  }

  inline WrapperBase* getWrapper(VALUE value)
  {
    // Turn off spurious warning on g++ 12
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Warray-bounds"
#endif

    if (!RTYPEDDATA_P(value))
    {
      throw Exception(rb_eTypeError, "wrong argument type %s (expected %s)",
                      detail::protect(rb_obj_classname, value),
                      "wrapped C++ object");
    }

    return static_cast<WrapperBase*>(RTYPEDDATA_DATA(value));
    
    #if defined(__GNUC__) || defined(__clang__)
    #pragma GCC diagnostic pop
    #endif
  }

  template <typename T>
  inline Wrapper<T*>* wrapConstructed(VALUE value, rb_data_type_t* rb_data_type, T* data, VALUE source)
  {
    using Wrapper_T = Wrapper<T*>;

    Wrapper_T* wrapper = nullptr;
    TypedData_Get_Struct(value, Wrapper_T, rb_data_type, wrapper);
    if (wrapper)
    {
      Registries::instance.instances.remove(wrapper->get(rb_data_type));
      delete wrapper;
    }

    wrapper = new Wrapper_T(rb_data_type, data, true);
    RTYPEDDATA_DATA(value) = wrapper;

    Registries::instance.instances.add(data, value, true);

    // Copy keepAlive references from the source object (used by initialize_copy
    // so that cloned containers directly protect the same Ruby objects)
    if (source != Qnil)
    {
      WrapperBase* sourceWrapper = getWrapper(source);
      wrapper->setKeepAlive(sourceWrapper->getKeepAlive());
    }

    return wrapper;
  }
}

// =========   Native.ipp   =========
namespace Rice::detail
{
  inline bool Resolved::operator<(Resolved other)
  {
    return this->score < other.score;
  }

  inline bool Resolved::operator>(Resolved other)
  {
    return this->score > other.score;
  }

  inline VALUE Native::resolve(int argc, VALUE* argv, VALUE self)
  {
    /* This method is called from Ruby and is responsible for determining the correct
       Native object (ie, NativeFunction, NativeIterator, NativeAttributeGet and
       NativeAttributeSet) that should be used to invoke the underlying C++ code.
       Most of the time there will be a single Native object registered for a C++ function,
       method, constructor, iterator or attribute. However, there can be multiple Natives
       when a C++ function/method/constructor is overloaded.

       In that case, the code iterates over each Native and calls its matches method. The matches
       method returns a Resolved object with a numeric score (0.0 to 1.0). The score is computed as:

         score = minParameterScore * parameterMatch

       where minParameterScore is the minimum score across all passed parameters (using precision-based
       scoring for numeric types), and parameterMatch applies a small penalty (0.99) for each default
       parameter used. If not enough arguments are provided and missing parameters don't have defaults,
       the method returns 0 (not viable).

       The method sorts the Natives and picks the one with the highest score. Given these two C++ functions:

       void some_method(int a);
       void some_method(int a, float b = 2.0);

       A call from ruby of some_method(1) will match both signatures, but the first one
       will be chosen because parameterMatch = 1.0 for the first overload but 0.99 for the second. */

    Native* native = nullptr;

    ID methodId;
    VALUE klass;
    if (!rb_frame_method_id_and_class(&methodId, &klass))
    {
      rb_raise(rb_eRuntimeError, "Cannot get method id and class for function");
    }

    // Execute the function but make sure to catch any C++ exceptions!
    return cpp_protect([&]()
    {
      std::map<std::string, VALUE> values = readRubyArgs(argc, argv);

      const std::vector<std::unique_ptr<Native>>& natives = Registries::instance.natives.lookup(klass, methodId);

      if (natives.size() == 1)
      {
        native = natives.front().get();
      }
      else if (natives.size() == 0)
      {
        Identifier identifier(methodId);
        rb_enc_raise(rb_utf8_encoding(), rb_eArgError, "Could not find method call for %s#%s", rb_class2name(klass), identifier.c_str());
      }
      else
      {
        Identifier identifier(methodId);

        // Loop over every native to see how well they match the Ruby parameters
        std::vector<Resolved> resolves;
        std::transform(natives.begin(), natives.end(), 
          std::back_inserter(resolves), 
          [&](const std::unique_ptr<Native>& native)
          {
            return native->matches(values);
          });

        // Now sort from best to worst
        std::sort(resolves.begin(), resolves.end(), std::greater{});

        // Get the first one
        Resolved resolved = resolves.front();

        // Was there more than one match?
        /*size_t count = std::count_if(resolves.begin(), resolves.end(),
          [&resolved](Resolved& element)
          {
            return resolved.convertible == element.convertible;
          });

        if (count > 1)
        {
          std::ostringstream message;
          message << "Could not resolve method call for %s#%s" << "\n"
                  << "  %d overloaded functions matched based on the types of Ruby parameters provided:";

          for (int i = 0; i < count; i++)
          {
            message << "\n     " << resolves[i].native->toString();
          }
          
          rb_raise(rb_eArgError, message.str().c_str(), rb_class2name(klass), identifier.c_str(), count);
        }*/

        // Did it match?
        if (resolved.score > Convertible::None)
        {
          native = resolved.native;
        }
        else
        {
          // Special case == to make the RubyMine debugger work. It calls == with a Module as
          // the other argument, thus breaking if C++ operator== is implemented.
          if (identifier.str() == "==")
          {
            return detail::protect(rb_call_super, argc, argv);
          }
          else
          {
            std::ostringstream message;
            message << "Could not resolve method call for %s#%s" << "\n"
                    << "  %d overload(s) were evaluated based on the types of Ruby parameters provided:";

            for (Resolved& resolve: resolves)
            {
              message << "\n     " << resolve.native->toString();
            }

            rb_enc_raise(rb_utf8_encoding(), rb_eArgError, message.str().c_str(), rb_class2name(klass), identifier.c_str(), natives.size());
          }
        }
      }

      // Call the C++ function
      return (*native)(values, self);
    });
  }

  inline Native::Native(std::string name) :
    name_(name)
  {
  }

  inline Native::Native(std::string name,std::unique_ptr<Return>&& returnInfo) :
    name_(name), returnInfo_(std::move(returnInfo))
  {
  }

  inline Native::Native(std::string name, std::unique_ptr<Return>&& returnInfo, std::vector<std::unique_ptr<ParameterAbstract>>&& parameters) :
    name_(name), returnInfo_(std::move(returnInfo)), parameters_(std::move(parameters))
  {
  }

  inline std::string Native::name()
  {
    return this->name_;
  }
  inline ParameterAbstract* Native::getParameterByName(std::string name)
  {
    for (std::unique_ptr<ParameterAbstract>& parameter : this->parameters_)
    {
      if (parameter->arg()->name == name)
      {
        return parameter.get();
      }
    }

    return nullptr;
  }

  inline void Native::checkKeepAlive(VALUE self, VALUE returnValue, std::vector<std::optional<VALUE>>& rubyValues)
  {
    // Check function arguments
    for (size_t i = 0; i < this->parameters_.size(); i++)
    {
      Arg* arg = parameters_[i]->arg();
      if (arg->isKeepAlive())
      {
        WrapperBase::addKeepAlive(self, rubyValues[i].value());
      }
    }

    // Check return value
    if (this->returnInfo_->isKeepAlive())
    {
      WrapperBase::addKeepAlive(returnValue, self);
    }
  }

  // -----------  Type Checking ----------------
  template<typename T, bool isBuffer>
  inline void Native::verify_type()
  {
    detail::verifyType<T>();

    if constexpr (std::is_pointer_v<T>)
    {
      using Base_T = std::remove_pointer_t<remove_cv_recursive_t<T>>;

      if constexpr (std::is_fundamental_v<Base_T> || std::is_pointer_v<Base_T> || isBuffer)
      {
        Type<Pointer<Base_T>>::verify();
      }
    }
    else if constexpr (std::is_reference_v<T>)
    {
      using Base_T = std::remove_reference_t<remove_cv_recursive_t<T>>;

      if constexpr (std::is_fundamental_v<Base_T>)
      {
        Type<Reference<Base_T>>::verify();
      }
    }
    else if constexpr (std::is_array_v<T>)
    {
      using Base_T = std::remove_extent_t<remove_cv_recursive_t<T>>;

      Type<Pointer<Base_T>>::verify();
    }
  }

  template<typename Parameter_Tuple, typename Arg_Tuple, size_t I>
  inline void Native::verify_parameter()
  {
    using Param_T = std::tuple_element_t<I, Parameter_Tuple>;
    using Arg_T = std::tuple_element_t<I, Arg_Tuple>;
    if constexpr (std::is_same_v<ArgBuffer, std::decay_t<Arg_T>>)
    {
      verify_type<Param_T, true>();
    }
    else
    {
      verify_type<Param_T, false>();
    }
  };

  template<typename Parameter_Tuple, typename Arg_Tuple, std::size_t ...Indices>
  inline void Native::create_parameters_impl(std::vector<std::unique_ptr<ParameterAbstract>>& parameters, std::index_sequence<Indices...>, std::vector<std::unique_ptr<Arg>>&& args)
  {
    // Verify parameter types
    (verify_parameter<Parameter_Tuple, Arg_Tuple, Indices>(), ...);

    // Create parameters
    (parameters.push_back(std::move(std::make_unique<
      Parameter<std::tuple_element_t<Indices, Parameter_Tuple>>>(std::move(args[Indices])))), ...);
  }

  template<typename Parameter_Tuple, typename... Arg_Ts>
  inline std::vector<std::unique_ptr<ParameterAbstract>> Native::create_parameters(Arg_Ts&& ...args)
  {
    std::vector<std::unique_ptr<ParameterAbstract>> result;

    // Extract Arg and ArgBuffer from Arg_Ts and then pad Arg to match the size of Parameter_Tuple
    using ArgsBaseTuple = tuple_filter_types_t<std::tuple<Arg_Ts...>, Arg, ArgBuffer>;

    // Diff can be less than zero so it has to be signed! This happens when define_method is called with a self
    // parameter and specifies one or more Args (usually to call Arg("self).setValue()). 
    // In that case the self parameter is considered Class_T and there are no arguments.
    constexpr long diff = (long)std::tuple_size_v<Parameter_Tuple> - (long)std::tuple_size_v<ArgsBaseTuple>;
    using ArgsTuple = tuple_pad_type_t<ArgsBaseTuple, Arg, diff < 0 ? 0 : diff>;
    
    // Now play the same game but with the tuple values instead of types
    std::vector<std::unique_ptr<Arg>> argsVector;

    // Loop over each arg with an anonymous lambda
    ([&]
      {
        using Arg_T = std::decay_t<Arg_Ts>;

        if constexpr (std::is_same_v<Arg, Arg_T> || std::is_same_v<ArgBuffer, Arg_T>)
        {
          argsVector.emplace_back(std::make_unique<Arg_T>(args));
        }
      }(), ...);

    // Fill in missing args
    for (size_t i = argsVector.size(); i < std::tuple_size_v<Parameter_Tuple>; i++)
    {
      std::string argName = "arg_" + std::to_string(i);
      argsVector.emplace_back(std::make_unique<Arg>(argName));
    }

    auto indices = std::make_index_sequence<std::tuple_size_v<Parameter_Tuple>>{};
    Native::create_parameters_impl<Parameter_Tuple, ArgsTuple>(result, indices, std::move(argsVector));
    return result;
  }

  template<typename... Arg_Ts>
  inline std::unique_ptr<Return> Native::create_return(Arg_Ts& ...args)
  {
    using Arg_Tuple = std::tuple<Arg_Ts...>;

    constexpr std::size_t index = tuple_element_index_v<Arg_Tuple, Return, ReturnBuffer>;

    std::unique_ptr<Return> result;

    if constexpr (index < std::tuple_size_v<Arg_Tuple>)
    {
      using Return_T_Local = std::decay_t<std::tuple_element_t<index, Arg_Tuple>>;
      const Return_T_Local& returnInfo = std::get<index>(std::forward_as_tuple(std::forward<Arg_Ts>(args)...));
      result = std::make_unique<Return_T_Local>(returnInfo);
    }
    else
    {
      result = std::make_unique<Return>();
    }

    return result;
  }

  inline std::map<std::string, VALUE> Native::readRubyArgs(size_t argc, const VALUE* argv)
  {
    std::map<std::string, VALUE> result;

    // Keyword handling
    if (protect(rb_keyword_given_p))
    {
      // Keywords are stored in the last element in a hash
      size_t actualArgc = argc - 1;

      // Copy over leading non-keyword arguments
      for (size_t i = 0; i < actualArgc; i++)
      {
        std::string key = "arg_" + std::to_string(i);
        result[key] = argv[i];
      }

      VALUE value = argv[actualArgc];
      Hash keywords(value);

      // Copy over keyword arguments
      for (auto pair : keywords)
      {
        result[pair.first.to_s().str()] = pair.second.value();
      }
    }
    else
    {
      // Copy over leading non-keyword arguments
      for (size_t i = 0; i < argc; i++)
      {
        std::string key = "arg_" + std::to_string(i);
        result[key] = argv[i];
      }
    }

    // If a block is given we assume it maps to the last argument
    if (protect(rb_block_given_p))
    {
      std::string key = "arg_" + std::to_string(result.size());
      result[key] = protect(rb_block_proc);
    }

    return result;
  }

  inline std::vector<std::optional<VALUE>> Native::getRubyValues(std::map<std::string, VALUE> values, bool validate)
  {
    // !!!NOTE!!! We copied the values parameter because we are going to modify it!

    // Protect against user sending too many arguments
    if (values.size() > this->parameters_.size())
    {
      std::string message = "wrong number of arguments (given " +
        std::to_string(values.size()) + ", expected " + std::to_string(this->parameters_.size()) + ")";
      throw std::invalid_argument(message);
    }

    std::vector<std::optional<VALUE>> result(this->parameters_.size());

    for (size_t i=0; i< this->parameters_.size(); i++)
    {
      std::unique_ptr<ParameterAbstract>& parameter = this->parameters_[i];
      Arg* arg = parameter->arg();

      // If using keywords arguments, then the value key will be arg->name(). If using positional 
      // arguments then they key will be "arg_<position>"
      std::string keywordKey = arg->name;
      std::string positionKey = "arg_" + std::to_string(i);

      auto iter = values.find(keywordKey);
      if (iter == values.end() && keywordKey != positionKey)
      {
        iter = values.find(positionKey);
      }

      if (iter != values.end())
      {
        result[i] = iter->second;
        // Remove the value
        values.erase(iter);
      }
      else if (arg->hasDefaultValue())
      {
        result[i] = parameter->defaultValueRuby();
      }
      else if (validate)
      {
        std::string message = "Missing argument. Name: " + arg->name + ". Index: " + std::to_string(i) + ".";
        throw std::invalid_argument(message);
      }
      else
      {
        // No point in continuing - this native is not going to match
        return result;
      }
    }

    // Check for unknown arguments
    if (validate && values.size() > 0)
    {
      // There are unknown arguments
      std::ostringstream message;
      message << "Unknown argument(s): ";
      size_t count = 0;
      for (const std::pair<const std::string, VALUE>& pair : values)
      {
        if (count > 0)
          message << ", ";
        message << pair.first;
        count++;
      }
      throw std::invalid_argument(message.str());
    }

    return result;
  }

  inline double Native::matchParameters(std::vector<std::optional<VALUE>>& values, size_t argc)
  {
    // Only score arguments actually passed (not defaults)
    double minScore = Convertible::Exact;

    for (size_t i = 0; i < argc && i < this->parameters_.size(); i++)
    {
      ParameterAbstract* parameter = this->parameters_[i].get();
      std::optional<VALUE>& value = values[i];
      double score = parameter->matches(value);
      minScore = (std::min)(minScore, score);
    }

    return minScore;
  }

  inline Resolved Native::matches(std::map<std::string, VALUE>& values)
  {
    // Return Convertible::None if Ruby provided more arguments than the C++ method takes
    if (values.size() > this->parameters_.size())
    {
      return Resolved{ Convertible::None, this };
    }

    // Get Ruby values for each parameter and see how they match
    std::vector<std::optional<VALUE>> rubyValues = this->getRubyValues(values, false);
    double minScore = this->matchParameters(rubyValues, values.size());

    // If zero score return then stop
    if (minScore == 0)
    {
      return Resolved{ Convertible::None, this };
    }

    // How many actual values do we have?
    size_t actualValuesCount = std::count_if(rubyValues.begin(), rubyValues.end(),
      [](std::optional<VALUE>& optional)
      {
        return optional.has_value();
      });

    // If we don't have enough parameters return
    if (actualValuesCount < this->parameters_.size())
      return Resolved{ Convertible::None, this };

    // Penalize use of default parameters
    double parameterMatch = Convertible::Exact;
    size_t defaultParameterCount = actualValuesCount - values.size();
    for (size_t i = 0; i < defaultParameterCount; i++)
    {
      parameterMatch *= 0.99;  // Small penalty per default used
    }

    // Final score: minScore * parameterMatch
    double finalScore = minScore * parameterMatch;

    return Resolved{ finalScore, this };
  }

  inline std::vector<const ParameterAbstract*> Native::parameters()
  {
    std::vector<const ParameterAbstract*> result;

    std::transform(this->parameters_.begin(), this->parameters_.end(), std::back_inserter(result),
      [](std::unique_ptr<ParameterAbstract>& parameter) -> ParameterAbstract*
      {
        return parameter.get();
      });
      
    return result;
  }
}

// =========   NativeAttributeGet.ipp   =========
#include <array>
#include <algorithm>

namespace Rice::detail
{
  template<typename Attribute_T>
  template<typename...Arg_Ts>
  void NativeAttributeGet<Attribute_T>::define(VALUE klass, std::string name, Attribute_T attribute, Arg_Ts&...args)
  {
    // Verify attribute type
    Native::verify_type<Attr_T, is_one_of_v<ReturnBuffer, Arg_Ts...>>();

    // Create return info
    std::unique_ptr<Return> returnInfo = Native::create_return<Arg_Ts...>(args...);

    // Create a NativeAttributeGet that Ruby will call to read/write C++ variables
    NativeAttribute_T* nativeAttribute = new NativeAttribute_T(klass, name, std::forward<Attribute_T>(attribute), std::move(returnInfo));
    std::unique_ptr<Native> native(nativeAttribute);

    detail::protect(rb_define_method, klass, name.c_str(), (RUBY_METHOD_FUNC)&Native::resolve, -1);

    // Add to native registry. Since attributes cannot be overridden, there is no need to set the
    // matches or calls function pointer. Instead Ruby can call the static call method defined on
    // this class (&NativeAttribute_T::get).
    Identifier identifier(name);
    detail::Registries::instance.natives.replace(klass, identifier.id(), native);
  }

  template<typename Attribute_T>
  inline Resolved NativeAttributeGet<Attribute_T>::matches(std::map<std::string, VALUE>& values)
  {
    if (values.size() == 0)
      return Resolved{ Convertible::Exact, this };
    else
      return Resolved{ Convertible::None, this };
  }
  
  template<typename Attribute_T>
  NativeAttributeGet<Attribute_T>::NativeAttributeGet(VALUE klass, std::string name, Attribute_T attribute, std::unique_ptr<Return>&& returnInfo)
    : Native(name, std::move(returnInfo)),
      klass_(klass), attribute_(attribute)
  {
  }

  template<typename Attribute_T>
  inline VALUE NativeAttributeGet<Attribute_T>::operator()(std::map<std::string, VALUE>&, VALUE self)
  {
    if constexpr (std::is_member_object_pointer_v<Attribute_T>)
    {
      Receiver_T* nativeSelf = From_Ruby<Receiver_T*>().convert(self);

      if constexpr (std::is_fundamental_v<detail::intrinsic_type<To_Ruby_T>>)
      {
        return To_Ruby<To_Ruby_T>(this->returnInfo_.get()).convert(nativeSelf->*attribute_);
      }
      else if constexpr (std::is_array_v<To_Ruby_T>)
      {
        return To_Ruby<To_Ruby_T>(this->returnInfo_.get()).convert(nativeSelf->*attribute_);
      }
      else if constexpr (std::is_pointer_v<To_Ruby_T>)
      {
        return To_Ruby<To_Ruby_T>(this->returnInfo_.get()).convert(nativeSelf->*attribute_);
      }
      else
      {
        // If the attribute is an object return a reference to avoid a copy (and avoid issues with
        // attributes that are not assignable, copy constructible or move constructible)
        return To_Ruby<To_Ruby_T&>(this->returnInfo_.get()).convert(nativeSelf->*attribute_);
      }
    }
    else
    {
      if constexpr (std::is_fundamental_v<detail::intrinsic_type<To_Ruby_T>>)
      {
        return To_Ruby<To_Ruby_T>(this->returnInfo_.get()).convert(*attribute_);
      }
      else if constexpr (std::is_array_v<To_Ruby_T>)
      {
        return To_Ruby<To_Ruby_T>(this->returnInfo_.get()).convert(*attribute_);
      }
      else if constexpr (std::is_pointer_v<To_Ruby_T>)
      {
        return To_Ruby<To_Ruby_T>(this->returnInfo_.get()).convert(*attribute_);
      }
      else
      {
        // If the attribute is an object return a reference to avoid a copy (and avoid issues with
        // attributes that are not assignable, copy constructible or move constructible)
        return To_Ruby<To_Ruby_T&>(this->returnInfo_.get()).convert(*attribute_);
      }
    }
  }

  template<typename Attribute_T>
  inline std::string NativeAttributeGet<Attribute_T>::toString()
  {
    return "";
  }

  template<typename Attribute_T>
  inline NativeKind NativeAttributeGet<Attribute_T>::kind()
  {
    return NativeKind::AttributeReader;
  }

  template<typename Attribute_T>
  inline VALUE NativeAttributeGet<Attribute_T>::returnKlass()
  {
    // Check if an array is being returned
    bool isBuffer = dynamic_cast<ReturnBuffer*>(this->returnInfo_.get()) ? true : false;
    if (isBuffer)
    {
      TypeDetail<Pointer<detail::remove_cv_recursive_t<std::remove_pointer_t<Attr_T>>>> typeDetail;
      return typeDetail.rubyKlass();
    }
    else
    {
      TypeDetail<Attr_T> typeDetail;
      return typeDetail.rubyKlass();
    }
  }
}
// =========   NativeAttributeSet.ipp   =========
#include <array>
#include <algorithm>


namespace Rice::detail
{
  template<typename Attribute_T>
  template<typename...Arg_Ts>
  void NativeAttributeSet<Attribute_T>::define(VALUE klass, std::string name, Attribute_T attribute, Arg_Ts&...args)
  {
    // Extract Arg from Arg_Ts if present, otherwise create default
    using Arg_Tuple = std::tuple<Arg_Ts...>;
    constexpr std::size_t index = tuple_element_index_v<Arg_Tuple, Arg, ArgBuffer>;

    std::unique_ptr<Arg> arg;
    if constexpr (index < std::tuple_size_v<Arg_Tuple>)
    {
      using Arg_T_Local = std::decay_t<std::tuple_element_t<index, Arg_Tuple>>;
      const Arg_T_Local& argInfo = std::get<index>(std::forward_as_tuple(std::forward<Arg_Ts>(args)...));
      arg = std::make_unique<Arg_T_Local>(argInfo);
    }
    else
    {
      arg = std::make_unique<Arg>("value");
    }

    // Create the parameter
    auto parameter = std::make_unique<Parameter<T_Unqualified>>(std::move(arg));

    // Create a NativeAttributeSet that Ruby will call to write C++ variables
    NativeAttribute_T* nativeAttribute = new NativeAttribute_T(klass, name, std::forward<Attribute_T>(attribute), std::move(parameter));
    std::unique_ptr<Native> native(nativeAttribute);

    // Define the write method name
    std::string setter = name + "=";

    // Tell Ruby to invoke the static method resolve to set the attribute value
    detail::protect(rb_define_method, klass, setter.c_str(), (RUBY_METHOD_FUNC)&Native::resolve, -1);

    // Add to native registry
    Identifier identifier(setter);
    detail::Registries::instance.natives.replace(klass, identifier.id(), native);
  }

  template<typename Attribute_T>
  NativeAttributeSet<Attribute_T>::NativeAttributeSet(VALUE klass, std::string name, Attribute_T attribute, std::unique_ptr<Parameter<T_Unqualified>> parameter)
    : Native(name), klass_(klass), attribute_(attribute), parameter_(std::move(parameter))
  {
  }

  template<typename Attribute_T>
  inline Resolved NativeAttributeSet<Attribute_T>::matches(std::map<std::string, VALUE>& values)
  {
    if (values.size() == 1)
      return Resolved{ Convertible::Exact, this };
    else
      return Resolved{ Convertible::None, this };
  }

  template<typename Attribute_T>
  inline VALUE NativeAttributeSet<Attribute_T>::operator()(std::map<std::string, VALUE>& values, VALUE self)
  {
    if (values.size() != 1)
    {
      throw std::runtime_error("Incorrect number of parameters for setting attribute. Attribute: " + this->name_);
    }

    // Get the Ruby value and convert to native
    VALUE value = values.begin()->second;
    std::optional<VALUE> valueOpt(value);
    T_Unqualified nativeValue = this->parameter_->convertToNative(valueOpt);

    if constexpr (!std::is_null_pointer_v<Receiver_T>)
    {
      Receiver_T* nativeSelf = From_Ruby<Receiver_T*>().convert(self);
      nativeSelf->*attribute_ = (Attr_T)nativeValue;
    }
    else
    {
      *attribute_ = nativeValue;
    }

    // Check if we need to prevent the value from being garbage collected
    if (this->parameter_->arg()->isKeepAlive())
    {
      WrapperBase::addKeepAlive(self, value);
    }

    return value;
  }

  template<typename Attribute_T>
  inline std::string NativeAttributeSet<Attribute_T>::toString()
  {
    return "";
  }

  template<typename Attribute_T>
  inline NativeKind NativeAttributeSet<Attribute_T>::kind()
  {
    return NativeKind::AttributeWriter;
  }

  template<typename Attribute_T>
  inline VALUE NativeAttributeSet<Attribute_T>::returnKlass()
  {
    TypeDetail<Attr_T> typeDetail;
    return typeDetail.rubyKlass();
  }
}

// =========   NativeFunction.hpp   =========

namespace Rice::detail
{
  //! The NativeFunction class calls C++ functions/methods/lambdas on behalf of Ruby
  /*! The NativeFunction class is an intermediate between Ruby and C++. Every method
   *  defined in Rice is associated with a NativeFuntion instance that is stored in
   *  a unordered_map maintained by the MethodData class. The key is the Ruby class
   *  and method.
   * 
   *  When Ruby calls into C++ it invokes the static NativeFunction.call method. This
   *  method then looks up the NativeFunction instance and calls its ->() operator.
   *
   *  The instance then converts each of the arguments passed from Ruby into their
   *  C++ equivalents. It then retrieves the C++ object (if there is one, Ruby could
   *  be calling a free standing method or lambda). Then it calls the C++ method
   *  and gets back the result. If there is a result (so not void), it is converted
   *  from a C++ object to a Ruby object and returned back to Ruby.
   * 
   *  This class make heavy use of C++ Template metaprogramming to determine
   *  the types and parameters a method takes. It then uses that information
   *  to perform type conversion Ruby to C++.
   *   
   *  @tparam Receiver_T - The type of C++ class wrapped by Ruby. Althought NativeFunction
   *    can derive the C++ class (Receiver_T), it can differ per member function. For example,
   *    std::map has a size() method but that is actually implemented on an ancestor class _Tree.
   *    Thus Receiver_T is std::map but Function_T::Receiver_T is _Tree. This breaks Rice in two ways. 
   *    First, _Tree is not a registered type. Second, Rice would return a _Tree instance back to
   *    C++ and not a std::map.
   *  @tparam Function_T - A template that represents the C++ function
   *    to call. This typename is automatically deduced by the compiler.
   *  @tparam IsMethod - A boolean specifying whether the function has
   *    a self parameter or not. Rice differentiates these two cases by
   *    calling them methods (self) or functions (no self).
   */

  template<typename Function_T, bool NoGVL = false>
  class NativeFunction: Native
  {
  public:
    using NativeFunction_T = NativeFunction<Function_T, NoGVL>;

    // We remove const to avoid an explosion of To_Ruby specializations and Ruby doesn't
    // have the concept of constants anyways
    using Return_T = typename function_traits<Function_T>::return_type;
    using Class_T = typename function_traits<Function_T>::class_type;
    using Parameter_Ts = typename function_traits<Function_T>::arg_types;
    using To_Ruby_T = remove_cv_recursive_t<Return_T>;

    template<typename ...Arg_Ts>
    static void define(VALUE klass, std::string function_name, Function_T function, Arg_Ts&& ...args);

  public:
    NativeFunction(VALUE klass, std::string method_name, Function_T function, std::unique_ptr<Return>&& returnInfo, std::vector<std::unique_ptr<ParameterAbstract>>&& parameters);

    VALUE operator()(std::map<std::string, VALUE>& values, VALUE self) override;
    std::string toString() override;

    NativeKind kind() override;
    VALUE returnKlass() override;

  private:
    std::vector<std::string> argTypeNames();

    // Convert Ruby values to C++ values
    template<typename std::size_t...I>
    Parameter_Ts getNativeValues(std::vector<std::optional<VALUE>>& values, std::index_sequence<I...>& indices);

    // Call the underlying C++ function
    VALUE invoke(Parameter_Ts&& nativeArgs);
    VALUE invokeNoGVL(Parameter_Ts&& nativeArgs);

  private:
    VALUE klass_;
    Function_T function_;
    To_Ruby<To_Ruby_T> toRuby_;
  };
}


// =========   NativeFunction.ipp   =========
#include <algorithm>
#include <array>
#include <stdexcept>
#include <sstream>
#include <tuple>

namespace Rice::detail
{
  template<typename Function_T, bool NoGVL>
  template<typename ...Arg_Ts>
  void NativeFunction<Function_T, NoGVL>::define(VALUE klass, std::string method_name, Function_T function, Arg_Ts&& ...args)
  {
    // Verify return type
    using Arg_Tuple = std::tuple<Arg_Ts...>;
    constexpr bool isBuffer = tuple_element_index_v<Arg_Tuple, ReturnBuffer> < std::tuple_size_v<Arg_Tuple>;
    Native::verify_type<Return_T, isBuffer>();

    // Have we defined this method yet in Ruby?
    Identifier identifier(method_name);
    const std::vector<std::unique_ptr<Native>>& natives = Registries::instance.natives.lookup(klass, identifier.id());
    if (natives.empty())
    {
      // Tell Ruby to invoke the static resolved method defined above
      detail::protect(rb_define_method, klass, method_name.c_str(), (RUBY_METHOD_FUNC)&Native::resolve, -1);
    }

    // Create function parameters - this will also validate their types
    std::vector<std::unique_ptr<ParameterAbstract>> parameters = Native::create_parameters<Parameter_Ts>(args...);

    // Create return info
    std::unique_ptr<Return> returnInfo = Native::create_return<Arg_Ts...>(args...);

    // Create native method
    NativeFunction_T* nativeFunction = new NativeFunction_T(klass, method_name, std::forward<Function_T>(function), std::move(returnInfo), std::move(parameters));
    std::unique_ptr<Native> native(nativeFunction);

    // Register the native function
    detail::Registries::instance.natives.add(klass, identifier.id(), native);
  }

  template<typename Function_T, bool NoGVL>
  NativeFunction<Function_T, NoGVL>::NativeFunction(VALUE klass, std::string function_name, Function_T function, std::unique_ptr<Return>&& returnInfo, std::vector<std::unique_ptr<ParameterAbstract>>&& parameters)
    : Native(function_name, std::move(returnInfo), std::move(parameters)),
      klass_(klass), function_(function), toRuby_(returnInfo_.get())
  {
  }

  template<typename Function_T, bool NoGVL>
  std::vector<std::string> NativeFunction<Function_T, NoGVL>::argTypeNames()
  {
    std::vector<std::string> result;
    for (std::unique_ptr<ParameterAbstract>& parameter : this->parameters_)
    {
      result.push_back(parameter->cppTypeName());
    }
    return result;
  }

  template<typename Function_T, bool NoGVL>
  std::string NativeFunction<Function_T, NoGVL>::toString()
  {
    std::ostringstream result;

    detail::TypeDetail<Return_T> typeDetail;
    result << typeDetail.simplifiedName() << " ";
    result << this->name();

    result << "(";

    std::vector<std::string> argTypeNames = this->argTypeNames();
    for (size_t i = 0; i < argTypeNames.size(); i++)
    {
      result << argTypeNames[i];
      if (i < argTypeNames.size() - 1)
        result << ", ";
    }
    result << ")";
    return result.str();
  }
    
  template<typename Function_T, bool NoGVL>
  template<std::size_t... I>
  typename NativeFunction<Function_T, NoGVL>::Parameter_Ts NativeFunction<Function_T, NoGVL>::getNativeValues(std::vector<std::optional<VALUE>>& values,
     std::index_sequence<I...>&)
  {
    /* Loop over each value returned from Ruby and convert it to the appropriate C++ type based
       on the arguments (Parameter_Ts) required by the C++ function. Arg_T may have const/volatile while
       the associated From_Ruby<T> template parameter will not. Thus From_Ruby produces non-const values 
       which we let the compiler convert to const values as needed. This works except for 
       T** -> const T**, see comment in convertToNative method. */
    //return std::forward_as_tuple(this->getNativeValue<std::tuple_element_t<I, Parameter_Ts>, I>(values)...);
    return std::forward_as_tuple(
      (dynamic_cast<Parameter<std::tuple_element_t<I, Parameter_Ts>>*>(this->parameters_[I].get()))->
               convertToNative(values[I])...);
  }

  template<typename Function_T, bool NoGVL>
  VALUE NativeFunction<Function_T, NoGVL>::invoke(Parameter_Ts&& nativeArgs)
  {
    if constexpr (std::is_void_v<Return_T>)
    {
      std::apply(this->function_, std::forward<Parameter_Ts>(nativeArgs));
      return Qnil;
    }
    else
    {
      // Call the native method and get the result
      Return_T nativeResult = std::apply(this->function_, std::forward<Parameter_Ts>(nativeArgs));

      // Return the result
      return this->toRuby_.convert(nativeResult);
    }
  }

  template<typename Function_T, bool NoGVL>
  VALUE NativeFunction<Function_T, NoGVL>::invokeNoGVL(Parameter_Ts&& nativeArgs)
  {
    if constexpr (std::is_void_v<Return_T>)
    {
      no_gvl(this->function_, std::forward<Parameter_Ts>(nativeArgs));
      return Qnil;
    }
    else
    {
      // Call the native method and get the result
      Return_T nativeResult = no_gvl(this->function_, std::forward<Parameter_Ts>(nativeArgs));

      // Return the result
      return this->toRuby_.convert(nativeResult);
    }
  }

  template<typename Function_T, bool NoGVL>
  VALUE NativeFunction<Function_T, NoGVL>::operator()(std::map<std::string, VALUE>& values, VALUE self)
  {
    // Get the ruby values and make sure we have the correct number
    std::vector<std::optional<VALUE>> rubyValues = this->getRubyValues(values, true);

    auto indices = std::make_index_sequence<std::tuple_size_v<Parameter_Ts>>{};

    // Convert the Ruby values to native values
    Parameter_Ts nativeValues = this->getNativeValues(rubyValues, indices);

    VALUE result = Qnil;

    if constexpr (NoGVL)
    {
      result = this->invokeNoGVL(std::forward<Parameter_Ts>(nativeValues));
    }
    else
    {
      result = this->invoke(std::forward<Parameter_Ts>(nativeValues));
    }

    // Check if any function arguments or return values need to have their lifetimes tied to the receiver
    this->checkKeepAlive(self, result, rubyValues);

    return result;
  }

  template<typename Function_T, bool NoGVL>
  inline NativeKind NativeFunction<Function_T, NoGVL>::kind()
  {
    return NativeKind::Function;
  }
  template<typename Function_T, bool NoGVL>
  inline VALUE NativeFunction<Function_T, NoGVL>::returnKlass()
  {
    // Check if an array is being returned
    bool isBuffer = dynamic_cast<ReturnBuffer*>(this->returnInfo_.get()) ? true : false;
    if (isBuffer)
    {
      TypeDetail<Pointer<detail::remove_cv_recursive_t<std::remove_pointer_t<Return_T>>>> typeDetail;
      return typeDetail.rubyKlass();
    }
    else
    {
      TypeDetail<Return_T> typeDetail;
      return typeDetail.rubyKlass();
    }
  }
}

// =========   NativeIterator.hpp   =========

namespace Rice::detail
{
  template<typename T, typename Iterator_Func_T>
  class NativeIterator: Native
  {
  public:
    using NativeIterator_T = NativeIterator<T, Iterator_Func_T>;
    using Iterator_T = typename function_traits<Iterator_Func_T>::return_type;
    using Value_T = typename std::iterator_traits<Iterator_T>::value_type;
    using Reference_T = typename std::iterator_traits<Iterator_T>::reference;
    using Difference_T = typename std::iterator_traits<Iterator_T>::difference_type;
    using To_Ruby_T = remove_cv_recursive_t<Reference_T>;

  public:
    // Register function with Ruby
    void static define(VALUE klass, std::string method_name, Iterator_Func_T begin, Iterator_Func_T end);

  public:
    // Disallow creating/copying/moving
    NativeIterator() = delete;
    NativeIterator(const NativeIterator_T&) = delete;
    NativeIterator(NativeIterator_T&&) = delete;
    void operator=(const NativeIterator_T&) = delete;
    void operator=(NativeIterator_T&&) = delete;

    Resolved matches(std::map<std::string, VALUE>& values) override;
    VALUE operator()(std::map<std::string, VALUE>& values, VALUE self) override;
    std::string toString() override;

    NativeKind kind() override;
    VALUE returnKlass() override;

  protected:
    NativeIterator(VALUE klass, std::string method_name, Iterator_Func_T begin, Iterator_Func_T end);

  private:
    VALUE createRubyEnumerator(VALUE self);

  private:
    VALUE klass_;
    Iterator_Func_T begin_;
    Iterator_Func_T end_;
  };
}


// =========   NativeIterator.ipp   =========
#include <iterator>
#include <functional>
#include <type_traits>

namespace Rice::detail
{
  template <typename T, typename Iterator_Func_T>
  inline void NativeIterator<T, Iterator_Func_T>::define(VALUE klass, std::string method_name, Iterator_Func_T begin, Iterator_Func_T end)
  {
    // Tell Ruby to invoke the resolveIterator static method defined in Native super class.
    detail::protect(rb_define_method, klass, method_name.c_str(), (RUBY_METHOD_FUNC)&Native::resolve, -1);

    // Create a NativeIterator instance and save it to the NativeRegistry. There may be multiple
    // NativeFunction instances for a specific method because C++ supports method overloading.
    NativeIterator_T* nativeIterator = new NativeIterator_T(klass, method_name, begin, end);
    std::unique_ptr<Native> native(nativeIterator);

    Identifier identifier(method_name);
    detail::Registries::instance.natives.add(klass, identifier.id(), native);
  }

  template <typename T, typename Iterator_Func_T>
  inline NativeIterator<T, Iterator_Func_T>::NativeIterator(VALUE klass, std::string method_name, Iterator_Func_T begin, Iterator_Func_T end) :
    Native(method_name), klass_(klass), begin_(begin), end_(end)
  {
  }

  template<typename T, typename Iterator_Func_T>
  inline Resolved NativeIterator<T, Iterator_Func_T>::matches(std::map<std::string, VALUE>&)
  {
    return Resolved{ Convertible::Exact, this };
  }

  template<typename T, typename Iterator_Func_T>
  inline VALUE NativeIterator<T, Iterator_Func_T>::createRubyEnumerator(VALUE self)
  {
    auto rb_size_function = [](VALUE recv, VALUE, VALUE eobj) -> VALUE
    {
      // Since we can't capture VALUE self from above (because then we can't send
      // this lambda to rb_enumeratorize_with_size), extract it from recv
      return cpp_protect([&]
      {
        // Get the iterator instance
        // Class is easy
        VALUE klass = protect(rb_class_of, recv);
        // Read the method_id from an attribute we added to the enumerator instance
        Identifier identifier = protect(rb_ivar_get, eobj, rb_intern("rice_method"));

        const std::vector<std::unique_ptr<Native>>& natives = detail::Registries::instance.natives.lookup(klass, identifier.id());
        NativeIterator_T* iterator = static_cast<NativeIterator_T*>(natives.back().get());

        // Get the wrapped C++ instance
        T* receiver = detail::From_Ruby<T*>().convert(recv);

        // Get the distance
        Iterator_T begin = std::invoke(iterator->begin_, *receiver);
        Iterator_T end = std::invoke(iterator->end_, *receiver);
        Difference_T distance = std::distance(begin, end);

        return detail::To_Ruby<Difference_T>().convert(distance);
      });
    };

    Identifier identifier(this->name());
    VALUE enumerator = protect(rb_enumeratorize_with_size, self, identifier.to_sym(), 0, nullptr, rb_size_function);
    
    // Hack the enumerator object by storing name_ on the enumerator object so
    // the rb_size_function above has access to it
    protect(rb_ivar_set, enumerator, rb_intern("rice_method"), identifier.id());

    return enumerator;
  }

  template<typename T, typename Iterator_Func_T>
  inline VALUE NativeIterator<T, Iterator_Func_T>::operator()(std::map<std::string, VALUE>&, VALUE self)
  {
    if (!protect(rb_block_given_p))
    {
      return createRubyEnumerator(self);
    }
    else
    {
      detail::From_Ruby<T*> fromRuby;
      T* receiver = fromRuby.convert(self);

      Iterator_T it = std::invoke(this->begin_, *receiver);
      Iterator_T end = std::invoke(this->end_, *receiver);

      detail::To_Ruby<To_Ruby_T> toRuby;
      for (; it != end; ++it)
      {
        // Use auto&& to accept both reference- and value-returning iterators.
        // - If *it is an lvalue (T&), auto&& deduces to T&, no copy made.
        // - If *it is a prvalue (T), auto&& deduces to T&&, value binds to the temporary for the scope of this loop iteration.
        // This also avoids MSVC C4239 when convert expects a non-const lvalue reference.
        auto&& value = *it;
        protect(rb_yield, toRuby.convert(value));
      }

      return self;
    }
  }

  template<typename T, typename Iterator_Func_T>
  inline std::string NativeIterator<T, Iterator_Func_T>::toString()
  {
    return "";
  }

  template<typename T, typename Iterator_Func_T>
  inline NativeKind NativeIterator<T, Iterator_Func_T>::kind()
  {
    return NativeKind::Iterator;
  }

  template<typename T, typename Iterator_Func_T>
  inline VALUE NativeIterator<T, Iterator_Func_T>::returnKlass()
  {
    // Check if an array is being returned
    bool isBuffer = dynamic_cast<ReturnBuffer*>(this->returnInfo_.get()) ? true : false;
    if (isBuffer)
    {
      TypeDetail<Pointer<detail::remove_cv_recursive_t<std::remove_pointer_t<Value_T>>>> typeDetail;
      return typeDetail.rubyKlass();
    }
    else
    {
      TypeDetail<Value_T> typeDetail;
      return typeDetail.rubyKlass();
    }
  }
}
// =========   NativeMethod.hpp   =========

namespace Rice::detail
{
  //! The NativeMethod class calls C++ functions/methods/lambdas on behalf of Ruby
  /*! The NativeMethod class is an intermediate between Ruby and C++. Every method
   *  defined in Rice is associated with a NativeFuntion instance that is stored in
   *  a unordered_map maintained by the MethodData class. The key is the Ruby class
   *  and method.
   * 
   *  When Ruby calls into C++ it invokes the static NativeMethod.call method. This
   *  method then looks up the NativeMethod instance and calls its ->() operator.
   *
   *  The instance then converts each of the arguments passed from Ruby into their
   *  C++ equivalents. It then retrieves the C++ object (if there is one, Ruby could
   *  be calling a free standing method or lambda). Then it calls the C++ method
   *  and gets back the result. If there is a result (so not void), it is converted
   *  from a C++ object to a Ruby object and returned back to Ruby.
   * 
   *  This class make heavy use of C++ Template metaprogramming to determine
   *  the types and parameters a method takes. It then uses that information
   *  to perform type conversion Ruby to C++.
   *   
   *  @tparam Receiver_T - The type of C++ class wrapped by Ruby. Althought NativeMethod
   *    can derive the C++ class (Receiver_T), it can differ per member function. For example,
   *    std::map has a size() method but that is actually implemented on an ancestor class _Tree.
   *    Thus Receiver_T is std::map but Method_T::Receiver_T is _Tree. This breaks Rice in two ways. 
   *    First, _Tree is not a registered type. Second, Rice would return a _Tree instance back to
   *    C++ and not a std::map.
   *  @tparam Method_T - A template that represents the C++ function
   *    to call. This typename is automatically deduced by the compiler.
   *  @tparam IsMethod - A boolean specifying whether the function has
   *    a self parameter or not. Rice differentiates these two cases by
   *    calling them methods (self) or functions (no self).
   */

  template<typename Class_T, typename Method_T, bool NoGVL>
  class NativeMethod: Native
  {
  public:
    using NativeMethod_T = NativeMethod<Class_T, Method_T, NoGVL>;

    // We remove const to avoid an explosion of To_Ruby specializations and Ruby doesn't
    // have the concept of constants anyways
    using Return_T = typename method_traits<Method_T>::Return_T;
    using Receiver_T = typename method_traits<Method_T>::Class_T;
    using Parameter_Ts = typename method_traits<Method_T>::Parameter_Ts;
    using Apply_Args_T = typename tuple_unshift<Receiver_T, Parameter_Ts>::type;

    using To_Ruby_T = remove_cv_recursive_t<Return_T>;

    // Register method with Ruby
    template <typename ...Arg_Ts>
    static void define(VALUE klass, std::string method_name, Method_T method, Arg_Ts&& ...args);

  public:
    NativeMethod(VALUE klass, std::string method_name, Method_T method, std::unique_ptr<Return>&& returnInfo, std::vector<std::unique_ptr<ParameterAbstract>>&& parameters);

    VALUE operator()(std::map<std::string, VALUE>& values, VALUE self) override;
    std::string toString() override;

    NativeKind kind() override;
    VALUE returnKlass() override;

  private:
    std::vector<std::string> argTypeNames();

    // Convert Ruby values to C++ values
    template<typename std::size_t...I>
    Apply_Args_T getNativeValues(VALUE self, std::vector<std::optional<VALUE>>& values, const std::index_sequence<I...>& indices);

    // Figure out what self is
    Receiver_T getReceiver(VALUE self);

    // Call the underlying C++ method
    VALUE invoke(VALUE self, Apply_Args_T&& nativeArgs);
    VALUE invokeNoGVL(VALUE self, Apply_Args_T&& nativeArgs);

  private:
    VALUE klass_;
    Method_T method_;
    To_Ruby<To_Ruby_T> toRuby_;
  };
}


// =========   NativeMethod.ipp   =========
#include <algorithm>
#include <array>
#include <stdexcept>
#include <sstream>
#include <tuple>

namespace Rice::detail
{
  template<typename Class_T, typename Method_T, bool NoGVL>
  template<typename ...Arg_Ts>
  void NativeMethod<Class_T, Method_T, NoGVL>::define(VALUE klass, std::string method_name, Method_T method, Arg_Ts&& ...args)
  {
    // Verify return type
    using Arg_Tuple = std::tuple<Arg_Ts...>;
    constexpr bool isBuffer = tuple_element_index_v<Arg_Tuple, ReturnBuffer> < std::tuple_size_v<Arg_Tuple>;
    Native::verify_type<Return_T, isBuffer>();

    // Have we defined this method yet in Ruby?
    Identifier identifier(method_name);
    const std::vector<std::unique_ptr<Native>>& natives = Registries::instance.natives.lookup(klass, identifier.id());
    if (natives.empty())
    {
      // Tell Ruby to invoke the static resolved method defined above
      detail::protect(rb_define_method, klass, method_name.c_str(), (RUBY_METHOD_FUNC)&Native::resolve, -1);
    }

    // Create method parameters - this will also validate their types
    std::vector<std::unique_ptr<ParameterAbstract>> parameters = Native::create_parameters<Parameter_Ts>(args...);

    // Create return info
    std::unique_ptr<Return> returnInfo = Native::create_return<Arg_Ts...>(args...);
    
    // Create native method
    NativeMethod_T* nativeMethod = new NativeMethod_T(klass, method_name, std::forward<Method_T>(method), std::move(returnInfo), std::move(parameters));
    std::unique_ptr<Native> native(nativeMethod);

    // Register the native method
    detail::Registries::instance.natives.add(klass, identifier.id(), native);
  }

  template<typename Class_T, typename Method_T, bool NoGVL>
  NativeMethod<Class_T, Method_T, NoGVL>::NativeMethod(VALUE klass, std::string method_name, Method_T method, std::unique_ptr<Return>&& returnInfo, std::vector<std::unique_ptr<ParameterAbstract>>&& parameters)
    : Native(method_name, std::move(returnInfo), std::move(parameters)),
      klass_(klass), method_(method), toRuby_(returnInfo_.get())
  {
  }

  template<typename Class_T, typename Method_T, bool NoGVL>
  std::vector<std::string> NativeMethod<Class_T, Method_T, NoGVL>::argTypeNames()
  {
    std::vector<std::string> result;
    for (std::unique_ptr<ParameterAbstract>& parameter : this->parameters_)
    {
      result.push_back(parameter->cppTypeName());
    }
    return result;
  }

  template<typename Class_T, typename Method_T, bool NoGVL>
  std::string NativeMethod<Class_T, Method_T, NoGVL>::toString()
  {
    std::ostringstream result;

    detail::TypeDetail<Return_T> typeDetailReturn;
    result << typeDetailReturn.simplifiedName() << " ";

    if (!std::is_null_pointer_v<Receiver_T>)
    {
      detail::TypeDetail<Receiver_T> typeDetailReceiver;
      result << typeDetailReceiver.simplifiedName() << "::";
    }
    
    result << this->name();

    result << "(";

    std::vector<std::string> argTypeNames = this->argTypeNames();
    for (size_t i = 0; i < argTypeNames.size(); i++)
    {
      result << argTypeNames[i];
      if (i < argTypeNames.size() - 1)
        result << ", ";
    }
    result << ")";
    return result.str();
  }
    
  template<typename Class_T, typename Method_T, bool NoGVL>
  template<std::size_t... I>
  typename NativeMethod<Class_T, Method_T, NoGVL>::Apply_Args_T NativeMethod<Class_T, Method_T, NoGVL>::getNativeValues(VALUE self, std::vector<std::optional<VALUE>>& values, const std::index_sequence<I...>&)
  {
    /* Loop over each value returned from Ruby and convert it to the appropriate C++ type based
       on the arguments (Parameter_Ts) required by the C++ method. Arg_T may have const/volatile while
       the associated From_Ruby<T> template parameter will not. Thus From_Ruby produces non-const values 
       which we let the compiler convert to const values as needed. This works except for 
       T** -> const T**, see comment in convertToNative method. */
    return std::forward_as_tuple(this->getReceiver(self),
      (dynamic_cast<Parameter<std::tuple_element_t<I, Parameter_Ts>>*>(this->parameters_[I].get()))->
               convertToNative(values[I])...);
  }

  template<typename Class_T, typename Method_T, bool NoGVL>
  typename NativeMethod<Class_T, Method_T, NoGVL>::Receiver_T NativeMethod<Class_T, Method_T, NoGVL>::getReceiver(VALUE self)
  {
    // Self parameter is a Ruby VALUE so no conversion is needed
    if constexpr (std::is_same_v<Receiver_T, VALUE>)
    {
      return self;
    }
    else
    {
      /* When a class wrapped by Rice calls a method defined on an ancestor class
         (e.g., std::map calling a method from _Tree), we need to unwrap as Class_T
         and dynamic_cast to the base class. Otherwise unwrap directly as Receiver_T. */
      constexpr bool isDerived = !std::is_same_v<intrinsic_type<Receiver_T>, Class_T> &&
                                  std::is_base_of_v<intrinsic_type<Receiver_T>, Class_T>;

      if constexpr (isDerived)
      {
        if constexpr (std::is_pointer_v<Receiver_T>)
        {
          Class_T* instance = From_Ruby<Class_T*>().convert(self);
          return dynamic_cast<Receiver_T>(instance);
        }
        else if constexpr (std::is_reference_v<Receiver_T>)
        {
          Class_T& instance = From_Ruby<Class_T&>().convert(self);
          return dynamic_cast<Receiver_T>(instance);
        }
      }
      else
      {
        // Note GCC has a false warning: function may return address of local variable [-Wreturn-local-addr].
        // From_Ruby returns a reference to data in the Ruby object, not the temporary.
        return From_Ruby<Receiver_T>().convert(self);
      }
    }
  }

  template<typename Class_T, typename Method_T, bool NoGVL>
  inline VALUE NativeMethod<Class_T, Method_T, NoGVL>::invoke(VALUE self, Apply_Args_T&& nativeArgs)
  {
    if constexpr (std::is_void_v<Return_T>)
    {
      std::apply(this->method_, std::forward<Apply_Args_T>(nativeArgs));
      return Qnil;
    }
    else
    {
      Return_T nativeResult = std::apply(this->method_, std::forward<Apply_Args_T>(nativeArgs));

      // Special handling if the method returns self. If so we do not want
      // to create a new Ruby wrapper object and instead return self.
      if constexpr (std::is_same_v<intrinsic_type<Return_T>, intrinsic_type<Receiver_T>>)
      {
				Receiver_T receiver = std::get<0>(nativeArgs);

        if constexpr (std::is_pointer_v<Return_T> && std::is_pointer_v<Receiver_T>)
        {
          if (nativeResult == receiver)
            return self;
        }
        else if constexpr (std::is_pointer_v<Return_T> && std::is_reference_v<Receiver_T>)
        {
          if (nativeResult == &receiver)
            return self;
        }
        else if constexpr (std::is_reference_v<Return_T> && std::is_pointer_v<Receiver_T>)
        {
          if (&nativeResult == receiver)
            return self;
        }
        else if constexpr (std::is_reference_v<Return_T> && std::is_reference_v<Receiver_T>)
        {
          if (&nativeResult == &receiver)
            return self;
        }
      }

      return this->toRuby_.convert(nativeResult);
    }
  }

  template<typename Class_T, typename Method_T, bool NoGVL>
  inline VALUE NativeMethod<Class_T, Method_T, NoGVL>::invokeNoGVL(VALUE self, Apply_Args_T&& nativeArgs)
  {
    if constexpr (std::is_void_v<Return_T>)
    {
      no_gvl(this->method_, std::forward<Apply_Args_T>(nativeArgs));
      return Qnil;
    }
    else
    {
      Return_T nativeResult = no_gvl(this->method_, std::forward<Apply_Args_T>(nativeArgs));

      // Special handling if the method returns self. If so we do not want
      // to create a new Ruby wrapper object and instead return self.
      if constexpr (std::is_same_v<intrinsic_type<Return_T>, intrinsic_type<Receiver_T>>)
      {
        Receiver_T receiver = std::get<0>(nativeArgs);

        if constexpr (std::is_pointer_v<Return_T> && std::is_pointer_v<Receiver_T>)
        {
          if (nativeResult == receiver)
            return self;
        }
        else if constexpr (std::is_pointer_v<Return_T> && std::is_reference_v<Receiver_T>)
        {
          if (nativeResult == &receiver)
            return self;
        }
        else if constexpr (std::is_reference_v<Return_T> && std::is_pointer_v<Receiver_T>)
        {
          if (&nativeResult == receiver)
            return self;
        }
        else if constexpr (std::is_reference_v<Return_T> && std::is_reference_v<Receiver_T>)
        {
          if (&nativeResult == &receiver)
            return self;
        }
      }

      return this->toRuby_.convert(nativeResult);
    }
  }

  template<typename Class_T, typename Method_T, bool NoGVL>
  VALUE NativeMethod<Class_T, Method_T, NoGVL>::operator()(std::map<std::string, VALUE>& values, VALUE self)
  {
    // Get the ruby values and make sure we have the correct number
    std::vector<std::optional<VALUE>> rubyValues = this->getRubyValues(values, true);
    auto indices = std::make_index_sequence<std::tuple_size_v<Parameter_Ts>>{};
    Apply_Args_T nativeArgs = this->getNativeValues(self, rubyValues, indices);

    VALUE result = Qnil;

    if constexpr (NoGVL)
    {
      result = this->invokeNoGVL(self, std::forward<Apply_Args_T>(nativeArgs));
    }
    else
    {
      result = this->invoke(self, std::forward<Apply_Args_T>(nativeArgs));
    }

    // Check if any method arguments or return values need to have their lifetimes tied to the receiver
    this->checkKeepAlive(self, result, rubyValues);

    return result;
  }

  template<typename Class_T, typename Method_T, bool NoGVL>
  inline NativeKind NativeMethod<Class_T, Method_T, NoGVL>::kind()
  {
    return NativeKind::Method;
  }

  template<typename Class_T, typename Method_T, bool NoGVL>
  inline VALUE NativeMethod<Class_T, Method_T, NoGVL>::returnKlass()
  {
    // Check if an array is being returned
    bool isBuffer = dynamic_cast<ReturnBuffer*>(this->returnInfo_.get()) ? true : false;
    if (isBuffer)
    {
      TypeDetail<Pointer<detail::remove_cv_recursive_t<std::remove_pointer_t<Return_T>>>> typeDetail;
      return typeDetail.rubyKlass();
    }
    else
    {
      TypeDetail<Return_T> typeDetail;
      return typeDetail.rubyKlass();
    }
  }
}

// =========   NativeProc.hpp   =========

namespace Rice::detail
{
  template<typename Proc_T>
  class NativeProc: Native
  {
  public:
    using NativeProc_T = NativeProc<Proc_T>;

    // We remove const to avoid an explosion of To_Ruby specializations and Ruby doesn't
    // have the concept of constants anyways
    using Return_T = typename function_traits<Proc_T>::return_type;
    using Parameter_Ts = typename function_traits<Proc_T>::arg_types;
    using To_Ruby_T = remove_cv_recursive_t<Return_T>;

    // Define a new Ruby Proc to wrap a C++ function
    static VALUE createRubyProc(Proc_T proc);
    static NativeProc<Proc_T>* define(Proc_T proc);

    // This is the method Ruby calls when invoking the proc
    static VALUE resolve(VALUE yielded_arg, VALUE callback_arg, int argc, const VALUE* argv, VALUE blockarg);
 
  public:
    NativeProc(Proc_T proc, std::unique_ptr<Return>&& returnInfo, std::vector<std::unique_ptr<ParameterAbstract>>&& parameters);
    VALUE operator()(std::map<std::string, VALUE>& values, VALUE self) override;
    std::string toString() override;
    
    NativeKind kind() override;
    VALUE returnKlass() override;

  private:
    static VALUE finalizerCallback(VALUE yielded_arg, VALUE callback_arg, int argc, const VALUE* argv, VALUE blockarg);

    // Convert Ruby values to C++ values
    template<typename std::size_t...I>
    Parameter_Ts getNativeValues(std::vector<std::optional<VALUE>>& values, std::index_sequence<I...>& indices);

    // Call the underlying C++ function
    VALUE invoke(Parameter_Ts&& nativeArgs);

  private:
    Proc_T proc_;
    To_Ruby<To_Ruby_T> toRuby_;
  };
}


// =========   NativeProc.ipp   =========
#include <algorithm>
#include <array>
#include <stdexcept>
#include <sstream>
#include <tuple>

namespace Rice::detail
{
  template<typename Proc_T>
  NativeProc<Proc_T>* NativeProc<Proc_T>::define(Proc_T proc)
  {
    // Create proc parameters
    std::vector<std::unique_ptr<ParameterAbstract>> parameters = Native::create_parameters<Parameter_Ts>();

    // Create return info
    std::unique_ptr<Return> returnInfo = std::make_unique<Return>();

    return new NativeProc_T(std::forward<Proc_T>(proc), std::move(returnInfo), std::move(parameters));
  }

  template<typename Proc_T>
  VALUE NativeProc<Proc_T>::createRubyProc(Proc_T proc)
  {
    NativeProc_T* nativeProc = NativeProc_T::define(std::forward<Proc_T>(proc));

    // Create a Ruby proc to wrap it and pass the NativeProc as a callback parameter
    VALUE result = rb_proc_new(NativeProc_T::resolve, (VALUE)nativeProc);

    // Tie the lifetime of the NativeProc to the Ruby Proc
    VALUE finalizer = rb_proc_new(NativeProc_T::finalizerCallback, (VALUE)nativeProc);
    rb_define_finalizer(result, finalizer);

    return result;
  }

  // Ruby calls this method when invoking a proc that was defined as a C++ function
  template<typename Proc_T>
  VALUE NativeProc<Proc_T>::resolve(VALUE, VALUE callback_arg, int argc, const VALUE* argv, VALUE)
  {
    return cpp_protect([&]
    {
      std::map<std::string, VALUE> values = readRubyArgs(argc, argv);
      NativeProc_T * native = (NativeProc_T*)callback_arg;
      return (*native)(values, Qnil);
    });
  }

  // Ruby calls this method if an instance of a NativeProc is owned by a Ruby proc. That happens when C++
  // returns a function back to Ruby
  template<typename Proc_T>
  VALUE NativeProc<Proc_T>::finalizerCallback(VALUE, VALUE callback_arg, int, const VALUE*, VALUE)
  {
    NativeProc_T* native = (NativeProc_T*)callback_arg;
    delete native;
    return Qnil;
  }

  template<typename Proc_T>
  NativeProc<Proc_T>::NativeProc(Proc_T proc, std::unique_ptr<Return>&& returnInfo, std::vector<std::unique_ptr<ParameterAbstract>>&& parameters)
    : Native("proc", std::move(returnInfo), std::move(parameters)),
      proc_(proc), toRuby_(returnInfo_.get())
  {
  }

  template<typename Proc_T>
  std::string NativeProc<Proc_T>::toString()
  {
    return "Proc";
  }

  template<typename Proc_T>
  template<std::size_t... I>
  typename NativeProc<Proc_T>::Parameter_Ts NativeProc<Proc_T>::getNativeValues(std::vector<std::optional<VALUE>>& values,
     std::index_sequence<I...>&)
  {
    /* Loop over each value returned from Ruby and convert it to the appropriate C++ type based
       on the arguments (Parameter_Ts) required by the C++ function. Arg_T may have const/volatile while
       the associated From_Ruby<T> template parameter will not. Thus From_Ruby produces non-const values 
       which we let the compiler convert to const values as needed. This works except for 
       T** -> const T**, see comment in convertToNative method. */
    //return std::forward_as_tuple(this->getNativeValue<std::tuple_element_t<I, Parameter_Ts>, I>(values)...);
    return std::forward_as_tuple(
      (dynamic_cast<Parameter<std::tuple_element_t<I, Parameter_Ts>>*>(this->parameters_[I].get()))->
               convertToNative(values[I])...);
  }

  template<typename Proc_T>
  VALUE NativeProc<Proc_T>::invoke(Parameter_Ts&& nativeArgs)
  {
    if constexpr (std::is_void_v<Return_T>)
    {
      std::apply(this->proc_, std::forward<Parameter_Ts>(nativeArgs));
      return Qnil;
    }
    else
    {
      // Call the native method and get the result
      Return_T nativeResult = std::apply(this->proc_, std::forward<Parameter_Ts>(nativeArgs));

      // Return the result
      return this->toRuby_.convert(std::forward<Return_T>(nativeResult));
    }
  }

  template<typename Proc_T>
  VALUE NativeProc<Proc_T>::operator()(std::map<std::string, VALUE>& values, VALUE)
  {
    // Get the ruby values and make sure we have the correct number
    std::vector<std::optional<VALUE>> rubyValues = this->getRubyValues(values, true);

    auto indices = std::make_index_sequence<std::tuple_size_v<Parameter_Ts>>{};

    // Convert the Ruby values to native values
    Parameter_Ts nativeValues = this->getNativeValues(rubyValues, indices);

    // Now call the native method
    VALUE result = this->invoke(std::forward<Parameter_Ts>(nativeValues));

    return result;
  }

  template<typename Proc_T>
  inline NativeKind NativeProc< Proc_T>::kind()
  {
    return NativeKind::Proc;
  }

  template<typename Proc_T>
  inline VALUE NativeProc<Proc_T>::returnKlass()
  {
    // Check if an array is being returned
    bool isBuffer = dynamic_cast<ReturnBuffer*>(this->returnInfo_.get()) ? true : false;
    if (isBuffer)
    {
      TypeDetail<Pointer<detail::remove_cv_recursive_t<std::remove_pointer_t<Return_T>>>> typeDetail;
      return typeDetail.rubyKlass();
    }
    else
    {
      TypeDetail<Return_T> typeDetail;
      return typeDetail.rubyKlass();
    }
  }
}
// =========   NativeCallback.hpp   =========

#ifdef HAVE_LIBFFI
#include <ffi.h>
#endif //HAVE_LIBFFI

namespace Rice::detail
{
  template<typename Callback_T>
  class NativeCallback;

  // NativeCallback instances are never freed because there is no way for us to know
  // when they can be freed. At the same time, the Pin prevents the Ruby proc from being
  // garbage collected, which is necessary because C code may call the callback
  // at any time. This supports passing blocks to C callbacks without requiring the Ruby
  // user to manually hold a reference to a proc.
  template<typename Return_T, typename ...Parameter_Ts>
  class NativeCallback<Return_T(*)(Parameter_Ts...)> : public Native
  {
  public:
    using Callback_T = Return_T(*)(Parameter_Ts...);
    using NativeCallback_T = NativeCallback<Callback_T>;
    using Tuple_T = std::tuple<Parameter_Ts...>;

    template<typename ...Arg_Ts>
    static void define(Arg_Ts&& ...args);

    static Return_T invoke(Parameter_Ts...args);
  public:
    NativeCallback(VALUE proc);
    ~NativeCallback();
    NativeCallback(const NativeCallback&) = delete;
    NativeCallback(NativeCallback&&) = delete;
    void operator=(const NativeCallback&) = delete;
    void operator=(NativeCallback&&) = delete;

    Callback_T callback();
  private:
    template<typename Parameter_T>
    static Parameter_T extractArg(void* arg);

    template<std::size_t... I>
    static Tuple_T convertArgsToTuple(void* args[], std::index_sequence<I...>& indices);
    Callback_T callback_ = nullptr;

    template<std::size_t... I>
    static void copyParametersImpl(std::vector<std::unique_ptr<ParameterAbstract>>& result, std::index_sequence<I...> indices);
    static std::vector<std::unique_ptr<ParameterAbstract>> copyParameters();
    static std::unique_ptr<Return> copyReturnInfo();

    static inline std::vector<std::unique_ptr<ParameterAbstract>> parameters_;
    static inline std::unique_ptr<Return> returnInfo_;
    static inline NativeCallback_T* native_;

  private:
    VALUE operator()(std::map<std::string, VALUE>& values, VALUE self) override;
    std::string toString() override;
    NativeKind kind() override;
    VALUE returnKlass() override;

    template<std::size_t... I>
    Return_T callRuby(std::index_sequence<I...>& indices, Parameter_Ts...args);

    Pin proc_;
    From_Ruby<Return_T> fromRuby_;

#ifdef HAVE_LIBFFI
    template <typename Arg_T>
    static ffi_type* ffiType();

    static void invokeFFI(ffi_cif* cif, void* ret, void* args[], void* instance);

    static inline std::array<ffi_type*, sizeof...(Parameter_Ts)> args_ = { ffiType<Parameter_Ts>()... };
    static inline ffi_cif cif_;
    ffi_closure* closure_ = nullptr;
#endif //HAVE_LIBFFI
  };
}

// =========   NativeCallback.ipp   =========
namespace Rice::detail
{
#ifdef HAVE_LIBFFI
  template<typename Return_T, typename ...Parameter_Ts>
  template<typename Arg_T>
  ffi_type* NativeCallback<Return_T(*)(Parameter_Ts...)>::ffiType()
  {
    std::map<std::type_index, ffi_type*> nativeToFfiMapping = { 
      {std::type_index(typeid(bool)),               &ffi_type_uint8},
      {std::type_index(typeid(bool)),               &ffi_type_uint8},
      {std::type_index(typeid(char)),               &ffi_type_schar},
      {std::type_index(typeid(unsigned char)),      &ffi_type_uchar},
      {std::type_index(typeid(signed char)),        &ffi_type_schar},
      {std::type_index(typeid(uint8_t)),            &ffi_type_uint8},
      {std::type_index(typeid(unsigned short)),     &ffi_type_uint8},
      {std::type_index(typeid(int8_t)),             &ffi_type_sint8},
      {std::type_index(typeid(short)),              &ffi_type_sint8},
      {std::type_index(typeid(uint16_t)),           &ffi_type_uint16},
      {std::type_index(typeid(int16_t)),            &ffi_type_sint16},
      {std::type_index(typeid(uint32_t)),           &ffi_type_uint32},
      {std::type_index(typeid(unsigned int)),       &ffi_type_uint32},
      {std::type_index(typeid(signed int)),         &ffi_type_uint32},
      {std::type_index(typeid(int32_t)),            &ffi_type_sint32},
      {std::type_index(typeid(uint64_t)),           &ffi_type_uint64},
      {std::type_index(typeid(unsigned long long)), &ffi_type_uint64},
      {std::type_index(typeid(int64_t)),            &ffi_type_sint64},
      {std::type_index(typeid(signed long long)),   &ffi_type_sint64},
      {std::type_index(typeid(float)),              &ffi_type_float},
      {std::type_index(typeid(double)),             &ffi_type_double},
      {std::type_index(typeid(void)),               &ffi_type_pointer},
      {std::type_index(typeid(long double)),        &ffi_type_longdouble}
    };

    if (sizeof(long) == 32)
    {
      nativeToFfiMapping[std::type_index(typeid(unsigned long))] = &ffi_type_uint32;
      nativeToFfiMapping[std::type_index(typeid(long))] = &ffi_type_sint32;
    }
    else if (sizeof(long) == 64)
    {
      nativeToFfiMapping[std::type_index(typeid(unsigned long))] = &ffi_type_uint64;
      nativeToFfiMapping[std::type_index(typeid(long))] = &ffi_type_sint64;
    }
    
    if constexpr (std::is_pointer_v<Arg_T> || std::is_reference_v<Arg_T>)
    {
      return &ffi_type_pointer;
    }
    else
    {
      const std::type_index& key = std::type_index(typeid(Arg_T));
      return nativeToFfiMapping[key];
    }
  }

  // This is the function provided to the C++ callback with FFI
  template<typename Return_T, typename ...Parameter_Ts>
  void NativeCallback<Return_T(*)(Parameter_Ts...)>::invokeFFI(ffi_cif*, void* ret, void* args[], void* instance)
  {
    NativeCallback_T* self = (NativeCallback_T*)instance;

    // Define a helper lambda to invoke callRuby with unpacked args
    auto indices = std::make_index_sequence<sizeof...(Parameter_Ts)>{};
    auto helper = [&](auto&&... args)
    {
      if constexpr (!std::is_void_v<Return_T>)
      {
        *(Return_T*)ret = self->callRuby(indices, std::forward<Parameter_Ts>(args)...);
      }
      else
      {
        self->callRuby(indices, std::forward<Parameter_Ts>(args)...);
      }
    };

    // Convert the C style array to a tuple
    Tuple_T argsTuple = convertArgsToTuple(args, indices);

    // Now use std::apply to unpack the tuple and call the lamba helper
    std::apply(helper, std::forward<Tuple_T>(argsTuple));
  }
#endif //HAVE_LIBFFI

  // This is the function provided to the C++ callback without FFI
  template<typename Return_T, typename ...Parameter_Ts>
  inline Return_T NativeCallback<Return_T(*)(Parameter_Ts...)>::invoke(Parameter_Ts...args)
  {
    auto indices = std::make_index_sequence<sizeof...(Parameter_Ts)>{};

    if constexpr (std::is_void_v<Return_T>)
    {
      NativeCallback::native_->callRuby(indices, args...);
    }
    else
    {
      return NativeCallback::native_->callRuby(indices, args...);
    }
  }

  template<typename Return_T, typename ...Parameter_Ts>
  std::vector<std::unique_ptr<ParameterAbstract>> NativeCallback<Return_T(*)(Parameter_Ts...)>::copyParameters()
  {
    std::vector<std::unique_ptr<ParameterAbstract>> result;

    if (sizeof...(Parameter_Ts) > 0 && parameters_.empty())
    {
      NativeCallback_T::define();
    }

    if (parameters_.size() > 0)
    {
      auto indices = std::make_index_sequence<sizeof...(Parameter_Ts)>{};
      copyParametersImpl(result, indices);
    }
    return result;
  }

  template<typename Return_T, typename ...Parameter_Ts>
  template<std::size_t... I>
  void NativeCallback<Return_T(*)(Parameter_Ts...)>::copyParametersImpl(std::vector<std::unique_ptr<ParameterAbstract>>& result, std::index_sequence<I...>)
  {
    (result.push_back(std::make_unique<Parameter<Parameter_Ts>>(*(Parameter<Parameter_Ts>*)parameters_[I].get())), ...);
  }

  template<typename Return_T, typename ...Parameter_Ts>
  std::unique_ptr<Return> NativeCallback<Return_T(*)(Parameter_Ts...)>::copyReturnInfo()
  {
    if (!returnInfo_)
    {
      NativeCallback_T::define();
    }

    return std::make_unique<Return>(*returnInfo_);
  }

  template<typename Return_T, typename ...Parameter_Ts>
  template<typename Parameter_T>
  Parameter_T NativeCallback<Return_T(*)(Parameter_Ts...)>::extractArg(void* arg)
  {
    if constexpr (std::is_reference_v<Parameter_T>)
    {
      // We told libffi to pass references as pointers, so arg points to the pointer
      return static_cast<Parameter_T>(**reinterpret_cast<std::remove_reference_t<Parameter_T>**>(arg));
    }
    else
    {
      return *reinterpret_cast<Parameter_T*>(arg);
    }
  }

  template<typename Return_T, typename ...Parameter_Ts>
  template<std::size_t... I>
  typename NativeCallback<Return_T(*)(Parameter_Ts...)>::Tuple_T NativeCallback<Return_T(*)(Parameter_Ts...)>::convertArgsToTuple(void* args[], std::index_sequence<I...>&)
  {
    /* Loop over each value returned from Ruby and convert it to the appropriate C++ type based
       on the arguments (Parameter_Ts) required by the C++ function. Arg_T may have const/volatile while
       the associated From_Ruby<T> template parameter will not. Thus From_Ruby produces non-const values
       which we let the compiler convert to const values as needed. This works except for
       T** -> const T**, see comment in convertToNative method. */
    return std::forward_as_tuple(extractArg<Parameter_Ts>(args[I])...);
  }

  template<typename Return_T, typename...Parameter_Ts>
  template<typename ...Arg_Ts>
  inline void NativeCallback<Return_T(*)(Parameter_Ts...)>::define(Arg_Ts&& ...args)
  {
    // Create parameters and save them in static member so we can use them later when constructing an instance
    using Parameter_Tuple = std::tuple<Parameter_Ts...>;
    NativeCallback_T::parameters_ = Native::create_parameters<Parameter_Tuple>(std::forward<Arg_Ts>(args)...);

    // Create Return and save it in static member so we can use them later when constructing an instance
    NativeCallback_T::returnInfo_ = Native::create_return<Arg_Ts...>(args...);
  }

  template<typename Return_T, typename ...Parameter_Ts>
  NativeCallback<Return_T(*)(Parameter_Ts...)>::NativeCallback(VALUE proc) :
    Native("callback", copyReturnInfo(), copyParameters()),
      proc_(proc), fromRuby_(returnInfo_.get())
  {
#ifdef HAVE_LIBFFI
    // First setup description of callback
    if (cif_.bytes == 0)
    {
      ffi_prep_cif(&cif_, FFI_DEFAULT_ABI, sizeof...(Parameter_Ts), ffiType<Return_T>(), args_.data());
    }

    // Now allocate memory
    this->closure_ = (ffi_closure *)ffi_closure_alloc(sizeof(ffi_closure) + sizeof(void*), (void**)(&this->callback_));
    // Now create the closure which will create a C++ callback
    ffi_prep_closure_loc(this->closure_, &cif_, invokeFFI, (void*)this, (void*)this->callback_);
#else
    NativeCallback_T::callback_ = &NativeCallback_T::invoke;
    NativeCallback_T::native_ = this;
#endif
  }

  template<typename Return_T, typename ...Parameter_Ts>
  NativeCallback<Return_T(*)(Parameter_Ts...)>::~NativeCallback()
  {
#ifdef HAVE_LIBFFI
    ffi_closure_free(this->closure_);
#endif

    NativeCallback_T::callback_ = nullptr;
    NativeCallback_T::native_ = nullptr;
  }

  template<typename Return_T, typename ...Parameter_Ts>
  typename NativeCallback<Return_T(*)(Parameter_Ts...)>::Callback_T NativeCallback<Return_T(*)(Parameter_Ts...)>::callback()
  {
    return this->callback_;
  }

  template<typename Return_T, typename ...Parameter_Ts>
  template<std::size_t... I>
  Return_T NativeCallback<Return_T(*)(Parameter_Ts...)>::callRuby(std::index_sequence<I...>&, Parameter_Ts...args)
  {
    // Convert the C++ arguments to Ruby VALUEs
    std::array<VALUE, sizeof...(Parameter_Ts)> values = {
      dynamic_cast<Parameter<Parameter_Ts>*>(this->parameters_[I].get())->
               convertToRuby(args)... };

    static Identifier id("call");
    VALUE result = detail::protect(rb_funcallv, this->proc_.value(), id.id(), (int)sizeof...(Parameter_Ts), values.data());
    if constexpr (!std::is_void_v<Return_T>)
    {
      return this->fromRuby_.convert(result);
    }
  }

  template<typename Return_T, typename ...Parameter_Ts>
  inline VALUE NativeCallback<Return_T(*)(Parameter_Ts...)>::operator()(std::map<std::string, VALUE>&, VALUE)
  {
    return Qnil;
  }

  template<typename Return_T, typename ...Parameter_Ts>
  inline std::string NativeCallback<Return_T(*)(Parameter_Ts...)>::toString()
  {
    return "";
  }

  //NativeKind kind() override;
  template<typename Return_T, typename ...Parameter_Ts>
  inline NativeKind NativeCallback<Return_T(*)(Parameter_Ts...)>::kind()
  {
    return NativeKind::Callback;
  }

  template<typename Return_T, typename ...Parameter_Ts>
  inline VALUE NativeCallback<Return_T(*)(Parameter_Ts...)>::returnKlass()
  {
    // Check if an array is being returned
    bool isBuffer = dynamic_cast<ReturnBuffer*>(this->returnInfo_.get()) ? true : false;
    if (isBuffer)
    {
      TypeDetail<Pointer<detail::remove_cv_recursive_t<std::remove_pointer_t<Return_T>>>> typeDetail;
      return typeDetail.rubyKlass();
    }
    else
    {
      TypeDetail<Return_T> typeDetail;
      return typeDetail.rubyKlass();
    }
  }
}

// =========   Proc.ipp   =========
namespace Rice::detail
{
  template<typename Return_T, typename ...Parameter_Ts>
  struct Type<Return_T(*)(Parameter_Ts...)>
  {
    static bool verify()
    {
      return true;
    }

    static VALUE rubyKlass()
    {
      return rb_cProc;
    }
  };

  // Wraps a C++ function as a Ruby proc
  template<typename Return_T, typename ...Parameter_Ts>
  class To_Ruby<Return_T(*)(Parameter_Ts...)>
  {
  public:
    using Proc_T = Return_T(*)(Parameter_Ts...);

    To_Ruby() = default;

    explicit To_Ruby(Arg*)
    {
    }

    VALUE convert(Proc_T proc)
    {
      // Wrap the C+++ function pointer as a Ruby Proc
      return NativeProc<Proc_T>::createRubyProc(std::forward<Proc_T>(proc));
    }
  };

  // Makes a Ruby proc callable as C callback
  template<typename Return_T, typename ...Parameter_Ts>
  class From_Ruby<Return_T(*)(Parameter_Ts...)>
  {
  public:
    using Callback_T = Return_T(*)(Parameter_Ts...);

    From_Ruby() = default;

    explicit From_Ruby(Arg* arg) : arg_(arg)
    {
    }

    double is_convertible(VALUE value)
    {
      if (protect(rb_obj_is_proc, value) == Qtrue)
      {
        return Convertible::Exact;
      }
      else
      {
        return Convertible::None;
      }
    }

    Callback_T convert(VALUE value)
    {
      using NativeCallback_T = NativeCallback<Callback_T>;
      NativeCallback_T* callback = new NativeCallback_T(value);
      return callback->callback();
    }

  private:
    Arg* arg_ = nullptr;
  };
}

// C++ API definitions

// =========   Encoding.ipp   =========
namespace Rice
{
  inline Encoding Encoding::utf8()
  {
    return Encoding(rb_utf8_encoding());
  }

  inline Encoding::Encoding(rb_encoding* encoding) : encoding_(encoding)
  {
  }
}

/*namespace Rice::detail
{
  template<>
  struct Type<Encoding>
  {
    static bool verify()
    {
      return true;
    }
  };
  
  template<>
  class To_Ruby<Encoding>
  {
  public:
    VALUE convert(const Encoding& encoding)
    {
    //  return x.value();
    }
  };

  template<>
  class From_Ruby<Encoding>
  {
  public:
    Convertible is_convertible(VALUE value)
    {
      switch (rb_type(value))
      {
        case RUBY_T_SYMBOL:
          return Convertible::Exact;
          break;
      case RUBY_T_STRING:
          return Convertible::Cast;
          break;
        default:
          return Convertible::None;
        }
    }

    Encoding convert(VALUE value)
    {
     // return Symbol(value);
    }
  };
}
*/
// =========   Object.ipp   =========
namespace Rice
{
  inline Object::Object() : value_(Qnil)
  {
  }

  inline Object::Object(VALUE value) : value_(value)
  {
  }

  inline VALUE Object::value() const
  {
    return this->value_.value();
  }

  inline Object::operator VALUE() const
  {
    return this->value();
  }

  inline VALUE Object::validated_value() const
  {
    VALUE result = this->value();

    if (result == Qnil)
    {
      std::string message = "Rice Object does not wrap a Ruby object";
      throw std::runtime_error(message.c_str());
    }

    return result;
  }

  inline Object::operator bool() const
  {
    return RTEST(this->value());
  }

  inline bool Object::is_nil() const
  {
    return NIL_P(this->value());
  }

  template<typename ...Parameter_Ts>
  inline Object Object::call(Identifier id, Parameter_Ts... args) const
  {
    /* IMPORTANT - We store VALUEs in an array that is a local variable.
       That allows the Ruby garbage collector to find them when scanning
       the stack and thus mark them. If instead we use a vector, then Ruby's GC
       can't find the VALUEs and may garbage collect them before they are sent
       to the destination method resulting in a segmentation fault. This is
       easy to duplicate by setting GC.stress to true and calling a constructor
       that takes multiple values like a std::pair wrapper. */
    std::array<VALUE, sizeof...(Parameter_Ts)> values = { detail::To_Ruby<detail::remove_cv_recursive_t<Parameter_Ts>>().convert(std::forward<Parameter_Ts>(args))... };
    return detail::protect(rb_funcallv, this->validated_value(), id.id(), (int)values.size(), (const VALUE*)values.data());
  }

  template<typename ...Parameter_Ts>
  inline Object Object::call_kw(Identifier id, Parameter_Ts... args) const
  {
    /* IMPORTANT - See call() above */
    std::array<VALUE, sizeof...(Parameter_Ts)> values = { detail::To_Ruby<detail::remove_cv_recursive_t<Parameter_Ts>>().convert(args)... };
    return detail::protect(rb_funcallv_kw, this->validated_value(), id.id(), (int)values.size(), (const VALUE*)values.data(), RB_PASS_KEYWORDS);
  }

  template<typename T>
  inline void Object::iv_set(Identifier name, T const& value)
  {
    detail::protect(rb_ivar_set, this->validated_value(), name.id(), detail::To_Ruby<T>().convert(value));
  }

  inline int Object::compare(Object const& other) const
  {
    Object result = call("<=>", other);
    return detail::From_Ruby<int>().convert(result);
  }

  inline bool Object::is_equal(const Object& other) const
  {
    if (this->is_nil() || other.is_nil())
    {
      return this->is_nil() && other.is_nil();
    }

    VALUE result = detail::protect(rb_equal, this->validated_value(), other.validated_value());
    return RB_TEST(result);
  }

  inline bool Object::is_eql(const Object& other) const
  {
    if (this->is_nil() || other.is_nil())
    {
      return this->is_nil() && other.is_nil();
    }

    VALUE result = detail::protect(rb_eql, this->validated_value(), other.validated_value());
    return RB_TEST(result);
  }

  inline void Object::freeze()
  {
    detail::protect(rb_obj_freeze, this->validated_value());
  }

  inline bool Object::is_frozen() const
  {
    return RB_OBJ_FROZEN(this->validated_value());
  }

  inline int Object::rb_type() const
  {
    return ::rb_type(this->validated_value());
  }

  inline VALUE Object::object_id() const
  {
    return detail::protect(rb_obj_id, this->validated_value());
  }

  inline bool Object::is_a(Object klass) const
  {
    VALUE result = detail::protect(rb_obj_is_kind_of, this->validated_value(), klass.validated_value());
    return RB_TEST(result);
  }

  inline void Object::extend(Module const& mod)
  {
    detail::protect(rb_extend_object, this->validated_value(), mod.validated_value());
  }

  inline bool Object::respond_to(Identifier id) const
  {
    return bool(rb_respond_to(this->validated_value(), id.id()));
  }

  inline bool Object::is_instance_of(Object klass) const
  {
    VALUE result = detail::protect(rb_obj_is_instance_of, this->validated_value(), klass.validated_value());
    return RB_TEST(result);
  }

  inline Object Object::iv_get(Identifier name) const
  {
    return detail::protect(rb_ivar_get, this->validated_value(), name.id());
  }

  inline Object Object::attr_get(Identifier name) const
  {
    return detail::protect(rb_attr_get, this->validated_value(), name.id());
  }

  inline void Object::set_value(VALUE value)
  {
    this->value_ = Pin(value);
  }

  inline Object Object::const_get(Identifier name) const
  {
    return detail::protect(rb_const_get, this->validated_value(), name.id());
  }

  inline bool Object::const_defined(Identifier name) const
  {
    size_t result = detail::protect(rb_const_defined, this->validated_value(), name.id());
    return bool(result);
  }

  inline Object Object::const_set(Identifier name, Object value)
  {
    // We will allow setting constants to Qnil, or the decimal value of 4. This happens
    // in C++ libraries with enums. Thus use value() instead of validated_value
    detail::protect(rb_const_set, this->validated_value(), name.id(), value.value());
    return value;
  }

  inline Object Object::const_set_maybe(Identifier name, Object value)
  {
    if (!this->const_defined(name))
    {
      this->const_set(name, value);
    }
    return value;
  }

  inline void Object::remove_const(Identifier name)
  {
    detail::protect(rb_mod_remove_const, this->validated_value(), name.to_sym());
  }

  inline bool operator==(Object const& lhs, Object const& rhs)
  {
    return lhs.is_equal(rhs);
  }

  inline bool operator!=(Object const& lhs, Object const& rhs)
  {
    return !(lhs == rhs);
  }

  inline bool operator<(Object const& lhs, Object const& rhs)
  {
    Object result = lhs.call("<", rhs);
    return result;
  }

  inline bool operator>(Object const& lhs, Object const& rhs)
  {
    Object result = lhs.call(">", rhs);
    return result;
  }
}

namespace Rice::detail
{
  template<>
  struct Type<Object>
  {
    static bool verify()
    {
      return true;
    }

    static VALUE rubyKlass()
    {
      return rb_cObject;
    }
  };

  template<>
  class To_Ruby<Object>
  {
  public:
    To_Ruby() = default;

    explicit To_Ruby(Arg* arg) : arg_(arg)
    {
    }

    VALUE convert(Object const& x)
    {
      return x.value();
    }

  private:
    Arg* arg_ = nullptr;
  };

  template<>
  class To_Ruby<Object&>
  {
  public:
    To_Ruby() = default;

    explicit To_Ruby(Arg* arg) : arg_(arg)
    {
    }

    VALUE convert(Object const& x)
    {
      return x.value();
    }

  private:
    Arg* arg_ = nullptr;
  };

  template<>
  class From_Ruby<Object>
  {
  public:
    From_Ruby() = default;

    explicit From_Ruby(Arg* arg) : arg_(arg)
    {
    }

    double is_convertible(VALUE value)
    {
      switch (rb_type(value))
      {
        case RUBY_T_OBJECT:
          return Convertible::Exact;
          break;
        default:
          return Convertible::None;
      }
    }

    Object convert(VALUE value)
    {
      return Object(value);
    }

  private:
    Arg* arg_ = nullptr;
  };
}

// =========   String.ipp   =========
namespace Rice
{
  inline String::String() : Object(detail::protect(rb_str_new2, ""))
  {
  }

  inline String::String(VALUE v) : Object(v)
  {
    detail::protect(rb_check_type, this->value(), T_STRING);
  }

  inline String::String(Object v) : Object(v)
  {
    detail::protect(rb_check_type, this->value(), T_STRING);
  }

  inline String::String(char const* s) : Object(detail::protect(rb_utf8_str_new_cstr, s))
  {
  }

  inline String::String(std::string const& s) : Object(detail::protect(rb_utf8_str_new, s.data(), (long)s.length()))
  {
  }

  inline String::String(std::string_view const& s) : Object(detail::protect(rb_utf8_str_new, s.data(), (long)s.length()))
  {
  }

  inline String::String(Identifier id) : Object(detail::protect(rb_utf8_str_new_cstr, id.c_str()))
  {
  }

  template <typename... Parameter_Ts>
  inline String String::format(char const* fmt, Parameter_Ts&&...args)
  {
    size_t size = std::snprintf(nullptr, 0, fmt, std::forward<Parameter_Ts>(args)...);
    std::string temp(size, '\0');

    // size+1 avoids truncating the string. Otherwise snprintf writes n - 1 characters
    // to allow space for null character but we don't need that since std::string
    // will add a null character internally at n + 1
    std::snprintf(&temp[0], size + 1, fmt, std::forward<Parameter_Ts>(args)...);

    String s = String(temp.c_str());
    return s;
  }

  inline size_t String::length() const
  {
    return RSTRING_LEN(this->value());
  }

  inline char String::operator[](ptrdiff_t index) const
  {
    return RSTRING_PTR(this->value())[index];
  }

  inline char const* String::c_str() const
  {
    return RSTRING_PTR(this->value());
  }

  inline std::string String::str() const
  {
    return std::string(RSTRING_PTR(this->value()), length());
  }

  template<typename T>
  inline Array String::unpack() const
  {
    return this->call("unpack", detail::RubyType<detail::remove_cv_recursive_t<T>>::packTemplate.c_str());
  }

  inline Identifier String::intern() const
  {
    return rb_intern(c_str());
  }
}

namespace Rice::detail
{
  template<>
  struct Type<String>
  {
    static bool verify()
    {
      return true;
    }

    static VALUE rubyKlass()
    {
      return rb_cString;
    }
  };
  
  template<>
  class To_Ruby<String>
  {
  public:
    To_Ruby() = default;

    explicit To_Ruby(Arg* arg) : arg_(arg)
    {
    }

    VALUE convert(String const& x)
    {
      return x.value();
    }

  private:
    Arg* arg_ = nullptr;
  };

  template<>
  class From_Ruby<String>
  {
  public:
    From_Ruby() = default;

    explicit From_Ruby(Arg* arg) : arg_(arg)
    {
    }

    double is_convertible(VALUE value)
    {
      switch (rb_type(value))
      {
        case RUBY_T_STRING:
          return Convertible::Exact;
          break;
        default:
          return Convertible::None;
      }
    }

    String convert(VALUE value)
    {
      return String(value);
    }

  private:
    Arg* arg_ = nullptr;
  };
}

// =========   Array.ipp   =========

namespace Rice
{
  inline Array::Array() : Object(detail::protect(rb_ary_new))
  {
  }

  inline Array::Array(long capacity) : Object(detail::protect(rb_ary_new_capa, capacity))
  {
  }

  inline Array::Array(Object v) : Object(v)
  {
    detail::protect(rb_check_type, this->value(), T_ARRAY);
  }

  inline Array::Array(VALUE v) : Object(v)
  {
    detail::protect(rb_check_type, this->value(), T_ARRAY);
  }

  template<typename Iter_T>
  inline Array::Array(Iter_T it, Iter_T end) : Object(detail::protect(rb_ary_new))
  {
    for (; it != end; ++it)
    {
      push(*it, false);
    }
  }

  template<typename T, long n>
  inline Array::Array(T (&a)[n]) : Object(detail::protect(rb_ary_new))
  {
    for (long j = 0; j < n; ++j)
    {
      push(a[j], false);
    }
  }

  inline long Array::size() const
  {
    return RARRAY_LEN(this->value());
  }

  inline String Array::join(const char* separator)
  {
    return this->call("join", separator);
  }

  template<typename T>
  String Array::pack()
  {
    // Use .c_str so that the stl.hpp header is not required
    return this->call("pack", detail::RubyType<T>::packTemplate.c_str());
  }

  inline Object Array::operator[](long index) const
  {
    return detail::protect(rb_ary_entry, value(), position_of(index));
  }

  inline Array::Proxy Array::operator[](long index)
  {
    return Proxy(*this, position_of(index));
  }

  template<typename T>
  inline Object Array::push(T&& obj, bool takeOwnership)
  {
    Return returnInfo;
    if (takeOwnership)
    {
      returnInfo.takeOwnership();
    }

    detail::To_Ruby<detail::remove_cv_recursive_t<T>> toRuby(&returnInfo);
    return detail::protect(rb_ary_push, value(), toRuby.convert(std::forward<T>(obj)));
  }

  inline Object Array::pop()
  {
    return detail::protect(rb_ary_pop, value());
  }

  template<typename T>
  inline Object Array::unshift(T const& obj)
  {
    return detail::protect(rb_ary_unshift, value(), detail::To_Ruby<T>().convert(obj));
  }

  inline Object Array::shift()
  {
    return detail::protect(rb_ary_shift, value());
  }

  inline long Array::position_of(long index) const
  {
    if (index < 0)
    {
      return size() + index;
    }
    else
    {
      return static_cast<long>(index);
    }
  }

  template<typename T>
  std::vector<T> Array::to_vector()
  {
    std::vector<T> result;

    long size = this->size();
    result.reserve(size);

    detail::From_Ruby<T> fromRuby;
    for (long i = 0; i < size; i++)
    {
      VALUE element = detail::protect(rb_ary_entry, this->value(), i);
      result.push_back(fromRuby.convert(element));
    }

    return result;
  }

  inline Array::Proxy::Proxy(Array array, long index)
    : array_(array)
    , index_(index)
  {
  }

  inline VALUE Array::Proxy::value() const
  {
    return detail::protect(rb_ary_entry, array_.value(), index_);
  }

  inline Array::Proxy::operator VALUE() const
  {
    return this->value();
  }

  template<typename T>
  Object Array::Proxy::operator=(T const& value)
  {
    Object o = detail::To_Ruby<T>().convert(value);
    detail::protect(rb_ary_store, array_.value(), index_, o.value());
    return o;
  }

  template<typename Array_Ptr_T, typename Value_T>
  inline Array::Iterator<Array_Ptr_T, Value_T>::Iterator(Array_Ptr_T array, long index) :
    array_(array), index_(index)
  {
  }

  template<typename Array_Ptr_T, typename Value_T>
  template<typename Array_Ptr_T_, typename Value_T_>
  inline
    Array::Iterator<Array_Ptr_T, Value_T>::Iterator(Iterator<Array_Ptr_T_, Value_T_> const& rhs) :
      array_(rhs.array()) , index_(rhs.index()), tmp_()
  {
  }

  template<typename Array_Ptr_T, typename Value_T>
  template<typename Array_Ptr_T_, typename Value_T_>
  inline Array::Iterator<Array_Ptr_T, Value_T>& Array::Iterator<Array_Ptr_T, Value_T>::operator=(Iterator<Array_Ptr_T_, Value_T_> const& rhs)
  {
    array_ = rhs.array_;
    index_ = rhs.index_;
    return *this;
  }

  template<typename Array_Ptr_T, typename Value_T>
  inline Array::Iterator<Array_Ptr_T, Value_T>& Array::Iterator<Array_Ptr_T, Value_T>::operator++()
  {
    ++index_;
    return *this;
  }

  template<typename Array_Ptr_T, typename Value_T>
  inline Array::Iterator<Array_Ptr_T, Value_T> Array::Iterator<Array_Ptr_T, Value_T>::operator++(int)
  {
    Array copy(*this);
    ++(*this);
    return *this;
  }

  template<typename Array_Ptr_T, typename Value_T>
  inline Value_T Array::Iterator<Array_Ptr_T, Value_T>::operator*() const
  {
    return (*array_)[index_];
  }

  template<typename Array_Ptr_T, typename Value_T>
  inline Object* Array::Iterator<Array_Ptr_T, Value_T>::operator->()
  {
    tmp_ = Object((*array_)[index_]);
    return &tmp_;
  }

  template<typename Array_Ptr_T, typename Value_T>
  template<typename Array_Ptr_T_, typename Value_T_>
  inline bool Array::Iterator<Array_Ptr_T, Value_T>::operator==(Iterator<Array_Ptr_T_, Value_T_> const& rhs) const
  {
    return array_->value() == rhs.array_->value() && index_ == rhs.index_;
  }

  template<typename Array_Ptr_T, typename Value_T>
  template<typename Array_Ptr_T_, typename Value_T_>
  inline bool Array::Iterator<Array_Ptr_T, Value_T>::operator!=(Iterator<Array_Ptr_T_, Value_T_> const& rhs) const
  {
    return !(*this == rhs);
  }

  template<typename Array_Ptr_T, typename Value_T>
  template<typename Array_Ptr_T_, typename Value_T_>
  inline bool Array::Iterator<Array_Ptr_T, Value_T>::operator<(Iterator<Array_Ptr_T_, Value_T_> const& rhs) const
  {
    return index_ < rhs.index_;
  }

  template<typename Array_Ptr_T, typename Value_T>
  template<typename Array_Ptr_T_, typename Value_T_>
  inline bool Array::Iterator<Array_Ptr_T, Value_T>::operator>(Iterator<Array_Ptr_T_, Value_T_> const& rhs) const
  {
    return index_ > rhs.index_;
  }

  template<typename Array_Ptr_T, typename Value_T>
  template<typename Array_Ptr_T_, typename Value_T_>
  inline bool Array::Iterator<Array_Ptr_T, Value_T>::operator<=(Iterator<Array_Ptr_T_, Value_T_> const& rhs) const
  {
    return index_ <= rhs.index_;
  }

  template<typename Array_Ptr_T, typename Value_T>
  template<typename Array_Ptr_T_, typename Value_T_>
  inline bool Array::Iterator<Array_Ptr_T, Value_T>::operator>=(Iterator<Array_Ptr_T_, Value_T_> const& rhs) const
  {
    return index_ >= rhs.index_;
  }

  // Bidirectional iterator operations
  template<typename Array_Ptr_T, typename Value_T>
  inline Array::Iterator<Array_Ptr_T, Value_T>& Array::Iterator<Array_Ptr_T, Value_T>::operator--()
  {
    --index_;
    return *this;
  }

  template<typename Array_Ptr_T, typename Value_T>
  inline Array::Iterator<Array_Ptr_T, Value_T> Array::Iterator<Array_Ptr_T, Value_T>::operator--(int)
  {
    Iterator copy(*this);
    --(*this);
    return copy;
  }

  // Random access iterator operations
  template<typename Array_Ptr_T, typename Value_T>
  inline Array::Iterator<Array_Ptr_T, Value_T>& Array::Iterator<Array_Ptr_T, Value_T>::operator+=(difference_type n)
  {
    index_ += n;
    return *this;
  }

  template<typename Array_Ptr_T, typename Value_T>
  inline Array::Iterator<Array_Ptr_T, Value_T>& Array::Iterator<Array_Ptr_T, Value_T>::operator-=(difference_type n)
  {
    index_ -= n;
    return *this;
  }

  template<typename Array_Ptr_T, typename Value_T>
  inline Array::Iterator<Array_Ptr_T, Value_T> Array::Iterator<Array_Ptr_T, Value_T>::operator+(difference_type n) const
  {
    return Iterator(array_, index_ + n);
  }

  template<typename Array_Ptr_T, typename Value_T>
  inline Array::Iterator<Array_Ptr_T, Value_T> Array::Iterator<Array_Ptr_T, Value_T>::operator-(difference_type n) const
  {
    return Iterator(array_, index_ - n);
  }

  template<typename Array_Ptr_T, typename Value_T>
  inline typename Array::Iterator<Array_Ptr_T, Value_T>::difference_type
  Array::Iterator<Array_Ptr_T, Value_T>::operator-(Iterator const& rhs) const
  {
    return index_ - rhs.index_;
  }

  template<typename Array_Ptr_T, typename Value_T>
  inline Value_T Array::Iterator<Array_Ptr_T, Value_T>::operator[](difference_type n) const
  {
    return (*array_)[index_ + n];
  }

  // Non-member operator+ (allows n + iterator syntax)
  template<typename Array_Ptr_T, typename Value_T>
  inline Array::Iterator<Array_Ptr_T, Value_T> operator+(
    long n,
    Array::Iterator<Array_Ptr_T, Value_T> const& it)
  {
    return it + n;
  }

  template<typename Array_Ptr_T, typename Value_T>
  Array_Ptr_T Array::Iterator<Array_Ptr_T, Value_T>::array() const
  {
    return array_;
  }

  template<typename Array_Ptr_T, typename Value_T>
  long Array::Iterator<Array_Ptr_T, Value_T>::index() const
  {
    return index_;
  }

  inline Array::iterator Array::begin()
  {
    return iterator(this, 0);
  }

  inline Array::const_iterator Array::begin() const
  {
    return const_iterator(this, 0);
  }

  inline Array::iterator Array::end()
  {
    return iterator(this, size());
  }

  inline Array::const_iterator Array::end() const
  {
    return const_iterator(this, size());
  }
}

namespace Rice::detail
{
  template<>
  struct Type<Array>
  {
    static bool verify()
    {
      return true;
    }

    static VALUE rubyKlass()
    {
      return rb_cArray;
    }
  };

  template<>
  class To_Ruby<Array>
  {
  public:
    To_Ruby() = default;

    explicit To_Ruby(Arg* arg) : arg_(arg)
    {
    }

    VALUE convert(Array const& x)
    {
      return x.value();
    }

  private:
    Arg* arg_ = nullptr;
  };

  template<>
  class To_Ruby<Array&>
  {
  public:
    To_Ruby() = default;

    explicit To_Ruby(Arg* arg) : arg_(arg)
    {
    }

    VALUE convert(Array const& x)
    {
      return x.value();
    }

  private:
    Arg* arg_ = nullptr;
  };

  template<>
  class To_Ruby<Array*>
  {
  public:
    To_Ruby() = default;

    explicit To_Ruby(Arg* arg) : arg_(arg)
    {
    }

    VALUE convert(Array const* x)
    {
      return x->value();
    }

  private:
    Arg* arg_ = nullptr;
  };

  template<>
  class From_Ruby<Array>
  {
  public:
    From_Ruby() = default;

    explicit From_Ruby(Arg* arg) : arg_(arg)
    {
    }

    double is_convertible(VALUE value)
    {
      switch (rb_type(value))
      {
        case RUBY_T_ARRAY:
          return Convertible::Exact;
          break;
        default:
          return Convertible::None;
      }
    }

    Array convert(VALUE value)
    {
      return Array(value);
    }

  private:
    Arg* arg_ = nullptr;
  };
}

// =========   Hash.ipp   =========
#include <algorithm>

namespace Rice
{
  inline Hash::Hash() : Object(detail::protect(rb_hash_new))
  {
  }

  inline Hash::Hash(Object v) : Object(v)
  {
    detail::protect(rb_check_type, this->value(), T_HASH);
  }

  inline size_t Hash::size() const
  {
    return RHASH_SIZE(this->value());
  }

  inline Hash::Proxy::Proxy(Hash* hash, Object key) : hash_(hash), key_(key)
  {
  }

  inline Hash::Proxy::operator VALUE() const
  {
    return value();
  }

  inline VALUE Hash::Proxy::value() const
  {
    return detail::protect(rb_hash_aref, hash_->value(), key_.value());
  }

  template<typename T>
  inline Object Hash::Proxy::operator=(T const& value)
  {
    return detail::protect(rb_hash_aset, hash_->value(), key_.value(), detail::To_Ruby<T>().convert(value));
  }

  template<typename Key_T>
  inline Hash::Proxy const Hash::operator[](Key_T const& key) const
  {
    return Proxy(*this, detail::To_Ruby<Key_T>().convert(key));
  }

  template<typename Key_T>
  inline Hash::Proxy Hash::operator[](Key_T const& key)
  {
    return Proxy(this, detail::To_Ruby<Key_T>().convert(key));
  }

  template<typename Value_T, typename Key_T>
  inline Value_T Hash::get(Key_T const& key)
  {
    Object ruby_key(detail::To_Ruby<Key_T>().convert(key));
    Object value(operator[](ruby_key));
    try
    {
      return detail::From_Ruby<Value_T>().convert(value);
    }
    catch (Exception const& ex)
    {
      String s_key(ruby_key.to_s());
      throw Exception(
        ex,
        "%s while converting value for key %s",
        ex.what(),
        s_key.c_str());
    }
  }

  inline Hash::Entry::Entry(Hash* hash, Object key) :
    key(key), first(Hash::Entry::key), value(hash, key), second(Hash::Entry::value)
  {
  }

  inline Hash::Entry::Entry(Entry const& entry) :
    key(entry.key), first(Hash::Entry::key), value(entry.value), second(Hash::Entry::value)
  {
  }

  inline Hash::Entry& Hash::Entry::operator=(Hash::Entry const& other)
  {
    const_cast<Object&>(key) = const_cast<Object&>(other.key);

    this->value = other.value;
    this->second = this->value;

    return *this;
  }

  template<typename Hash_Ptr_T, typename Value_T>
  inline Hash::Iterator<Hash_Ptr_T, Value_T>::Iterator(Hash_Ptr_T hash)
    : hash_(hash), current_index_(0), keys_(Qnil), tmp_(const_cast<Hash*>(hash), Qnil)
  {
  }

  template<typename Hash_Ptr_T, typename Value_T>
  inline Hash::Iterator<Hash_Ptr_T, Value_T>::Iterator(Hash_Ptr_T hash, int start_at)
    : hash_(hash), current_index_(start_at), keys_(Qnil), tmp_(const_cast<Hash*>(hash), Qnil)
  {
  }

  template<typename Hash_Ptr_T, typename Value_T>
  template<typename Iterator_T>
  inline Hash::Iterator<Hash_Ptr_T, Value_T>::Iterator(Iterator_T const& iterator) :
    hash_(iterator.hash_), current_index_(iterator.current_index_), keys_(Qnil), tmp_(iterator.hash_, Qnil)
  {
  }

  template<typename Hash_Ptr_T, typename Value_T>
  inline Hash::Iterator<Hash_Ptr_T, Value_T>& Hash::Iterator<Hash_Ptr_T, Value_T>::operator++()
  {
    // Ensure we're within the range
    if (current_index_ < hash_keys().size())
    {
      current_index_++;
    }

    return *this;
  }

  template<typename Hash_Ptr_T, typename Value_T>
  inline Hash::Iterator<Hash_Ptr_T, Value_T> Hash::Iterator<Hash_Ptr_T, Value_T>::operator++(int)
  {
    Iterator copy(*this);
    ++(*this);
    return copy;
  }

  template<typename Hash_Ptr_T, typename Value_T>
  inline Value_T Hash::Iterator<Hash_Ptr_T, Value_T>::operator*()
  {
    return Value_T(const_cast<Hash*>(hash_), current_key());
  }

  template<typename Hash_Ptr_T, typename Value_T>
  inline Value_T* Hash::Iterator<Hash_Ptr_T, Value_T>::operator->()
  {
    this->tmp_ = Entry(const_cast<Hash*>(hash_), current_key());
    return &tmp_;
  }

  template<typename Hash_Ptr_T, typename Value_T>
  inline bool Hash::Iterator<Hash_Ptr_T, Value_T>::operator==(Iterator const& rhs) const
  {
    return hash_->value() == rhs.hash_->value()
      && current_index_ == rhs.current_index_;
  }

  template<typename Hash_Ptr_T, typename Value_T>
  inline bool Hash::Iterator<Hash_Ptr_T, Value_T>::operator!=(Iterator const& rhs) const
  {
    return !(*this == rhs);
  }

  template<typename Hash_Ptr_T, typename Value_T>
  inline Object Hash::Iterator<Hash_Ptr_T, Value_T>::current_key()
  {
    return Object(hash_keys()[current_index_]);
  }

  template<typename Hash_Ptr_T, typename Value_T>
  inline Array Hash::Iterator<Hash_Ptr_T, Value_T>::hash_keys()
  {
    if (NIL_P(keys_))
    {
      keys_ = rb_funcall(hash_->value(), rb_intern("keys"), 0, 0);
    }

    return Array(keys_);
  }

  inline Hash::iterator Hash::begin()
  {
    return iterator(this);
  }

  inline Hash::const_iterator Hash::begin() const
  {
    return const_iterator(this);
  }

  inline Hash::iterator Hash::end()
  {
    return iterator(this, (int)size());
  }

  inline Hash::const_iterator Hash::end() const
  {
    return const_iterator(this, (int)size());
  }

  inline bool operator<(Rice::Hash::Entry const& lhs, Rice::Hash::Entry const& rhs)
  {
    Rice::Object lhs_key(lhs.key);
    Rice::Object rhs_key(rhs.key);
    if (lhs_key < rhs_key)
    {
      return true;
    }
    else if (lhs_key > rhs_key)
    {
      return false;
    }
    else if (Rice::Object(lhs.value.value()) < Rice::Object(rhs.value.value()))
    {
      return true;
    }
    else
    {
      return false;
    }
  }
}

namespace Rice::detail
{
  template<>
  struct Type<Hash>
  {
    static bool verify()
    {
      return true;
    }

    static VALUE rubyKlass()
    {
      return rb_cHash;
    }
  };

  template<>
  class To_Ruby<Hash>
  {
  public:
    To_Ruby() = default;

    explicit To_Ruby(Arg* arg) : arg_(arg)
    {
    }

    VALUE convert(Hash const& x)
    {
      return x.value();
    }

  private:
    Arg* arg_ = nullptr;
  };

  template<>
  class From_Ruby<Hash>
  {
  public:
    From_Ruby() = default;

    explicit From_Ruby(Arg* arg) : arg_(arg)
    {
    }

    double is_convertible(VALUE value)
    {
      switch (rb_type(value))
      {
        case RUBY_T_HASH:
          return Convertible::Exact;
          break;
        default:
          return Convertible::None;
      }
    }

    Hash convert(VALUE value)
    {
      return Hash(value);
    }

  private:
    Arg* arg_ = nullptr;
  };
}

// =========   Symbol.ipp   =========
namespace Rice
{
  inline Symbol::Symbol(VALUE value) : Object(value)
  {
    detail::protect(rb_check_type, value, (int)T_SYMBOL);
  }

  inline Symbol::Symbol(Object value) : Object(value)
  {
    detail::protect(rb_check_type, value.value(), (int)T_SYMBOL);
  }

  inline Symbol::Symbol(char const* s)
    : Object(detail::protect(rb_id2sym, detail::protect(rb_intern, s)))
  {
  }

  inline Symbol::Symbol(std::string const& s)
    : Object(detail::protect(rb_id2sym, detail::protect(rb_intern2, s.c_str(), (long)s.length())))
  {
  }

  inline Symbol::Symbol(std::string_view const& view)
    : Object(detail::protect(rb_id2sym, detail::protect(rb_intern2, view.data(), (long)view.length())))
  {
  }

  inline Symbol::Symbol(Identifier id) : Object(detail::protect(rb_id2sym, id))
  {
  }

  inline char const* Symbol::c_str() const
  {
    return to_id().c_str();
  }

  inline std::string Symbol::str() const
  {
    return to_id().str();
  }

  inline Identifier Symbol::to_id() const
  {
    return rb_to_id(value());
  }
}

namespace Rice::detail
{
  template<>
  struct Type<Symbol>
  {
    static bool verify()
    {
      return true;
    }

    static VALUE rubyKlass()
    {
      return rb_cSymbol;
    }
  };
  
  template<>
  class To_Ruby<Symbol>
  {
  public:
    To_Ruby() = default;

    explicit To_Ruby(Arg* arg) : arg_(arg)
    {
    }

    VALUE convert(Symbol const& x)
    {
      return x.value();
    }

  private:
    Arg* arg_ = nullptr;
  };


  template<>
  class To_Ruby<Symbol&>
  {
  public:
    To_Ruby() = default;

    explicit To_Ruby(Arg* arg) : arg_(arg)
    {
    }

    VALUE convert(Symbol const& x)
    {
      return x.value();
    }

  private:
    Arg* arg_ = nullptr;
  };

  template<>
  class From_Ruby<Symbol>
  {
  public:
    From_Ruby() = default;

    explicit From_Ruby(Arg* arg) : arg_(arg)
    {
    }

    double is_convertible(VALUE value)
    {
      switch (rb_type(value))
      {
        case RUBY_T_SYMBOL:
          return Convertible::Exact;
          break;
        case RUBY_T_STRING:
          return Convertible::Exact;
          break;
        default:
          return Convertible::None;
        }
    }

    Symbol convert(VALUE value)
    {
      return Symbol(value);
    }

  private:
    Arg* arg_ = nullptr;
  };
}


// =========   Module.ipp   =========

namespace Rice
{
  inline Module::Module(VALUE value) : Object(value)
  {
    if (::rb_type(value) != T_CLASS && ::rb_type(value) != T_MODULE)
    {
      throw Exception(
        rb_eTypeError,
        "Expected a Module but got a %s",
        detail::protect(rb_obj_classname, value)); // TODO: might raise an exception
    }
  }

  //! Construct a Module from a string that references a Module
  inline Module::Module(std::string name, Object under)
  {
    VALUE result = under.const_get(name);

    if (::rb_type(result) != T_MODULE)
    {
      throw Exception(
        rb_eTypeError,
        "Expected a Module but got a %s",
        detail::protect(rb_obj_classname, result)); // TODO: might raise an exception
    }

    this->set_value(result);
  }

  template<typename Function_T, typename ...Arg_Ts>
  inline void Module::wrap_native_function(VALUE klass, std::string name, Function_T&& function, const Arg_Ts&...args)
  {
    constexpr bool isNoGVL = detail::tuple_element_index_v<std::tuple<Arg_Ts...>, NoGVL> < (sizeof...(Arg_Ts));
    detail::NativeFunction<Function_T, isNoGVL>::define(klass, name, std::forward<Function_T>(function), args...);
  }

  template<typename Class_T, typename Method_T, typename ...Arg_Ts>
  inline void Module::wrap_native_method(VALUE klass, std::string name, Method_T&& method, const Arg_Ts&...args)
  {
    constexpr bool isNoGVL = detail::tuple_element_index_v<std::tuple<Arg_Ts...>, NoGVL> < (sizeof...(Arg_Ts));
    detail::NativeMethod<Class_T, Method_T, isNoGVL>::define(klass, name, std::forward<Method_T>(method), args...);
  }

  inline Module define_module_under(Object parent, char const* name)
  {
    VALUE module = detail::protect(rb_define_module_under, parent.value(), name);
    detail::Registries::instance.modules.add(module);
    return module;
  }

  inline Module define_module(char const* name)
  {
    VALUE module = detail::protect(rb_define_module, name);
    detail::Registries::instance.modules.add(module);
    return module;
  }

  inline Module anonymous_module()
  {
    VALUE klass = detail::protect(rb_module_new);
    VALUE singleton = detail::protect(rb_singleton_class, klass);

    // Ruby will reuse addresses previously assigned to other modules
    // that have subsequently been garbage collected
    detail::Registries::instance.natives.reset(klass);
    detail::Registries::instance.natives.reset(singleton);

    return klass;
  }
}

namespace Rice::detail
{
  template<>
  struct Type<Module>
  {
    static bool verify()
    {
      return true;
    }

    static VALUE rubyKlass()
    {
      return rb_cModule;
    }
  };

  template<>
  class To_Ruby<Module>
  {
  public:
    To_Ruby() = default;

    explicit To_Ruby(Arg* arg) : arg_(arg)
    {
    }

    VALUE convert(Module const& x)
    {
      return x.value();
    }

  private:
    Arg* arg_ = nullptr;
  };


  template<>
  class To_Ruby<Module&>
  {
  public:
    To_Ruby() = default;

    explicit To_Ruby(Arg* arg) : arg_(arg)
    {
    }

    VALUE convert(Module const& x)
    {
      return x.value();
    }

  private:
    Arg* arg_ = nullptr;
  };

  template<>
  class From_Ruby<Module>
  {
  public:
    Module convert(VALUE value)
    {
      return Module(value);
    }
  };
}

// =========   Class.ipp   =========

namespace Rice
{
  inline Class::Class(VALUE value) : Module(value)
  {
    detail::protect(rb_check_type, value, (int)T_CLASS);
  }

  inline Class& Class::undef_creation_funcs()
  {
    detail::protect(rb_undef_alloc_func, value());
    detail::protect(rb_undef_method, value(), "initialize");
    return *this;
  }

  template<typename ...Parameter_Ts>
  inline Object Class::create(Parameter_Ts ...args)
  {
    return this->call("new", args...);
  }

  inline const std::string Class::name() const
  {
    const char* buffer = rb_class2name(this->value());
    return std::string(buffer);
  }

  inline const std::string Class::base_name() const
  {
    std::string name = this->name();
    auto regex = std::regex("^.*::");
    std::string result = std::regex_replace(name, regex, "");
    return result;
  }

  inline Class Class::superclass() const
  {
    return detail::protect(rb_class_superclass, this->value());
  }

  inline Class define_class_under(Object parent, Identifier id, const Class& superclass)
  {
    VALUE klass = detail::protect(rb_define_class_id_under, parent.value(), id, superclass.value());

    // We MUST reset the instance registry in case the user just redefined a class which resets it
    detail::Registries::instance.natives.reset(klass);

    return klass;
  }

  inline Class define_class_under(Object parent, char const* name, const Class& superclass)
  {
    Identifier id(name);
    return define_class_under(parent, id, superclass);
  }

  inline Class define_class(char const* name, const Class& superclass)
  {
    VALUE klass = detail::protect(rb_define_class, name, superclass.value());

    // We MUST reset the instance registry in case the user just redefined a class which resets it
    detail::Registries::instance.natives.reset(klass);

    return klass;
  }

  inline Class anonymous_class()
  {
    VALUE klass = detail::protect(rb_class_new, rb_cObject);
    VALUE singleton = detail::protect(rb_singleton_class, klass);

    // Ruby will reuse addresses previously assigned to other modules
    // that have subsequently been garbage collected
    detail::Registries::instance.natives.reset(klass);
    detail::Registries::instance.natives.reset(singleton);

    return klass;
  }
}

namespace Rice::detail
{
  template<>
  class To_Ruby<Class>
  {
  public:
    static VALUE convert(Class const& x)
    {
      return x.value();
    }
  };

  template<>
  class To_Ruby<Class&>
  {
  public:
    To_Ruby() = default;

    explicit To_Ruby(Arg* arg) : arg_(arg)
    {
    }

    VALUE convert(Class const& x)
    {
      return x.value();
    }

  private:
    Arg* arg_ = nullptr;
  };

  template<>
  class From_Ruby<Class>
  {
  public:
    Class convert(VALUE value)
    {
      return Class(value);
    }
  };
}

// =========   Struct.hpp   =========

namespace Rice
{
  //! A wrapper for creating Struct classes.
  /*! The Struct class is used for creating new Classes.  Note that the
   *  notation used here differs slightly from the notation inside the
   *  interpreter.
   *
   *  Inside the interpreter, calling Struct.new creates a new Class:
   *  \code
   *  irb(main):001:0> MyStruct = Struct.new(:a, :b, :c)
   *  => S
   *  irb(main):002:0> MyStruct.class
   *  => Class
   *  \endcode
   *
   *  Instantiating that Class creates an instance of that Class:
   *  \code
   *  irb(main):003:0> mystruct_instance = MyStruct.new
   *  => #<struct MyStruct a=nil, b=nil, c=nil>
   *  irb(main):004:0> mystruct_instance.class
   *  => MyStruct
   *  irb(main):005:0> mystruct_instance.class.ancestors
   *  => [MyStruct, Struct, Enumerable, Object, Kernel]
   *  \endcode
   *
   *  Thus, inside the interpreter, MyStruct is a Class which inherits
   *  from Struct, and mystruct_instance is an instance of MyStruct.
   *
   *  At the C++ level, we might do this instead:
   *  \code
   *  Struct rb_cMyStruct = define_struct()
   *    .define_member("a")
   *    .define_member("b")
   *    .define_member("c")
   *    .initialize("MyStruct");
   *  Struct::Instance mystruct_instance(rb_cMyStruct.new_instance());
   *  \endcode
   *
   * Here rb_cMyStruct is an instance of Struct and that mystruct_instance
   * is an instance of Struct::Instance.
   */
  class Struct : public Class
  {
  public:
    //! Define a new Struct member.
    /*! Defines a new member of the Struct.  Must be called before the
     *  Struct is initialized.
     *  \return *this
     */
    Struct& define_member(Identifier name);

    //! Initialize the Struct class.
    /*! Must be called after all Struct members have been defined.
     *  \param module the module under which to define the Struct.
     *  \param name the name of the Class at the ruby level.
     */
    Struct& initialize(Module module, Identifier name);

    //! Get the members in Struct.
    Array members() const;

    class Instance;
    friend class Instance;
    //friend Struct Rice::define_struct();

    //! Create a new instance of the Struct
    /*! \param args the arguments to the constructor.
     *  \return a new Struct::Instance
     */
    Instance new_instance(Array args = Array()) const;

  private:
    std::vector<Symbol> members_;
  };

  //! An instance of a Struct
  //! \sa Struct
  class Struct::Instance : public Object
  {
  public:
    //! Create a new Instance of a Struct.
    /*! \param type the Struct type to create.
     *  \param args the initial values for the objects of the instance.
     */
    Instance(Struct const& type,Array args = Array());

    //! Encapsulate an existing Struct instance.
    /*! \param type the Struct type to encapsulate.
     *  \param s the instance to encapsulate.
     */
    Instance(Struct const& type, Object s);

    //! Get a member, given its offset.
    /*! \param index the (integral) index into the Struct's internal
     *  array or its name (an Identifier or char const *)
     *  \return the member.
     */
    template<typename T>
    Object operator[](T index);

  private:
    Struct type_;
  };

  //! Define a new Struct
  Struct define_struct();

} // namespace Rice


// =========   Struct.ipp   =========

namespace Rice
{
  inline Struct& Struct::initialize(Module module, Identifier name)
  {
    Class struct_class(rb_cStruct);

    Object type = struct_class.vcall("new", this->members());

    set_value(type);
    module.const_set(name, type);

    return *this;
  }

  inline Struct& Struct::define_member(Identifier name)
  {
    if (!this->is_nil())
    {
      throw std::runtime_error("struct is already initialized");
    }

    members_.push_back(name.to_sym());

    return *this;
  }

  inline Array Struct::members() const
  {
    if (this->is_nil())
    {
      // Struct is not yet defined
      return Array(members_.begin(), members_.end());
    }
    else
    {
      // Struct is defined, call Ruby API
      return rb_struct_s_members(this->value());
    }
  }

  inline Struct::Instance Struct::new_instance(Array args) const
  {
    Object instance = const_cast<Struct*>(this)->vcall("new", args);
    return Instance(*this, instance);
  }

  inline Struct::Instance::Instance(Struct const& type, Array args) :
    Object(type.new_instance(args)), type_(type)
  {
    detail::protect(rb_check_type, this->value(), T_STRUCT);
  }

  inline Struct::Instance::Instance(Struct const& type, Object s) :
    Object(s), type_(type)
  {
    detail::protect(rb_check_type, this->value(), T_STRUCT);
  }

  inline Struct define_struct()
  {
    return Struct();
  }

  template<typename T>
  inline Object Struct::Instance::operator[](T index)
  {
    return rb_struct_aref(value(), ULONG2NUM(index));
  }

  template<>
  inline Object Struct::Instance::operator[]<Identifier>(Identifier member)
  {
    return rb_struct_aref(value(), Symbol(member));
  }

  template<>
  inline Object Struct::Instance::operator[]<char const*>(char const* name)
  {
    return (*this)[Identifier(name)];
  }
}

namespace Rice::detail
{
  template<>
  struct Type<Struct>
  {
    static bool verify()
    {
      return true;
    }

    static VALUE rubyKlass()
    {
      return rb_cStruct;
    }
  };
}

// =========   global_function.hpp   =========

namespace Rice
{
   //! Define an global function
   /*! The method's implementation can be any function or static member
    *  function.  A wrapper will be generated which will convert the arguments
    *  from ruby types to C++ types before calling the function.  The return
    *  value will be converted back to ruby.
    *  \param name the name of the method
    *  \param func the implementation of the function, either a function
    *  pointer or a member function pointer.
    *  \param args a list of Arg instance used to define default parameters (optional)
    *  \return *this
    */
  template<typename Function_T, typename...Arg_Ts>
  void define_global_function(char const * name, Function_T&& func, Arg_Ts const& ...args);
} // Rice


// =========   global_function.ipp   =========

template<typename Function_T, typename...Arg_Ts>
void Rice::define_global_function(char const * name, Function_T&& func, Arg_Ts const& ...args)
{
  Module(rb_mKernel).define_module_function(name, std::forward<Function_T>(func), args...);
}
// Code involved in creating custom DataTypes (ie, Ruby classes that wrap C++ classes)

// =========   ruby_mark.hpp   =========

//! Default function to call to mark a data object.
/*! This function can be specialized for a particular type to override
 *  the default behavior (which is to not mark any additional objects).
 */
namespace Rice
{
  template<typename T>
  void ruby_mark(T*)
  {
    // Do nothing by default
  }
}


// =========   default_allocation_func.hpp   =========

namespace Rice::detail
{
  //! A default implementation of an allocate_func.  This function does no
  //! actual allocation; the initialize_func can later do the real
  //! allocation with: DATA_PTR(self) = new Type(arg1, arg2, ...)
  template<typename T>
  VALUE default_allocation_func(VALUE klass);
}

// =========   Director.hpp   =========

namespace Rice
{
  /**
   * A Director works exactly as a SWIG %director works (thus the name).
   * You use this class to help build proxy classes so that polymorphism
   * works from C++ into Ruby. See the main README for how this class works.
   */
  class Director
  {
    public:
      //! Construct new Director. Needs the Ruby object so that the
      //  proxy class can call methods on that object.
      Director(Object self);

      virtual ~Director() = default;

      //! Raise a ruby exception when a call comes through for a pure virtual method
      /*! If a Ruby script calls 'super' on a method that's otherwise a pure virtual
       *  method, use this method to throw an exception in this case.
       */
      [[noreturn]]
      void raisePureVirtual() const;

      //! Get the Ruby object linked to this C++ instance
      Object getSelf() const;

    private:

      // Save the Ruby object related to the instance of this class
      Object self_;

  };
}

// =========   Director.ipp   =========

namespace Rice
{
  inline Director::Director(Object self) : self_(self)
  {
  }

  inline void Director::raisePureVirtual() const
  {
    rb_raise(rb_eNotImpError, "Cannot call super() into a pure-virtual C++ method");
  }

  inline Object Director::getSelf() const
  {
    return self_;
  }
}

// =========   Data_Type.ipp   =========
#include <stdexcept>

namespace Rice
{
  template<typename T>
  inline void ruby_mark_internal(detail::WrapperBase* wrapper)
  {
    // Tell the wrapper to mark the objects its keeping alive
    wrapper->ruby_mark();

    // Get the underlying data and call custom mark function (if any)
    // Use the wrapper's stored rb_data_type to avoid type mismatch
    T* data = static_cast<T*>(wrapper->get(Data_Type<T>::ruby_data_type()));
    ruby_mark<T>(data);
  }

  template<typename T>
  inline void ruby_free_internal(detail::WrapperBase* wrapper)
  {
    // Destructors are noexcept so we cannot use cpp_protect here
    delete wrapper;
  }

  template<typename T>
  inline size_t ruby_size_internal(const T*)
  {
    if constexpr (detail::is_complete_v<T>)
    {
      return sizeof(T);
    }
    else
    {
      return 0;
    }
  }

  template<>
  inline size_t ruby_size_internal(const void*)
  {
    return sizeof(void*);
  }

  template<typename T>
  template <typename Base_T>
  inline Data_Type<T> Data_Type<T>::bind(const Module& klass)
  {
    if (is_bound())
    {
      std::string message = "Type " + detail::TypeDetail<T>().name() + " is already bound to a different type";
      throw std::runtime_error(message.c_str());
    }

    klass_ = klass;

    rb_data_type_ = new rb_data_type_t();
    rb_data_type_->wrap_struct_name = strdup(Rice::detail::protect(rb_class2name, klass_));
    rb_data_type_->function.dmark = reinterpret_cast<void(*)(void*)>(&Rice::ruby_mark_internal<T>);
    rb_data_type_->function.dfree = reinterpret_cast<void(*)(void*)>(&Rice::ruby_free_internal<T>);
    rb_data_type_->function.dsize = reinterpret_cast<size_t(*)(const void*)>(&Rice::ruby_size_internal<T>);
    rb_data_type_->data = nullptr;
    rb_data_type_->flags = RUBY_TYPED_FREE_IMMEDIATELY;

    if constexpr (!std::is_void_v<Base_T>)
    {
      rb_data_type_->parent = Data_Type<Base_T>::ruby_data_type();
    }

    auto instances = unbound_instances();
    for (auto instance: instances)
    {
      instance->set_value(klass);
    }
    instances.clear();

    // Register with the type registry
    detail::Registries::instance.types.add<T>(klass_, rb_data_type_);

    // Add a method to get the source C++ class name from Ruby
    Data_Type<T> dataType;
    if constexpr (detail::is_complete_v<T>)
    {
      dataType.define_singleton_method("cpp_class", [](VALUE) -> VALUE
      {
        Return returnInfo;
        returnInfo.takeOwnership();

        detail::TypeDetail<T> typeDetail;
        std::string cppClassName = typeDetail.simplifiedName();

        return detail::To_Ruby<char*>(&returnInfo).convert(cppClassName.c_str());
      }, Arg("klass").setValue(), Return().setValue());
    }
    else
    {
      VALUE klass_value = klass.value();
      dataType.define_singleton_method("cpp_class", [klass_value](VALUE) -> VALUE
      {
        Return returnInfo;
        returnInfo.takeOwnership();

        Rice::String cppClassName = detail::protect(rb_class_path, klass_value);

        return detail::To_Ruby<char*>(&returnInfo).convert(cppClassName.c_str());
      }, Arg("klass").setValue(), Return().setValue());
    }
    return dataType;
  }

  template<typename T>
  inline void Data_Type<T>::unbind()
  {
    detail::Registries::instance.types.remove<T>();

    if (klass_ != Qnil)
    {
      klass_ = Qnil;
    }

    // There could be objects floating around using the existing rb_type so 
    // do not delete it. This is of course a memory leak.
    rb_data_type_ = nullptr;
  }

  // Track unbound instances (ie, declared variables of type Data_Type<T>
  // before define_class is called). We can't simply use a static inline
  // member because it sometimes crashes clang and gcc (msvc seems fine)
  template<typename T>
  inline std::set<Data_Type<T>*>& Data_Type<T>::unbound_instances()
  {
    static std::set<Data_Type<T>*> unbound_instances;
    return unbound_instances;
  }

  template<typename T>
  inline Data_Type<T>::Data_Type()
  {
    if (is_bound())
    {
      this->set_value(klass_);
    }
    else
    {
      unbound_instances().insert(this);
    }
  }

  template<typename T>
  inline Data_Type<T>::Data_Type(Module const& klass) : Class(klass)
  {
    this->bind(klass);
  }

  template<typename T>
  inline rb_data_type_t* Data_Type<T>::ruby_data_type()
  {
    check_is_bound();
    return rb_data_type_;
  }

  template<typename T>
  inline Class Data_Type<T>::klass()
  {
    check_is_bound();
    return klass_;
  }

  template<typename T>
  inline Data_Type<T>& Data_Type<T>::operator=(Module const& klass)
  {
    this->bind(klass);
    return *this;
  }

  template<typename T>
  template<typename Constructor_T, typename...Rice_Arg_Ts>
  inline Data_Type<T>& Data_Type<T>::define_constructor(Constructor_T, Rice_Arg_Ts const& ...args)
  {
    check_is_bound();

    // Define a Ruby allocator which creates the Ruby object
    detail::protect(rb_define_alloc_func, static_cast<VALUE>(*this), detail::default_allocation_func<T>);

    // We can't do anything with move constructors so blow up
    static_assert(!Constructor_T::isMoveConstructor(), "Rice does not support move constructors");

    // If this is a copy constructor then use it to support Ruby's Object#dup and Object#clone methods.
    // Otherwise if a user calls #dup or #clone an error will occur because the newly cloned Ruby
    // object will have a NULL ptr because the C++ object is never copied. This also prevents having
    // very unlike Ruby code of:
    // 
    //    my_object_copy = MyObject.new(my_ojbect_original).

    if constexpr (Constructor_T::isCopyConstructor())
    {
      // Define initialize_copy that will copy the C++ object and its keepAlive references.
      // We use setValue() so Rice passes the raw VALUE without conversion - this gives
      // initialize_copy access to both wrappers so it can copy the keepAlive list.
      using Rice_Arg_Tuple = std::tuple<Rice_Arg_Ts...>;
      constexpr std::size_t arg_index = detail::tuple_element_index_v<Rice_Arg_Tuple, Arg>;

      if constexpr (arg_index < sizeof...(Rice_Arg_Ts))
      {
        // User provided an Arg - extract it and ensure setValue is set
        Arg arg = std::get<arg_index>(std::forward_as_tuple(args...));
        arg.setValue();
        this->define_method("initialize_copy", &Constructor_T::initialize_copy, arg);
      }
      else
      {
        this->define_method("initialize_copy", &Constructor_T::initialize_copy, Arg("other").setValue());
      }
    }
    else if constexpr (Constructor_T::isMoveConstructor())
    {
      throw std::runtime_error("Rice does not support move constructors");
    }
    else
    {
      // Define an initialize function that will create the C++ object
      this->define_method("initialize", &Constructor_T::initialize, args...);
    }

    return *this;
  }

  template<typename T>
  template<typename Director_T>
  inline Data_Type<T>& Data_Type<T>::define_director()
  {
    if (!Data_Type<Director_T>::is_defined())
    {
      Data_Type<Director_T>::bind(*this);
    }

    // TODO - hack to fake Ruby into thinking that a Director is
    // the same as the base data type
    Data_Type<Director_T>::rb_data_type_ = Data_Type<T>::rb_data_type_;
    return *this;
  }

  template<typename T>
  inline bool Data_Type<T>::is_bound()
  {
    return klass_ != Qnil;
  }

  template<typename T>
  inline bool Data_Type<T>::is_descendant(VALUE value)
  {
    if (is_bound())
    {
      return detail::protect(rb_obj_is_kind_of, value, klass_) == Qtrue;
    }
    else
    {
      return false;
    }
  }

  template<typename T>
  inline void Data_Type<T>::check_is_bound()
  {
    if (!is_bound())
    {
      std::string message = "Type is not defined with Rice: " + detail::TypeDetail<T>().name();
      throw std::invalid_argument(message.c_str());
    }
  }

  template<typename T>
  inline bool Data_Type<T>::is_defined()
  {
    return detail::Registries::instance.types.isDefined<T>();
  }

  template<typename T>
  inline bool Data_Type<T>::check_defined(const std::string& name, Object parent)
  {
    if (Data_Type<T>::is_defined())
    {
      Data_Type<T> dataType;
      parent.const_set_maybe(name, dataType.klass());
      return true;
    }
    else
    {
      return false;
    }
  }

  template<typename Base_T>
  inline Class get_superklass()
  {
    Class result;

    if constexpr (std::is_void_v<Base_T>)
    {
      result = rb_cObject;
    }
    else
    {
      // This gives a chance to auto-register classes such as std::exception
      detail::verifyType<Base_T>();
      result = Data_Type<Base_T>::klass();
    }

    return result;
  }

  template<typename T, typename Base_T>
  inline Data_Type<T> define_class_under(Object parent, Identifier id, Class superKlass)
  {
    if (Rice::Data_Type<T>::check_defined(id.str(), parent))
    {
      return Data_Type<T>();
    }

    Class klass = define_class_under(parent, id, superKlass);
    klass.undef_creation_funcs();
    return Data_Type<T>::template bind<Base_T>(klass);
  }

  template<typename T, typename Base_T>
  inline Data_Type<T> define_class_under(Object parent, char const* name)
  {
    Identifier id(name);
    Class superKlass = get_superklass<Base_T>();
    return define_class_under<T, Base_T>(parent, id, superKlass);
  }

  template<typename T, typename Base_T>
  inline Data_Type<T> define_class(char const* name)
  {
    std::string klassName(name);

    if (Rice::Data_Type<T>::check_defined(klassName))
    {
      return Data_Type<T>();
    }

    Class superKlass = get_superklass<Base_T>();
    Class klass = define_class(name, superKlass);
    klass.undef_creation_funcs();
    return Data_Type<T>::template bind<Base_T>(klass);
  }

  template<typename T>
  template<typename Iterator_Func_T>
  inline Data_Type<T>& Data_Type<T>::define_iterator(Iterator_Func_T begin, Iterator_Func_T end, std::string name)
  {
    // Define a NativeIterator to bridge Ruby to C++
    detail::NativeIterator<T, Iterator_Func_T>::define(Data_Type<T>::klass(), name, begin, end);

    // Include enumerable support
    this->klass().include_module(rb_mEnumerable);

    return *this;
  }

  template <typename T>
  template <typename Attribute_T, typename Access_T, typename...Arg_Ts>
  inline Data_Type<T>& Data_Type<T>::define_attr(std::string name, Attribute_T attribute, Access_T access, const Arg_Ts&...args)
  {
    return this->define_attr_internal<Attribute_T, Access_T>(this->klass_, name, std::forward<Attribute_T>(attribute), access, args...);
  }

  template <typename T>
  template <typename Attribute_T, typename Access_T, typename...Arg_Ts>
  inline Data_Type<T>& Data_Type<T>::define_singleton_attr(std::string name, Attribute_T attribute, Access_T access, const Arg_Ts&...args)
  {
    VALUE singleton = detail::protect(rb_singleton_class, this->validated_value());
    return this->define_attr_internal<Attribute_T, Access_T>(singleton, name, std::forward<Attribute_T>(attribute), access, args...);
  }

  template <typename T>
  template <typename Attribute_T, typename Access_T, typename...Arg_Ts>
  inline Data_Type<T>& Data_Type<T>::define_attr_internal(VALUE klass, std::string name, Attribute_T attribute, Access_T, const Arg_Ts&...args)
  {
    // Define attribute getter
    if constexpr (std::is_same_v<Access_T, AttrAccess::ReadWriteType> || std::is_same_v<Access_T, AttrAccess::ReadType>)
    {
      detail::NativeAttributeGet<Attribute_T>::define(klass, name, std::forward<Attribute_T>(attribute), args...);
    }

    // Define attribute setter
    if constexpr (std::is_same_v<Access_T, AttrAccess::ReadWriteType> || std::is_same_v<Access_T, AttrAccess::WriteType>)
    {
      detail::NativeAttributeSet<Attribute_T>::define(klass, name, std::forward<Attribute_T>(attribute), args...);
    }

    return *this;
  }

  template <typename T>
  template<typename Method_T, typename ...Arg_Ts>
  inline void Data_Type<T>::wrap_native_method(VALUE klass, std::string name, Method_T&& method, const Arg_Ts&...args)
  {
    Module::wrap_native_method<T, Method_T>(klass, name, std::forward<Method_T>(method), args...);
  }
}

// =========   default_allocation_func.ipp   =========
namespace Rice::detail
{
  template<typename T>
  VALUE default_allocation_func(VALUE klass)
  {
    // Create a new Ruby object but since we do not yet have a C++ object
    // just pass a nullptr. It will be set via the Constructor call
    return TypedData_Wrap_Struct(klass, Data_Type<T>::ruby_data_type(), nullptr);
  }
}
// =========   Constructor.ipp   =========
namespace Rice
{
  template<typename T, typename...Parameter_Ts>
  class Constructor
  {
  public:
    static constexpr std::size_t arity = sizeof...(Parameter_Ts);

    static constexpr bool isCopyConstructor()
    {
      if constexpr (arity == 1)
      {
        using Arg_Types = std::tuple<Parameter_Ts...>;
        using First_Arg_T = std::tuple_element_t<0, Arg_Types>;
        return (arity == 1 &&
                std::is_lvalue_reference_v<First_Arg_T> &&
                std::is_same_v<T, detail::intrinsic_type<First_Arg_T>>);
      }
      else
      {
        return false;
      }
    }

    static constexpr bool isMoveConstructor()
    {
      if constexpr (arity == 1)
      {
        using Arg_Types = std::tuple<Parameter_Ts...>;
        using First_Arg_T = std::tuple_element_t<0, Arg_Types>;
        return (arity == 1 &&
          std::is_rvalue_reference_v<First_Arg_T> &&
          std::is_same_v<T, detail::intrinsic_type<First_Arg_T>>);
      }
      else
      {
        return false;
      }
    }

    static void initialize(VALUE self, Parameter_Ts...args)
    {
      // Call C++ constructor
      T* data = new T(args...);
      detail::wrapConstructed<T>(self, Data_Type<T>::ruby_data_type(), data);
    }

    // Takes VALUE (via Arg.setValue()) instead of const T& so we have access to
    // both Ruby wrappers and can copy the keepAlive list from the original to the clone.
    static VALUE initialize_copy(VALUE self, VALUE other)
    {
      T* otherData = detail::unwrap<T>(other, Data_Type<T>::ruby_data_type(), false);
      T* data = new T(*otherData);
      detail::wrapConstructed<T>(self, Data_Type<T>::ruby_data_type(), data, other);
      return self;
    }

  };

  //! Special-case Constructor used when defining Directors.
  template<typename T, typename...Parameter_Ts>
  class Constructor<T, Object, Parameter_Ts...>
  {
    public:
      static constexpr bool isCopyConstructor()
      {
        return false;
      }

      static constexpr bool isMoveConstructor()
      {
        return false;
      }

      static void initialize(Object self, Parameter_Ts...args)
      {
        // Call C++ constructor
        T* data = new T(self, args...);
        detail::wrapConstructed<T>(self.value(), Data_Type<T>::ruby_data_type(), data);
      }
  };
}
// =========   Callback.hpp   =========

namespace Rice
{
  //! Define a callback.
  /*! When C++ invokes a C style callback, Rice automatically converts the C++ arguments
   *  to Ruby. However, there may be cases where you need to specify how individual arguments
   *  should be handled. For example, callbacks often have a user data parameter which is 
   *  defined as a void pointer (void*). In this case, you need to tell Ruby that the parameter
   *  is opaque and should not be convered. For example:
   * 
   *  define_callback<void(*)(void*)>(Arg("user_data").setOpaque());
   *
   *  \param args a list of Arg instance used to define default parameters (optional)
   *  \return nothing
   */
  template<typename Callback_T, typename...Arg_Ts>
  void define_callback(Arg_Ts&&...args);
}

// =========   Callback.ipp   =========
namespace Rice
{
  template<typename Callback_T, typename...Arg_Ts>
  inline void define_callback(Arg_Ts&&...args)
  {
    detail::NativeCallback<Callback_T>::define(std::forward<Arg_Ts>(args)...);
  }
}
// =========   Data_Object.ipp   =========

#include <algorithm>

namespace Rice
{
  template <typename T>
  Exception create_type_exception(VALUE value)
  {
    if (Data_Type<T>::is_bound())
    {
      return Exception(rb_eTypeError, "Wrong argument type. Expected %s. Received %s.",
        detail::protect(rb_class2name, Data_Type<T>::klass().value()),
        detail::protect(rb_obj_classname, value));
    }
    else
    {
      return Exception(rb_eTypeError, "Wrong argument type. Expected %s. Received %s.",
        detail::TypeDetail<T>().name().c_str(),
        detail::protect(rb_obj_classname, value));
    }
  }

  template<typename T>
  inline Data_Object<T>::Data_Object(T& data, bool isOwner, Class klass)
  {
    VALUE value = detail::wrap(klass, Data_Type<T>::ruby_data_type(), data, isOwner);
    this->set_value(value);
  }

  template<typename T>
  inline Data_Object<T>::Data_Object(T&& data, Class klass)
  {
    VALUE value = detail::wrap(klass, Data_Type<T>::ruby_data_type(), data, true);
    this->set_value(value);
  }
  
  template<typename T>
  inline Data_Object<T>::Data_Object(const T& data, bool isOwner, Class klass)
  {
    VALUE value = detail::wrap(klass, Data_Type<T>::ruby_data_type(), data, isOwner);
    this->set_value(value);
  }

  template<typename T>
  inline Data_Object<T>::Data_Object(T* data, bool isOwner, Class klass)
  {
    VALUE value = detail::wrap(klass, Data_Type<T>::ruby_data_type(), data, isOwner);
    this->set_value(value);
  }

  template<typename T>
  inline Data_Object<T>::Data_Object(Object value) : Object(value)
  {
    check_ruby_type(value);
  }

  template<typename T>
  inline Data_Object<T>::Data_Object(VALUE value) : Object(value)
  {
    check_ruby_type(value);
  }

  template<typename T>
  inline void Data_Object<T>::check_ruby_type(VALUE value)
  {
    if (rb_obj_is_kind_of(value, Data_Type<T>::klass()) == Qfalse)
    {
      throw create_type_exception<T>(value);
    }
  }

  template<typename T>
  inline T& Data_Object<T>::operator*() const
  {
    return *this->get();
  }

  template<typename T>
  inline T* Data_Object<T>::operator->() const
  {
    return this->get();
  }

  template<typename T>
  inline T* Data_Object<T>::get() const
  {
    if (this->is_nil())
    {
      return nullptr;
    }
    else
    {
      return detail::unwrap<T>(this->value(), Data_Type<T>::ruby_data_type(), false);
    }
  }
}

namespace Rice::detail
{
  template<typename T>
  class To_Ruby
  {
    static_assert(!std::is_fundamental_v<intrinsic_type<T>>,
                  "Data_Object cannot be used with fundamental types");

    static_assert(!std::is_same_v<T, std::map<T, T>> && !std::is_same_v<T, std::unordered_map<T, T>> &&
                  !std::is_same_v<T, std::monostate> && !std::is_same_v<T, std::multimap<T, T>> &&
                  !std::is_same_v<T, std::optional<T>> && !std::is_same_v<T, std::pair<T, T>> &&
                  !std::is_same_v<T, std::set<T>> && !std::is_same_v<T, std::string> &&
                  !std::is_same_v<T, std::vector<T>>,
                  "Please include rice/stl.hpp header for STL support");

  public:
    To_Ruby() = default;

    explicit To_Ruby(Arg* arg) : arg_(arg)
    {
    }

    template<typename U>
    VALUE convert(U& data)
    {
      // Get the ruby typeinfo
      std::pair<VALUE, rb_data_type_t*> rubyTypeInfo = detail::Registries::instance.types.figureType<T>(data);

      // We always take ownership of data passed by value (yes the parameter is T& but the template
      // matched <typename T> thus we have to tell wrap to copy the reference we are sending to it
      return detail::wrap(rubyTypeInfo.first, rubyTypeInfo.second, data, true);
    }

    template<typename U>
    VALUE convert(U&& data)
    {
      // Get the ruby typeinfo
      std::pair<VALUE, rb_data_type_t*> rubyTypeInfo = detail::Registries::instance.types.figureType<T>(data);

      // We always take ownership of data passed by value (yes the parameter is T& but the template
      // matched <typename T> thus we have to tell wrap to copy the reference we are sending to it
      return detail::wrap(rubyTypeInfo.first, rubyTypeInfo.second, data, true);
    }

  private:
    Arg* arg_ = nullptr;
  };

  template <typename T>
  class To_Ruby<T&>
  {
    static_assert(!std::is_fundamental_v<intrinsic_type<T>>,
                  "Data_Object cannot be used with fundamental types");

    static_assert(!std::is_same_v<T, std::map<T, T>> && !std::is_same_v<T, std::unordered_map<T, T>> &&
                  !std::is_same_v<T, std::monostate> && !std::is_same_v<T, std::multimap<T, T>> &&
                  !std::is_same_v<T, std::optional<T>> && !std::is_same_v<T, std::pair<T, T>> &&
                  !std::is_same_v<T, std::set<T>> && !std::is_same_v<T, std::string> &&
                  !std::is_same_v<T, std::vector<T>>,
                  "Please include rice/stl.hpp header for STL support");

  public:
    To_Ruby() = default;

    explicit To_Ruby(Arg* arg) : arg_(arg)
    {
    }

    template<typename U>
    VALUE convert(U& data)
    {
      // Note that T could be a pointer or reference to a base class while data is in fact a
      // child class. Lookup the correct type so we return an instance of the correct Ruby class
      std::pair<VALUE, rb_data_type_t*> rubyTypeInfo = detail::Registries::instance.types.figureType<T>(data);

      bool isOwner = (this->arg_ && this->arg_->isOwner());
      return detail::wrap(rubyTypeInfo.first, rubyTypeInfo.second, data, isOwner);
    }
  private:
    Arg* arg_ = nullptr;
  };

  template <typename T, int N>
  class To_Ruby<T[N]>
  {
    static_assert(!std::is_same_v<T, std::map<T, T>> && !std::is_same_v<T, std::unordered_map<T, T>> &&
      !std::is_same_v<T, std::monostate> && !std::is_same_v<T, std::multimap<T, T>> &&
      !std::is_same_v<T, std::optional<T>> && !std::is_same_v<T, std::pair<T, T>> &&
      !std::is_same_v<T, std::set<T>> && !std::is_same_v<T, std::string> &&
      !std::is_same_v<T, std::vector<T>>,
      "Please include rice/stl.hpp header for STL support");

  public:
    To_Ruby() = default;

    explicit To_Ruby(Arg* arg) : arg_(arg)
    {
    }

    template<typename U>
    VALUE convert(U data[N])
    {
      Buffer<T> buffer(data, N);
      Data_Object<Buffer<T>> dataObject(std::move(buffer));
      return dataObject.value();
    }

  private:
    Arg* arg_ = nullptr;
  };

  template <typename T>
  class To_Ruby<T*>
  {
    static_assert(!std::is_same_v<T, std::map<T, T>> && !std::is_same_v<T, std::unordered_map<T, T>> &&
                  !std::is_same_v<T, std::monostate> && !std::is_same_v<T, std::multimap<T, T>> &&
                  !std::is_same_v<T, std::optional<T>> && !std::is_same_v<T, std::pair<T, T>> &&
                  !std::is_same_v<T, std::set<T>> && !std::is_same_v<T, std::string> &&
                  !std::is_same_v<T, std::vector<T>>,
                  "Please include rice/stl.hpp header for STL support");

  public:
    To_Ruby() = default;

    explicit To_Ruby(Arg* arg) : arg_(arg)
    {
    }

    template<typename U>
    VALUE convert(U* data)
    {
      bool isOwner = this->arg_ && this->arg_->isOwner();
      bool isBuffer = dynamic_cast<ReturnBuffer*>(this->arg_) ? true : false;

      if (data == nullptr)
      {
        return Qnil;
      }
      else if (std::is_fundamental_v<std::remove_pointer_t<T>> || isBuffer)
      {
        using Pointer_T = Pointer<remove_cv_recursive_t<U>>;
        return detail::wrap(Data_Type<Pointer_T>::klass(), Data_Type<Pointer_T>::ruby_data_type(), data, isOwner);
      }
      else
      {
        // Note that T could be a pointer or reference to a base class while data is in fact a
        // child class. Lookup the correct type so we return an instance of the correct Ruby class
        std::pair<VALUE, rb_data_type_t*> rubyTypeInfo = detail::Registries::instance.types.figureType(*data);
        return detail::wrap(rubyTypeInfo.first, rubyTypeInfo.second, data, isOwner);
      }
    }
    
  private:
    Arg* arg_ = nullptr;
  };

  template <typename T>
    class To_Ruby<T*&>
  {
    static_assert(!std::is_same_v<T, std::map<T, T>> && !std::is_same_v<T, std::unordered_map<T, T>> &&
                  !std::is_same_v<T, std::monostate> && !std::is_same_v<T, std::multimap<T, T>> &&
                  !std::is_same_v<T, std::optional<T>> && !std::is_same_v<T, std::pair<T, T>> &&
                  !std::is_same_v<T, std::set<T>> && !std::is_same_v<T, std::string> &&
                  !std::is_same_v<T, std::vector<T>>,
                  "Please include rice/stl.hpp header for STL support");

  public:
    To_Ruby() = default;

    explicit To_Ruby(Arg* arg) : arg_(arg)
    {
    }

    template<typename U>
    VALUE convert(U* data)
    {
      bool isOwner = this->arg_ && this->arg_->isOwner();
      bool isBuffer = dynamic_cast<ReturnBuffer*>(this->arg_) ? true : false;
 
      if (data == nullptr)
      {
        return Qnil;
      }
      else if constexpr (std::is_const_v<U>)
      {
        std::pair<VALUE, rb_data_type_t*> rubyTypeInfo = detail::Registries::instance.types.figureType(*data);
        return detail::wrap(rubyTypeInfo.first, rubyTypeInfo.second, data, isOwner);
      }
      else if (std::is_fundamental_v<T> || isBuffer)
      {
        using Pointer_T = Pointer<remove_cv_recursive_t<U>>;
        return detail::wrap(Data_Type<Pointer_T>::klass(), Data_Type<Pointer_T>::ruby_data_type(), data, isOwner);
      }
      else
      {
        // Note that T could be a pointer or reference to a base class while data is in fact a
        // child class. Lookup the correct type so we return an instance of the correct Ruby class
        std::pair<VALUE, rb_data_type_t*> rubyTypeInfo = detail::Registries::instance.types.figureType(*data);
        return detail::wrap(rubyTypeInfo.first, rubyTypeInfo.second, data, isOwner);
      }
    }

  private:
    Arg* arg_ = nullptr;
  };

  template <typename T>
  class To_Ruby<T**>
  {
  public:
    To_Ruby() = default;

    explicit To_Ruby(Arg* arg) : arg_(arg)
    {
    }

    template<typename U>
    VALUE convert(U** data)
    {
      if (data)
      {
        bool isOwner = this->arg_ && this->arg_->isOwner();
        using Pointer_T = Pointer<remove_cv_recursive_t<U>*>;
        return detail::wrap(Data_Type<Pointer_T>::klass(), Data_Type<Pointer_T>::ruby_data_type(), data, isOwner);
      }
      else
      {
        return Qnil;
      }
    }

  private:
    Arg* arg_ = nullptr;
  };

  template<typename T>
  class To_Ruby<Data_Object<T>>
  {
  public:
    VALUE convert(const Object& x)
    {
      return x.value();
    }
  };

  template <typename T>
  class From_Ruby
  {
    static_assert(!std::is_fundamental_v<intrinsic_type<T>>,
                  "Data_Object cannot be used with fundamental types");

    static_assert(!std::is_same_v<T, std::map<T, T>> || !std::is_same_v<T, std::unordered_map<T, T>> ||
                  !std::is_same_v<T, std::monostate> || !std::is_same_v<T, std::multimap<T, T>> ||
                  !std::is_same_v<T, std::optional<T>> || !std::is_same_v<T, std::pair<T, T>> ||
                  !std::is_same_v<T, std::set<T>> || !std::is_same_v<T, std::string> ||
                  !std::is_same_v<T, std::vector<T>>,
                  "Please include rice/stl.hpp header for STL support");

  public:
    From_Ruby() = default;

    explicit From_Ruby(Arg * arg) : arg_(arg)
    {
    }
    
    double is_convertible(VALUE value)
    {
      switch (rb_type(value))
      {
        case RUBY_T_DATA:
          return Data_Type<T>::is_descendant(value) ? Convertible::Exact : Convertible::None;
          break;
        default:
          return Convertible::None;
      }
    }

    T convert(VALUE value)
    {
      using Intrinsic_T = intrinsic_type<T>;
      Intrinsic_T* instance = detail::unwrap<Intrinsic_T>(value, Data_Type<Intrinsic_T>::ruby_data_type(), this->arg_ && this->arg_->isOwner());

      if constexpr (std::is_constructible_v<T, T> && !std::is_convertible_v<T, T>)
      {
        return T(*instance);
      }
      else
      {
        return *instance;
      }
    }

  private:
    Arg* arg_ = nullptr;
  };

  template<typename T>
  class From_Ruby<T&>
  {
    static_assert(!std::is_fundamental_v<intrinsic_type<T>>,
                  "Data_Object cannot be used with fundamental types");

    static_assert(!std::is_same_v<T, std::map<T, T>>   && !std::is_same_v<T, std::unordered_map<T, T>> &&
                  !std::is_same_v<T, std::monostate>   && !std::is_same_v<T, std::multimap<T, T>>      &&
                  !std::is_same_v<T, std::optional<T>> && !std::is_same_v<T, std::pair<T, T>>          &&
                  !std::is_same_v<T, std::set<T>>      && !std::is_same_v<T, std::string>              &&
                  !std::is_same_v<T, std::vector<T>>,
                  "Please include rice/stl.hpp header for STL support");

  public:
    From_Ruby() = default;

    explicit From_Ruby(Arg * arg) : arg_(arg)
    {
    }

    double is_convertible(VALUE value)
    {
      switch (rb_type(value))
      {
        case RUBY_T_DATA:
          return Data_Type<T>::is_descendant(value) ? Convertible::Exact : Convertible::None;
          break;
        default:
          return Convertible::None;
      }
    }

    T& convert(VALUE value)
    {
      using Intrinsic_T = intrinsic_type<T>;

      return *detail::unwrap<Intrinsic_T>(value, Data_Type<Intrinsic_T>::ruby_data_type(), this->arg_ && this->arg_->isOwner()); 
    }

  private:
    Arg* arg_ = nullptr;
  };

  template<typename T>
  class From_Ruby<T&&>
  {
    static_assert(!std::is_fundamental_v<intrinsic_type<T>>,
                  "Data_Object cannot be used with fundamental types");

    static_assert(!std::is_same_v<T, std::map<T, T>> && !std::is_same_v<T, std::unordered_map<T, T>> &&
                  !std::is_same_v<T, std::monostate> && !std::is_same_v<T, std::multimap<T, T>> &&
                  !std::is_same_v<T, std::optional<T>> && !std::is_same_v<T, std::pair<T, T>> &&
                  !std::is_same_v<T, std::set<T>> && !std::is_same_v<T, std::string> &&
                  !std::is_same_v<T, std::vector<T>>,
                  "Please include rice/stl.hpp header for STL support");

  public:
    From_Ruby() = default;

    explicit From_Ruby(Arg * arg) : arg_(arg)
    {
    }

    double is_convertible(VALUE value)
    {
      switch (rb_type(value))
      {
      case RUBY_T_DATA:
        return Data_Type<T>::is_descendant(value) ? Convertible::Exact : Convertible::None;
        break;
      default:
        return Convertible::None;
      }
    }

    T&& convert(VALUE value)
    {
      using Intrinsic_T = intrinsic_type<T>;

      Intrinsic_T* object = detail::unwrap<Intrinsic_T>(value, Data_Type<Intrinsic_T>::ruby_data_type(), this->arg_ && this->arg_->isOwner());
      return std::move(*object);
    }

  private:
    Arg* arg_ = nullptr;
  };

  // 99% of the time a T* represents a wrapped C++ object that we want to call methods on. However, T* 
  // could also be a pointer to an array of T objects, so T[]. OpenCV for example has API calls like this.
  template<typename T>
  class From_Ruby<T*>
  {
    static_assert(!std::is_same_v<T, std::map<T, T>> && !std::is_same_v<T, std::unordered_map<T, T>> &&
                  !std::is_same_v<T, std::monostate> && !std::is_same_v<T, std::multimap<T, T>> &&
                  !std::is_same_v<T, std::optional<T>> && !std::is_same_v<T, std::pair<T, T>> &&
                  !std::is_same_v<T, std::set<T>> && !std::is_same_v<T, std::string> &&
                  !std::is_same_v<T, std::vector<T>>,
                  "Please include rice/stl.hpp header for STL support");

    using Intrinsic_T = intrinsic_type<T>;
    using Pointer_T = Pointer<remove_cv_recursive_t<T>>;

  public:
    From_Ruby() = default;

    explicit From_Ruby(Arg* arg) : arg_(arg)
    {
    }

    double is_convertible(VALUE value)
    {
      bool isBuffer = dynamic_cast<ArgBuffer*>(this->arg_) ? true : false;

      switch (rb_type(value))
      {
        case RUBY_T_NIL:
          return Convertible::Exact;
          break;
        case RUBY_T_DATA:
          if (Data_Type<T>::is_descendant(value) && !isBuffer)
          {
            return Convertible::Exact;
          }
          else if (Data_Type<Pointer_T>::is_descendant(value) && isBuffer)
          {
            return Convertible::Exact;
          }
          else if (Data_Type<Pointer_T>::is_descendant(value) && !isBuffer)
          {
            return Convertible::Exact * 0.99;
          }
          [[fallthrough]];
        default:
          return Convertible::None;
      }
    }

    T* convert(VALUE value)
    {
      bool isOwner = this->arg_ && this->arg_->isOwner();
      bool isBuffer = dynamic_cast<ArgBuffer*>(this->arg_) ? true : false;

      switch (rb_type(value))
      {
        case RUBY_T_NIL:
        {
          return nullptr;
          break;
        }
        case RUBY_T_DATA:
        {
          if (Data_Type<T>::is_descendant(value) && !isBuffer)
          {
            return detail::unwrap<Intrinsic_T>(value, Data_Type<Intrinsic_T>::ruby_data_type(), isOwner);
          }
          else if (Data_Type<Pointer_T>::is_descendant(value))
          {
            return detail::unwrap<T>(value, Data_Type<Pointer_T>::ruby_data_type(), isOwner);
          }
          [[fallthrough]];
        }
        default:
        {
          if (isBuffer || std::is_fundamental_v<T>)
          {
            throw create_type_exception<Pointer_T>(value);
          }
          else
          {
            throw create_type_exception<T>(value);
          }
        }
      }
    }

  private:
    Arg* arg_ = nullptr;
  };

  template<typename T>
  class From_Ruby<T*&>
  {
    static_assert(!std::is_same_v<T, std::map<T, T>> && !std::is_same_v<T, std::unordered_map<T, T>> &&
                  !std::is_same_v<T, std::monostate> && !std::is_same_v<T, std::multimap<T, T>> &&
                  !std::is_same_v<T, std::optional<T>> && !std::is_same_v<T, std::pair<T, T>> &&
                  !std::is_same_v<T, std::set<T>> && !std::is_same_v<T, std::string> &&
                  !std::is_same_v<T, std::vector<T>>,
                  "Please include rice/stl.hpp header for STL support");

  public:
    From_Ruby() = default;

    explicit From_Ruby(Arg* arg) : arg_(arg)
    {
    }

    double is_convertible(VALUE value)
    {
      switch (rb_type(value))
      {
        case RUBY_T_DATA:
          return Data_Type<T>::is_descendant(value) ? Convertible::Exact : Convertible::None;
          break;
        default:
          return Convertible::None;
      }
    }

    T* convert(VALUE value)
    {
      using Intrinsic_T = intrinsic_type<T>;

      if (value == Qnil)
      {
        return nullptr;
      }
      else
      {
        return detail::unwrap<Intrinsic_T>(value, Data_Type<Intrinsic_T>::ruby_data_type(), this->arg_ && this->arg_->isOwner());
      }
    }

  private:
    Arg* arg_ = nullptr;
  };

  template<typename T>
  class From_Ruby<T**>
  {
    static_assert(!std::is_same_v<T, std::map<T, T>> && !std::is_same_v<T, std::unordered_map<T, T>> &&
                  !std::is_same_v<T, std::monostate> && !std::is_same_v<T, std::multimap<T, T>> &&
                  !std::is_same_v<T, std::optional<T>> && !std::is_same_v<T, std::pair<T, T>> &&
                  !std::is_same_v<T, std::set<T>> && !std::is_same_v<T, std::string> &&
                  !std::is_same_v<T, std::vector<T>>,
                  "Please include rice/stl.hpp header for STL support");

    using Intrinsic_T = intrinsic_type<T>;
    using Pointer_T = Pointer<remove_cv_recursive_t<T>*>;
  public:
    From_Ruby() = default;

    explicit From_Ruby(Arg* arg) : arg_(arg)
    {
    }

    double is_convertible(VALUE value)
    {
      switch (rb_type(value))
      {
        case RUBY_T_NIL:
          return Convertible::Exact;
          break;
        case RUBY_T_DATA:
          if (Data_Type<Pointer_T>::is_descendant(value))
          {
            return Convertible::Exact;
          }
          [[fallthrough]];
        default:
          return Convertible::None;
      }
    }

    T** convert(VALUE value)
    {
      bool isOwner = this->arg_ && this->arg_->isOwner();

      switch (rb_type(value))
      {
        case RUBY_T_NIL:
        {
          return nullptr;
          break;
        }
        case RUBY_T_DATA:
        {
          if (Data_Type<Pointer_T>::is_descendant(value))
          {
            T** result = detail::unwrap<Intrinsic_T*>(value, Data_Type<Pointer_T>::ruby_data_type(), isOwner);
            return result;
          }
          [[fallthrough]];
        }
        default:
        {
          throw create_type_exception<Pointer_T>(value);
        }
      }
    }

  private:
    Arg* arg_ = nullptr;
    std::vector<Intrinsic_T*> vector_;
  };

  template<typename T>
  class From_Ruby<Data_Object<T>>
  {
    static_assert(!std::is_fundamental_v<intrinsic_type<T>>,
                  "Data_Object cannot be used with fundamental types");

    static_assert(!std::is_same_v<T, std::map<T, T>> && !std::is_same_v<T, std::unordered_map<T, T>> &&
                  !std::is_same_v<T, std::monostate> && !std::is_same_v<T, std::multimap<T, T>> &&
                  !std::is_same_v<T, std::optional<T>> && !std::is_same_v<T, std::pair<T, T>> &&
                  !std::is_same_v<T, std::set<T>> && !std::is_same_v<T, std::string> &&
                  !std::is_same_v<T, std::vector<T>>,
                  "Please include rice/stl.hpp header for STL support");

  public:
    double is_convertible(VALUE value)
    {
      switch (rb_type(value))
      {
        case RUBY_T_DATA:
          return Data_Type<T>::is_descendant(value) ? Convertible::Exact : Convertible::None;
          break;
        default:
          return Convertible::None;
        }
    }

    static Data_Object<T> convert(VALUE value)
    {
      return Data_Object<T>(value);
    }
  };
}

// =========   Enum.hpp   =========

namespace Rice
{
  /*!
   *  \example enum/sample_enum.cpp
   */

   //! A wrapper for enumerated types.
   /*! Provides a simple type-safe wrapper for enumerated types.  At the
    *  ruby level, the class will have convenience methods for iterating
    *  over all the defined enum values, converting the values to strings,
    *  and more.
    *
    *  \param Enum_T the enumerated type
    *
    *  Example:
    *  \code
    *    enum Color { Red, Green, Blue };
    *    Enum<Color> rb_cColor = define_enum<Color>("Color")
    *      .define_value("Red", Red)
    *      .define_value("Green", Green)
    *      .define_value("Blue", Blue);
    *  \endcode
    */
  template<typename Enum_T>
  class Enum : public Data_Type<Enum_T>
  {
    using Underlying_T = std::underlying_type_t<Enum_T>;

  public:
    Enum() = default;

    //! Construct and initialize.
    Enum(char const* name, Module module = rb_cObject);

    //! Define a new enum value.
    /*! \param name the name of the enum value.
     *  \param value the value to associate with name.
     *  \return *this
     */
    Enum<Enum_T>& define_value(std::string name, Enum_T value);

    //! Maps an enum value to the correct Ruby object
    /*! \param klass The bound Ruby class
     *  \param enumValue The enum value
     *  \return Object - The Ruby wrapper */
    static Object from_enum(Class klass, Enum_T enumValue);

  private:
    void define_methods(Data_Type<Enum_T> klass);

    static inline std::map<Enum_T, std::string> valuesToNames_;
  };

  template<typename T>
  Enum<T> define_enum(char const* name);

  template<typename T>
  Enum<T> define_enum_under(char const* name, Module module );
} // namespace Rice


// =========   Enum.ipp   =========
#include <stdexcept>

namespace Rice
{
  template<typename Enum_T>
  Enum<Enum_T>::Enum(char const* name, Module module) : Data_Type<Enum_T>()
  {
    Data_Type<Enum_T> klass = define_class_under<Enum_T>(module, name);
    define_methods(klass);
  }

  template<typename Enum_T>
  inline Enum<Enum_T>& Enum<Enum_T>::define_value(std::string name, Enum_T value)
  {
    // Save mapping from value to name
    valuesToNames_[value] = name;

    // Store value as class constant available to Ruby
    Data_Object<Enum_T> object(value, true, Enum<Enum_T>::klass());
    this->const_set(name, object);

    return *this;
  }

  template<typename Enum_T>
  inline void Enum<Enum_T>::define_methods(Data_Type<Enum_T> klass)
  {
    // First we need a constructor
    klass.define_constructor(Constructor<Enum_T>());

    klass.define_method("to_s", [](Enum_T& self) -> String
    {
      return String(valuesToNames_[self]);
    })
    .define_method("to_int", [](Enum_T& self) ->  Underlying_T
    {
      return (Underlying_T)(self);
    })
    .define_method("coerce", [](Enum_T& self, Underlying_T& other) -> Array
    {
      /* Other will be a numeric value that matches the underlying type of the enum, for example an int.
          Convert that to the enum type and then create new Ruby object to wrap it. This then enables code
          like this:
        
          Colors::Red | Colors:Blue | Colors:Green

      Colors::Red | Colors:Blue returns an integer. Then this method converts the integer back into an Enum
      instance so that Colors:Blue | Colors:Green works. */
      Enum_T otherEnum = (Enum_T)other;

      Array result;
      result.push(otherEnum, true);
      result.push(self, false);
      return result;
    })
    .define_method("inspect", [](Enum_T& self)
    {
      std::stringstream result;
      VALUE rubyKlass = Enum<Enum_T>::klass().value();
      result << "#<" << detail::protect(rb_class2name, rubyKlass)
        << "::" << Enum<Enum_T>::valuesToNames_[self] << ">";

      // We have to return string because we don't know if std::string support has
      // been included by the user
      return String(result.str());
    })
    .define_method("hash", [](Enum_T& self) ->  Underlying_T
    {
      return (Underlying_T)self;
    })
    .define_method("eql?", [](Enum_T& self, Enum_T& other)
    {
      return self == other;
    })
    .define_method("eql?", [](Enum_T& self, Underlying_T& other)
    {
      return self == (Enum_T)other;
    });

    // Add aliases
    rb_define_alias(klass, "===", "eql?");
    rb_define_alias(klass, "to_i", "to_int");

    // Add comparable support
    klass.include_module(rb_mComparable)
      .define_method("<=>", [](Enum_T& self, Enum_T& other)
      {
        if (self == other)
        {
          return 0;
        }
        else if (self < other)
        {
          return -1;
        }
        else
        {
          return 1;
        }
      })
      .define_method("<=>", [](Enum_T& self, Underlying_T& other)
      {
        if (self == (Enum_T)other)
        {
          return 0;
        }
        else if (self < (Enum_T)other)
        {
          return -1;
        }
        else
        {
          return 1;
        }
      });

    // Add ability to get enum values
    klass.define_singleton_method("values", [](VALUE ruby_klass) -> VALUE
    {
      Array result;

      for (auto& pair : valuesToNames_)
      {
        Object enumValue = Class(ruby_klass).const_get(pair.second);
        result.push(enumValue, false);
      }

      return result;
    }, Return().setValue());

    // Add bitwise operators
    klass.define_method("&", [](Enum_T& self, Enum_T& other) -> Underlying_T
      {
        return (Underlying_T)self & (Underlying_T)other;
      })
      .define_method("|", [](Enum_T& self, Enum_T& other) -> Underlying_T
      {
        return (Underlying_T)self | (Underlying_T)other;
      })
      .define_method("^", [](Enum_T& self, Enum_T& other) -> Underlying_T
      {
        return (Underlying_T)self ^ (Underlying_T)other;
      })
      .define_method("~", [](Enum_T& self) -> Underlying_T
      {
        return ~(Underlying_T)self;
      });

    // Add shift operators
    klass.define_method("<<", [](Enum_T& self, int shift) -> Underlying_T
      {
        return (Underlying_T)self << shift;
      })
      .define_method(">>", [](Enum_T& self, int shift) -> Underlying_T
      {
        return (Underlying_T)self >> shift;
      });

    // Add conversions from int
    klass.define_singleton_method("from_int", [](VALUE ruby_klass, int32_t value) -> Object
      {
        auto iter = Enum<Enum_T>::valuesToNames_.find((Enum_T)value);
        if (iter == Enum<Enum_T>::valuesToNames_.end())
        {
          throw std::runtime_error("Unknown enum value: " + std::to_string(value));
        }

        std::string name = iter->second;
        return Object(ruby_klass).const_get(name);
      });
  }

  template<typename Enum_T>
  Enum<Enum_T> define_enum(char const* name)
  {
    return define_enum_under<Enum_T>(name, rb_cObject);
  }

  template<typename Enum_T>
  Enum<Enum_T> define_enum_under(char const* name, Module module)
  {
    if (detail::Registries::instance.types.isDefined<Enum_T>())
    {
      return Enum<Enum_T>();
    }

    return Enum<Enum_T>(name, module);
  }
}
// =========   MemoryView.hpp   =========

namespace Rice
{
  class MemoryView
  {
  };
}


// =========   MemoryView.ipp   =========
namespace Rice
{
}
// Dependent on Module, Class, Array and String

// =========   forward_declares.ipp   =========

namespace Rice
{
  // These methods cannot be defined where they are declared due to circular dependencies
  inline Class Object::class_of() const
  {
    return detail::protect(rb_class_of, this->value());
  }

  inline String Object::to_s() const
  {
    return call("to_s");
  }

  inline String Object::class_name() const
  {
    return detail::protect(rb_obj_classname, this->value());
  }

  inline String Object::inspect() const
  {
    return call("inspect");
  }

  inline Object Object::instance_eval(String const& s)
  {
    const VALUE argv[] = { s.value() };
    return detail::protect(rb_obj_instance_eval, 1, &argv[0], this->value());
  }

  inline Object Object::vcall(Identifier id, Array args)
  {
    std::vector<VALUE> a(args.size());

    Array::const_iterator it = args.begin();
    Array::const_iterator end = args.end();

    for (int i = 0; it != end; i++, ++it)
    {
      a[i] = it->value();
    }

    return detail::protect(rb_funcall3, this->value(), id.id(), (int)args.size(), (const VALUE*)a.data());
  }

  inline std::ostream& operator<<(std::ostream& out, Object const& obj)
  {
    String s(obj.to_s());
    out << s.c_str();
    return out;
  }

  inline Identifier::Identifier(Symbol const& symbol) : id_(SYM2ID(symbol.value()))
  {
  }

  inline String Module::name() const
  {
    VALUE name = detail::protect(rb_mod_name, this->value());
    if (name == Qnil)
    {
      return String("");
    }
    else
    {
      return name;
    }
  }

  inline Array Module::ancestors() const
  {
    return detail::protect(rb_mod_ancestors, this->value());
  }

  inline Class Module::singleton_class() const
  {
    return CLASS_OF(value());
  }

  inline Object Module::module_eval(String const& s)
  {
    const VALUE argv[] = { s.value() };
    return detail::protect(rb_mod_module_eval, 1, &argv[0], this->value());
  }
}

// For now include libc support - maybe should be separate header file someday

// =========   file.hpp   =========

namespace Rice::Libc
{
  extern Class rb_cLibcFile;
}


// ---------   file.ipp   ---------
#include <exception>

namespace Rice::Libc
{
  inline Class rb_cLibcFile;

  inline void define_libc_file()
  {
    Module rb_mLibc = define_module("Libc");
    rb_cLibcFile = define_class_under<FILE>(rb_mLibc, "File");
  }
}

namespace Rice::detail
{
  template<>
  struct Type<FILE>
  {
    static bool verify()
    {
      if (!Data_Type<FILE>::is_defined())
      {
        Libc::define_libc_file();
      }

      return true;
    }
  };
}


#endif // Rice__hpp_
