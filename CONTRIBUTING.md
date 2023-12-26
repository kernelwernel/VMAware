# CONTRIBUTION GUIDELINES

Doubt anybody will even read this, but hey, what's up! :)

This guideline will cover how contributions can be made. The process of adding a new detection mechanism is a bit complicated, so I'll outline the basic steps and the standard format needed to contribute.
<br>

# Step 1: Choose the right branch
Make sure you choose the **dev** branch to make pull requests. 

<br>

# Step 2: Understand the format of a detection function
A VM detection mechanism has 3 things:
1. A unique bit flag value for the function
2. The function itself
3. The inclusion of the function in the technique table

<br>

# Step 3: Add the unique flag value for your function
Go to the vmaware.hpp source code, then CTRL+F the string "`__UNIQUE_LABEL`". This will bring you to the list of flag values for every function in the library. It should look something like this:
```cpp
// ...
GAMARUE = 1ULL << 39,
WINDOWS_NUMBER = 1ULL << 40,
VMID_0X4 = 1ULL << 41,
VPC_BACKDOOR = 1ULL << 42,
PARALLELS_VM = 1ULL << 43,
// ...
```

To add one, make sure to add a name for your own function (in all caps) with an incremental value based on the previous unique flag variable. You can name it whatever you want, just be clear and succint with your naming. So for example:
```cpp
VPC_BACKDOOR = 1ULL << 42,
PARALLELS_VM = 1ULL << 43,
YOUR_FUNCTION = 1ULL << 44, // here
```


<br>

# Step 4: Add the detection function itself
To add your own function, follow the format below:

```cpp
/**
 * @brief Brief description [REQUIRED]
 * @category x86, Linux, Apple, Windows, All systems [CHOOSE ONE OR MULTIPLE, REQUIRED]
 * @link https://example.com [OPTIONAL]
 * @author add your name here [OPTIONAL]
 * @note add anything that people should know about [OPTIONAL]
 */
[[nodiscard]] static bool example() try {
    if (disabled(YOUR_FUNCTION)) {
        return false;
    }

    #if (!MSVC) // This is a filter in case your function only works for a specific platform. There are many macros such as "LINUX", "MSVC", "APPLE", and "x86". It's also case sensitive, so don't make any typos!
        return false;
    #else

        // add your VM detection code here, make sure to return a boolean (true = VM, false = baremetal)

    #endif
} catch (...) {
    #ifdef __VMAWARE_DEBUG__
        debug("YOUR_FUNCTION: catched error, returned false");
    #endif
    return false;
}
```


some key stuff you should be aware of:
- If you want to make a mechanism that's available only for x86, Linux, MSVC, and Apple, make sure to add the correct preprocessor based on what platforms your function can be ran under.
- Make sure to add `[[nodiscard]]`.
- Add a function try-catch block.
- Copy-paste the same code within the example's catch block for debug reasons. Don't forget to replace the `YOUR_FUNCTION` part with your own unique function flag string within the debug code.
- The library also uses integer size suffixes such as `u8`, `i32`, `u16`, instead of `uint8_t`, `std::int32_t`, or `unsigned short`. The full alias list goes as follows:
```cpp
    using u8  = std::uint8_t;
    using u16 = std::uint16_t;
    using u32 = std::uint32_t;
    using u64 = std::uint64_t;
    using i8  = std::int8_t;
    using i16 = std::int16_t;
    using i32 = std::int32_t;
    using i64 = std::int64_t;
```

So for example, this is the code for a technique that checks CPUID bits (CPUID_0X4) as a reference:
```cpp
/**
 * @brief Check if 0x40000000~0x400000FF cpuid input is present (mostly present in VMs, according to VMware)
 * @link https://kb.vmware.com/s/article/1009458
 * @category x86
 */
[[nodiscard]] static bool cpuid_0x4() try {
    if (disabled(CPUID_0x4)) {
        return false;
    }

    #if (!x86)
        return false;
    #else
        u32 a, b, c, d = 0;

        for (u8 i = 0; i < 0xFF; i++) {
            cpuid(a, b, c, d, (0x40000000, + i));    // don't worry what this does, it's just an example after all
            if ((a + b + c + d) != 0) {
                return true;
            }
        }

        return false;
    #endif
} catch (...) { 
    #ifdef __VMAWARE_DEBUG__
        debug("CPUID_0x4: catched error, returned false");
    #endif
    return false;
}
```

After you have your function ready, CTRL+F again and search for "`__TECHNIQUE_LABEL`", then plop that function below the previous function and that's done for step 4. The hard part is over :)

<br>

# Step 5: Including your function to the technique table
CTRL+F again and search for "`__TABLE_LABEL`". This should show you the place where all the techniques are organised in a `std::map`. To add your own function, follow the format of:
```
{ VM::YOUR_FUNCTION, { POINTS, VM::FUNCTION_PTR }}
```

- `VM::YOUR_FUNCTION`: Your function flag variable 
- `POINTS`: How certain you think a VM has been detected if the function returns true based on a 0-100 score (think of it as a percentage)
- `VM::YOUR_FUNCTION`: The pointer to your function

So this:
```cpp
{ VM::VPC_BACKDOOR, { 70, VM::vpc_backdoor }},
{ VM::PARALLELS_VM, { 50, VM::parallels }},
{ VM::SPEC_RDTSC, { 80, VM::speculative_rdtsc }}
```

Becomes this:
```cpp
{ VM::VPC_BACKDOOR, { 70, VM::vpc_backdoor }},
{ VM::PARALLELS_VM, { 50, VM::parallels }},
{ VM::SPEC_RDTSC, { 80, VM::speculative_rdtsc }},
{ VM::YOUR_FUNCTION, { 50, VM::example }}
```

Double check if your comma placements are valid, as this can cause those cancerous metaprogramming errors in C++ over a single character misplacement lol

<br>
<br>

Hopefully all of this makes sense. If you have any questions, don't hesitate to create an issue or ask me on discord at `kr.nl`