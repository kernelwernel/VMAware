# Contribution Guidelines


Please consider adding your name and github in the vmaware.hpp file and the README's credit sections. Your work is valuable to us, and we want to credit you for the improvements you've made. 


## Translations
If you're making translations, please make sure that you have the intention to be as accurate as possible. If you're unsure which parts should be translated or not, you can use the other translated files as a reference to guide you.

Using translation software like google translate is allowed, but only if you cross-check between the english and translation version to verify if it's done correctly.

The README is quite big, so this is quite an effort. I'm sure you have better thing to do in your life but if you can do this, it would be greatly appreciated :)


## Code contributions
The general rules are:
- Keep it C++11 compatible, this is extremely important
- Use snake_case 
- Be as simple as possible
- Prefer readability over aggressive optimisations (especially intrinsics)
- Keep indentations at a minimum
- Don't create huge one-liners, try to break down statements line by line
- Write as few lines as possible for what you're trying to achieve
- Document your code and intentions very clearly, but don't overdo them for very obvious code
- Avoid `std::function`, `std::shared_ptr`, `std::bind`, `std::list`, or very obscure C++ features
- Indent size should be 4 spaces
- Use "We" instead of the first person when commenting

There are other formatting rules, which will be covered with a demonstration:

```cpp
int main() {
    const u32 number = 10; // 1. use const whenever it should be used.
                           // 2. use the rust integral type convention from 8 to 64 (i.e. i8, u16, u64, etc...)
                           // 3. keep the names as simple and clear as possible, don't call it "n", call it "number".
                           //    Try to name the variables into something that can universally be discerned by anybody,
                           //    Make sure it's also context-aware and should make sense. Calling it "tmp" is also fine.
                           //    Consistency is also key in this aspect, don't do "u32 number = find_num()", do find_number(). 

    if (number >= 54) { // 4. avoid magic numbers, put a comment or make a constexpr variable prior to using it,
        something();    //    preferably the latter.
    } else if (number) {  // 5. make the if, else if, and else statement lines the same without breaking lines, so don't do:
        something_else(); //    if () 
    }                     //    {
                          //       something();
                          //    }
                          //    else 
                          //    {
                          //       something_else(); 
                          //    }
                          //    
                          // try to follow as shown in this actual demonstration.

    if (
        ((number % 4) == 0) && // 6. use separate lines for each statement of a condition check. While this might look ok
        (number > 50) &&       //    on a single line, in practice your conditions will most likely not be as short and 
        (number < 100)         //    and simple as this. Try to avoid multiple condition checks in a single line for simplicity.
    ) {
        something()
    }


    for (u8 i = 0; i < number; i++) { // 6. Be as simple as possible without using fancy features like iterators if it's not necessary.
        something();
    }

    // Other rules will be added in the future, this is just a rough guideline for the moment.
}
```

## I want to add a new technique, how would I do that?
There's a few steps that should be taken:
1. Make sure to add the technique name in the enums of all the techniques in the appropriate place.
2. Add the technique function itself in the technique section of the library. Make sure to add it in the right place, as there's preprocessor directives for each platform (Linux, Windows, and Apple)
3. Add the technique in the technique table situated at the end of the header file. The score should be between 10 and 100. Although there are exceptions, it's advised to follow the aforementioned score range.
4. Add it to the CLI's technique runner list.


## I want to make a major change to the library
Depending on how big the change is, if the change is fairly small then just a simple PR is fine. But if it has hundreds of lines of code changes then it's best to create an issue prior to even starting to write the code, or you can discuss it with us, either works.


## I want to contribute in any way but I'm not sure what to do or where to start
One of the main demands at the moment is creating cross-compatibility for techniques as much as possible. Many techniques in the library are platform specific, but some of those can have shared detection vectors that are implementable on other platforms as well. For example, our firmware technique used to be limited to Windows but we've extended it to support Linux as well. This is a good way to start contributing to the project, so pick any technique to your liking that's applicable to a cross-platform implementation and we'll more than likely accept your change with open arms. You don't need to understand the whole architecture of the project, just a quick glance at a single technique function is all you need. Additionally, we have a [TODO](TODO.md) file at the root of the project that explains the things we need to do, although it's a bit outdated and rarely ever used. Either paths are a good starting point.


## Notes 
If you have any questions or inquiries, our contact details are in the README.
