# Contribution Guidelines

If you have any questions or inquiries, our contact details are in the README.

## I want to add a new technique, how would I do that?
There's a few steps that should be taken:
1. Make sure to add the technique name in the enums of all the techniques in the appropriate place.
2. Add the technique function itself in the technique section of the library. Make sure to add it in the right place, as there's preprocessor directives for each platform (Linux, Windows, and Apple)
3. Add the technique in the technique table situated at the end of the header file. The score should be between 10 and 100. Although there are exceptions, it's advised to follow the aforementioned score range.





## I want to make a major change to the library
Depending on how big the change is, if the change is fairly small then just a simple PR is fine. But if it has hundreds of lines of code changes then it's best to create an issue prior to even starting to write the code, or you can discuss it with us, either works.

## Extra 
We have a useful script at `auxiliary/updater.py` that will update:
- the section line numbers in the header banner
- the date of the update
- the library documentation

It's highly recommended to use this script before sending the PR so that all the above don't have to be manually updated, which can be time consuming and can potentially creep in some human errors. 
