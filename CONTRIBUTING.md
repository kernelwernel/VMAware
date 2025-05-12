# Contribution Guidelines

## I want to add a new technique, how would I do that?
There used to be a complicated process in adding techniques, but that's now been replaced with a tool that prompts you on the new technique details and updates the library code automagically. You can check out the python script at `auxiliary/add_technique.py` 


## I want to make a major change to the library
Depending on how big the change is, if the change is fairly small then just a simple PR is fine. But if it has hundreds of lines of code changes then it's best to create an issue prior to even starting to write the code, or you can discuss it with us discord (`kr.nl` or `shenzken`). 


## I want to contribute but there's something that I don't understand about the library code
You can create an issue, and I will reply within 24 hours. We have too much free time on our hands in reality.


## Extra 
We have an useful script at `auxiliary/updater.py` will update:
- the section line numbers in the header banner
- the date of the update

It's highly recommended to use this script before sending the PR so that all the above don't have to be manually updated, which can be time consuming and can potentially creep in some human errors. 