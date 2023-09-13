- fix the inconsistent naming 
- finish the linux one FIRST
- revise sidt check
- convert makefile to cmake
- fix this:
```
In file included from cli.cpp:1:
./vmaware.hpp:818:39: warning: object backing the pointer will be destroyed at the end of the full-expression [-Wdangling-gsl]
                    const sv vendor = read_file(vendor_file);
                                      ^~~~~~~~~~~~~~~~~~~~
1 warning generated.
```

- ~~create a standard cpuid function (replace __cpuidex bc wine)~~


# distant plans
- add ARM support