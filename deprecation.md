> [!WARNING]
> The library has been deprecated as of 1.7.1 release **only for production environments**. 
>
> In other words, the library should NOT be used for critical projects where an integral program (anticheat, paid software, etc...) or anything serious where a false detection of a VM could be catastrophic. The library should now instead be used as an interactive toy piece of C++ code for people to play around with in a non-serious manner.
> 
> The CLI is not affected by this usage deprecation, however, as the CLI was already treated as a toy program from the start.
> 
> 
> The deprecation is due to a few reasons:
> ## 1. **Hyper-V:** 
> - Microsoft's Hyper-V has been a complete nightmare since this project began. It took me and [@Requiem](https://github.com/NotRequiem) a while to discover that Hyper-V (upon installation) changes hardware values by making it seem it's actually running in a VM even though the program is running on the host [[example](https://github.com/kernelwernel/VMAware/issues/75)]. This mechanism is even worse considering that Windows 11 has Hyper-V installed by default, making Windows 11 completely impossible to detect whether it's running in a manually intended Hyper-V VM by the user, or the leftover artifacts of what Hyper-V vomited all over the system when it was installed, which gave the library a false positive on the host system. Although Windows 10 must allow the user to install Hyper-V manually, this does not make the issue any better to handle for us. Hyper-V has been the main reason why I can't sleep well at night for the past half a year.
> 
> ## 2. **Spoofability:** 
> - The library does tackle spoofable techniques by skipping over them by default, unless whether `VM::SPOOFABLE` (for the library) or `--spoofable` (for the CLI) options were given. Although this is a fairly practical way to combat against the "easily" spoofable techniques, everything is technically spoofable. One anti-anti-VM project called [VMwareHardenedLoader](https://github.com/hzqst/VmwareHardenedLoader) is at a massive advantage against the library, and there's nothing we can do about it realistically. The library struggled to find anything of value EVEN with spoofable techniques enabled. There's also the problem that 1/3 of all the techniques in the library are considered "spoofable". It doesn't take a genius to figure out that this is a really bad VM detection library if 33% of all techniques can't be ran by default. 
> 
> ## 3. **Practicality:** 
> - The main goal of the project was for the aforementioned category of "integral" programs to detect a VM in a practical and convenient way. If we knew the full extent of the pitfalls (the Hyper-V and spoofability problems mentioned above) from the start, this project wouldn't had been designed with this intention. What I thought was a practical library when starting out has now turned into an ineffective edgecase hell the more we discovered about the reality of VM detections. Not only this, there's the assumption of the fact that this library could be used by serious devs (or worse, companies) who might have a false sense of integrity for how effective the library is for their software. For example, having a gamer get declined to run their newly bought game because the library falsely detected the system to be a Hyper-V VM is an absolute fucking nuclear proportion disaster.
> 
> This is just a deprecation of **how** the library should be used, however. Development will still continue as usual, and the library will be improved more and more as time passes. But the core issues that were mentioned will linger, and the deprecation will not be lifted for a while unless a solution will be discovered.


## TL;DR: Too many spoofable techniques, library has become impractial, Hyper-V makes me want to kill myself in an infinite loop of an infinite lifetimes.