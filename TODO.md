- [ ] add C++20 concepts for the VM::add_custom() function
- [ ] add c++20 module support 
- [ ] upload the lib to dnf 
- [ ] upload the lib to apt 
- [ ] make a man file in markdown for the cli tool
- [ ] implement techniques from here https://stackoverflow.com/questions/43026032/detect-running-on-virtual-machine
- [ ] check if bios date in /sys/class/dmi/id/ could be useful under QEMU
- [ ] add a .so, .dll, and .dylib shared object files in the release 
- [ ] /sys/class/dmi/id/product_name check this in qemu
- [ ] fix "dmidecode not found" error
- [ ] implement techniques from here https://www.cyberciti.biz/faq/linux-determine-virtualization-technology-command/
- [ ] implement techniques from virt-what
- implement empty /sys/class dirs:
    - iommu
    - power_supply
- check for presence of /dev/virtio-ports dir
- replace all thread mismatch techniques to C style arrays


# Distant plans
- add the library to conan.io when released
- add a python version of the library (or any other lang for that matter)
- add a GUI version of the lib
- add a rust version of the lib
- submit the project to oss-fuzz 
