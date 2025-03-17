- [ ] add C++20 concepts for the VM::add_custom() function
- [ ] add c++20 module support 
- [ ] upload the lib to dnf 
- [ ] upload the lib to apt 
- [ ] make a man file in markdown for the cli tool
- [ ] implement techniques from here https://stackoverflow.com/questions/43026032/detect-running-on-virtual-machine
- [ ] add a .clang_format thingy
- [ ] make a medium post about it
- [ ] check if bios date in /sys/class/dmi/id/ could be useful under QEMU
- [ ] add a .so, .dll, and .dylib shared object files in the release 
- [ ] fix the issue of VM::QEMU_USB being ultra slow in some edge-cases
- [ ] /sys/class/dmi/id/product_name check this in qemu
- [ ] add linux support for the hdd_serial_number technique
- [ ] fix "dmidecode not found" error
- [ ] fix /dev/mem not found in vbox default
- [ ] update sourceforge
- [ ] rearrange the techniques so that the more likely ones will be executed first
- [ ] make a hardware scanner module where it'll find for VM strings in all sorts of devices
- [ ] add more QEMU techniques
- [ ] implement techniques from here https://www.cyberciti.biz/faq/linux-determine-virtualization-technology-command/
- [ ] implement techniques from virt-what
- [ ] https://cloud.google.com/compute/docs/instances/detect-compute-engine
- [ ] update the updater.py script and fix it
- [ ] @thereisnospoon this is where we need to start modifing the qemu source further by replacing vendor/device ids.
https://www.pcilookup.com/
- [ ] https://wasm.in/threads/testy-v-vmware.35315/#post-444576
 
QEMU default: 0x1234
Intel: 0x8086
AMD: 0x1022
VMware: 0x15ad
Red Hat/Qumranet: 0x1af4
In the QEMU source:
include/hw/pci/pci.h
include/hw/pci/pci_ids.h

# Distant plans
- add the library to conan.io when released
- add a python version of the library (or any other lang for that matter)
- add a GUI version of the lib
- add a rust version of the lib
- submit the project to oss-fuzz 
