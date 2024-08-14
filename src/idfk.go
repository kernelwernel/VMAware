//go:build linux
// +build linux

package vmdetect

import (
	"bytes"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"
	"time"
)

/*
Checks if the DMI table contains vendor strings of known VMs.
*/
func checkDMITable() bool {

	//  /!\ All lowercase /!\
	blacklistDMI := []string{
		"innotek",
		"virtualbox",
		"vbox",
		"kvm",
		"qemu",
		"vmware",
		"vmw",
		"oracle",
		"xen",
		"bochs",
		"parallels",
		"bhyve",
	}

	dmiPath := "/sys/class/dmi/id/"
	dmiFiles, err := ioutil.ReadDir(dmiPath)

	if err != nil {
		PrintError(err)
		return false
	}

	for _, dmiEntry := range dmiFiles {
		if !dmiEntry.Mode().IsRegular() {
			continue
		}

		dmiContent, err := ioutil.ReadFile(filepath.Join(dmiPath, dmiEntry.Name()))

		if err != nil {
			PrintError(err)
			continue
		}

		for _, entry := range blacklistDMI {
			// Lowercase comparison to prevent false negatives
			if bytes.Contains(bytes.ToLower(dmiContent), []byte(entry)) {
				return true
			}
		}
	}

	return false
}

/*
Checks printk messages to see if Linux detected an hypervisor.
https://github.com/torvalds/linux/blob/31cc088a4f5d83481c6f5041bd6eb06115b974af/arch/x86/kernel/cpu/hypervisor.c#L79
*/
func checkKernelRingBuffer() bool {

	file, err := os.Open("/dev/kmsg")

	if err != nil {
		PrintError(err)
		return false
	}

	defer file.Close()

	// Set a read timeout because otherwise reading kmsg (which is a character device) will block
	if err = file.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		PrintError(err)
		return false
	}

	return DoesFileContain(file, "Hypervisor detected")
}


/*
Some GNU/Linux distributions expose /proc/sysinfo containing potential VM info
https://www.ibm.com/support/knowledgecenter/en/linuxonibm/com.ibm.linux.z.lhdd/lhdd_t_sysinfo.html
*/
func checkSysInfo() bool {
	file, err := os.Open("/proc/sysinfo")

	if err != nil {
		PrintError(err)
		return false
	}

	defer file.Close()

	return DoesFileContain(file, "VM00")
}

/*
Some virtualization technologies can be detected using /proc/device-tree
*/
func checkDeviceTree() bool {
	deviceTreeBase := "/proc/device-tree"

	if DoesFileExist(filepath.Join(deviceTreeBase, "/hypervisor/compatible")) {
		return true
	}

	if DoesFileExist(filepath.Join(deviceTreeBase, "/fw-cfg")) {
		return true
	}

	return false
}

/*
Some virtualization technologies can be detected using /proc/type
*/
func checkHypervisorType() bool {
	return DoesFileExist("/sys/hypervisor/type")
}

/*
Xen can be detected thanks to /proc/xen
*/
func checkXenProcFile() bool {
	return DoesFileExist("/proc/xen")
}

func checkKernelModules() bool {

	file, err := os.Open("/proc/modules")

	if err != nil {
		PrintError(err)
		return false
	}

	return DoesFileContain(file, "vboxguest")
}

/*
Public function returning true if a VM is detected.
If so, a non-empty string is also returned to tell how it was detected.
*/
func IsRunningInVirtualMachine() (bool, string) {

	if currentUser, _ := user.Current(); currentUser != nil && currentUser.Uid != "0" {
		PrintWarning("Unprivileged user detected, some techniques might not work")
	}

	if vmDetected, how := CommonChecks(); vmDetected {
		return vmDetected, how
	}

	if checkKernelModules() {
		return true, "Kernel module (/proc/modules)"
	}

	if checkUML() {
		return true, "CPU Vendor (/proc/cpuinfo)"
	}

	if checkSysInfo() {
		return true, "System Information (/proc/sysinfo)"
	}

	if checkDMITable() {
		return true, "DMI Table (/sys/class/dmi/id/*)"
	}

	if checkKernelRingBuffer() {
		return true, "Kernel Ring Buffer (/dev/kmsg)"
	}

	if checkDeviceTree() {
		return true, "VM device tree (/proc/device-tree)"
	}

	if checkXenProcFile() {
		return true, "Xen proc file (/proc/xen)"
	}

	return false, "nothing"
}