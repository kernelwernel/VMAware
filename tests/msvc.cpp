#include <Lmcons.h>
#include <windows.h>

#include <bits/stdc++.h> // remove when done

namespace MSVC {

    auto CheckLoadedDLLs = []() -> BOOL {
        std::vector<std::string> real_dlls = {
            "kernel32.dll",
            "networkexplorer.dll",
            "NlsData0000.dll"
        };

        std::vector<std::string> false_dlls = {
            "NetProjW.dll",
            "Ghofr.dll",
            "fg122.dll"
        };

        HMODULE lib_inst;

        for (auto &dll : real_dlls) {
            lib_inst = LoadLibraryA(dll.c_str());
            if (lib_inst == nullptr) {
                return true;
            }
            FreeLibrary(lib_inst);
        }

        for (auto &dll : false_dlls) {
            lib_inst = LoadLibraryA(dll.c_str());
            if (lib_inst != nullptr) {
                return true;
            }
        }

        return false;
    };





    // credits: some guy in a russian underground forum from a screenshot I saw, idk i don't speak russian ¯\_(ツ)_/¯
    auto GetUser = []() -> bool {      
        char user[UNLEN+1];
        DWORD user_len = UNLEN+1;
        GetUserName(user, &user_len);
        return (
            (user == "username") || // ThreadExpert
            (user =="USER") ||      // Sandbox
            (user =="user") ||      // Sandbox 2
            (user =="currentuser")  // Normal
        );
    };

    // credits: same russian guy as above. Whoever you are, ty
    auto CheckSunbelt = []() -> bool {
        return (fs::exists("C:\\analysis"));
    };


    /** 
     * @brief Check if the mouse coordinates have changed after 5 seconds
     * @note Doing this on linux is a major pain bc it requires X11 linkage and it isn't universally supported
     * @note Some VMs are automatic without a human due to mass malware scanning being a thing
     * @note Disabled by default due to performance reasons
     */
    auto CursorCheck = []() -> bool {
        POINT pos1, pos2;
        GetCursorPos(&pos1);
        Sleep(5000);
        GetCursorPos(&pos2);

        return ((pos1.x == pos2.x) && (pos1.y == pos2.y));
    }


    // find vmware tools presence
    auto VMwareCheck = []() -> bool {
        try {
            HKEY hKey = 0;
            DWORD dwType = REG_SZ;
            char buf[0xFF] = {0};
            DWORD dwBufSize = sizeof(buf);
            return (RegOpenKeyEx(TEXT("SOFTWARE\\VMware, Inc.\\VMware Tools"), 0, KEY_QUERY_VALUE, &hKey ) == ERROR_SUCCESS);
        } catch (...) { return false; }
    }




    // Check vbox rdrdn
    auto VBoxCheck = []() -> bool {
        try {
            HANDLE handle = CreateFile(_T("\\\\.\\VBoxMiniRdrDN"), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (handle != INVALID_HANDLE_VALUE) {
                CloseHandle(handle);
                return true;
            }
            return false;
        } catch (...) { return false; }
    };




    auto RegKeyVM = []() -> bool {
        uint8_t score = 0;

        auto key = [&score](const std::string_view regkey_sv) -> void {
            HKEY regkey;
            LONG ret;
            BOOL isWow64 = FALSE;
            LPCSTR regkey_s = regkey_sv.data();

            if (IsWow64Process(GetCurrentProcess(), &isWow64) && isWow64) { 
                ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE, regkey_s, 0, KEY_READ | KEY_WOW64_64KEY, &regkey);
            } else { 
                ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE, regkey_s, 0, KEY_READ, &regkey);
            }

            if (ret == ERROR_SUCCESS) {
                RegCloseKey(regkey);
                score++;
                return;
            } else { 
                return;
            }
        };

        // general
        key("HKLM\\Software\\Classes\\Folder\\shell\\sandbox");

        // hyper-v
        key("HKLM\\SOFTWARE\\Microsoft\\Hyper-V");
        key("HKLM\\SOFTWARE\\Microsoft\\VirtualMachine");
        key("HKLM\\SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters");
        key("HKLM\\SYSTEM\\ControlSet001\\Services\\vmicheartbeat");
        key("HKLM\\SYSTEM\\ControlSet001\\Services\\vmicvss");
        key("HKLM\\SYSTEM\\ControlSet001\\Services\\vmicshutdown");
        key("HKLM\\SYSTEM\\ControlSet001\\Services\\vmicexchange");

        // parallels
        key("HKLM\\SYSTEM\\CurrentControlSet\\Enum\\PCI\\VEN_1AB8*");

        // sandboxie
        key("HKLM\\SYSTEM\\CurrentControlSet\\Services\\SbieDrv");
        key("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Sandboxie");

        // virtualbox
        key("HKLM\\SYSTEM\\CurrentControlSet\\Enum\\PCI\\VEN_80EE*");
        key("HKLM\\HARDWARE\\ACPI\\DSDT\\VBOX__");
        key("HKLM\\HARDWARE\\ACPI\\FADT\\VBOX__");
        key("HKLM\\HARDWARE\\ACPI\\RSDT\\VBOX__");
        key("HKLM\\SOFTWARE\\Oracle\\VirtualBox Guest Additions");
        key("HKLM\\SYSTEM\\ControlSet001\\Services\\VBoxGuest");
        key("HKLM\\SYSTEM\\ControlSet001\\Services\\VBoxMouse");
        key("HKLM\\SYSTEM\\ControlSet001\\Services\\VBoxService");
        key("HKLM\\SYSTEM\\ControlSet001\\Services\\VBoxSF");
        key("HKLM\\SYSTEM\\ControlSet001\\Services\\VBoxVideo");

        // virtualpc
        key("HKLM\\SYSTEM\\CurrentControlSet\\Enum\\PCI\\VEN_5333*");
        key("HKLM\\SYSTEM\\ControlSet001\\Services\\vpcbus");
        key("HKLM\\SYSTEM\\ControlSet001\\Services\\vpc-s3");
        key("HKLM\\SYSTEM\\ControlSet001\\Services\\vpcuhub");
        key("HKLM\\SYSTEM\\ControlSet001\\Services\\msvmmouf");

        // vmware
        key("HKLM\\SYSTEM\\CurrentControlSet\\Enum\\PCI\\VEN_15AD*");
        key("HKCU\\SOFTWARE\\VMware, Inc.\\VMware Tools");
        key("HKLM\\SOFTWARE\\VMware, Inc.\\VMware Tools");
        key("HKLM\\SYSTEM\\ControlSet001\\Services\\vmdebug");
        key("HKLM\\SYSTEM\\ControlSet001\\Services\\vmmouse");
        key("HKLM\\SYSTEM\\ControlSet001\\Services\\VMTools");
        key("HKLM\\SYSTEM\\ControlSet001\\Services\\VMMEMCTL");
        key("HKLM\\SYSTEM\\ControlSet001\\Services\\vmware");
        key("HKLM\\SYSTEM\\ControlSet001\\Services\\vmci");
        key("HKLM\\SYSTEM\\ControlSet001\\Services\\vmx86");
        key("HKLM\\SYSTEM\\CurrentControlSet\\Enum\\IDE\\CdRomNECVMWar_VMware_IDE_CD*");
        key("HKLM\\SYSTEM\\CurrentControlSet\\Enum\\IDE\\CdRomNECVMWar_VMware_SATA_CD*");
        key("HKLM\\SYSTEM\\CurrentControlSet\\Enum\\IDE\\DiskVMware_Virtual_IDE_Hard_Drive*");
        key("HKLM\\SYSTEM\\CurrentControlSet\\Enum\\IDE\\DiskVMware_Virtual_SATA_Hard_Drive*");

        // wine
        key("HKCU\\SOFTWARE\\Wine");
        key("HKLM\\SOFTWARE\\Wine");

        // xen
        key("HKLM\\HARDWARE\\ACPI\\DSDT\\xen");
        key("HKLM\\HARDWARE\\ACPI\\FADT\\xen");
        key("HKLM\\HARDWARE\\ACPI\\RSDT\\xen");
        key("HKLM\\SYSTEM\\ControlSet001\\Services\\xenevtchn");
        key("HKLM\\SYSTEM\\ControlSet001\\Services\\xennet");
        key("HKLM\\SYSTEM\\ControlSet001\\Services\\xennet6");
        key("HKLM\\SYSTEM\\ControlSet001\\Services\\xensvc");
        key("HKLM\\SYSTEM\\ControlSet001\\Services\\xenvdb");
        return (score >= 1);
    };


}