            // check dsdt vbox
            auto VboxCheck2 = []() -> bool {
                try {
                    return (RegOpenKeyEx("HARDWARE\\ACPI\\DSDT\\VBOX__", NULL, KEY_READ, &resultKey) == ERROR_SUCCESS);
                } catch (...) { return false; }
            };

            auto VPC = []() -> bool {
                try {
                    auto IsInsideVPC_exceptionFilter = [](LPEXCEPTION_POINTERS ep) -> DWORD {
                        PCONTEXT ctx = ep->ContextRecord;
                        ctx->Ebx = -1;
                        ctx->Eip += 4;
                        return EXCEPTION_CONTINUE_EXECUTION;
                    };

                    auto InsideVPC = []() -> bool {
                        bool rc = false;
                        __try {
                            _asm push ebx
                            _asm mov  ebx, 0
                            _asm mov  eax, 1
                            _asm __emit 0Fh
                            _asm __emit 3Fh
                            _asm __emit 07h
                            _asm __emit 0Bh
                            _asm test ebx, ebx
                            _asm setz [rc]
                            _asm pop ebx
                        } __except(IsInsideVPC_exceptionFilter(GetExceptionInformation())) {};

                        return rc;
                    };
                } catch (...) { return false; }
            }

            auto CheckSandboxie = []() {
                BYTE IsSB = 0;
                ULONG hashA, hashB;
                HANDLE hKey;
                NTSTATUS Status;
                UNICODE_STRING ustrRegPath;
                OBJECT_ATTRIBUTES obja;

                WCHAR szObjectName[MAX_PATH * 2] = {0};
                hashA = HashFromStrW(REGSTR_KEY_USER);

                RtlInitUnicodeString(&ustrRegPath, REGSTR_KEY_USER);
                InitializeObjectAttributes(&obja, &ustrRegPath, OBJ_CASE_SENSITIVE, NULL, NULL);
                Status = NtOpenKey(&hKey, MAXIMUM_ALLOWED, &obja);
                if (NT_SUCCESS(Status)) {
                    if (QueryObjectName((HKEY)hKey, &szObjectName, MAX_PATH * 2, TRUE)) {
                        hashB = HashFromStrW(szObjectName);
                        if (hashB != hashA) { IsSB = 1; }
                    }
                    NtClose(hKey);
                }
                return IsSB;
            };

            // ================ REGISTRY SEARCHES ================

    
            auto RegKeyStrSearch = []() -> bool {
                uint8_t score = 0;
                auto findkey = [](HKEY hKey, char * regkey_s, char * value_s, char * lookup) -> void {
                    HKEY regkey;
                    LONG ret;
                    DWORD size;
                    char value[1024], * lookup_str;
                    size_t lookup_size;

                    lookup_size = strlen(lookup);
                    lookup_str = malloc(lookup_size+sizeof(char));
                    strncpy(lookup_str, lookup, lookup_size+sizeof(char));
                    size = sizeof(value);

                    if (pafish_iswow64()) {
                        ret = RegOpenKeyEx(hKey, regkey_s, 0, KEY_READ | KEY_WOW64_64KEY, &regkey);
                    }
                    else {
                        ret = RegOpenKeyEx(hKey, regkey_s, 0, KEY_READ, &regkey);
                    }

                    if (ret == ERROR_SUCCESS) {
                        ret = RegQueryValueEx(regkey, value_s, NULL, NULL, (BYTE*)value, &size);
                        RegCloseKey(regkey);

                        if (ret == ERROR_SUCCESS) {
                            size_t i;
                            for (i = 0; i < strlen(value); i++) {
                                value[i] = toupper(value[i]);
                            }
                            for (i = 0; i < lookup_size; i++) {
                                lookup_str[i] = toupper(lookup_str[i]);
                            }
                            if (strstr(value, lookup_str) != NULL) {
                                free(lookup_str);
                                score++
                                return;
                            }
                        }
                    }

                    free(lookup_str);
                    return;
                };

                // general
                findkey("HKLM\\HARDWARE\\Description\\System", "SystemBiosDate", "06/23/99");
                findkey("HKLM\\HARDWARE\\Description\\System\\BIOS", "SystemProductName", "A M I");

                // bochs
                findkey("HKLM\\HARDWARE\\Description\\System", "SystemBiosVersion", "BOCHS");
                findkey("HKLM\\HARDWARE\\Description\\System", "VideoBiosVersion", "BOCHS");

                // anubis
                findkey("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion", "ProductID", "76487-337-8429955-22614");
                findkey("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ProductID", "76487-337-8429955-22614");

                // cwsandbox
                findkey("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion", "ProductID", "76487-644-3177037-23510");
                findkey("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ProductID", "76487-644-3177037-23510");

                // joebox
                findkey("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion", "ProductID", "55274-640-2673064-23950");
                findkey("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ProductID", "55274-640-2673064-23950");

                // parallels
                findkey("HKLM\\HARDWARE\\Description\\System", "SystemBiosVersion", "PARALLELS");
                findkey("HKLM\\HARDWARE\\Description\\System", "VideoBiosVersion", "PARALLELS");

                // qemu
                findkey("HKLM\\HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier", "QEMU");
                findkey("HKLM\\HARDWARE\\Description\\System", "SystemBiosVersion", "QEMU");
                findkey("HKLM\\HARDWARE\\Description\\System", "VideoBiosVersion", "QEMU");
                findkey("HKLM\\HARDWARE\\Description\\System\\BIOS", "SystemManufacturer", "QEMU");

                // virtualbox
                findkey("HKLM\\HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "", "");
                findkey("HKLM\\HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 1\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "", "");
                findkey("HKLM\\HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 2\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "", "");
                findkey("HKLM\\HARDWARE\\Description\\System", "SystemBiosVersion", "VBOX");
                findkey("HKLM\\HARDWARE\\Description\\System", "VideoBiosVersion", "VIRTUALBOX");
                findkey("HKLM\\HARDWARE\\Description\\System\\BIOS", "SystemProductName", "VIRTUAL");
                findkey("HKLM\\SYSTEM\\ControlSet001\\Services\\Disk\\Enum", "DeviceDesc", "VBOX");
                findkey("HKLM\\SYSTEM\\ControlSet001\\Services\\Disk\\Enum", "FriendlyName", "VBOX");
                findkey("HKLM\\SYSTEM\\ControlSet002\\Services\\Disk\\Enum", "DeviceDesc", "VBOX");
                findkey("HKLM\\SYSTEM\\ControlSet002\\Services\\Disk\\Enum", "FriendlyName", "VBOX");
                findkey("HKLM\\SYSTEM\\ControlSet003\\Services\\Disk\\Enum", "DeviceDesc", "VBOX");
                findkey("HKLM\\SYSTEM\\ControlSet004\\Services\\Disk\\Enum", "FriendlyName", "VBOX");
                findkey("HKLM\\SYSTEM\\CurrentControlSet\\Control\\SystemInformation", "SystemProductName", "VIRTUAL");
                findkey("HKLM\\SYSTEM\\CurrentControlSet\\Control\\SystemInformation", "SystemProductName", "VIRTUALBOX");

                // vmware
                findkey("HKLM\\HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier", "VMWARE");
                findkey("HKLM\\HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 1\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier", "VMWARE");
                findkey("HKLM\\HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 2\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier", "VMWARE");
                findkey("HKLM\\HARDWARE\\Description\\System", "SystemBiosVersion", "VMWARE");
                findkey("HKLM\\HARDWARE\\Description\\System", "SystemBiosVersion", "INTEL - 6040000");
                findkey("HKLM\\HARDWARE\\Description\\System", "VideoBiosVersion", "VMWARE");
                findkey("HKLM\\HARDWARE\\Description\\System\\BIOS", "", "");
                findkey("HKLM\\SYSTEM\\ControlSet001\\Services\\Disk\\Enum", "0", "VMware");
                findkey("HKLM\\SYSTEM\\ControlSet001\\Services\\Disk\\Enum", "1", "VMware");
                findkey("HKLM\\SYSTEM\\ControlSet001\\Services\\Disk\\Enum", "DeviceDesc", "VMware");
                findkey("HKLM\\SYSTEM\\ControlSet001\\Services\\Disk\\Enum", "FriendlyName", "VMware");
                findkey("HKLM\\SYSTEM\\ControlSet002\\Services\\Disk\\Enum", "DeviceDesc", "VMware");
                findkey("HKLM\\SYSTEM\\ControlSet002\\Services\\Disk\\Enum", "FriendlyName", "VMware");
                findkey("HKLM\\SYSTEM\\ControlSet003\\Services\\Disk\\Enum", "DeviceDesc", "VMware");
                findkey("HKLM\\SYSTEM\\ControlSet003\\Services\\Disk\\Enum", "FriendlyName", "VMware");
                findkey("HKCR\\Installer\\Products", "ProductName", "vmware tools");
                findkey("HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", "DisplayName", "vmware tools");
                findkey("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", "DisplayName", "vmware tools");
                findkey("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", "DisplayName", "vmware tools");
                findkey("HKLM\\SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000", "CoInstallers32", "*vmx*");
                findkey("HKLM\\SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000", "DriverDesc", "VMware*");
                findkey("HKLM\\SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000", "InfSection", "vmx*");
                findkey("HKLM\\SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000", "ProviderName", "VMware*");
                findkey("HKLM\\SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000\\Settings", "Device Description", "VMware*");
                findkey("HKLM\\SYSTEM\\CurrentControlSet\\Control\\SystemInformation", "SystemProductName", "VMWARE");
                findkey("HKLM\\SYSTEM\\CurrentControlSet\\Control\\Video\\{GUID}\\Video", "Service", "vm3dmp");
                findkey("HKLM\\SYSTEM\\CurrentControlSet\\Control\\Video\\{GUID}\\Video", "Service", "vmx_svga");
                findkey("HKLM\\SYSTEM\\CurrentControlSet\\Control\\Video\\{GUID}\\0000", "Device Description", "VMware SVGA*");
                findkey("HKLM\\HARDWARE\\Description\\System\\BIOS", "SystemProductName", "Xen");

                std::cout << "score: " << score << "\n";
                return true;
            };








            
            // check against some of VMware blacklisted files
            auto VMwareFiles = []() -> bool {
                TCHAR* szPaths[] = {
                    // vmware
                    _T("system32\\drivers\\vmmouse.sys"),
                    _T("system32\\drivers\\vmhgfs.sys"),
                    _T("system32\\drivers\\hgfs.sys"),
                    _T("system32\\drivers\\vmx86.sys"),
                    _T("system32\\drivers\\vmxnet.sys"),
                    _T("system32\\drivers\\vmnet.sys"),

                    // virtualpc
                    _T("system32\\drivers\\vpc-s3.sys"),
                    _T("system32\\drivers\\vmsrvc.sys"),

                    // vbox
                    _T("system32\\drivers\\VBoxMouse.sys"), 	
                    _T("system32\\drivers\\VBoxGuest.sys"), 	
                    _T("system32\\drivers\\VBoxSF.sys"), 	
                    _T("system32\\drivers\\VBoxVideo.sys"), 	
                    _T("system32\\vboxdisp.dll"), 	
                    _T("system32\\vboxhook.dll"), 	
                    _T("system32\\vboxmrxnp.dll"), 	
                    _T("system32\\vboxogl.dll"), 	
                    _T("system32\\vboxoglarrayspu.dll"), 	
                    _T("system32\\vboxoglcrutil.dll"), 	
                    _T("system32\\vboxoglerrorspu.dll"), 	
                    _T("system32\\vboxoglfeedbackspu.dll"), 	
                    _T("system32\\vboxoglpackspu.dll"), 	
                    _T("system32\\vboxoglpassthroughspu.dll"), 	
                    _T("system32\\vboxservice.exe"), 	
                    _T("system32\\vboxtray.exe"), 	
                    _T("system32\\VBoxControl.exe"),

                    // parallels 	
                    _T("system32\\drivers\\prleth.sys"),
                    _T("system32\\drivers\\prlfs.sys"),
                    _T("system32\\drivers\\prlmouse.sys"),
                    _T("system32\\drivers\\prlvideo.sys"),
                    _T("system32\\drivers\\prltime.sys"),
                    _T("system32\\drivers\\prl_pv32.sys"),
                    _T("system32\\drivers\\prl_paravirt_32.sys")
                };
                
                WORD dwlength = sizeof(szPaths) / sizeof(szPaths[0]);
                TCHAR szWinDir[MAX_PATH] = _T("");
                TCHAR szPath[MAX_PATH] = _T("");
                GetWindowsDirectory(szWinDir, MAX_PATH);
                
                for (size_t i = 0; i < dwlength; i++)
                {
                    PathCombine(szPath, szWinDir, szPaths[i]);
                    TCHAR msg[256] = _T("");
                    if (fs::exists(szPath)) { return true; }
                }
                return false;
            };












            auto VMwareDir = []() -> bool {
                TCHAR szProgramFile[MAX_PATH];
                TCHAR szPath[MAX_PATH] = _T("");
                TCHAR szTarget[MAX_PATH] = _T("VMware\\");
                if (IsWoW64()) { ExpandEnvironmentStrings(_T("%ProgramW6432%"), szProgramFile, ARRAYSIZE(szProgramFile)); }
                else { SHGetSpecialFolderPath(NULL, szProgramFile, CSIDL_PROGRAM_FILES, FALSE); }
                PathCombine(szPath, szProgramFile, szTarget);
                return fs::exists(szPath);
            };










            auto SandboxPath = []() -> bool {
                char path[500];
                size_t i;
                DWORD pathsize = sizeof(path);

                GetModuleFileName(NULL, path, pathsize);

                for (i = 0; i < strlen(path); i++) {
                    path[i] = toupper(path[i]);
                }

                return ((strstr(path, "\\SAMPLE") != NULL) || (strstr(path, "\\VIRUS") != NULL) || (strstr(path, "SANDBOX") != NULL));
            };







            // ================== UI ==================
            auto VboxUIWindow = []() -> bool {
                HWND hClass = FindWindow(_T("VBoxTrayToolWndClass"), NULL);
                HWND hWindow = FindWindow(NULL, _T("VBoxTrayToolWnd"));
                return (hClass || hWindow);
            };



            auto enumWindowsCheck = [](bool& detected) -> bool {
                auto enumProc = [](HWND, LPARAM lParam) -> bool {
                    if (LPDWORD pCnt = reinterpret_cast<LPDWORD>(lParam)) { *pCnt++; }
                    return true;
                };

                DWORD winCnt = 0;

                if (!EnumWindows(enumProc,LPARAM(&winCnt))) { return false; }

                return (winCnt < 10);
            };



            // ====================== TIME ======================
            auto MeasureTime = []() -> bool {
                auto Timeskip1 = []() -> bool {
                    DWORD StartingTick, TimeElapsedMs;
                    LARGE_INTEGER DueTime;
                    HANDLE hTimer = NULL;
                    TIMER_BASIC_INFORMATION TimerInformation;
                    ULONG ReturnLength;

                    hTimer = CreateWaitableTimer(NULL, TRUE, NULL);
                    DueTime.QuadPart = Timeout * (-10000LL);

                    StartingTick = GetTickCount();
                    SetWaitableTimer(hTimer, &DueTime, 0, NULL, NULL, 0);
                    do {
                        Sleep(Timeout/10);
                        NtQueryTimer(hTimer, TimerBasicInformation, &TimerInformation, sizeof(TIMER_BASIC_INFORMATION), &ReturnLength);
                    } while (!TimerInformation.TimerState);

                    CloseHandle(hTimer);

                    TimeElapsedMs = GetTickCount() - StartingTick;
                    return (abs((LONG)(TimeElapsedMs - Timeout)) > Timeout / 2);
                };

                auto Timeskip2 = []() -> bool {
                    LARGE_INTEGER StartingTime, EndingTime;
                    LARGE_INTEGER Frequency;
                    DWORD TimeElapsedMs;

                    QueryPerformanceFrequency(&Frequency);
                    QueryPerformanceCounter(&StartingTime);

                    Sleep(Timeout);

                    QueryPerformanceCounter(&EndingTime);
                    TimeElapsedMs = (DWORD)(1000ll * (EndingTime.QuadPart - StartingTime.QuadPart) / Frequency.QuadPart);
                    return (abs((LONG)(TimeElapsedMs - Timeout)) > Timeout / 2);
                };

                auto Timeskip3 = []() -> bool {
                    ULONGLONG tick;
                    DWORD TimeElapsedMs;

                    tick = GetTickCount64();
                    Sleep(Timeout);
                    TimeElapsedMs = GetTickCount64() - tick;

                    printf("Requested delay: %d, elapsed time: %d\n", Timeout, TimeElapsedMs);

                    return (abs((LONG)(TimeElapsedMs - Timeout)) > Timeout / 2);
                };

                auto SysTime = []() -> bool {
                    SYSTEM_TIME_OF_DAY_INFORMATION  SysTimeInfo;
                    ULONGLONG time;
                    LONGLONG diff;

                    Sleep(60000); // should trigger sleep skipping
                    GetSystemTimeAsFileTime((LPFILETIME)&time);

                    NtQuerySystemInformation(SystemTimeOfDayInformation, &SysTimeInfo, sizeof(SysTimeInfo), 0);
                    diff = time - SysTimeInfo.CurrentTime.QuadPart;
                    return (abs(diff) > 10000000);
                }

                auto NtDelay = []() -> bool {
                    LONGLONG SavedTimeout = Timeout * (-10000LL);
                    DelayInterval->QuadPart = SavedTimeout;
                    status = NtDelayExecution(TRUE, DelayInterval);
                    return (DelayInterval->QuadPart != SavedTimeout);
                };

                return (
                    [](){
                        uint8_t score = 0;
                        score += Timeskip1();
                        score += Timeskip2();
                        score += Timeskip3();
                        score += SysTime();
                        score += NtDelay();
                        return (score >= 4); 
                    }()
                );
            };




            auto rdtsc_diff_locky = []() -> bool {
                ULONGLONG tsc1;
                ULONGLONG tsc2;
                ULONGLONG tsc3;
                for (size_t i = 0; i < 10; i++)
                {
                    tsc1 = __rdtsc();
                    GetProcessHeap();
                    tsc2 = __rdtsc();
                    CloseHandle(0);
                    tsc3 = __rdtsc();
                    if (((DWORD)(tsc3) - (DWORD)(tsc2)) / ((DWORD)(tsc2) - (DWORD)(tsc1)) >= 10) { return false; }
                }
                return true;
            };






            auto check_last_boot_time() -> bool {
                SYSTEM_TIME_OF_DAY_INFORMATION  SysTimeInfo;
                LARGE_INTEGER LastBootTime;
                
                NtQuerySystemInformation(SystemTimeOfDayInformation, &SysTimeInfo, sizeof(SysTimeInfo), 0);
                LastBootTime = wmi_Get_LastBootTime();
                return (wmi_LastBootTime.QuadPart - SysTimeInfo.BootTime.QuadPart) / 10000000 != 0;
            };




            auto HookDelay = []() -> bool {
                __declspec(align(4)) BYTE aligned_bytes[sizeof(LARGE_INTEGER) * 2];
                DWORD tick_start, time_elapsed_ms;
                DWORD Timeout = 10000;
                PLARGE_INTEGER DelayInterval = (PLARGE_INTEGER)(aligned_bytes + 1);
                NTSTATUS status;

                DelayInterval->QuadPart = Timeout * (-10000LL);
                tick_start = GetTickCount();
                status = NtDelayExecution(FALSE, DelayInterval);
                time_elapsed_ms = GetTickCount() - tick_start;
                return (time_elapsed_ms > 500 || status != STATUS_DATATYPE_MISALIGNMENT);
            };



            auto DelayIntervalCheck = []() -> bool {
                return (NtDelayExecution(FALSE, (PLARGE_INTEGER)0) != STATUS_ACCESS_VIOLATION);
            };




            // ========================= process =======================
            auto CheckVMProcs = []() -> bool {
                uint8_t score = 0;
                auto CheckRunningProc = [](const std::string &proc_name) -> void {
                    HANDLE hSnapshot;
                    PROCESSENTRY32 pe = {};

                    pe.dwSize = sizeof(pe);
                    bool present = false;
                    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

                    if (hSnapshot == INVALID_HANDLE_VALUE) { return; }
                    if (Process32First(hSnapshot, &pe)) {
                        do {
                            if (!StrCmpI(pe.szExeFile, proc_name.c_str())) {
                                present = true;
                                break;
                            }
                        } while (Process32Next(hSnapshot, &pe));
                    }
                    CloseHandle(hSnapshot);

                    score += present;
                    return;
                }

                // JoeBox
                CheckRunningProc("joeboxserver.exe");
                CheckRunningProc("joeboxcontrol.exe");

                // Parallels
                CheckRunningProc("prl_cc.exe");
                CheckRunningProc("prl_tools.exe");

                // Virtualbox
                CheckRunningProc("vboxservice.exe");
                CheckRunningProc("vboxtray.exe");

                // Virtual PC
                CheckRunningProc("vmsrvc.exe");
                CheckRunningProc("vmusrvc.exe");

                // VMware
                CheckRunningProc("vmtoolsd.exe");
                CheckRunningProc("vmacthlp.exe");
                CheckRunningProc("vmwaretray.exe");
                CheckRunningProc("vmwareuser.exe");
                CheckRunningProc("vmware.exe");
                CheckRunningProc("vmount2.exe");

                // Xen
                CheckRunningProc("xenservice.exe");
                CheckRunningProc("xsvc_depriv.exe");

                // WPE Pro
                CheckRunningProc("WPE Pro.exe");

                return (score >= 1);
            };












            auto loaded_dlls = []() -> bool {
                HMODULE hDll;
                TCHAR* szDlls[] = {
                    _T("sbiedll.dll"),
                    _T("dbghelp.dll"),
                    _T("api_log.dll"),
                    _T("dir_watch.dll"),
                    _T("pstorec.dll"),
                    _T("vmcheck.dll"),
                    _T("wpespy.dll"),
                };

                WORD dwlength = sizeof(szDlls) / sizeof(szDlls[0]);
                for (int i = 0; i < dwlength; i++)
                {
                    TCHAR msg[256] = _T("");
                    //_stprintf_s(msg, sizeof(msg) / sizeof(TCHAR), _T("Checking if process loaded modules contains: %s "), szDlls[i]);

                    hDll = GetModuleHandle(szDlls[i]);
                    return (!(hDll == NULL));
                }
            };


            auto WineExports = []() -> bool {
                auto CheckWine = [](const std::string &module, const std::string &proc) -> bool {
                    HMODULE hKernel32;
                    hKernel32 = GetModuleHandle(_T(module));
                    if (hKernel32 == NULL) { return false; }
                    return (!(GetProcAddress(hKernel32, proc) == NULL));
                };

                return (
                    CheckWine("kernel32.dll", "wine_get_unix_file_name") && \
                    CheckWine("ntdll.dll", "wine_get_version");
                );
            };

            https://godbolt.org/z/qjW57cT5a
