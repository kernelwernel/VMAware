echo on
cd "%~dp0..\.."
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Debug -G "Visual Studio 17 2022" -A Win32 -S ..
"C:\Program Files\Microsoft Visual Studio\2022\Enterprise\Common7\IDE\devenv.com" "VMAware.sln" /Build "Debug|Win32" /Project "vmaware" /ProjectConfig "Debug|Win32"
cd Debug
vmaware.exe