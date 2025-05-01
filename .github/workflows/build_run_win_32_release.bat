echo on
cd "%~dp0..\.."
mkdir build
cd build
cmake -G "Visual Studio 17 2022" -A Win32 -S ..
"C:\Program Files\Microsoft Visual Studio\2022\Enterprise\Common7\IDE\devenv.com" "VMAware.sln" /Build "Release|Win32" /Project "vmaware" /ProjectConfig "Release|Win32"
cd Release
vmaware.exe