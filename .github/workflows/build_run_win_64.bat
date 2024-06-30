echo on
cd "%~dp0..\.."
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Debug -G "Visual Studio 17 2022" -A x64 -S ..
"C:\Program Files\Microsoft Visual Studio\2022\Enterprise\Common7\IDE\devenv.com" "VMAware.sln" /Build "Debug|x64" /Project "vmaware" /ProjectConfig "Debug|x64"
cd Debug
vmaware.exe