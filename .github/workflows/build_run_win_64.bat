echo on
cd "%~dp0..\.."
mkdir build
cd build
cmake -G "Visual Studio 17 2022" -A x64 -S ..
"C:\Program Files\Microsoft Visual Studio\2022\Enterprise\Common7\IDE\devenv.com" "VMAware.sln" /Build "Release|x64" /Project "vmaware" /ProjectConfig "Release|x64"
cd Release
vmaware.exe
