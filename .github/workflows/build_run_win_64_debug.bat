"C:\Program Files\Microsoft Visual Studio\2022\Enterprise\Common7\IDE\devenv.com" "VMAware.sln" /Build "Release|x64" /Project "vmaware" /ProjectConfig "Release|x64"

echo on
cd "%~dp0..\.."
mkdir build
cd build
cmake -DCMAKE_CXX_FLAGS="-D__VMAWARE_DEBUG__" .. -G "Visual Studio 17 2022" -A x64 -S ..
"C:\Program Files\Microsoft Visual Studio\2022\Enterprise\Common7\IDE\devenv.com" "VMAware.sln" /Build "Release|x64" /Project "vmaware" /ProjectConfig "Release|x64"
cd Release
vmaware.exe