echo on
cd "%~dp0..\.."
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Debug -G "Visual Studio 17 2022" -A x64 -S ..
"C:\Program Files\Microsoft Visual Studio\2022\Enterprise\Common7\IDE\devenv.com" "VMAware.sln" /Build "Debug|x64" /Project "vmaware" /ProjectConfig "Debug|x64"
copy "C:\Program Files (x86)\Microsoft Visual Studio\2022\Enterprise\VC\Redist\MSVC\14.30.30704\debug_nonredist\x86\Microsoft.VC143.DebugCRT\ucrtbased.dll" Debug\
copy "C:\Program Files (x86)\Microsoft Visual Studio\2022\Enterprise\VC\Redist\MSVC\14.30.30704\debug_nonredist\x86\Microsoft.VC143.DebugCRT\vcruntime140d.dll" Debug\
copy "C:\Program Files (x86)\Microsoft Visual Studio\2022\Enterprise\VC\Redist\MSVC\14.30.30704\debug_nonredist\x86\Microsoft.VC143.DebugCRT\msvcp140d.dll" Debug\
cd Debug
vmaware.exe
vmaware.exe --spoofable