#
# ██╗   ██╗███╗   ███╗ █████╗ ██╗    ██╗ █████╗ ██████╗ ███████╗
# ██║   ██║████╗ ████║██╔══██╗██║    ██║██╔══██╗██╔══██╗██╔════╝
# ██║   ██║██╔████╔██║███████║██║ █╗ ██║███████║██████╔╝█████╗  
# ╚██╗ ██╔╝██║╚██╔╝██║██╔══██║██║███╗██║██╔══██║██╔══██╗██╔══╝  
#  ╚████╔╝ ██║ ╚═╝ ██║██║  ██║╚███╔███╔╝██║  ██║██║  ██║███████╗
#   ╚═══╝  ╚═╝     ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
# 
#  C++ VM detection library
# 
# ===============================================================
#
#  This script is designed to test different C++ standards to see
#  if there are any edgecases before releasing it
# 
# ===============================================================
# 
#  - Made by: @kernelwernel (https://github.com/kernelwernel)
#  - Repository: https://github.com/kernelwernel/VMAware
#  - License: MIT

clear

current_dir=$(pwd) 
rm -rf build/
mkdir build/ 2>/dev/null
cd build/

standards=("11" "14" "17" "20" "23")

for version in "${standards[@]}"; do
    echo "[LOG] Running cmake with $version standard"
    cmake -DCMAKE_BUILD_TYPE=Debug -DCMAKE_CXX_STANDARD=$version ../..

    echo "[LOG] make"
    make
    make_status=$?

    if [ $make_status -ne 0 ]; then
        exit
    fi

    cp ../../build/vmaware .

    echo "[LOG] ./vmaware"
    ./vmaware 2>&1
    vmaware_status=$?

    if [ $vmaware_status -ne 0 ]; then
        exit
    fi
done

cd $current_dir

rm -rf build