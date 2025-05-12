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
#  This is the installation module for CMake.
#
#  INCLUDE CODE: 
#    include(/path/to/vmaware_download.cmake)
#   
#  EXAMPLE USAGE:
#    download_vmaware("/path/to/your/destination/directory/")
#   
# 
# ===============================================================
# 
#  - Made by: @kernelwernel (https://github.com/kernelwernel)
#  - Repository: https://github.com/kernelwernel/VMAware

function(download_vmaware directory)
    set(DIRECTORY "${directory}" CACHE STRING "Directory to save VMAware header")

    set(DESTINATION "${DIRECTORY}/vmaware.hpp")

    if (NOT EXISTS ${DESTINATION})
        message(STATUS "Downloading VMAware")
        set(URL "https://github.com/kernelwernel/VMAware/releases/latest/download/vmaware.hpp")
        file(DOWNLOAD ${URL} ${DESTINATION} SHOW_PROGRESS)
    else()
        message(STATUS "VMAware already downloaded, skipping")
    endif()
endfunction()