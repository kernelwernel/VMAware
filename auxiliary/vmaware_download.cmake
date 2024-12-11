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
#    download_vmaware("/path/to/your/destination/directory/" OFF)
#   
#  NOTE:
#    if you want the MIT version, switch the OFF to ON in the above example
# 
# ===============================================================
# 
#  - Made by: @kernelwernel (https://github.com/kernelwernel)
#  - Repository: https://github.com/kernelwernel/VMAware


function(download_vmaware directory mit_version)
    set(DIRECTORY "${directory}" CACHE STRING "Directory to save VMAware header")

    if (mit_version)
        set(EXTENSION "_MIT")
    else()
        set(EXTENSION "")
    endif()

    set(DESTINATION "${DIRECTORY}/vmaware${EXTENSION}.hpp")

    if (NOT EXISTS ${DESTINATION})
        message(STATUS "Downloading VMAware")
        set(URL "https://github.com/kernelwernel/VMAware/releases/latest/download/vmaware${EXTENSION}.hpp")
        file(DOWNLOAD ${URL} ${DESTINATION} SHOW_PROGRESS)
    else()
        message(STATUS "VMAware already downloaded, skipping")
    endif()
endfunction()
