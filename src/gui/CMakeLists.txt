cmake_minimum_required(VERSION 3.22 FATAL_ERROR)
project(
    vmaware_gui
    LANGUAGES CXX
)


if(NOT DEFINED CMAKE_CXX_STANDARD)
    set(CMAKE_CXX_STANDARD 20)
endif()


find_package(glfw3 REQUIRED)
find_package(Vulkan REQUIRED)


function(download URL)
    string(REGEX REPLACE ".*/([^/]+)$" "\\1" ASSET "${URL}")
    set(DESTINATION "../lib/${ASSET}")

    if (NOT EXISTS ${DESTINATION})
        message(STATUS "Downloading ${ASSET}")
        file(DOWNLOAD ${URL} ${DESTINATION})
    else()
        message(STATUS "${ASSET} already downloaded, skipping")
    endif()
endfunction()


# faster this way rather than downloading the whole imgui repository
download("https://raw.githubusercontent.com/ocornut/imgui/refs/heads/master/imgui.cpp")
download("https://raw.githubusercontent.com/ocornut/imgui/refs/heads/master/imgui.h")
download("https://raw.githubusercontent.com/ocornut/imgui/refs/heads/master/imconfig.h")
download("https://raw.githubusercontent.com/ocornut/imgui/refs/heads/master/imgui_internal.h")
download("https://raw.githubusercontent.com/ocornut/imgui/refs/heads/master/backends/imgui_impl_glfw.cpp")
download("https://raw.githubusercontent.com/ocornut/imgui/refs/heads/master/backends/imgui_impl_glfw.h")
download("https://raw.githubusercontent.com/ocornut/imgui/refs/heads/master/backends/imgui_impl_vulkan.cpp")
download("https://raw.githubusercontent.com/ocornut/imgui/refs/heads/master/backends/imgui_impl_vulkan.h")
download("https://raw.githubusercontent.com/ocornut/imgui/refs/heads/master/imgui_draw.cpp")
download("https://raw.githubusercontent.com/ocornut/imgui/refs/heads/master/imgui_tables.cpp")
download("https://raw.githubusercontent.com/ocornut/imgui/refs/heads/master/imgui_widgets.cpp")
download("https://raw.githubusercontent.com/ocornut/imgui/refs/heads/master/imgui_demo.cpp")
download("https://raw.githubusercontent.com/ocornut/imgui/refs/heads/master/imstb_rectpack.h")
download("https://raw.githubusercontent.com/ocornut/imgui/refs/heads/master/imstb_truetype.h")
download("https://raw.githubusercontent.com/ocornut/imgui/refs/heads/master/imstb_textedit.h")


include_directories(lib)
include_directories(include)

set(SOURCES
    main.cpp
    lib/imgui.cpp
    lib/imgui_impl_glfw.cpp
    lib/imgui_impl_vulkan.cpp
    lib/imgui_draw.cpp
    lib/imgui_tables.cpp
    lib/imgui_widgets.cpp
    lib/imgui_demo.cpp
    vulkan.cpp
    frame.cpp
)

add_executable(vmaware_gui ${SOURCES})

target_link_libraries(vmaware_gui PRIVATE glfw Vulkan::Vulkan)
target_compile_options(vmaware_gui PRIVATE -Wall -Wextra)