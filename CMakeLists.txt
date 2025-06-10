cmake_minimum_required(VERSION 3.31)
project(borderlands_proxy C)

set(FINAL_DLL_OUTPUT_NAME "version")

# MinHook source files (these are .c files and will be compiled with the C compiler)
set(MINHOOK_SOURCES
        minhook/src/buffer.c
        minhook/src/hook.c
        minhook/src/trampoline.c
        minhook/src/hde/hde64.c
)

add_library(${PROJECT_NAME} SHARED
        dllmain.c
        ${MINHOOK_SOURCES}
)

set_target_properties(${PROJECT_NAME} PROPERTIES
        OUTPUT_NAME ${FINAL_DLL_OUTPUT_NAME}
        PREFIX ""
        SUFFIX ".dll"
)

# Include directories
target_include_directories(${PROJECT_NAME} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/minhook/include  # For MinHook.h
        ${CMAKE_CURRENT_SOURCE_DIR}/minhook/src      # For MinHook's internal headers
        ${CMAKE_CURRENT_SOURCE_DIR}/minhook/src/hde  # For HDE's internal headers
)

# Link against necessary Windows libraries
target_link_libraries(${PROJECT_NAME} PRIVATE kernel32 user32)

# Compiler and Linker options specifically for MinGW
if(MINGW)
    message(STATUS "MinGW detected. Applying MinGW-specific options.")

    # Compiler flags (for C code)
    target_compile_options(${PROJECT_NAME} PRIVATE
            -m64  # Explicitly for 64-bit compilation
            -ffunction-sections
            -fdata-sections
    )

    # Linker flags
    target_link_options(${PROJECT_NAME} PRIVATE
            "-m64"
            "-Wl,--gc-sections"    # Garbage collect unused sections
            "-s"                   # Strip symbols (this strips the DLL, map file is separate)
            "-Wl,-Map,${CMAKE_BINARY_DIR}/${FINAL_DLL_OUTPUT_NAME}.map"  # <--- ADD THIS LINE
            # Uncomment these if you want to try avoiding copying MinGW runtime DLLs later
            # "-static-libgcc"
            # (libstdc++ is not needed for a pure C project)
    )
endif()

# Add the .def file to specify exports
target_sources(${PROJECT_NAME} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/version.def")

# Build type handling
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose build type" FORCE)
    message(STATUS "Build type not specified by IDE, defaulting to CMakeLists.txt value: ${CMAKE_BUILD_TYPE}")
else()
    message(STATUS "Build type selected by IDE or existing cache: ${CMAKE_BUILD_TYPE}")
endif()

message(STATUS "Project target: ${PROJECT_NAME}")
message(STATUS "Output DLL will be named: ${FINAL_DLL_OUTPUT_NAME}.dll")
