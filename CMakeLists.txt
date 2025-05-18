cmake_minimum_required(VERSION 3.14)
project(mpmc_queue)

# C++17 standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Source includes
include_directories(.)
include_directories(src)

# Option: Enable or disable COMPARE_BOOST
option(COMPARE_BOOST "Enable COMPARE_BOOST functionality" OFF)

# Platform-specific compile options
if (MSVC)
    add_compile_options(/W4 /permissive- /bigobj)
else()
    add_compile_options(-Wall -Wextra -Wshadow -Wpedantic -O3 -ggdb3 -mcx16)
endif()

# GTest dependency
include(FetchContent)
FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/release-1.12.1.zip
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

# Windows-only: integrate wingetopt via FetchContent
if(WIN32)
    FetchContent_Declare(
        wingetopt
        GIT_REPOSITORY https://github.com/sldr/wingetopt.git
        GIT_TAG        master  # Pin this if possible for reproducibility
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    )
    FetchContent_MakeAvailable(wingetopt)

    # Link the wingetopt library to the needed targets
    set(WINGETOPT_TARGET wingetopt)  # Or wingetopt::wingetopt if exported with namespace
endif()

# Helper macro to apply COMPARE_BOOST and pthread
macro(configure_target target)
    if(COMPARE_BOOST)
        target_compile_definitions(${target} PRIVATE COMPARE_BOOST=1)
    else()
        target_compile_definitions(${target} PRIVATE COMPARE_BOOST=0)
    endif()

    if(WIN32)
        target_compile_definitions(${target} PRIVATE _CRT_SECURE_NO_WARNINGS=1)
    else()
        target_link_libraries(${target} PRIVATE pthread)
    endif()
endmacro()

# Executable: gtest_mpmc_queue
add_executable(gtest_mpmc_queue
    src/gtest_mpmc_queue.cpp
    mpmc_queue.h
)
target_link_libraries(gtest_mpmc_queue PRIVATE gtest_main)
if(WIN32)
    target_link_libraries(gtest_mpmc_queue PRIVATE ${WINGETOPT_TARGET})
endif()
configure_target(gtest_mpmc_queue)

# Executable: shared_mpmc_queue
add_executable(shared_mpmc_queue
    src/shared_q_test.cpp
    mpmc_queue.h
    shared_mpmc_queue.h
)
if(WIN32)
    target_link_libraries(shared_mpmc_queue PRIVATE ${WINGETOPT_TARGET})
endif()
configure_target(shared_mpmc_queue)

# Executable: q_bandwidth
add_executable(q_bandwidth
    src/q_bandwidth.cpp
    mpmc_queue.h
    src/mpmc_queue_timing.h
)
if(WIN32)
    target_link_libraries(q_bandwidth PRIVATE ${WINGETOPT_TARGET})
    target_compile_definitions(q_bandwidth PRIVATE USE_WINGETOPT)
endif()
configure_target(q_bandwidth)

# Executable: test_uniqptr_q
add_executable(test_uniqptr_q
    src/test_uniqptr_q.cpp
    mpmc_queue.h
)
if(WIN32)
    target_link_libraries(test_uniqptr_q PRIVATE ${WINGETOPT_TARGET})
endif()
configure_target(test_uniqptr_q)
