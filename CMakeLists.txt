cmake_minimum_required(VERSION 3.28)
project(DAT-TWS)

set(CMAKE_CXX_STANDARD 17)
set(FETCHCONTENT_UPDATES_DISCONNECTED ON) # Disable auto-update to prevent Git stash conflicts

# 1. External Dependencies (miracl-wrapper)
include(FetchContent)

FetchContent_Declare(
        WrapperLib
        GIT_REPOSITORY https://github.com/rookie-papers/miracl-wrapper.git
        GIT_TAG        main
)

FetchContent_MakeAvailable(WrapperLib) # Download and populate the library

# Build external libraries
add_subdirectory(external)
add_subdirectory(protocol_simulation)
add_subdirectory(network_simulation)

# 2. Build Function for Schemes
function(add_scheme_executable name)
    set(SCHEME_DIR ${CMAKE_SOURCE_DIR}/${name})

    # A. Gather source files
    file(GLOB SCHEME_SRC "${SCHEME_DIR}/src/*.cpp")

    # B. Define executable target
    add_executable(${name}_exec ${SCHEME_SRC})

    # C. Include directories. Note: WrapperLib headers are automatically included via linking
    target_include_directories(${name}_exec PRIVATE
            ${SCHEME_DIR}/include
    )

    # D. Link libraries. Links MIRACL, GMP, and Tools automatically via WrapperLib
    target_link_libraries(${name}_exec PRIVATE
            WrapperLib
            benchmark::benchmark
    )

    message(STATUS "Configured scheme: ${name}")
endfunction()

# 3. Register Schemes
add_scheme_executable(DAT-TWS)
add_scheme_executable(IhMA)
add_scheme_executable(DTACB)
add_scheme_executable(NTAT)