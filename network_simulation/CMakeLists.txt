# ============================================================================
# CMake Configuration for DAT-TWS Network Simulation
# ============================================================================

# 1. Find Boost libraries required by WebSocketpp
find_package(Boost REQUIRED COMPONENTS system thread)

# 2. Gather network simulation source files
file(GLOB SIMULATION_SRC_FILES "src/*.cpp")

# 3. Gather common sources (Serializer.cpp)
file(GLOB COMMON_SRC "${CMAKE_SOURCE_DIR}/common/src/*.cpp")

# 4. Specify the core DAT-TWS scheme source
set(DAT_TWS_SRC "${CMAKE_SOURCE_DIR}/DAT-TWS/src/dat-tws.cpp")

# ============================================================================
# Executable Generation
# ============================================================================
foreach(file ${SIMULATION_SRC_FILES})
    # Extract the base filename (e.g., "src/issuer.cpp" -> "issuer")
    get_filename_component(filename ${file} NAME_WE)

    # 1. Create a UNIQUE target name
    set(target_name "${filename}_net")

    # 2. Define the executable using the correct source paths
    add_executable(${target_name}
            ${file}
            ${COMMON_SRC}       # <--- Added your common folder sources
            ${DAT_TWS_SRC}
    )

    # 3. FORCE the output binary name to match our bash scripts
    set_target_properties(${target_name} PROPERTIES OUTPUT_NAME "${filename}")

    # 4. Specify include directories
    target_include_directories(${target_name} PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
            ${CMAKE_SOURCE_DIR}/common/include  # <--- Included common headers
            ${CMAKE_SOURCE_DIR}/DAT-TWS/include
    )

    # 5. Link required libraries
    target_link_libraries(${target_name}
            PRIVATE
            WrapperLib
            websocketpp
            ${Boost_LIBRARIES} pthread
    )
endforeach()

# ============================================================================
# Script Deployment (Auto-copy to build directory)
# ============================================================================

# 1. Locate all shell scripts in the scripts/ directory
file(GLOB SCRIPTS "${CMAKE_CURRENT_SOURCE_DIR}/scripts/*.sh")

# 2. Copy each script and grant execution permissions
foreach(script ${SCRIPTS})
    get_filename_component(name ${script} NAME)

    # Copy to the build directory (COPYONLY ensures it copies only when modified)
    configure_file(${script} ${CMAKE_CURRENT_BINARY_DIR}/scripts/${name} COPYONLY)

    # Grant execution permissions (+x) directly during the CMake generation phase
    execute_process(COMMAND chmod +x ${CMAKE_CURRENT_BINARY_DIR}/scripts/${name})
endforeach()

# 3. Copy the environment configuration file (Execution permissions not required)
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/scripts/config.env")
    configure_file(
            "${CMAKE_CURRENT_SOURCE_DIR}/scripts/config.env"
            "${CMAKE_CURRENT_BINARY_DIR}/scripts/config.env"
            COPYONLY
    )
endif()