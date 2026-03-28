# protocol_simulation/CMakeLists.txt

# Find Boost libraries required by WebSocketpp
find_package(Boost REQUIRED COMPONENTS system thread)

# 1. Auto-discover all network entity source files
file(GLOB SIMULATION_SRC_FILES "src/*.cpp")

# 2. Specify the core DAT-TWS scheme source and Serializer
# Assuming Serializer.cpp was moved to DAT-TWS/src/ (adjust if it's still somewhere else)
set(DAT_TWS_SRC
        ${CMAKE_SOURCE_DIR}/DAT-TWS/src/dat-tws.cpp
        ${CMAKE_SOURCE_DIR}/common/src/Serializer.cpp
)

# 3. Generate an executable for each network entity
foreach(file ${SIMULATION_SRC_FILES})
    # Extract the executable name (e.g., "issuer" from "src/issuer.cpp")
    get_filename_component(filename ${file} NAME_WE)

    add_executable(${filename}
            ${file}
            ${DAT_TWS_SRC}
    )

    # Include directories for the entity and the scheme
    # Note: Tools.h path is automatically included via WrapperLib linking below!
    target_include_directories(${filename} PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
            ${CMAKE_SOURCE_DIR}/DAT-TWS/include
    )

    # Link libraries: WrapperLib provides all cryptography dependencies cleanly!
    target_link_libraries(${filename}
            PRIVATE
            WrapperLib          # <-- Directly link your new miracle-wrapper project
            websocketpp
            ${Boost_LIBRARIES} pthread
    )
endforeach()


# Automatically process and deploy all .sh scripts from the scripts/ directory

# 1. Locate all shell scripts in the source directory
file(GLOB SCRIPTS "${CMAKE_CURRENT_SOURCE_DIR}/scripts/*.sh")

# 2. Iterate through and copy each script to the build directory
foreach(script ${SCRIPTS})
    get_filename_component(name ${script} NAME)

    # Copy the script to the build directory
    # (COPYONLY ensures it only copies when the source file is modified)
    configure_file(${script} ${CMAKE_CURRENT_BINARY_DIR}/scripts/${name} COPYONLY)

    # Grant execution permissions to the copied script
    execute_process(COMMAND chmod +x ${CMAKE_CURRENT_BINARY_DIR}/scripts/${name})
endforeach()

# 3. 处理配置文件 (只复制，不需要执行权限) <--- 新增这部分
configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/scripts/config.env"
        "${CMAKE_CURRENT_BINARY_DIR}/scripts/config.env"
        COPYONLY
)