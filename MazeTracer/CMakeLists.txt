cmake_minimum_required(VERSION 3.18)

project(MazeTracer)

set(CMAKE_CXX_STANDARD 14)

set(CPM_DOWNLOAD_VERSION 0.27.2) 
set(CPM_DOWNLOAD_LOCATION "${CMAKE_BINARY_DIR}/cmake/CPM_${CPM_DOWNLOAD_VERSION}.cmake")

if(NOT (EXISTS ${CPM_DOWNLOAD_LOCATION}))
    message(STATUS "Downloading CPM.cmake")
    file(DOWNLOAD https://github.com/TheLartians/CPM.cmake/releases/download/v${CPM_DOWNLOAD_VERSION}/CPM.cmake ${CPM_DOWNLOAD_LOCATION})
endif()

include(${CPM_DOWNLOAD_LOCATION})
include(cmake/IntelPIN.cmake)

# Instruction counter example
file(GLOB TRACER_SOURCES
        "${CMAKE_CURRENT_SOURCE_DIR}/src/lib/*.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/lib/*.c"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/lib/*.h")

file(GLOB TEST_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/src/test/*.cpp")

add_pintool(MazeTracer ${TRACER_SOURCES})
target_include_directories(MazeTracer PRIVATE "C:/Python27/include")
target_link_directories(MazeTracer PRIVATE "C:/Python27/libs")
target_link_libraries(MazeTracer PRIVATE python27)

add_executable(TestApp ${TEST_SOURCES})