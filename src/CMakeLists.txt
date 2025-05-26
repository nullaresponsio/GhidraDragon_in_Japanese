# CMakeLists.txt

cmake_minimum_required(VERSION 3.15)
project(SoftTPM LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
find_package(pybind11 REQUIRED)

include(FetchContent)
FetchContent_Declare(
  nlohmann_json
  URL https://github.com/nlohmann/json/releases/download/v3.11.2/json.hpp
)
FetchContent_GetProperties(nlohmann_json)
if(NOT nlohmann_json_POPULATED)
  FetchContent_Populate(nlohmann_json)
endif()

# SoftTPM library
add_library(softtpm
    softtpm.cpp
    softtpm.hpp
)
target_include_directories(softtpm PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    ${nlohmann_json_SOURCE_DIR}
)
target_link_libraries(softtpm PRIVATE OpenSSL::Crypto)

# Python binding
pybind11_add_module(softtpm_py
    binding.cpp
)
target_link_libraries(softtpm_py PRIVATE softtpm)

# Command-line tool
add_executable(softtpm_tool tool.cpp)
target_link_libraries(softtpm_tool PRIVATE softtpm nlohmann_json)

install(TARGETS softtpm_py RUNTIME DESTINATION bin LIBRARY DESTINATION bin)
install(TARGETS softtpm_tool RUNTIME DESTINATION bin)
