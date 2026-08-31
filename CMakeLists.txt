cmake_minimum_required(VERSION 3.16)
project(adi_extract LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(adi-extract
    src/main.cpp
    src/adi_file.cpp
    src/codec.cpp
    src/image.cpp
    src/extract.cpp
)

target_include_directories(adi-extract PRIVATE src)

if(WIN32)
    target_compile_definitions(adi-extract PRIVATE _CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN)
endif()
