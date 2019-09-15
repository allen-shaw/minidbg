cmake_minimum_required(VERSION 3.0)
project (MiniDbg)

add_compile_options(-std=c++14)

include_directories(include)
add_executable(minidbg src/minidbg.cpp src/debugger.cpp src/linenoise.c src/utils.cpp)

