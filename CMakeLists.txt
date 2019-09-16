cmake_minimum_required(VERSION 3.0)
project (MiniDbg)

# add_compile_options(-std=c++14)
set(CMAKE_CXX_STANDARD 14)

include_directories(include)
aux_source_directory(${PROJECT_SOURCE_DIR}/src source)
add_executable(minidbg ${source})

