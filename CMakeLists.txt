cmake_minimum_required(VERSION 3.0)
project (MiniDbg)

# add_compile_options(-std=c++14)
set(CMAKE_CXX_STANDARD 14)

include_directories(include include/libelfin)
aux_source_directory(${PROJECT_SOURCE_DIR}/src source)
add_executable(minidbg ${source})

target_link_libraries(minidbg 
                        /usr/local/lib/libdwarf++.so
                        /usr/local/lib/libelf++.so)