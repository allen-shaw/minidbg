#!/bin/zsh
rm -rf ./build
mkdir -p build
cd build
cmake ..
make 
mv minidbg ../bin/