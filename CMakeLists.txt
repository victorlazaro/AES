cmake_minimum_required(VERSION 3.8)
project(AES)

set(CMAKE_CXX_STANDARD 11)

set(SOURCE_FILES main.cpp AES.cpp AES.h)
add_executable(AES ${SOURCE_FILES})