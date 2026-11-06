cmake_minimum_required(VERSION 3.22)
project(chsi C)

add_library(chsi SHARED chsi.c)
target_link_libraries(chsi log)
