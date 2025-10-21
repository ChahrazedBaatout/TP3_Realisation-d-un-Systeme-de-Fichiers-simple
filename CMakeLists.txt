cmake_minimum_required(VERSION 4.0)
project(TP3_Realisation_d_un_Systeme_de_Fichiers_simple C)

set(CMAKE_C_STANDARD 11)

include_directories(.)

add_executable(TP3_Realisation_d_un_Systeme_de_Fichiers_simple
        tosfs.h
        tostfs.c
)

find_package(PkgConfig REQUIRED)
pkg_check_modules(FUSE REQUIRED fuse)
include_directories(${FUSE_INCLUDE_DIRS})
target_link_libraries(TP3_Realisation_d_un_Systeme_de_Fichiers_simple ${FUSE_LIBRARIES})