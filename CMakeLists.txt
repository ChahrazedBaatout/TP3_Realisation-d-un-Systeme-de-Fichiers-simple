cmake_minimum_required(VERSION 4.0)
project(TP3_Realisation_d_un_Systeme_de_Fichiers_simple C)

set(CMAKE_C_STANDARD 11)

include_directories(.)

add_executable(TP3_Realisation_d_un_Systeme_de_Fichiers_simple
        tosfs.h
        tostfs.c)
