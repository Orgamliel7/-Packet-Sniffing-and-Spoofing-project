cmake_minimum_required(VERSION 3.16)
project(C C)

set(CMAKE_C_STANDARD 11)

include_directories(.)

add_executable(C
        sniffer.c
        sniffSpoof.c
        spoof.c
        spoof.h)
