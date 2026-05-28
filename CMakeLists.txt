cmake_minimum_required(VERSION 3.30)
project(KZInjector)

set(CMAKE_CXX_STANDARD 17)

file(GLOB_RECURSE SOURCES
        CONFIGURE_DEPENDS
        "src/*.cpp"
        "src/*.h"
        "src/*/*.cpp"
        "src/*/*.h"
        "res/*.rc"
)

add_executable(KZInjector ${SOURCES})

target_link_libraries(KZInjector)
