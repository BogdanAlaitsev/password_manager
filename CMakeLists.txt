cmake_minimum_required(VERSION 3.10)
project(password_manager)

set(CMAKE_CXX_STANDARD 17)

find_package(SQLite3 REQUIRED)
include_directories(${SQLite3_INCLUDE_DIRS})

add_library(core
        password_manager.cpp
        password_manager.h
)
target_link_libraries(core
        SQLite::SQLite3
)

add_executable(password_manager
        main.cpp
)
target_link_libraries(password_manager
        core
)

add_executable(tests
        tests.cpp
)
target_link_libraries(tests
        core
)