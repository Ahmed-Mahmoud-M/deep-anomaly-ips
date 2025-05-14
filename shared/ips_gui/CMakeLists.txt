cmake_minimum_required(VERSION 3.5)
project(IPS_GUI)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

find_package(Qt5 REQUIRED Widgets)

add_executable(IPS_GUI
    main.cpp
    ipsgui.cpp
    ipsgui.h
)

target_link_libraries(IPS_GUI Qt5::Widgets)
