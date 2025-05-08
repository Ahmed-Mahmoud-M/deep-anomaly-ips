cmake_minimum_required(VERSION 3.10)
project(IPS_GUI)

set(CMAKE_CXX_STANDARD 17)

find_package(Qt5 COMPONENTS Widgets REQUIRED)

set(SOURCES
    main.cpp
    ipsgui.cpp
)

set(HEADERS
    ipsgui.h
)

qt5_wrap_cpp(MOC_SOURCES ${HEADERS})

add_executable(IPS_GUI ${SOURCES} ${MOC_SOURCES})
target_link_libraries(IPS_GUI Qt5::Widgets)
