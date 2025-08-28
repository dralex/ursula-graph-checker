cmake_minimum_required(VERSION 3.12)

project(ursulachecktester VERSION 1.0)
add_executable(ursulachecktester main.c)
target_include_directories(ursulachecktester PUBLIC
			   $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>
			   $<INSTALL_INTERFACE:include/cyberiada>)
target_link_directories(ursulachecktester PUBLIC "${PROJECT_BINARY_DIR}")
target_link_libraries(ursulachecktester PUBLIC ursulacheck)
