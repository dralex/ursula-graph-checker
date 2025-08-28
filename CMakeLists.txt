cmake_minimum_required(VERSION 3.12)

project(ursulacheck VERSION 1.0 LANGUAGES C)

set(cyberiadaml_DIR /usr/lib/cmake)
find_package(cyberiadaml REQUIRED)
if(!cyberiadaml_FOUND)
  message(FATAL_ERROR "Cannot find libcyberiadaml library")
endif()

if (NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/sha256.c)
  message(FATAL_ERROR "Cannot find sha256.c file (download here: https://github.com/jb55/sha256.c)")
endif()
if (NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/sha256.h)
  message(FATAL_ERROR "Cannot find sha256.h file (download here: https://github.com/jb55/sha256.c)")
endif()
if (NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/rotate-bits)
  message(FATAL_ERROR "Cannot find rotate-bits directory (download here: https://github.com/jb55/sha256.c)")
endif()

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -D__DEBUG__")

if(CMAKE_BUILD_TYPE STREQUAL Debug)
  add_compile_options(-Wall)
  add_compile_options(-Wextra) 
  add_compile_options(-Wpedantic)
endif()

add_library(ursulacheck SHARED
			ursulacheck.c
			sha256.c
)

target_include_directories(ursulacheck PUBLIC
				        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
			               	$<INSTALL_INTERFACE:include/cyberiada>
				       "${cyberiadaml_INCLUDE_DIR}")
target_link_directories(ursulacheck PUBLIC "${cyberiadaml_LIBRARY}")
target_link_libraries(ursulacheck PUBLIC "${cyberiadaml_LIBRARIES}")

add_subdirectory(tester)

install(TARGETS ursulacheck DESTINATION lib EXPORT ursulacheck)
install(FILES ursulacheck.h ${CMAKE_CURRENT_SOURCE_DIR}/ursulacheck.h
        DESTINATION include/cyberiada)
