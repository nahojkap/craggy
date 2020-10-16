# Copyright 2020 Johan Lindquist
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

project(craggy C)

set(SOURCES
        CraggyProtocol
        CraggyProtocol
        CraggyClient
        CraggyClient
        CraggyCrypto
        CraggyOS
        CraggyTypes)

if (UNIX)
    set(SOURCES ${SOURCES} crypto/CraggyCrypto-Linux.c)
endif()

if (CRAGGY_WITH_UDP_TRANSPORT)
    set(SOURCES ${SOURCES} CraggyUDPTransport)
endif ()

if (CRAGGY_WITH_ORLP_ED25519_BINDINGS)

    message("Loading ORLP ED25519 source code")

    configure_file(../orlp-ed25519/CMakeLists.txt.in craggy-orlp-ed25519-download/CMakeLists.txt)
    execute_process(COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" . RESULT_VARIABLE result WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/craggy-orlp-ed25519-download/ )

    if(result)
        message(FATAL_ERROR "CMake step for ORLP/ED25519 failed: ${result}")
    endif()

    execute_process(COMMAND ${CMAKE_COMMAND} --build . RESULT_VARIABLE result WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/craggy-orlp-ed25519-download )

    if(result)
        message(FATAL_ERROR "Build step for ORLP/ED25519  failed: ${result}")
    endif()

    configure_file(../orlp-ed25519/CMakeLists-ORLP-ED25519.txt ${CMAKE_CURRENT_BINARY_DIR}/craggy-orlp-ed25519-src/src/CMakeLists.txt COPYONLY)

    add_subdirectory(${CMAKE_CURRENT_BINARY_DIR}/craggy-orlp-ed25519-src/src
                     ${CMAKE_CURRENT_BINARY_DIR}/craggy-orlp-ed25519-build
            EXCLUDE_FROM_ALL)

    set(SOURCES ${SOURCES} crypto/CraggyCrypto-ORLP-ED25519)

endif()

if (CRAGGY_WITH_OPENSSL_BINDINGS)
    find_package(OpenSSL REQUIRED)
    include_directories(${OPENSSL_INCLUDE_DIR})
    set(SOURCES ${SOURCES} crypto/CraggyCrypto-OpenSSL CraggyTypes.h CraggyOS.h)
endif()

add_library(craggy STATIC ${SOURCES})
set(craggy_include_dirs ${craggy_SOURCE_DIR})
target_include_directories(craggy PUBLIC ${craggy_include_dirs})

if (CRAGGY_WITH_OPENSSL_BINDINGS)
    target_link_libraries(craggy OpenSSL::SSL)
endif()

if (CRAGGY_WITH_ORLP_ED25519_BINDINGS)
    target_link_libraries(craggy craggy-orlp-ed25519)
endif()

