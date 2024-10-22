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

project(craggy-cli C)

set(SOURCES
        base64.c
        main.c)

add_executable(craggy-cli ${SOURCES})
target_link_libraries(craggy-cli craggy)

if (CRAGGY_WITH_OPENSSL_BINDINGS)
    find_package(OpenSSL REQUIRED)
    target_link_libraries(craggy-cli OpenSSL::SSL)
endif()
