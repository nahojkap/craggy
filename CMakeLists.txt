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

cmake_minimum_required(VERSION 3.12)
project(craggy C)

set(CMAKE_C_STANDARD 11)

option(CRAGGY_WITH_UDP_TRANSPORT "Enable UDP transport" ON)
option(CRAGGY_WITH_OPENSSL_BINDINGS "Use OpenSSL cryptographic operations" OFF)
option(CRAGGY_WITH_ORLP_ED25519_BINDINGS "Use ORLPs ED25519 cryptographic operations" OFF)

add_subdirectory(library)

enable_testing()
add_subdirectory(tests)

add_subdirectory(cli)

