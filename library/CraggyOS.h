/* Copyright 2020 Johan Lindquist
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef CRAGGY_CRAGGYOS_H
#define CRAGGY_CRAGGYOS_H

#include <memory.h>

#define craggy_malloc malloc
#define craggy_calloc calloc
#define craggy_free free
#define craggy_memset memset
#define craggy_memcpy memcpy
#define craggy_memcmp memcmp

#endif //CRAGGY_CRAGGYOS_H
