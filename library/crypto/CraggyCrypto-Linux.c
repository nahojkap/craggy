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

#include <stddef.h>
#include <stdio.h>
#include <assert.h>

#include "CraggyCrypto.h"

bool craggy_fillRandomBytes(uint8_t *randomBuf, size_t randomBufLen, CraggyResult *result)
{
    FILE *f = fopen("/dev/urandom", "rb");
    if (f == NULL) {
        *result = CraggyResultInternalError;
        return false;
    }
    size_t read = fread(randomBuf, 1, randomBufLen, f);
    assert(read == randomBufLen);
    fclose(f);
    *result = CraggyResultSuccess;

    return true;
}