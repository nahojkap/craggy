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

#include <ed25519.h>
#include <sha512.h>

#include "CraggyCrypto.h"

bool craggy_verifySignature(const craggy_rough_time_public_key_t rootPublicKey, const uint8_t *signature, const uint8_t *msg, const size_t msgLen)
{
    return ed25519_verify(signature,msg,msgLen,rootPublicKey) == 1;
}

bool craggy_calculateSHA512(const uint8_t *msg, const size_t msgLen, uint8_t hash[CRAGGY_ROUGH_TIME_HASH_LENGTH])
{
    sha512_context hashContext;
    sha512_init(&hashContext);
    sha512_update(&hashContext, msg, msgLen);
    sha512_final(&hashContext, hash);
    return true;
}
