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
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "CraggyCrypto.h"

bool craggy_verifySignature(const craggy_rough_time_public_key_t rootPublicKey, const uint8_t *signature, const uint8_t *msg, const size_t msgLen)
{
    EVP_PKEY *key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL,rootPublicKey,CRAGGY_ROUGH_TIME_PUBLIC_KEY_LENGTH);

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_create();
    EVP_MD_CTX_init(md_ctx);

    int result = 0;
    if (1 ==  EVP_DigestVerifyInit(md_ctx, NULL, NULL, NULL, key))
    {
        result = EVP_DigestVerify(md_ctx, signature, CRAGGY_ROUGH_TIME_SIGNATURE_LENGTH, msg, msgLen);
    }
    EVP_MD_CTX_free(md_ctx);

    return result == 1;
}

bool craggy_calculateSHA512(const uint8_t *msg, const size_t msgLen, uint8_t hash[CRAGGY_ROUGH_TIME_HASH_LENGTH])
{
    SHA512_CTX context;
    SHA512_Init(&context);
    SHA512_Update(&context, msg, msgLen);
    SHA512_Final(hash, &context);
    return true;
}