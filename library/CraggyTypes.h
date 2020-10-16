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
#ifndef CRAGGY_CRAGGYTYPES_H
#define CRAGGY_CRAGGYTYPES_H

#include <stdint.h>

typedef enum {
    CraggyResultSuccess = 0,
    CraggyResultGeneralError = 100,
    CraggyResultInternalError = 101,
    CraggyResultParseError = 200,
    CraggyResultParseErrorMissingTags = 201,
    CraggyResultParseErrorTagSizeMismatch = 202,
    CraggyResultAuthenticationSignatureError = 300,
    CraggyResultAuthenticationHashError = 301,
    CraggyResultAuthenticationPublicKeyUsageOutOfBounds = 302,
    CraggyResultNetworkError = 400,
    CraggyResultNetworkInternalError = 401,
    CraggyResultNetworkNameLookupError = 402,
    CraggyResultNetworkTimeout = 403,
    CraggyResultNetworkConnectionError = 404
} CraggyResult;

#define CRAGGY_ROUGH_TIME_MIN_REQUEST_SIZE 1024
#define CRAGGY_ROUGH_TIME_NONCE_LENGTH 64
#define CRAGGY_ROUGH_TIME_PUBLIC_KEY_LENGTH 32
#define CRAGGY_ROUGH_TIME_SIGNATURE_LENGTH 64
#define CRAGGY_ROUGH_TIME_SIGNATURE_LENGTH 64
#define CRAGGY_ROUGH_TIME_HASH_LENGTH 64

typedef uint8_t craggy_rough_time_request_t[CRAGGY_ROUGH_TIME_MIN_REQUEST_SIZE];
typedef uint8_t craggy_rough_time_nonce_t[CRAGGY_ROUGH_TIME_NONCE_LENGTH];
typedef uint8_t craggy_rough_time_public_key_t[CRAGGY_ROUGH_TIME_PUBLIC_KEY_LENGTH];

typedef uint8_t craggy_rough_time_response_t;
typedef uint32_t craggy_rough_time_radius_t;
typedef uint64_t craggy_rough_time_t;

#endif //CRAGGY_CRAGGYTYPES_H
