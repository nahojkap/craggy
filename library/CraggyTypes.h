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
    CraggyResultParseErrorInvalidPacket = 201,
    CraggyResultParseErrorMissingTags = 202,
    CraggyResultParseErrorTagSizeMismatch = 203,

    CraggyResultAuthenticationSignatureError = 300,
    CraggyResultAuthenticationHashError = 301,
    CraggyResultAuthenticationPublicKeyUsageOutOfBounds = 302,
    CraggyResultNetworkError = 400,
    CraggyResultNetworkInternalError = 401,
    CraggyResultNetworkNameLookupError = 402,
    CraggyResultNetworkTimeout = 403,
    CraggyResultNetworkConnectionError = 404,
    CraggyResultUnsupportedVersionError = 405,

} CraggyResult;

#define CRAGGY_ROUGHTIME_MIN_REQUEST_SIZE 1024
#define CRAGGY_ROUGHTIME_NONCE_LENGTH 32
#define CRAGGY_ROUGHTIME_PUBLIC_KEY_LENGTH 32
#define CRAGGY_ROUGHTIME_SIGNATURE_LENGTH 64
#define CRAGGY_ROUGHTIME_HASH_LENGTH 32

// Update to Draft 11
#define CRAGGY_ROUGHTIME_VERSION 0x8000000b

typedef uint8_t craggy_rough_time_payload_t[CRAGGY_ROUGHTIME_MIN_REQUEST_SIZE];

typedef craggy_rough_time_payload_t craggy_rough_time_request_t;
typedef craggy_rough_time_payload_t craggy_rough_time_response_t;

typedef uint8_t craggy_rough_time_nonce_t[CRAGGY_ROUGHTIME_NONCE_LENGTH];
typedef uint8_t craggy_rough_time_public_key_t[CRAGGY_ROUGHTIME_PUBLIC_KEY_LENGTH];

typedef uint32_t craggy_rough_time_radius_t;
typedef uint64_t craggy_roughtime_t;

/** Structure containing the Roughtime results */
typedef struct craggy_roughtime_result {
    craggy_roughtime_t midpoint;
    craggy_rough_time_radius_t radius;
} craggy_roughtime_result;

#endif //CRAGGY_CRAGGYTYPES_H
