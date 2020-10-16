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

#ifndef CRAGGY_CRAGGYCLIENT_H
#define CRAGGY_CRAGGYCLIENT_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "CraggyTypes.h"

/** Creates a new Roughtime request message containing the specified nonce.
 *
 * @param nonce The nonce to include in the request
 * @param requestBuf Buffer for the request
 * @param requestBufLen Buffer length
 * @return True if the request creation was successful, otherwise false
 */
bool craggy_createRequest(craggy_rough_time_nonce_t nonce, craggy_rough_time_request_t requestBuf);

/** Processes a response from the server, verifying the necessary signatures and extracting the time and radius if successful.
 *
 * @param nonce The nonce originally used for creating the request
 * @param rootPublicKey Root public key of the server in question
 * @param responseBuf Response to be processed
 * @param responseBufLen Size of the response to be processed
 * @param result Result of response processing
 * @param time Time reported by the server
 * @param radius Radius reported by the server
 * @return True if the request creation was successful, otherwise false and {@link result} will signal the error
 */
bool craggy_processResponse(craggy_rough_time_nonce_t nonce, craggy_rough_time_public_key_t rootPublicKey, craggy_rough_time_response_t *responseBuf, size_t responseBufLen, CraggyResult *result, craggy_rough_time_t *time, craggy_rough_time_radius_t *radius);

/** Generates a new nonce value, placing it in the nonce specified.
 *
 * @param result Result of the nonce creation
 * @param nonce Nonce to place the generated value in
 * @return True if successful, otherwise false and {@link result} will indicate the error
 */
bool craggy_generateNonce(CraggyResult *result, craggy_rough_time_nonce_t nonce);

#endif //CRAGGY_CRAGGYCLIENT_H
