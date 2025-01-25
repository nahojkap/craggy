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

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

#include "CraggyTypes.h"

/** Creates a new Roughtime request message containing the specified nonce.
 *
 * @param rootPublicKey Root public key of the server in question
 * @param nonce The nonce to include in the request
 * @param requestBuf Buffer for the request
 * @return Status of the invocation
 */
CraggyResult craggy_createRequest(craggy_roughtime_public_key_t rootPublicKey, craggy_roughtime_nonce_t nonce, craggy_roughtime_request_t requestBuf);

/** Processes a response from the server, verifying the necessary signatures and extracting the time and radius if successful.
 *
 * @param nonce The nonce originally used for creating the request
 * @param rootPublicKey Root public key of the server in question
 * @param responseBuf Response to be processed
 * @param responseBufLen Size of the response to be processed
 * @param roughtimeResult Result structure populated with midpoint and radius according to documentation.
 * @return Status of the invocation
 */
CraggyResult craggy_processResponse(craggy_roughtime_nonce_t nonce, craggy_roughtime_public_key_t rootPublicKey, craggy_roughtime_response_t responseBuf, size_t responseBufLen, craggy_roughtime_result *roughtimeResult);

/** Generates a new nonce value, placing it in the nonce specified.
 *
 * @param result Result of the nonce creation
 * @param nonce Nonce to place the generated value in
 * @return Status of the invocation
 */
CraggyResult craggy_generateNonce(craggy_roughtime_nonce_t nonce);

#ifdef __cplusplus
}
#endif

#endif //CRAGGY_CRAGGYCLIENT_H
