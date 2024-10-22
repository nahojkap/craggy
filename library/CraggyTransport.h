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
#ifndef CRAGGY_UDPTRANSPORT_H
#define CRAGGY_UDPTRANSPORT_H

#include <stdbool.h>

#include "CraggyClient.h"

/** Send a Roughtime request to the server and return the response received.
 *
 * @param address The host/port to send the paylaod to.  In the form of <hostname> or <hostname:port>.  If port is omitted, the transports default value will be used.
 * @param requestBuf Buffer containing the request to send.
 * @param result Result of transport operation
 * @param responseBuf Buffer used for response
 * @param responseBufLen Size of the response buffer.  If a response is successfully received, the corresponding size of the response is signalled here too.
 * @return True if the request is successful, otherwise false (and outResult will indicate the error)
 */
bool craggy_makeRequest(const char *address, const craggy_rough_time_request_t requestBuf, CraggyResult *result, craggy_rough_time_response_t responseBuf, size_t *responseBufLen);

#endif //CRAGGY_UDPTRANSPORT_H
