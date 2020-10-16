/* Copyright 2020 Johan Lindquist
 * Copyright 2016 The Roughtime Authors.
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

#include <memory.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdbool.h>
#include <assert.h>

#include "CraggyTransport.h"
#include "CraggyTypes.h"
#include "CraggyClient.h"
#include "CraggyOS.h"

#define ERROR_OCCURRED(x) *result = x; goto error;

bool craggy_createSocket(int *outSocket, const char *address, CraggyResult *result) {

    *result = CraggyResultGeneralError;

    char *host = malloc(strlen(address) + 1);
    host = strcpy(host, address);
    char *port = "2002";

    char* colonPtr = strchr(address,':');
    if (colonPtr != NULL)
    {
        port = colonPtr+1;
        host[colonPtr - address] = '\0';
    }

    struct addrinfo hints;
    craggy_memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    hints.ai_flags = AI_NUMERICSERV;

    // FIXME: Handle IPV6

    struct addrinfo* addrs = NULL;
    int r = getaddrinfo(host, port, &hints, &addrs);
    if (r != 0) {
        ERROR_OCCURRED(CraggyResultNetworkNameLookupError);
    }

    int sock = socket(addrs->ai_family, addrs->ai_socktype, addrs->ai_protocol);
    if (sock < 0) {
        ERROR_OCCURRED(CraggyResultNetworkInternalError);
    }

    if (connect(sock, addrs->ai_addr, addrs->ai_addrlen)) {
        ERROR_OCCURRED(CraggyResultNetworkConnectionError);
    }

    char dest_str[INET6_ADDRSTRLEN];
    r = getnameinfo(addrs->ai_addr, addrs->ai_addrlen, dest_str, sizeof(dest_str),NULL /* don't want port information */, 0, NI_NUMERICHOST);

    if (r != 0) {
        ERROR_OCCURRED(CraggyResultNetworkNameLookupError)
    }

    *outSocket = sock;
    *result = CraggyResultSuccess;

    goto exit;

error:
    assert(*result != CraggyResultSuccess);
    close(sock);

exit:
    freeaddrinfo(addrs);
    craggy_free(host);
    return *result == CraggyResultSuccess;
}

bool craggy_makeRequest(const char *address, const craggy_rough_time_request_t requestBuf, CraggyResult *result, craggy_rough_time_response_t *responseBuf, size_t *responseBufLen) {

    *result = CraggyResultGeneralError;

    int fd = 0;
    if (!craggy_createSocket(&fd, address,result)) {
        ERROR_OCCURRED(*result);
    }

    struct timeval timeout;
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    ssize_t r;
    do {
        r = send(fd, requestBuf, sizeof(craggy_rough_time_request_t), 0 /* flags */);
    } while (r == -1 && errno == EINTR);

    if (r < 0 || r != sizeof(craggy_rough_time_request_t)) {
        ERROR_OCCURRED(CraggyResultNetworkInternalError);
    }

    ssize_t bufLen;
    do {
        bufLen = recv(fd, responseBuf, CRAGGY_ROUGH_TIME_MIN_REQUEST_SIZE, 0 /* flags */);
    } while (bufLen == -1 && errno == EINTR);

    if (bufLen == -1) {
        if (errno == EINTR) {
            ERROR_OCCURRED(CraggyResultNetworkTimeout);
        }
        ERROR_OCCURRED(CraggyResultNetworkInternalError);
    }

    *responseBufLen = bufLen;
    *result = CraggyResultSuccess;
    goto exit;

error:
    assert(*result != CraggyResultSuccess);

exit:
    close(fd);
    return *result == CraggyResultSuccess;
}
