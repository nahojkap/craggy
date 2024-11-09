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

#include <string.h>
#include <time.h>
#include <stdio.h>
#include <inttypes.h>
#include <getopt.h>
#include <assert.h>
#include <stdlib.h>

#include "base64.h"
#include "CraggyTransport.h"
#include "CraggyClient.h"

// TimeUs returns the current value of the specified clock in microseconds.
static uint64_t TimeUs(clockid_t clock) {
    struct timespec tv;
    if (clock_gettime(clock, &tv)) {
        abort();
    }
    uint64_t ret = tv.tv_sec;
    ret *= 1000000;
    ret += tv.tv_nsec / 1000;
    return ret;
}

// MonotonicUs returns the value of the monotonic clock in microseconds.
uint64_t MonotonicUs() { return TimeUs(CLOCK_MONOTONIC); }

// MonotonicUs returns the value of the realtime clock in microseconds.
uint64_t RealtimeUs() { return TimeUs(CLOCK_REALTIME); }

int main(int argc, char *argv[]) {

    CraggyResult craggyResult;

    int result = 1;

    static struct option long_options[] = {
            {"host",    required_argument, 0,             'h'},
            {"key",     required_argument, 0,             'k'},
            {"nonce",   optional_argument, 0,             'n'},
            {0, 0,                         0,             0}
    };

    int c;

    char* hostname = NULL;
    char* nonce = NULL;
    char* publicKey = NULL;

    while (1) {

        int option_index = 0;
        c = getopt_long(argc, argv, "h:k:n:", long_options, &option_index);

        /* Detect the end of the options. */
        if (c == -1)
            break;

        switch (c) {
            case 0:
                /* If this option set a flag, do nothing else now. */
                if (long_options[option_index].flag != 0)
                    break;
                printf("option %s", long_options[option_index].name);
                if (optarg)
                    printf(" with arg %s", optarg);
                printf("\n");
                break;

            case 'h':
                hostname = strdup(optarg);
                break;

            case 'n':
                nonce = strdup(optarg);
                break;

            case 'k':
                publicKey = strdup(optarg);
                break;

            case '?':
                /* getopt_long already printed an error message. */
                break;

            default:
                abort();
        }
    }

    if (publicKey == NULL || hostname == NULL)
    {
        printf("usage: craggy -h <hostname:port> -k <public key> (-n <nonce>)");
        return 1;
    }

    craggy_roughtime_public_key_t rootPublicKey;
    size_t base64DecodedRootPublicKeyLen = 0;
    unsigned char *base64DecodedRootPublicKey = base64_decode((const unsigned char *) publicKey, strlen(publicKey), &base64DecodedRootPublicKeyLen);
    if (base64DecodedRootPublicKeyLen != CRAGGY_ROUGHTIME_PUBLIC_KEY_LENGTH) {
        printf("Public key length must be %d byte(s) (got %zu after base64 decoding)", CRAGGY_ROUGHTIME_PUBLIC_KEY_LENGTH, base64DecodedRootPublicKeyLen);
        goto error;
    }
    memcpy(&rootPublicKey, base64DecodedRootPublicKey, CRAGGY_ROUGHTIME_PUBLIC_KEY_LENGTH);
    free(base64DecodedRootPublicKey);

    craggy_roughtime_request_t requestBuf;
    memset(requestBuf, 0, sizeof(craggy_roughtime_request_t));

    craggy_roughtime_nonce_t nonceBytes;

    if (nonce != NULL)
    {
        size_t outLen = 0;
        unsigned char *decodedNonceBytes = base64_decode((unsigned char*)nonce, strlen(nonce), &outLen);
        if (outLen != CRAGGY_ROUGHTIME_NONCE_LENGTH) {
            printf("Nonce length must be %d byte(s) (got %zu after base64 decoding)", CRAGGY_ROUGHTIME_NONCE_LENGTH, outLen);
            goto error;
        }
        memcpy(nonceBytes, decodedNonceBytes, outLen);
        free(decodedNonceBytes);
    }
    else {
        if (!craggy_generateNonce(&craggyResult, nonceBytes))
        {
            printf("Error generating nonce: %d",craggyResult);
            goto error;
        }
    }

    if (craggy_createRequest(rootPublicKey, nonceBytes, requestBuf))
    {
        const uint64_t start_us = MonotonicUs();

        size_t responseBufLen = 0;
        craggy_roughtime_response_t responseBuf;

        if (craggy_makeRequest(hostname, requestBuf, &craggyResult, responseBuf, &responseBufLen)) {

            const uint64_t end_us = MonotonicUs();
            const uint64_t roundtripElapsedTimeUs = (end_us - start_us) / 2;
            const uint64_t endRealtimeUs = RealtimeUs();

            craggy_roughtime_result roughtimeResult;

            if (!craggy_processResponse(nonceBytes, rootPublicKey, responseBuf, responseBufLen, &craggyResult, &roughtimeResult)) {
                printf("Error parsing response: %d", craggyResult);
                goto error;
            }

            // We assume that the path to the Roughtime server is symmetric and thus add
            // half the round-trip time to the server's timestamp to produce our estimate
            // of the current time.
            printf("Received reply in %" PRIu64 "μs. (%dms)\n", end_us - start_us, (uint32_t)(end_us - start_us)/1000);
            printf("Current time is %" PRIu64 "ms from the epoch, ±%us \n", (roughtimeResult.midpoint + (roundtripElapsedTimeUs/1000)), roughtimeResult.radius);
            int64_t systemOffsetUs = (roughtimeResult.midpoint*1000000) - endRealtimeUs;
            printf("System clock differs from that estimate by %" PRId64 "μs. (%dms)\n", systemOffsetUs, (int32_t)(systemOffsetUs/1000));

        }
        else {
            printf("Error making request: %d", craggyResult);
            goto error;
        }

    }

    goto exit;
error:
    printf("Error request %d\n", result);

    assert (result != 0);

exit:
    free(hostname);
    free(publicKey);

    return result;


}