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
#include <assert.h>

#include "CraggyClient.h"

#include <stdio.h>

#include "CraggyProtocol.h"
#include "CraggyCrypto.h"

#include "CraggyOS.h"

#define CRAGGY_ROUGHTIME_MESSAGE_HEADER_SIZE 12

bool craggy_generateNonce(CraggyResult *result, craggy_rough_time_nonce_t nonce)
{
    craggy_fillRandomBytes(nonce, CRAGGY_ROUGHTIME_NONCE_LENGTH, result);
    return *result == CraggyResultSuccess;
}

bool craggy_createRequest(craggy_rough_time_nonce_t nonce, craggy_rough_time_request_t requestBuf) {

    bool success = false;

    size_t requestBufLen = 0;
    size_t paddingLen = CRAGGY_ROUGHTIME_MIN_REQUEST_SIZE - (CRAGGY_ROUGHTIME_MESSAGE_HEADER_SIZE + craggy_messageHeaderLen(3) + CRAGGY_ROUGHTIME_NONCE_LENGTH + sizeof(uint32_t));
    uint8_t padding[paddingLen];
    craggy_memset(padding, 0, paddingLen);

    CraggyRoughtimeMessageBuilder *builder = NULL;

    if (craggy_createMessageBuilder(3, requestBuf+CRAGGY_ROUGHTIME_MESSAGE_HEADER_SIZE, CRAGGY_ROUGHTIME_MIN_REQUEST_SIZE-12, &builder)) {
        uint32_t version = CRAGGY_ROUGHTIME_VERSION;
        if (craggy_addTagData(builder, CRAGGY_TAG_VER, (uint8_t *) &version, sizeof(uint32_t))) {
            if (craggy_addTagData(builder, CRAGGY_TAG_NONCE, nonce, CRAGGY_ROUGHTIME_NONCE_LENGTH)) {
                if (craggy_addTagData(builder, CRAGGY_TAG_ZZZZ, padding, paddingLen)) {
                    success = craggy_finish(builder, &requestBufLen);
                    assert(requestBufLen == (CRAGGY_ROUGHTIME_MIN_REQUEST_SIZE-CRAGGY_ROUGHTIME_MESSAGE_HEADER_SIZE));
                    // Insert the ROUGHTIME header + the size of the payload
                    craggy_memcpy(requestBuf,&CRAGGY_ROUGHTIME_HEADER, sizeof(CRAGGY_ROUGHTIME_HEADER));
                    craggy_memcpy(requestBuf+sizeof(uint64_t),&requestBufLen, sizeof(uint32_t));
                }
            }
        }
        craggy_destroyMessageBuilder(builder);
    }
    return success;
}

static bool craggy_verifySignatureWithContext(const craggy_rough_time_public_key_t rootPublicKey, const char *context, const uint8_t *signature, const uint8_t *msg, const size_t msgLen) {

    size_t signedDataLen = strlen(context) + 1 + msgLen;
    uint8_t signedData[signedDataLen];

    craggy_memcpy(signedData, context, strlen(context));
    craggy_memset(signedData + strlen(context), 0, 1);
    craggy_memcpy(signedData + strlen(context) + 1 , msg, msgLen);

    return craggy_verifySignature(rootPublicKey, signature, signedData, signedDataLen);
}

//
// Roughtime Payload
//
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                  0x4d49544847554f52 (uint64)                  |
// |                        ("ROUGHTIM")                           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Message length (uint32)                    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// .                                                               .
// .                      Roughtime message                        .
// .                                                               .
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//

#define ERROR_OCCURRED(x) { *result = x; goto error; }
#define HASH_NODE(hash, scratch,left, right) scratch[0] = '\x01'; craggy_memcpy((scratch)+1, (left), CRAGGY_ROUGHTIME_HASH_LENGTH); craggy_memcpy((scratch)+1+CRAGGY_ROUGHTIME_HASH_LENGTH, (right), CRAGGY_ROUGHTIME_HASH_LENGTH); if (!craggy_calculateSHA512(scratch, (2*CRAGGY_ROUGHTIME_HASH_LENGTH)+1, (hash))) { ERROR_OCCURRED(CraggyResultInternalError) };
#define HASH_NONCE(hash, scratch,leaf) scratch[0] = '\x00'; craggy_memcpy((scratch)+1,(leaf), CRAGGY_ROUGHTIME_NONCE_LENGTH); if (!craggy_calculateSHA512((scratch), CRAGGY_ROUGHTIME_NONCE_LENGTH+1, (hash))) { ERROR_OCCURRED(CraggyResultInternalError) };

bool craggy_processResponse(craggy_rough_time_nonce_t nonce, craggy_rough_time_public_key_t rootPublicKey, craggy_rough_time_response_t response, size_t responseLen, CraggyResult *result, craggy_roughtime_result *roughtimeResult) {

    *result = CraggyResultGeneralError;

/**
    0. Verify the packet starts with ROUGHTIM header and size of payload
    1. Verify the signature in the certificate of the delegation message.
    2. Verify the top-level signature of the signed response message using the public key from the delegation.
    3. Verify that the nonce from the request is included in the Merkle tree.
    4. Verify that the midpoint is within the valid bounds of the delegation.
    5. Return the midpoint and radius.
 */

    CraggyRoughtimeMessage *message = NULL;
    CraggyRoughtimeMessage *certMessage = NULL;
    CraggyRoughtimeMessage *delegationMessage = NULL;
    CraggyRoughtimeMessage *srepMessage = NULL;

    uint8_t *nestedData = NULL;
    size_t nestedDataSize = 0;

    uint8_t *signature = NULL;
    uint8_t *delegationPublicKey = NULL;

    uint8_t *rootHash = NULL;
    uint32_t index = 0;

    uint8_t *path = NULL;
    size_t pathSize = 0;

    CraggyProtocolResult protocolResult = CraggyProtocolResultSuccess;

    /** 0. Verify the packet starts with ROUGHTIM header and size of payload */
    if (craggy_memcmp(response, &CRAGGY_ROUGHTIME_HEADER, sizeof(CRAGGY_ROUGHTIME_HEADER)) != 0) {
        ERROR_OCCURRED(CraggyResultParseErrorInvalidPacket);
    }
    uint32_t payloadSize = 0;

    // FIXME: Redundant mempcy
    craggy_memcpy(&payloadSize, response+sizeof(CRAGGY_ROUGHTIME_HEADER), sizeof(uint32_t));
    if (responseLen != (payloadSize+CRAGGY_ROUGHTIME_MESSAGE_HEADER_SIZE)) {
        ERROR_OCCURRED(CraggyResultParseErrorInvalidPacket);
    }

    if (!craggy_parseMessage(response+CRAGGY_ROUGHTIME_MESSAGE_HEADER_SIZE, payloadSize, &protocolResult, &message)) {
        ERROR_OCCURRED(CraggyResultParseError);
    }

    // Validate the tags are present and accounted for - we do them all here to somewhat simplify the flow in the code

    if (!craggy_hasTag(message, CRAGGY_TAG_SREP) || !craggy_hasTag(message, CRAGGY_TAG_SIG) || !craggy_hasTag(message, CRAGGY_TAG_INDX) ||
        !craggy_hasTag(message, CRAGGY_TAG_PATH) || !craggy_hasTag(message, CRAGGY_TAG_CERT) || !craggy_hasTag(message, CRAGGY_TAG_VER)) {
        ERROR_OCCURRED(CraggyResultParseErrorMissingTags);
    }

    // Validate the version matches our supported version
    if (!craggy_getFixedLenTag(message, CRAGGY_TAG_VER, 4,&nestedData)) {
        ERROR_OCCURRED(CraggyResultParseError);
    }

    const uint32_t responseVersion = nestedData[0] | (nestedData[1] << 8) | (nestedData[2] << 16) | (nestedData[3] << 24);
    if (responseVersion != CRAGGY_ROUGHTIME_VERSION) {
        ERROR_OCCURRED(CraggyResultUnsupportedVersionError);
    }

    // Validate the CERT message tags
    if (!craggy_getTag(message, CRAGGY_TAG_CERT, &nestedData, &nestedDataSize)) {
        ERROR_OCCURRED(CraggyResultParseError);
    }

    if (!craggy_parseMessage(nestedData, nestedDataSize, &protocolResult, &certMessage)) {
        ERROR_OCCURRED(CraggyResultParseError);
    }

    if (!craggy_hasTag(certMessage, CRAGGY_TAG_SIG) || !craggy_hasTag(certMessage, CRAGGY_TAG_DELE)) {
        ERROR_OCCURRED(CraggyResultParseErrorMissingTags);
    }

    if (!craggy_getTag(certMessage, CRAGGY_TAG_DELE, &nestedData, &nestedDataSize)) {
        ERROR_OCCURRED(CraggyResultParseError);
    }

    if (!craggy_parseMessage(nestedData, nestedDataSize, &protocolResult, &delegationMessage)) {
        ERROR_OCCURRED(CraggyResultParseError);
    }

    if (!craggy_hasTag(delegationMessage, CRAGGY_TAG_MINT) || !craggy_hasTag(delegationMessage, CRAGGY_TAG_MAXT) || !craggy_hasTag(delegationMessage, CRAGGY_TAG_PUBK)) {
        ERROR_OCCURRED(CraggyResultParseErrorMissingTags);
    }

    if (!craggy_getTag(message, CRAGGY_TAG_SREP, &nestedData, &nestedDataSize)) {
        ERROR_OCCURRED(CraggyResultParseError);
    }

    if (!craggy_parseMessage(nestedData, nestedDataSize, &protocolResult, &srepMessage)) {
        ERROR_OCCURRED(CraggyResultParseError);
    }
    if (!craggy_hasTag(srepMessage, CRAGGY_TAG_ROOT) || !craggy_hasTag(srepMessage, CRAGGY_TAG_MIDP) || !craggy_hasTag(srepMessage, CRAGGY_TAG_RADI)) {
        ERROR_OCCURRED(CraggyResultParseErrorMissingTags);
    }

    // At this point we should have all the tags validated (not for length though)
    assert(srepMessage != NULL && delegationMessage != NULL);

    /** 1. Verify the signature in the certificate of the delegation message. */
    if (!craggy_getFixedLenTag(certMessage, CRAGGY_TAG_SIG, CRAGGY_ROUGHTIME_SIGNATURE_LENGTH, &signature)) {
        ERROR_OCCURRED(CraggyResultParseErrorTagSizeMismatch);
    }

    if (!craggy_verifySignatureWithContext(rootPublicKey, "RoughTime v1 delegation signature--", signature, craggy_getMessageBuffer(delegationMessage), craggy_getMessageBufferSize(delegationMessage))) {
        ERROR_OCCURRED(CraggyResultAuthenticationSignatureError);
    }

    /** 2. Verify the top-level signature of the signed response message using the public key from the delegation. */

    if (!craggy_getFixedLenTag(delegationMessage, CRAGGY_TAG_PUBK, CRAGGY_ROUGHTIME_PUBLIC_KEY_LENGTH,
                               &delegationPublicKey)) {
        ERROR_OCCURRED(CraggyResultParseErrorTagSizeMismatch);
    }
    if (!craggy_getFixedLenTag(message, CRAGGY_TAG_SIG, CRAGGY_ROUGHTIME_SIGNATURE_LENGTH, &signature)) {
        ERROR_OCCURRED(CraggyResultParseErrorTagSizeMismatch);
    }

    if (!craggy_verifySignatureWithContext(delegationPublicKey, "RoughTime v1 response signature", signature, craggy_getMessageBuffer(srepMessage), craggy_getMessageBufferSize(srepMessage))) {
        ERROR_OCCURRED(CraggyResultAuthenticationSignatureError);
    }

    /** 3. Verify that the nonce from the request is included in the Merkle tree. */

    if (!craggy_getFixedLenTag(srepMessage, CRAGGY_TAG_ROOT, CRAGGY_ROUGHTIME_HASH_LENGTH, &rootHash)) {
        ERROR_OCCURRED(CraggyResultParseErrorTagSizeMismatch);
    }

    if (!craggy_getFixedLenTag(message, CRAGGY_TAG_INDX, sizeof(uint32_t), &nestedData)) {
        ERROR_OCCURRED(CraggyResultParseErrorTagSizeMismatch);
    }
    craggy_memcpy(&index, nestedData, sizeof(uint32_t));

    if (!craggy_getTag(message, CRAGGY_TAG_PATH, &path, &pathSize)) {
        ERROR_OCCURRED(CraggyResultParseError);
    }
    assert((pathSize & (uint32_t) CRAGGY_ROUGHTIME_HASH_LENGTH) == 0);

    uint8_t hash[CRAGGY_CRYPTO_SHA512_LENGTH];
    uint8_t scratch[CRAGGY_ROUGHTIME_HASH_LENGTH + CRAGGY_ROUGHTIME_HASH_LENGTH + 1];

    HASH_NONCE(hash, scratch, nonce);

    while (pathSize > 0) {
        const bool isRight = (index & (uint32_t )1) == 0;
        if (isRight) {
            HASH_NODE(hash, scratch, hash, path);
        } else {
            HASH_NODE(hash, scratch, path, hash);
        }
        index >>= (uint32_t) 1;
        pathSize -= CRAGGY_ROUGHTIME_HASH_LENGTH;
        path += CRAGGY_ROUGHTIME_HASH_LENGTH;
    }
    assert(pathSize == 0);

    if (craggy_memcmp(rootHash, hash, CRAGGY_ROUGHTIME_HASH_LENGTH) != 0) {
        ERROR_OCCURRED(CraggyResultAuthenticationHashError);
    }

    /** 4. Verify that the midpoint is within the valid bounds of the delegation. */

    craggy_roughtime_t midPoint;
    if (!craggy_getFixedLenTag(srepMessage, CRAGGY_TAG_MIDP, sizeof(craggy_roughtime_t), &nestedData)) {
        ERROR_OCCURRED(CraggyResultParseErrorTagSizeMismatch);
    }
    craggy_memcpy(&midPoint, nestedData, sizeof(craggy_roughtime_t));

    craggy_roughtime_t minTime;
    if (!craggy_getFixedLenTag(delegationMessage, CRAGGY_TAG_MINT, sizeof(craggy_roughtime_t), &nestedData)) {
        ERROR_OCCURRED(CraggyResultParseErrorTagSizeMismatch);
    }
    craggy_memcpy(&minTime, nestedData, sizeof(craggy_roughtime_t));

    craggy_roughtime_t maxTime;
    if (!craggy_getFixedLenTag(delegationMessage, CRAGGY_TAG_MAXT, sizeof(craggy_roughtime_t), &nestedData)) {
        ERROR_OCCURRED(CraggyResultParseErrorTagSizeMismatch);
    }
    craggy_memcpy(&maxTime, nestedData, sizeof(craggy_roughtime_t));

    if (midPoint < minTime || midPoint > maxTime) {
        ERROR_OCCURRED(CraggyResultAuthenticationPublicKeyUsageOutOfBounds)
    }

    /** 5. Return the midpoint and radius. */

    if (!craggy_getFixedLenTag(srepMessage, CRAGGY_TAG_RADI, sizeof(craggy_rough_time_radius_t), &nestedData))
    {
        ERROR_OCCURRED(CraggyResultParseErrorTagSizeMismatch);
    }

    craggy_memcpy(&roughtimeResult->radius, nestedData, sizeof(craggy_rough_time_radius_t));
    craggy_memcpy(&roughtimeResult->midpoint, &midPoint, sizeof(craggy_roughtime_t));

    *result = CraggyResultSuccess;
    goto exit;

error:
    assert(*result != CraggyResultSuccess);

exit:

    craggy_destroyMessage(delegationMessage);
    craggy_destroyMessage(certMessage);
    craggy_destroyMessage(srepMessage);
    craggy_destroyMessage(message);

    return *result == CraggyResultSuccess;

}
