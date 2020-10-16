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

#include "CraggyProtocol.h"

#include "CraggyOS.h"

struct CraggyRoughtimeMessage {
    const uint8_t *buffer;
    size_t bufferLen;
    uint32_t numTags;
    uint8_t *tags;
    uint8_t *offsets;
    uint8_t *data;
    size_t dataLen;
    bool valid;
};

struct CraggyRoughtimeMessageBuilder {

    const uint8_t *out;
    size_t outLen;

    uint32_t numTags;
    uint32_t tagsAdded;

    uint32_t nextTagDataOffset;

    bool havePreviousTag;
    craggy_tag_t previousTag;

    size_t len;
    size_t headerLen;

    uint8_t *tags;
    uint8_t *offsets;
    uint8_t *data;

    bool valid;
};


static void advance(uint8_t **ptr, size_t *len, size_t bytes) {
    *ptr += bytes;
    *len -= bytes;
}

static size_t numMessageOffsets(size_t numTags) {
    return numTags == 0 ? 0 : numTags - 1;
}

size_t craggy_messageHeaderLen(size_t num_tags) {
    return sizeof(uint32_t) /* tag count */ + sizeof(uint32_t) * numMessageOffsets(num_tags) /* offsets */ +
           sizeof(craggy_tag_t) * num_tags /* tag values */;
}

static int tag_cmp(const void *keyp, const void *memberp) {
    craggy_tag_t key, member;
    craggy_memcpy(&key, keyp, sizeof(craggy_tag_t));
    craggy_memcpy(&member, memberp, sizeof(uint32_t));
    if (key == member) {
        return 0;
    }
    return key < member ? -1 : 1;
}

bool craggy_getTag(const CraggyRoughtimeMessage *message, uint8_t **outData, size_t *outLen, craggy_tag_t tag) {
    uint8_t *tagPtr = bsearch(&tag, message->tags, message->numTags, sizeof(craggy_tag_t), tag_cmp);
    if (tagPtr == NULL) {
        return false;
    }
    size_t tagNumber = (tagPtr - message->tags) / sizeof(uint32_t);
    uint32_t offset = 0;
    if (tagNumber != 0) {
        craggy_memcpy(&offset, message->offsets + sizeof(uint32_t) * (tagNumber - 1), sizeof(uint32_t));
    }
    *outData = message->data + offset;
    if (tagNumber == message->numTags - 1) {
        *outLen = message->dataLen - offset;
    } else {
        uint32_t next_offset;
        craggy_memcpy(&next_offset, message->offsets + sizeof(uint32_t) * tagNumber, sizeof(uint32_t));
        *outLen = next_offset - offset;
    }
    return true;
}

bool craggy_hasTag(const CraggyRoughtimeMessage *message, craggy_tag_t tag) {
    uint8_t *outData = NULL;
    size_t outLen = 0;
    return craggy_getTag(message, &outData, &outLen, tag);
}


bool craggy_getFixedLenTag(const CraggyRoughtimeMessage *message, uint8_t **outData, craggy_tag_t tag,
                           size_t expectedLen) {
    size_t len;
    return craggy_getTag(message, outData, &len, tag) && len == expectedLen;
}

bool craggy_parseMessage(const uint8_t *in, const  size_t inLen, CraggyRoughtimeMessage **message) {

    uint8_t *ourIn = (uint8_t*)in;
    size_t ourInLen = inLen;

    uint32_t numTags = 0;
    craggy_memcpy(&numTags, ourIn, sizeof(uint32_t));
    advance(&ourIn, &ourInLen, sizeof(uint32_t));


    if (0xffff < numTags) {
        // Avoids any subsequent overflows.
        return false;
    }

    // Validate table of offsets.
    const size_t numOffsets = numMessageOffsets(numTags);
    if (inLen < numOffsets * sizeof(uint32_t)) {
        return false;
    }

    uint8_t *offsetsPtr = ourIn;
    advance(&ourIn, &ourInLen, numOffsets * sizeof(uint32_t));

    uint32_t previousOffset = 0;
    for (size_t i = 0; i < numOffsets; i++) {
        // A tag may have no data.  Hence, subsequent offsets may be equal.
        uint32_t offset;
        craggy_memcpy(&offset, offsetsPtr + sizeof(uint32_t) * i, sizeof(uint32_t));
        if (offset < previousOffset || offset % 4 != 0) {
            return false;
        }
        previousOffset = offset;
    }
    uint32_t lastOffset = previousOffset;

    // Validate list of tags.  Tags must be in increasing order.
    if (inLen < numTags * sizeof(craggy_tag_t)) {
        return false;
    }

    uint8_t *tagsPtr = ourIn;
    advance(&ourIn, &ourInLen, numTags * sizeof(craggy_tag_t));
    craggy_tag_t previousTag = 0;
    for (size_t i = 0; i < numTags; i++) {
        craggy_tag_t tag;
        craggy_memcpy(&tag, tagsPtr + sizeof(craggy_tag_t) * i, sizeof(craggy_tag_t));
        if (i > 0 && tag <= previousTag) {
            return false;
        }
        previousTag = tag;
    }

    // Make sure the offset table doesn't point past the end of the data.
    if (inLen < lastOffset) {
        return false;
    }

    uint8_t *dataPtr = ourIn;

    *message = craggy_calloc(1, sizeof(CraggyRoughtimeMessage));
    (*message)->buffer = in;
    (*message)->bufferLen = inLen;
    (*message)->offsets = offsetsPtr;
    (*message)->numTags = numTags;
    (*message)->tags = tagsPtr;
    (*message)->data = dataPtr;
    (*message)->dataLen = ourInLen;
    (*message)->valid = true;

    return true;

}
const uint8_t *craggy_getMessageBuffer(const CraggyRoughtimeMessage *message)
{
    return message->buffer;
}
size_t craggy_getMessageBufferSize(const CraggyRoughtimeMessage *message)
{
    return message->bufferLen;
}


void craggy_destroyMessage(CraggyRoughtimeMessage *message) {
    craggy_free(message);
}

bool craggy_createMessageBuilder(const size_t numTags, uint8_t *out, size_t outLen,
                                 CraggyRoughtimeMessageBuilder **builder) {

    size_t headerLen = craggy_messageHeaderLen(numTags);

    if (outLen < sizeof(uint32_t) || outLen < headerLen || 0xffff < numTags) {
        return NULL;
    }

    *builder = craggy_calloc(1, sizeof(CraggyRoughtimeMessageBuilder));
    (*builder)->valid = false;

    const uint32_t numTags32 = numTags;
    craggy_memcpy(out, &numTags32, sizeof(uint32_t));

    (*builder)->headerLen = headerLen;
    (*builder)->out = out;
    (*builder)->data = out + headerLen;
    (*builder)->len = outLen - headerLen;

    (*builder)->offsets = out + sizeof(uint32_t);
    (*builder)->tags = out + sizeof(uint32_t) * (1 + numMessageOffsets(numTags));

    (*builder)->numTags = numTags;
    (*builder)->out = out;
    (*builder)->outLen = outLen;

    (*builder)->valid = true;

    return true;
}

bool craggy_addTag(CraggyRoughtimeMessageBuilder *builder, uint8_t **out_data, craggy_tag_t tag, size_t len) {

    if (!builder->valid || len % 4 != 0 || builder->len < len || builder->tagsAdded >= builder->numTags ||
        (builder->havePreviousTag && tag <= builder->previousTag)) {
        return false;
    }

    craggy_memcpy(builder->tags + sizeof(uint32_t) * builder->tagsAdded, &tag, sizeof(craggy_tag_t));
    if (builder->tagsAdded > 0) {
        const uint32_t offset_32 = builder->nextTagDataOffset;
        craggy_memcpy(builder->offsets + sizeof(uint32_t) * (builder->tagsAdded - 1), &offset_32, sizeof(uint32_t));
    }

    builder->tagsAdded++;
    builder->previousTag = tag;
    builder->havePreviousTag = true;
    *out_data = builder->data;

    builder->nextTagDataOffset += len;
    builder->len -= len;
    builder->data += len;

    return true;
}

bool craggy_addTagData(CraggyRoughtimeMessageBuilder *builder, craggy_tag_t tag, const uint8_t *data, size_t len) {
    uint8_t *out;
    if (!craggy_addTag(builder, &out, tag, len)) {
        return false;
    }
    craggy_memcpy(out, data, len);
    return true;
}

bool craggy_finish(CraggyRoughtimeMessageBuilder *builder, size_t *outLen) {
    if (!builder->valid || builder->tagsAdded != builder->numTags) {
        return false;
    }
    *outLen = builder->headerLen + builder->nextTagDataOffset;
    builder->valid = false;
    return true;
}

void craggy_destroyMessageBuilder(CraggyRoughtimeMessageBuilder *builder) {
    craggy_free(builder);
}