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

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#ifndef CRAGGY_PROTOCOL_H
#define CRAGGY_PROTOCOL_H

// Parser decodes requests from a time server client.
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         Number of tags                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       Offset, Tag 1 Data                      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                              ...                              |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       Offset, Tag N Data                      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                             Tag 0                             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                              ...                              |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                             Tag N                             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                             Data...                           |
// |                      (indexed by offsets)                     |
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

typedef uint32_t craggy_tag_t;

#define MAKE_TAG(val) (craggy_tag_t) ( \
    (uint32_t)(val)[0] | \
    (uint32_t)(val)[1] << (uint32_t)8 | \
    (uint32_t)(val)[2] << (uint32_t)16 | \
    (uint32_t)(val)[3] << (uint32_t)24 \
    )

#define CRAGGY_TAG_PAD MAKE_TAG("PAD\0")
#define CRAGGY_TAG_VER MAKE_TAG("VER\0")
#define CRAGGY_TAG_SIG MAKE_TAG("SIG\0")
#define CRAGGY_TAG_NONCE MAKE_TAG("NONC")
#define CRAGGY_TAG_MIDP MAKE_TAG("MIDP")
#define CRAGGY_TAG_RADI MAKE_TAG("RADI")
#define CRAGGY_TAG_ROOT MAKE_TAG("ROOT")
#define CRAGGY_TAG_PATH MAKE_TAG("PATH")
#define CRAGGY_TAG_SREP MAKE_TAG("SREP")
#define CRAGGY_TAG_CERT MAKE_TAG("CERT")
#define CRAGGY_TAG_INDX MAKE_TAG("INDX")
#define CRAGGY_TAG_PUBK MAKE_TAG("PUBK")
#define CRAGGY_TAG_MINT MAKE_TAG("MINT")
#define CRAGGY_TAG_MAXT MAKE_TAG("MAXT")
#define CRAGGY_TAG_DELE MAKE_TAG("DELE")

typedef struct CraggyRoughtimeMessage CraggyRoughtimeMessage;
typedef struct CraggyRoughtimeMessageBuilder CraggyRoughtimeMessageBuilder;

/**
 *
 * @param in
 * @param inLen
 * @param message
 * @return
 */
bool craggy_parseMessage(const uint8_t *in, size_t inLen, CraggyRoughtimeMessage **message);

/**
 *
 * @param message
 * @param tag
 * @return
 */
bool craggy_hasTag(const CraggyRoughtimeMessage *message, craggy_tag_t tag);

/**
 *
 * @param message
 * @param outData
 * @param tag
 * @param expectedLen
 * @return
 */
bool craggy_getFixedLenTag(const CraggyRoughtimeMessage *message, uint8_t **outData, craggy_tag_t tag, size_t expectedLen);

/**
 *
 * @param message
 * @return
 */
const uint8_t *craggy_getMessageBuffer(const CraggyRoughtimeMessage *message);

/**
 *
 * @param message
 * @return
 */
size_t craggy_getMessageBufferSize(const CraggyRoughtimeMessage *message);

/**
 *
 * @param message
 * @param outData
 * @param outLen
 * @param tag
 * @return
 */
bool craggy_getTag(const CraggyRoughtimeMessage *message, uint8_t **outData, size_t *outLen, craggy_tag_t tag);

/**
 *
 * @param message
 */
void craggy_destroyMessage(CraggyRoughtimeMessage *message);

/**
 *
 * @param builder
 * @param out_data
 * @param tag
 * @param len
 * @return
 */
bool craggy_addTag(CraggyRoughtimeMessageBuilder *builder, uint8_t **out_data, craggy_tag_t tag, size_t len);

/**
 *
 * @param builder
 * @param tag
 * @param data
 * @param len
 * @return
 */
bool craggy_addTagData(CraggyRoughtimeMessageBuilder *builder, craggy_tag_t tag, const uint8_t *data, size_t len);

/**
 *
 * @param num_tags
 * @return
 */
size_t craggy_messageHeaderLen(size_t num_tags);

/**
 *
 * @param numTags
 * @param out
 * @param outLen
 * @param builder
 * @return
 */
bool craggy_createMessageBuilder(size_t numTags, uint8_t *out, size_t outLen, CraggyRoughtimeMessageBuilder **builder);

/**
 *
 * @param builder
 * @param outLen
 * @return
 */
bool craggy_finish(CraggyRoughtimeMessageBuilder *builder, size_t *outLen);

/**
 *
 * @param builder
 */
void craggy_destroyMessageBuilder(CraggyRoughtimeMessageBuilder *builder);

#endif