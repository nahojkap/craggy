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

#ifndef CRAGGY_PROTOCOL_H
#define CRAGGY_PROTOCOL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include "CraggyTypes.h"

//
// Roughtime Message
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
//

typedef uint32_t craggy_tag_t;

#define MAKE_TAG(val) (craggy_tag_t) ( \
    (uint32_t)(val)[0] | \
    (uint32_t)(val)[1] << (uint32_t)8 | \
    (uint32_t)(val)[2] << (uint32_t)16 | \
    (uint32_t)(val)[3] << (uint32_t)24 \
    )

static const uint64_t CRAGGY_ROUGHTIME_HEADER = 0x4d49544847554f52;
 /**
+============+======================+===============+
|        Tag | ASCII Representation | Reference     |
+============+======================+===============+
| 0x00474953 | SIG                  | [[this memo]] |
+------------+----------------------+---------------+
| 0x00565253 | SRV                  | [[this memo]] |
+------------+----------------------+---------------+
| 0x00524556 | VER                  | [[this memo]] |
+------------+----------------------+---------------+
| 0x434e4f4e | NONC                 | [[this memo]] |
+------------+----------------------+---------------+
| 0x454c4544 | DELE                 | [[this memo]] |
+------------+----------------------+---------------+
| 0x48544150 | PATH                 | [[this memo]] |
+------------+----------------------+---------------+
| 0x49444152 | RADI                 | [[this memo]] |
+------------+----------------------+---------------+
| 0x4b425550 | PUBK                 | [[this memo]] |
+------------+----------------------+---------------+
| 0x5044494d | MIDP                 | [[this memo]] |
+------------+----------------------+---------------+
| 0x50455253 | SREP                 | [[this memo]] |
+------------+----------------------+---------------+
| 0x53524556 | VERS                 | [[this memo]] |
+------------+----------------------+---------------+
| 0x544e494d | MINT                 | [[this memo]] |
+------------+----------------------+---------------+
| 0x544f4f52 | ROOT                 | [[this memo]] |
+------------+----------------------+---------------+
| 0x54524543 | CERT                 | [[this memo]] |
+------------+----------------------+---------------+
| 0x5458414d | MAXT                 | [[this memo]] |
+------------+----------------------+---------------+
| 0x58444e49 | INDX                 | [[this memo]] |
+------------+----------------------+---------------+
| 0x5a5a5a5a | ZZZZ                 | [[this memo]] |
+------------+----------------------+---------------+
*/

#define CRAGGY_TAG_SIG MAKE_TAG("SIG\0")
#define CRAGGY_TAG_SRV MAKE_TAG("SRV\0")
#define CRAGGY_TAG_VER MAKE_TAG("VER\0")
#define CRAGGY_TAG_NONCE MAKE_TAG("NONC")
#define CRAGGY_TAG_DELE MAKE_TAG("DELE")
#define CRAGGY_TAG_PATH MAKE_TAG("PATH")
#define CRAGGY_TAG_RADI MAKE_TAG("RADI")
#define CRAGGY_TAG_PUBK MAKE_TAG("PUBK")
#define CRAGGY_TAG_MIDP MAKE_TAG("MIDP")
#define CRAGGY_TAG_SREP MAKE_TAG("SREP")
#define CRAGGY_TAG_VERS MAKE_TAG("VERS")
#define CRAGGY_TAG_MINT MAKE_TAG("MINT")
#define CRAGGY_TAG_ROOT MAKE_TAG("ROOT")
#define CRAGGY_TAG_CERT MAKE_TAG("CERT")
#define CRAGGY_TAG_MAXT MAKE_TAG("MAXT")
#define CRAGGY_TAG_INDX MAKE_TAG("INDX")
#define CRAGGY_TAG_ZZZZ MAKE_TAG("ZZZZ")

typedef enum {
    CraggyProtocolResultSuccess = 0,
    CraggyProtocolResultTooManyTags,
    CraggyProtocolResultTagsNotInOrder,
    CraggyProtocolResultInvalidOffset,
} CraggyProtocolResult;

typedef struct CraggyRoughtimeMessage CraggyRoughtimeMessage;
typedef struct CraggyRoughtimeMessageBuilder CraggyRoughtimeMessageBuilder;

/** Parse the specified buffer into a CraggyRoughtimeMessage.
 *
 * @param in Buffer to parse
 * @param inLen Length of buffer
 * @param message Parsed message
 * @return True if successfully parsed, otherwise false and result will reflect the actual error
 */
bool craggy_parseMessage(const uint8_t *in, size_t inLen, CraggyProtocolResult *result, CraggyRoughtimeMessage **message);

/** Checks the specified message for the existence of the specified tag.
 *
 * @param message Message to check
 * @param tag Tag to check for
 * @return True if the tag exists in the message, otherwise false
 */
bool craggy_hasTag(const CraggyRoughtimeMessage *message, craggy_tag_t tag);

/** Retrieves a tag with a fixed length.  If tag length does not equal the expected length, this will result in an error.
 *
 * @param message Message to retrieve tag from
 * @param outData Buffer that will be pointing to the tag value on success
 * @param tag Tag to retrieve
 * @param expectedTagLen Expected length of tag
 * @return True if tag successfully retrieved, otherwise false.
 */
bool craggy_getFixedLenTag(const CraggyRoughtimeMessage *message, craggy_tag_t tag, size_t expectedTagLen, uint8_t **outData);

/** Retrieves the underlying buffer backing this message.
 *
 * @param message Message to retrieve buffer from
 * @return Underlying buffer
 */
const uint8_t *craggy_getMessageBuffer(const CraggyRoughtimeMessage *message);

/** Retrieves the underlying buffer size backing this message.#include <stdio.h>

 *
 * @param message Message to retrieve buffer size from
 * @return Underlying buffer size
 */
size_t craggy_getMessageBufferSize(const CraggyRoughtimeMessage *message);

/** Retrieves a tag with a variable length.  If tag length does not equal the expected length, this will result in an error.
 *
 * @param message Message to retrieve tag from
 * @param tag Tag to retrieve
 * @param outData Buffer that will be pointing to the tag value on success
 * @param outLen Length of tag value
 * @return
 */
bool craggy_getTag(const CraggyRoughtimeMessage *message, craggy_tag_t tag, uint8_t **outData, size_t *outLen);

/** Destroys (frees) all of the memory associated with the specified message.
 *
 * @param message Message to destroy
 */
void craggy_destroyMessage(CraggyRoughtimeMessage *message);

/** Creates a new message builder, wrapping the specific output buffer.
 *
 * @param numTags Number of tags that will be added to the message
 * @param out Buffer to back the message with
 * @param outLen Length of the buffer
 * @param builder Builder created
 * @return True if successful, otherwise false
 */
bool craggy_createMessageBuilder(size_t numTags, uint8_t *out, size_t outLen, CraggyRoughtimeMessageBuilder **builder);

/** Adds the specified tag to the specified message.
 *
 * @param builder Builder being used
 * @param tag Tag to add to the message
 * @param len Size of tag being added
 * @param outData Pointer to location where data can be written to
 * @return True if successful, otherwise false
 */
bool craggy_addTag(CraggyRoughtimeMessageBuilder *builder, craggy_tag_t tag, size_t len, uint8_t **outData);

/** Adds the specified tag and value to the specified message.
 *
 * @param builder Builder being used
 * @param tag Tag to add to the message
 * @param data Value to add to the message
 * @param len Size of tag being added
 * @return True if successful, otherwise false
 */
bool craggy_addTagData(CraggyRoughtimeMessageBuilder *builder, craggy_tag_t tag, const uint8_t *data, size_t len);

/**
 *
 * @param num_tags
 * @return
 */
size_t craggy_messageHeaderLen(size_t num_tags);

/** Finalizes the Roughtime message being constructed by the builder.
 *
 * @param builder
 * @param outLen
 * @return
 */
bool craggy_finish(CraggyRoughtimeMessageBuilder *builder, size_t *outLen);

/** Destroys (frees) all of the memory associated with the specified message builder.
 *
 * @param builder Builder to destroy
 */
void craggy_destroyMessageBuilder(CraggyRoughtimeMessageBuilder *builder);

#ifdef __cplusplus
}
#endif

#endif // CRAGGY_PROTOCOL_H