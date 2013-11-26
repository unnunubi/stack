/*
 * (S|P) Data Unit
 *
 *    Francesco Salvestrini <f.salvestrini@nextworks.it>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef RINA_DU_H
#define RINA_DU_H

#include <linux/types.h>

#include "common.h"
#include "qos.h"

#define PDU_FLAGS_FRAG_MIDDLE         0x00
#define PDU_FLAGS_FRAG_FIRST          0x01
#define PDU_FLAGS_FRAG_LAST           0x02
#define PDU_FLAGS_CARRY_COMPLETE_SDU  0x03
#define PDU_FLAGS_CARRY_MULTIPLE_SDUS 0x07
#define PDU_FLAGS_DATA_RUN            0x80

typedef uint8_t pdu_flags_t;

#define PDU_TYPE_EFCP       0x8000 /* EFCP PDUs */
#define PDU_TYPE_DT         0x8001 /* Data Transfer PDU */
#define PDU_TYPE_CC         0x8002 /* Common Control PDU */
#define PDU_TYPE_SACK       0x8004 /* Selective ACK */
#define PDU_TYPE_NACK       0x8006 /* Forced Retransmission PDU (NACK) */
#define PDU_TYPE_FC         0x8009 /* Flow Control only */
#define PDU_TYPE_ACK        0x800C /* ACK only */
#define PDU_TYPE_ACK_AND_FC 0x800D /* ACK and Flow Control */
#define PDU_TYPE_MGMT       0xC000 /* Management */

typedef uint16_t pdu_type_t;

#define is_pdu_type_ok(X)                               \
        ((X && PDU_TYPE_EFCP)       ? 1 :               \
         ((X && PDU_TYPE_DT)         ? 1 :              \
          ((X && PDU_TYPE_CC)         ? 1 :             \
           ((X && PDU_TYPE_SACK)       ? 1 :            \
            ((X && PDU_TYPE_NACK)       ? 1 :           \
             ((X && PDU_TYPE_FC)         ? 1 :          \
              ((X && PDU_TYPE_ACK)        ? 1 :         \
               ((X && PDU_TYPE_ACK_AND_FC) ? 1 :        \
                ((X && PDU_TYPE_MGMT)       ? 1 :       \
                 0)))))))))

typedef uint seq_num_t;

struct pci {
        address_t  source;
        address_t  destination;

        pdu_type_t type;

        struct {
                cep_id_t source_id;
                cep_id_t dest_id;
        } ceps;

        qos_id_t   qos_id;
        seq_num_t  sequence_number;
};

/*
 * FIXME: This structure will be hidden soon. Do not access its field(s)
 *        directly, prefer the access functions below.
 */
struct buffer {
        char * data;
        size_t size;
};

/* NOTE: Creates a buffer from raw data (takes ownership) */
struct buffer * buffer_create_with(void * data, size_t size);
struct buffer * buffer_create_with_ni(void * data, size_t size);

/* NOTE: Creates an uninitialized buffer (data might be garbage) */
struct buffer * buffer_create(size_t size);
struct buffer * buffer_create_ni(size_t size);

int             buffer_destroy(struct buffer * b);

/* NOTE: The following function may return -1 */
ssize_t         buffer_length(const struct buffer * b);

/* NOTE: Returns the raw buffer memory, watch-out ... */
void *          buffer_data(struct buffer * b);

struct buffer * buffer_dup(const struct buffer * b);
struct buffer * buffer_dup_ni(const struct buffer * b);

bool            buffer_is_ok(const struct buffer * b);

/*
 * FIXME: This structure will be hidden soon. Do not access its field(s)
 *        directly, prefer the access functions below.
 */
struct sdu {
        struct buffer * buffer;
};

/* NOTE: The following function take the ownership of the buffer passed */
struct sdu *          sdu_create_from_buffer(struct buffer * buffer);
struct sdu *          sdu_create_from_buffer_ni(struct buffer * buffer);

int                   sdu_destroy(struct sdu * s);

const struct buffer * sdu_buffer(const struct sdu * s);

struct sdu *          sdu_dup(const struct sdu * sdu);
struct sdu *          sdu_dup_ni(const struct sdu * sdu);

bool                  sdu_is_ok(const struct sdu * sdu);

struct sdu *          sdu_protect(struct sdu * sdu);
struct sdu *          sdu_unprotect(struct sdu * sdu);

/*
 * FIXME: This structure will be hidden soon. Do not access its field(s)
 *        directly, prefer the access functions below.
 */
struct pdu {
        struct pci *    pci;
        struct buffer * buffer;
};

struct pdu *          pdu_create(void);
struct pdu *          pdu_create_ni(void);
bool                  pdu_is_ok(const struct pdu * pdu);
const struct buffer * pdu_buffer(const struct pdu * pdu);
const struct pci *    pdu_pci(const struct pdu * pdu);
int                   pdu_destroy(struct pdu * pdu);

#endif
