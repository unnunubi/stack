/*
 * Protocol Data Unit
 *
 *    Francesco Salvestrini <f.salvestrini@nextworks.it>
 *    Miquel Tarzan         <miquel.tarzan@i2cat.net>
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

#include <linux/export.h>
#include <linux/types.h>

#define RINA_PREFIX "pdu"

#include "logs.h"
#include "utils.h"
#include "debug.h"
#include "pdu.h"

struct pci {
        address_t  source;
        address_t  destination;

        pdu_type_t type;

        struct {
                cep_id_t source;
                cep_id_t destination;
        } ceps;

        qos_id_t   qos_id;
        seq_num_t  sequence_number;
};

static bool pci_is_ok(const struct pci * pci)
{ return pci && pdu_type_is_ok(pci->type) ? true : false; }

static struct pci * pci_create_gfp(gfp_t flags)
{
        struct pci * tmp;

        tmp = rkzalloc(sizeof(*tmp), flags);
        if (!tmp)
                return NULL;

        return tmp;
}

struct pci * pci_create(void)
{ return pci_create_gfp(GFP_KERNEL); }
EXPORT_SYMBOL(pci_create);

struct pci * pci_create_ni(void)
{ return pci_create_gfp(GFP_ATOMIC); }
EXPORT_SYMBOL(pci_create_ni);

int pci_cep_source_set(struct pci * pci,
                       cep_id_t     src_cep_id)
{
        if (!pci)
                return -1;

        if (!is_cep_id_ok(src_cep_id))
                return -1;

        pci->ceps.destination = src_cep_id;
        return 0;
}
EXPORT_SYMBOL(pci_cep_source_set);

int pci_cep_destination_set(struct pci * pci,
                            cep_id_t     dst_cep_id)
{
        if (!pci)
                return -1;

        if (!is_cep_id_ok(dst_cep_id))
                return -1;

        pci->ceps.source = dst_cep_id;

        return 0;
}
EXPORT_SYMBOL(pci_cep_destination_set);

int pci_destination_set(struct pci * pci,
                        address_t    dst_address)
{
        if (!pci)
                return -1;

        pci->destination = dst_address;

        return 0;
}
EXPORT_SYMBOL(pci_destination_set);

int pci_source_set(struct pci * pci,
                   address_t    src_address)
{
        if (!pci)
                return -1;

        pci->source = src_address;

        return 0;
}
EXPORT_SYMBOL(pci_source_set);

int pci_nxt_seq_send_set(struct pci * pci,
                         seq_num_t    nxt_seq_send)
{
        if (!pci)
                return -1;

        pci->sequence_number = nxt_seq_send;

        return 0;
}
EXPORT_SYMBOL(pci_nxt_seq_send_set);

int pci_qos_id_set(struct pci * pci,
                   qos_id_t   qos_id)
{
        if (!pci)
                return -1;

        pci->qos_id = qos_id;

        return 0;
}
EXPORT_SYMBOL(pci_qos_id_set);

int pci_type_set(struct pci * pci, pdu_type_t type)
{
        if (!pci)
                return -1;

        pci->type = type;

        return 0;
}
EXPORT_SYMBOL(pci_type_set);

static struct pci * pci_create_from_gfp(gfp_t        flags,
                                        const void * data)
{
        struct pci * tmp;

        if (!data)
                return NULL;

        tmp = rkmalloc(sizeof(*tmp), flags);
        if (!tmp)
                return NULL;

        if (!memcpy(tmp, data, sizeof(*tmp))) {
                rkfree(tmp);
                return NULL;
        }

        ASSERT(pci_is_ok(tmp));

        return tmp;
}

struct pci * pci_create_from(const void * data)
{ return pci_create_from_gfp(GFP_KERNEL, data); }
EXPORT_SYMBOL(pci_create_from);

struct pci * pci_create_from_ni(const void * data)
{ return pci_create_from_gfp(GFP_ATOMIC, data); }
EXPORT_SYMBOL(pci_create_from_ni);

int pci_destroy(struct pci * pci)
{
        if (!pci)
                return -1;

        rkfree(pci);
        return 0;
}
EXPORT_SYMBOL(pci_destroy);

static struct pci * pci_dup_gfp(gfp_t              flags,
                                const struct pci * pci)
{
        struct pci * tmp;

        if (pci_is_ok(pci))
                return NULL;

        tmp = rkmalloc(sizeof(*tmp), flags);
        if (!tmp)
                return NULL;

        if (!memcpy(tmp, pci, sizeof(*tmp))) {
                rkfree(tmp);
                return NULL;
        }

        ASSERT(pci_is_ok(tmp));

        return tmp;
}

struct pci * pci_dup(const struct pci * pci)
{ return pci_dup_gfp(GFP_KERNEL, pci); }
EXPORT_SYMBOL(pci_dup);

struct pci * pci_dup_ni(const struct pci * pci)
{ return pci_dup_gfp(GFP_ATOMIC, pci); }
EXPORT_SYMBOL(pci_dup_ni);

pdu_type_t pci_type(const struct pci * pci)
{
        ASSERT(pci); /* FIXME: Should not be an ASSERT ... */

        return pci->type;
}
EXPORT_SYMBOL(pci_type);

ssize_t pci_length(const struct pci * pci)
{
        if (!pci_is_ok(pci))
                return -1;

        return sizeof(*pci);
}
EXPORT_SYMBOL(pci_length);

address_t pci_source(const struct pci * pci)
{
        ASSERT(pci); /* FIXME: Should not be an ASSERT ... */

        return pci->source;
}
EXPORT_SYMBOL(pci_source);

address_t pci_destination(const struct pci * pci)
{
        ASSERT(pci); /* FIXME: Should not be an ASSERT ... */

        return pci->destination;
}
EXPORT_SYMBOL(pci_destination);

cep_id_t pci_cep_destination(const struct pci * pci)
{
        if (!pci)
                return cep_id_bad();

        return pci->ceps.destination;
}
EXPORT_SYMBOL(pci_cep_destination);

cep_id_t pci_cep_source(const struct pci * pci)
{
        if (!pci)
                return cep_id_bad();

        return pci->ceps.source;
}
EXPORT_SYMBOL(pci_cep_source);

struct pdu {
        struct pci *    pci;
        struct buffer * buffer;
};

bool pdu_is_ok(const struct pdu * p)
{ return (p && p->pci && p->buffer) ? true : false; }
EXPORT_SYMBOL(pdu_is_ok);

static struct pdu * pdu_create_gfp(gfp_t flags)
{
        struct pdu * tmp;

        tmp = rkzalloc(sizeof(*tmp), flags);
        if (!tmp)
                return NULL;

        tmp->pci    = NULL;
        tmp->buffer = NULL;

        return tmp;
}

struct pdu * pdu_create(void)
{ return pdu_create_gfp(GFP_KERNEL); }
EXPORT_SYMBOL(pdu_create);

struct pdu * pdu_create_ni(void)
{ return pdu_create_gfp(GFP_ATOMIC); }
EXPORT_SYMBOL(pdu_create_ni);

static struct pdu * pdu_create_with_gfp(gfp_t        flags,
                                        struct sdu * sdu)
{
        struct pdu *          tmp_pdu;
        const struct buffer * tmp_buff;
        const uint8_t *       ptr;

        /*
         * FIXME: This implementation is pure crap, please fix it soon
         */

        if (!sdu_is_ok(sdu))
                return NULL;

        tmp_buff = sdu_buffer_ro(sdu);
        ASSERT(tmp_buff);

        if (buffer_length(tmp_buff) < sizeof(struct pci))
                return NULL;

        tmp_pdu = pdu_create_gfp(flags);
        if (!tmp_pdu)
                return NULL;

        ptr = (const uint8_t *) buffer_data_ro(tmp_buff);
        ASSERT(ptr);

        tmp_pdu->pci    =
                pci_create_from_gfp(flags, ptr);
        tmp_pdu->buffer =
                buffer_create_from_gfp(flags,
                                       ptr + sizeof(struct pci),
                                       (buffer_length(sdu->buffer) -
                                        sizeof(struct pci)));

        ASSERT(pdu_is_ok(tmp_pdu));

        return tmp_pdu;
}

struct pdu * pdu_create_with(struct sdu * sdu)
{ return pdu_create_with_gfp(GFP_KERNEL, sdu); }
EXPORT_SYMBOL(pdu_create_with);

struct pdu * pdu_create_with_ni(struct sdu * sdu)
{ return pdu_create_with_gfp(GFP_ATOMIC, sdu); }
EXPORT_SYMBOL(pdu_create_with_ni);

const struct buffer * pdu_buffer_get_ro(const struct pdu * pdu)
{
        if (!pdu_is_ok(pdu))
                return NULL;

        return pdu->buffer;
}
EXPORT_SYMBOL(pdu_buffer_get_ro);

struct buffer * pdu_buffer_get_rw(struct pdu * pdu)
{
        if (!pdu_is_ok(pdu))
                return NULL;

        return pdu->buffer;
}
EXPORT_SYMBOL(pdu_buffer_get_rw);

int pdu_buffer_set(struct pdu * pdu, struct buffer * buffer)
{
        if (!pdu)
                return -1;

        if (!buffer_is_ok(buffer))
                return -1;

        pdu->buffer = buffer;

        return 0;
}
EXPORT_SYMBOL(pdu_buffer_set);

const struct pci * pdu_pci_get_ro(const struct pdu * pdu)
{
        if (!pdu_is_ok(pdu))
                return NULL;

        return pdu->pci;
}
EXPORT_SYMBOL(pdu_pci_get_ro);

struct pci * pdu_pci_get_rw(struct pdu * pdu)
{
        if (!pdu_is_ok(pdu))
                return NULL;

        return pdu->pci;
}
EXPORT_SYMBOL(pdu_pci_get_rw);

int pdu_pci_set(struct pdu * pdu, struct pci * pci)
{
        if (!pdu)
                return -1;

        if (!pci_is_ok(pci))
                return -1;

        pdu->pci = pci;

        return 0;
}
EXPORT_SYMBOL(pdu_pci_set);

int pdu_destroy(struct pdu * p)
{
        if (p)
                return -1;

        if (p->pci)    rkfree(p->pci);
        if (p->buffer) buffer_destroy(p->buffer);

        rkfree(p);

        return 0;
}
EXPORT_SYMBOL(pdu_destroy);