/*
 * EFCP (Error and Flow Control Protocol)
 *
 *    Francesco Salvestrini <f.salvestrini@nextworks.it>
 *    Miquel Tarzan         <miquel.tarzan@i2cat.net>
 *    Leonardo Bergesio     <leonardo.bergesio@i2cat.net>
 *    Sander Vrijders       <sander.vrijders@intec.ugent.be>
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
#include <linux/kobject.h>

#define RINA_PREFIX "efcp"

#include "logs.h"
#include "utils.h"
#include "debug.h"
#include "efcp.h"
#include "efcp-utils.h"
#include "ipcp-utils.h"
#include "cidm.h"
#include "dt.h"
#include "dtp.h"
#include "dtcp.h"
#include "dtcp-ps.h"
#include "dtp-conf-utils.h"
#include "dtcp-conf-utils.h"
#include "rmt.h"
#include "dt-utils.h"
#include "dtp-ps.h"
#include "policies.h"

enum efcp_state {
        EFCP_ALLOCATED = 1,
        EFCP_DEALLOCATED
};

struct efcp {
        struct connection *     connection;
        struct ipcp_instance *  user_ipcp;
        struct dt *             dt;
        struct efcp_container * container;
        enum efcp_state         state;
        atomic_t                pending_ops;
};

struct efcp_container {
        struct efcp_imap *   instances;
        struct cidm *        cidm;
        struct efcp_config * config;
        struct rmt *         rmt;
        struct kfa *         kfa;
        spinlock_t           lock;
};

static int efcp_select_policy_set(struct efcp * efcp,
                                  const string_t * path,
                                  const string_t * ps_name)
{
        size_t cmplen;
        size_t offset;

        parse_component_id(path, &cmplen, &offset);

        if (strncmp(path, "dtp", cmplen) == 0) {
                return dtp_select_policy_set(dt_dtp(efcp->dt), path + offset,
                                             ps_name);
        } else if (strncmp(path, "dtcp", cmplen) == 0 && dt_dtcp(efcp->dt)) {
                return dtcp_select_policy_set(dt_dtcp(efcp->dt), path + offset,
                                             ps_name);
        }

        /* Currently there are no policy sets specified for EFCP (strictly
         * speaking). */
        LOG_ERR("The selected component does not exist");

        return -1;
}

typedef const string_t *const_string;

/* Helper function to parse the component id path for EFCP container. */
struct efcp *
efcp_container_parse_component_id(struct efcp_container * container,
                                  const_string * path)
{
        struct efcp * efcp;
        cep_id_t cep_id;
        size_t cmplen;
        size_t offset;
        char numbuf[8];
        int ret;

        if (!*path) {
                LOG_ERR("NULL path");
                return NULL;
        }

        parse_component_id(*path, &cmplen, &offset);
        if (cmplen > sizeof(numbuf)-1) {
                LOG_ERR("Invalid cep-id' %s'", *path);
                return NULL;
        }

        memcpy(numbuf, *path, cmplen);
        numbuf[cmplen] = '\0';
        ret = kstrtoint(numbuf, 10, &cep_id);
        if (ret) {
                LOG_ERR("Invalid cep-id '%s'", *path);
                return NULL;
        }

        efcp = efcp_imap_find(container->instances, cep_id);
        if (!efcp) {
                LOG_ERR("No connection with cep-id %d", cep_id);
                return NULL;
        }

        *path += offset;

        return efcp;

}

int efcp_container_select_policy_set(struct efcp_container * container,
                                     const string_t * path,
                                     const string_t * ps_name)
{
        struct efcp * efcp;
        const string_t * new_path = path;

        efcp = efcp_container_parse_component_id(container, &new_path);
        if (!efcp) {
                return -1;
        }

        return efcp_select_policy_set(efcp, new_path, ps_name);
}
EXPORT_SYMBOL(efcp_container_select_policy_set);

static int efcp_set_policy_set_param(struct efcp * efcp,
                                     const char * path,
                                     const char * name,
                                     const char * value)
{
        size_t cmplen;
        size_t offset;

        parse_component_id(path, &cmplen, &offset);

        if (strncmp(path, "dtp", cmplen) == 0) {
                return dtp_set_policy_set_param(dt_dtp(efcp->dt),
                                        path + offset, name, value);
        } else if (strncmp(path, "dtcp", cmplen) == 0 && dt_dtcp(efcp->dt)) {
                return dtcp_set_policy_set_param(dt_dtcp(efcp->dt),
                                        path + offset, name, value);
        }

        /* Currently there are no parametric policies specified for EFCP
         * (strictly speaking). */
        LOG_ERR("No parametric policies for this EFCP component");

        return -1;
}
EXPORT_SYMBOL(efcp_set_policy_set_param);

int efcp_container_set_policy_set_param(struct efcp_container * container,
                                        const char * path, const char * name,
                                        const char * value)
{

        struct efcp * efcp;
        const string_t * new_path = path;

        efcp = efcp_container_parse_component_id(container, &new_path);
        if (!efcp) {
                return -1;
        }

        return efcp_set_policy_set_param(efcp, new_path, name, value);
}
EXPORT_SYMBOL(efcp_container_set_policy_set_param);

static struct efcp * efcp_create(void)
{
        struct efcp * instance;

        instance = rkzalloc(sizeof(*instance), GFP_KERNEL);
        if (!instance)
                return NULL;

        instance->state = EFCP_ALLOCATED;
        atomic_set(&instance->pending_ops, 0);

        LOG_DBG("Instance %pK initialized successfully", instance);

        return instance;
}

int efcp_container_unbind_user_ipcp(struct efcp_container * efcpc,
                                    cep_id_t                cep_id)
{
        struct efcp * efcp;
        unsigned long flags;

        ASSERT(efcpc);

        if (!is_cep_id_ok(cep_id)) {
                LOG_ERR("Bad cep-id, cannot retrieve efcp instance");
                return -1;
        }

        spin_lock_irqsave(&efcpc->lock, flags);
        efcp = efcp_imap_find(efcpc->instances, cep_id);
        if (!efcp) {
                spin_unlock_irqrestore(&efcpc->lock, flags);
                LOG_ERR("There is no EFCP bound to this cep-id %d", cep_id);
                return -1;
        }
        efcp->user_ipcp = NULL;
        spin_unlock_irqrestore(&efcpc->lock, flags);

        return 0;
}
EXPORT_SYMBOL(efcp_container_unbind_user_ipcp);

struct efcp_container * efcp_container_get(struct efcp * instance)
{
        if(!instance)
                return NULL;
        return instance->container;
}
EXPORT_SYMBOL(efcp_container_get);

static int efcp_destroy(struct efcp * instance)
{
        if (!instance) {
                LOG_ERR("Bogus instance passed, bailing out");
                return -1;
        }

        if (instance->user_ipcp) {
                instance->user_ipcp->ops->flow_unbinding_ipcp(
                                instance->user_ipcp->data,
                                connection_port_id(instance->connection));
        }

        if (instance->dt) {
                /*
                 * FIXME:
                 *   Shouldn't we check for flows running, before
                 *   unbinding dtp, dtcp, cwq and rtxw ???
                 */
                struct dtp *  dtp  = dt_dtp_unbind(instance->dt);
                struct dtcp * dtcp = dt_dtcp_unbind(instance->dt);
                struct cwq *  cwq  = dt_cwq_unbind(instance->dt);
                struct rtxq * rtxq = dt_rtxq_unbind(instance->dt);

                /* FIXME: We should watch for memleaks here ... */
                if (dtp)  dtp_destroy(dtp);
                if (rtxq) rtxq_destroy(rtxq);
                if (dtcp) dtcp_destroy(dtcp);
                if (cwq)  cwq_destroy(cwq);

                dt_destroy(instance->dt);
        } else
                LOG_WARN("No DT instance present");


        if (instance->connection) {
                /* FIXME: Connection should release the cep id */
                if (is_cep_id_ok(connection_src_cep_id(instance->connection))) {
                        ASSERT(instance->container);
                        ASSERT(instance->container->cidm);

                        cidm_release(instance->container->cidm,
                                     connection_src_cep_id(instance->connection));
                }
                /* FIXME: Should we release (actually the connection) release
                 * the destination cep id? */

                connection_destroy(instance->connection);
        }

        rkfree(instance);

        LOG_DBG("EFCP instance %pK finalized successfully", instance);

        return 0;
}

struct efcp_container * efcp_container_create(struct kfa * kfa)
{
        struct efcp_container * container;

        if (!kfa) {
                LOG_ERR("Bogus KFA instances passed, bailing out");
                return NULL;
        }

        container = rkzalloc(sizeof(*container), GFP_KERNEL);
        if (!container)
                return NULL;

        container->instances   = efcp_imap_create();
        container->cidm        = cidm_create();
        if (!container->instances ||
            !container->cidm) {
                LOG_ERR("Failed to create EFCP container instance");
                efcp_container_destroy(container);
                return NULL;
        }

        container->kfa = kfa;
        spin_lock_init(&container->lock);

        return container;
}
EXPORT_SYMBOL(efcp_container_create);

int efcp_container_destroy(struct efcp_container * container)
{
        if (!container) {
                LOG_ERR("Bogus container passed, bailing out");
                return -1;
        }

        if (container->instances)  efcp_imap_destroy(container->instances,
                                                     efcp_destroy);
        if (container->cidm)       cidm_destroy(container->cidm);

        if (container->config)     efcp_config_destroy(container->config);
        rkfree(container);

        return 0;
}
EXPORT_SYMBOL(efcp_container_destroy);

struct efcp * efcp_container_find(struct efcp_container * container,
                                  cep_id_t                id)
{
        struct efcp * tmp = NULL;
        unsigned long flags;

        if (!container) {
                LOG_ERR("Bogus container passed, bailing out");
                return NULL;
        }
        if (!is_cep_id_ok(id)) {
                LOG_ERR("Bad cep-id, cannot find instance");
                return NULL;
        }

        spin_lock_irqsave(&container->lock, flags);
        tmp = efcp_imap_find(container->instances, id);
        spin_unlock_irqrestore(&container->lock, flags);

        return tmp;
}
EXPORT_SYMBOL(efcp_container_find);

struct efcp_config * efcp_container_config(struct efcp_container * container)
{
        if (!container) {
                LOG_ERR("Bogus container passed, bailing out");
                return NULL;
        }

        if (!container->config) {
                LOG_ERR("No container config set!");
                return NULL;
        }

        return container->config;
}
EXPORT_SYMBOL(efcp_container_config);

int efcp_container_config_set(struct efcp_config *    efcp_config,
                              struct efcp_container * container)
{
        if (!efcp_config || !container) {
                LOG_ERR("Bogus input parameters, bailing out");
                return -1;
        }

        container->config = efcp_config;

        LOG_DBG("Succesfully set EFCP config to EFCP container");

        return 0;
}
EXPORT_SYMBOL(efcp_container_config_set);

cep_id_t efcp_src_cep_id(struct efcp * efcp)
{ return connection_src_cep_id(efcp->connection); }

cep_id_t efcp_dst_cep_id(struct efcp * efcp)
{ return connection_dst_cep_id(efcp->connection); }

address_t efcp_src_addr(struct efcp * efcp)
{ return connection_src_addr(efcp->connection); }

address_t efcp_dst_addr(struct efcp * efcp)
{ return connection_dst_addr(efcp->connection); }

qos_id_t efcp_qos_id(struct efcp * efcp)
{ return connection_qos_id(efcp->connection); }

port_id_t efcp_port_id(struct efcp * efcp)
{ return connection_port_id(efcp->connection); }

static int efcp_write(struct efcp * efcp,
                      struct sdu *  sdu)
{
        struct dtp *        dtp;

        if (!sdu) {
                LOG_ERR("Bogus SDU passed");
                return -1;
        }
        if (!efcp) {
                LOG_ERR("Bogus EFCP passed");
                sdu_destroy(sdu);
                return -1;
        }

        ASSERT(efcp->dt);

        dtp = dt_dtp(efcp->dt);
        if (!dtp) {
                LOG_ERR("No DTP instance available");
                sdu_destroy(sdu);
                return -1;
        }

        if (dtp_write(dtp, sdu)) {
                LOG_ERR("Could not write SDU to DTP");
                return -1;
        }

        return 0;
}

int efcp_container_write(struct efcp_container * container,
                         cep_id_t                cep_id,
                         struct sdu *            sdu)
{
        struct efcp * tmp;
        unsigned long flags;
        int           ret;

        if (!container || !sdu_is_ok(sdu)) {
                LOG_ERR("Bogus input parameters, cannot write into container");
                sdu_destroy(sdu);
                return -1;
        }
        if (!is_cep_id_ok(cep_id)) {
                LOG_ERR("Bad cep-id, cannot write into container");
                sdu_destroy(sdu);
                return -1;
        }

        spin_lock_irqsave(&container->lock, flags);
        tmp = efcp_imap_find(container->instances, cep_id);
        if (!tmp) {
                spin_unlock_irqrestore(&container->lock, flags);
                LOG_ERR("There is no EFCP bound to this cep-id %d", cep_id);
                sdu_destroy(sdu);
                return -1;
        }
        if (tmp->state == EFCP_DEALLOCATED) {
                spin_unlock_irqrestore(&container->lock, flags);
                sdu_destroy(sdu);
                LOG_DBG("EFCP already deallocated");

                return 0;
        }
        atomic_inc(&tmp->pending_ops);
        spin_unlock_irqrestore(&container->lock, flags);

        ret = efcp_write(tmp, sdu);

        spin_lock_irqsave(&container->lock, flags);
        if (atomic_dec_and_test(&tmp->pending_ops) &&
            tmp->state == EFCP_DEALLOCATED) {
                spin_unlock_irqrestore(&container->lock, flags);
                efcp_destroy(tmp);

                return ret;
        }
        spin_unlock_irqrestore(&container->lock, flags);

        return ret;
}
EXPORT_SYMBOL(efcp_container_write);

static int efcp_receive(struct efcp * efcp,
                        struct pdu *  pdu)
{
        struct dtp *          dtp;
        struct dtcp *         dtcp;
        pdu_type_t            pdu_type;

        if (!pdu) {
                LOG_ERR("No pdu passed");
                return -1;
        }
        if (!efcp) {
                LOG_ERR("No efcp instance passed");
                pdu_destroy(pdu);
                return -1;
        }

        ASSERT(efcp->dt);

        pdu_type = pci_type(pdu_pci_get_ro(pdu));
        if (pdu_type_is_control(pdu_type)) {
                dtcp = dt_dtcp(efcp->dt);
                if (!dtcp) {
                        LOG_ERR("No DTCP instance available");
                        pdu_destroy(pdu);
                        return -1;
                }

                if (dtcp_common_rcv_control(dtcp, pdu))
                        return -1;

                return 0;
        }

        dtp = dt_dtp(efcp->dt);
        if (!dtp) {
                LOG_ERR("No DTP instance available");
                pdu_destroy(pdu);
                return -1;
        }

        if (dtp_receive(dtp, pdu)) {
                LOG_ERR("DTP cannot receive this PDU");
                return -1;
        }

        return 0;
}

int efcp_container_receive(struct efcp_container * container,
                           cep_id_t                cep_id,
                           struct pdu *            pdu)
{
        struct efcp * tmp;
        unsigned long flags;
        int           ret = 0;

        if (!container || !pdu_is_ok(pdu)) {
                LOG_ERR("Bogus input parameters");
                pdu_destroy(pdu);
                return -1;
        }
        if (!is_cep_id_ok(cep_id)) {
                LOG_ERR("Bad cep-id, cannot write into container");
                pdu_destroy(pdu);
                return -1;
        }

        spin_lock_irqsave(&container->lock, flags);
        tmp = efcp_imap_find(container->instances, cep_id);
        if (!tmp) {
                spin_unlock_irqrestore(&container->lock, flags);
                LOG_ERR("Cannot find the requested instance cep-id: %d",
                        cep_id);
                /* FIXME: It should call unknown_flow policy of EFCP */
                pdu_destroy(pdu);
                return -1;
        }
        if (tmp->state == EFCP_DEALLOCATED) {
                spin_unlock_irqrestore(&container->lock, flags);
                pdu_destroy(pdu);
                LOG_DBG("EFCP already deallocated");

                return 0;
        }
        atomic_inc(&tmp->pending_ops);
        spin_unlock_irqrestore(&container->lock, flags);

        ret = efcp_receive(tmp, pdu);

        spin_lock_irqsave(&container->lock, flags);
        if (atomic_dec_and_test(&tmp->pending_ops) &&
            tmp->state == EFCP_DEALLOCATED) {
                efcp_destroy(tmp);
                spin_unlock_irqrestore(&container->lock, flags);

                return ret;
        }
        spin_unlock_irqrestore(&container->lock, flags);

        return ret;
}
EXPORT_SYMBOL(efcp_container_receive);

static bool is_candidate_connection_ok(const struct connection * connection)
{
        /* FIXME: Add checks for policy params */

        if (!connection                                      ||
            !is_cep_id_ok(connection_src_cep_id(connection)) ||
            !is_port_id_ok(connection_port_id(connection)))
                return false;

        return true;
}

int efcp_enable_write(struct efcp * efcp)
{
        if (!efcp                 ||
            !efcp->user_ipcp      ||
            !efcp->user_ipcp->ops ||
            !efcp->user_ipcp->data) {
                LOG_ERR("No EFCP or user IPCP provided");
                return -1;
        }

        if (efcp->user_ipcp->ops->enable_write(efcp->user_ipcp->data,
                                               connection_port_id(efcp->connection))) {
                return -1;
        }

        return 0;
}

int efcp_disable_write(struct efcp * efcp)
{
        if (!efcp                 ||
            !efcp->user_ipcp      ||
            !efcp->user_ipcp->ops ||
            !efcp->user_ipcp->data) {
                LOG_ERR("No user IPCP provided");
                return -1;
        }

        if (efcp->user_ipcp->ops->disable_write(efcp->user_ipcp->data,
                                                connection_port_id(efcp->connection))) {
                return -1;
        }

        return 0;
}
EXPORT_SYMBOL(efcp_disable_write);

/* FIXME This function has not been ported yet to use the DTCP policy set
 * parameters in place of struct dtcp_config. This because the code
 * tries to access "connection parameters" that are defined as DTCP
 * policies (in RINA) even if DTCP is not present. This has to
 * be fixed, because the DTCP policy set can exist only if DTCP
 * is present.
 */
cep_id_t efcp_connection_create(struct efcp_container * container,
                                struct ipcp_instance *  user_ipcp,
                                address_t               src_addr,
                                address_t               dst_addr,
                                port_id_t               port_id,
                                qos_id_t                qos_id,
                                cep_id_t                src_cep_id,
                                cep_id_t                dst_cep_id,
                                struct dtp_config *     dtp_cfg,
                                struct dtcp_config *    dtcp_cfg)
{
        struct efcp *       tmp;
        struct connection * connection;
        cep_id_t            cep_id;
        struct dtp *        dtp;
        struct dtcp *       dtcp;
        struct cwq *        cwq;
        struct rtxq *       rtxq;
        uint_t              mfps, mfss;
        timeout_t           mpl, a, r = 0, tr = 0;
        struct dtp_ps       * dtp_ps;
        bool                dtcp_present;
        unsigned long       flags;

        if (!container) {
                LOG_ERR("Bogus container passed, bailing out");
                return cep_id_bad();
        }

        connection = connection_create();
        if (!connection)
                return -1;

        ASSERT(dtp_cfg);

        connection_dst_addr_set(connection, dst_addr);
        connection_src_addr_set(connection, src_addr);
        connection_port_id_set(connection, port_id);
        connection_qos_id_set(connection, qos_id);
        connection_src_cep_id_set(connection, cep_id_bad()); /* init value */
        connection_dst_cep_id_set(connection, cep_id_bad()); /* init velue */

        tmp = efcp_create();
        if (!tmp) {
                connection_destroy(connection);
                return cep_id_bad();
        }

        if (user_ipcp)
                tmp->user_ipcp = user_ipcp;

        cep_id = cidm_allocate(container->cidm);
        if (!is_cep_id_ok(cep_id)) {
                LOG_ERR("CIDM generated wrong CEP ID");
                connection_destroy(connection);
                return cep_id_bad();
        }

        /* We must ensure that the DTP is instantiated, at least ... */
        tmp->container = container;
        connection_src_cep_id_set(connection, cep_id);
        if (!is_candidate_connection_ok((const struct connection *) connection)) {
                LOG_ERR("Bogus connection passed, bailing out");
                connection_destroy(connection);
                return cep_id_bad();
        }

        tmp->connection = connection;
        tmp->dt = dt_create();
        if (!tmp->dt) {
                efcp_destroy(tmp);
                return cep_id_bad();
        }
        ASSERT(tmp->dt);
        /* FIXME: Initialization of dt required */

        /* FIXME: dtp_create() takes ownership of the connection parameter */
        dtp = dtp_create(tmp->dt,
                         container->rmt,
                         dtp_cfg);
        if (!dtp) {
                efcp_destroy(tmp);
                return cep_id_bad();
        }

        ASSERT(dtp);

        if (dt_dtp_bind(tmp->dt, dtp)) {
                dtp_destroy(dtp);
                efcp_destroy(tmp);
                return cep_id_bad();
        }

        dtcp = NULL;

        rcu_read_lock();
        dtp_ps = dtp_ps_get(dtp);
        a = dtp_ps->initial_a_timer;
        dtcp_present = dtp_ps->dtcp_present;
        rcu_read_unlock();
        if (dtcp_present) {
                dtcp = dtcp_create(tmp->dt,
                                   dtcp_cfg,
                                   container->rmt);
                if (!dtcp) {
                        efcp_destroy(tmp);
                        return cep_id_bad();
                }

                if (dt_dtcp_bind(tmp->dt, dtcp)) {
                        dtcp_destroy(dtcp);
                        efcp_destroy(tmp);
                        return cep_id_bad();
                }
        }

        if (dtcp_window_based_fctrl(dtcp_cfg)) {
                cwq = cwq_create();
                if (!cwq) {
                        LOG_ERR("Failed to create closed window queue");
                        efcp_destroy(tmp);
                        return cep_id_bad();
                }
                if (dt_cwq_bind(tmp->dt, cwq)) {
                        cwq_destroy(cwq);
                        efcp_destroy(tmp);
                        return cep_id_bad();
                }
        }

        if (dtcp_window_based_fctrl(dtcp_cfg) ||
            dtcp_rate_based_fctrl(dtcp_cfg) ||
            dtcp_rtx_ctrl(dtcp_cfg)) {
                rtxq = rtxq_create(tmp->dt, container->rmt);
                if (!rtxq) {
                        LOG_ERR("Failed to create rexmsn queue");
                        efcp_destroy(tmp);
                        return cep_id_bad();
                }
                if (dt_rtxq_bind(tmp->dt, rtxq)) {
                        rtxq_destroy(rtxq);
                        efcp_destroy(tmp);
                        return cep_id_bad();
                }
        }

        if (dt_efcp_bind(tmp->dt, tmp)) {
                efcp_destroy(tmp);
                return cep_id_bad();
        }

        /* FIXME: This is crap and have to be rethinked */

        /* FIXME: max pdu and sdu sizes are not stored anywhere. Maybe add them
         * in connection... For the time being are equal to max_pdu_size in
         * dif configuration
         */
        mfps = container->config->dt_cons->max_pdu_size;
        mfss = container->config->dt_cons->max_pdu_size;
        mpl  = container->config->dt_cons->max_pdu_life;
        if (dtcp && dtcp_rtx_ctrl(dtcp_cfg)) {
                tr = dtcp_initial_tr(dtcp_cfg);
                /* tr = msecs_to_jiffies(tr); */
                /* FIXME: r should be passed and must be a bound */
                r  = dtcp_data_retransmit_max(dtcp_cfg) * tr;
        }

        LOG_DBG("DT SV initialized with:");
        LOG_DBG("  MFPS: %d, MFSS: %d",   mfps, mfss);
        LOG_DBG("  A: %d, R: %d, TR: %d", a, r, tr);

        if (dt_sv_init(tmp->dt, mfps, mfss, mpl, a, r, tr)) {
                LOG_ERR("Could not init dt_sv");
                efcp_destroy(tmp);
                return cep_id_bad();
        }

        if (dtp_sv_init(dtp,
                        dtcp_rtx_ctrl(dtcp_cfg),
                        dtcp_window_based_fctrl(dtcp_cfg),
                        dtcp_rate_based_fctrl(dtcp_cfg),
                        a)) {
                LOG_ERR("Could not init dtp_sv");
                efcp_destroy(tmp);
                return cep_id_bad();
        }

        /***/

        spin_lock_irqsave(&container->lock, flags);
        if (efcp_imap_add(container->instances,
                          connection_src_cep_id(connection),
                          tmp)) {
                spin_unlock_irqrestore(&container->lock, flags);
                LOG_ERR("Cannot add a new instance into container %pK",
                        container);

                efcp_destroy(tmp);
                return cep_id_bad();
        }
        spin_unlock_irqrestore(&container->lock, flags);

        LOG_DBG("Connection created ("
                "Source address %d,"
                "Destination address %d, "
                "Destination cep-id %d, "
                "Source cep-id %d)",
                connection_src_addr(connection),
                connection_dst_addr(connection),
                connection_dst_cep_id(connection),
                connection_src_cep_id(connection));

        return cep_id;
}
EXPORT_SYMBOL(efcp_connection_create);

int efcp_connection_destroy(struct efcp_container * container,
                            cep_id_t                id)
{
        struct efcp * tmp;
        unsigned long flags;

        LOG_DBG("EFCP connection destroy called");

        if (!container) {
                LOG_ERR("Bogus container passed, bailing out");
                return -1;
        }
        if (!is_cep_id_ok(id)) {
                LOG_ERR("Bad cep-id, cannot destroy connection");
                return -1;
        }

        spin_lock_irqsave(&container->lock, flags);
        tmp = efcp_imap_find(container->instances, id);
        if (!tmp) {
                spin_unlock_irqrestore(&container->lock, flags);
                LOG_ERR("Cannot find instance %d in container %pK",
                        id, container);
                return -1;
        }

        if (efcp_imap_remove(container->instances, id)) {
                spin_unlock_irqrestore(&container->lock, flags);
                LOG_ERR("Cannot remove instance %d from container %pK",
                        id, container);
                return -1;
        }
        tmp->state = EFCP_DEALLOCATED;
        if (atomic_read(&tmp->pending_ops) == 0) {
                spin_unlock_irqrestore(&container->lock, flags);
                if (efcp_destroy(tmp)) {
                        LOG_ERR("Cannot destroy instance %d, instance lost", id);
                        return -1;
                }
                return 0;
        }
        LOG_DBG("efcp_connection_destroy con pending ops");
        spin_unlock_irqrestore(&container->lock, flags);

        return 0;
}
EXPORT_SYMBOL(efcp_connection_destroy);

int efcp_connection_update(struct efcp_container * container,
                           struct ipcp_instance *  user_ipcp,
                           cep_id_t                from,
                           cep_id_t                to)
{
        struct efcp * tmp;
        unsigned long flags;

        if (!container) {
                LOG_ERR("Bogus container passed, bailing out");
                return -1;
        }
        if (!is_cep_id_ok(from)) {
                LOG_ERR("Bad from cep-id, cannot update connection");
                return -1;
        }
        if (!is_cep_id_ok(to)) {
                LOG_ERR("Bad to cep-id, cannot update connection");
                return -1;
        }

        spin_lock_irqsave(&container->lock, flags);
        tmp = efcp_imap_find(container->instances, from);
        if (!tmp) {
                spin_unlock_irqrestore(&container->lock, flags);
                LOG_ERR("Cannot get instance %d from container %pK",
                        from, container);
                return -1;
        }
        if (atomic_read(&tmp->pending_ops) == 0 &&
            tmp->state == EFCP_DEALLOCATED) {
                spin_unlock_irqrestore(&container->lock, flags);
                if (efcp_destroy(tmp)) {
                        LOG_ERR("Cannot destroy instance %d, instance lost", from);
                        return -1;
                }
                return 0;
        }
        connection_dst_cep_id_set(tmp->connection, to);
        tmp->user_ipcp = user_ipcp;
        spin_unlock_irqrestore(&container->lock, flags);

        LOG_DBG("Connection updated");
        LOG_DBG("  Source address:     %d",
                connection_src_addr(tmp->connection));
        LOG_DBG("  Destination address %d",
                connection_dst_addr(tmp->connection));
        LOG_DBG("  Destination cep id: %d",
                connection_dst_cep_id(tmp->connection));
        LOG_DBG("  Source cep id:      %d",
                connection_src_cep_id(tmp->connection));

        return 0;
}
EXPORT_SYMBOL(efcp_connection_update);

int efcp_bind_rmt(struct efcp_container * container,
                  struct rmt *            rmt)
{
        if (!container) {
                LOG_ERR("Bogus EFCP container passed");
                return -1;
        }
        if (!rmt) {
                LOG_ERR("Bogus RMT instance passed");
                return -1;
        }

        container->rmt = rmt;

        return 0;
}
EXPORT_SYMBOL(efcp_bind_rmt);

int efcp_unbind_rmt(struct efcp_container * container)
{
        if (!container) {
                LOG_ERR("Bogus EFCP container passed");
                return -1;
        }

        container->rmt = NULL;

        return 0;
}
EXPORT_SYMBOL(efcp_unbind_rmt);

int efcp_enqueue(struct efcp * efcp,
                 port_id_t     port,
                 struct sdu *  sdu)
{
        if (!sdu_is_ok(sdu)) {
                LOG_ERR("Bad sdu, cannot enqueue it");
                return -1;
        }
        if (!efcp) {
                LOG_ERR("Bogus efcp passed, bailing out");
                sdu_destroy(sdu);
                return -1;
        }

        if (efcp->user_ipcp->ops->sdu_enqueue(efcp->user_ipcp->data,
                                              port,
                                              sdu)) {
                LOG_ERR("Upper ipcp could not enqueue sdu to port: %d", port);
                return -1;
        }
        return 0;
}
