/* xZTL: Zone Translation Layer User-space Library
 *
 * Copyright 2019 Samsung Electronics
 *
 * Written by Ivan L. Picoli <i.picoli@samsung.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0

 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

#include <libxnvme_spec.h>
#include <libxnvme_znd.h>
#include <stdlib.h>
#include <sys/queue.h>
#include <xztl-ztl.h>
#include <xztl.h>
#include <ztl.h>
#include <ztl_metadata.h>

struct xztl_mthread_info mthread;

#define MGMT_MAX_RETRY 3

struct xnvme_node_mgmt_entry {
    struct app_group *    grp;
    struct ztl_pro_node * node;
    struct xztl_mp_entry *mp_entry;
    int32_t               op_code;
    STAILQ_ENTRY(xnvme_node_mgmt_entry) entry;
};

static pthread_spinlock_t xnvme_mgmt_spin;
static STAILQ_HEAD(xnvme_emu_head, xnvme_node_mgmt_entry) submit_head;

static void ztl_pro_grp_print_status(struct app_group *grp) {
    struct ztl_pro_node_grp *pro_node;
    struct ztl_pro_node *    node;
    struct ztl_pro_zone *    zone;
    uint32_t                 type_i;

    pro_node = (struct ztl_pro_node_grp *)grp->pro;
}

int ztl_pro_grp_get(struct app_group *grp, struct app_pro_addr *ctx,
                    uint32_t nsec, int32_t node_id,
                    struct xztl_thread *tdinfo) {
    struct ztl_pro_node_grp *pro = NULL;
    pro                          = (struct ztl_pro_node_grp *)grp->pro;
    struct ztl_pro_node *node    = &pro->vnodes[node_id];

    uint64_t nlevel     = nsec / (ZTL_PRO_ZONE_NUM_INNODE * ZTL_READ_SEC_MCMD);
    int32_t  remain_sec = nsec % (ZTL_PRO_ZONE_NUM_INNODE * ZTL_READ_SEC_MCMD);
    int      zn_i       = 0;
    ctx->naddr          = 0;
    for (zn_i = 0; zn_i < ZTL_PRO_ZONE_NUM_INNODE; zn_i++) {
        struct ztl_pro_zone *zone = node->vzones[zn_i];
        uint64_t sec_avlb = zone->zmd_entry->addr.g.sect + zone->capacity -
                            zone->zmd_entry->wptr_inflight;
        uint64_t actual_sec =
            nlevel * ZTL_READ_SEC_MCMD +
            (remain_sec >= ZTL_READ_SEC_MCMD ? ZTL_READ_SEC_MCMD : remain_sec);

        if (sec_avlb < actual_sec) {
            log_erra(
                "ztl_pro_grp_get: left sector is not enough sec_avlb [%u] "
                "actual_sec [%u] remain_sec [%d]",
                sec_avlb, actual_sec, remain_sec);
            goto NO_LEFT;
        }

        if (remain_sec >= ZTL_READ_SEC_MCMD) {
            remain_sec -= ZTL_READ_SEC_MCMD;
        } else {
            remain_sec = 0;
        }

        ctx->naddr++;
        ctx->addr[zn_i].addr   = zone->addr.addr;
        ctx->addr[zn_i].g.sect = zone->zmd_entry->wptr_inflight;
        ctx->nsec[zn_i]        = actual_sec;
        zone->zmd_entry->wptr_inflight += ctx->nsec[zn_i];

        ZDEBUG(ZDEBUG_PRO,
               "ztl_pro_grp_get: [%d/%d/0x%lx/0x%lx/0x%lx] "
               " sp [%d], remain_sec [%d]",
               zone->addr.g.grp, zone->addr.g.zone, (uint64_t)zone->addr.g.sect,
               zone->zmd_entry->wptr, zone->zmd_entry->wptr_inflight,
               ctx->nsec[zn_i], remain_sec);
    }

    return XZTL_OK;

NO_LEFT:
    while (zn_i) {
        zn_i--;
        ztl_pro_grp_free(grp, ctx->addr[zn_i].g.zone, 0);
        ctx->naddr--;
        ctx->addr[zn_i].addr = 0;
        ctx->nsec[zn_i]      = 0;
    }

    log_erra("ztl_pro_grp_get: No zones left. Group [%d]", grp->id);
    return XZTL_ZTL_PROV_GRP_ERR;
}

void ztl_pro_grp_free(struct app_group *grp, uint32_t zone_i, uint32_t nsec) {
    struct ztl_pro_zone *    zone;
    struct ztl_pro_node_grp *pro;
    struct xztl_zn_mcmd      cmd;
    int                      ret;

    pro  = (struct ztl_pro_node_grp *)grp->pro;
    zone = &(pro->vzones[zone_i - get_metadata_zone_num()]);

    /* Move the write pointer */
    /* A single thread touches the write pointer, no lock needed */
    zone->zmd_entry->wptr += nsec;

    ZDEBUG(ZDEBUG_PRO, "ztl_pro_grp_free: [%d/%d/0x%lx/0x%lx/0x%lx] ",
           zone->addr.g.grp, zone->addr.g.zone, (uint64_t)zone->addr.g.sect,
           zone->zmd_entry->wptr, zone->zmd_entry->wptr_inflight);

    if (ZDEBUG_PRO_GRP)
        ztl_pro_grp_print_status(grp);
}

int ztl_pro_grp_node_finish(struct app_group *grp, struct ztl_pro_node *node) {
    struct ztl_pro_zone *zone;
    struct xztl_zn_mcmd cmd;
    int                 ret;

    for (int i = 0; i < ZTL_PRO_ZONE_NUM_INNODE; i++) {
        /* Explicit closes the zone */
        zone          = node->vzones[i];
        cmd.opcode    = XZTL_ZONE_MGMT_FINISH;
        cmd.addr.addr = zone->addr.addr;
        cmd.nzones    = 1;
        ret           = xztl_media_submit_zn(&cmd);

        if (ret || cmd.status) {
            log_erra("ztl_pro_grp_node_finish: Zone finish failure [%lld] status [%d]\n",
                     zone->addr.g.zone, cmd.status);
            xztl_atomic_int32_update(&node->nr_finish_err,
                                     node->nr_finish_err + 1);
            goto ERR;
        }
        zone->zmd_entry->wptr = zone->addr.g.sect + zone->capacity;
    }

ERR:
    return ret;
}

int ztl_pro_grp_submit_mgmt(struct app_group *grp, struct ztl_pro_node *node,
                            int32_t op_code) {
    struct xztl_mp_entry *mp_cmd;
    mp_cmd = xztl_mempool_get(XZTL_NODE_MGMT_ENTRY, 0);
    if (!mp_cmd) {
        log_err("ztl_pro_grp_submit_mgmt: Mempool failed.\n");
        return XZTL_ZTL_PROV_GRP_ERR;
    }

    struct xnvme_node_mgmt_entry *et =
        (struct xnvme_node_mgmt_entry *)mp_cmd->opaque;
    et->grp      = grp;
    et->node     = node;
    et->op_code  = op_code;
    et->mp_entry = mp_cmd;

    pthread_spin_lock(&xnvme_mgmt_spin);
    STAILQ_INSERT_TAIL(&submit_head, et, entry);
    pthread_spin_unlock(&xnvme_mgmt_spin);
    return XZTL_OK;
}

static void *ztl_pro_grp_process_mgmt(void *args) {
    mthread.comp_active = 1;
    struct xnvme_node_mgmt_entry *et;
    int                           ret;
    while (mthread.comp_active) {
        usleep(1);

    NEXT:
        if (!STAILQ_EMPTY(&submit_head)) {
            pthread_spin_lock(&xnvme_mgmt_spin);
            et = STAILQ_FIRST(&submit_head);
            if (!et) {
                pthread_spin_unlock(&xnvme_mgmt_spin);
                continue;
            }

            STAILQ_REMOVE_HEAD(&submit_head, entry);
            pthread_spin_unlock(&xnvme_mgmt_spin);
            int retry = 0;
    MGMT_FAIL:
            if (et->op_code == ZTL_MGMG_FULL_ZONE) {
                ret = ztl_pro_grp_node_finish(et->grp, et->node);
            } else {
                ret = ztl_pro_grp_node_reset(et->grp, et->node);
            }

            if (ret) {
                xztl_stats_inc(XZTL_STATS_MGMT_FAIL, 1);
                log_erra("znd_pro_grp_process_mgmt: ret [%d]\n", ret);
                retry++;
                if (retry < MGMT_MAX_RETRY) {
                    goto MGMT_FAIL;
                }
            }

            xztl_mempool_put(et->mp_entry, XZTL_NODE_MGMT_ENTRY, 0);
            goto NEXT;
        }
    }

    return XZTL_OK;
}

static void ztl_pro_grp_zones_free(struct app_group *grp) {
    // struct ztl_pro_zone *zone;
    struct ztl_pro_node_grp *pro;
    struct ztl_pro_node *    vnode;
    uint8_t                  ptype;

    pro = (struct ztl_pro_node_grp *)grp->pro;
    free(pro->vnodes);
    free(pro->vzones);
}

int ztl_pro_grp_node_reset(struct app_group *grp, struct ztl_pro_node *node) {
    struct ztl_pro_zone *    zone;
    struct ztl_pro_node_grp *node_grp = grp->pro;
    int                      ret;

    for (int i = 0; i < ZTL_PRO_ZONE_NUM_INNODE; i++) {
        zone = node->vzones[i];
        ret  = ztl_pro_node_reset_zn(zone);
        if (ret) {
            log_erra("ztl_pro_grp_node_reset: Zone [%lu] reset failure\n", zone->addr.g.zone);
            xztl_atomic_int32_update(&node->nr_reset_err,
                                     node->nr_reset_err + 1);
            goto ERR;
        }
    }

    node_grp->vnodes[node->id].status = XZTL_ZMD_NODE_FREE;

ERR:
    return ret;
}

int ztl_pro_node_reset_zn(struct ztl_pro_zone *zone) {
    struct xztl_zn_mcmd   cmd;
    struct app_zmd_entry *zmde;
    int                   ret = 0;

    zmde          = zone->zmd_entry;
    cmd.opcode    = XZTL_ZONE_MGMT_RESET;
    cmd.addr.addr = zone->addr.addr;
    cmd.nzones    = 1;
    ret           = xztl_media_submit_zn(&cmd);

    if (ret || cmd.status) {
        log_erra("ztl_pro_node_reset_zn: Zone: [%lu] reset failure. status [%d]\n",
                 zone->addr.g.zone, cmd.status);
        goto ERR;
    }

    xztl_atomic_int64_update(&zmde->wptr, zone->addr.g.sect);
    xztl_atomic_int64_update(&zmde->wptr_inflight, zone->addr.g.sect);
ERR:
    return ret;
}

int ztl_pro_grp_reset_all_zones(struct app_group *grp) {
    struct xztl_zn_mcmd cmd;
    int                 ret;
    cmd.opcode = XZTL_ZONE_MGMT_RESET;
    cmd.nzones = grp->zmd.entries;

    ret = xztl_media_submit_zn(&cmd);
    if (ret || cmd.status) {
        log_erra("ztl_pro_grp_reset_all_zones: All zone reset failure. ret [%d] status [%d]\n", ret, cmd.status);
    }
    return XZTL_OK;
}

int ztl_pro_grp_node_init(struct app_group *grp) {
    struct xnvme_spec_znd_descr *zinfo;
    struct xnvme_znd_report *    rep;
    struct ztl_pro_zone *        zone;
    struct app_zmd_entry *       zmde;
    struct ztl_pro_node_grp *    pro;
    struct xztl_core *           core;
    get_xztl_core(&core);
    uint8_t ptype;

    int ntype, zone_i, node_i, zone_num_in_node;

    pro = calloc(1, sizeof(struct ztl_pro_node_grp));
    if (!pro)
        return XZTL_ZTL_PROV_ERR;

    int metadata_zone_num = get_metadata_zone_num();

    int32_t node_num = grp->zmd.entries / ZTL_PRO_ZONE_NUM_INNODE;
    pro->vnodes      = calloc(node_num, sizeof(struct ztl_pro_node));
    if (!pro->vnodes) {
        log_err("ztl_pro_grp_node_init: pro->vnodes is NULL\n");
        free(pro);
        return XZTL_ZTL_PROV_ERR;
    }
    pro->vzones = calloc(grp->zmd.entries, sizeof(struct ztl_pro_zone));
    if (!pro->vzones) {
        // vnodes have been claimed
        log_err("ztl_pro_grp_node_init: pro->vzones is NULL\n");
        free(pro->vnodes);
        free(pro);
        return XZTL_ZTL_PROV_ERR;
    }

    if (pthread_spin_init(&pro->spin, 0)) {
        log_err("ztl_pro_grp_node_init: pthread_spin_init failed\n");
        free(pro->vnodes);
        free(pro->vzones);
        return XZTL_ZTL_PROV_ERR;
    }

    grp->pro = pro;
    rep      = grp->zmd.report;

    node_i           = 0;
    zone_num_in_node = 0;
    for (zone_i = metadata_zone_num; zone_i < grp->zmd.entries; zone_i++) {
        if (zone_num_in_node == ZTL_PRO_ZONE_NUM_INNODE) {
            pro->vnodes[node_i].id = node_i;
            pro->vnodes[node_i].zone_num = zone_num_in_node;
            pro->totalnode++;
            node_i++;
            zone_num_in_node = 0;
        }

        /* We are getting the full report here */
        zinfo = XNVME_ZND_REPORT_DESCR(
            rep, grp->id * core->media->geo.zn_grp + zone_i);

        zone = &pro->vzones[zone_i - metadata_zone_num];

        zmde = ztl()->zmd->get_fn(grp, zone_i, 0);

        if (zmde->addr.g.zone != zone_i || zmde->addr.g.grp != grp->id)
            log_erra("ztl_pro_grp_node_init: zmd entry address does not match [%d/%d] [%d/%d]",
                     zmde->addr.g.grp, zmde->addr.g.zone, grp->id, zone_i);

        if ((zmde->flags & XZTL_ZMD_RSVD) || !(zmde->flags & XZTL_ZMD_AVLB)) {
            log_infoa("ztl_pro_grp_node_init: flags [%x]\n", zmde->flags);
            continue;
        }

        zone->addr.addr = zmde->addr.addr;
        zone->capacity  = zinfo->zcap;
        zone->state     = zinfo->zs;
        zone->zmd_entry = zmde;
        zone->lock      = 0;
        // zone->grp = grp;
        pro->vnodes[node_i].vzones[zone_num_in_node++] = zone;

        switch (zinfo->zs) {
            case XNVME_SPEC_ZND_STATE_EMPTY:

                if ((zmde->flags & XZTL_ZMD_USED) ||
                    (zmde->flags & XZTL_ZMD_OPEN)) {
                    log_erra(
                        "ztl_pro_grp_node_init: device reported EMPTY zone, but ZMD flag"
                        " does not match [%d/%d] [%x]",
                        grp->id, zone_i, zmde->flags);
                    continue;
                }

                zmde->npieces  = 0;
                zmde->ndeletes = 0;
                if (pro->vnodes[node_i].status != XZTL_ZMD_NODE_FREE &&
                    pro->vnodes[node_i].status != XZTL_ZMD_NODE_USED) {
                    pro->vnodes[node_i].status = XZTL_ZMD_NODE_FREE;
                }

                ZDEBUG(ZDEBUG_PRO_GRP, " ztl_pro_grp_node_init: [%d/%d] empty\n",
                       zmde->addr.g.grp, zmde->addr.g.zone);
                break;
            case XNVME_SPEC_ZND_STATE_EOPEN:
            case XNVME_SPEC_ZND_STATE_IOPEN:
            case XNVME_SPEC_ZND_STATE_CLOSED:
            case XNVME_SPEC_ZND_STATE_FULL:
                pro->vnodes[node_i].status = XZTL_ZMD_NODE_USED;
                ZDEBUG(ZDEBUG_PRO_GRP,
                       " ztl_pro_grp_node_init: ZINFO NOT CORRECT [%d/%d] , status [%d]\n",
                       zmde->addr.g.grp, zmde->addr.g.zone, zinfo->zs);
                break;

            default:
                log_infoa("ztl_pro_grp_node_init: Unknown zone condition. zone [%d], zs [%d]",
                          grp->id * core->media->geo.zn_grp + zone_i,
                          zinfo->zs);
        }

        zmde->wptr = zmde->wptr_inflight = zinfo->wp;
    }

    STAILQ_INIT(&submit_head);
    if (pthread_spin_init(&xnvme_mgmt_spin, 0)) {
        return XZTL_ZTL_PROV_GRP_ERR;
    }

    pthread_create(&mthread.comp_tid, NULL, ztl_pro_grp_process_mgmt, NULL);

    log_infoa("ztl_pro_grp_node_init: Started. Group [%d].", grp->id);
    return XZTL_OK;
}

void ztl_pro_grp_exit(struct app_group *grp) {
    struct ztl_pro_node_grp *pro;

    pro = (struct ztl_pro_node_grp *)grp->pro;

    pthread_spin_destroy(&pro->spin);
    ztl_pro_grp_zones_free(grp);
    free(grp->pro);

    log_infoa("ztl_pro_grp_exit: Stopped. Group [%d].", grp->id);
}
