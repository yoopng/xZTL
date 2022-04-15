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

#include <sched.h>
#include <unistd.h>
#include <xztl-media.h>
#include <xztl-ztl.h>
#include <xztl.h>
#include <ztl.h>

#define ZTL_MCMD_ENTS       XZTL_IO_MAX_MCMD
#define ZROCKS_DEBUG        0
#define ZNS_ALIGMENT        4096
#define XZTL_CTX_NVME_DEPTH 128

extern struct app_group **glist;

static void ztl_io_read_callback_mcmd(void *arg) {
    struct xztl_io_ucmd *ucmd;
    struct xztl_io_mcmd *mcmd;
    uint32_t             misalign;

    mcmd = (struct xztl_io_mcmd *)arg;
    ucmd = (struct xztl_io_ucmd *)mcmd->opaque;

    if (mcmd->status) {
        xztl_stats_inc(XZTL_STATS_READ_CALLBACK_FAIL, 1);
        log_erra("ztl_io_read_callback_mcmd: Callback. ID [%lu], S [%d/%d], C %d, WOFF [0x%lx]. St [%d]\n",
           ucmd->id, mcmd->sequence, ucmd->nmcmd, ucmd->ncb,
           ucmd->moffset[mcmd->sequence], mcmd->status);

        mcmd->callback_err_cnt++;
        if (mcmd->callback_err_cnt < MAX_CALLBACK_ERR_CNT) {
            int ret = xztl_media_submit_io(mcmd);
            if (ret) {
                xztl_stats_inc(XZTL_STATS_READ_SUBMIT_FAIL, 1);
                log_erra("ztl_io_read_callback_mcmd: submit_io. ID [%lu], S [%d/%d], C %d, WOFF [0x%lx]. ret [%d]\n",
                           ucmd->id, mcmd->sequence, ucmd->nmcmd, ucmd->ncb,
                           ucmd->moffset[mcmd->sequence], ret);
            }
            return;
        }

        ucmd->status = mcmd->status;
    } else {
        /* If I/O succeeded, we copy the data from the correct offset to the
         * user */
        misalign = mcmd->sequence;  // temp
        memcpy(ucmd->buf + mcmd->buf_off,
            (char *)mcmd->prp[0] + misalign, mcmd->cpsize); // NOLINT
    }

    xztl_atomic_int16_update(&ucmd->ncb, ucmd->ncb + 1);
    if (ucmd->ncb == ucmd->nmcmd) {
        ucmd->completed = 1;
    }
}

static void ztl_io_write_callback_mcmd(void *arg) {
    struct xztl_io_ucmd * ucmd;
    struct xztl_io_mcmd * mcmd;
    struct app_map_entry  map;
    struct app_zmd_entry *zmd;
    uint64_t              old;
    int                   ret, off_i;

    mcmd = (struct xztl_io_mcmd *)arg;
    ucmd = (struct xztl_io_ucmd *)mcmd->opaque;

    if (mcmd->status) {
        xztl_stats_inc(XZTL_STATS_WRITE_CALLBACK_FAIL, 1);
        log_erra("ztl_io_write_callback_mcmd: Callback. ID [%lu], S [%d/%d], C [%d], WOFF [0x%lx]. St [%d]\n",
            ucmd->id, mcmd->sequence, ucmd->nmcmd, ucmd->ncb,
            ucmd->moffset[mcmd->sequence], mcmd->status);
        mcmd->callback_err_cnt++;
        if (mcmd->callback_err_cnt < MAX_CALLBACK_ERR_CNT) {
            int ret = xztl_media_submit_io(mcmd);
            if (ret) {
                xztl_stats_inc(XZTL_STATS_WRITE_SUBMIT_FAIL, 1);
                log_erra("ztl_io_write_callback_mcmd: submit ID [%lu], S [%d/%d], C %d, WOFF [0x%lx]. ret [%d]\n",
                           ucmd->id, mcmd->sequence, ucmd->nmcmd, ucmd->ncb,
                           ucmd->moffset[mcmd->sequence], ret);
            }
            return;
        }
        ucmd->status = mcmd->status;
    } else {
        ucmd->moffset[mcmd->sequence] = mcmd->paddr[0];
    }

    xztl_atomic_int16_update(&ucmd->ncb, ucmd->ncb + 1);

    if (ucmd->ncb == ucmd->nmcmd) {
        ucmd->completed = 1;
		ztl()->pro->free_fn(ucmd->prov);
    }
}

static int ztl_io_submit(struct xztl_io_ucmd *ucmd) {
    int  tid, ret;
    tid = ucmd->xd.tid;

    ret = 0;
    if (ucmd->xd.node_id != -1) {
        ucmd->xd.tdinfo = ztl()->thd->get_xtd_fn(tid);

        if (ucmd->prov_type == XZTL_CMD_READ) {
            ret = ztl_io_read_ucmd(ucmd);
        } else if (ucmd->prov_type == XZTL_CMD_WRITE) {
            ret = ztl_io_write_ucmd(ucmd);
        }

    } else {
        log_err("ztl_io_submit: No available node resource.\n");
    }

    return ret;
}

static uint32_t ztl_io_write_ncmd_prov_based(struct app_pro_addr *prov) {
    uint32_t zn_i, ncmd;

    ncmd = 0;
    for (zn_i = 0; zn_i < prov->naddr; zn_i++) {
        ncmd += prov->nsec[zn_i] / ZTL_WCA_SEC_MCMD;
        if (prov->nsec[zn_i] % ZTL_WCA_SEC_MCMD != 0)
            ncmd++;
    }

    return ncmd;
}

static void ztl_io_write_poke_ctx(struct xztl_mthread_ctx *tctx) {
    struct xztl_misc_cmd misc;
    misc.opcode         = XZTL_MISC_ASYNCH_POKE;
    misc.asynch.ctx_ptr = tctx;
    misc.asynch.limit   = 1;
    misc.asynch.count   = 0;

    if (!xztl_media_submit_misc(&misc)) {
        if (!misc.asynch.count) {
            // We may check outstanding commands here
        }
    }
}

int ztl_io_read_ucmd(struct xztl_io_ucmd *ucmd) {
    int tid = ucmd->xd.tid;
    ucmd->xd.tdinfo = ztl()->thd->get_xtd_fn(tid);
    uint64_t offset = ucmd->offset;
    size_t size = ucmd->size;
    uint32_t node_id = ucmd->xd.node_id;
                       
    struct ztl_pro_node_grp *pro;
    struct ztl_pro_node *    znode;
    struct xztl_io_mcmd *    mcmd;

    uint64_t misalign, sec_size, sec_start, zindex, zone_sec_off, read_num;
    uint64_t sec_left, bytes_off, left;
    uint32_t nlevel, ncmd, cmd_i, total_cmd, zone_i, submitted;
    int      ret = 0;

    struct xztl_thread *     tdinfo = ucmd->xd.tdinfo;
    struct xztl_mthread_ctx *tctx   = tdinfo->tctx;

    // struct app_group *grp = ztl()->groups.get_fn(0);
    struct app_group *grp = glist[0];
    pro                   = grp->pro;
    znode                 = (struct ztl_pro_node *)(&pro->vnodes[node_id]);

    /*
     *1. check if it is normal : size==0   offset+size
     *2. offset
     *3. byte_off_sec:
     *4. sec_size:alignment 
     *5. sec_start:the start sector 
     */

    misalign = offset % ZNS_ALIGMENT;
    sec_size = (size + misalign) / ZNS_ALIGMENT +
               (((size + misalign) % ZNS_ALIGMENT) ? 1 : 0);
    sec_start       = offset / ZNS_ALIGMENT;
    int level_bytes = ZTL_PRO_ZONE_NUM_INNODE * ZTL_READ_SEC_MCMD;

    /* Count level:(8 * 16=128) (0~127 0lun 128~255 1lun ...)*/
    nlevel = sec_start / level_bytes;
    zindex = (sec_start % level_bytes) / ZTL_READ_SEC_MCMD;
    zone_sec_off = (nlevel * ZTL_READ_SEC_MCMD) +
                   (sec_start % level_bytes) % ZTL_READ_SEC_MCMD;
    read_num =
        ZTL_READ_SEC_MCMD - (sec_start % level_bytes) % ZTL_READ_SEC_MCMD;
    read_num = (sec_size > read_num) ? read_num : sec_size;

    /*printf("misalign=%lu sec_size=%lu sec_start=%lu nlevel=%d zindex=%lu
       zone_sec_off=%lu read_num=%lu\r\n",
        misalign, sec_size, sec_start, nlevel, zindex, zone_sec_off,
       read_num);*/

    if (ZROCKS_DEBUG)
        log_infoa("ztl_wca_read_ucmd: sec_size [%lu]\n", sec_size);

    sec_left  = sec_size;
    bytes_off = 0;
    left      = size;
    total_cmd = 0;
    while (sec_left) {
        mcmd = tdinfo->mcmd[total_cmd];
        memset(mcmd, 0x0, sizeof(struct xztl_io_mcmd));

        mcmd->opcode       = XZTL_CMD_READ;
        mcmd->naddr        = 1;
        mcmd->synch        = 0;
        mcmd->async_ctx    = tctx;
        mcmd->addr[0].addr = 0;
        mcmd->nsec[0]      = read_num;
        mcmd->callback_err_cnt = 0;
        sec_left -= mcmd->nsec[0];
        mcmd->prp[0] = tdinfo->prp[total_cmd];

        mcmd->addr[0].g.sect =
            znode->vzones[zindex]->addr.g.sect + zone_sec_off;
        mcmd->status   = 0;
        mcmd->callback = ztl_io_read_callback_mcmd;

        mcmd->sequence    = misalign;  // tmp prp offset
        mcmd->sequence_zn = zindex;
        mcmd->buf_off     = bytes_off;  // temp
        mcmd->cpsize =
            (mcmd->nsec[0] * ZNS_ALIGMENT) - misalign > left
                ? left
                : ((mcmd->nsec[0] * ZNS_ALIGMENT) - misalign);  // copy size
        left -= mcmd->cpsize;

        mcmd->opaque          = ucmd;
        mcmd->submitted       = 0;
        ucmd->mcmd[total_cmd] = mcmd;

        total_cmd++;

        if (sec_left == 0)
            break;

        zindex = (zindex + 1) % ZTL_PRO_ZONE_NUM_INNODE;
        if (zindex == 0)
            nlevel++;

        zone_sec_off = nlevel * ZTL_READ_SEC_MCMD;
        read_num =
            (sec_left > ZTL_READ_SEC_MCMD) ? ZTL_READ_SEC_MCMD : sec_left;
        bytes_off += mcmd->cpsize;
        misalign = 0;
    }

    if (total_cmd == 1) {
        ucmd->mcmd[0]->synch = 1;
        ret = xztl_media_submit_io(ucmd->mcmd[0]);

        misalign = ucmd->mcmd[0]->sequence;
        memcpy(ucmd->buf,
           (char *) ( ucmd->mcmd[0]->prp[0] + misalign), /* NOLINT */
            ucmd->mcmd[0]->cpsize);

        ucmd->completed = 1;
        return ret;
    }

    submitted = 0;
    while (submitted < total_cmd) {
        for (cmd_i = 0; cmd_i < total_cmd; cmd_i++) {
            if (ucmd->mcmd[cmd_i]->submitted)
                continue;

            ret = xztl_media_submit_io(ucmd->mcmd[cmd_i]);
            if (ret) {
                xztl_stats_inc(XZTL_STATS_READ_SUBMIT_FAIL, 1);
                log_erra("ztl_wca_read_ucmd: xztl_media_submit_io err [%d]\n", ret);
                continue;
            }

            ucmd->mcmd[cmd_i]->submitted = 1;
            submitted++;
        }
    }

    int err = xnvme_queue_wait(tctx->queue);
    if (err < 0) {
        log_erra("ztl_wca_read_ucmd: xnvme_queue_wait() returns error [%d]\n", err);
    }
    ucmd->completed = 1;
    return ret;
}

int ztl_io_write_ucmd(struct xztl_io_ucmd *ucmd) {
	int tid = ucmd->xd.tid;
	ucmd->xd.tdinfo = ztl()->thd->get_xtd_fn(tid);

    if (ucmd->xd.node_id == -1) {
        ucmd->xd.node_id = ztl()->thd->get_nid_fn(ucmd->xd.tdinfo);
    }

    if (ucmd->xd.node_id == -1) {
        log_erra("ztl_wca_write_ucmd: no node resouce [%u]\n", ucmd->xd.node_id);
        return XZTL_ZTL_WCA_S_ERR;
    }

    int32_t node_id = ucmd->xd.node_id;

    struct app_pro_addr *prov;
    struct xztl_io_mcmd *mcmd;
    struct xztl_core *   core;
    get_xztl_core(&core);
    uint32_t nsec, nsec_zn, ncmd, cmd_i, zn_i, submitted;
    int      zn_cmd_id[ZTL_PRO_STRIPE * 2][2000] = {-1};
    int      zn_cmd_id_num[ZTL_PRO_STRIPE * 2]   = {0};
    uint64_t boff;
    int      ret, ncmd_zn, zncmd_i;
	int ret = 0;

    struct xztl_thread *     tdinfo = ucmd->xd.tdinfo;
    struct xztl_mthread_ctx *tctx   = tdinfo->tctx;

    ZDEBUG(ZDEBUG_WCA, "ztl_wca_write_ucmd: Processing user write. ID [%lu]", ucmd->id);

    nsec = ucmd->size / core->media->geo.nbytes;

    /* We do not support non-aligned buffers */
    if (ucmd->size % (core->media->geo.nbytes * ZTL_WCA_SEC_MCMD_MIN) != 0) {
        log_erra("ztl_wca_write_ucmd: Buffer is not aligned to [%d] bytes [%lu] bytes.",
                 core->media->geo.nbytes * ZTL_WCA_SEC_MCMD_MIN, ucmd->size);
        goto FAILURE;
    }

    /* First we check the number of commands based on ZTL_WCA_SEC_MCMD */
    ncmd = nsec / ZTL_WCA_SEC_MCMD;
    if (nsec % ZTL_WCA_SEC_MCMD != 0)
        ncmd++;

    if (ncmd > XZTL_IO_MAX_MCMD) {
        log_erra(
            "ztl_wca_write_ucmd: User command exceed XZTL_IO_MAX_MCMD. "
            "[%d] of [%d]",
            ncmd, XZTL_IO_MAX_MCMD);
        goto FAILURE;
    }

    prov = tdinfo->prov;
    if (!prov) {
        log_erra("ztl_wca_write_ucmd: Provisioning failed. nsec [%d], node_id [%d]", nsec,
                 node_id);
        goto FAILURE;
    }

	ret = ztl()->pro->new_fn(nsec, node_id, prov, tdinfo);
	if (ret)
		goto FAILURE;

    /* We check the number of commands again based on the provisioning */
    ncmd = ztl_io_write_ncmd_prov_based(prov);
    if (ncmd > XZTL_IO_MAX_MCMD) {
        log_erra(
            "ztl_wca_write_ucmd: User command exceed XZTL_IO_MAX_MCMD. "
            "[%d] of [%d]",
            ncmd, XZTL_IO_MAX_MCMD);
        goto FAIL_NCMD;
    }

    ucmd->prov      = prov;
    ucmd->nmcmd     = prov->naddr;
    ucmd->completed = 0;
    ucmd->ncb       = 0;

    boff = (uint64_t)ucmd->buf;

    ZDEBUG(ZDEBUG_WCA, "ztl_wca_write_ucmd: NMCMD [%d]", ncmd);

    /* Populate media commands */
    cmd_i = 0;
	
    struct iovec dvecs[ZTL_PRO_STRIPE * 2][32];
    for (int i = 0; i < prov->naddr; i++) {
	 uint64_t dvec_cnt = prov->nsec[i] / ZTL_WCA_SEC_MCMD;
	 uint64_t dvec_nbytes= prov->nsec[i]  *  ZNS_ALIGMENT;
	 uint64_t tbuf = boff + i * ZTL_WCA_SEC_MCMD * ZNS_ALIGMENT;
	 for (uint64_t j = 0; j < dvec_cnt; j++) {
		struct iovec* piovec = &dvecs[i][j];
		piovec->iov_base = tbuf;
		piovec->iov_len = ZTL_WCA_SEC_MCMD * ZNS_ALIGMENT;
		tbuf += ZTL_PRO_STRIPE * ZTL_PRO_STRIPE * ZNS_ALIGMENT;
	 }

	prov->addr[i].g.sect += prov->nsec[i];
	mcmd = tdinfo->mcmd[cmd_i++];
	mcmd->opcode = XZTL_CMD_WRITE;
	mcmd->synch       = 0;
	mcmd->status      = 0;	
	mcmd->callback  = ztl_io_write_callback_mcmd;
	mcmd->opaque    = ucmd;
	mcmd->async_ctx = tctx;
	mcmd->dvec = &dvecs[i];
	mcmd->dvec_cnt = dvec_cnt;
	mcmd->dvec_nbytes = dvec_nbytes;
	ret = xztl_media_submit_io(mcmd);
	if (ret) {
		printf("xztl_media_submit_io failed")
		xztl_stats_inc(XZTL_STATS_WRITE_SUBMIT_FAIL, 1);
		ztl_io_write_poke_ctx(tctx);
	}
    }


    ZDEBUG(ZDEBUG_WCA, "ztl_wca_write_ucmd: Populated: %d", cmd_i);

    /* Poke the context for completions */
    while (ucmd->ncb < ucmd->nmcmd) {
        ztl_io_write_poke_ctx(tctx);
    }

    ZDEBUG(ZDEBUG_WCA, " ztl_wca_write_ucmd: Submitted [%d]", submitted);

    return XZTL_OK;

    /* If we get a submit failure but previous I/Os have been
     * submitted, we fail all subsequent I/Os and completion is
     * performed by the callback function */

FAIL_NCMD:
    for (zn_i = 0; zn_i < prov->naddr; zn_i++)
        prov->nsec[zn_i] = 0;

    ztl()->pro->free_fn(prov);

FAILURE:
    ucmd->status    = XZTL_ZTL_WCA_S_ERR;
    ucmd->completed = 1;
    return XZTL_ZTL_WCA_S_ERR;
}

static int ztl_io_init(void) {
    return ztl()->thd->init_fn();
}

static void ztl_io_exit(void) {
    ztl()->thd->exit_fn();
}

static struct app_io_mod libztl_io = {.mod_id      = LIBZTL_IO,
                                      .name        = "LIBZTL-IO",
                                      .init_fn     = ztl_io_init,
                                      .exit_fn     = ztl_io_exit,
                                      .read_fn     = ztl_io_read_ucmd,
                                      .write_fn    = ztl_io_write_ucmd};

void ztl_io_register(void) {
    ztl_mod_register(ZTLMOD_IO, LIBZTL_IO, &libztl_io);
}

