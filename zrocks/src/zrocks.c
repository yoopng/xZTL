/* libztl: User-space Zone Translation Layer Library
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

#include <libxnvme.h>
#include <libxnvme_znd.h>
#include <libzrocks.h>
#include <omp.h>
#include <pthread.h>
#include <stdlib.h>
#include <xztl-media.h>
#include <xztl-mempool.h>
#include <xztl-ztl.h>
#include <xztl.h>
#include <ztl-media.h>
#include <ztl.h>

#define ZROCKS_DEBUG       0
#define ZROCKS_BUF_ENTS    1024
#define ZROCKS_MAX_READ_SZ (256 * ZNS_ALIGMENT) /* 512 KB */

extern struct znd_media zndmedia;
#define ZROCKS_READ_MAX_RETRY 3

/* Remove this lock if we find a way to get a thread ID starting from 0 */
static pthread_spinlock_t zrocks_mp_spin;

void *zrocks_alloc(size_t size) {
    return xztl_media_dma_alloc(size);
}

void zrocks_free(void *ptr) {
    xztl_media_dma_free(ptr);
}

int zrocks_new(uint64_t id, void *buf, size_t size, uint16_t level) {
    struct xztl_io_ucmd ucmd;
    // int                 ret;

    if (ZROCKS_DEBUG)
        log_infoa("zrocks_new: ID [%lu], level [%d], size [%lu]\n", id, level,
                  size);

    ucmd.app_md = 0;
    // ret = __zrocks_write(&ucmd, id, buf, size, level);

    // return (!ret) ? ucmd.status : ret;
    return XZTL_OK;
}

int zrocks_write(void *buf, size_t size, int32_t *node_id, int tid) {
    uint32_t misalign;
    size_t   new_sz, alignment;
    alignment = ZNS_ALIGMENT * ZTL_WCA_SEC_MCMD_MIN;
    misalign  = size % alignment;
    new_sz = (misalign != 0) ? size + (alignment - misalign) : size;

    if (ZROCKS_DEBUG)
        log_infoa(
            "__zrocks_write: ID [%lu], node_id [%d], size [%lu], new size [%lu], "
            "aligment [%lu], misalign [%d]\n",
            id, *node_id, size, new_sz, alignment, misalign);
    int ret = 0;
    struct xztl_io_ucmd ucmd;
    ucmd.app_md = 1;
    ucmd.prov_type  = XZTL_CMD_WRITE;
    ucmd.id         = 0;
    ucmd.buf        = buf;
    ucmd.size       = new_sz;
    ucmd.status     = 0;
    ucmd.completed  = 0;
    ucmd.callback   = NULL;
    ucmd.prov       = NULL;
    ucmd.xd.node_id = *node_id;
    ucmd.xd.tid     = tid;
    ret = ztl()->wca->write_fn(&ucmd);
    if (ret || ucmd.status) {
         log_erra("zrocks_write: node_id [%d], size [%lu], tid [%d] ret [%d] status [%d]\n",
                  *node_id, size, tid, ret, ucmd.status);
        return XZTL_ZROCKS_WRITE_ERR;
    }

    *node_id = ucmd.xd.node_id;

    xztl_stats_inc(XZTL_STATS_APPEND_BYTES_U, size);
    xztl_stats_inc(XZTL_STATS_APPEND_BYTES, new_sz);
    xztl_stats_inc(XZTL_STATS_APPEND_UCMD, 1);

    return XZTL_OK;
}

int zrocks_read_obj(uint64_t id, uint64_t offset, void *buf, size_t size) {
    uint64_t objsec_off;

    if (ZROCKS_DEBUG)
        log_infoa("zrocks_read_obj: ID [%lu], off [%lu], size [%lu]\n", id, offset,
                  size);

    /* This assumes a single zone offset per object */
    objsec_off = ztl()->map->read_fn(id);

    if (ZROCKS_DEBUG)
        log_infoa("zrocks_read_obj: objsec_off [%lx], userbytes_off [%lu]\n", objsec_off, offset);

    return XZTL_OK;
}

int zrocks_read(uint32_t node_id, uint64_t offset, void *buf, uint64_t size,
                int tid) {
    int                 ret;
    struct xztl_io_ucmd ucmd;

    ucmd.prov_type = XZTL_CMD_READ;
    ucmd.id        = 0;
    ucmd.buf       = buf;
    ucmd.size      = size;
    ucmd.offset    = offset;
    ucmd.status    = 0;
    ucmd.callback  = NULL;
    ucmd.prov      = NULL;
    ucmd.completed = 0;
    ucmd.xd.node_id = node_id;
    ucmd.xd.tid     = tid;
    if (ZROCKS_DEBUG)
        log_infoa("zrocks_read: node [%d] off [%lu], size [%lu], tid [%d]\n",
                  node_id, offset, size, tid);
               
    int retry = 0;
READ_FAIL:
    ret = ztl()->wca->read_fn(&ucmd);
    if (ret || ucmd.status) {
        log_erra("zrocks_read: submit_fn failed. node [%d] off [%lu], sz [%lu] ret [%d] status[%d]\n",
                 node_id, offset, size, ret, ucmd.status);
        retry++;
        if (retry < ZROCKS_READ_MAX_RETRY) {
            goto READ_FAIL;
        }
        return XZTL_ZROCKS_READ_ERR;
    }

    xztl_stats_inc(XZTL_STATS_READ_BYTES_U, size);
    xztl_stats_inc(XZTL_STATS_READ_UCMD, 1);

    return XZTL_OK;
}

int zrocks_get_resource() {
    int tid, rettid = -1;

    for (tid = 0; tid < ZTL_TH_NUM; tid++) {
       if (!xtd[tid].usedflag) {
           xtd[tid].usedflag = true;
           rettid = tid;
           break;
      }
    }
    return rettid;
}

void zrocksk_put_resource(int tid) {
    xtd[tid].usedflag = false;
}

int zrocks_delete(uint64_t id) {
    uint64_t old;

    return ztl()->map->upsert_fn(id, 0, &old, 0);
}

int zrocks_trim(uint32_t node_id) {
    struct app_group *       grp      = ztl()->groups.get_fn(0);
    struct ztl_pro_node_grp *node_grp = grp->pro;
    struct ztl_pro_node *    node =
        (struct ztl_pro_node *)(&node_grp->vnodes[node_id]);

    int ret;
    if (ZROCKS_DEBUG)
        log_infoa("zrocks_trim: node ID [%u]\n", node->id);

    ret = ztl()->pro->submit_node_fn(grp, node, ZTL_MGMG_RESET_ZONE);
    if (ret) {
        log_infoa("zrocks_trim: node ID [%u], ret [%d]\n", node->id, ret);
    }

    return ret;
}

int zrocks_exit(void) {
    pthread_spin_destroy(&zrocks_mp_spin);
    xztl_mempool_destroy(ZROCKS_MEMORY, 0);
    return xztl_exit();
}

int zrocks_node_finish(uint32_t node_id) {
    struct app_group *       grp      = ztl()->groups.get_fn(0);
    struct ztl_pro_node_grp *node_grp = grp->pro;
    struct ztl_pro_node *    node =
        (struct ztl_pro_node *)(&node_grp->vnodes[node_id]);
    int ret;

    ret = ztl()->pro->submit_node_fn(grp, node, ZTL_MGMG_FULL_ZONE);
    if (ret) {
        log_erra("zrocks_node_finish: err node ID [%u], ret [%d]\n", node_id, ret);
    }

    return ret;
}

int zrocks_init(const char *dev_name) {
    int ret;

    /* Add libznd media layer */
    xztl_add_media(znd_media_register);

    /* Add the ZTL modules */
    ztl_zmd_register();
    ztl_pro_register();
    ztl_mpe_register();
    ztl_map_register();
    ztl_wca_register();

    if (pthread_spin_init(&zrocks_mp_spin, 0)) {
        log_err("zrocks_init: pthread_spin_init failed\n");
        return XZTL_ZROCKS_INIT_ERR;
    }

    ret = xztl_init(dev_name);
    if (ret) {
        log_erra("zrocks_init: err xztl_init dev [%s] ret [%d]\n", dev_name, ret);
        pthread_spin_destroy(&zrocks_mp_spin);
        return XZTL_ZROCKS_INIT_ERR;
    }

    ret = xztl_mempool_create(ZROCKS_MEMORY, 0, ZROCKS_BUF_ENTS,
                            ZROCKS_MAX_READ_SZ, zrocks_alloc, zrocks_free);
    if (ret) {
        log_erra("zrocks_init: err xztl_mempool_create failed, ret [%d]\n", ret);
        xztl_exit();
        pthread_spin_destroy(&zrocks_mp_spin);
    }

    return ret;
}
