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

#ifndef XZTL_MEDIA_H
#define XZTL_MEDIA_H

#include <libxnvme.h>
#include <stdint.h>
#include <stdlib.h>
#include <xztl.h>

/* Append Command support */
#define XZTL_WRITE_APPEND 0

/* Number of maximum addresses in a single command vector.
 * 	A single address is needed for zone append. We should
 * 	increase this number in case of possible vectored I/Os. */
#define XZTL_MAX_MADDR 1

#define XZTL_MCTX_SZ 640

#define XZTL_MEDIA_MAX_GRP   128     /* groups */
#define XZTL_MEDIA_MAX_PUGRP 8       /* punits */
#define XZTL_MEDIA_MAX_ZNPU  8388608 /* zones */
#define XZTL_MEDIA_MAX_SECZN 8388608 /* sectors */
#define XZTL_MEDIA_MAX_SECSZ 1048576 /* bytes */
#define XZTL_MEDIA_MAX_OOBSZ 128     /* bytes */

struct znd_media *get_znd_media(void);

enum xztl_media_opcodes {
    /* Admin commands */
    XZTL_ADM_IDENTIFY   = 0x06,
    XZTL_ADM_IDFY_OCSSD = 0xE2,
    XZTL_ADM_GET_LOG    = 0x02,
    XZTL_ADM_SET_FEAT   = 0x09,
    XZTL_ADM_GET_FEAT   = 0x0A,
    XZTL_ADM_FORMAT_NVM = 0x80,
    XZTL_ADM_SANITIZE   = 0x84,

    /* I/O commands */
    XZTL_CMD_WRITE       = 0x01,
    XZTL_CMD_READ        = 0x02,
    XZTL_CMD_WRITE_OCSSD = 0x91,
    XZTL_CMD_READ_OCSSD  = 0x92,

    /* Zoned commands */
    XZTL_ZONE_MGMT   = 0x79,
    XZTL_ZONE_APPEND = 0x7D,

    /* Zone Management actions */
    XZTL_ZONE_MGMT_CLOSE  = 0x1,
    XZTL_ZONE_MGMT_FINISH = 0x2,
    XZTL_ZONE_MGMT_OPEN   = 0x3,
    XZTL_ZONE_MGMT_RESET  = 0x4,
    XZTL_ZONE_MGMT_REPORT = 0xf,
    XZTL_ZONE_ERASE_OCSSD = 0x90,

    /* Media other commands */
    XZTL_MISC_ASYNCH_INIT = 0x1,
    XZTL_MISC_ASYNCH_TERM = 0x2,
    XZTL_MISC_ASYNCH_POKE = 0x3,
    XZTL_MISC_ASYNCH_OUTS = 0x4,
    XZTL_MISC_ASYNCH_WAIT = 0x5
};

struct xztl_mthread_ctx {
    uint16_t            is_busy;
    xztl_thread *       comp_th;
    int                 tid;
    int                 comp_active;
    pthread_spinlock_t  qpair_spin;
    struct xnvme_queue *queue;
};

struct xztl_io_mcmd {
    uint8_t                  opcode;
    uint8_t                  submitted;
    uint8_t                  synch;
    uint8_t                  callback_err_cnt;
    uint32_t                 sequence;
    uint32_t                 sequence_zn;
    uint64_t                 buf_off;
    uint64_t                 cpsize;
    uint32_t                 naddr;
    uint16_t                 status;
    uint64_t                 nsec[XZTL_MAX_MADDR];
    struct xztl_maddr        addr[XZTL_MAX_MADDR];
    uint64_t                 prp[XZTL_MAX_MADDR];
    uint64_t                 paddr[XZTL_MAX_MADDR];
    xztl_callback *          callback;
    void *                   opaque;
    struct xztl_mthread_ctx *async_ctx;
    struct xztl_mp_entry *   mp_cmd;
    struct xztl_mp_entry *   mp_entry;

    /* For latency */
    uint64_t us_start;
    uint64_t us_end;

    /* change to pointer when xnvme is updated */
    struct xnvme_cmd_ctx *media_ctx;

    /* Completion queue */
    STAILQ_ENTRY(xztl_io_mcmd) entry;
};

struct xztl_zn_mcmd {
    uint8_t           opcode;
    uint8_t           status;
    struct xztl_maddr addr;
    uint32_t          nzones;
    void *            opaque;
};

struct xztl_misc_cmd {
    uint8_t opcode;
    uint8_t rsv[7];

    union {
        uint64_t rsv2[7];

        struct {
            struct xztl_mthread_ctx *ctx_ptr;

            uint32_t depth; /* Context/queue depth */
            uint32_t limit; /* Max number of completions */
            uint32_t count; /* Processed completions */

            uint32_t rsv31;
            uint64_t rsv32[4];
        } asynch;
    };
};

struct xztl_mgeo {
    uint32_t ngrps;      /* Groups */
    uint32_t pu_grp;     /* PUs per group */
    uint32_t zn_pu;      /* Zones per PU */
    uint32_t sec_zn;     /* Sectors per zone */
    uint32_t nbytes;     /* Per sector */
    uint32_t nbytes_oob; /* Per sector */

    /* Calculated values */
    uint32_t zn_dev;     /* Total zones in device */
    uint32_t zn_grp;     /* Zones per group */
    uint32_t sec_dev;    /* Toatl sectors in device */
    uint32_t sec_grp;    /* Sectors per group */
    uint32_t sec_pu;     /* Sectors per PU */
    uint64_t nbytes_zn;  /* Bytes per zone */
    uint64_t nbytes_grp; /* Bytes per group */
    uint32_t oob_grp;    /* OOB size per group */
    uint32_t oob_pu;     /* OOB size per PU */
    uint32_t oob_zn;     /* OOB size per zone */
};

typedef int(xztl_media_io_fn)(struct xztl_io_mcmd *cmd);
typedef int(xztl_media_zn_fn)(struct xztl_zn_mcmd *cmd);
typedef void *(xztl_media_dma_alloc_fn)(size_t size);
typedef void(xztl_media_dma_free_fn)(void *ptr);
typedef int(xztl_media_cmd_fn)(struct xztl_misc_cmd *cmd);

struct xztl_media {
    struct xztl_mgeo         geo;
    xztl_init_fn *           init_fn;
    xztl_exit_fn *           exit_fn;
    xztl_media_io_fn *       submit_io;
    xztl_media_zn_fn *       zone_fn;
    xztl_media_dma_alloc_fn *dma_alloc;
    xztl_media_dma_free_fn * dma_free;
    xztl_media_cmd_fn *      cmd_exec;
};

#endif /* XZTL_MEDIA_H */
