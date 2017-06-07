/******************************************************************************
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2016 Intel Corporation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * The full GNU General Public License is included in this distribution
 * in the file called LICENSE.GPL.
 *
 * Contact Information:
 *	Intel Corporation.
 *	linux-mei@linux.intel.com
 *	http://www.intel.com
 *
 * BSD LICENSE
 *
 * Copyright(c) 2016 Intel Corporation. All rights reserved.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *  * Neither the name Intel Corporation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *****************************************************************************/

#ifndef __BH_INTERNAL_H
#define __BH_INTERNAL_H

#include <linux/list.h>
#include <linux/slab.h>
#include <linux/bitops.h>
#include <linux/uuid.h>

#include "bh_cmd_defs.h"

/**
 * struct bh_response_record - response record
 *
 * @code: response code
 *        0 on success
 *        <0 on system failure
 *        >0 on FW failure
 * @ta_session_id: session id
 * @length: response buffer length
 * @buffer: response buffer
 */
struct bh_response_record {
	int code;
	u64 ta_session_id;
	unsigned int length;
	void *buffer;
};

/**
 * struct bh_session_record - session record
 *
 * @link: link in dal_dev_session_list of dal fw client
 * @host_id: message/session host id
 * @ta_session_id: session id
 */
struct bh_session_record {
	struct list_head link;
	u64 host_id;
	u64 ta_session_id;
};

/* heci command header buffer size in bytes */
#define CMDBUF_SIZE 100

/**
 * enum bhp_connection_index - connection index to dal fw clients
 *
 * @CONN_IDX_START: start idx
 *
 * @CONN_IDX_IVM: Intel/Issuer Virtual Machine
 * @CONN_IDX_SDM: Security Domain Manager
 * @CONN_IDX_LAUNCHER: Run Time Manager (Launcher)
 *
 * @MAX_CONNECTIONS: max connection idx
 */
enum bhp_connection_index {
	CONN_IDX_START = 0,

	CONN_IDX_IVM = 0,
	CONN_IDX_SDM = 1,
	CONN_IDX_LAUNCHER = 2,

	MAX_CONNECTIONS
};

u64 get_msg_host_id(void);
struct bh_session_record *session_find(int conn_idx, u64 host_id);
void session_add(int conn_idx, struct bh_session_record *session);
void session_remove(int conn_idx, u64 host_id);

int bh_request(int conn_idx, void *hdr, unsigned int hdr_len,
	       const void *data, unsigned int data_len,
	       u64 host_id, struct bh_response_record *rr);

int bh_proxy_check_svl_ta_blocked_state(uuid_be ta_id);

int bh_proxy_list_jta_packages(int conn_idx, int *count, uuid_be **ta_ids);

int bh_proxy_download_javata(int conn_idx, uuid_be ta_id, const char *ta_pkg,
			     unsigned int pkg_len);

int bh_proxy_openjtasession(int conn_idx, uuid_be ta_id,
			    const char *init_buffer, unsigned int init_len,
			    u64 *host_id, const char *ta_pkg,
			    unsigned int pkg_len);

void init_session_list(int conn_idx);
void free_session_list(int conn_idx);

#define mutex_enter(s) {}
#define mutex_exit(s)  {}

#endif /* __BH_INTERNAL_H */
