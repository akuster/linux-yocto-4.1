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

#ifndef _BHP_IMPL_H_
#define _BHP_IMPL_H_

#include <linux/list.h>
#include <linux/slab.h>
#include <linux/bitops.h>
#include <linux/uuid.h>

#include "bh_types.h"
#include "bhp_exp.h"
#include "bh_acp_exp.h"
#include "bhp_heci.h"

/**
 * struct bh_response_record - response record
 *
 * @code: response code
 * @length: response buffer length
 * @buffer: response buffer
 * @addr: session id (FW address)
 * @is_session: flag points whether this record is session response record
 * @killed: session killed flag (relevant when is_session flag is set)
 * @count: count of users using this session, should be 0 or 1
 *         (relevant when is_session flag is set)
 */
struct bh_response_record {
	int code;
	unsigned int length;
	void *buffer;
	u64 addr;
	bool is_session;
	bool killed;
	unsigned int count;
};

/* maximum concurrent activities on one session */
#define MAX_SESSION_LIMIT 20

/* heci command header buffer size in bytes */
#define CMDBUF_SIZE 100

/* TODO: review to avoid seq conflicts */
# define MSG_SEQ_START_NUMBER BIT_ULL(32)

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

/**
 * enum bhp_state - current state of bhp
 *
 * @DEINITED: not inited
 * @INITED: inited
 */
enum bhp_state {
	DEINITED = 0,
	INITED = 1,
};

bool bhp_is_initialized(void);

u64 rrmap_add(int conn_idx, struct bh_response_record *rr);

struct bh_response_record *session_enter(int conn_idx, u64 seq,
					 int lock_session);

void session_exit(int conn_idx, struct bh_response_record *session,
		  u64 seq, int unlock_session);

void session_close(int conn_idx, struct bh_response_record *session,
		   u64 seq, int unlock_session);

int bh_request(int conn_idx, void *cmd, unsigned int clen,
	       const void *data, unsigned int dlen, u64 seq);

const struct bhp_command_header *bh_msg_cmd_hdr(const void *msg, size_t len);

typedef int (*bh_filter_func)(const struct bhp_command_header *hdr,
			      size_t count, void *ctx);

int bh_filter_hdr(const struct bhp_command_header *hdr, size_t count, void *ctx,
		  const bh_filter_func tbl[]);

bool bh_msg_is_cmd_open_session(const struct bhp_command_header *hdr);

const uuid_be *bh_open_session_ta_id(const struct bhp_command_header *hdr,
				     size_t count);

void bh_prep_access_denied_response(const char *cmd,
				    struct bhp_response_header *res);

bool bh_msg_is_cmd(const void *msg, size_t len);
bool bh_msg_is_response(const void *msg, size_t len);

#define mutex_enter(s) {}
#define mutex_exit(s)  {}

#endif /* _BHP_IMPL_H_ */
