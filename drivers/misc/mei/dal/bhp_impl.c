/******************************************************************************
 * Intel mei_dal Linux driver
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
#define pr_fmt(fmt) KBUILD_MODNAME ":%s: " fmt, __func__

#include <linux/printk.h>
#include <linux/mei_cl_bus.h>
#include "bhp_impl.h"
#include "bhp_exp.h"
#include "dal_dev.h"

static unsigned int init_state = DEINITED;
static u64 sequence_number = MSG_SEQ_START_NUMBER;

/*
 * dal device response records list (array of list per dal device)
 * represents connection to dal fw client
 */
static struct list_head dal_dev_rr_list[MAX_CONNECTIONS];

/**
 * increment_sequence_number - increase the shared variable sequence_number
 *                             by 1 and wrap around if needed
 *
 * Return: the updated sequence number
 */
static u64 increment_sequence_number(void)
{
	u64 ret = 0;

	mutex_enter(bhm_seqno);
	sequence_number++;
	/* wrap around. sequence_number must
	 * not be 0, as required by Firmware VM
	 */
	if (sequence_number == 0)
		sequence_number = MSG_SEQ_START_NUMBER;

	ret = sequence_number;
	mutex_exit(bhm_seqno);

	return ret;
}

/**
 * struct RR_MAP_INFO - response record information
 *
 * @link: link in rr_map_list of dal fw client
 * @seq: message sequence
 * @rr: response record
 */
struct RR_MAP_INFO {
	struct list_head link;
	u64 seq;
	struct bh_response_record *rr;
};

#if 0 /* for debug */
/**
 * rrmap_dump - dump response record information
 *
 * @rr_map_header: response record list
 */
static void rrmap_dump(struct list_head *rr_map_header)
{
	struct list_head *pos;
	struct RR_MAP_INFO *rrmap_info;
	size_t count;

	count = 0;

	list_for_each(pos, rr_map_header) {
		rrmap_info = list_entry(pos, struct RR_MAP_INFO, link);
		if (rrmap_info) {
			pr_debug("[%02x] seq: %llu, rr->addr: %llu",
				 count, rrmap_info->seq, rrmap_info->rr->addr);
			count++;
		}
	}
}
#endif

/**
 * rrmap_find_by_addr - find response record by sequence
 *
 * @rr_map_header: response record list
 * @seq: sequence number
 *
 * Return: pointer to RR_MAP_INFO if found
 *         NULL if the response record wasn't found
 */
static struct RR_MAP_INFO *rrmap_find_by_addr(struct list_head *rr_map_header,
					      u64 seq)
{
	struct list_head *pos;
	struct RR_MAP_INFO *rrmap_info;

	list_for_each(pos, rr_map_header) {
		rrmap_info = list_entry(pos, struct RR_MAP_INFO, link);
		if (rrmap_info && rrmap_info->seq == seq)
			return rrmap_info;
	}

	return NULL;
}

/**
 * rrmap_add - add response record to list and return the new sequence
 *
 * @conn_idx: fw client connection idx
 * @rr: response record
 *
 * Return: sequence of the new response record
 */
u64 rrmap_add(int conn_idx, struct bh_response_record *rr)
{
	u64 seq = increment_sequence_number();
	struct RR_MAP_INFO *rrmap_info;

	/* TODO: check if malloc succeeded: need to refactor the usage
	 * of rrmap_add() to check and handle errors
	 */
	rrmap_info = kzalloc(sizeof(*rrmap_info), GFP_KERNEL);

	rrmap_info->seq = seq;
	rrmap_info->rr = rr;

	list_add_tail(&rrmap_info->link, &dal_dev_rr_list[conn_idx]);

	return rrmap_info->seq;
}

/**
 * rrmap_remove - remove response record from list
 *
 * @conn_idx: fw client connection idx
 * @seq: sequence number
 * @remove_record: remove record flag. used to remove session records
 *
 * in the original BHP they use a map, in the kernel we don't have a map.
 * we're using a list.
 * in BHP they simply delete an element from the map.
 * so in order to remove a record which is a session we added a parameter
 * 'remove_record'
 *
 * Return: pointer to the removed response record
 */
static struct bh_response_record *rrmap_remove(int conn_idx, u64 seq,
					       bool remove_record)
{
	struct RR_MAP_INFO *rrmap_info;
	struct bh_response_record *rr = NULL;

	rrmap_info = rrmap_find_by_addr(&dal_dev_rr_list[conn_idx], seq);

	if (rrmap_info) {
		rr = rrmap_info->rr;
		if (!rr->is_session || remove_record) {
			list_del_init(&rrmap_info->link);
			kfree(rrmap_info);
		}
	}

	return rr;
}

/**
 * addr2record - get response record by sequence number
 *
 * @conn_idx: fw client connection idx
 * @seq: sequence number
 *
 * Return: pointer to the response record
 *         NULL if it wasn't found
 */
static struct bh_response_record *addr2record(int conn_idx, u64 seq)
{
	struct bh_response_record *rr = NULL;
	struct RR_MAP_INFO *rrmap_info;

	rrmap_info = rrmap_find_by_addr(&dal_dev_rr_list[conn_idx], seq);

	if (rrmap_info)
		rr = rrmap_info->rr;

	return rr;
}

/**
 * destroy_session - release session's response record memory
 *
 * @session: session's response record
 */
static void destroy_session(struct bh_response_record *session)
{
	if (session)
		kfree(session->buffer);
	kfree(session);
}

/**
 * session_enter - increase session count in response record
 *
 * @conn_idx: fw client connection idx
 * @seq: sequence number
 * @lock_session: catch session mutex flag
 *
 * Return: pointer to the response record
 */
struct bh_response_record *session_enter(int conn_idx, u64 seq,
					 int lock_session)
{
	struct bh_response_record *session = NULL;
	struct RR_MAP_INFO *rrmap_info;

	mutex_enter(connections[conn_idx].bhm_rrmap);

	rrmap_info = rrmap_find_by_addr(&dal_dev_rr_list[conn_idx], seq);

	if (rrmap_info) {
		if (rrmap_info->rr->is_session && !rrmap_info->rr->killed) {
			session = rrmap_info->rr;

			if (session->count < MAX_SESSION_LIMIT)
				session->count++;
			else
				session = NULL;
		}
	}

	mutex_exit(connections[conn_idx].bhm_rrmap);

	if (session && lock_session) {
		mutex_enter(session->session_lock);

		/* check whether session has been
		 * killed before session operation
		 */
		if (session->killed) {
			session_exit(conn_idx, session, seq, 1);
			session = NULL;
		}
	}

	return session;
}

/**
 * session_exit - decrease session count in response record
 *
 * When the session count is 0 and the session is killed,
 * remove the response record from the list and free it
 *
 * @conn_idx: fw client connection idx
 * @session: the response record
 * @seq: sequence number
 * @unlock_session: release session mutex flag
 */
void session_exit(int conn_idx, struct bh_response_record *session,
		  u64 seq, int unlock_session)
{
	mutex_enter(connections[conn_idx].bhm_rrmap);
	session->count--;

	if (session->count == 0 && session->killed) {
		rrmap_remove(conn_idx, seq, true);

		if (unlock_session)
			mutex_exit(session->session_lock);

		destroy_session(session);
	} else {
		if (unlock_session)
			mutex_exit(session->session_lock);
	}

	mutex_exit(connections[conn_idx].bhm_rrmap);
}

/**
 * session_close - decrease session count in response record
 *
 * When the session count is 0, remove the response record
 * from the list and free it
 *
 * @conn_idx: fw client connection idx
 * @session: the response record
 * @seq: sequence number
 * @unlock_session: release session mutex flag
 */
void session_close(int conn_idx, struct bh_response_record *session,
		   u64 seq, int unlock_session)
{
	mutex_enter(connections[conn_idx].bhm_rrmap);
	session->count--;

	if (session->count == 0) {
		rrmap_remove(conn_idx, seq, true);
		if (unlock_session)
			mutex_exit(session->session_lock);
		destroy_session(session);
	} else {
		session->killed = true;
		if (unlock_session)
			mutex_exit(session->session_lock);
	}

	mutex_exit(connections[conn_idx].bhm_rrmap);
}

/**
 * session_kill - set session killed flag
 *
 * When the session count is 0, remove the response record
 * from the list and free it
 *
 * @conn_idx: fw client connection idx
 * @session: the response record
 * @seq: sequence number
 */
static void session_kill(int conn_idx, struct bh_response_record *session,
			 u64 seq)
{
	mutex_enter(connections[conn_idx].bhm_rrmap);
	session->killed = true;
	if (session->count == 0) {
		rrmap_remove(conn_idx, seq, true);
		destroy_session(session);
	}
	mutex_exit(connections[conn_idx].bhm_rrmap);
}

/**
 * bhp_is_initialized - check if bhp is initialized
 *
 * Return: true when bhp is initialized
 *         false when bhp is not initialized
 */
bool bhp_is_initialized(void)
{
	return (READ_ONCE(init_state) == INITED);
}

static char skip_buffer[DAL_MAX_BUFFER_SIZE] = {0};
/**
 * bh_transport_recv - receive message from FW, using kdi callback 'kdi_recv'
 *
 * @handle: session handle
 * @buffer: output buffer to hold the received message
 * @size: output buffer size
 *
 * Return: 0 on success
 *         <0 on failure
 */
static int bh_transport_recv(unsigned int handle, void *buffer, size_t size)
{
	size_t got;
	size_t count = 0;
	int ret;
	char *buf = buffer;

	if (handle > DAL_MEI_DEVICE_MAX)
		return -ENODEV;

	while (size - count > 0) {
		got = min_t(size_t, size - count, DAL_MAX_BUFFER_SIZE);
		if (buf)
			ret = kdi_recv(handle, buf + count, &got);
		else
			ret = kdi_recv(handle, skip_buffer, &got);

		if (ret)
			return ret;

		count += got;
	}

	if (count != size)
		return -EFAULT;

	return 0;
}

/**
 * bh_transport_send - send message to FW, using kdi callback 'kdi_send'
 *
 * @handle: session handle
 * @buffer: message to send
 * @size: message size
 * @seq: message sequence
 *
 * Return: 0 on success
 *         <0 on failure
 */
static int bh_transport_send(unsigned int handle, const void *buffer,
			     unsigned int size, u64 seq)
{
	size_t chunk_sz;
	unsigned int count = 0;
	int ret;
	const char *buf = buffer;

	if (handle > DAL_MEI_DEVICE_MAX)
		return -ENODEV;

	while (size - count > 0) {
		chunk_sz = min_t(size_t, size - count, DAL_MAX_BUFFER_SIZE);
		ret = kdi_send(handle, buf + count, chunk_sz, seq);
		if (ret)
			return ret;

		count += chunk_sz;
	}

	return 0;
}

/**
 * bh_send_message - build and send command message to FW
 *
 * @conn_idx: fw client connection idx
 * @cmd: command header
 * @clen: command header length
 * @data: command data (message content)
 * @dlen: data length
 * @seq: message sequence
 *
 * Return: 0 on success
 *         <0 on failure
 */
static int bh_send_message(int conn_idx, void *cmd, unsigned int clen,
			   const void *data, unsigned int dlen, u64 seq)
{
	int ret;
	struct bh_response_record *rr = addr2record(conn_idx, seq);
	struct bhp_command_header *h = NULL;

	if (!rr)
		return -EFAULT;

	mutex_enter(connections[conn_idx].bhm_send);

	if (clen < sizeof(*h) || !cmd || !rr)
		return -EINVAL;

	rr->buffer = NULL;
	rr->length = 0;

	h = cmd;
	h->h.magic = BH_MSG_CMD_MAGIC;
	h->h.length = clen + dlen;
	h->seq = seq;

	ret = bh_transport_send(conn_idx, cmd, clen, seq);
	if (!ret && dlen > 0)
		ret = bh_transport_send(conn_idx, data, dlen, seq);

	if (ret)
		rrmap_remove(conn_idx, seq, false);

	mutex_exit(connections[conn_idx].bhm_send);

	return ret;
}

/**
 * bh_recv_message - receive and prosses message from FW
 *
 * @conn_idx: fw client connection idx
 * @seq: output param to hold the message sequence number
 *
 * Return: 0 on success
 *         <0 on failure
 */
static int bh_recv_message(int conn_idx, u64 *seq)
{
	int ret;
	struct bhp_response_header headbuf;
	struct bhp_response_header *head = &headbuf;
	char *data = NULL;
	unsigned int dlen = 0;
	struct bh_response_record *rr = NULL;
	int session_killed;

	ret = bh_transport_recv(conn_idx, head, sizeof(*head));
	if (ret)
		return ret;

	/* check magic */
	if (head->h.magic != BH_MSG_RESP_MAGIC)
		return -EBADMSG;

	/* verify rr */
	rr = rrmap_remove(conn_idx, head->seq, false);

	if (head->h.length > sizeof(*head)) {
		dlen = head->h.length - sizeof(*head);
		data = kzalloc(dlen, GFP_KERNEL);
		ret = bh_transport_recv(conn_idx, data, dlen);
		if (!ret && !data)
			ret = -ENOMEM;
	}

	if (rr) {
		rr->buffer = data;
		rr->length = dlen;

		if (!ret)
			rr->code = head->code;
		else
			rr->code = ret;

		if (head->ta_session_id)
			rr->addr = head->ta_session_id;

		session_killed = (rr->is_session &&
				  (rr->code == BHE_WD_TIMEOUT ||
				  rr->code == BHE_UNCAUGHT_EXCEPTION ||
				  rr->code == BHE_APPLET_CRASHED));

		/* set killed flag before wake up send_wait thread */
		if (session_killed) {
			rr->killed = true;
			session_kill(conn_idx, rr, head->seq);
		}

	} else {
		kfree(data);
	}

	if (seq)
		*seq = head->seq;

	return ret;
}

/**
 * free_rr_list - free response record list of given dal fw client
 *
 * @conn_idx: fw client connection idx
 *
 * Return: 0
 */
static int free_rr_list(int conn_idx)
{
	struct list_head *pos, *tmp;
	struct RR_MAP_INFO *rrmap_info;

	list_for_each_safe(pos, tmp, &dal_dev_rr_list[conn_idx]) {
		rrmap_info = list_entry(pos, struct RR_MAP_INFO, link);
		if (rrmap_info) {
			list_del(pos);
			kfree(rrmap_info);
		}
	}

	INIT_LIST_HEAD(&dal_dev_rr_list[conn_idx]);

	return 0;
}

/**
 * bh_connections_init - init dal fw clients connections
 *
 * Init the response record list of all dal devices (dal fw clients)
 */
static void bh_connections_init(void)
{
	int i;

	for (i = CONN_IDX_START; i < MAX_CONNECTIONS; i++)
		INIT_LIST_HEAD(&dal_dev_rr_list[i]);
}

/**
 * bh_connections_deinit - deinit dal fw clients connections
 *
 * Deinit the response record list of all dal devices (dal fw clients)
 */
static void bh_connections_deinit(void)
{
	int i;

	for (i = CONN_IDX_START; i < MAX_CONNECTIONS; i++)
		free_rr_list(i);
}

#define MAX_RETRY_COUNT 3
/**
 * bh_request - send request to FW and receive response back
 *
 * @conn_idx: fw client connection idx
 * @cmd: command header
 * @clen: command header length
 * @data: command data (message content)
 * @dlen: data length
 * @seq: message sequence
 *
 * Return: 0 on success
 *         <0 on failure
 */
int bh_request(int conn_idx, void *cmd, unsigned int clen,
	       const void *data, unsigned int dlen, u64 seq)
{
	int ret;
	u32 retry_count;
	u64 seq_response = 0;

	ret = bh_send_message(conn_idx, cmd, clen, data, dlen, seq);
	if (ret)
		return ret;

	for (retry_count = 0; retry_count < MAX_RETRY_COUNT; retry_count++) {
		ret = bh_recv_message(conn_idx, &seq_response);
		if (ret) {
			pr_debug("failed to recv msg = %d\n", ret);
			continue;
		}

		if (seq_response != seq) {
			pr_debug("recv message with seq=%llu != seq_response=%llu\n",
				 seq, seq_response);
			continue;
		}

		pr_debug("recv message with try=%d seq=%llu\n",
			 retry_count, seq_response);
		break;
	}

	if (retry_count == MAX_RETRY_COUNT) {
		pr_err("out of retry attempts\n");
		ret = -EFAULT;
	}

	return ret;
}

/**
 * bhp_init_internal - Beihai plugin init function
 *
 * Return: 0
 */
int bhp_init_internal(void)
{
	if (bhp_is_initialized())
		return 0;

	/* step 1: init connections to each process */
	bh_connections_init();

	/* RESET flow removed to allow JHI and KDI to coexist */
	/* this assignment is atomic operation */
	WRITE_ONCE(init_state, INITED);

	return 0;
}

/**
 * bhp_deinit_internal - Beihai plugin deinit function
 *
 * Return: 0
 */
int bhp_deinit_internal(void)
{
	mutex_enter(bhm_gInit);

	if (bhp_is_initialized()) {
		/* RESET flow removed to allow JHI and KDI to coexist */
		bh_connections_deinit();
		WRITE_ONCE(init_state, DEINITED);
	}

	mutex_exit(bhm_gInit);

	return 0;
}
