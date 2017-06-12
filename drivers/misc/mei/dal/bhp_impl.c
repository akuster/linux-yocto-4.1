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

/* BPH initialization state */
static atomic_t bhp_state = ATOMIC_INIT(0);
static u64 host_id_number = MSG_SEQ_START_NUMBER;

/*
 * dal device session records list (array of list per dal device)
 * represents opened sessions to dal fw client
 */
static struct list_head dal_dev_session_list[MAX_CONNECTIONS];

/**
 * get_msg_host_id - increase the shared variable host_id_number by 1
 *                   and wrap around if needed
 *
 * Return: the updated host id number
 */
u64 get_msg_host_id(void)
{
	host_id_number++;
	/* wrap around. sequence_number must
	 * not be 0, as required by Firmware VM
	 */
	if (host_id_number == 0)
		host_id_number = MSG_SEQ_START_NUMBER;

	return host_id_number;
}

/**
 * session_find - find session record by handle
 *
 * @conn_idx: fw client connection idx
 * @host_id: session host id
 *
 * Return: pointer to bh_session_record if found
 *         NULL if the session wasn't found
 */
struct bh_session_record *session_find(int conn_idx, u64 host_id)
{
	struct bh_session_record *pos;

	list_for_each_entry(pos, &dal_dev_session_list[conn_idx], link) {
		if (pos->host_id == host_id)
			return pos;
	}

	return NULL;
}

/**
 * session_add - add session record to list
 *
 * @conn_idx: fw client connection idx
 * @session: session record
 */
void session_add(int conn_idx, struct bh_session_record *session)
{
	list_add_tail(&session->link, &dal_dev_session_list[conn_idx]);
}

/**
 * session_remove - remove session record from list, ad release its memory
 *
 * @conn_idx: fw client connection idx
 * @host_id: session host id
 */
void session_remove(int conn_idx, u64 host_id)
{
	struct bh_session_record *session;

	session = session_find(conn_idx, host_id);

	if (session) {
		list_del(&session->link);
		kfree(session);
	}
}

static char skip_buffer[DAL_MAX_BUFFER_SIZE] = {0};
/**
 * bh_transport_recv - receive message from FW, using kdi callback 'kdi_recv'
 *
 * @conn_idx: fw client connection idx
 * @buffer: output buffer to hold the received message
 * @size: output buffer size
 *
 * Return: 0 on success
 *         <0 on failure
 */
static int bh_transport_recv(unsigned int conn_idx, void *buffer, size_t size)
{
	size_t got;
	size_t count = 0;
	int ret;
	char *buf = buffer;

	if (conn_idx > DAL_MEI_DEVICE_MAX)
		return -ENODEV;

	while (size - count > 0) {
		got = min_t(size_t, size - count, DAL_MAX_BUFFER_SIZE);
		if (buf)
			ret = kdi_recv(conn_idx, buf + count, &got);
		else
			ret = kdi_recv(conn_idx, skip_buffer, &got);

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
 * @conn_idx: fw client connection idx
 * @buffer: message to send
 * @size: message size
 * @host_id: message host id
 *
 * Return: 0 on success
 *         <0 on failure
 */
static int bh_transport_send(unsigned int conn_idx, const void *buffer,
			     unsigned int size, u64 host_id)
{
	size_t chunk_sz;
	unsigned int count = 0;
	int ret;
	const char *buf = buffer;

	if (conn_idx > DAL_MEI_DEVICE_MAX)
		return -ENODEV;

	while (size - count > 0) {
		chunk_sz = min_t(size_t, size - count, DAL_MAX_BUFFER_SIZE);
		ret = kdi_send(conn_idx, buf + count, chunk_sz, host_id);
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
 * @hdr: command header
 * @hdr_len: command header length
 * @data: command data (message content)
 * @data_len: data length
 * @host_id: message host id
 *
 * Return: 0 on success
 *         <0 on failure
 */
static int bh_send_message(int conn_idx,
			   void *hdr, unsigned int hdr_len,
			   const void *data, unsigned int data_len,
			   u64 host_id)
{
	int ret;
	struct bhp_command_header *h = NULL;

	mutex_enter(connections[conn_idx].bhm_send);

	if (hdr_len < sizeof(*h) || !hdr)
		return -EINVAL;

	h = hdr;
	h->h.magic = BH_MSG_CMD_MAGIC;
	h->h.length = hdr_len + data_len;
	h->seq = host_id;

	ret = bh_transport_send(conn_idx, hdr, hdr_len, host_id);
	if (!ret && data_len > 0)
		ret = bh_transport_send(conn_idx, data, data_len, host_id);

	mutex_exit(connections[conn_idx].bhm_send);

	return ret;
}

/**
 * bh_recv_message - receive and prosses message from FW
 *
 * @conn_idx: fw client connection idx
 * @rr: response record to hold the received message
 * @out_host_id: output param to hold the received message host id
 *               it should be identical to the sent message host id
 *
 * Return: 0 on success
 *         <0 on failure
 */
static int bh_recv_message(int conn_idx, struct bh_response_record *rr,
			   u64 *out_host_id)
{
	int ret;
	struct bhp_response_header hdr;
	char *data = NULL;
	unsigned int data_len = 0;

	if (!rr)
		return -EINVAL;

	ret = bh_transport_recv(conn_idx, &hdr, sizeof(hdr));
	if (ret)
		return ret;

	/* check magic */
	if (hdr.h.magic != BH_MSG_RESP_MAGIC)
		return -EBADMSG;

	/* message contains hdr only */
	if (hdr.h.length <= sizeof(hdr))
		goto out;

	data_len = hdr.h.length - sizeof(hdr);
	data = kzalloc(data_len, GFP_KERNEL);
	if (!data) {
		ret = -ENOMEM;
		goto out;
	}

	ret = bh_transport_recv(conn_idx, data, data_len);

	rr->buffer = data;
	rr->length = data_len;

out:
	if (ret)
		rr->code = ret;
	else
		rr->code = hdr.code;

	if (hdr.ta_session_id)
		rr->ta_session_id = hdr.ta_session_id;

	if (out_host_id)
		*out_host_id = hdr.seq;

	return ret;
}

/**
 * free_session_list - free session list of given dal fw client
 *
 * @conn_idx: fw client connection idx
 */
static void free_session_list(int conn_idx)
{
	struct bh_session_record *pos, *next;

	list_for_each_entry_safe(pos, next, &dal_dev_session_list[conn_idx],
				 link) {
		list_del(&pos->link);
		kfree(pos);
	}

	INIT_LIST_HEAD(&dal_dev_session_list[conn_idx]);
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
		free_session_list(i);
}

#define MAX_RETRY_COUNT 3
/**
 * bh_request - send request to FW and receive response back
 *
 * @conn_idx: fw client connection idx
 * @hdr: command header
 * @hdr_len: command header length
 * @data: command data (message content)
 * @data_len: data length
 * @host_id: message host id
 * @rr: response record to hold the received message
 *
 * Return: 0 on success
 *         <0 on failure
 */
int bh_request(int conn_idx,
	       void *hdr, unsigned int hdr_len,
	       const void *data, unsigned int data_len,
	       u64 host_id, struct bh_response_record *rr)
{
	int ret;
	u32 retry_count;
	u64 res_host_id;

	ret = bh_send_message(conn_idx, hdr, hdr_len, data, data_len, host_id);
	if (ret)
		return ret;

	for (retry_count = 0; retry_count < MAX_RETRY_COUNT; retry_count++) {
		res_host_id = 0;
		ret = bh_recv_message(conn_idx, rr, &res_host_id);
		if (ret) {
			pr_debug("failed to recv msg = %d\n", ret);
			continue;
		}

		if (res_host_id != host_id) {
			pr_debug("recv message with host_id=%llu != sent host_id=%llu\n",
				 res_host_id, host_id);
			continue;
		}

		pr_debug("recv message with try=%d host_id=%llu\n",
			 retry_count, res_host_id);
		break;
	}

	if (retry_count == MAX_RETRY_COUNT) {
		pr_err("out of retry attempts\n");
		ret = -EFAULT;
	}

	return ret;
}

/**
 * bhp_is_initialized - check if bhp is initialized
 *
 * Return: true when bhp is initialized
 *         false when bhp is not initialized
 */
bool bhp_is_initialized(void)
{
	return atomic_read(&bhp_state) == 1;
}

/**
 * bhp_init_internal - Beihai plugin init function
 *
 * The plugin initialization includes initializing the session lists of all
 * dal devices (dal fw clients)
 *
 * Return: 0
 */
void bhp_init_internal(void)
{
	int i;

	if (atomic_add_unless(&bhp_state, 1, 1))
		for (i = CONN_IDX_START; i < MAX_CONNECTIONS; i++)
			INIT_LIST_HEAD(&dal_dev_session_list[i]);
}

/**
 * bhp_deinit_internal - Beihai plugin deinit function
 */
void bhp_deinit_internal(void)
{
	if (atomic_add_unless(&bhp_state, -1, 0))
		bh_connections_deinit();
}
