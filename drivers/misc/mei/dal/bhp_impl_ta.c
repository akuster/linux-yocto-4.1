/******************************************************************************
 * Intel mei_dal Linux driver
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2016-2017 Intel Corporation. All rights reserved.
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

#include <linux/string.h>
#include <linux/uuid.h>
#include <linux/ctype.h>
#include <linux/dal.h>

#include "bh_errcode.h"
#include "bhp_impl.h"

/**
 * uuid_is_valid_hyphenless - check if uuid is valid in hyphenless format
 *
 * @uuid_str: uuid string
 *
 * Return: true when uuid is valid in hyphenless format
 *         false when uuid is invalid
 */
static bool uuid_is_valid_hyphenless(const char *uuid_str)
{
	unsigned int i;

	/* exclude (i == 8 || i == 13 || i == 18 || i == 23) */
	for (i = 0; i < UUID_STRING_LEN - 4; i++)
		if (!isxdigit(uuid_str[i]))
			return false;

	return true;
}

/**
 * uuid_normalize_hyphenless - convert uuid from hyphenless format
 *                             to standard format
 *
 * @uuid_hl: uuid string in hyphenless format
 * @uuid_str: output param to hold uuid string in standard format
 */
static void uuid_normalize_hyphenless(const char *uuid_hl, char *uuid_str)
{
	unsigned int i;

	for (i = 0; i < UUID_STRING_LEN; i++) {
		if (i == 8 || i == 13 || i == 18 || i == 23)
			uuid_str[i] = '-';
		else
			uuid_str[i] = *uuid_hl++;
	}
	uuid_str[i] = '\0';
}

/**
 * dal_uuid_be_to_bin - convert uuid string to bin
 *
 * Input uuid is in either hyphenless or standard format
 *
 * @uuid_str: uuid string
 * @uuid: output param to hold uuid bin
 *
 * Return: 0 on success
 *         <0 on failure
 */
int dal_uuid_be_to_bin(const char *uuid_str, uuid_be *uuid)
{
	char __uuid_str[UUID_STRING_LEN + 1];

	if (!uuid_str || !uuid)
		return -EINVAL;

	if (uuid_is_valid_hyphenless(uuid_str)) {
		uuid_normalize_hyphenless(uuid_str, __uuid_str);
		uuid_str = __uuid_str;
	}

	return uuid_be_to_bin(uuid_str, uuid);
}
EXPORT_SYMBOL(dal_uuid_be_to_bin);

/**
 * bh_msg_is_response - check if message is response
 *
 * @msg: message
 * @len: message length
 *
 * Return: true when message is response
 *         false otherwise
 */
bool bh_msg_is_response(const void *msg, size_t len)
{
	const struct bhp_response_header *r =  msg;

	return (len >= sizeof(*r) && r->h.magic == BH_MSG_RESP_MAGIC);
}

/**
 * bh_msg_is_cmd - check if message is command
 *
 * @msg: message
 * @len: message length
 *
 * Return: true when message is command
 *         false otherwise
 */
bool bh_msg_is_cmd(const void *msg, size_t len)
{
	const struct bhp_command_header *c = msg;

	return (len >= sizeof(*c) && c->h.magic == BH_MSG_CMD_MAGIC);
}

/**
 * bh_msg_cmd_hdr - get the command header if message is command
 *
 * @msg: message
 * @len: message length
 *
 * Return: pointer to the command header when message is command
 *         NULL otherwise
 */
const struct bhp_command_header *bh_msg_cmd_hdr(const void *msg, size_t len)
{
	if (!bh_msg_is_cmd(msg, len))
		return NULL;

	return msg;
}

/**
 * bh_msg_is_cmd_open_session - check if command is open session command
 *
 * @hdr: message header
 *
 * Return: true when command is open session command
 *         false otherwise
 */
bool bh_msg_is_cmd_open_session(const struct bhp_command_header *hdr)
{
	return hdr->id == BHP_CMD_OPEN_JTASESSION;
}

/**
 * bh_open_session_ta_id - get ta id from open session command
 *
 * @hdr: message header
 * @count: message size
 *
 * Return: pointer to ta id when command is valid
 *         NULL otherwise
 */
const uuid_be *bh_open_session_ta_id(const struct bhp_command_header *hdr,
				     size_t count)
{
	struct bhp_open_jtasession_cmd *open_cmd;

	if (count < sizeof(*hdr) + sizeof(*open_cmd))
		return NULL;

	open_cmd = (struct bhp_open_jtasession_cmd *)hdr->cmd;

	return &open_cmd->ta_id;
}

/**
 * bh_cmd - send command to FW and receive response code back
 *
 * There is no need in the received buffer, just in the response code from FW.
 * Free the received buffer immediately.
 *
 * @conn_idx: fw client connection idx
 * @cmd: command header
 * @cmd_len: command header length
 * @data: command data (message content)
 * @data_len: data length
 * @seq: message sequence
 * @rr: response record
 *
 * Return: 0 on success
 *         <0 on failure
 */
static int bh_cmd(int conn_idx,
		  void *cmd, unsigned int cmd_len,
		  const void *data, unsigned int data_len,
		  u64 seq, struct bh_response_record *rr)
{
	int ret;

	ret = bh_request(conn_idx, cmd, cmd_len, data, data_len, seq);

	kfree(rr->buffer);
	rr->buffer = NULL;

	return ret;
}

/**
 * session_enter_vm - enter session with IVM fw client
 *
 * @seq: sequence number
 * @conn_idx: out param to hold fw client connection idx
 * @lock_session: catch session mutex flag
 *
 * Return: pointer to the response record
 */
static struct bh_response_record *
session_enter_vm(u64 seq, int *conn_idx, int lock_session)
{
	struct bh_response_record *rr = NULL;

	if (!conn_idx)
		return NULL;

	rr = session_enter(CONN_IDX_IVM, seq, lock_session);
	if (rr)
		*conn_idx = CONN_IDX_IVM;

	return rr;
}

/**
 * bh_proxy_check_svl_ta_blocked_state - check if ta security version is blocked
 *
 * When installing a ta, a minimum security version is given,
 * so FW will block installation of this ta from lower version.
 * (even after the ta will be uninstalled)
 *
 * @ta_id: trusted application (ta) id
 *
 * Return: 0 when ta security version isn't blocked
 *         <0 on system failure
 *         >0 on FW failure
 */
static int bh_proxy_check_svl_ta_blocked_state(uuid_be ta_id)
{
	int ret;
	char cmdbuf[CMDBUF_SIZE];
	struct bhp_command_header *h = (struct bhp_command_header *)cmdbuf;
	struct bhp_check_svl_ta_blocked_state_cmd *cmd =
			(struct bhp_check_svl_ta_blocked_state_cmd *)h->cmd;
	struct bh_response_record rr;

	memset(cmdbuf, 0, sizeof(cmdbuf));
	memset(&rr, 0, sizeof(rr));

	h->id = BHP_CMD_CHECK_SVL_TA_BLOCKED_STATE;
	cmd->ta_id = ta_id;

	ret = bh_cmd(CONN_IDX_SDM, h, sizeof(*h) + sizeof(*cmd), NULL,
		     0, rrmap_add(CONN_IDX_SDM, &rr), &rr);
	if (!ret)
		ret = rr.code;

	return ret;
}

/**
 * bh_proxy_list_jta_packages - get list of ta packages in FW
 *
 * @conn_idx: fw client connection idx
 * @count: out param to hold the count of ta packages in FW
 * @ta_ids: out param to hold pointer to the ids of ta packages in FW
 *           The buffer which holds the ids is allocated in this function
 *           and freed by the caller
 *
 * Return: 0 when ta security version isn't blocked
 *         <0 on system failure
 *         >0 on FW failure
 */
static int bh_proxy_list_jta_packages(int conn_idx, int *count,
				      uuid_be **ta_ids)
{
	int ret;
	char cmdbuf[CMDBUF_SIZE];
	struct bhp_command_header *h = (struct bhp_command_header *)cmdbuf;
	struct bh_response_record rr;
	struct bhp_resp_list_ta_packages *resp;
	uuid_be *outbuf;
	unsigned int i;

	memset(cmdbuf, 0, sizeof(cmdbuf));
	memset(&rr, 0, sizeof(rr));

	if (!bhp_is_initialized())
		return -EFAULT;

	if (!count || !ta_ids)
		return -EINVAL;

	*ta_ids = NULL;
	*count = 0;

	h->id = BHP_CMD_LIST_TA_PACKAGES;

	ret = bh_request(conn_idx, h, sizeof(*h), NULL, 0,
			 rrmap_add(conn_idx, &rr));
	if (!ret)
		ret = rr.code;
	if (ret)
		goto out;

	if (!rr.buffer) {
		ret = -EBADMSG;
		goto out;
	}

	resp = (struct bhp_resp_list_ta_packages *)rr.buffer;
	if (!resp->count) {
		ret = -EBADMSG;
		goto out;
	}

	if (rr.length != sizeof(uuid_be) * resp->count + sizeof(*resp)) {
		ret = -EBADMSG;
		goto out;
	}

	outbuf = kcalloc(resp->count, sizeof(uuid_be), GFP_KERNEL);

	if (!outbuf) {
		ret = -ENOMEM;
		goto out;
	}

	for (i = 0; i < resp->count; i++)
		outbuf[i] = resp->ta_ids[i];

	*ta_ids = outbuf;
	*count = resp->count;

out:
	kfree(rr.buffer);
	return ret;
}

/**
 * bh_proxy_download_javata - download ta package to FW
 *
 * @conn_idx: fw client connection idx
 * @ta_id: trusted application (ta) id
 * @ta_pkg: ta binary package
 * @pkg_len: ta binary package length
 *
 * Return: 0 on success
 *         <0 on system failure
 *         >0 on FW failure
 */
static int bh_proxy_download_javata(int conn_idx,
				    uuid_be ta_id,
				    const char *ta_pkg,
				    unsigned int pkg_len)
{
	int ret;
	char cmdbuf[CMDBUF_SIZE];
	struct bhp_command_header *h = (struct bhp_command_header *)cmdbuf;
	struct bhp_download_javata_cmd *cmd =
			(struct bhp_download_javata_cmd *)h->cmd;
	struct bh_response_record rr;

	memset(cmdbuf, 0, sizeof(cmdbuf));
	memset(&rr, 0, sizeof(rr));

	if (!ta_pkg || !pkg_len)
		return -EINVAL;

	h->id = BHP_CMD_DOWNLOAD_JAVATA;
	cmd->ta_id = ta_id;

	ret = bh_cmd(conn_idx, h, sizeof(*h) + sizeof(*cmd), ta_pkg,
		     pkg_len, rrmap_add(conn_idx, &rr), &rr);

	if (!ret)
		ret = rr.code;

	return ret;
}

/**
 * bh_proxy_openjtasession - send open session command
 *
 * @conn_idx: fw client connection idx
 * @ta_id: trusted application (ta) id
 * @init_buffer: init parameters to the session (optional)
 * @init_len: length of the init parameters
 * @handle: out param to hold the session handle
 * @ta_pkg: ta binary package
 * @pkg_len: ta binary package length
 *
 * Return: 0 on success
 *         <0 on system failure
 *         >0 on FW failure
 */
static int bh_proxy_openjtasession(int conn_idx,
				   uuid_be ta_id,
				   const char *init_buffer,
				   unsigned int init_len,
				   u64 *handle,
				   const char *ta_pkg,
				   unsigned int pkg_len)
{
	int ret;
	struct bhp_command_header *h;
	struct bhp_open_jtasession_cmd *cmd;
	const size_t cmd_sz = sizeof(*h) + sizeof(*cmd);
	char cmd_buf[cmd_sz];
	struct bh_response_record *rr;
	u64 seq;

	if (!handle)
		return -EINVAL;

	if (!init_buffer && init_len > 0)
		return -EINVAL;

	memset(cmd_buf, 0, cmd_sz);

	h = (struct bhp_command_header *)cmd_buf;
	cmd = (struct bhp_open_jtasession_cmd *)h->cmd;

	rr = kzalloc(sizeof(*rr), GFP_KERNEL);
	if (!rr)
		return -ENOMEM;

	rr->count = 1;
	rr->is_session = true;
	seq = rrmap_add(conn_idx, rr);

	h->id = BHP_CMD_OPEN_JTASESSION;
	cmd->ta_id = ta_id;

	ret = bh_cmd(conn_idx, cmd_buf, cmd_sz, init_buffer, init_len, seq, rr);
	if (!ret)
		ret = rr->code;

	if (ret == BHE_PACKAGE_NOT_FOUND) {
		/*
		 * VM might delete the TA pkg when no live session.
		 * Download the TA pkg and open session again
		 */
		ret = bh_proxy_download_javata(conn_idx, ta_id,
					       ta_pkg, pkg_len);
		if (ret)
			goto out_err;

		ret = bh_cmd(conn_idx, cmd_buf, cmd_sz, init_buffer,
			     init_len, seq, rr);

		if (!ret)
			ret = rr->code;
	}

	if (ret)
		goto out_err;

	*handle = seq;
	session_exit(conn_idx, rr, seq, 0);

	return 0;

out_err:
	session_close(conn_idx, rr, seq, 0);

	return ret;
}

/**
 * bhp_open_ta_session - open session to ta
 *
 * This function will block until VM replied the response
 *
 * @session: out param to hold the session handle
 * @ta_id: trusted application (ta) id
 * @ta_pkg: ta binary package
 * @pkg_len: ta binary package length
 * @init_param: init parameters to the session (optional)
 * @init_len: length of the init parameters
 *
 * Return: 0 on success
 *         <0 on system failure
 *         >0 on FW failure
 */
int bhp_open_ta_session(u64 *session, const char *ta_id,
			const u8 *ta_pkg, size_t pkg_len,
			const u8 *init_param, size_t init_len)
{
	int ret;
	uuid_be bin_ta_id;
	int conn_idx = 0;
	int ta_existed = 0;
	int count = 0;
	uuid_be *ta_ids = NULL;
	int i;

	if (!ta_id || !session)
		return -EINVAL;

	if (!ta_pkg || !pkg_len)
		return -EINVAL;

	if (!init_param && init_len != 0)
		return -EINVAL;

	if (dal_uuid_be_to_bin(ta_id, &bin_ta_id))
		return -EINVAL;

	*session = 0;

	ret = bh_proxy_check_svl_ta_blocked_state(bin_ta_id);
	if (ret)
		return ret;

	/* 1: vm conn_idx is IVM dal FW client */
	conn_idx = CONN_IDX_IVM;

	/* 2.1: check whether the ta pkg existed in VM or not */
	ret = bh_proxy_list_jta_packages(conn_idx, &count, &ta_ids);

	if (!ret) {
		for (i = 0; i < count; i++) {
			if (!uuid_be_cmp(bin_ta_id, ta_ids[i])) {
				ta_existed = 1;
				break;
			}
		}
		kfree(ta_ids);
	}

	/* 2.2: download ta pkg if not existed. */
	if (!ta_existed) {
		ret = bh_proxy_download_javata(conn_idx, bin_ta_id, ta_pkg,
					       pkg_len);
		if (ret && ret != BHE_PACKAGE_EXIST)
			goto cleanup;
	}

	/* 3: send open session command to VM */
	ret = bh_proxy_openjtasession(conn_idx, bin_ta_id,
				      init_param, init_len,
				      session, ta_pkg, pkg_len);

cleanup:
	return ret;
}

/**
 * bhp_send_and_recv - send and receive data to/from ta
 *
 * This function will block until VM replied the response
 *
 * @handle: session handle
 * @command_id: command id
 * @input: message to be sent
 * @length: sent message size
 * @output: output param to hold pointer to the buffer which
 *          will contain received message.
 *          This buffer is allocated by Beihai and freed by the user
 * @output_length: input and output param -
 *                 - input: the expected maximum length of the received message
 *                 - output: size of the received message
 * @response_code: output param to hold the return value from the applet
 *
 * Return: 0 on success
 *         <0 on system failure
 *         >0 on FW failure
 */
int bhp_send_and_recv(const u64 handle, int command_id,
		      const void *input, size_t length,
		      void **output, size_t *output_length,
		      int *response_code)
{
	int ret;
	char cmdbuf[CMDBUF_SIZE];
	struct bhp_command_header *h = (struct bhp_command_header *)cmdbuf;
	struct bhp_cmd *cmd = (struct bhp_cmd *)h->cmd;
	u64 seq = handle;
	struct bh_response_record *rr = NULL;
	int conn_idx = 0;
	unsigned int len;

	memset(cmdbuf, 0, sizeof(cmdbuf));

	if (!bhp_is_initialized())
		return -EFAULT;

	if (!input && length != 0)
		return -EINVAL;

	if (!output_length)
		return -EINVAL;

	if (output)
		*output = NULL;

	rr = session_enter_vm(seq, &conn_idx, 1);
	if (!rr)
		return -EINVAL;

	rr->buffer = NULL;
	h->id = BHP_CMD_SENDANDRECV;
	cmd->ta_session_id = rr->addr;
	cmd->command = command_id;
	cmd->outlen = *output_length;

	ret = bh_request(conn_idx, h, sizeof(*h) + sizeof(*cmd), input,
			 length, seq);
	if (!ret)
		ret = rr->code;

	if (rr->killed)
		ret = BHE_UNCAUGHT_EXCEPTION;

	if (ret == BHE_APPLET_SMALL_BUFFER && rr->buffer &&
	    rr->length == sizeof(struct bhp_resp_bof)) {
		struct bhp_resp_bof *bof = (struct bhp_resp_bof *)rr->buffer;

		if (response_code)
			*response_code = be32_to_cpu(bof->response);

		*output_length = be32_to_cpu(bof->request_length);
	}

	if (ret)
		goto out;

	if (rr->buffer && rr->length >= sizeof(struct bhp_resp)) {
		struct bhp_resp *resp = (struct bhp_resp *)rr->buffer;

		if (response_code)
			*response_code = be32_to_cpu(resp->response);

		len = rr->length - sizeof(*resp);

		if (*output_length < len) {
			ret = -EMSGSIZE;
			goto out;
		}

		if (len > 0 && output) {
			*output = kzalloc(len, GFP_KERNEL);
			if (!*output) {
				ret = -ENOMEM;
				goto out;
			}
			memcpy(*output, resp->buffer, len);
		}

		*output_length = len;
	} else {
		ret = -EBADMSG;
	}

out:
	kfree(rr->buffer);
	rr->buffer = NULL;

	session_exit(conn_idx, rr, seq, 1);

	return ret;
}

/**
 * bhp_close_ta_session - close ta session
 *
 * This function will block until VM replied the response
 *
 * @handle: session handle
 *
 * Return: 0 on success
 *         <0 on system failure
 *         >0 on FW failure
 */
int bhp_close_ta_session(const u64 handle)
{
	int ret;
	char cmdbuf[CMDBUF_SIZE];
	struct bhp_command_header *h = (struct bhp_command_header *)cmdbuf;
	struct bhp_close_jtasession_cmd *cmd =
			(struct bhp_close_jtasession_cmd *)h->cmd;
	struct bh_response_record *rr;
	const size_t cmd_sz = sizeof(*h) + sizeof(*cmd);
	u64 seq = handle;
	int conn_idx = 0;

	memset(cmdbuf, 0, sizeof(cmdbuf));

	rr = session_enter_vm(seq, &conn_idx, 1);
	if (!rr)
		return -EINVAL;

	h->id = BHP_CMD_CLOSE_JTASESSION;
	cmd->ta_session_id = rr->addr;

	ret = bh_cmd(conn_idx, h, cmd_sz, NULL, 0, seq, rr);

	if (!ret)
		ret = rr->code;

	if (rr->killed)
		ret = BHE_UNCAUGHT_EXCEPTION;

	/*
	 * An internal session exists, so we should not close the session.
	 * It means that host app should call this API at appropriate time.
	 */
	if (ret == BHE_IAC_EXIST_INTERNAL_SESSION)
		session_exit(conn_idx, rr, seq, 1);
	else
		session_close(conn_idx, rr, seq, 1);

	return ret;
}

/**
 * bh_filter_hdr - filter the sent message
 *
 * Allow to send valid messages only.
 * The filtering is done using given filter functions table
 *
 * @hdr: message header
 * @count: message size
 * @ctx: context to send to the filter functions
 * @tbl: filter functions table
 *
 * Return: 0 when message is valid
 *         <0 on otherwise
 */
int bh_filter_hdr(const struct bhp_command_header *hdr, size_t count, void *ctx,
		  const bh_filter_func tbl[])
{
	int i;
	int ret;

	for (i = 0; tbl[i]; i++) {
		ret = tbl[i](hdr, count, ctx);
		if (ret < 0)
			return ret;
	}
	return 0;
}

/**
 * bh_prep_access_denied_response - prepare package with 'access denied'
 *                                  response code.
 *
 * This function is used to send in band error to user who trying to send
 * message when he lacks the needed permissions
 *
 * @cmd: the invalid command message (needed in order to find out
 *       the sequence number)
 * @res: out param to hold the response header
 */
void bh_prep_access_denied_response(const char *cmd,
				    struct bhp_response_header *res)
{
	struct bhp_command_header *cmd_hdr = (struct bhp_command_header *)cmd;

	res->h.magic = BH_MSG_RESP_MAGIC;
	res->h.length = sizeof(*res);
	res->code = BHE_OPERATION_NOT_PERMITTED;
	res->seq = cmd_hdr->seq;
}
