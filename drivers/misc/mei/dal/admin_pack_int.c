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

/*
 * @file  admin_pack_int.cpp
 * @brief This file implements internal atomic api of admin command parsing
 *        The counter part which generate admin package is BPKT
 * @author Wenlong Feng(wenlong.feng@intel.com)
 */

#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/errno.h>

#include "bh_errcode.h"
#include "bh_acp_format.h"
#include "bh_acp_internal.h"
#include "bh_acp_exp.h"

#define PR_ALIGN 4

/**
 * pr_init - init pack reader
 *
 * @pr: pack reader
 * @data: acp file content (without CSS header)
 * @n: acp file size (without CSS header)
 *
 * Return: 0 on success
 *         -EINVAL on invalid parameters
 */
int pr_init(struct pack_reader *pr, const char *data, unsigned int n)
{
	/* check integer overflow */
	if ((size_t)data > SIZE_MAX - n)
		return -EINVAL;

	pr->cur = data;
	pr->head = data;
	pr->total = n;
	return 0;
}

/**
 * pr_8b_align_move - update pack reader cur pointer after reading n_move bytes
 *                    Leave cur aligned to 8 bytes.
 *                    (e.g. when n_move is 3, increase cur by 8)
 *
 * @pr: pack reader
 * @n_move: number of bytes to move cur pointer ahead
 *          will be rounded up to keep cur 8 bytes aligned
 *
 * Return: 0 on success
 *         -EINVAL on invalid parameters
 */
static int pr_8b_align_move(struct pack_reader *pr, size_t n_move)
{
	unsigned long offset;
	const char *new_cur = pr->cur + n_move;
	size_t len_from_head = new_cur - pr->head;

	if ((size_t)pr->cur > SIZE_MAX - n_move || new_cur < pr->head)
		return -EINVAL;

	offset = ((8 - (len_from_head & 7)) & 7);
	if ((size_t)new_cur > SIZE_MAX - offset)
		return -EINVAL;

	new_cur = new_cur + offset;
	if (new_cur > pr->head + pr->total)
		return -EINVAL;

	pr->cur = new_cur;
	return 0;
}

/**
 * pr_align_move - update pack reader cur pointer after reading n_move bytes
 *                 Leave cur aligned to 4 bytes.
 *                 (e.g. when n_move is 1, increase cur by 4)
 *
 * @pr: pack reader
 * @n_move: number of bytes to move cur pointer ahead
 *          will be rounded up to keep cur 4 bytes aligned
 *
 * Return: 0 on success
 *         -EINVAL on invalid parameters
 */
static int pr_align_move(struct pack_reader *pr, size_t n_move)
{
	const char *new_cur = pr->cur + n_move;
	size_t len_from_head = new_cur - pr->head;
	size_t offset;

	if ((size_t)pr->cur > SIZE_MAX - n_move || new_cur < pr->head)
		return -EINVAL;

	offset = ((4 - (len_from_head & 3)) & 3);
	if ((size_t)new_cur > SIZE_MAX - offset)
		return -EINVAL;

	new_cur = new_cur + offset;
	if (new_cur > pr->head + pr->total)
		return -EINVAL;

	pr->cur = new_cur;
	return 0;
}

/**
 * pr_move - update pack reader cur pointer after reading n_move bytes
 *
 * @pr: pack reader
 * @n_move: number of bytes to move cur pointer ahead
 *
 * Return: 0 on success
 *         -EINVAL on invalid parameters
 */
static int pr_move(struct pack_reader *pr, size_t n_move)
{
	const char *new_cur = pr->cur + n_move;

	/* integer overflow or out of acp pkg size */
	if ((size_t)pr->cur > SIZE_MAX - n_move ||
	    new_cur > pr->head + pr->total)
		return -EINVAL;

	pr->cur = new_cur;

	return 0;
}

/**
 * pr_is_safe_to_read - check whether it is safe to read more n_move
 *                      bytes from the acp file
 *
 * @pr: pack reader
 * @n_move: number of bytes to check if it is safe to read
 *
 * Return: true when it is safe to read more n_move bytes
 *         false otherwise
 */
static bool pr_is_safe_to_read(const struct pack_reader *pr, size_t n_move)
{
	/* pointer overflow */
	if ((size_t)pr->cur > SIZE_MAX - n_move)
		return false;

	if (pr->cur + n_move > pr->head + pr->total)
		return false;

	return true;
}

/**
 * pr_is_end - check if cur is at the end of the acp file
 *
 * @pr: pack reader
 *
 * Return: true when cur is at the end of the acp
 *         false otherwise
 */
bool pr_is_end(struct pack_reader *pr)
{
	return (pr->cur == pr->head + pr->total);
}

/**
 * acp_load_reasons - load list of event codes that can be
 *                    received or posted by ta
 *
 * @pr: pack reader
 * @reasons: out param to hold the list of event codes
 *
 * Return: 0 on success
 *         -EINVAL on invalid parameters
 */
static int acp_load_reasons(struct pack_reader *pr,
			    struct ac_ins_reasons **reasons)
{
	size_t len;
	struct ac_ins_reasons *r;

	if (!pr_is_safe_to_read(pr, sizeof(*r)))
		return -EINVAL;

	r = (struct ac_ins_reasons *)pr->cur;

	if (r->len > BH_MAX_ACP_INS_REASONS_LENGTH)
		return -EINVAL;

	len = sizeof(*r) + r->len * sizeof(r->data[0]);
	if (!pr_is_safe_to_read(pr, len))
		return -EINVAL;

	*reasons = r;
	return pr_align_move(pr, len);
}

/**
 * acp_load_taid_list - load list of ta ids which ta is allowed
 *                      to communicate with
 *
 * @pr: pack reader
 * @taid_list: out param to hold the loaded ta ids
 *
 * Return: 0 on success
 *         -EINVAL on invalid parameters
 */
static int acp_load_taid_list(struct pack_reader *pr,
			      struct bh_ta_id_list **taid_list)
{
	size_t len;
	struct bh_ta_id_list *t;

	if (!pr_is_safe_to_read(pr, sizeof(*t)))
		return -EINVAL;

	t = (struct bh_ta_id_list *)pr->cur;
	if (t->num > BH_MAX_ACP_USED_SERVICES)
		return -EINVAL;

	len = sizeof(*t) + t->num * sizeof(t->list[0]);

	if (!pr_is_safe_to_read(pr, len))
		return -EINVAL;

	*taid_list = t;
	return pr_align_move(pr, len);
}

/**
 * acp_load_prop - load property from acp
 *
 * @pr: pack reader
 * @prop: out param to hold the loaded property
 *
 * Return: 0 on success
 *         -EINVAL on invalid parameters
 */
static int acp_load_prop(struct pack_reader *pr, struct bh_prop_list **prop)
{
	size_t len;
	struct bh_prop_list *p;

	if (!pr_is_safe_to_read(pr, sizeof(*p)))
		return -EINVAL;

	p = (struct bh_prop_list *)pr->cur;
	if (p->len > BH_MAX_ACP_PROPS_LENGTH)
		return -EINVAL;

	len = sizeof(*p) + p->len * sizeof(p->data[0]);

	if (!pr_is_safe_to_read(pr, len))
		return -EINVAL;

	*prop = p;
	return pr_align_move(pr, len);
}

/**
 * acp_load_ta_pack - load ta pack from acp
 *
 * @pr: pack reader
 * @ta_pack: out param to hold the ta pack
 *
 * Return: 0 on success
 *         -EINVAL on invalid parameters
 */
int acp_load_ta_pack(struct pack_reader *pr, char **ta_pack)
{
	size_t len;
	char *t;

	/*8 byte align to obey jeff rule*/
	if (pr_8b_align_move(pr, 0))
		return -EINVAL;

	t = (char *)pr->cur;

	/*
	 *assume ta pack is the last item of one package,
	 *move cursor to the end directly
	 */
	if (pr->cur > pr->head + pr->total)
		return -EINVAL;

	len = pr->head + pr->total - pr->cur;
	if (!pr_is_safe_to_read(pr, len))
		return -EINVAL;

	*ta_pack = t;
	return pr_move(pr, len);
}

/**
 * acp_load_ins_jta_prop_head - load ta manifest header
 *
 * @pr: pack reader
 * @head: out param to hold manifest header
 *
 * Return: 0 on success
 *         -EINVAL on invalid parameters
 */
static int acp_load_ins_jta_prop_head(struct pack_reader *pr,
				      struct ac_ins_jta_prop_header **head)
{
	if (!pr_is_safe_to_read(pr, sizeof(**head)))
		return -EINVAL;

	*head = (struct ac_ins_jta_prop_header *)pr->cur;
	return pr_align_move(pr, sizeof(**head));
}

/**
 * acp_load_ins_jta_prop - load ta properties information (ta manifest)
 *
 * @pr: pack reader
 * @pack: out param to hold ta manifest
 *
 * Return: 0 on success
 *         -EINVAL on invalid parameters
 */
int acp_load_ins_jta_prop(struct pack_reader *pr, struct ac_ins_jta_prop *pack)
{
	int ret;

	ret = acp_load_ins_jta_prop_head(pr, &pack->head);
	if (ret)
		return ret;

	ret = acp_load_reasons(pr, &pack->post_reasons);
	if (ret)
		return ret;

	ret = acp_load_reasons(pr, &pack->reg_reasons);
	if (ret)
		return ret;

	ret = acp_load_prop(pr, &pack->prop);
	if (ret)
		return ret;

	ret = acp_load_taid_list(pr, &pack->used_service_list);

	return ret;
}

/**
 * acp_load_ins_jta_head - load ta installation header
 *
 * @pr: pack reader
 * @head: out param to hold the installation header
 *
 * Return: 0 on success
 *         -EINVAL on invalid parameters
 */
static int acp_load_ins_jta_head(struct pack_reader *pr,
				 struct ac_ins_ta_header **head)
{
	if (!pr_is_safe_to_read(pr, sizeof(**head)))
		return -EINVAL;

	*head = (struct ac_ins_ta_header *)pr->cur;
	return pr_align_move(pr, sizeof(**head));
}

/**
 * acp_load_ins_jta - load ta installation information from acp
 *
 * @pr: pack reader
 * @pack: out param to hold install information
 *
 * Return: 0 on success
 *         -EINVAL on invalid parameters
 */
int acp_load_ins_jta(struct pack_reader *pr, struct ac_ins_jta_pack *pack)
{
	int ret;

	ret = acp_load_prop(pr, &pack->ins_cond);
	if (ret)
		return ret;

	ret = acp_load_ins_jta_head(pr, &pack->head);

	return ret;
}

/**
 * acp_load_pack_head - load acp pack header
 *
 * @pr: pack reader
 * @head: out param to hold the acp header
 *
 * Return: 0 on success
 *         -EINVAL on invalid parameters
 */
int acp_load_pack_head(struct pack_reader *pr, struct ac_pack_header **head)
{
	if (!pr_is_safe_to_read(pr, sizeof(**head)))
		return -EINVAL;

	*head = (struct ac_pack_header *)pr->cur;
	return pr_align_move(pr, sizeof(**head));
}
