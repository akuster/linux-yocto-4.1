/******************************************************************************
 * Intel mei_dal test Linux driver
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
#ifndef KDI_CMD_DEFS_H
#define KDI_CMD_DEFS_H

#define NULL_ARG ((__u32)-1)

enum kdi_command_id {
	KDI_SESSION_CREATE,
	KDI_SESSION_CLOSE,
	KDI_SEND_AND_RCV,
	KDI_VERSION_GET_INFO,
	KDI_EXCLUSIVE_ACCESS_SET,
	KDI_EXCLUSIVE_ACCESS_REMOVE
};

/**
 * struct kdi_test_command - contains the command data to be sent
 * to the kdi_test module.
 * @cmd_id: the command id (kdi_command_id type)
 * @data: the actual command data.
 */
struct kdi_test_command {
	__u8 cmd_id;
	unsigned char data[0];
};

struct session_create_cmd {
	__u8 is_session_handle_ptr; /* either send kdi session handle or NULL */
	__u32 app_id_len;           /* length app_id arg (valid len is 33) */
	__u32 acp_pkg_len_real;     /* real length of the acp_pkg arg */
	__u32 acp_pkg_len_to_kdi;   /* the acp_pkg len to be passed to kdi */
	__u32 init_param_len_real;  /* real length of init param arg */
	__u32 init_param_len_to_kdi;/* init param len to be passed to kdi */
	unsigned char data[0];
};

struct session_create_resp {
	__u64 session_handle;
	__s32 status;
};

struct session_close_cmd {
	__u64 session_handle;
};

struct session_close_resp {
	__s32 status;
};

struct send_and_rcv_cmd {
	__u64 session_handle;
	__u32 command_id;
	__u32 input_len_real;     /* real length of the input */
	__u32 input_len_to_kdi;   /* the input len to be passed to kdi */
	__u32 output_buf_len;     /* the size of output buffer */
	__u8 is_output_buf;       /* either send kdi output buffer or NULL */
	__u8 is_output_len_ptr;   /* either send kdi output len ptr or NULL */
	__u8 is_response_code_ptr;/* either send kdi res code ptr or NULL */
	unsigned char input[0];
};

struct send_and_rcv_resp {
	__s32 status;
	__s32 response_code;
	__u32 output_len;
	unsigned char output[0];
};

struct version_get_info_cmd {
	__u8 is_version_ptr; /* either send kdi version info ptr or NULL */
};

struct version_get_info_resp {
	char kdi_version[32];
	__u32 reserved[4];
	__s32 status;

};

struct ta_access_set_remove_cmd {
	__u32 app_id_len;
	unsigned char data[0];
};

struct ta_access_set_remove_resp {
	__s32 status;
};

#endif
