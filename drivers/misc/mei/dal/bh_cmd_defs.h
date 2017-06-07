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

#ifndef __BHP_HECI_H
#define __BHP_HECI_H

#include <linux/types.h>
#include <linux/uuid.h>

/**
 * enum bhp_command_id - bhp command ids
 *
 * @BHP_CMD_INIT: init command
 * @BHP_CMD_DEINIT: deinit command
 * @BHP_CMD_VERIFY_JAVATA: verify ta
 * @BHP_CMD_DOWNLOAD_JAVATA: download ta to FW
 * @BHP_CMD_OPEN_JTASESSION: open session to ta
 * @BHP_CMD_CLOSE_JTASESSION: close session with ta
 * @BHP_CMD_FORCECLOSE_JTASESSION: force close session
 * @BHP_CMD_SENDANDRECV: send and receive massages to ta
 * @BHP_CMD_SENDANDRECV_INTERNAL: internal send and receive
 * @BHP_CMD_RUN_NATIVETA: run native trusted application
 *                        (currently NOT SUPPORTED)
 * @BHP_CMD_STOP_NATIVETA: stop running native ta (currently NOT SUPPORTED)
 * @BHP_CMD_OPEN_SDSESSION: open security domain session
 * @BHP_CMD_CLOSE_SDSESSION: close security domain session
 * @BHP_CMD_INSTALL_SD: install new sub security domain
 * @BHP_CMD_UNINSTALL_SD: uninstall sub security domain
 * @BHP_CMD_INSTALL_JAVATA: install java ta
 * @BHP_CMD_UNINSTALL_JAVATA: uninstall java ta
 * @BHP_CMD_INSTALL_NATIVETA: install native ta (currently NOT SUPPORTED)
 * @BHP_CMD_UNINSTALL_NATIVETA: uninstall native ta (currently NOT SUPPORTED)
 * @BHP_CMD_LIST_SD: get list of all security domains
 * @BHP_CMD_LIST_TA: get list of all installed trusted applications
 * @BHP_CMD_RESET: reset command
 * @BHP_CMD_LIST_TA_PROPERTIES: get list of all ta properties (ta manifest)
 * @BHP_CMD_QUERY_TA_PROPERTY: query specified ta property
 * @BHP_CMD_LIST_JTA_SESSIONS: get list of all opened ta sessions
 * @BHP_CMD_LIST_TA_PACKAGES: get list of all ta packages in FW
 * @BHP_CMD_GET_ISD: get Intel security domain uuid
 * @BHP_CMD_GET_SD_BY_TA: get security domain id of ta
 * @BHP_CMD_LAUNCH_VM: lunch IVM
 * @BHP_CMD_CLOSE_VM: close IVM
 * @BHP_CMD_QUERY_NATIVETA_STATUS: query specified native ta status
 *                                 (currently NOT SUPPORTED)
 * @BHP_CMD_QUERY_SD_STATUS: query specified security domain status
 * @BHP_CMD_LIST_DOWNLOADED_NTA: get list of all native trusted applications
 *                               (currently NOT SUPPORTED)
 * @BHP_CMD_UPDATE_SVL: update security version list
 * @BHP_CMD_CHECK_SVL_TA_BLOCKED_STATE: check if ta security version is blocked
 * @BHP_CMD_QUERY_TEE_METADATA: get DAL metadata (including api_level,
 *                              library_version, dal_key_hash and more)
 *
 * @BHP_CMD_MAX: max command id
 */

enum bhp_command_id {
	BHP_CMD_INIT = 0,
	BHP_CMD_DEINIT,
	BHP_CMD_VERIFY_JAVATA,
	BHP_CMD_DOWNLOAD_JAVATA,
	BHP_CMD_OPEN_JTASESSION,
	BHP_CMD_CLOSE_JTASESSION,
	BHP_CMD_FORCECLOSE_JTASESSION,
	BHP_CMD_SENDANDRECV,
	BHP_CMD_SENDANDRECV_INTERNAL,
	BHP_CMD_RUN_NATIVETA,
	BHP_CMD_STOP_NATIVETA,
	BHP_CMD_OPEN_SDSESSION,
	BHP_CMD_CLOSE_SDSESSION,
	BHP_CMD_INSTALL_SD,
	BHP_CMD_UNINSTALL_SD,
	BHP_CMD_INSTALL_JAVATA,
	BHP_CMD_UNINSTALL_JAVATA,
	BHP_CMD_INSTALL_NATIVETA,
	BHP_CMD_UNINSTALL_NATIVETA,
	BHP_CMD_LIST_SD,
	BHP_CMD_LIST_TA,
	BHP_CMD_RESET,
	BHP_CMD_LIST_TA_PROPERTIES,
	BHP_CMD_QUERY_TA_PROPERTY,
	BHP_CMD_LIST_JTA_SESSIONS,
	BHP_CMD_LIST_TA_PACKAGES,
	BHP_CMD_GET_ISD,
	BHP_CMD_GET_SD_BY_TA,
	BHP_CMD_LAUNCH_VM,
	BHP_CMD_CLOSE_VM,
	BHP_CMD_QUERY_NATIVETA_STATUS,
	BHP_CMD_QUERY_SD_STATUS,
	BHP_CMD_LIST_DOWNLOADED_NTA,
	BHP_CMD_UPDATE_SVL,
	BHP_CMD_CHECK_SVL_TA_BLOCKED_STATE,
	BHP_CMD_QUERY_TEE_METADATA,
	BHP_CMD_MAX
};

#define BH_MSG_RESP_MAGIC  0x55aaa5ff
#define BH_MSG_CMD_MAGIC   0x55aaa3ff

/**
 * struct bhp_msg_header - transport header
 *
 * @magic: BH_MSG_RESP/CMD_MAGIC
 * @length: overall message length
 */
struct bhp_msg_header {
	u32 magic;
	u32 length;
};

/**
 * struct bhp_command_header - bh plugin command header
 *
 * @h: transport header
 * @seq: message sequence number
 * @id: the command id (enum bhp_command_id)
 * @pad: padded for 64 bit
 * @cmd: command buffer
 */
struct  bhp_command_header {
	struct bhp_msg_header h;
	u64 seq;
	u32 id;
	u8 pad[4];
	s8 cmd[0];
} __packed;

/**
 * struct bhp_response_header - response header (from the DAL)
 *
 * @h: transport header
 * @seq: message sequence number
 * @ta_session_id: session id (firmware address)
 * @code: response code
 * @pad: padded for 64 bit
 * @data: response buffer
 */
struct bhp_response_header {
	struct bhp_msg_header h;
	u64 seq;
	u64 ta_session_id;
	s32 code;
	u8 pad[4];
	s8 data[0];
} __packed;

/**
 * struct bhp_download_javata_cmd - download trusted application
 *     to the firmware
 *
 * @ta_id: trusted application (ta) id
 * @ta_blob: trusted application blob
 */
struct bhp_download_javata_cmd {
	uuid_be ta_id;
	s8 ta_blob[0];
} __packed;

/**
 * struct bhp_open_jtasession_cmd - open session to TA command
 *
 * @ta_id: trusted application (ta) id
 * @buffer: session initial parameters (optional)
 */
struct bhp_open_jtasession_cmd {
	uuid_be ta_id;
	s8 buffer[0];
} __packed;

/**
 * struct bhp_close_jtasession_cmd - close session cmd
 *
 * @ta_session_id: session id
 */
struct bhp_close_jtasession_cmd {
	u64 ta_session_id;
} __packed;

/**
 * struct bhp_cmd - bhp command
 *
 * @ta_session_id: session id
 * @command: command id to ta
 * @outlen: length of output buffer
 * @buffer: data to send
 */
struct bhp_cmd {
	u64 ta_session_id;
	s32 command;
	u32 outlen;
	s8 buffer[0];
} __packed;

/**
 * struct bhp_check_svl_ta_blocked_state_cmd - command to check if
 *     the trusted application security version is blocked
 *
 * @ta_id: trusted application id
 */
struct bhp_check_svl_ta_blocked_state_cmd {
	uuid_be ta_id;
} __packed;

/**
 * struct bhp_response - bhp response
 *
 * @response: response code. Originated from java in big endian format
 * @buffer: response buffer
 */
struct bhp_resp {
	__be32 response;
	s8 buffer[0];
} __packed;

/**
 * struct bhp_resp_bof - response when output buffer is too small
 *
 * @response: response code. Originated from java in big endian format
 * @request_length: the needed output buffer length
 */
struct bhp_resp_bof {
	__be32 response;
	__be32 request_length;
} __packed;

/**
 * struct bhp_resp_list_ta_packages - list of ta packages from the firmware.
 *
 * @count: count of ta packages
 * @ta_ids: ta packages ids
 */
struct bhp_resp_list_ta_packages {
	u32 count;
	uuid_be ta_ids[0];
} __packed;

#endif /* __BHP_HECI_H */
