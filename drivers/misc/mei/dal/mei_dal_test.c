/******************************************************************************
 * Intel dal test Linux driver
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

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/mei_cl_bus.h>
#include <linux/device.h>
#include <linux/init.h>
#include <linux/mutex.h>
#include <linux/wait.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/printk.h>
#include <linux/dal.h>
#include <linux/gfp.h>
#include <linux/uuid.h>
#include <linux/ctype.h>
#include <linux/sizes.h>
#include <linux/atomic.h>

#include "uapi/kdi_cmd_defs.h"

#define KDI_MODULE "mei_dal"
#define MAX_CDEV_NAME_LEN 20

/**
 * this is the max data size possible:
 * there is no acually max size for acp file,
 * but for testing 512k s good enough
 */
#define MAX_DATA_SIZE SZ_512K

static struct cdev cdev;
static dev_t dal_test_devt;
static struct class *cl;

#define KDI_TEST_OPENED 0
static unsigned long kdi_test_status;

struct dal_test_data {
	u32 cmd_data_size;
	u8 *cmd_data;
	struct mutex cmd_lock; /*protects cmd_data buffer */

	u32 resp_data_size;
	u8 *resp_data;
	struct mutex resp_lock; /*protects resp_data buffer */
};

static int id;
module_param(id, int, 0000);
MODULE_PARM_DESC(id, "Kernel module id");

#ifdef CONFIG_MODULES
static struct module *dal_test_find_module(const char *mod_name)
{
	struct module *mod;

	mutex_lock(&module_mutex);
	mod = find_module(mod_name);
	mutex_unlock(&module_mutex);

	return mod;
}

static int dal_test_load_kdi(void)
{
	struct module *mod;

	/* load KDI if it wasn't loaded */
	request_module(KDI_MODULE);

	mod = dal_test_find_module(KDI_MODULE);
	if (!mod) {
		pr_err("failed to find KDI module: %s\n", KDI_MODULE);
		return -ENODEV;
	}

	if (!try_module_get(mod)) {
		pr_err("failed to get KDI module\n");
		return  -EFAULT;
	}

	return 0;
}

static int dal_test_unload_kdi(void)
{
	struct module *mod;

	mod = dal_test_find_module(KDI_MODULE);
	if (!mod) {
		pr_err("failed to find KDI module: %s\n", KDI_MODULE);
		return -ENODEV;
	}
	module_put(mod);

	return 0;
}
#else
static inline int dal_test_load_kdi(void) { return 0; }
static inline int dal_test_unload_kdi(void) { return 0; }
#endif

static void print_input_send_and_rcv(struct send_and_rcv_cmd *send_and_rcv,
				     u8 *input, char *output)
{
	pr_debug("dal_send_and_receive params:\n"
		"\thandle=%llu\n\tcommand_id=%d\n"
		"\tinput (size)=%u\n\tinput (ptr)=%p\n"
		"\tinput_len_to_kdi=%u\n\toutput (ptr)=%p\n"
		"\tis_output_len (bool)=%d\n\toutput_buf_len =%u\n"
		"\tis_response_code (bool)=%d\n",
		send_and_rcv->session_handle,
		send_and_rcv->command_id,
		send_and_rcv->input_len_real == NULL_ARG ?
			-1 : send_and_rcv->input_len_real,
		input, send_and_rcv->input_len_to_kdi,
		send_and_rcv->is_output_buf ? output : NULL,
		send_and_rcv->is_output_len_ptr,
		send_and_rcv->output_buf_len,
		send_and_rcv->is_response_code_ptr);
}

static void
print_output_send_and_rcv(const struct send_and_rcv_resp *snr_resp)
{
	pr_debug("send_and_rcv_resp: status=%d toutput_len=%u tresponse_code=%d\n",
		 snr_resp->status,
		 snr_resp->output_len,
		 snr_resp->response_code);
}

/**
 * dal_test_result_set - set data to the result buffer
 *
 * @test_data: test command and response buffers
 * @data:  new data
 * @size:  size of the data buffer
 */
static void dal_test_result_set(struct dal_test_data *test_data,
				void *data, u32 size)
{
	memcpy(test_data->resp_data, data, size);
	test_data->resp_data_size = size;
}

/**
 * dal_test_result_append - append data to the result buffer
 *
 * @test_data: test command and response buffers
 * @data:  new data
 * @size:  size of the data buffer
 */
static void dal_test_result_append(struct dal_test_data *test_data,
				   void *data, u32 size)
{
	size_t offset = test_data->resp_data_size;

	memcpy(test_data->resp_data + offset, data, size);
	test_data->resp_data_size += size;
}

static s32 dal_test_send_and_recv(struct kdi_test_command *cmd,
				  struct dal_test_data *test_data)
{
	struct send_and_rcv_cmd *snr_cmd;
	struct send_and_rcv_resp snr_resp;
	size_t output_len;
	u32 snr_struct_size;
	u32 snr_data_size;
	s32 response_code;
	s32 status;
	u8 *output = NULL;
	u8 *input = NULL;

	snr_cmd = (struct send_and_rcv_cmd *)cmd->data;
	/* check that there is enough data to duplicate */
	snr_struct_size = test_data->cmd_data_size - sizeof(cmd->cmd_id);
	snr_data_size = snr_struct_size - sizeof(*snr_cmd);

	if (snr_cmd->input_len_real != NULL_ARG) {
		if (snr_cmd->input_len_real > snr_data_size) {
			pr_err("malformed command struct\n \tinput_len_real = %u; snr_data_size = %u\n",
			       snr_cmd->input_len_real, snr_data_size);
			status = -EINVAL;
			goto prep_output;
		}

		input = kmemdup(snr_cmd->input, snr_cmd->input_len_real,
				GFP_KERNEL);
		if (!input) {
			pr_err("failed to duplicate input\n");
			status = -ENOMEM;
			goto prep_output;
		}
	}

	print_input_send_and_rcv(snr_cmd, input, output);
	output_len = snr_cmd->output_buf_len;
	status = dal_send_and_receive(snr_cmd->session_handle,
				      snr_cmd->command_id, input,
				      snr_cmd->input_len_to_kdi,
				      snr_cmd->is_output_buf ? &output : NULL,
				      snr_cmd->is_output_len_ptr ?
				      &output_len : NULL,
				      snr_cmd->is_response_code_ptr ?
				      &response_code : NULL);

	pr_debug("dal_send_and_receive return:\n\tstatus=%d\n\toutput_len=%zu\n\tresponse_code=0x%x\n",
		 status, output_len, response_code);

prep_output:
	if (snr_cmd->is_output_buf && snr_cmd->is_output_len_ptr)
		snr_resp.output_len = (u32)output_len;
	else
		snr_resp.output_len = NULL_ARG;

	if (snr_cmd->is_response_code_ptr)
		snr_resp.response_code = response_code;

	snr_resp.status = status;

	print_output_send_and_rcv(&snr_resp);

	/* in case the call failed we don't copy the data */
	mutex_lock(&test_data->resp_lock);
	dal_test_result_set(test_data, &snr_resp, sizeof(snr_resp));
	if (output && snr_resp.output_len != NULL_ARG)
		dal_test_result_append(test_data, output, snr_resp.output_len);
	mutex_unlock(&test_data->resp_lock);

	if (output && snr_cmd->is_output_buf)
		kfree(output);

	kfree(input);

	return status;
}

static void
print_input_create_session(struct session_create_cmd *create_session,
			   char *app_id, u8 *acp_pkg, u8 *init_params)
{
	pr_debug("dal_create_session params:\n"
		"\tis_h_ptr (bool)=%d\n\tapp_id=%s\n\tacp_pkg (size)=%u\n"
		"\tacp_pkg (ptr)=%p\n\tacp_pkg_len_to_kdi=%u\n"
		"\tinit_param (size)=%u\n\tinit_param (ptr)=%p\n"
		"\tinit_param_len_to_kdi=%u\n",
		create_session->is_session_handle_ptr, app_id,
		create_session->acp_pkg_len_real == NULL_ARG ? -1 :
			create_session->acp_pkg_len_real,
		acp_pkg, create_session->acp_pkg_len_to_kdi,
		create_session->init_param_len_real == NULL_ARG ? -1 :
			create_session->init_param_len_real,
		init_params, create_session->init_param_len_to_kdi);
}

static int dal_test_create_session(struct kdi_test_command *tcmd,
				   struct dal_test_data *tdata)
{
	struct session_create_cmd *cmd;
	u64 handle = 0;
	char *app_id = NULL;
	u8 *acp_pkg = NULL;
	u8 *init_params = NULL;
	u32 create_session_cmd_size;
	u32 create_session_data_size;
	u32 total_input_data_size = 0;
	u32 offset = 0;
	s32 status;

	cmd  = (struct session_create_cmd *)tcmd->data;
	/* check that there is enough data to duplicate */
	create_session_cmd_size = tdata->cmd_data_size - sizeof(tcmd->cmd_id);
	create_session_data_size = create_session_cmd_size - sizeof(*cmd);

	pr_debug("create_session_cmd_size=%u create_session_data_size=%u\n",
		 create_session_cmd_size, create_session_data_size);

	if (cmd->app_id_len != NULL_ARG)
		total_input_data_size += cmd->app_id_len;
	if (cmd->acp_pkg_len_real != NULL_ARG)
		total_input_data_size += cmd->acp_pkg_len_real;
	if (cmd->init_param_len_real != NULL_ARG)
		total_input_data_size += cmd->init_param_len_real;

	if (total_input_data_size > create_session_data_size) {
		pr_err("malformed command struct;\n"
			"\tapp_id_len=%u; acp_pkg_len_real=%u;init_param_len_real=%u;\n"
			"\ttotal_input_data_size=%u\n\tcreate_session_data_size=%u\n",
			cmd->app_id_len,
			cmd->acp_pkg_len_real,
			cmd->init_param_len_real,
			total_input_data_size,
			create_session_data_size);
		status = -EINVAL;
		goto prepare_resp;
	}

	if (cmd->app_id_len != NULL_ARG) {
		app_id = kmemdup(cmd->data + offset,
				 cmd->app_id_len, GFP_KERNEL);
		if (!app_id) {
			pr_err("failed to duplicate app_id\n");
			status = -ENOMEM;
			goto prepare_resp;
		}
		offset += cmd->app_id_len;
	}

	if (cmd->acp_pkg_len_real != NULL_ARG) {
		acp_pkg = kmemdup(cmd->data + offset,
				  cmd->acp_pkg_len_real, GFP_KERNEL);
		if (!acp_pkg) {
			pr_err("failed to duplicate acp_pkg\n");
			status = -ENOMEM;
			goto prepare_resp;
		}
		offset += cmd->acp_pkg_len_real;
	}

	if (cmd->init_param_len_real != NULL_ARG) {
		init_params = kmemdup(cmd->data + offset,
				      cmd->init_param_len_real,
				      GFP_KERNEL);
		if (!init_params) {
			pr_err("failed to duplicate init_params\n");
			status = -ENOMEM;
			goto prepare_resp;
		}
		offset += cmd->init_param_len_real;
	}

	print_input_create_session(cmd, app_id, acp_pkg, init_params);

	status = dal_create_session(cmd->is_session_handle_ptr ?
				    &handle : NULL, app_id, acp_pkg,
				    cmd->acp_pkg_len_to_kdi,
				    init_params,
				    cmd->init_param_len_to_kdi);
	pr_debug("dal_create_session return:%d\n", status);

prepare_resp:
	mutex_lock(&tdata->resp_lock);
	dal_test_result_set(tdata, &handle, sizeof(handle));
	dal_test_result_append(tdata, &status, sizeof(status));
	mutex_unlock(&tdata->resp_lock);

	kfree(app_id);
	kfree(acp_pkg);
	kfree(init_params);

	return status;
}

static s32
dal_test_set_remove_exclusive_access(int set_access,
				     struct ta_access_set_remove_cmd *request,
				     struct ta_access_set_remove_resp *response)
{
	char *app_id = NULL;
	s32 status = 0;
	uuid_be app_uuid;

	if (request->app_id_len != NULL_ARG) {
		app_id = kmemdup(request->data,
				 request->app_id_len, GFP_KERNEL);
		if (!app_id) {
			pr_err("failed to duplicate app_id\n");
			status = -ENOMEM;
			goto out;
		}
	}

	if (dal_uuid_be_to_bin(app_id, &app_uuid)) {
		status = DAL_KDI_STATUS_INVALID_PARAMS;
		goto out;
	}

	if (set_access)
		status = dal_set_ta_exclusive_access(app_uuid);
	else
		status = dal_unset_ta_exclusive_access(app_uuid);
out:
	kfree(app_id);

	response->status = status;
	return status;
}

static void dal_test_kdi_command(struct dal_test_data *test_data)
{
	struct kdi_test_command *cmd;
	s32 status;

	cmd = (struct kdi_test_command *)test_data->cmd_data;

	switch (cmd->cmd_id) {
	case KDI_SESSION_CREATE: {
		pr_debug("KDI_CREATE_SESSION[%d]\n", cmd->cmd_id);

		status = dal_test_create_session(cmd, test_data);
		break;
	}

	case KDI_SESSION_CLOSE: {
		struct session_close_cmd *close_session;

		close_session = (struct session_close_cmd *)cmd->data;

		pr_debug("KDI_CLOSE_SESSION[%d]\n", cmd->cmd_id);

		status = dal_close_session(close_session->session_handle);

		mutex_lock(&test_data->resp_lock);
		dal_test_result_set(test_data, &status, sizeof(status));
		mutex_unlock(&test_data->resp_lock);
		break;
	}

	case KDI_SEND_AND_RCV: {
		pr_debug("KDI_SEND_AND_RCV[%d]\n", cmd->cmd_id);
		status = dal_test_send_and_recv(cmd, test_data);
		break;
	}

	case KDI_VERSION_GET_INFO: {
		struct dal_version_info version_info;
		struct version_get_info_cmd *get_version_info;

		pr_debug("KDI_GET_VERSION_INFO[%d]\n", cmd->cmd_id);

		get_version_info = (struct version_get_info_cmd *)cmd->data;
		status = dal_get_version_info(get_version_info->is_version_ptr ?
					      &version_info : NULL);

		mutex_lock(&test_data->resp_lock);
		dal_test_result_set(test_data, &version_info,
				    sizeof(version_info));
		dal_test_result_append(test_data, &status, sizeof(status));
		mutex_unlock(&test_data->resp_lock);
		break;
	}

	case KDI_EXCLUSIVE_ACCESS_SET:
	case KDI_EXCLUSIVE_ACCESS_REMOVE: {
		struct ta_access_set_remove_cmd *exclusive_access_req;
		struct ta_access_set_remove_resp exclusive_access_resp;

		pr_debug("KDI_SET_EXCLUSIVE_ACCESS or KDI_REMOVE_EXCLUSIVE_ACCESS[%d]\n",
			 cmd->cmd_id);

		exclusive_access_req =
			(struct ta_access_set_remove_cmd *)cmd->data;

		status = dal_test_set_remove_exclusive_access(
				(cmd->cmd_id == KDI_EXCLUSIVE_ACCESS_SET),
				exclusive_access_req, &exclusive_access_resp);

		mutex_lock(&test_data->resp_lock);
		dal_test_result_set(test_data, &exclusive_access_resp,
				    sizeof(exclusive_access_resp));
		mutex_unlock(&test_data->resp_lock);
		break;
	}

	default:
		pr_debug("unknown command %d\n", cmd->cmd_id);
		status = DAL_KDI_STATUS_INVALID_PARAMS;
		mutex_lock(&test_data->resp_lock);
		dal_test_result_set(test_data, &status, sizeof(status));
		mutex_unlock(&test_data->resp_lock);
	}
}

static ssize_t dal_test_read(struct file *filp, char __user *buff, size_t count,
			     loff_t *offp)
{
	struct dal_test_data *test_data = filp->private_data;
	int ret;

	mutex_lock(&test_data->resp_lock);

	if (test_data->resp_data_size > count) {
		ret = -EMSGSIZE;
		goto unlock;
	}

	pr_debug("copying %d bytes to userspace\n", test_data->resp_data_size);
	if (copy_to_user(buff, test_data->resp_data,
			 test_data->resp_data_size)) {
		pr_debug("copy_to_user failed\n");
		ret = -EFAULT;
		goto unlock;
	}
	ret = test_data->resp_data_size;

unlock:
	mutex_unlock(&test_data->resp_lock);

	return ret;
}

static ssize_t dal_test_write(struct file *filp, const char __user *buff,
			      size_t count, loff_t *offp)
{
	struct dal_test_data *test_data = filp->private_data;
	int status;

	if (count > MAX_DATA_SIZE)
		return -EMSGSIZE;

	mutex_lock(&test_data->cmd_lock);

	status = copy_from_user(test_data->cmd_data, buff, count);
	if (status < 0) {
		mutex_unlock(&test_data->cmd_lock);
		pr_debug("copy_from_user failed with status = %d\n", status);
		return status;
	}

	test_data->cmd_data_size = count;
	pr_debug("write %zu bytes\n", count);

	dal_test_kdi_command(test_data);

	mutex_unlock(&test_data->cmd_lock);

	return count;
}

static int dal_test_open(struct inode *inode, struct file *filp)
{
	struct dal_test_data *test_data;
	int ret = 0;

	/* single open */
	if (test_and_set_bit(KDI_TEST_OPENED, &kdi_test_status))
		return -EBUSY;

	test_data = kzalloc(sizeof(*test_data), GFP_KERNEL);
	if (!test_data) {
		ret = -ENOMEM;
		goto err_clear_bit;
	}

	test_data->cmd_data = kzalloc(MAX_DATA_SIZE, GFP_KERNEL);
	test_data->resp_data = kzalloc(MAX_DATA_SIZE, GFP_KERNEL);
	if (!test_data->cmd_data || !test_data->resp_data) {
		ret = -ENOMEM;
		goto err_free;
	}

	mutex_init(&test_data->cmd_lock);
	mutex_init(&test_data->resp_lock);

	ret = dal_test_load_kdi();
	if (ret)
		goto err_free;

	filp->private_data = test_data;

	return nonseekable_open(inode, filp);

err_free:
	kfree(test_data);
	kfree(test_data->cmd_data);
	kfree(test_data->resp_data);

err_clear_bit:
	clear_bit(KDI_TEST_OPENED, &kdi_test_status);

	return ret;
}

static int dal_test_release(struct inode *inode, struct file *filp)
{
	struct dal_test_data *test_data = filp->private_data;

	dal_test_unload_kdi();

	if (test_data) {
		kfree(test_data->cmd_data);
		kfree(test_data->resp_data);
		kfree(test_data);
	}

	clear_bit(KDI_TEST_OPENED, &kdi_test_status);

	filp->private_data = NULL;

	return 0;
}

static const struct file_operations kdi_test_fops = {
	.owner    = THIS_MODULE,
	.open     = dal_test_open,
	.release  = dal_test_release,
	.read     = dal_test_read,
	.write    = dal_test_write,
	.llseek   = no_llseek,
};

static void __exit dal_test_exit(void)
{
	pr_info("Test KDI shutdown\n");

	cdev_del(&cdev);
	device_destroy(cl, dal_test_devt);
	class_destroy(cl);
	unregister_chrdev_region(dal_test_devt, 1);
}

static int __init dal_test_init(void)
{
	char cdev_name[MAX_CDEV_NAME_LEN];
	struct device *dev_ret;
	int ret;

	pr_info("Test KDI init\n");

	snprintf(cdev_name, MAX_CDEV_NAME_LEN, "kdi_test%d", id);
	ret = alloc_chrdev_region(&dal_test_devt, 0, 1, cdev_name);
	if (ret)
		return ret;

	cl = class_create(THIS_MODULE, cdev_name);
	if (IS_ERR(cl)) {
		pr_err("couldn't create class\n");
		ret = PTR_ERR(cl);
		goto err_unregister_cdev;
	}

	dev_ret = device_create(cl, NULL, dal_test_devt, NULL, cdev_name);
	if (IS_ERR(dev_ret)) {
		pr_err("couldn't create device\n");
		ret = PTR_ERR(dev_ret);
		goto err_class_destroy;
	}

	cdev_init(&cdev, &kdi_test_fops);
	cdev.owner = THIS_MODULE;
	ret = cdev_add(&cdev, dal_test_devt, 1);
	if (ret) {
		pr_err("failed to add kdi_test cdev\n");
		goto err_device_destroy;
	}

	return 0;

err_device_destroy:
	device_destroy(cl, dal_test_devt);
err_class_destroy:
	class_destroy(cl);
err_unregister_cdev:
	unregister_chrdev_region(dal_test_devt, 1);

	return ret;
}

module_init(dal_test_init);
module_exit(dal_test_exit);

MODULE_AUTHOR("Intel Corporation");
MODULE_DESCRIPTION("Intel(R) DAL test");
MODULE_LICENSE("GPL v2");
