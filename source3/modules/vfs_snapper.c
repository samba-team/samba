/*
 * Module for snapshot IO using snapper
 *
 * Copyright (C) David Disseldorp 2012-2014
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <dbus/dbus.h>
#include <linux/ioctl.h>
#include <sys/ioctl.h>
#include <dirent.h>
#include <libgen.h>
#include "includes.h"
#include "include/ntioctl.h"
#include "system/filesys.h"
#include "smbd/smbd.h"
#include "lib/util/tevent_ntstatus.h"

#define SNAPPER_SIG_LIST_SNAPS_RSP "a(uquxussa{ss})"
#define SNAPPER_SIG_LIST_CONFS_RSP "a(ssa{ss})"
#define SNAPPER_SIG_STRING_DICT "{ss}"

struct snapper_dict {
	char *key;
	char *val;
};

struct snapper_snap {
	uint32_t id;
	uint16_t type;
	uint32_t pre_id;
	int64_t time;
	uint32_t creator_uid;
	char *desc;
	char *cleanup;
	uint32_t num_user_data;
	struct snapper_dict *user_data;
};

struct snapper_conf {
	char *name;
	char *mnt;
	uint32_t num_attrs;
	struct snapper_dict *attrs;
};

static const struct {
	const char *snapper_err_str;
	NTSTATUS status;
} snapper_err_map[] = {
	{ "error.no_permissions", NT_STATUS_ACCESS_DENIED },
};

static NTSTATUS snapper_err_ntstatus_map(const char *snapper_err_str)
{
	int i;

	if (snapper_err_str == NULL) {
		return NT_STATUS_UNSUCCESSFUL;
	}
	for (i = 0; i < ARRAY_SIZE(snapper_err_map); i++) {
		if (!strcmp(snapper_err_map[i].snapper_err_str,
			    snapper_err_str)) {
			return snapper_err_map[i].status;
		}
	}
	DEBUG(2, ("no explicit mapping for dbus error: %s\n", snapper_err_str));

	return NT_STATUS_UNSUCCESSFUL;
}

static DBusConnection *snapper_dbus_conn_create(void)
{
	DBusError err;
	DBusConnection *dconn;

	dbus_error_init(&err);

	/*
	 * Always create a new DBus connection, to ensure snapperd detects the
	 * correct client [E]UID. With dbus_bus_get() it does not!
	 */
	dconn = dbus_bus_get_private(DBUS_BUS_SYSTEM, &err);
	if (dbus_error_is_set(&err)) {
		DEBUG(0, ("dbus connection error: %s\n", err.message));
		dbus_error_free(&err);
	}
	if (dconn == NULL) {
		return NULL;
	}

	/* dbus_bus_get_private() sets exit-on-disconnect by default, undo it */
	dbus_connection_set_exit_on_disconnect(dconn, false);

	return dconn;
}

static void snapper_dbus_conn_destroy(DBusConnection *dconn)
{
	if (dconn == NULL) {
		DEBUG(2, ("attempt to destroy NULL dbus connection\n"));
		return;
	}

	dbus_connection_close(dconn);
	dbus_connection_unref(dconn);
}

/*
 * send the message @send_msg over the dbus and wait for a response, return the
 * responsee via @recv_msg_out.
 * @send_msg is not freed, dbus_message_unref() must be handled by the caller.
 */
static NTSTATUS snapper_dbus_msg_xchng(DBusConnection *dconn,
				       DBusMessage *send_msg,
				       DBusMessage **recv_msg_out)
{
	DBusPendingCall *pending;
	DBusMessage *recv_msg;

	/* send message and get a handle for a reply */
	if (!dbus_connection_send_with_reply(dconn, send_msg, &pending, -1)) {
		return NT_STATUS_NO_MEMORY;
	}
	if (NULL == pending) {
		DEBUG(0, ("dbus msg send failed\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	dbus_connection_flush(dconn);

	/* block until we receive a reply */
	dbus_pending_call_block(pending);

	/* get the reply message */
	recv_msg = dbus_pending_call_steal_reply(pending);
	if (recv_msg == NULL) {
		DEBUG(0, ("Reply Null\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}
	/* free the pending message handle */
	dbus_pending_call_unref(pending);
	*recv_msg_out = recv_msg;

	return NT_STATUS_OK;
}

static NTSTATUS snapper_type_check(DBusMessageIter *iter,
				   int expected_type)
{
	int type = dbus_message_iter_get_arg_type(iter);
	if (type != expected_type) {
		DEBUG(0, ("got type %d, expecting %d\n",
			type, expected_type));
		return NT_STATUS_INVALID_PARAMETER;
	}

	return NT_STATUS_OK;
}

static NTSTATUS snapper_type_check_get(DBusMessageIter *iter,
				       int expected_type,
				       void *val)
{
	NTSTATUS status;
	status = snapper_type_check(iter, expected_type);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	dbus_message_iter_get_basic(iter, val);

	return NT_STATUS_OK;
}

static NTSTATUS snapper_dict_unpack(DBusMessageIter *iter,
				    struct snapper_dict *dict_out)

{
	NTSTATUS status;
	DBusMessageIter dct_iter;

	status = snapper_type_check(iter, DBUS_TYPE_DICT_ENTRY);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	dbus_message_iter_recurse(iter, &dct_iter);

	status = snapper_type_check_get(&dct_iter, DBUS_TYPE_STRING,
					&dict_out->key);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	dbus_message_iter_next(&dct_iter);
	status = snapper_type_check_get(&dct_iter, DBUS_TYPE_STRING,
					&dict_out->val);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}

static void snapper_dict_array_print(uint32_t num_dicts,
				     struct snapper_dict *dicts)
{
	int i;

	for (i = 0; i < num_dicts; i++) {
		DEBUG(10, ("dict (key: %s, val: %s)\n",
			   dicts[i].key, dicts[i].val));
	}
}

static NTSTATUS snapper_dict_array_unpack(TALLOC_CTX *mem_ctx,
					  DBusMessageIter *iter,
					  uint32_t *num_dicts_out,
					  struct snapper_dict **dicts_out)
{
	NTSTATUS status;
	DBusMessageIter array_iter;
	uint32_t num_dicts;
	struct snapper_dict *dicts = NULL;

	status = snapper_type_check(iter, DBUS_TYPE_ARRAY);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	dbus_message_iter_recurse(iter, &array_iter);

	num_dicts = 0;
	while (dbus_message_iter_get_arg_type(&array_iter)
							!= DBUS_TYPE_INVALID) {
		num_dicts++;
		dicts = talloc_realloc(mem_ctx, dicts, struct snapper_dict,
				       num_dicts);
		if (dicts == NULL)
			abort();

		status = snapper_dict_unpack(&array_iter,
					     &dicts[num_dicts - 1]);
		if (!NT_STATUS_IS_OK(status)) {
			talloc_free(dicts);
			return status;
		}
		dbus_message_iter_next(&array_iter);
	}

	*num_dicts_out = num_dicts;
	*dicts_out = dicts;

	return NT_STATUS_OK;
}

static NTSTATUS snapper_list_confs_pack(DBusMessage **req_msg_out)
{
	DBusMessage *msg;

	msg = dbus_message_new_method_call("org.opensuse.Snapper",
					   "/org/opensuse/Snapper",
					   "org.opensuse.Snapper",
					   "ListConfigs");
	if (msg == NULL) {
		DEBUG(0, ("null msg\n"));
		return NT_STATUS_NO_MEMORY;
	}

	/* no arguments to append */
	*req_msg_out = msg;

	return NT_STATUS_OK;
}

static NTSTATUS snapper_conf_unpack(TALLOC_CTX *mem_ctx,
				    DBusMessageIter *iter,
				    struct snapper_conf *conf_out)
{
	NTSTATUS status;
	DBusMessageIter st_iter;

	status = snapper_type_check(iter, DBUS_TYPE_STRUCT);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	dbus_message_iter_recurse(iter, &st_iter);

	status = snapper_type_check_get(&st_iter, DBUS_TYPE_STRING,
					&conf_out->name);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	dbus_message_iter_next(&st_iter);
	status = snapper_type_check_get(&st_iter, DBUS_TYPE_STRING,
					&conf_out->mnt);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	dbus_message_iter_next(&st_iter);
	status = snapper_dict_array_unpack(mem_ctx, &st_iter,
					   &conf_out->num_attrs,
					   &conf_out->attrs);

	return status;
}

static void snapper_conf_array_free(int32_t num_confs,
				    struct snapper_conf *confs)
{
	int i;

	for (i = 0; i < num_confs; i++) {
		talloc_free(confs[i].attrs);
	}
	talloc_free(confs);
}

static struct snapper_conf *snapper_conf_array_base_find(int32_t num_confs,
						struct snapper_conf *confs,
							 const char *base)
{
	int i;

	for (i = 0; i < num_confs; i++) {
		if (strcmp(confs[i].mnt, base) == 0) {
			DEBUG(5, ("found snapper conf %s for path %s\n",
				  confs[i].name, base));
			return &confs[i];
		}
	}
	DEBUG(5, ("config for base %s not found\n", base));

	return NULL;
}

static void snapper_conf_array_print(int32_t num_confs,
				     struct snapper_conf *confs)
{
	int i;

	for (i = 0; i < num_confs; i++) {
		DEBUG(10, ("name: %s, mnt: %s\n",
			   confs[i].name, confs[i].mnt));
		snapper_dict_array_print(confs[i].num_attrs, confs[i].attrs);
	}
}

static NTSTATUS snapper_conf_array_unpack(TALLOC_CTX *mem_ctx,
					  DBusMessageIter *iter,
					  uint32_t *num_confs_out,
					  struct snapper_conf **confs_out)
{
	uint32_t num_confs;
	NTSTATUS status;
	struct snapper_conf *confs = NULL;
	DBusMessageIter array_iter;


	status = snapper_type_check(iter, DBUS_TYPE_ARRAY);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	dbus_message_iter_recurse(iter, &array_iter);

	num_confs = 0;
	while (dbus_message_iter_get_arg_type(&array_iter)
							!= DBUS_TYPE_INVALID) {
		num_confs++;
		confs = talloc_realloc(mem_ctx, confs, struct snapper_conf,
				       num_confs);
		if (confs == NULL)
			abort();

		status = snapper_conf_unpack(mem_ctx, &array_iter,
					     &confs[num_confs - 1]);
		if (!NT_STATUS_IS_OK(status)) {
			talloc_free(confs);
			return status;
		}
		dbus_message_iter_next(&array_iter);
	}

	*num_confs_out = num_confs;
	*confs_out = confs;

	return NT_STATUS_OK;
}

static NTSTATUS snapper_list_confs_unpack(TALLOC_CTX *mem_ctx,
					  DBusConnection *dconn,
					  DBusMessage *rsp_msg,
					  uint32_t *num_confs_out,
					  struct snapper_conf **confs_out)
{
	NTSTATUS status;
	DBusMessageIter iter;
	int msg_type;
	uint32_t num_confs;
	struct snapper_conf *confs;
	const char *sig;

	msg_type = dbus_message_get_type(rsp_msg);
	if (msg_type == DBUS_MESSAGE_TYPE_ERROR) {
		const char *err_str = dbus_message_get_error_name(rsp_msg);
		DEBUG(0, ("list_confs error response: %s\n", err_str));
		return snapper_err_ntstatus_map(err_str);
	}

	if (msg_type != DBUS_MESSAGE_TYPE_METHOD_RETURN) {
		DEBUG(0, ("unexpected list_confs ret type: %d\n",
			  msg_type));
		return NT_STATUS_INVALID_PARAMETER;
	}

	sig = dbus_message_get_signature(rsp_msg);
	if ((sig == NULL)
	 || (strcmp(sig, SNAPPER_SIG_LIST_CONFS_RSP) != 0)) {
		DEBUG(0, ("bad list confs response sig: %s, expected: %s\n",
			  (sig ? sig : "NULL"), SNAPPER_SIG_LIST_CONFS_RSP));
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!dbus_message_iter_init(rsp_msg, &iter)) {
		/* FIXME return empty? */
		DEBUG(0, ("Message has no arguments!\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	status = snapper_conf_array_unpack(mem_ctx, &iter, &num_confs, &confs);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("failed to unpack conf array\n"));
		return status;
	}

	snapper_conf_array_print(num_confs, confs);

	*num_confs_out = num_confs;
	*confs_out = confs;

	return NT_STATUS_OK;
}

static NTSTATUS snapper_list_snaps_pack(char *snapper_conf,
					DBusMessage **req_msg_out)
{
	DBusMessage *msg;
	DBusMessageIter args;

	msg = dbus_message_new_method_call("org.opensuse.Snapper", /* target for the method call */
					   "/org/opensuse/Snapper", /* object to call on */
					   "org.opensuse.Snapper", /* interface to call on */
					   "ListSnapshots"); /* method name */
	if (msg == NULL) {
		DEBUG(0, ("failed to create list snaps message\n"));
		return NT_STATUS_NO_MEMORY;
	}

	/* append arguments */
	dbus_message_iter_init_append(msg, &args);
	if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING,
					    &snapper_conf)) {
		return NT_STATUS_NO_MEMORY;
	}

	*req_msg_out = msg;

	return NT_STATUS_OK;
}

static NTSTATUS snapper_snap_struct_unpack(TALLOC_CTX *mem_ctx,
					   DBusMessageIter *iter,
					   struct snapper_snap *snap_out)
{
	NTSTATUS status;
	DBusMessageIter st_iter;

	status = snapper_type_check(iter, DBUS_TYPE_STRUCT);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	dbus_message_iter_recurse(iter, &st_iter);

	status = snapper_type_check_get(&st_iter, DBUS_TYPE_UINT32,
					&snap_out->id);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	dbus_message_iter_next(&st_iter);
	status = snapper_type_check_get(&st_iter, DBUS_TYPE_UINT16,
					&snap_out->type);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	dbus_message_iter_next(&st_iter);
	status = snapper_type_check_get(&st_iter, DBUS_TYPE_UINT32,
					&snap_out->pre_id);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	dbus_message_iter_next(&st_iter);
	status = snapper_type_check_get(&st_iter, DBUS_TYPE_INT64,
					&snap_out->time);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	dbus_message_iter_next(&st_iter);
	status = snapper_type_check_get(&st_iter, DBUS_TYPE_UINT32,
					&snap_out->creator_uid);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	dbus_message_iter_next(&st_iter);
	status = snapper_type_check_get(&st_iter, DBUS_TYPE_STRING,
					&snap_out->desc);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	dbus_message_iter_next(&st_iter);
	status = snapper_type_check_get(&st_iter, DBUS_TYPE_STRING,
					&snap_out->cleanup);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	dbus_message_iter_next(&st_iter);
	status = snapper_dict_array_unpack(mem_ctx, &st_iter,
					   &snap_out->num_user_data,
					   &snap_out->user_data);

	return status;
}

static void snapper_snap_array_free(int32_t num_snaps,
				    struct snapper_snap *snaps)
{
	int i;

	for (i = 0; i < num_snaps; i++) {
		talloc_free(snaps[i].user_data);
	}
	talloc_free(snaps);
}

static void snapper_snap_array_print(int32_t num_snaps,
				     struct snapper_snap *snaps)
{
	int i;

	for (i = 0; i < num_snaps; i++) {
		DEBUG(10, ("id: %u, "
			   "type: %u, "
			   "pre_id: %u, "
			   "time: %ld, "
			   "creator_uid: %u, "
			   "desc: %s, "
			   "cleanup: %s\n",
			   (unsigned int)snaps[i].id,
			   (unsigned int)snaps[i].type,
			   (unsigned int)snaps[i].pre_id,
			   (long int)snaps[i].time,
			   (unsigned int)snaps[i].creator_uid,
			   snaps[i].desc,
			   snaps[i].cleanup));
		snapper_dict_array_print(snaps[i].num_user_data,
					 snaps[i].user_data);
	}
}

static NTSTATUS snapper_snap_array_unpack(TALLOC_CTX *mem_ctx,
					  DBusMessageIter *iter,
					  uint32_t *num_snaps_out,
					  struct snapper_snap **snaps_out)
{
	uint32_t num_snaps;
	NTSTATUS status;
	struct snapper_snap *snaps = NULL;
	DBusMessageIter array_iter;


	status = snapper_type_check(iter, DBUS_TYPE_ARRAY);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	dbus_message_iter_recurse(iter, &array_iter);

	num_snaps = 0;
	while (dbus_message_iter_get_arg_type(&array_iter)
							!= DBUS_TYPE_INVALID) {
		num_snaps++;
		snaps = talloc_realloc(mem_ctx, snaps, struct snapper_snap,
				       num_snaps);
		if (snaps == NULL)
			abort();

		status = snapper_snap_struct_unpack(mem_ctx, &array_iter,
						    &snaps[num_snaps - 1]);
		if (!NT_STATUS_IS_OK(status)) {
			talloc_free(snaps);
			return status;
		}
		dbus_message_iter_next(&array_iter);
	}

	*num_snaps_out = num_snaps;
	*snaps_out = snaps;

	return NT_STATUS_OK;
}

static NTSTATUS snapper_list_snaps_unpack(TALLOC_CTX *mem_ctx,
					  DBusMessage *rsp_msg,
					  uint32_t *num_snaps_out,
					  struct snapper_snap **snaps_out)
{
	NTSTATUS status;
	DBusMessageIter iter;
	int msg_type;
	uint32_t num_snaps;
	struct snapper_snap *snaps;
	const char *sig;

	msg_type = dbus_message_get_type(rsp_msg);
	if (msg_type == DBUS_MESSAGE_TYPE_ERROR) {
		const char *err_str = dbus_message_get_error_name(rsp_msg);
		DEBUG(0, ("list_snaps error response: %s\n", err_str));
		return snapper_err_ntstatus_map(err_str);
	}

	if (msg_type != DBUS_MESSAGE_TYPE_METHOD_RETURN) {
		DEBUG(0,("unexpected list_snaps ret type: %d\n",
			 msg_type));
		return NT_STATUS_INVALID_PARAMETER;
	}

	sig = dbus_message_get_signature(rsp_msg);
	if ((sig == NULL)
	 || (strcmp(sig, SNAPPER_SIG_LIST_SNAPS_RSP) != 0)) {
		DEBUG(0, ("bad list snaps response sig: %s, "
			  "expected: %s\n",
			  (sig ? sig : "NULL"),
			  SNAPPER_SIG_LIST_SNAPS_RSP));
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* read the parameters */
	if (!dbus_message_iter_init(rsp_msg, &iter)) {
		DEBUG(0, ("response has no arguments!\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	status = snapper_snap_array_unpack(mem_ctx, &iter, &num_snaps, &snaps);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("failed to unpack snap array\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	snapper_snap_array_print(num_snaps, snaps);

	*num_snaps_out = num_snaps;
	*snaps_out = snaps;

	return NT_STATUS_OK;
}

static NTSTATUS snapper_list_snaps_at_time_pack(const char *snapper_conf,
						time_t time_lower,
						time_t time_upper,
						DBusMessage **req_msg_out)
{
	DBusMessage *msg;
	DBusMessageIter args;

	msg = dbus_message_new_method_call("org.opensuse.Snapper",
					   "/org/opensuse/Snapper",
					   "org.opensuse.Snapper",
					   "ListSnapshotsAtTime");
	if (msg == NULL) {
		DEBUG(0, ("failed to create list snaps message\n"));
		return NT_STATUS_NO_MEMORY;
	}

	dbus_message_iter_init_append(msg, &args);
	if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING,
					    &snapper_conf)) {
		return NT_STATUS_NO_MEMORY;
	}

	if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_INT64,
					    &time_lower)) {
		return NT_STATUS_NO_MEMORY;
	}

	if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_INT64,
					    &time_upper)) {
		return NT_STATUS_NO_MEMORY;
	}

	*req_msg_out = msg;

	return NT_STATUS_OK;
}
/* no snapper_list_snaps_at_time_unpack, use snapper_list_snaps_unpack */

/*
 * Determine the snapper snapshot path given an id and base.
 * Ideally this should be determined via a lookup.
 */
static NTSTATUS snapper_snap_id_to_path(TALLOC_CTX *mem_ctx,
					const char *base_path,
					uint32_t snap_id,
					char **snap_path_out)
{
	char *snap_path;

	snap_path = talloc_asprintf(mem_ctx, "%s/.snapshots/%u/snapshot",
				    base_path, snap_id);
	if (snap_path == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	*snap_path_out = snap_path;
	return NT_STATUS_OK;
}

static NTSTATUS snapper_get_conf_call(TALLOC_CTX *mem_ctx,
				      DBusConnection *dconn,
				      const char *path,
				      char **conf_name_out,
				      char **base_path_out)
{
	NTSTATUS status;
	DBusMessage *req_msg;
	DBusMessage *rsp_msg;
	uint32_t num_confs = 0;
	struct snapper_conf *confs = NULL;
	struct snapper_conf *conf;
	char *conf_name;
	char *base_path;

	status = snapper_list_confs_pack(&req_msg);
	if (!NT_STATUS_IS_OK(status)) {
		goto err_out;
	}

	status = snapper_dbus_msg_xchng(dconn, req_msg, &rsp_msg);
	if (!NT_STATUS_IS_OK(status)) {
		goto err_req_free;
	}

	status = snapper_list_confs_unpack(mem_ctx, dconn, rsp_msg,
					   &num_confs, &confs);
	if (!NT_STATUS_IS_OK(status)) {
		goto err_rsp_free;
	}

	/*
	 * for now we only support shares where the path directly corresponds
	 * to a snapper configuration.
	 */
	conf = snapper_conf_array_base_find(num_confs, confs,
					    path);
	if (conf == NULL) {
		status = NT_STATUS_NOT_SUPPORTED;
		goto err_array_free;
	}

	conf_name = talloc_strdup(mem_ctx, conf->name);
	if (conf_name == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto err_array_free;
	}
	base_path = talloc_strdup(mem_ctx, conf->mnt);
	if (base_path == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto err_conf_name_free;
	}

	snapper_conf_array_free(num_confs, confs);
	dbus_message_unref(rsp_msg);
	dbus_message_unref(req_msg);

	*conf_name_out = conf_name;
	*base_path_out = base_path;

	return NT_STATUS_OK;

err_conf_name_free:
	talloc_free(conf_name);
err_array_free:
	snapper_conf_array_free(num_confs, confs);
err_rsp_free:
	dbus_message_unref(rsp_msg);
err_req_free:
	dbus_message_unref(req_msg);
err_out:
	return status;
}

static struct vfs_fn_pointers snapper_fns = {
};

NTSTATUS vfs_snapper_init(void);
NTSTATUS vfs_snapper_init(void)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
				"snapper", &snapper_fns);
}
