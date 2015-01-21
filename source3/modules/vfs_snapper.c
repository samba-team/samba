/*
 * Module for snapshot IO using snapper
 *
 * Copyright (C) David Disseldorp 2012-2014
 *
 * Portions taken from vfs_shadow_copy2.c:
 * Copyright (C) Andrew Tridgell   2007
 * Copyright (C) Ed Plese          2009
 * Copyright (C) Volker Lendecke   2011
 * Copyright (C) Christian Ambach  2011
 * Copyright (C) Michael Adam      2013
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
#ifdef HAVE_LINUX_IOCTL_H
#include <linux/ioctl.h>
#endif
#include <sys/ioctl.h>
#include <dirent.h>
#include <libgen.h>
#include "includes.h"
#include "include/ntioctl.h"
#include "include/smb.h"
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

/*
 * Strings are UTF-8. Other characters must be encoded hexadecimal as "\x??".
 * As a consequence "\" must be encoded as "\\".
 */
static NTSTATUS snapper_dbus_str_encode(TALLOC_CTX *mem_ctx, const char *in_str,
					char **_out_str)
{
	size_t in_len;
	char *out_str;
	int i;
	int out_off;
	int out_len;

	if (in_str == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	in_len = strlen(in_str);

	/* output can be max 4 times the length of @in_str, +1 for terminator */
	out_len = (in_len * 4) + 1;

	out_str = talloc_array(mem_ctx, char, out_len);
	if (out_str == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	out_off = 0;
	for (i = 0; i < in_len; i++) {
		size_t pushed;

		if (in_str[i] == '\\') {
			pushed = snprintf(out_str + out_off, out_len - out_off,
					  "\\\\");
		} else if ((unsigned char)in_str[i] > 127) {
			pushed = snprintf(out_str + out_off, out_len - out_off,
					  "\\x%02x", (unsigned char)in_str[i]);
		} else {
			/* regular character */
			*(out_str + out_off) = in_str[i];
			pushed = sizeof(char);
		}
		if (pushed >= out_len - out_off) {
			/* truncated, should never happen */
			talloc_free(out_str);
			return NT_STATUS_INTERNAL_ERROR;
		}
		out_off += pushed;
	}

	*(out_str + out_off) = '\0';
	*_out_str = out_str;

	return NT_STATUS_OK;
}

static NTSTATUS snapper_dbus_str_decode(TALLOC_CTX *mem_ctx, const char *in_str,
					char **_out_str)
{
	size_t in_len;
	char *out_str;
	int i;
	int out_off;
	int out_len;

	if (in_str == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	in_len = strlen(in_str);

	/* output cannot be larger than input, +1 for terminator */
	out_len = in_len + 1;

	out_str = talloc_array(mem_ctx, char, out_len);
	if (out_str == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	out_off = 0;
	for (i = 0; i < in_len; i++) {
		int j;
		char hex_buf[3];
		unsigned int non_ascii_byte;

		if (in_str[i] != '\\') {
			out_str[out_off] = in_str[i];
			out_off++;
			continue;
		}

		i++;
		if (in_str[i] == '\\') {
			out_str[out_off] = '\\';
			out_off++;
			continue;
		} else if (in_str[i] != 'x') {
			goto err_invalid_src_encoding;
		}

		/* non-ASCII, encoded as two hex chars */
		for (j = 0; j < 2; j++) {
			i++;
			if ((in_str[i] == '\0') || !isxdigit(in_str[i])) {
				goto err_invalid_src_encoding;
			}
			hex_buf[j] = in_str[i];
		}
		hex_buf[2] = '\0';

		sscanf(hex_buf, "%x", &non_ascii_byte);
		out_str[out_off] = (unsigned char)non_ascii_byte;
		out_off++;
	}

	out_str[out_off] = '\0';
	*_out_str = out_str;

	return NT_STATUS_OK;
err_invalid_src_encoding:
	DEBUG(0, ("invalid encoding %s\n", in_str));
	return NT_STATUS_INVALID_PARAMETER;
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

static NTSTATUS snapper_dict_unpack(TALLOC_CTX *mem_ctx,
				    DBusMessageIter *iter,
				    struct snapper_dict *dict_out)

{
	NTSTATUS status;
	DBusMessageIter dct_iter;
	char *key_encoded;
	char *val_encoded;

	status = snapper_type_check(iter, DBUS_TYPE_DICT_ENTRY);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	dbus_message_iter_recurse(iter, &dct_iter);

	status = snapper_type_check_get(&dct_iter, DBUS_TYPE_STRING,
					&key_encoded);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	status = snapper_dbus_str_decode(mem_ctx, key_encoded, &dict_out->key);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	dbus_message_iter_next(&dct_iter);
	status = snapper_type_check_get(&dct_iter, DBUS_TYPE_STRING,
					&val_encoded);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(dict_out->key);
		return status;
	}
	status = snapper_dbus_str_decode(mem_ctx, val_encoded, &dict_out->val);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(dict_out->key);
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

		status = snapper_dict_unpack(mem_ctx, &array_iter,
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
	char *name_encoded;
	char *mnt_encoded;

	status = snapper_type_check(iter, DBUS_TYPE_STRUCT);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	dbus_message_iter_recurse(iter, &st_iter);

	status = snapper_type_check_get(&st_iter, DBUS_TYPE_STRING,
					&name_encoded);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = snapper_dbus_str_decode(mem_ctx, name_encoded,
					 &conf_out->name);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	dbus_message_iter_next(&st_iter);
	status = snapper_type_check_get(&st_iter, DBUS_TYPE_STRING,
					&mnt_encoded);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(conf_out->name);
		return status;
	}

	status = snapper_dbus_str_decode(mem_ctx, mnt_encoded,
					 &conf_out->mnt);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(conf_out->name);
		return status;
	}

	dbus_message_iter_next(&st_iter);
	status = snapper_dict_array_unpack(mem_ctx, &st_iter,
					   &conf_out->num_attrs,
					   &conf_out->attrs);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(conf_out->mnt);
		talloc_free(conf_out->name);
		return status;
	}

	return NT_STATUS_OK;
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

		status = snapper_conf_unpack(confs, &array_iter,
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

static NTSTATUS snapper_list_snaps_pack(TALLOC_CTX *mem_ctx,
					char *snapper_conf,
					DBusMessage **req_msg_out)
{
	DBusMessage *msg;
	DBusMessageIter args;
	char *conf_encoded;
	NTSTATUS status;

	msg = dbus_message_new_method_call("org.opensuse.Snapper", /* target for the method call */
					   "/org/opensuse/Snapper", /* object to call on */
					   "org.opensuse.Snapper", /* interface to call on */
					   "ListSnapshots"); /* method name */
	if (msg == NULL) {
		DEBUG(0, ("failed to create list snaps message\n"));
		return NT_STATUS_NO_MEMORY;
	}

	status = snapper_dbus_str_encode(mem_ctx, snapper_conf, &conf_encoded);
	if (!NT_STATUS_IS_OK(status)) {
		dbus_message_unref(msg);
		return status;
	}

	/* append arguments */
	dbus_message_iter_init_append(msg, &args);
	if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING,
					    &conf_encoded)) {
		talloc_free(conf_encoded);
		dbus_message_unref(msg);
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
	char *desc_encoded;
	char *cleanup_encoded;

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
					&desc_encoded);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = snapper_dbus_str_decode(mem_ctx, desc_encoded,
					 &snap_out->desc);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	dbus_message_iter_next(&st_iter);
	status = snapper_type_check_get(&st_iter, DBUS_TYPE_STRING,
					&cleanup_encoded);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(snap_out->desc);
		return status;
	}

	status = snapper_dbus_str_decode(mem_ctx, cleanup_encoded,
					 &snap_out->cleanup);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(snap_out->desc);
		return status;
	}

	dbus_message_iter_next(&st_iter);
	status = snapper_dict_array_unpack(mem_ctx, &st_iter,
					   &snap_out->num_user_data,
					   &snap_out->user_data);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(snap_out->cleanup);
		talloc_free(snap_out->desc);
		return status;
	}

	return NT_STATUS_OK;
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

		status = snapper_snap_struct_unpack(snaps, &array_iter,
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

static NTSTATUS snapper_list_snaps_at_time_pack(TALLOC_CTX *mem_ctx,
						const char *snapper_conf,
						time_t time_lower,
						time_t time_upper,
						DBusMessage **req_msg_out)
{
	DBusMessage *msg;
	DBusMessageIter args;
	char *conf_encoded;
	NTSTATUS status;

	msg = dbus_message_new_method_call("org.opensuse.Snapper",
					   "/org/opensuse/Snapper",
					   "org.opensuse.Snapper",
					   "ListSnapshotsAtTime");
	if (msg == NULL) {
		DEBUG(0, ("failed to create list snaps message\n"));
		return NT_STATUS_NO_MEMORY;
	}

	status = snapper_dbus_str_encode(mem_ctx, snapper_conf, &conf_encoded);
	if (!NT_STATUS_IS_OK(status)) {
		dbus_message_unref(msg);
		return status;
	}

	dbus_message_iter_init_append(msg, &args);
	if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING,
					    &conf_encoded)) {
		talloc_free(conf_encoded);
		dbus_message_unref(msg);
		return NT_STATUS_NO_MEMORY;
	}

	if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_INT64,
					    &time_lower)) {
		talloc_free(conf_encoded);
		dbus_message_unref(msg);
		return NT_STATUS_NO_MEMORY;
	}

	if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_INT64,
					    &time_upper)) {
		talloc_free(conf_encoded);
		dbus_message_unref(msg);
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

	talloc_free(confs);
	dbus_message_unref(rsp_msg);
	dbus_message_unref(req_msg);

	*conf_name_out = conf_name;
	*base_path_out = base_path;

	return NT_STATUS_OK;

err_conf_name_free:
	talloc_free(conf_name);
err_array_free:
	talloc_free(confs);
err_rsp_free:
	dbus_message_unref(rsp_msg);
err_req_free:
	dbus_message_unref(req_msg);
err_out:
	return status;
}

/* sc_data used as parent talloc context for all labels */
static int snapper_get_shadow_copy_data(struct vfs_handle_struct *handle,
					struct files_struct *fsp,
					struct shadow_copy_data *sc_data,
					bool labels)
{
	DBusConnection *dconn;
	TALLOC_CTX *tmp_ctx;
	NTSTATUS status;
	char *conf_name;
	char *base_path;
	DBusMessage *req_msg;
	DBusMessage *rsp_msg;
	uint32_t num_snaps;
	struct snapper_snap *snaps;
	uint32_t i;
	uint32_t lbl_off;

	tmp_ctx = talloc_new(sc_data);
	if (tmp_ctx == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto err_out;
	}

	dconn = snapper_dbus_conn_create();
	if (dconn == NULL) {
		status = NT_STATUS_UNSUCCESSFUL;
		goto err_mem_ctx_free;
	}

	if (fsp->conn->connectpath == NULL) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto err_conn_free;
	}

	status = snapper_get_conf_call(tmp_ctx, dconn,
				       fsp->conn->connectpath,
				       &conf_name,
				       &base_path);
	if (!NT_STATUS_IS_OK(status)) {
		goto err_conn_free;
	}

	status = snapper_list_snaps_pack(tmp_ctx, conf_name, &req_msg);
	if (!NT_STATUS_IS_OK(status)) {
		goto err_conn_free;
	}

	status = snapper_dbus_msg_xchng(dconn, req_msg, &rsp_msg);
	if (!NT_STATUS_IS_OK(status)) {
		goto err_req_free;
	}

	status = snapper_list_snaps_unpack(tmp_ctx, rsp_msg,
					   &num_snaps, &snaps);
	if (!NT_STATUS_IS_OK(status)) {
		goto err_rsp_free;
	}
	/* we should always get at least one snapshot (current) */
	if (num_snaps == 0) {
		DEBUG(1, ("zero snapshots in snap list response\n"));
		status = NT_STATUS_UNSUCCESSFUL;
		goto err_rsp_free;
	}

	/* subtract 1, (current) snapshot is not returned */
	sc_data->num_volumes = num_snaps - 1;
	sc_data->labels = NULL;

	if ((labels == false) || (sc_data->num_volumes == 0)) {
		/* tokens need not be added to the labels array */
		goto done;
	}

	sc_data->labels = talloc_array(sc_data, SHADOW_COPY_LABEL,
				       sc_data->num_volumes);
	if (sc_data->labels == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto err_rsp_free;
	}

	/* start at end for decending order, do not include 0 (current) */
	lbl_off = 0;
	for (i = num_snaps - 1; i > 0; i--) {
		char *lbl = sc_data->labels[lbl_off++];
		struct tm gmt_snap_time;
		struct tm *tm_ret;
		size_t str_sz;

		tm_ret = gmtime_r((time_t *)&snaps[i].time, &gmt_snap_time);
		if (tm_ret == NULL) {
			status = NT_STATUS_UNSUCCESSFUL;
			goto err_labels_free;
		}
		str_sz = strftime(lbl, sizeof(SHADOW_COPY_LABEL),
				  "@GMT-%Y.%m.%d-%H.%M.%S", &gmt_snap_time);
		if (str_sz == 0) {
			status = NT_STATUS_UNSUCCESSFUL;
			goto err_labels_free;
		}
	}

done:
	talloc_free(tmp_ctx);
	dbus_message_unref(rsp_msg);
	dbus_message_unref(req_msg);
	snapper_dbus_conn_destroy(dconn);

	return 0;

err_labels_free:
	TALLOC_FREE(sc_data->labels);
err_rsp_free:
	dbus_message_unref(rsp_msg);
err_req_free:
	dbus_message_unref(req_msg);
err_conn_free:
	snapper_dbus_conn_destroy(dconn);
err_mem_ctx_free:
	talloc_free(tmp_ctx);
err_out:
	errno = map_errno_from_nt_status(status);
	return -1;
}

static bool snapper_gmt_strip_snapshot(TALLOC_CTX *mem_ctx,
				       struct vfs_handle_struct *handle,
				       const char *name,
				       time_t *ptimestamp,
				       char **pstripped)
{
	struct tm tm;
	time_t timestamp;
	const char *p;
	char *q;
	char *stripped;
	size_t rest_len, dst_len;

	p = strstr_m(name, "@GMT-");
	if (p == NULL) {
		goto no_snapshot;
	}
	if ((p > name) && (p[-1] != '/')) {
		goto no_snapshot;
	}
	q = strptime(p, GMT_FORMAT, &tm);
	if (q == NULL) {
		goto no_snapshot;
	}
	tm.tm_isdst = -1;
	timestamp = timegm(&tm);
	if (timestamp == (time_t)-1) {
		goto no_snapshot;
	}
	if ((p == name) && (q[0] == '\0')) {
		if (pstripped != NULL) {
			stripped = talloc_strdup(mem_ctx, "");
			if (stripped == NULL) {
				return false;
			}
			*pstripped = stripped;
		}
		*ptimestamp = timestamp;
		return true;
	}
	if (q[0] != '/') {
		goto no_snapshot;
	}
	q += 1;

	rest_len = strlen(q);
	dst_len = (p-name) + rest_len;

	if (pstripped != NULL) {
		stripped = talloc_array(mem_ctx, char, dst_len+1);
		if (stripped == NULL) {
			errno = ENOMEM;
			return false;
		}
		if (p > name) {
			memcpy(stripped, name, p-name);
		}
		if (rest_len > 0) {
			memcpy(stripped + (p-name), q, rest_len);
		}
		stripped[dst_len] = '\0';
		*pstripped = stripped;
	}
	*ptimestamp = timestamp;
	return true;
no_snapshot:
	*ptimestamp = 0;
	return true;
}

static NTSTATUS snapper_get_snap_at_time_call(TALLOC_CTX *mem_ctx,
					      DBusConnection *dconn,
					      const char *conf_name,
					      const char *base_path,
					      time_t snaptime,
					      char **snap_path_out)
{
	NTSTATUS status;
	DBusMessage *req_msg;
	DBusMessage *rsp_msg;
	uint32_t num_snaps;
	struct snapper_snap *snaps;
	char *snap_path;

	status = snapper_list_snaps_at_time_pack(mem_ctx,
						 conf_name,
						 snaptime,
						 snaptime,
						 &req_msg);
	if (!NT_STATUS_IS_OK(status)) {
		goto err_out;
	}

	status = snapper_dbus_msg_xchng(dconn, req_msg, &rsp_msg);
	if (!NT_STATUS_IS_OK(status)) {
		goto err_req_free;
	}

	status = snapper_list_snaps_unpack(mem_ctx, rsp_msg,
					   &num_snaps, &snaps);
	if (!NT_STATUS_IS_OK(status)) {
		goto err_rsp_free;
	}

	if (num_snaps == 0) {
		DEBUG(4, ("no snapshots found with time: %lu\n", snaptime));
		status = NT_STATUS_INVALID_PARAMETER;
		goto err_snap_array_free;
	} else if (num_snaps > 0) {
		DEBUG(4, ("got %u snapshots for single time %lu, using top\n",
			  num_snaps, snaptime));
	}

	status = snapper_snap_id_to_path(mem_ctx, base_path, snaps[0].id,
					 &snap_path);
	if (!NT_STATUS_IS_OK(status)) {
		goto err_snap_array_free;
	}

	*snap_path_out = snap_path;
err_snap_array_free:
	talloc_free(snaps);
err_rsp_free:
	dbus_message_unref(rsp_msg);
err_req_free:
	dbus_message_unref(req_msg);
err_out:
	return status;
}

static NTSTATUS snapper_snap_path_expand(struct connection_struct *conn,
					 TALLOC_CTX *mem_ctx,
					 time_t snap_time,
					 char **snap_dir_out)
{
	DBusConnection *dconn;
	NTSTATUS status;
	char *conf_name;
	char *base_path;
	char *snap_path;

	dconn = snapper_dbus_conn_create();
	if (dconn == NULL) {
		status = NT_STATUS_UNSUCCESSFUL;
		goto err_out;
	}

	if (conn->connectpath == NULL) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto err_conn_free;
	}

	status = snapper_get_conf_call(mem_ctx, dconn,
				       conn->connectpath,
				       &conf_name,
				       &base_path);
	if (!NT_STATUS_IS_OK(status)) {
		goto err_conn_free;
	}

	status = snapper_get_snap_at_time_call(mem_ctx, dconn,
					       conf_name, base_path, snap_time,
					       &snap_path);
	if (!NT_STATUS_IS_OK(status)) {
		goto err_conf_name_free;
	}

	/* confirm snapshot path is nested under base path */
	if (strncmp(snap_path, base_path, strlen(base_path)) != 0) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto err_snap_path_free;
	}

	talloc_free(conf_name);
	talloc_free(base_path);
	snapper_dbus_conn_destroy(dconn);
	*snap_dir_out = snap_path;

	return NT_STATUS_OK;

err_snap_path_free:
	talloc_free(snap_path);
err_conf_name_free:
	talloc_free(conf_name);
	talloc_free(base_path);
err_conn_free:
	snapper_dbus_conn_destroy(dconn);
err_out:
	return status;
}

static char *snapper_gmt_convert(TALLOC_CTX *mem_ctx,
			     struct vfs_handle_struct *handle,
			     const char *name, time_t timestamp)
{
	char *snap_path = NULL;
	char *path = NULL;
	NTSTATUS status;
	int saved_errno;

	status = snapper_snap_path_expand(handle->conn, mem_ctx, timestamp,
					  &snap_path);
	if (!NT_STATUS_IS_OK(status)) {
		errno = map_errno_from_nt_status(status);
		goto err_out;
	}

	path = talloc_asprintf(mem_ctx, "%s/%s", snap_path, name);
	if (path == NULL) {
		errno = ENOMEM;
		goto err_snap_path_free;
	}

	DEBUG(10, ("converted %s/%s @ time to %s\n",
		   handle->conn->connectpath, name, path));
	return path;

err_snap_path_free:
	saved_errno = errno;
	talloc_free(snap_path);
	errno = saved_errno;
err_out:
	return NULL;
}

static DIR *snapper_gmt_opendir(vfs_handle_struct *handle,
				const char *fname,
				const char *mask,
				uint32_t attr)
{
	time_t timestamp;
	char *stripped;
	DIR *ret;
	int saved_errno;
	char *conv;

	if (!snapper_gmt_strip_snapshot(talloc_tos(), handle, fname,
					&timestamp, &stripped)) {
		return NULL;
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_OPENDIR(handle, fname, mask, attr);
	}
	conv = snapper_gmt_convert(talloc_tos(), handle, stripped, timestamp);
	TALLOC_FREE(stripped);
	if (conv == NULL) {
		return NULL;
	}
	ret = SMB_VFS_NEXT_OPENDIR(handle, conv, mask, attr);
	saved_errno = errno;
	TALLOC_FREE(conv);
	errno = saved_errno;
	return ret;
}

static int snapper_gmt_rename(vfs_handle_struct *handle,
			      const struct smb_filename *smb_fname_src,
			      const struct smb_filename *smb_fname_dst)
{
	time_t timestamp_src, timestamp_dst;

	if (!snapper_gmt_strip_snapshot(talloc_tos(), handle,
					smb_fname_src->base_name,
					&timestamp_src, NULL)) {
		return -1;
	}
	if (!snapper_gmt_strip_snapshot(talloc_tos(), handle,
					smb_fname_dst->base_name,
					&timestamp_dst, NULL)) {
		return -1;
	}
	if (timestamp_src != 0) {
		errno = EXDEV;
		return -1;
	}
	if (timestamp_dst != 0) {
		errno = EROFS;
		return -1;
	}
	return SMB_VFS_NEXT_RENAME(handle, smb_fname_src, smb_fname_dst);
}

static int snapper_gmt_symlink(vfs_handle_struct *handle,
			       const char *oldname, const char *newname)
{
	time_t timestamp_old, timestamp_new;

	if (!snapper_gmt_strip_snapshot(talloc_tos(), handle, oldname,
					&timestamp_old, NULL)) {
		return -1;
	}
	if (!snapper_gmt_strip_snapshot(talloc_tos(), handle, newname,
					&timestamp_new, NULL)) {
		return -1;
	}
	if ((timestamp_old != 0) || (timestamp_new != 0)) {
		errno = EROFS;
		return -1;
	}
	return SMB_VFS_NEXT_SYMLINK(handle, oldname, newname);
}

static int snapper_gmt_link(vfs_handle_struct *handle,
			    const char *oldname, const char *newname)
{
	time_t timestamp_old, timestamp_new;

	if (!snapper_gmt_strip_snapshot(talloc_tos(), handle, oldname,
					&timestamp_old, NULL)) {
		return -1;
	}
	if (!snapper_gmt_strip_snapshot(talloc_tos(), handle, newname,
					&timestamp_new, NULL)) {
		return -1;
	}
	if ((timestamp_old != 0) || (timestamp_new != 0)) {
		errno = EROFS;
		return -1;
	}
	return SMB_VFS_NEXT_LINK(handle, oldname, newname);
}

static int snapper_gmt_stat(vfs_handle_struct *handle,
			    struct smb_filename *smb_fname)
{
	time_t timestamp;
	char *stripped, *tmp;
	int ret, saved_errno;

	if (!snapper_gmt_strip_snapshot(talloc_tos(), handle,
					smb_fname->base_name,
					&timestamp, &stripped)) {
		return -1;
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_STAT(handle, smb_fname);
	}

	tmp = smb_fname->base_name;
	smb_fname->base_name = snapper_gmt_convert(talloc_tos(), handle,
						   stripped, timestamp);
	TALLOC_FREE(stripped);

	if (smb_fname->base_name == NULL) {
		smb_fname->base_name = tmp;
		return -1;
	}

	ret = SMB_VFS_NEXT_STAT(handle, smb_fname);
	saved_errno = errno;

	TALLOC_FREE(smb_fname->base_name);
	smb_fname->base_name = tmp;

	errno = saved_errno;
	return ret;
}

static int snapper_gmt_lstat(vfs_handle_struct *handle,
			     struct smb_filename *smb_fname)
{
	time_t timestamp;
	char *stripped, *tmp;
	int ret, saved_errno;

	if (!snapper_gmt_strip_snapshot(talloc_tos(), handle,
					smb_fname->base_name,
					&timestamp, &stripped)) {
		return -1;
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_LSTAT(handle, smb_fname);
	}

	tmp = smb_fname->base_name;
	smb_fname->base_name = snapper_gmt_convert(talloc_tos(), handle,
						   stripped, timestamp);
	TALLOC_FREE(stripped);

	if (smb_fname->base_name == NULL) {
		smb_fname->base_name = tmp;
		return -1;
	}

	ret = SMB_VFS_NEXT_LSTAT(handle, smb_fname);
	saved_errno = errno;

	TALLOC_FREE(smb_fname->base_name);
	smb_fname->base_name = tmp;

	errno = saved_errno;
	return ret;
}

static int snapper_gmt_fstat(vfs_handle_struct *handle, files_struct *fsp,
			     SMB_STRUCT_STAT *sbuf)
{
	time_t timestamp;
	int ret;

	ret = SMB_VFS_NEXT_FSTAT(handle, fsp, sbuf);
	if (ret == -1) {
		return ret;
	}
	if (!snapper_gmt_strip_snapshot(talloc_tos(), handle,
					fsp->fsp_name->base_name,
					&timestamp, NULL)) {
		return 0;
	}
	return 0;
}

static int snapper_gmt_open(vfs_handle_struct *handle,
			    struct smb_filename *smb_fname, files_struct *fsp,
			    int flags, mode_t mode)
{
	time_t timestamp;
	char *stripped, *tmp;
	int ret, saved_errno;

	if (!snapper_gmt_strip_snapshot(talloc_tos(), handle,
					smb_fname->base_name,
					&timestamp, &stripped)) {
		return -1;
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_OPEN(handle, smb_fname, fsp, flags, mode);
	}

	tmp = smb_fname->base_name;
	smb_fname->base_name = snapper_gmt_convert(talloc_tos(), handle,
						   stripped, timestamp);
	TALLOC_FREE(stripped);

	if (smb_fname->base_name == NULL) {
		smb_fname->base_name = tmp;
		return -1;
	}

	ret = SMB_VFS_NEXT_OPEN(handle, smb_fname, fsp, flags, mode);
	saved_errno = errno;

	TALLOC_FREE(smb_fname->base_name);
	smb_fname->base_name = tmp;

	errno = saved_errno;
	return ret;
}

static int snapper_gmt_unlink(vfs_handle_struct *handle,
			      const struct smb_filename *smb_fname)
{
	time_t timestamp;
	char *stripped;
	int ret, saved_errno;
	struct smb_filename *conv;

	if (!snapper_gmt_strip_snapshot(talloc_tos(), handle,
					smb_fname->base_name,
					&timestamp, &stripped)) {
		return -1;
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_UNLINK(handle, smb_fname);
	}
	conv = cp_smb_filename(talloc_tos(), smb_fname);
	if (conv == NULL) {
		errno = ENOMEM;
		return -1;
	}
	conv->base_name = snapper_gmt_convert(conv, handle,
					      stripped, timestamp);
	TALLOC_FREE(stripped);
	if (conv->base_name == NULL) {
		return -1;
	}
	ret = SMB_VFS_NEXT_UNLINK(handle, conv);
	saved_errno = errno;
	TALLOC_FREE(conv);
	errno = saved_errno;
	return ret;
}

static int snapper_gmt_chmod(vfs_handle_struct *handle, const char *fname,
			     mode_t mode)
{
	time_t timestamp;
	char *stripped;
	int ret, saved_errno;
	char *conv;

	if (!snapper_gmt_strip_snapshot(talloc_tos(), handle, fname,
					&timestamp, &stripped)) {
		return -1;
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_CHMOD(handle, fname, mode);
	}
	conv = snapper_gmt_convert(talloc_tos(), handle, stripped, timestamp);
	TALLOC_FREE(stripped);
	if (conv == NULL) {
		return -1;
	}
	ret = SMB_VFS_NEXT_CHMOD(handle, conv, mode);
	saved_errno = errno;
	TALLOC_FREE(conv);
	errno = saved_errno;
	return ret;
}

static int snapper_gmt_chown(vfs_handle_struct *handle, const char *fname,
			     uid_t uid, gid_t gid)
{
	time_t timestamp;
	char *stripped;
	int ret, saved_errno;
	char *conv;

	if (!snapper_gmt_strip_snapshot(talloc_tos(), handle, fname,
					&timestamp, &stripped)) {
		return -1;
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_CHOWN(handle, fname, uid, gid);
	}
	conv = snapper_gmt_convert(talloc_tos(), handle, stripped, timestamp);
	TALLOC_FREE(stripped);
	if (conv == NULL) {
		return -1;
	}
	ret = SMB_VFS_NEXT_CHOWN(handle, conv, uid, gid);
	saved_errno = errno;
	TALLOC_FREE(conv);
	errno = saved_errno;
	return ret;
}

static int snapper_gmt_chdir(vfs_handle_struct *handle,
			     const char *fname)
{
	time_t timestamp;
	char *stripped;
	int ret, saved_errno;
	char *conv;

	if (!snapper_gmt_strip_snapshot(talloc_tos(), handle, fname,
					&timestamp, &stripped)) {
		return -1;
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_CHDIR(handle, fname);
	}
	conv = snapper_gmt_convert(talloc_tos(), handle, stripped, timestamp);
	TALLOC_FREE(stripped);
	if (conv == NULL) {
		return -1;
	}
	ret = SMB_VFS_NEXT_CHDIR(handle, conv);
	saved_errno = errno;
	TALLOC_FREE(conv);
	errno = saved_errno;
	return ret;
}

static int snapper_gmt_ntimes(vfs_handle_struct *handle,
			      const struct smb_filename *smb_fname,
			      struct smb_file_time *ft)
{
	time_t timestamp;
	char *stripped;
	int ret, saved_errno;
	struct smb_filename *conv;

	if (!snapper_gmt_strip_snapshot(talloc_tos(), handle,
					smb_fname->base_name,
					&timestamp, &stripped)) {
		return -1;
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_NTIMES(handle, smb_fname, ft);
	}
	conv = cp_smb_filename(talloc_tos(), smb_fname);
	if (conv == NULL) {
		errno = ENOMEM;
		return -1;
	}
	conv->base_name = snapper_gmt_convert(conv, handle,
					      stripped, timestamp);
	TALLOC_FREE(stripped);
	if (conv->base_name == NULL) {
		return -1;
	}
	ret = SMB_VFS_NEXT_NTIMES(handle, conv, ft);
	saved_errno = errno;
	TALLOC_FREE(conv);
	errno = saved_errno;
	return ret;
}

static int snapper_gmt_readlink(vfs_handle_struct *handle,
				const char *fname, char *buf, size_t bufsiz)
{
	time_t timestamp;
	char *stripped;
	int ret, saved_errno;
	char *conv;

	if (!snapper_gmt_strip_snapshot(talloc_tos(), handle, fname,
					&timestamp, &stripped)) {
		return -1;
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_READLINK(handle, fname, buf, bufsiz);
	}
	conv = snapper_gmt_convert(talloc_tos(), handle, stripped, timestamp);
	TALLOC_FREE(stripped);
	if (conv == NULL) {
		return -1;
	}
	ret = SMB_VFS_NEXT_READLINK(handle, conv, buf, bufsiz);
	saved_errno = errno;
	TALLOC_FREE(conv);
	errno = saved_errno;
	return ret;
}

static int snapper_gmt_mknod(vfs_handle_struct *handle,
			     const char *fname, mode_t mode, SMB_DEV_T dev)
{
	time_t timestamp;
	char *stripped;
	int ret, saved_errno;
	char *conv;

	if (!snapper_gmt_strip_snapshot(talloc_tos(), handle, fname,
					&timestamp, &stripped)) {
		return -1;
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_MKNOD(handle, fname, mode, dev);
	}
	conv = snapper_gmt_convert(talloc_tos(), handle, stripped, timestamp);
	TALLOC_FREE(stripped);
	if (conv == NULL) {
		return -1;
	}
	ret = SMB_VFS_NEXT_MKNOD(handle, conv, mode, dev);
	saved_errno = errno;
	TALLOC_FREE(conv);
	errno = saved_errno;
	return ret;
}

static char *snapper_gmt_realpath(vfs_handle_struct *handle,
				  const char *fname)
{
	time_t timestamp;
	char *stripped = NULL;
	char *tmp = NULL;
	char *result = NULL;
	int saved_errno;

	if (!snapper_gmt_strip_snapshot(talloc_tos(), handle, fname,
					&timestamp, &stripped)) {
		goto done;
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_REALPATH(handle, fname);
	}

	tmp = snapper_gmt_convert(talloc_tos(), handle, stripped, timestamp);
	if (tmp == NULL) {
		goto done;
	}

	result = SMB_VFS_NEXT_REALPATH(handle, tmp);
	if (result == NULL) {
		goto done;
	}

done:
	saved_errno = errno;
	TALLOC_FREE(tmp);
	TALLOC_FREE(stripped);
	errno = saved_errno;
	return result;
}

static NTSTATUS snapper_gmt_fget_nt_acl(vfs_handle_struct *handle,
					struct files_struct *fsp,
					uint32 security_info,
					TALLOC_CTX *mem_ctx,
					struct security_descriptor **ppdesc)
{
	time_t timestamp;
	char *stripped;
	NTSTATUS status;
	char *conv;

	if (!snapper_gmt_strip_snapshot(talloc_tos(), handle,
					fsp->fsp_name->base_name,
					&timestamp, &stripped)) {
		return map_nt_error_from_unix(errno);
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_FGET_NT_ACL(handle, fsp, security_info,
						mem_ctx,
						ppdesc);
	}
	conv = snapper_gmt_convert(talloc_tos(), handle, stripped, timestamp);
	TALLOC_FREE(stripped);
	if (conv == NULL) {
		return map_nt_error_from_unix(errno);
	}
	status = SMB_VFS_NEXT_GET_NT_ACL(handle, conv, security_info,
					 mem_ctx, ppdesc);
	TALLOC_FREE(conv);
	return status;
}

static NTSTATUS snapper_gmt_get_nt_acl(vfs_handle_struct *handle,
				       const char *fname,
				       uint32 security_info,
				       TALLOC_CTX *mem_ctx,
				       struct security_descriptor **ppdesc)
{
	time_t timestamp;
	char *stripped;
	NTSTATUS status;
	char *conv;

	if (!snapper_gmt_strip_snapshot(talloc_tos(), handle, fname,
					&timestamp, &stripped)) {
		return map_nt_error_from_unix(errno);
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_GET_NT_ACL(handle, fname, security_info,
					       mem_ctx, ppdesc);
	}
	conv = snapper_gmt_convert(talloc_tos(), handle, stripped, timestamp);
	TALLOC_FREE(stripped);
	if (conv == NULL) {
		return map_nt_error_from_unix(errno);
	}
	status = SMB_VFS_NEXT_GET_NT_ACL(handle, conv, security_info,
					 mem_ctx, ppdesc);
	TALLOC_FREE(conv);
	return status;
}

static int snapper_gmt_mkdir(vfs_handle_struct *handle,
			     const char *fname, mode_t mode)
{
	time_t timestamp;
	char *stripped;
	int ret, saved_errno;
	char *conv;

	if (!snapper_gmt_strip_snapshot(talloc_tos(), handle, fname,
					&timestamp, &stripped)) {
		return -1;
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_MKDIR(handle, fname, mode);
	}
	conv = snapper_gmt_convert(talloc_tos(), handle, stripped, timestamp);
	TALLOC_FREE(stripped);
	if (conv == NULL) {
		return -1;
	}
	ret = SMB_VFS_NEXT_MKDIR(handle, conv, mode);
	saved_errno = errno;
	TALLOC_FREE(conv);
	errno = saved_errno;
	return ret;
}

static int snapper_gmt_rmdir(vfs_handle_struct *handle, const char *fname)
{
	time_t timestamp;
	char *stripped;
	int ret, saved_errno;
	char *conv;

	if (!snapper_gmt_strip_snapshot(talloc_tos(), handle, fname,
					&timestamp, &stripped)) {
		return -1;
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_RMDIR(handle, fname);
	}
	conv = snapper_gmt_convert(talloc_tos(), handle, stripped, timestamp);
	TALLOC_FREE(stripped);
	if (conv == NULL) {
		return -1;
	}
	ret = SMB_VFS_NEXT_RMDIR(handle, conv);
	saved_errno = errno;
	TALLOC_FREE(conv);
	errno = saved_errno;
	return ret;
}

static int snapper_gmt_chflags(vfs_handle_struct *handle, const char *fname,
			       unsigned int flags)
{
	time_t timestamp;
	char *stripped;
	int ret, saved_errno;
	char *conv;

	if (!snapper_gmt_strip_snapshot(talloc_tos(), handle, fname,
					&timestamp, &stripped)) {
		return -1;
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_CHFLAGS(handle, fname, flags);
	}
	conv = snapper_gmt_convert(talloc_tos(), handle, stripped, timestamp);
	TALLOC_FREE(stripped);
	if (conv == NULL) {
		return -1;
	}
	ret = SMB_VFS_NEXT_CHFLAGS(handle, conv, flags);
	saved_errno = errno;
	TALLOC_FREE(conv);
	errno = saved_errno;
	return ret;
}

static ssize_t snapper_gmt_getxattr(vfs_handle_struct *handle,
				    const char *fname, const char *aname,
				    void *value, size_t size)
{
	time_t timestamp;
	char *stripped;
	ssize_t ret;
	int saved_errno;
	char *conv;

	if (!snapper_gmt_strip_snapshot(talloc_tos(), handle, fname,
					&timestamp, &stripped)) {
		return -1;
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_GETXATTR(handle, fname, aname, value,
					     size);
	}
	conv = snapper_gmt_convert(talloc_tos(), handle, stripped, timestamp);
	TALLOC_FREE(stripped);
	if (conv == NULL) {
		return -1;
	}
	ret = SMB_VFS_NEXT_GETXATTR(handle, conv, aname, value, size);
	saved_errno = errno;
	TALLOC_FREE(conv);
	errno = saved_errno;
	return ret;
}

static ssize_t snapper_gmt_listxattr(struct vfs_handle_struct *handle,
				     const char *fname,
				     char *list, size_t size)
{
	time_t timestamp;
	char *stripped;
	ssize_t ret;
	int saved_errno;
	char *conv;

	if (!snapper_gmt_strip_snapshot(talloc_tos(), handle, fname,
					&timestamp, &stripped)) {
		return -1;
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_LISTXATTR(handle, fname, list, size);
	}
	conv = snapper_gmt_convert(talloc_tos(), handle, stripped, timestamp);
	TALLOC_FREE(stripped);
	if (conv == NULL) {
		return -1;
	}
	ret = SMB_VFS_NEXT_LISTXATTR(handle, conv, list, size);
	saved_errno = errno;
	TALLOC_FREE(conv);
	errno = saved_errno;
	return ret;
}

static int snapper_gmt_removexattr(vfs_handle_struct *handle,
				   const char *fname, const char *aname)
{
	time_t timestamp;
	char *stripped;
	int ret, saved_errno;
	char *conv;

	if (!snapper_gmt_strip_snapshot(talloc_tos(), handle, fname,
					&timestamp, &stripped)) {
		return -1;
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_REMOVEXATTR(handle, fname, aname);
	}
	conv = snapper_gmt_convert(talloc_tos(), handle, stripped, timestamp);
	TALLOC_FREE(stripped);
	if (conv == NULL) {
		return -1;
	}
	ret = SMB_VFS_NEXT_REMOVEXATTR(handle, conv, aname);
	saved_errno = errno;
	TALLOC_FREE(conv);
	errno = saved_errno;
	return ret;
}

static int snapper_gmt_setxattr(struct vfs_handle_struct *handle,
				const char *fname,
				const char *aname, const void *value,
				size_t size, int flags)
{
	time_t timestamp;
	char *stripped;
	ssize_t ret;
	int saved_errno;
	char *conv;

	if (!snapper_gmt_strip_snapshot(talloc_tos(), handle, fname,
					&timestamp, &stripped)) {
		return -1;
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_SETXATTR(handle, fname, aname, value, size,
					     flags);
	}
	conv = snapper_gmt_convert(talloc_tos(), handle, stripped, timestamp);
	TALLOC_FREE(stripped);
	if (conv == NULL) {
		return -1;
	}
	ret = SMB_VFS_NEXT_SETXATTR(handle, conv, aname, value, size, flags);
	saved_errno = errno;
	TALLOC_FREE(conv);
	errno = saved_errno;
	return ret;
}

static int snapper_gmt_chmod_acl(vfs_handle_struct *handle,
				 const char *fname, mode_t mode)
{
	time_t timestamp;
	char *stripped;
	ssize_t ret;
	int saved_errno;
	char *conv;

	if (!snapper_gmt_strip_snapshot(talloc_tos(), handle, fname,
					&timestamp, &stripped)) {
		return -1;
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_CHMOD_ACL(handle, fname, mode);
	}
	conv = snapper_gmt_convert(talloc_tos(), handle, stripped, timestamp);
	TALLOC_FREE(stripped);
	if (conv == NULL) {
		return -1;
	}
	ret = SMB_VFS_NEXT_CHMOD_ACL(handle, conv, mode);
	saved_errno = errno;
	TALLOC_FREE(conv);
	errno = saved_errno;
	return ret;
}

static int snapper_gmt_get_real_filename(struct vfs_handle_struct *handle,
					 const char *path,
					 const char *name,
					 TALLOC_CTX *mem_ctx,
					 char **found_name)
{
	time_t timestamp;
	char *stripped;
	ssize_t ret;
	int saved_errno;
	char *conv;

	if (!snapper_gmt_strip_snapshot(talloc_tos(), handle, path,
					&timestamp, &stripped)) {
		return -1;
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_GET_REAL_FILENAME(handle, path, name,
						      mem_ctx, found_name);
	}
	if (stripped[0] == '\0') {
		*found_name = talloc_strdup(mem_ctx, name);
		if (*found_name == NULL) {
			errno = ENOMEM;
			return -1;
		}
		return 0;
	}
	conv = snapper_gmt_convert(talloc_tos(), handle, stripped, timestamp);
	TALLOC_FREE(stripped);
	if (conv == NULL) {
		return -1;
	}
	ret = SMB_VFS_NEXT_GET_REAL_FILENAME(handle, conv, name,
					     mem_ctx, found_name);
	saved_errno = errno;
	TALLOC_FREE(conv);
	errno = saved_errno;
	return ret;
}

static uint64_t snapper_gmt_disk_free(vfs_handle_struct *handle,
				      const char *path, bool small_query,
				      uint64_t *bsize, uint64_t *dfree,
				      uint64_t *dsize)
{
	time_t timestamp;
	char *stripped;
	ssize_t ret;
	int saved_errno;
	char *conv;

	if (!snapper_gmt_strip_snapshot(talloc_tos(), handle, path,
					&timestamp, &stripped)) {
		return -1;
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_DISK_FREE(handle, path, small_query,
					      bsize, dfree, dsize);
	}

	conv = snapper_gmt_convert(talloc_tos(), handle, stripped, timestamp);
	TALLOC_FREE(stripped);
	if (conv == NULL) {
		return -1;
	}

	ret = SMB_VFS_NEXT_DISK_FREE(handle, conv, small_query, bsize, dfree,
				     dsize);

	saved_errno = errno;
	TALLOC_FREE(conv);
	errno = saved_errno;

	return ret;
}


static struct vfs_fn_pointers snapper_fns = {
	.get_shadow_copy_data_fn = snapper_get_shadow_copy_data,
	.opendir_fn = snapper_gmt_opendir,
	.disk_free_fn = snapper_gmt_disk_free,
	.rename_fn = snapper_gmt_rename,
	.link_fn = snapper_gmt_link,
	.symlink_fn = snapper_gmt_symlink,
	.stat_fn = snapper_gmt_stat,
	.lstat_fn = snapper_gmt_lstat,
	.fstat_fn = snapper_gmt_fstat,
	.open_fn = snapper_gmt_open,
	.unlink_fn = snapper_gmt_unlink,
	.chmod_fn = snapper_gmt_chmod,
	.chown_fn = snapper_gmt_chown,
	.chdir_fn = snapper_gmt_chdir,
	.ntimes_fn = snapper_gmt_ntimes,
	.readlink_fn = snapper_gmt_readlink,
	.mknod_fn = snapper_gmt_mknod,
	.realpath_fn = snapper_gmt_realpath,
	.get_nt_acl_fn = snapper_gmt_get_nt_acl,
	.fget_nt_acl_fn = snapper_gmt_fget_nt_acl,
	.mkdir_fn = snapper_gmt_mkdir,
	.rmdir_fn = snapper_gmt_rmdir,
	.getxattr_fn = snapper_gmt_getxattr,
	.listxattr_fn = snapper_gmt_listxattr,
	.removexattr_fn = snapper_gmt_removexattr,
	.setxattr_fn = snapper_gmt_setxattr,
	.chmod_acl_fn = snapper_gmt_chmod_acl,
	.chflags_fn = snapper_gmt_chflags,
	.get_real_filename_fn = snapper_gmt_get_real_filename,
};

NTSTATUS vfs_snapper_init(void);
NTSTATUS vfs_snapper_init(void)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
				"snapper", &snapper_fns);
}
