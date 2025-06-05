/*
 * Unix SMB/CIFS implementation.
 *
 * Copyright (c) 2025      John Mulligan <jmulligan@samba.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "varlink_keybridge.h"

#include <varlink.h>

#define VLKB_PREFIX "[varlink_keybridge] "
#define KB_DBG_T(...) DEBUG(8, (VLKB_PREFIX __VA_ARGS__))
#define KB_DBG_I(...) DEBUG(5, (VLKB_PREFIX __VA_ARGS__))

#define DBG_ERR_VLKB(msg, verror) \
	DBG_ERR(VLKB_PREFIX "%s: %s\n", (msg), (varlink_error_string(verror)))

#define KB_GET "org.samba.containers.keybridge.Get"
#define KB_F_NAME "name"
#define KB_F_SCOPE "scope"
#define KB_F_KIND "kind"
#define KB_F_ENTRY "entry"
#define KB_F_DATA "data"
#define KB_KIND_B64 "B64"
#define KB_KIND_VALUE "VALUE"

static const char *vlkb_kind_string(enum varlink_keybridge_kind kind)
{
	switch (kind) {
	case VARLINK_KEYBRIDGE_KIND_B64:
		return KB_KIND_B64;
	default:
		return KB_KIND_VALUE;
	}
}

static void vlkb_error(struct varlink_keybridge_result *result,
		       const char *msg,
		       VarlinkObject *obj)
{
	char *json;
	long vret = varlink_object_to_json(obj, &json);
	if (vret < 0) {
		result->status = VARLINK_KEYBRIDGE_STATUS_FAILURE;
		result->data = talloc_strdup(result,
					     "varlink_object_to_json failed");
		return;
	}

	result->status = VARLINK_KEYBRIDGE_STATUS_ERROR;
	result->data = talloc_asprintf(result, "%s, object: %s", msg, json);
	free(json);
}

static long vlkb_get(VarlinkConnection *conn,
		     const char *error,
		     VarlinkObject *parameters,
		     uint64_t flags,
		     void *userdata)
{
	struct varlink_keybridge_result *result = userdata;
	const char *tmp = NULL;
	VarlinkObject *entry;
	enum varlink_keybridge_kind kind = VARLINK_KEYBRIDGE_KIND_DEFAULT;
	int vret;

	if (error) {
		vlkb_error(result, error, parameters);
		goto done;
	}

	vret = varlink_object_get_object(parameters, KB_F_ENTRY, &entry);
	if (vret < 0) {
		vlkb_error(result, "invalid field: " KB_F_ENTRY, parameters);
		goto done;
	}

	vret = varlink_object_get_string(entry, KB_F_KIND, &tmp);
	if (vret < 0) {
		vlkb_error(result, "invalid field: " KB_F_KIND, entry);
		goto done;
	}
	if (strcmp(KB_KIND_B64, tmp) == 0) {
		kind = VARLINK_KEYBRIDGE_KIND_B64;
	} else if (strcmp(KB_KIND_VALUE, tmp) == 0) {
		kind = VARLINK_KEYBRIDGE_KIND_VALUE;
	}

	vret = varlink_object_get_string(entry, KB_F_DATA, &tmp);
	if (vret < 0) {
		vlkb_error(result, "invalid field: " KB_F_DATA, entry);
		goto done;
	}
	result->data = talloc_strdup(result, tmp);
	if (result->data == NULL) {
		DBG_ERR(VLKB_PREFIX "talloc_strdup failed\n");
		goto done;
	}
	result->status = VARLINK_KEYBRIDGE_STATUS_OK;
	result->kind = kind;

done:
	return varlink_connection_close(conn);
}

static long vlkb_wait_for_response(VarlinkConnection *conn)
{
	struct timeval tv = {.tv_sec = 5, .tv_usec = 0};
	int fd = varlink_connection_get_fd(conn);
	int ret;
	fd_set rfds;

	FD_ZERO(&rfds);
	FD_SET(fd, &rfds);

	ret = select(fd + 1, &rfds, NULL, NULL, &tv);
	if (ret == -1) {
		DBG_ERR(VLKB_PREFIX "select() error: %s\n", strerror(errno));
		return -VARLINK_ERROR_INVALID_CALL;
	} else if (ret == 0) {
		DBG_ERR(VLKB_PREFIX "select() timed out\n");
		return -VARLINK_ERROR_INVALID_CALL;
	}
	return varlink_connection_process_events(conn, 0);
}

static bool vlkb_entry_get(TALLOC_CTX *mem_ctx,
			   const struct varlink_keybridge_config *kbc,
			   struct varlink_keybridge_result **resp)
{
	bool completed = false;
	VarlinkConnection *conn = NULL;
	VarlinkObject *params = NULL;
	struct varlink_keybridge_result *result;
	long vret;

	KB_DBG_I("calling varlink keybridge get method\n");
	KB_DBG_T("creating %s arguments object\n", KB_GET);
	vret = varlink_object_new(&params);
	if (vret < 0) {
		DBG_ERR_VLKB("varlink_object_new failed", -vret);
		goto done;
	}
	vret = varlink_object_set_string(params, KB_F_NAME, kbc->name);
	if (vret < 0) {
		DBG_ERR_VLKB("varlink_object_set_string '" KB_F_NAME "' failed",
			     -vret);
		goto done;
	}
	vret = varlink_object_set_string(params, KB_F_SCOPE, kbc->scope);
	if (vret < 0) {
		DBG_ERR_VLKB("varlink_object_set_string '" KB_F_SCOPE
			     "' failed",
			     -vret);
		goto done;
	}
	vret = varlink_object_set_string(params,
					 KB_F_KIND,
					 vlkb_kind_string(kbc->kind));
	if (vret < 0) {
		DBG_ERR_VLKB("varlink_object_set_string '" KB_F_KIND "' failed",
			     -vret);
		goto done;
	}

	/* set up the varlink connection */
	KB_DBG_T("creating %s connection\n", KB_GET);
	vret = varlink_connection_new(&conn, kbc->path);
	if (vret < 0) {
		DBG_ERR_VLKB("varlink_connection_new failed", -vret);
		goto done;
	}

	KB_DBG_T("creating %s result object\n", KB_GET);
	result = talloc_zero(mem_ctx, struct varlink_keybridge_result);
	if (result == NULL) {
		DBG_ERR(VLKB_PREFIX "talloc_zero failed\n");
		goto done;
	}
	*resp = result;

	KB_DBG_T("performing %s call\n", KB_GET);
	vret = varlink_connection_call(
		conn, KB_GET, params, 0, vlkb_get, result);
	if (vret < 0) {
		DBG_ERR_VLKB("varlink_connection_call failed", -vret);
		goto done;
	}
	KB_DBG_T("waiting for %s response\n", KB_GET);
	vret = vlkb_wait_for_response(conn);
	if (vret < 0) {
		DBG_ERR_VLKB("vlkb_wait_for_response failed", -vret);
		goto done;
	}
	completed = true;

done:
	if (params) {
		varlink_object_unref(params);
	}
	if (conn) {
		varlink_connection_free(conn);
	}
	KB_DBG_I("varlink keybridge get method: %s\n",
		 (completed) ? "success" : "failure");
	return completed;
}

bool varlink_keybridge_entry_get(TALLOC_CTX *mem_ctx,
				 const struct varlink_keybridge_config *kbc,
				 struct varlink_keybridge_result **resp)
{
	return vlkb_entry_get(mem_ctx, kbc, resp);
}
