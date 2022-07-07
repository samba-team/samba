/*
 * Samba Unix/Linux SMB client library
 * Json output
 * Copyright (C) Jule Anger 2022
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "smbprofile.h"
#include "conn_tdb.h"
#include "status_json.h"
#include "../libcli/security/security.h"
#include "status.h"
#include "lib/util/server_id.h"

#include <jansson.h>
#include "audit_logging.h" /* various JSON helpers */
#include "auth/common_auth.h"

int add_general_information_to_json(struct traverse_state *state)
{
	int result;

	result = json_add_timestamp(&state->root_json);
	if (result < 0) {
		return -1;
	}

	result = json_add_string(&state->root_json, "version", samba_version_string());
	if (result < 0) {
		return -1;
	}

	result = json_add_string(&state->root_json, "smb_conf", get_dyn_CONFIGFILE());
	if (result < 0) {
		return -1;
	}

	return 0;
}

static int add_server_id_to_json(struct json_object *parent_json,
				 const struct server_id server_id)
{
	struct json_object sub_json;
	char *pid_str = NULL;
	char *task_id_str = NULL;
	char *vnn_str = NULL;
	char *unique_id_str = NULL;
	int result;

	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return -1;
	}

	sub_json = json_new_object();
	if (json_is_invalid(&sub_json)) {
		goto failure;
	}

	pid_str = talloc_asprintf(tmp_ctx, "%lu", server_id.pid);
	result = json_add_string(&sub_json, "pid", pid_str);
	if (result < 0) {
		goto failure;
	}
	task_id_str = talloc_asprintf(tmp_ctx, "%u", server_id.task_id);
	result = json_add_string(&sub_json, "task_id", task_id_str);
	if (result < 0) {
		goto failure;
	}
	vnn_str = talloc_asprintf(tmp_ctx, "%u", server_id.vnn);
	result = json_add_string(&sub_json, "vnn", vnn_str);
	if (result < 0) {
		goto failure;
	}
	unique_id_str = talloc_asprintf(tmp_ctx, "%lu", server_id.unique_id);
	result = json_add_string(&sub_json, "unique_id", unique_id_str);
	if (result < 0) {
		goto failure;
	}

	result = json_add_object(parent_json, "server_id", &sub_json);
	if (result < 0) {
		goto failure;
	}

	json_free(&sub_json);
	TALLOC_FREE(tmp_ctx);
	return 0;
failure:
	json_free(&sub_json);
	TALLOC_FREE(tmp_ctx);
	return -1;
}

int add_section_to_json(struct traverse_state *state,
			const char *key)
{
	struct json_object empty_json;
	int result;

	empty_json = json_new_object();
	if (json_is_invalid(&empty_json)) {
		return -1;
	}

	result = json_add_object(&state->root_json, key, &empty_json);
	if (result < 0) {
		return -1;
	}

	return result;
}

int traverse_connections_json(struct traverse_state *state,
			      const struct connections_data *crec)
{
	struct json_object sub_json;
	struct json_object connections_json;
	int result = 0;
	char *sess_id_str = NULL;
	char *tcon_id_str = NULL;

	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return -1;
	}

	sub_json = json_new_object();
	if (json_is_invalid(&sub_json)) {
		goto failure;
	}
	connections_json = json_get_object(&state->root_json, "tcons");
	if (json_is_invalid(&connections_json)) {
		goto failure;
	}

	result = json_add_string(&sub_json, "service", crec->servicename);
	if (result < 0) {
		goto failure;
	}
	result = add_server_id_to_json(&sub_json, crec->pid);
	if (result < 0) {
		goto failure;
	}
	tcon_id_str = talloc_asprintf(tmp_ctx, "%u", crec->cnum);
	if (tcon_id_str == NULL) {
		goto failure;
	}
	result = json_add_string(&sub_json, "tcon_id", tcon_id_str);
	if (result < 0) {
		goto failure;
	}
	sess_id_str = talloc_asprintf(tmp_ctx, "%u", crec->sess_id);
	if (sess_id_str == NULL) {
		goto failure;
	}
	result = json_add_string(&sub_json, "session_id", sess_id_str);
	if (result < 0) {
		goto failure;
	}
	result = json_add_string(&sub_json, "machine", crec->machine);
	if (result < 0) {
		goto failure;
	}

	result = json_add_object(&connections_json, tcon_id_str, &sub_json);
	if (result < 0) {
		goto failure;
	}

	result = json_update_object(&state->root_json, "tcons", &connections_json);
	if (result < 0) {
		goto failure;
	}

	TALLOC_FREE(tmp_ctx);
	return 0;
failure:
	json_free(&sub_json);
	TALLOC_FREE(tmp_ctx);
	return -1;
}
