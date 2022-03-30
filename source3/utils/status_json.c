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
#include "lib/util/time_basic.h"
#include "conn_tdb.h"
#include "session.h"
#include "librpc/gen_ndr/open_files.h"
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

static int add_crypto_to_json(struct json_object *parent_json,
			      const char *key,
			      const char *cipher,
			      enum crypto_degree degree)
{
	struct json_object sub_json;
	const char *degree_str;
	int result;

	if (degree == CRYPTO_DEGREE_NONE) {
		degree_str = "none";
	} else if (degree == CRYPTO_DEGREE_PARTIAL) {
		degree_str = "partial";
	} else {
		degree_str = "full";
	}

	sub_json = json_new_object();
	if (json_is_invalid(&sub_json)) {
		goto failure;
	}

	result = json_add_string(&sub_json, "cipher", cipher);
	if (result < 0) {
		goto failure;
	}
	result = json_add_string(&sub_json, "degree", degree_str);
	if (result < 0) {
		goto failure;
	}
	result = json_add_object(parent_json, key, &sub_json);
	if (result < 0) {
		goto failure;
	}

	return 0;
failure:
	json_free(&sub_json);
	return -1;
}

int traverse_connections_json(struct traverse_state *state,
			      const struct connections_data *crec,
			      const char *encryption_cipher,
			      enum crypto_degree encryption_degree,
			      const char *signing_cipher,
			      enum crypto_degree signing_degree)
{
	struct json_object sub_json;
	struct json_object connections_json;
	struct timeval tv;
	struct timeval_buf tv_buf;
	char *time = NULL;
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
	nttime_to_timeval(&tv, crec->start);
	time = timeval_str_buf(&tv, true, true, &tv_buf);
	if (time == NULL) {
		goto failure;
	}
	result = json_add_string(&sub_json, "connected_at", time);
	if (result < 0) {
		goto failure;
	}
	result = add_crypto_to_json(&sub_json, "encryption",
				   encryption_cipher, encryption_degree);
	if (result < 0) {
		goto failure;
	}
	result = add_crypto_to_json(&sub_json, "signing",
				   signing_cipher, signing_degree);
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

int traverse_sessionid_json(struct traverse_state *state,
			    struct sessionid *session,
			    char *uid_str,
			    char *gid_str,
			    const char *encryption_cipher,
			    enum crypto_degree encryption_degree,
			    const char *signing_cipher,
			    enum crypto_degree signing_degree,
			    const char *connection_dialect)
{
	struct json_object sub_json;
	struct json_object session_json;
	int result = 0;
	char *id_str = NULL;

	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return -1;
	}

	sub_json = json_new_object();
	if (json_is_invalid(&sub_json)) {
		goto failure;
	}

	session_json = json_get_object(&state->root_json, "sessions");
	if (json_is_invalid(&session_json)) {
		goto failure;
	}

	id_str = talloc_asprintf(tmp_ctx, "%u", session->id_num);
	result = json_add_string(&sub_json, "session_id", id_str);
	if (result < 0) {
		goto failure;
	}
	result = add_server_id_to_json(&sub_json, session->pid);
	if (result < 0) {
		goto failure;
	}
	result = json_add_int(&sub_json, "uid", session->uid);
	if (result < 0) {
		goto failure;
	}
	result = json_add_int(&sub_json, "gid", session->gid);
	if (result < 0) {
		goto failure;
	}
	result = json_add_string(&sub_json, "username", uid_str);
	if (result < 0) {
		goto failure;
	}
	result = json_add_string(&sub_json, "groupname", gid_str);
	if (result < 0) {
		goto failure;
	}
	result = json_add_string(&sub_json, "remote_machine", session->remote_machine);
	if (result < 0) {
		goto failure;
	}
	result = json_add_string(&sub_json, "hostname", session->hostname);
	if (result < 0) {
		goto failure;
	}
	result = json_add_string(&sub_json, "session_dialect", connection_dialect);
	if (result < 0) {
		goto failure;
	}
	result = add_crypto_to_json(&sub_json, "encryption",
				    encryption_cipher, encryption_degree);
	if (result < 0) {
		goto failure;
	}
	result = add_crypto_to_json(&sub_json, "signing",
				    signing_cipher, signing_degree);
	if (result < 0) {
		goto failure;
	}

	result = json_add_object(&session_json, id_str, &sub_json);
	if (result < 0) {
		goto failure;
	}

	result = json_update_object(&state->root_json, "sessions", &session_json);
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

static int add_open_to_json(struct json_object *parent_json,
			    const struct share_mode_entry *e,
			    bool resolve_uids,
			    const char *pid,
			    const char *uid_str)
{
	struct json_object sub_json;
	struct json_object opens_json;
	int result = 0;
	char *key = NULL;
	char *share_file_id = NULL;

	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return -1;
	}

	opens_json = json_get_object(parent_json, "opens");
	if (json_is_invalid(&opens_json)) {
		goto failure;
	}
	sub_json = json_new_object();
	if (json_is_invalid(&sub_json)) {
		goto failure;
	}

	result = json_add_string(&sub_json, "pid", pid);
	if (result < 0) {
		goto failure;
	}
	if (resolve_uids) {
		result = json_add_string(&sub_json, "username", uid_str);
		if (result < 0) {
			goto failure;
		}
	}
	result = json_add_int(&sub_json, "uid", e->uid);
	if (result < 0) {
		goto failure;
	}
	share_file_id = talloc_asprintf(tmp_ctx, "%lu", e->share_file_id);
	result = json_add_string(&sub_json, "share_file_id", share_file_id);
	if (result < 0) {
		goto failure;
	}

	key = talloc_asprintf(tmp_ctx, "%s/%lu", pid, e->share_file_id);
	result = json_add_object(&opens_json, key, &sub_json);
	if (result < 0) {
		goto failure;
	}
	result = json_update_object(parent_json, "opens", &opens_json);
	if (result < 0) {
		goto failure;
	}

	TALLOC_FREE(tmp_ctx);
	return 0;
failure:
	json_free(&opens_json);
	json_free(&sub_json);
	TALLOC_FREE(tmp_ctx);
	return -1;
}

static int add_fileid_to_json(struct json_object *parent_json,
			      struct file_id fid)
{
	struct json_object fid_json;
	int result;

	fid_json = json_new_object();
	if (json_is_invalid(&fid_json)) {
		goto failure;
	}

	result = json_add_int(&fid_json, "devid", fid.devid);
	if (result < 0) {
		goto failure;
	}
	result = json_add_int(&fid_json, "inode", fid.inode);
	if (result < 0) {
		goto failure;
	}
	result = json_add_int(&fid_json, "extid", fid.extid);
	if (result < 0) {
		goto failure;
	}

	result = json_add_object(parent_json, "fileid", &fid_json);
	if (result < 0) {
		goto failure;
	}

	return 0;
failure:
	json_free(&fid_json);
	return -1;
}

int print_share_mode_json(struct traverse_state *state,
			  const struct share_mode_data *d,
			  const struct share_mode_entry *e,
			  struct file_id fid,
			  const char *pid,
			  const char *uid_str,
			  const char *filename)
{
	struct json_object locks_json;
	struct json_object file_json;
	char *key = NULL;
	int result = 0;

	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return -1;
	}

	if (d->servicepath[strlen(d->servicepath)-1] == '/') {
		key = talloc_asprintf(tmp_ctx, "%s%s", d->servicepath, filename);
	} else {
		key = talloc_asprintf(tmp_ctx, "%s/%s", d->servicepath, filename);
	}

	locks_json = json_get_object(&state->root_json, "open_files");
	if (json_is_invalid(&locks_json)) {
		goto failure;
	}
	file_json = json_get_object(&locks_json, key);
	if (json_is_invalid(&file_json)) {
		goto failure;
	}

	result = json_add_string(&file_json, "service_path", d->servicepath);
	if (result < 0) {
		goto failure;
	}
	result = json_add_string(&file_json, "filename", filename);
	if (result < 0) {
		goto failure;
	}
	result = add_fileid_to_json(&file_json, fid);
	if (result < 0) {
		goto failure;
	}
	result = json_add_int(&file_json, "num_pending_deletes", d->num_delete_tokens);
	if (result < 0) {
		goto failure;
	}

	result = add_open_to_json(&file_json,
				  e,
				  state->resolve_uids,
				  pid,
				  uid_str);
	if (result < 0) {
		goto failure;
	}

	result = json_update_object(&locks_json, key, &file_json);
	if (result < 0) {
		goto failure;
	}
	result = json_update_object(&state->root_json, "open_files", &locks_json);
	if (result < 0) {
		goto failure;
	}

	TALLOC_FREE(tmp_ctx);
	return 0;
failure:
	json_free(&file_json);
	json_free(&locks_json);
	TALLOC_FREE(tmp_ctx);
	return -1;
}
