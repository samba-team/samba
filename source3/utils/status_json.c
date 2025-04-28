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
#include "librpc/gen_ndr/smbXsrv.h"
#include "librpc/gen_ndr/open_files.h"
#include "status_json.h"
#include "../libcli/security/security.h"
#include "status.h"
#include "lib/util/server_id.h"
#include "lib/util/string_wrappers.h"

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

	pid_str = talloc_asprintf(
		tmp_ctx, "%lu", (unsigned long)server_id.pid);
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
	unique_id_str = talloc_asprintf(
		tmp_ctx, "%"PRIu64, server_id.unique_id);
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

struct mask2txt {
	uint32_t mask;
	const char *string_desc;
};

/*
 * Convert a mask of some sort (access, oplock, leases),
 * to key/value pairs in a JSON object.
 */
static int map_mask_to_json(struct json_object *root_json,
			    uint32_t tomap,
			    const struct mask2txt *table)
{
	const struct mask2txt *a = NULL;
	int result = 0;

	for (a = table; a->string_desc != 0; a++) {
		result = json_add_bool(root_json, a->string_desc,
				      (tomap & a->mask) ? true : false);

		if (result < 0) {
			return result;
		}
		tomap &= ~a->mask;
	}

	/* Assert we know about all requested "tomap" values */
	SMB_ASSERT(tomap == 0);

	return 0;
}

static const struct mask2txt access_mask[] = {
	{FILE_READ_DATA, "READ_DATA"},
	{FILE_WRITE_DATA, "WRITE_DATA"},
	{FILE_APPEND_DATA, "APPEND_DATA"},
	{FILE_READ_EA, "READ_EA"},
	{FILE_WRITE_EA, "WRITE_EA"},
	{FILE_EXECUTE, "EXECUTE"},
	{FILE_READ_ATTRIBUTES, "READ_ATTRIBUTES"},
	{FILE_WRITE_ATTRIBUTES, "WRITE_ATTRIBUTES"},
	{FILE_DELETE_CHILD, "DELETE_CHILD"},
	{SEC_STD_DELETE, "DELETE"},
	{SEC_STD_READ_CONTROL, "READ_CONTROL"},
	{SEC_STD_WRITE_DAC, "WRITE_DAC"},
	{SEC_STD_SYNCHRONIZE, "SYNCHRONIZE"},
	{SEC_FLAG_SYSTEM_SECURITY, "ACCESS_SYSTEM_SECURITY"},
	{0, NULL}
};

static const struct mask2txt oplock_mask[] = {
	{EXCLUSIVE_OPLOCK, "EXCLUSIVE"},
	{BATCH_OPLOCK, "BATCH"},
	{LEVEL_II_OPLOCK, "LEVEL_II"},
	{LEASE_OPLOCK, "LEASE"},
	{0, NULL}
};

static const struct mask2txt sharemode_mask[] = {
	{FILE_SHARE_READ, "READ"},
	{FILE_SHARE_WRITE, "WRITE"},
	{FILE_SHARE_DELETE, "DELETE"},
	{0, NULL}
};

static const struct mask2txt lease_mask[] = {
	{SMB2_LEASE_READ, "READ"},
	{SMB2_LEASE_WRITE, "WRITE"},
	{SMB2_LEASE_HANDLE, "HANDLE"},
	{0, NULL}
};

/* Add nested json key:value entry, up to 4 levels deep */
static int add_nested_item_to_json(struct json_object *root_json,
				   const char **subs,
				   size_t nsubs,
				   const char *key,
				   uintmax_t value)
{
	struct json_object jobj_sub[4] = {0};
	struct json_object *jo[5] = {root_json,
				     &jobj_sub[0],
				     &jobj_sub[1],
				     &jobj_sub[2],
				     &jobj_sub[3]};
	size_t i = 0;
	int result = 0;

	if (nsubs > ARRAY_SIZE(jobj_sub)) {
		return -1;
	}

	for (i = 0; i < nsubs; ++i) {
		*(jo[i + 1]) = json_get_object(jo[i], subs[i]);
		if (json_is_invalid(jo[i + 1])) {
			goto failure;
		}
	}

	result = json_add_int(jo[nsubs], key, value);
	if (result < 0) {
		goto failure;
	}

	for (i = nsubs; i > 0; --i) {
		result = json_update_object(jo[i - 1], subs[i - 1], jo[i]);
		if (result < 0) {
			goto failure;
		}
	}

	return 0;
failure:
	for (i = 0; i < nsubs; ++i) {
		json_free(&jobj_sub[i]);
	}
	return -1;
}

int add_profile_item_to_json(struct traverse_state *state,
			     const char *section,
			     const char *subsection,
			     const char *key,
			     uintmax_t value)
{
	const char *subs[] = {section, subsection};

	return add_nested_item_to_json(&state->root_json, subs, 2, key, value);
}

int add_profile_persvc_item_to_json(struct traverse_state *state,
				    const char *section1,
				    const char *section2,
				    const char *section3,
				    const char *key,
				    uintmax_t value)
{
	const char *subs[] = {"Extended Profile", section1, section2, section3};

	return add_nested_item_to_json(&state->root_json, subs, 4, key, value);
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
	} else if (degree == CRYPTO_DEGREE_ANONYMOUS) {
		degree_str = "anonymous";
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

static int add_channel_to_json(struct json_object *parent_json,
			       const struct smbXsrv_channel_global0 *channel)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct json_object sub_json;
	char *id_str = NULL;
	struct timeval tv;
	struct timeval_buf tv_buf;
	char *time_str = NULL;
	const char *transport_str = NULL;
	enum smb_transport_type tt =
		(enum smb_transport_type)channel->transport_type;
	int result;

	switch (tt) {
	case SMB_TRANSPORT_TYPE_UNKNOWN:
		transport_str = "unknown";
		break;
	case SMB_TRANSPORT_TYPE_NBT:
		transport_str = "nbt";
		break;
	case SMB_TRANSPORT_TYPE_TCP:
		transport_str = "tcp";
		break;
	}

	if (transport_str == NULL) {
		transport_str = talloc_asprintf(frame,
						"unknown%u",
						tt);
		if (transport_str == NULL) {
			goto failure;
		}
	}

	sub_json = json_new_object();
	if (json_is_invalid(&sub_json)) {
		goto failure;
	}

	id_str = talloc_asprintf(frame, "%"PRIu64"", channel->channel_id);
	if (id_str == NULL) {
		goto failure;
	}
	result = json_add_string(&sub_json, "channel_id", id_str);
	if (result < 0) {
		goto failure;
	}
	nttime_to_timeval(&tv, channel->creation_time);
	time_str = timeval_str_buf(&tv, true, true, &tv_buf);
	if (time_str == NULL) {
		goto failure;
	}
	result = json_add_string(&sub_json, "creation_time", time_str);
	if (result < 0) {
		goto failure;
	}
	result = json_add_string(&sub_json, "local_address", channel->local_address);
	if (result < 0) {
		goto failure;
	}
	result = json_add_string(&sub_json, "remote_address", channel->remote_address);
	if (result < 0) {
		goto failure;
	}
	result = json_add_string(&sub_json, "transport", transport_str);
	if (result < 0) {
		goto failure;
	}

	result = json_add_object(parent_json, id_str, &sub_json);
	if (result < 0) {
		goto failure;
	}

	TALLOC_FREE(frame);
	return 0;
failure:
	json_free(&sub_json);
	TALLOC_FREE(frame);
	return -1;
}

static int add_channels_to_json(struct json_object *parent_json,
				const struct smbXsrv_session_global0 *global)
{
	struct json_object sub_json;
	uint32_t i;
	int result;

	sub_json = json_new_object();
	if (json_is_invalid(&sub_json)) {
		goto failure;
	}

	for (i = 0; i < global->num_channels; i++) {
		const struct smbXsrv_channel_global0 *c = &global->channels[i];

		result = add_channel_to_json(&sub_json, c);
		if (result < 0) {
			goto failure;
		}
	}

	result = json_add_object(parent_json, "channels", &sub_json);
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
	struct timeval tv;
	struct timeval_buf tv_buf;
	char *time_str = NULL;

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

	nttime_to_timeval(&tv, session->global->creation_time);
	time_str = timeval_str_buf(&tv, true, true, &tv_buf);
	if (time_str == NULL) {
		goto failure;
	}
	result = json_add_string(&sub_json, "creation_time", time_str);
	if (result < 0) {
		goto failure;
	}

	nttime_to_timeval(&tv, session->global->expiration_time);
	time_str = timeval_str_buf(&tv, true, true, &tv_buf);
	if (time_str == NULL) {
		goto failure;
	}
	result = json_add_string(&sub_json, "expiration_time", time_str);
	if (result < 0) {
		goto failure;
	}

	nttime_to_timeval(&tv, session->global->auth_time);
	time_str = timeval_str_buf(&tv, true, true, &tv_buf);
	if (time_str == NULL) {
		goto failure;
	}
	result = json_add_string(&sub_json, "auth_time", time_str);
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
	result = json_add_guid(&sub_json,
			       "client_guid",
			       &session->global->client_guid);
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

	result = add_channels_to_json(&sub_json, session->global);
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

static int add_access_mode_to_json(struct json_object *parent_json,
				   int access_int)
{
	struct json_object access_json;
	char *access_hex = NULL;
	const char *access_str = NULL;
	int result;

	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return -1;
	}

	access_json = json_new_object();
	if (json_is_invalid(&access_json)) {
		goto failure;
	}

	access_hex = talloc_asprintf(tmp_ctx, "0x%08x", access_int);
	result = json_add_string(&access_json, "hex", access_hex);
	if (result < 0) {
		  goto failure;
	}
	result = map_mask_to_json(&access_json, access_int, access_mask);
	if (result < 0) {
		goto failure;
	}

	access_str = talloc_asprintf(tmp_ctx, "%s%s",
				     (access_int & FILE_READ_DATA)?"R":"",
				     (access_int & (FILE_WRITE_DATA|FILE_APPEND_DATA))?"W":"");
	result = json_add_string(&access_json, "text", access_str);
	if (result < 0) {
		  goto failure;
	}

	result = json_add_object(parent_json, "access_mask", &access_json);
	if (result < 0) {
		goto failure;
	}

	TALLOC_FREE(tmp_ctx);
	return 0;
failure:
	json_free(&access_json);
	TALLOC_FREE(tmp_ctx);
	return -1;
}

static int add_caching_to_json(struct json_object *parent_json,
			      int op_type,
			      int lease_type)
{
	struct json_object caching_json;
	char *hex = NULL;
	char *caching_text = NULL;
	int caching_type = 0;
	int result;

	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return -1;
	}

	caching_json = json_new_object();
	if (json_is_invalid(&caching_json)) {
		goto failure;
	}

	if (op_type & LEASE_OPLOCK) {
		caching_type = lease_type;
	} else {
		if (op_type & LEVEL_II_OPLOCK) {
			caching_type = SMB2_LEASE_READ;
		} else if (op_type & EXCLUSIVE_OPLOCK) {
			caching_type = SMB2_LEASE_READ + SMB2_LEASE_WRITE;
		} else if (op_type & BATCH_OPLOCK) {
			caching_type = SMB2_LEASE_READ + SMB2_LEASE_WRITE + SMB2_LEASE_HANDLE;
		}
	}
	result = map_mask_to_json(&caching_json, caching_type, lease_mask);
	if (result < 0) {
		goto failure;
	}

	hex = talloc_asprintf(tmp_ctx, "0x%08x", caching_type);
	if (hex == NULL) {
		goto failure;
	}
	result = json_add_string(&caching_json, "hex", hex);
	if (result < 0) {
		goto failure;
	}

	caching_text = talloc_asprintf(tmp_ctx, "%s%s%s",
				       (caching_type & SMB2_LEASE_READ)?"R":"",
				       (caching_type & SMB2_LEASE_WRITE)?"W":"",
				       (caching_type & SMB2_LEASE_HANDLE)?"H":"");
	if (caching_text == NULL) {
		return -1;
	}

	result = json_add_string(&caching_json, "text", caching_text);
	if (result < 0) {
		goto failure;
	}

	result = json_add_object(parent_json, "caching", &caching_json);
	if (result < 0) {
		goto failure;
	}

	TALLOC_FREE(tmp_ctx);
	return 0;
failure:
	json_free(&caching_json);
	TALLOC_FREE(tmp_ctx);
	return -1;
}

static int add_oplock_to_json(struct json_object *parent_json,
			      uint16_t op_type,
			      const char *op_str)
{
	struct json_object oplock_json;
	int result;

	oplock_json = json_new_object();
	if (json_is_invalid(&oplock_json)) {
		goto failure;
	}

	if (op_type != 0) {
		result = map_mask_to_json(&oplock_json, op_type, oplock_mask);
		if (result < 0) {
			goto failure;
		}
		result = json_add_string(&oplock_json, "text", op_str);
		if (result < 0) {
			goto failure;
		}
	}

	result = json_add_object(parent_json, "oplock", &oplock_json);
	if (result < 0) {
		goto failure;
	}

	return 0;
failure:
	json_free(&oplock_json);
	return -1;
}

static int lease_key_to_str(struct smb2_lease_key lease_key,
			    char *lease_str)
{
	uint8_t _buf[16] = {0};
	DATA_BLOB blob = data_blob_const(_buf, sizeof(_buf));
	struct GUID guid;
	NTSTATUS status;
	char *tmp = NULL;

	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return -1;
	}

	PUSH_LE_U64(_buf, 0, lease_key.data[0]);
	PUSH_LE_U64(_buf, 8, lease_key.data[1]);

	status = GUID_from_ndr_blob(&blob, &guid);
	if (!NT_STATUS_IS_OK(status)) {
		goto failure;
	}
	tmp = GUID_string(tmp_ctx, &guid);
	if (tmp == NULL) {
		goto failure;
	}
	fstrcpy(lease_str, tmp);

	TALLOC_FREE(tmp_ctx);
	return 0;
failure:
	TALLOC_FREE(tmp_ctx);
	return -1;
}

static int add_lease_to_json(struct json_object *parent_json,
			     int lease_type,
			     struct smb2_lease_key lease_key,
			     bool add_lease)
{
	struct json_object lease_json;
	char *lease_hex = NULL;
	char *lease_text = NULL;
	fstring lease_key_str;
	int result;

	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return -1;
	}

	lease_json = json_new_object();
	if (json_is_invalid(&lease_json)) {
		goto failure;
	}


	if (add_lease) {
		result = lease_key_to_str(lease_key, lease_key_str);
		if (result < 0) {
			goto failure;
		}
		result = json_add_string(&lease_json, "lease_key", lease_key_str);
		if (result < 0) {
			goto failure;
		}
		lease_hex = talloc_asprintf(tmp_ctx, "0x%08x", lease_type);
		result = json_add_string(&lease_json, "hex", lease_hex);
		if (result < 0) {
			goto failure;
		}
		if (lease_type > (SMB2_LEASE_WRITE + SMB2_LEASE_HANDLE + SMB2_LEASE_READ)) {
			result = json_add_bool(&lease_json, "UNKNOWN", true);
			if (result < 0) {
				goto failure;
			}
		} else {
			result = map_mask_to_json(&lease_json, lease_type, lease_mask);
			if (result < 0) {
				goto failure;
			}
		}
		lease_text = talloc_asprintf(tmp_ctx, "%s%s%s",
					     (lease_type & SMB2_LEASE_READ)?"R":"",
					     (lease_type & SMB2_LEASE_WRITE)?"W":"",
					     (lease_type & SMB2_LEASE_HANDLE)?"H":"");

		result = json_add_string(&lease_json, "text", lease_text);
		if (result < 0) {
			goto failure;
		}
	}

	result = json_add_object(parent_json, "lease", &lease_json);
	if (result < 0) {
		goto failure;
	}

	TALLOC_FREE(tmp_ctx);
	return 0;
failure:
	json_free(&lease_json);
	TALLOC_FREE(tmp_ctx);
	return -1;
}

static int add_sharemode_to_json(struct json_object *parent_json,
				 int sharemode)
{
	struct json_object sharemode_json;
	char *hex = NULL;
	char *text = NULL;
	int result;

	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return -1;
	}

	sharemode_json = json_new_object();
	if (json_is_invalid(&sharemode_json)) {
		goto failure;
	}

	hex = talloc_asprintf(tmp_ctx, "0x%08x", sharemode);
	if (hex == NULL) {
		goto failure;
	}
	result = json_add_string(&sharemode_json, "hex", hex);
	if (result < 0) {
		goto failure;
	}
	result = map_mask_to_json(&sharemode_json, sharemode, sharemode_mask);
	if (result < 0) {
		goto failure;
	}

	text = talloc_asprintf(tmp_ctx, "%s%s%s",
			       (sharemode & FILE_SHARE_READ)?"R":"",
			       (sharemode & FILE_SHARE_WRITE)?"W":"",
			       (sharemode & FILE_SHARE_DELETE)?"D":"");
	if (text == NULL) {
		goto failure;
	}
	result = json_add_string(&sharemode_json, "text", text);
	if (result < 0) {
		goto failure;
	}

	result = json_add_object(parent_json, "sharemode", &sharemode_json);
	if (result < 0) {
		goto failure;
	}

	TALLOC_FREE(tmp_ctx);
	return 0;
failure:
	json_free(&sharemode_json);
	TALLOC_FREE(tmp_ctx);
	return -1;
}

static int add_open_to_json(struct json_object *parent_json,
			    const struct share_mode_entry *e,
			    bool resolve_uids,
			    const char *op_str,
			    uint32_t lease_type,
			    const char *uid_str)
{
	struct json_object sub_json = {
		.valid = false,
	};
	struct json_object opens_json = {
		.valid = false,
	};
	struct timeval_buf tv_buf;
	int result = 0;
	char *timestr;
	bool add_lease = false;
	char *key = NULL;
	char *share_file_id = NULL;
	char *pid = NULL;
	struct server_id_buf tmp;

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


	result = add_server_id_to_json(&sub_json, e->pid);
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
	share_file_id = talloc_asprintf(tmp_ctx, "%"PRIu64, e->share_file_id);
	result = json_add_string(&sub_json, "share_file_id", share_file_id);
	if (result < 0) {
		goto failure;
	}
	result = add_sharemode_to_json(&sub_json, e->share_access);
	if (result < 0) {
		goto failure;
	}
	result = add_access_mode_to_json(&sub_json, e->access_mask);
	if (result < 0) {
		goto failure;
	}
	result = add_caching_to_json(&sub_json, e->op_type, lease_type);
	if (result < 0) {
		goto failure;
	}
	result = add_oplock_to_json(&sub_json, e->op_type, op_str);
	if (result < 0) {
		goto failure;
	}
	add_lease = e->op_type & LEASE_OPLOCK;
	result = add_lease_to_json(&sub_json, lease_type, e->lease_key, add_lease);
	if (result < 0) {
		goto failure;
	}

	timestr = timeval_str_buf(&e->time, true, true, &tv_buf);
	if (timestr == NULL) {
		goto failure;
	}
	result = json_add_string(&sub_json, "opened_at", timestr);
	if (result < 0) {
		goto failure;
	}

	pid = server_id_str_buf(e->pid, &tmp);
	key = talloc_asprintf(tmp_ctx, "%s/%"PRIu64, pid, e->share_file_id);
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
			  const char *uid_str,
			  const char *op_str,
			  uint32_t lease_type,
			  const char *filename)
{
	struct json_object locks_json = {
		.valid = false,
	};
	struct json_object file_json = {
		.valid = false,
	};
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
				  op_str,
				  lease_type,
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

static int add_lock_to_json(struct json_object *parent_json,
			    struct server_id server_id,
			    const char *type,
			    enum brl_flavour flavour,
			    intmax_t start,
			    intmax_t size)
{
	struct json_object sub_json = {
		.valid = false,
	};
	struct json_object locks_json = {
		.valid = false,
	};
	const char *flavour_str;
	int result = 0;

	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return -1;
	}

	locks_json = json_get_array(parent_json, "locks");
	if (json_is_invalid(&locks_json)) {
		goto failure;
	}
	sub_json = json_new_object();
	if (json_is_invalid(&sub_json)) {
		goto failure;
	}

	result = add_server_id_to_json(&sub_json, server_id);
	if (result < 0) {
		goto failure;
	}
	result = json_add_string(&sub_json, "type", type);
	if (result < 0) {
		goto failure;
	}
	flavour_str = talloc_asprintf(tmp_ctx, "%s%s",
				      (flavour == WINDOWS_LOCK)?"Windows":"",
				      (flavour == POSIX_LOCK)?"Posix":"");
	result = json_add_string(&sub_json, "flavour", flavour_str);
	if (result < 0) {
		goto failure;
	}
	result = json_add_int(&sub_json, "start", start);
	if (result < 0) {
		goto failure;
	}
	result = json_add_int(&sub_json, "size", size);
	if (result < 0) {
		goto failure;
	}

	result = json_add_object(&locks_json, NULL, &sub_json);
	if (result < 0) {
		goto failure;
	}
	result = json_update_object(parent_json, "locks", &locks_json);
	if (result < 0) {
		goto failure;
	}

	TALLOC_FREE(tmp_ctx);
	return 0;
failure:
	json_free(&locks_json);
	json_free(&sub_json);
	TALLOC_FREE(tmp_ctx);
	return -1;
}

int print_brl_json(struct traverse_state *state,
		   const struct server_id server_id,
		   struct file_id fid,
		   const char *type,
		   enum brl_flavour flavour,
		   intmax_t start,
		   intmax_t size,
		   const char *sharepath,
		   const char *filename)
{
	struct json_object file_json = {
		.valid = false,
	};
	struct json_object brl_json = {
		.valid = false,
	};
	int result = 0;
	char *key;

	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return -1;
	}

	if (sharepath[strlen(sharepath)-1] == '/') {
		key = talloc_asprintf(tmp_ctx, "%s%s", sharepath, filename);
	} else {
		key = talloc_asprintf(tmp_ctx, "%s/%s", sharepath, filename);
	}
	if (key == NULL) {
		goto failure;
	}

	brl_json = json_get_object(&state->root_json, "byte_range_locks");
	if (json_is_invalid(&brl_json)) {
		goto failure;
	}
	file_json = json_get_object(&brl_json, key);
	if (json_is_invalid(&file_json)) {
		goto failure;
	}

	result = add_fileid_to_json(&file_json, fid);
	if (result < 0) {
		goto failure;
	}
	result = json_add_string(&file_json, "file_name", filename);
	if (result < 0) {
		goto failure;
	}
	result = json_add_string(&file_json, "share_path", sharepath);
	if (result < 0) {
		goto failure;
	}
	result = add_server_id_to_json(&file_json, server_id);
	if (result < 0) {
		goto failure;
	}
	result = add_lock_to_json(&file_json, server_id, type, flavour, start, size);
	if (result < 0) {
		goto failure;
	}

	result = json_add_object(&brl_json, key, &file_json);
	if (result < 0) {
		goto failure;
	}
	result = json_update_object(&state->root_json, "byte_range_locks", &brl_json);
	if (result < 0) {
		goto failure;
	 }

	TALLOC_FREE(tmp_ctx);
	return 0;
failure:
	json_free(&file_json);
	json_free(&brl_json);
	TALLOC_FREE(tmp_ctx);
	return -1;
}

bool print_notify_rec_json(struct traverse_state *state,
			   const struct notify_instance *instance,
			   const struct server_id server_id,
			   const char *path)
{
	struct json_object sub_json;
	struct json_object notify_json;
	char *filter = NULL;
	char *subdir_filter = NULL;
	struct timeval_buf tv_buf;
	struct timeval val;
	char *time = NULL;
	char *pid = NULL;
	struct server_id_buf tmp;
	int result = 0;

	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return -1;
	}

	sub_json = json_new_object();
	if (json_is_invalid(&sub_json)) {
		return false;
	}
	notify_json = json_get_object(&state->root_json, "notifies");
	if (json_is_invalid(&notify_json)) {
		goto failure;
	}

	result = add_server_id_to_json(&sub_json, server_id);
	if (result < 0) {
		goto failure;
	}
	result = json_add_string(&sub_json, "path", path);
	if (result < 0) {
		goto failure;
	}
	filter = talloc_asprintf(tmp_ctx, "%u", instance->filter);
	if (filter == NULL) {
		goto failure;
	}
	result = json_add_string(&sub_json, "filter", filter);
	if (result < 0) {
		goto failure;
	}
	subdir_filter = talloc_asprintf(tmp_ctx, "%u", instance->subdir_filter);
	if (subdir_filter == NULL) {
		goto failure;
	}
	result = json_add_string(&sub_json, "subdir_filter", subdir_filter);
	if (result < 0) {
		goto failure;
	}
	val = convert_timespec_to_timeval(instance->creation_time);
	time = timeval_str_buf(&val, true, true, &tv_buf);
	result = json_add_string(&sub_json, "creation_time", time);
	if (result < 0) {
		goto failure;
	}

	pid = server_id_str_buf(server_id, &tmp);
	result = json_add_object(&notify_json, pid, &sub_json);
	if (result < 0) {
		goto failure;
	}

	result = json_update_object(&state->root_json, "notifies", &notify_json);
	if (result < 0) {
		goto failure;
	}

	TALLOC_FREE(tmp_ctx);
	return true;
failure:
	json_free(&sub_json);
	TALLOC_FREE(tmp_ctx);
	return false;
}
