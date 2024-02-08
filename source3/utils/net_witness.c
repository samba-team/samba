/*
 * Samba Unix/Linux client library
 * net witness commands to manage smb witness registrations
 * Copyright (C) 2023 Stefan Metzmacher
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
#include "utils/net.h"
#include "messages.h"
#include "serverid.h"
#include "lib/util/util_tdb.h"
#include "source3/include/util_tdb.h"
#include "libcli/security/dom_sid.h"
#include "lib/dbwrap/dbwrap.h"
#include "lib/dbwrap/dbwrap_rbt.h"
#include "lib/dbwrap/dbwrap_open.h"
#include "lib/param/param.h"
#include "librpc/gen_ndr/ndr_rpcd_witness.h"
#include <regex.h>

struct json_object;

#ifdef HAVE_JANSSON
#include <jansson.h>
#include "audit_logging.h" /* various JSON helpers */
#endif /* HAVE_JANSSON */

#undef strcasecmp

static struct db_context *net_witness_open_registration_db(void)
{
	static struct db_context *db;
	char *global_path = NULL;

	if (db != NULL) {
		return db;
	}

	global_path = lock_path(talloc_tos(), "rpcd_witness_registration.tdb");
	if (global_path == NULL) {
		return NULL;
	}

	db = db_open(NULL,
		     global_path,
		     0, /* hash_size */
		     TDB_DEFAULT |
		     TDB_CLEAR_IF_FIRST |
		     TDB_INCOMPATIBLE_HASH,
		     O_RDONLY,
		     0600,
		     DBWRAP_LOCK_ORDER_1,
		     DBWRAP_FLAG_NONE);
	TALLOC_FREE(global_path);
	if (db == NULL) {
		return NULL;
	}

	return db;
}

struct net_witness_scan_registrations_action_state {
	bool (*prepare_fn)(void *private_data);
	bool (*match_fn)(void *private_data, const struct rpcd_witness_registration *rg);
	NTSTATUS (*process_fn)(void *private_data, const struct rpcd_witness_registration *rg);
	void *private_data;
};

struct net_witness_scan_registrations_regex {
	regex_t regex;
	bool valid;
};

struct net_witness_scan_registrations_state {
	struct net_context *c;
	struct net_witness_scan_registrations_regex net_name;
	struct net_witness_scan_registrations_regex share_name;
	struct net_witness_scan_registrations_regex ip_address;
	struct net_witness_scan_registrations_regex client_computer;
	struct json_object *message_json;
#ifdef HAVE_JANSSON
	struct json_object filters_json;
	struct json_object registrations_json;
#endif
	const struct net_witness_scan_registrations_action_state *action;
	NTSTATUS error;
};

static bool net_witness_scan_registrations_regex_init(
	struct net_witness_scan_registrations_state *state,
	struct net_witness_scan_registrations_regex *r,
	const char *option, const char *value);
static bool net_witness_scan_registrations_regex_match(
	struct net_witness_scan_registrations_regex *r,
	const char *name, const char *value);
static void net_witness_scan_registrations_regex_free(
	struct net_witness_scan_registrations_regex *r);

static bool net_witness_scan_registrations_match(
	struct net_witness_scan_registrations_state *state,
	const struct rpcd_witness_registration *rg)
{
	if (state->net_name.valid) {
		bool match;

		match = net_witness_scan_registrations_regex_match(
							&state->net_name,
							"net_name",
							rg->net_name);
		if (!match) {
			return false;
		}
	}

	if (state->share_name.valid) {
		bool match;

		match = net_witness_scan_registrations_regex_match(
							&state->share_name,
							"share_name",
							rg->share_name);
		if (!match) {
			return false;
		}
	}

	if (state->ip_address.valid) {
		bool match;

		match = net_witness_scan_registrations_regex_match(
							&state->ip_address,
							"ip_address",
							rg->ip_address);
		if (!match) {
			return false;
		}
	}

	if (state->client_computer.valid) {
		bool match;

		match = net_witness_scan_registrations_regex_match(
							&state->client_computer,
							"client_computer_name",
							rg->client_computer_name);
		if (!match) {
			return false;
		}
	}

	return true;
}

static bool net_witness_scan_registrations_regex_init(
	struct net_witness_scan_registrations_state *state,
	struct net_witness_scan_registrations_regex *r,
	const char *option, const char *value)
{
#ifdef HAVE_JANSSON
	struct net_context *c = state->c;
#endif /* HAVE_JANSSON */
	int ret;

	r->valid = false;

	if (value == NULL) {
		return true;
	}

	ret = regcomp(&r->regex, value, REG_EXTENDED|REG_ICASE|REG_NOSUB);
	if (ret != 0) {
		fstring buf = { 0,};
		regerror(ret, &r->regex, buf, sizeof(buf));
		d_printf("regcomp(%s) failed for %s: "
			 "%d: %s\n", value, option, ret, buf);
		return false;
	}

#ifdef HAVE_JANSSON
	if (c->opt_json) {
		ret = json_add_string(&state->filters_json,
				      option,
				      value);
		if (ret != 0) {
			return false;
		}
	}
#endif /* HAVE_JANSSON */

	r->valid = true;
	return true;
}

static bool net_witness_scan_registrations_regex_match(
	struct net_witness_scan_registrations_regex *r,
	const char *name, const char *value)
{
	int ret;

	if (!r->valid) {
		return false;
	}

	if (value == NULL) {
		/*
		 * without a share name,
		 * we match against an empty
		 * string.
		 */
		value = "";
	}

	ret = regexec(&r->regex, value, 0, NULL, 0);
	if (ret == REG_NOMATCH) {
		return false;
	}

	return true;
}

static void net_witness_scan_registrations_regex_free(
	struct net_witness_scan_registrations_regex *r)
{
	if (r->valid) {
		regfree(&r->regex);
		r->valid = false;
	}
}

static bool net_witness_scan_registrations_init(
	struct net_witness_scan_registrations_state *state)
{
	struct net_context *c = state->c;
	bool ok;

	if (c->opt_json) {
#ifdef HAVE_JANSSON
		state->filters_json = json_new_object();
		if (json_is_invalid(&state->filters_json)) {
			return false;
		}

		if (c->opt_witness_registration != NULL) {
			int ret;

			ret = json_add_string(&state->filters_json,
					      "--witness-registration",
					      c->opt_witness_registration);
			if (ret != 0) {
				return false;
			}
		}

		if (c->opt_witness_apply_to_all != 0) {
			int ret;

			ret = json_add_bool(&state->filters_json,
					    "--witness-apply-to-all",
					    c->opt_witness_apply_to_all != 0);
			if (ret != 0) {
				return false;
			}
		}

		state->registrations_json = json_new_object();
		if (json_is_invalid(&state->registrations_json)) {
			return false;
		}
#else /* not HAVE_JANSSON */
		d_fprintf(stderr, _("JSON support not available\n"));
		return false;
#endif /* not HAVE_JANSSON */
	}

	ok = net_witness_scan_registrations_regex_init(state,
						&state->net_name,
						"--witness-net-name",
						c->opt_witness_net_name);
	if (!ok) {
		return false;
	}

	ok = net_witness_scan_registrations_regex_init(state,
						&state->share_name,
						"--witness-share-name",
						c->opt_witness_share_name);
	if (!ok) {
		return false;
	}

	ok = net_witness_scan_registrations_regex_init(state,
						&state->ip_address,
						"--witness-ip-address",
						c->opt_witness_ip_address);
	if (!ok) {
		return false;
	}

	ok = net_witness_scan_registrations_regex_init(state,
						&state->client_computer,
						"--witness-client-computer-name",
						c->opt_witness_client_computer_name);
	if (!ok) {
		return false;
	}

	ok = state->action->prepare_fn(state->action->private_data);
	if (!ok) {
		return false;
	}

	if (!c->opt_json) {
		d_printf("%-36s %-20s %-15s %-20s %s\n",
			 "Registration-UUID:",
			 "NetName",
			 "ShareName",
			 "IpAddress",
			 "ClientComputerName");
		d_printf("%-36s-%-20s-%-15s-%-20s-%s\n",
			 "------------------------------------",
			 "--------------------",
			 "------------------",
			 "--------------------",
			 "------------------");
	}

	return true;
}

static bool net_witness_scan_registrations_finish(
	struct net_witness_scan_registrations_state *state)
{
#ifdef HAVE_JANSSON
	struct net_context *c = state->c;
	struct json_object root_json = json_empty_object;
	TALLOC_CTX *frame = NULL;
	const char *json_str = NULL;
	int ret;

	if (!c->opt_json) {
		return true;
	}

	frame = talloc_stackframe();

	root_json = json_new_object();
	if (json_is_invalid(&root_json)) {
		TALLOC_FREE(frame);
		return false;
	}

	ret = json_add_object(&root_json,
			      "filters",
			      &state->filters_json);
	if (ret != 0) {
		json_free(&root_json);
		TALLOC_FREE(frame);
		return false;
	}
	state->filters_json = json_empty_object;

	if (state->message_json != NULL) {
		ret = json_add_object(&root_json,
				      "message",
				      state->message_json);
		if (ret != 0) {
			json_free(&root_json);
			TALLOC_FREE(frame);
			return false;
		}
		*state->message_json = json_empty_object;
	}

	ret = json_add_object(&root_json,
			      "registrations",
			      &state->registrations_json);
	if (ret != 0) {
		json_free(&root_json);
		TALLOC_FREE(frame);
		return false;
	}
	state->registrations_json = json_empty_object;

	json_str = json_to_string(frame, &root_json);
	json_free(&root_json);
	if (json_str == NULL) {
		TALLOC_FREE(frame);
		return false;
	}

	d_printf("%s\n", json_str);
	TALLOC_FREE(frame);
	return true;
#else /* not HAVE_JANSSON */
	return true;
#endif /* not HAVE_JANSSON */
}

static void net_witness_scan_registrations_free(
	struct net_witness_scan_registrations_state *state)
{
#ifdef HAVE_JANSSON
	if (!json_is_invalid(&state->filters_json)) {
		json_free(&state->filters_json);
	}
	if (!json_is_invalid(&state->registrations_json)) {
		json_free(&state->registrations_json);
	}
#endif /* HAVE_JANSSON */

	net_witness_scan_registrations_regex_free(&state->net_name);
	net_witness_scan_registrations_regex_free(&state->share_name);
	net_witness_scan_registrations_regex_free(&state->ip_address);
	net_witness_scan_registrations_regex_free(&state->client_computer);
}

#ifdef HAVE_JANSSON
static int dump_registration_json(struct json_object *registrations_json,
				  const char *key_str,
				  const struct rpcd_witness_registration *rg)
{
	struct json_object jsobj = json_empty_object;
	struct json_object flags_json = json_empty_object;
	struct json_object context_json = json_empty_object;
	struct json_object serverid_json = json_empty_object;
	struct json_object auth_json = json_empty_object;
	struct json_object connection_json = json_empty_object;
	struct timeval tv;
	struct dom_sid_buf sid_buf;
	int ret = 0;

	jsobj = json_new_object();
	if (json_is_invalid(&jsobj)) {
		d_fprintf(stderr, _("error setting up JSON value\n"));
		goto failure;
	}

	ret = json_add_flags32(&jsobj, "version", rg->version);
	if (ret != 0) {
		goto failure;
	}

	ret = json_add_string(&jsobj, "net_name", rg->net_name);
	if (ret != 0) {
		goto failure;
	}

	ret = json_add_string(&jsobj, "share_name", rg->share_name);
	if (ret != 0) {
		goto failure;
	}

	ret = json_add_string(&jsobj, "ip_address", rg->ip_address);
	if (ret != 0) {
		goto failure;
	}

	ret = json_add_string(&jsobj, "client_computer_name", rg->client_computer_name);
	if (ret != 0) {
		goto failure;
	}

	flags_json = json_new_object();
	if (json_is_invalid(&flags_json)) {
		goto failure;
	}

	ret = json_add_bool(&flags_json, "WITNESS_REGISTER_IP_NOTIFICATION",
			    (rg->flags & WITNESS_REGISTER_IP_NOTIFICATION) ?
			    true : false);
	if (ret != 0) {
		goto failure;
	}

	ret = json_add_int(&flags_json, "int", rg->flags);
	if (ret != 0) {
		goto failure;
	}

	ret = json_add_flags32(&flags_json, "hex", rg->flags);
	if (ret != 0) {
		goto failure;
	}

	ret = json_add_object(&jsobj, "flags", &flags_json);
	if (ret != 0) {
		goto failure;
	}
	flags_json = json_empty_object;

	ret = json_add_int(&jsobj, "timeout", rg->timeout);
	if (ret != 0) {
		goto failure;
	}

	context_json = json_new_object();
	if (json_is_invalid(&context_json)) {
		goto failure;
	}

	ret = json_add_int(&context_json, "handle_type", rg->context_handle.handle_type);
	if (ret != 0) {
		goto failure;
	}

	ret = json_add_guid(&context_json, "uuid", &rg->context_handle.uuid);
	if (ret != 0) {
		goto failure;
	}

	ret = json_add_object(&jsobj, "context_handle", &context_json);
	if (ret != 0) {
		goto failure;
	}
	context_json = json_empty_object;

	serverid_json = json_new_object();
	if (json_is_invalid(&serverid_json)) {
		goto failure;
	}

	ret = json_add_int(&serverid_json, "pid", rg->server_id.pid);
	if (ret != 0) {
		goto failure;
	}

	ret = json_add_int(&serverid_json, "task_id", rg->server_id.task_id);
	if (ret != 0) {
		goto failure;
	}

	ret = json_add_int(&serverid_json, "vnn", rg->server_id.vnn);
	if (ret != 0) {
		goto failure;
	}

	ret = json_add_int(&serverid_json, "unique_id", rg->server_id.unique_id);
	if (ret != 0) {
		goto failure;
	}

	ret = json_add_object(&jsobj, "server_id", &serverid_json);
	if (ret != 0) {
		goto failure;
	}
	serverid_json = json_empty_object;

	auth_json = json_new_object();
	if (json_is_invalid(&auth_json)) {
		goto failure;
	}

	ret = json_add_string(&auth_json, "account_name", rg->account_name);
	if (ret != 0) {
		goto failure;
	}

	ret = json_add_string(&auth_json, "domain_name", rg->domain_name);
	if (ret != 0) {
		goto failure;
	}

	ret = json_add_string(&auth_json,
			      "account_sid",
			      dom_sid_str_buf(&rg->account_sid, &sid_buf));
	if (ret != 0) {
		goto failure;
	}

	ret = json_add_object(&jsobj, "auth", &auth_json);
	if (ret != 0) {
		goto failure;
	}
	auth_json = json_empty_object;

	connection_json = json_new_object();
	if (json_is_invalid(&connection_json)) {
		goto failure;
	}

	ret = json_add_string(&connection_json, "local_address", rg->local_address);
	if (ret != 0) {
		goto failure;
	}

	ret = json_add_string(&connection_json, "remote_address", rg->remote_address);
	if (ret != 0) {
		goto failure;
	}

	ret = json_add_object(&jsobj, "connection", &connection_json);
	if (ret != 0) {
		goto failure;
	}
	connection_json = json_empty_object;

	nttime_to_timeval(&tv, rg->registration_time);
	ret = json_add_time(&jsobj, "registration_time", tv);
	if (ret != 0) {
		goto failure;
	}

	ret = json_add_object(registrations_json, key_str, &jsobj);
	if (ret != 0) {
		goto failure;
	}
	jsobj = json_empty_object;

failure:
	if (!json_is_invalid(&connection_json)) {
		json_free(&connection_json);
	}
	if (!json_is_invalid(&auth_json)) {
		json_free(&auth_json);
	}
	if (!json_is_invalid(&serverid_json)) {
		json_free(&serverid_json);
	}
	if (!json_is_invalid(&context_json)) {
		json_free(&context_json);
	}
	if (!json_is_invalid(&flags_json)) {
		json_free(&flags_json);
	}
	if (!json_is_invalid(&jsobj)) {
		json_free(&jsobj);
	}

	return ret;
}
#endif /* HAVE_JANSSON */

static NTSTATUS net_witness_scan_registrations_dump_rg(
			struct net_witness_scan_registrations_state *state,
			const struct rpcd_witness_registration *rg)
{
	struct net_context *c = state->c;
	struct GUID_txt_buf key_buf;
	const char *key_str = GUID_buf_string(&rg->context_handle.uuid, &key_buf);

	if (c->opt_json) {
#ifdef HAVE_JANSSON
		int ret;

		ret = dump_registration_json(&state->registrations_json,
					     key_str,
					     rg);
		if (ret != 0) {
			d_fprintf(stderr, "dump_registration_json(%s) failed\n",
				  key_str);
			return NT_STATUS_INTERNAL_ERROR;
		}
#endif /* HAVE_JANSSON */
		return NT_STATUS_OK;
	}

	d_printf("%-36s %-20s %-15s %-20s %s\n",
		 key_str,
		 rg->net_name,
		 rg->share_name ? rg->share_name : "''",
		 rg->ip_address,
		 rg->client_computer_name);

	return NT_STATUS_OK;
}

static void net_witness_scan_registrations_parser(TDB_DATA key,
						  TDB_DATA val,
						  void *private_data)
{
	struct net_witness_scan_registrations_state *state =
		(struct net_witness_scan_registrations_state *)private_data;
	DATA_BLOB val_blob = data_blob_const(val.dptr, val.dsize);
	struct rpcd_witness_registration rg;
	enum ndr_err_code ndr_err;
	TALLOC_CTX *frame = NULL;
	bool match = false;

	if (val_blob.length == 0) {
		return;
	}

	frame = talloc_stackframe();

	ndr_err = ndr_pull_struct_blob(&val_blob, frame, &rg,
			(ndr_pull_flags_fn_t)ndr_pull_rpcd_witness_registration);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DBG_WARNING("Invalid record in rpcd_witness_registration.tdb:"
			 "key '%s' ndr_pull_struct_blob - %s\n",
			 tdb_data_dbg(key),
			 ndr_errstr(ndr_err));
		state->error = ndr_map_error2ntstatus(ndr_err);
		TALLOC_FREE(frame);
		return;
	}

	if (!serverid_exists(&rg.server_id)) {
		TALLOC_FREE(frame);
		return;
	}

	if (CHECK_DEBUGLVL(DBGLVL_DEBUG)) {
		NDR_PRINT_DEBUG(rpcd_witness_registration, &rg);
	}

	match = net_witness_scan_registrations_match(state, &rg);
	if (!NT_STATUS_IS_OK(state->error)) {
		TALLOC_FREE(frame);
		return;
	}
	if (!match) {
		TALLOC_FREE(frame);
		return;
	}

	match = state->action->match_fn(state->action->private_data, &rg);
	if (!match) {
		TALLOC_FREE(frame);
		return;
	}

	state->error = state->action->process_fn(state->action->private_data, &rg);
	if (NT_STATUS_IS_OK(state->error)) {
		state->error = net_witness_scan_registrations_dump_rg(state,
								      &rg);
	}
	TALLOC_FREE(frame);
}

static int net_witness_scan_registrations_traverse_cb(struct db_record *rec, void *private_data)
{
	struct net_witness_scan_registrations_state *state =
		(struct net_witness_scan_registrations_state *)private_data;
	TDB_DATA key = dbwrap_record_get_key(rec);
	TDB_DATA val = dbwrap_record_get_value(rec);

	net_witness_scan_registrations_parser(key, val, private_data);

	if (!NT_STATUS_IS_OK(state->error)) {
		return -1;
	}

	return 0;
}

static int net_witness_scan_registrations(struct net_context *c,
	struct json_object *message_json,
	const struct net_witness_scan_registrations_action_state *action)
{
	struct net_witness_scan_registrations_state state = {
		.c = c,
		.message_json = message_json,
		.action = action,
	};
	struct db_context *db = NULL;
	NTSTATUS status;
	bool ok;

	db = net_witness_open_registration_db();
	if (db == NULL) {
		d_printf("net_witness_open_registration_db() failed\n");
		return -1;
	}

	ok = net_witness_scan_registrations_init(&state);
	if (!ok) {
		d_printf("net_witness_scan_registrations_init() failed\n");
		return -1;
	}

	if (c->opt_witness_registration != NULL) {
		const char *key_str = c->opt_witness_registration;
		DATA_BLOB key_blob = data_blob_string_const(key_str);
		TDB_DATA key = make_tdb_data(key_blob.data, key_blob.length);

		status = dbwrap_parse_record(db,
					     key,
					     net_witness_scan_registrations_parser,
					     &state);
		if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
			status = NT_STATUS_OK;
		}
		if (!NT_STATUS_IS_OK(status)) {
			d_printf("dbwrap_parse_record(%s) failed: %s\n",
				 key_str, nt_errstr(status));
			net_witness_scan_registrations_free(&state);
			return -1;
		}
		if (!NT_STATUS_IS_OK(state.error)) {
			d_printf("net_witness_scan_registrations_parser(%s) failed: %s\n",
				 key_str, nt_errstr(state.error));
			net_witness_scan_registrations_free(&state);
			return -1;
		}
	} else {
		status = dbwrap_traverse_read(db,
					      net_witness_scan_registrations_traverse_cb,
					      &state,
					      NULL); /* count */
		if (!NT_STATUS_IS_OK(status)) {
			d_printf("dbwrap_traverse_read() failed\n");
			net_witness_scan_registrations_free(&state);
			return -1;
		}
		if (!NT_STATUS_IS_OK(state.error)) {
			d_printf("net_witness_scan_registrations_traverse_cb() failed: %s\n",
				 nt_errstr(state.error));
			net_witness_scan_registrations_free(&state);
			return -1;
		}
	}

	ok = net_witness_scan_registrations_finish(&state);
	if (!ok) {
		d_printf("net_witness_scan_registrations_finish() failed\n");
		return -1;
	}

	net_witness_scan_registrations_free(&state);
	return 0;
}

struct net_witness_list_state {
	struct net_context *c;
};

static bool net_witness_list_prepare_fn(void *private_data)
{
	return true;
}

static bool net_witness_list_match_fn(void *private_data,
			const struct rpcd_witness_registration *rg)
{
	return true;
}

static NTSTATUS net_witness_list_process_fn(void *private_data,
			const struct rpcd_witness_registration *rg)
{
	return NT_STATUS_OK;
}

static void net_witness_filter_usage(void)
{
	d_printf("    Note: Only supported with clustering=yes!\n\n");
	d_printf("    Machine readable output can be generated with "
		      "the following option:\n"
		 "\n"
		 "        --json\n"
		 "\n");
	d_printf("    The selection of registrations can be limited by "
		      "the following options:\n"
		 "\n"
		 "        --witness-registration=REGISTRATION_UUID\n"
		 "          This does a direct lookup for REGISTRATION_UUID\n"
		 "          instead of doing a database traversal.\n"
		 "\n"
		 "    The following options all take a "
		     "POSIX Extended Regular Expression,\n"
		 "    which can further filter the selection of "
		     "registrations.\n"
		 "    These options are applied as logical AND, "
		     "but each REGEX \n"
		 "    allows specifying multiple strings using "
		     "the pipe symbol.\n"
		 "\n"
		 "        --witness-net-name=REGEX\n"
		 "          This specifies the 'server name' the client\n"
		 "          registered for monitoring.\n"
		 "\n"
		 "        --witness-share-name=REGEX\n"
		 "          This specifies the 'share name' the client\n"
		 "          registered for monitoring.\n"
		 "          Note that the share name is optional in the\n"
		 "          registration, otherwise an empty string is \n"
		 "          matched.\n"
		 "\n"
		 "        --witness-ip-address=REGEX\n"
		 "          This specifies the ip address the client\n"
		 "          registered for monitoring.\n"
		 "\n"
		 "        --witness-client-computer-name=REGEX\n"
		 "          This specifies the client computer name the client\n"
		 "          specified in the registration.\n"
		 "          Note it is just a string chosen by the "
		           "client itself.\n"
		 "\n");
}

static void net_witness_list_usage(void)
{
	d_printf("%s\n"
		 "net witness list\n"
		 "    %s\n\n",
		 _("Usage:"),
		 _("List witness registrations "
		   "from rpcd_witness_registration.tdb"));
	net_witness_filter_usage();
}

static int net_witness_list(struct net_context *c, int argc, const char **argv)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct net_witness_list_state state = { .c = c, };
	struct net_witness_scan_registrations_action_state action = {
		.prepare_fn = net_witness_list_prepare_fn,
		.match_fn = net_witness_list_match_fn,
		.process_fn = net_witness_list_process_fn,
		.private_data = &state,
	};
	int ret = -1;

	if (c->display_usage) {
		net_witness_list_usage();
		goto out;
	}

	if (argc != 0) {
		net_witness_list_usage();
		goto out;
	}

	if (!lp_clustering()) {
		d_printf("ERROR: Only supported with clustering=yes!\n\n");
		goto out;
	}

	ret = net_witness_scan_registrations(c, NULL, &action);
	if (ret != 0) {
		d_printf("net_witness_scan_registrations() failed\n");
		goto out;
	}

	ret = 0;
out:
	TALLOC_FREE(frame);
	return ret;
}

struct net_witness_client_move_state {
	struct net_context *c;
	struct rpcd_witness_registration_updateB m;
	char *headline;
};

static bool net_witness_client_move_prepare_fn(void *private_data)
{
	struct net_witness_client_move_state *state =
		(struct net_witness_client_move_state *)private_data;

	if (state->headline != NULL) {
		d_printf("%s\n", state->headline);
		TALLOC_FREE(state->headline);
	}

	return true;
}

static bool net_witness_client_move_match_fn(void *private_data,
			const struct rpcd_witness_registration *rg)
{
	return true;
}

static NTSTATUS net_witness_client_move_process_fn(void *private_data,
			const struct rpcd_witness_registration *rg)
{
	struct net_witness_client_move_state *state =
		(struct net_witness_client_move_state *)private_data;
	struct net_context *c = state->c;
	struct rpcd_witness_registration_updateB update = {
		.context_handle = rg->context_handle,
		.type = state->m.type,
		.update = state->m.update,
	};
	DATA_BLOB blob = { .length = 0, };
	enum ndr_err_code ndr_err;
	NTSTATUS status;

	if (state->headline != NULL) {
		d_printf("%s\n", state->headline);
		TALLOC_FREE(state->headline);
	}

	SMB_ASSERT(update.type != 0);

	if (DEBUGLVL(DBGLVL_DEBUG)) {
		NDR_PRINT_DEBUG(rpcd_witness_registration_updateB, &update);
	}

	ndr_err = ndr_push_struct_blob(&blob, talloc_tos(), &update,
			(ndr_push_flags_fn_t)ndr_push_rpcd_witness_registration_updateB);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		status = ndr_map_error2ntstatus(ndr_err);
		DBG_ERR("ndr_push_struct_blob - %s\n", nt_errstr(status));
		return status;
	}

	status = messaging_send(c->msg_ctx,
				rg->server_id,
				MSG_RPCD_WITNESS_REGISTRATION_UPDATE,
				&blob);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("messaging_send() - %s\n", nt_errstr(status));
		return status;
	}

	return NT_STATUS_OK;
}

static void net_witness_update_usage(void)
{
	d_printf("    If the update should be applied to all registrations\n"
		 "    it needs to be explicitly specified:\n"
		 "\n"
		 "        --witness-apply-to-all\n"
		 "          This selects all registrations.\n"
		 "          Note: This is mutual exclusive to "
		           "the above options.\n"
		 "\n");
}

static bool net_witness_verify_update_options(struct net_context *c)
{
	if (c->opt_witness_registration == NULL &&
	    c->opt_witness_net_name == NULL &&
	    c->opt_witness_share_name == NULL &&
	    c->opt_witness_ip_address == NULL &&
	    c->opt_witness_client_computer_name == NULL &&
	    c->opt_witness_apply_to_all == 0)
	{
		d_printf("--witness-apply-to-all or "
			 "at least one of following requires:\n"
			 "--witness-registration\n"
			 "--witness-net-name\n"
			 "--witness-share-name\n"
			 "--witness-ip-address\n"
			 "--witness-client-computer-name\n");
		return false;
	}

	if (c->opt_witness_apply_to_all == 0) {
		return true;
	}

	if (c->opt_witness_registration != NULL ||
	    c->opt_witness_net_name != NULL ||
	    c->opt_witness_share_name != NULL ||
	    c->opt_witness_ip_address != NULL ||
	    c->opt_witness_client_computer_name != NULL)
	{
		d_printf("--witness-apply-to-all not allowed "
			 "together with the following options:\n"
			 "--witness-registration\n"
			 "--witness-net-name\n"
			 "--witness-share-name\n"
			 "--witness-ip-address\n"
			 "--witness-client-computer-name\n");
		return false;
	}

	return true;
}

static void net_witness_move_usage(const char *name)
{
	d_printf("    The content of the %s notification contains ip addresses\n"
		 "    specified by (exactly one) of the following options:\n"
		 "\n"
		 "        --witness-new-node=NODEID\n"
		 "          By specifying a NODEID all ip addresses\n"
		 "          currently available on the given node are\n"
		 "          included in the response.\n"
		 "          By specifying '-1' as NODEID all ip addresses\n"
		 "          of the cluster are included in the response.\n"
		 "\n"
		 "        --witness-new-ip=IPADDRESS\n"
		 "          By specifying an IPADDRESS only the specified\n"
		 "          ip address is included in the response.\n"
		 "\n",
		 name);
}

static bool net_witness_verify_move_options(struct net_context *c,
					    uint32_t *new_node,
					    bool *is_ipv4,
					    bool *is_ipv6)
{
	bool ok;

	*new_node = NONCLUSTER_VNN;
	*is_ipv4 = false;
	*is_ipv6 = false;

	ok = net_witness_verify_update_options(c);
	if (!ok) {
		return false;
	}

	if (c->opt_witness_new_ip != NULL &&
	    c->opt_witness_new_node != -2)
	{
		d_printf("--witness-new-ip and "
			 "--witness-new-node are not allowed together\n");
		return false;
	}

	if (c->opt_witness_new_ip == NULL &&
	    c->opt_witness_new_node == -2)
	{
		d_printf("--witness-new-ip or --witness-new-node required\n");
		return false;
	}

	if (c->opt_witness_new_node != -2) {
		*new_node = c->opt_witness_new_node;
		return true;
	}

	if (is_ipaddress_v4(c->opt_witness_new_ip)) {
		*is_ipv4 = true;
		return true;
	}

	if (is_ipaddress_v6(c->opt_witness_new_ip)) {
		*is_ipv6 = true;
		return true;
	}

	d_printf("Invalid ip address for --witness-new-ip=%s\n",
		 c->opt_witness_new_ip);
	return false;
}

#ifdef HAVE_JANSSON
static bool net_witness_move_message_json(struct net_context *c,
					  const char *msg_type,
					  struct json_object *pmessage_json)
{
	struct json_object message_json = json_empty_object;
	int ret;

	message_json = json_new_object();
	if (json_is_invalid(&message_json)) {
		return false;
	}

	ret = json_add_string(&message_json,
			      "type",
			      msg_type);
	if (ret != 0) {
		json_free(&message_json);
		return false;
	}

	if (c->opt_witness_new_ip != NULL) {
		ret = json_add_string(&message_json,
				      "new_ip",
				      c->opt_witness_new_ip);
		if (ret != 0) {
			return false;
		}
	} else if (c->opt_witness_new_node != -1) {
		ret = json_add_int(&message_json,
				   "new_node",
				   c->opt_witness_new_node);
		if (ret != 0) {
			return false;
		}
	} else {
		ret = json_add_bool(&message_json,
				    "all_nodes",
				    true);
		if (ret != 0) {
			return false;
		}
	}

	*pmessage_json = message_json;
	return true;
}
#endif /* HAVE_JANSSON */

static void net_witness_client_move_usage(void)
{
	d_printf("%s\n"
		 "net witness client-move\n"
		 "    %s\n\n",
		 _("Usage:"),
		 _("Generate client move notifications for "
		   "witness registrations to a new ip or node"));
	net_witness_filter_usage();
	net_witness_update_usage();
	net_witness_move_usage("CLIENT_MOVE");
}

static int net_witness_client_move(struct net_context *c, int argc, const char **argv)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct net_witness_client_move_state state = { .c = c, };
	struct rpcd_witness_registration_updateB *m = &state.m;
#ifdef HAVE_JANSSON
	struct json_object _message_json = json_empty_object;
#endif /* HAVE_JANSSON */
	struct json_object *message_json = NULL;
	struct net_witness_scan_registrations_action_state action = {
		.prepare_fn = net_witness_client_move_prepare_fn,
		.match_fn = net_witness_client_move_match_fn,
		.process_fn = net_witness_client_move_process_fn,
		.private_data = &state,
	};
	int ret = -1;
	const char *msg_type = NULL;
	uint32_t new_node = NONCLUSTER_VNN;
	bool is_ipv4 = false;
	bool is_ipv6 = false;
	bool ok;

	if (c->display_usage) {
		net_witness_client_move_usage();
		goto out;
	}

	if (argc != 0) {
		net_witness_client_move_usage();
		goto out;
	}

	if (!lp_clustering()) {
		d_printf("ERROR: Only supported with clustering=yes!\n\n");
		goto out;
	}

	ok = net_witness_verify_move_options(c, &new_node, &is_ipv4, &is_ipv6);
	if (!ok) {
		goto out;
	}

	if (is_ipv4) {
		m->type = RPCD_WITNESS_REGISTRATION_UPDATE_CLIENT_MOVE_TO_IPV4;
		m->update.client_move_to_ipv4.new_ipv4 = c->opt_witness_new_ip;
		msg_type = "CLIENT_MOVE_TO_IPV4";
		state.headline = talloc_asprintf(frame,
						 "CLIENT_MOVE_TO_IPV4: %s",
						 c->opt_witness_new_ip);
		if (state.headline == NULL) {
			goto out;
		}
	} else if (is_ipv6) {
		m->type = RPCD_WITNESS_REGISTRATION_UPDATE_CLIENT_MOVE_TO_IPV6;
		m->update.client_move_to_ipv6.new_ipv6 = c->opt_witness_new_ip;
		msg_type = "CLIENT_MOVE_TO_IPV6";
		state.headline = talloc_asprintf(frame,
						 "CLIENT_MOVE_TO_IPV6: %s",
						 c->opt_witness_new_ip);
		if (state.headline == NULL) {
			goto out;
		}
	} else if (new_node != NONCLUSTER_VNN) {
		m->type = RPCD_WITNESS_REGISTRATION_UPDATE_CLIENT_MOVE_TO_NODE;
		m->update.client_move_to_node.new_node = new_node;
		msg_type = "CLIENT_MOVE_TO_NODE";
		state.headline = talloc_asprintf(frame,
						 "CLIENT_MOVE_TO_NODE: %u",
						 new_node);
		if (state.headline == NULL) {
			goto out;
		}
	} else {
		m->type = RPCD_WITNESS_REGISTRATION_UPDATE_CLIENT_MOVE_TO_NODE;
		m->update.client_move_to_node.new_node = NONCLUSTER_VNN;
		msg_type = "CLIENT_MOVE_TO_NODE";
		state.headline = talloc_asprintf(frame,
						 "CLIENT_MOVE_TO_NODE: ALL");
		if (state.headline == NULL) {
			goto out;
		}
	}

#ifdef HAVE_JANSSON
	if (c->opt_json) {
		TALLOC_FREE(state.headline);

		ok = net_witness_move_message_json(c,
						   msg_type,
						   &_message_json);
		if (!ok) {
			d_printf("net_witness_move_message_json(%s) failed\n",
				 msg_type);
			goto out;
		}

		message_json = &_message_json;
	}
#else /* not HAVE_JANSSON */
	(void)msg_type;
#endif /* not HAVE_JANSSON */

	ret = net_witness_scan_registrations(c, message_json, &action);
	if (ret != 0) {
		d_printf("net_witness_scan_registrations() failed\n");
		goto out;
	}

	ret = 0;
out:
#ifdef HAVE_JANSSON
	if (!json_is_invalid(&_message_json)) {
		json_free(&_message_json);
	}
#endif /* HAVE_JANSSON */
	TALLOC_FREE(frame);
	return ret;
}

struct net_witness_share_move_state {
	struct net_context *c;
	struct rpcd_witness_registration_updateB m;
	char *headline;
};

static bool net_witness_share_move_prepare_fn(void *private_data)
{
	struct net_witness_share_move_state *state =
		(struct net_witness_share_move_state *)private_data;

	if (state->headline != NULL) {
		d_printf("%s\n", state->headline);
		TALLOC_FREE(state->headline);
	}

	return true;
}

static bool net_witness_share_move_match_fn(void *private_data,
			const struct rpcd_witness_registration *rg)
{
	if (rg->share_name == NULL) {
		return false;
	}

	return true;
}

static NTSTATUS net_witness_share_move_process_fn(void *private_data,
			const struct rpcd_witness_registration *rg)
{
	struct net_witness_share_move_state *state =
		(struct net_witness_share_move_state *)private_data;
	struct net_context *c = state->c;
	struct rpcd_witness_registration_updateB update = {
		.context_handle = rg->context_handle,
		.type = state->m.type,
		.update = state->m.update,
	};
	DATA_BLOB blob = { .length = 0, };
	enum ndr_err_code ndr_err;
	NTSTATUS status;

	SMB_ASSERT(update.type != 0);

	if (DEBUGLVL(DBGLVL_DEBUG)) {
		NDR_PRINT_DEBUG(rpcd_witness_registration_updateB, &update);
	}

	ndr_err = ndr_push_struct_blob(&blob, talloc_tos(), &update,
			(ndr_push_flags_fn_t)ndr_push_rpcd_witness_registration_updateB);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		status = ndr_map_error2ntstatus(ndr_err);
		DBG_ERR("ndr_push_struct_blob - %s\n", nt_errstr(status));
		return status;
	}

	status = messaging_send(c->msg_ctx,
				rg->server_id,
				MSG_RPCD_WITNESS_REGISTRATION_UPDATE,
				&blob);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("messaging_send() - %s\n", nt_errstr(status));
		return status;
	}

	return NT_STATUS_OK;
}

static void net_witness_share_move_usage(void)
{
	d_printf("%s\n"
		 "net witness share-move\n"
		 "    %s\n\n",
		 _("Usage:"),
		 _("Generate share move notifications for "
		   "witness registrations to a new ip or node"));
	net_witness_filter_usage();
	net_witness_update_usage();
	d_printf("    Note: This only applies to registrations with "
		     "a non empty share name!\n\n");
	net_witness_move_usage("SHARE_MOVE");
}

static int net_witness_share_move(struct net_context *c, int argc, const char **argv)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct net_witness_share_move_state state = { .c = c, };
	struct rpcd_witness_registration_updateB *m = &state.m;
#ifdef HAVE_JANSSON
	struct json_object _message_json = json_empty_object;
#endif /* HAVE_JANSSON */
	struct json_object *message_json = NULL;
	struct net_witness_scan_registrations_action_state action = {
		.prepare_fn = net_witness_share_move_prepare_fn,
		.match_fn = net_witness_share_move_match_fn,
		.process_fn = net_witness_share_move_process_fn,
		.private_data = &state,
	};
	int ret = -1;
	const char *msg_type = NULL;
	uint32_t new_node = NONCLUSTER_VNN;
	bool is_ipv4 = false;
	bool is_ipv6 = false;
	bool ok;

	if (c->display_usage) {
		net_witness_share_move_usage();
		goto out;
	}

	if (argc != 0) {
		net_witness_share_move_usage();
		goto out;
	}

	if (!lp_clustering()) {
		d_printf("ERROR: Only supported with clustering=yes!\n\n");
		goto out;
	}

	ok = net_witness_verify_move_options(c, &new_node, &is_ipv4, &is_ipv6);
	if (!ok) {
		goto out;
	}

	if (is_ipv4) {
		m->type = RPCD_WITNESS_REGISTRATION_UPDATE_SHARE_MOVE_TO_IPV4;
		m->update.share_move_to_ipv4.new_ipv4 = c->opt_witness_new_ip;
		msg_type = "SHARE_MOVE_TO_IPV4";
		state.headline = talloc_asprintf(frame,
						 "SHARE_MOVE_TO_IPV4: %s",
						 c->opt_witness_new_ip);
		if (state.headline == NULL) {
			goto out;
		}
	} else if (is_ipv6) {
		m->type = RPCD_WITNESS_REGISTRATION_UPDATE_SHARE_MOVE_TO_IPV6;
		m->update.share_move_to_ipv6.new_ipv6 = c->opt_witness_new_ip;
		msg_type = "SHARE_MOVE_TO_IPV6";
		state.headline = talloc_asprintf(frame,
						 "SHARE_MOVE_TO_IPV6: %s",
						 c->opt_witness_new_ip);
		if (state.headline == NULL) {
			goto out;
		}
	} else if (new_node != NONCLUSTER_VNN) {
		m->type = RPCD_WITNESS_REGISTRATION_UPDATE_SHARE_MOVE_TO_NODE;
		m->update.share_move_to_node.new_node = new_node;
		msg_type = "SHARE_MOVE_TO_NODE";
		state.headline = talloc_asprintf(frame,
						 "SHARE_MOVE_TO_NODE: %u",
						 new_node);
		if (state.headline == NULL) {
			goto out;
		}
	} else {
		m->type = RPCD_WITNESS_REGISTRATION_UPDATE_SHARE_MOVE_TO_NODE;
		m->update.share_move_to_node.new_node = NONCLUSTER_VNN;
		msg_type = "SHARE_MOVE_TO_NODE";
		state.headline = talloc_asprintf(frame,
						 "SHARE_MOVE_TO_NODE: ALL");
		if (state.headline == NULL) {
			goto out;
		}
	}

#ifdef HAVE_JANSSON
	if (c->opt_json) {
		TALLOC_FREE(state.headline);

		ok = net_witness_move_message_json(c,
						   msg_type,
						   &_message_json);
		if (!ok) {
			d_printf("net_witness_move_message_json(%s) failed\n",
				 msg_type);
			goto out;
		}

		message_json = &_message_json;
	}
#else /* not HAVE_JANSSON */
	(void)msg_type;
#endif /* not HAVE_JANSSON */

	ret = net_witness_scan_registrations(c, message_json, &action);
	if (ret != 0) {
		d_printf("net_witness_scan_registrations() failed\n");
		goto out;
	}

	ret = 0;
out:
#ifdef HAVE_JANSSON
	if (!json_is_invalid(&_message_json)) {
		json_free(&_message_json);
	}
#endif /* HAVE_JANSSON */
	TALLOC_FREE(frame);
	return ret;
}

struct net_witness_force_unregister_state {
	struct net_context *c;
	struct rpcd_witness_registration_updateB m;
	char *headline;
};

static bool net_witness_force_unregister_prepare_fn(void *private_data)
{
	struct net_witness_force_unregister_state *state =
		(struct net_witness_force_unregister_state *)private_data;

	if (state->headline != NULL) {
		d_printf("%s\n", state->headline);
		TALLOC_FREE(state->headline);
	}

	return true;
}

static bool net_witness_force_unregister_match_fn(void *private_data,
			const struct rpcd_witness_registration *rg)
{
	return true;
}

static NTSTATUS net_witness_force_unregister_process_fn(void *private_data,
			const struct rpcd_witness_registration *rg)
{
	struct net_witness_force_unregister_state *state =
		(struct net_witness_force_unregister_state *)private_data;
	struct net_context *c = state->c;
	struct rpcd_witness_registration_updateB update = {
		.context_handle = rg->context_handle,
		.type = state->m.type,
		.update = state->m.update,
	};
	DATA_BLOB blob = { .length = 0, };
	enum ndr_err_code ndr_err;
	NTSTATUS status;

	SMB_ASSERT(update.type != 0);

	if (DEBUGLVL(DBGLVL_DEBUG)) {
		NDR_PRINT_DEBUG(rpcd_witness_registration_updateB, &update);
	}

	ndr_err = ndr_push_struct_blob(&blob, talloc_tos(), &update,
			(ndr_push_flags_fn_t)ndr_push_rpcd_witness_registration_updateB);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		status = ndr_map_error2ntstatus(ndr_err);
		DBG_ERR("ndr_push_struct_blob - %s\n", nt_errstr(status));
		return status;
	}

	status = messaging_send(c->msg_ctx,
				rg->server_id,
				MSG_RPCD_WITNESS_REGISTRATION_UPDATE,
				&blob);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("messaging_send() - %s\n", nt_errstr(status));
		return status;
	}

	return NT_STATUS_OK;
}

static void net_witness_force_unregister_usage(void)
{
	d_printf("%s\n"
		 "net witness force-unregister\n"
		 "    %s\n\n",
		 _("Usage:"),
		 _("Force unregistrations for witness registrations"));
	net_witness_filter_usage();
	net_witness_update_usage();
	d_printf("    The selected registrations are removed on "
		     "the server and\n"
		 "    any pending AsyncNotify request will get "
		     "a NOT_FOUND error.\n"
		 "\n"
		 "    Typically this triggers a clean re-registration "
		     "on the client.\n"
		 "\n");
}

static int net_witness_force_unregister(struct net_context *c, int argc, const char **argv)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct net_witness_force_unregister_state state = { .c = c, };
	struct rpcd_witness_registration_updateB *m = &state.m;
#ifdef HAVE_JANSSON
	struct json_object _message_json = json_empty_object;
#endif /* HAVE_JANSSON */
	struct json_object *message_json = NULL;
	struct net_witness_scan_registrations_action_state action = {
		.prepare_fn = net_witness_force_unregister_prepare_fn,
		.match_fn = net_witness_force_unregister_match_fn,
		.process_fn = net_witness_force_unregister_process_fn,
		.private_data = &state,
	};
	int ret = -1;
	bool ok;

	if (c->display_usage) {
		net_witness_force_unregister_usage();
		goto out;
	}

	if (argc != 0) {
		net_witness_force_unregister_usage();
		goto out;
	}

	if (!lp_clustering()) {
		d_printf("ERROR: Only supported with clustering=yes!\n\n");
		goto out;
	}

	ok = net_witness_verify_update_options(c);
	if (!ok) {
		goto out;
	}

	m->type = RPCD_WITNESS_REGISTRATION_UPDATE_FORCE_UNREGISTER;

	state.headline = talloc_asprintf(frame, "FORCE_UNREGISTER:");
	if (state.headline == NULL) {
		goto out;
	}

#ifdef HAVE_JANSSON
	if (c->opt_json) {
		TALLOC_FREE(state.headline);

		_message_json = json_new_object();
		if (json_is_invalid(&_message_json)) {
			goto out;
		}

		ret = json_add_string(&_message_json,
				      "type",
				      "FORCE_UNREGISTER");
		if (ret != 0) {
			goto out;
		}

		message_json = &_message_json;
	}
#endif /* HAVE_JANSSON */

	ret = net_witness_scan_registrations(c, message_json, &action);
	if (ret != 0) {
		d_printf("net_witness_scan_registrations() failed\n");
		goto out;
	}

	ret = 0;
out:
#ifdef HAVE_JANSSON
	if (!json_is_invalid(&_message_json)) {
		json_free(&_message_json);
	}
#endif /* HAVE_JANSSON */
	TALLOC_FREE(frame);
	return ret;
}

struct net_witness_force_response_state {
	struct net_context *c;
	struct rpcd_witness_registration_updateB m;
#ifdef HAVE_JANSSON
	struct json_object json_root;
#endif /* HAVE_JANSSON */
	char *headline;
};

#ifdef HAVE_JANSSON
static NTSTATUS net_witness_force_response_parse_rc(
	struct net_witness_force_response_state *state,
	json_t *jsmsg,
	TALLOC_CTX *mem_ctx,
	size_t mi,
	union witness_notifyResponse_message *message)
{
	struct witness_ResourceChange *rc = &message->resource_change;
	json_t *jsctype = NULL;
	json_int_t ctype;
	json_t *jscname = NULL;
	const char *cname = NULL;

	if (!json_is_object(jsmsg)) {
		DBG_ERR("'message[%zu]' needs to be an object\n", mi);
		return NT_STATUS_INVALID_PARAMETER;
	}

	jsctype = json_object_get(jsmsg, "type");
	if (jsctype == NULL) {
		DBG_ERR("%s: INVALID_PARAMETER\n", __location__);
		return NT_STATUS_INVALID_PARAMETER;
	}
	if (!json_is_integer(jsctype)) {
		DBG_ERR("%s: INVALID_PARAMETER\n", __location__);
		return NT_STATUS_INVALID_PARAMETER;
	}
	ctype = json_integer_value(jsctype);

	jscname = json_object_get(jsmsg, "name");
	if (jscname == NULL) {
		DBG_ERR("%s: INVALID_PARAMETER\n", __location__);
		return NT_STATUS_INVALID_PARAMETER;
	}
	if (!json_is_string(jscname)) {
		DBG_ERR("%s: INVALID_PARAMETER\n", __location__);
		return NT_STATUS_INVALID_PARAMETER;
	}
	cname = json_string_value(jscname);

	rc->type = ctype;
	rc->name = talloc_strdup(mem_ctx, cname);
	if (rc->name == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	return NT_STATUS_OK;
}

static NTSTATUS net_witness_force_response_parse_ipl(
	struct net_witness_force_response_state *state,
	json_t *jsmsg,
	TALLOC_CTX *mem_ctx,
	size_t mi,
	union witness_notifyResponse_message *message)
{
	struct witness_IPaddrInfoList *ipl =
		&message->client_move;
	size_t ai, num_addrs = 0;
	struct witness_IPaddrInfo *addrs = NULL;

	if (!json_is_array(jsmsg)) {
		DBG_ERR("'messages[%zu]' needs to be an array\n", mi);
		return NT_STATUS_INVALID_PARAMETER;
	}

	num_addrs = json_array_size(jsmsg);
	if (num_addrs > UINT32_MAX) {
		DBG_ERR("Too many elements in 'messages[%zu]': %zu\n",
			mi, num_addrs);
		return NT_STATUS_INVALID_PARAMETER;
	}

	addrs = talloc_zero_array(mem_ctx,
				  struct witness_IPaddrInfo,
				  num_addrs);
	if (addrs == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	for (ai = 0; ai < num_addrs; ai++) {
		struct witness_IPaddrInfo *info =
			&addrs[ai];
		json_t *jsaddr = json_array_get(jsmsg, ai);
		json_t *jsflags = NULL;
		json_int_t flags;
		json_t *jsipv4 = NULL;
		const char *ipv4 = NULL;
		json_t *jsipv6 = NULL;
		const char *ipv6 = NULL;

		if (!json_is_object(jsaddr)) {
			DBG_ERR("'messages[%zu][%zu]' needs to be an object\n",
				mi, ai);
			return NT_STATUS_INVALID_PARAMETER;
		}

		jsflags = json_object_get(jsaddr, "flags");
		if (jsflags == NULL) {
			DBG_ERR("'messages[%zu][%zu]['flags']' missing\n",
				mi, ai);
			return NT_STATUS_INVALID_PARAMETER;
		}
		if (!json_is_integer(jsflags)) {
			DBG_ERR("'messages[%zu][%zu]['flags']' "
				"needs to be an integer\n",
				mi, ai);
			return NT_STATUS_INVALID_PARAMETER;
		}
		flags = json_integer_value(jsflags);

		jsipv4 = json_object_get(jsaddr, "ipv4");
		if (jsipv4 != NULL) {
			if (!json_is_string(jsipv4)) {
				DBG_ERR("'messages[%zu][%zu]['ipv4']' "
					"needs to be a string\n",
					mi, ai);
				return NT_STATUS_INVALID_PARAMETER;
			}
			ipv4 = json_string_value(jsipv4);
			if (!is_ipaddress_v4(ipv4)) {
				DBG_ERR("'messages[%zu][%zu]['ipv4']' "
					"needs to be a valid ipv4 address\n",
					mi, ai);
				return NT_STATUS_INVALID_PARAMETER;
			}
		} else {
			ipv4 = "0.0.0.0";
		}

		jsipv6 = json_object_get(jsaddr, "ipv6");
		if (jsipv6 != NULL) {
			if (!json_is_string(jsipv6)) {
				DBG_ERR("'messages[%zu][%zu]['ipv6']' "
					"needs to be a string\n",
					mi, ai);
				DBG_ERR("%s: INVALID_PARAMETER\n", __location__);
				return NT_STATUS_INVALID_PARAMETER;
			}
			ipv6 = json_string_value(jsipv6);
			if (!is_ipaddress_v6(ipv6)) {
				DBG_ERR("'messages[%zu][%zu]['ipv4']' "
					"needs to be a valid ipv6 address\n",
					mi, ai);
				return NT_STATUS_INVALID_PARAMETER;
			}
		} else {
			ipv6 = "::";
		}

		info->flags = flags;
		info->ipv4 = talloc_strdup(addrs, ipv4);
		if (info->ipv4 == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		info->ipv6 = talloc_strdup(addrs, ipv6);
		if (info->ipv6 == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	ipl->num = num_addrs;
	ipl->addr = addrs;

	return NT_STATUS_OK;
}
#endif /* HAVE_JANSSON */

static NTSTATUS net_witness_force_response_parse(struct net_witness_force_response_state *state)
{
#ifdef HAVE_JANSSON
	struct net_context *c = state->c;
	struct rpcd_witness_registration_update_force_response *force = NULL;
	struct witness_notifyResponse *response = NULL;
	size_t mi, num_messages = 0;
	union witness_notifyResponse_message *messages = NULL;
	json_t *jsroot = NULL;
	json_t *jsresult = NULL;
	json_t *jsresponse = NULL;
	json_t *jstype = NULL;
	json_t *jsmessages = NULL;

	if (c->opt_witness_forced_response != NULL) {
		const char *str = c->opt_witness_forced_response;
		size_t flags = JSON_REJECT_DUPLICATES;
		json_error_t jserror;

		jsroot = json_loads(str, flags, &jserror);
		if (jsroot == NULL) {
			DBG_ERR("Invalid JSON in "
				"--witness-forced-response='%s'\n",
				str);
			return NT_STATUS_INVALID_PARAMETER;
		}
		state->json_root = (struct json_object) {
			.root = jsroot,
			.valid = true,
		};
	}

	state->m.type = RPCD_WITNESS_REGISTRATION_UPDATE_FORCE_RESPONSE;
	force = &state->m.update.force_response;
	force->response = NULL;
	force->result = WERR_OK;

	if (jsroot == NULL) {
		return NT_STATUS_OK;
	}

	jsresult = json_object_get(jsroot, "result");
	if (jsresult != NULL) {
		int val_type = json_typeof(jsresult);

		switch (val_type) {
		case JSON_INTEGER: {
			json_int_t val = json_integer_value(jsresult);

			if (val > UINT32_MAX) {
				DBG_ERR("Invalid 'result' value: %d\n",
					(int) val);
				return NT_STATUS_INVALID_PARAMETER;
			}
			if (val < 0) {
				DBG_ERR("invalid 'result' value: %d\n",
					(int) val);
				return NT_STATUS_INVALID_PARAMETER;
			}

			force->result = W_ERROR(val);
			}; break;
		default:
			DBG_ERR("Invalid json type for 'result' - needs integer\n");
			return NT_STATUS_INVALID_PARAMETER;
		}
	}

	jsresponse = json_object_get(jsroot, "response");
	if (jsresponse == NULL) {
		return NT_STATUS_OK;
	}

	if (!json_is_object(jsresponse)) {
		DBG_ERR("Invalid json type 'response' needs object\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	response = talloc_zero(talloc_tos(), struct witness_notifyResponse);
	if (response == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	jstype = json_object_get(jsresponse, "type");
	if (jstype == NULL) {
		DBG_ERR("Missing 'type' element in 'response'\n");
		return NT_STATUS_INVALID_PARAMETER;
	}
	{
		int val_type = json_typeof(jstype);

		switch (val_type) {
		case JSON_INTEGER: {
			json_int_t val = json_integer_value(jstype);

			if (val > WITNESS_NOTIFY_IP_CHANGE) {
				DBG_ERR("invalid 'type' value in 'response': "
					"%d\n", (int) val);
				return NT_STATUS_INVALID_PARAMETER;
			}
			if (val < WITNESS_NOTIFY_RESOURCE_CHANGE) {
				DBG_ERR("invalid 'type' value in 'response': "
					"%d\n", (int) val);
				return NT_STATUS_INVALID_PARAMETER;
			}

			response->type = val;
			}; break;
		default:
			DBG_ERR("Invalid json type for 'type' in 'response' "
				"- needs integer\n");
			return NT_STATUS_INVALID_PARAMETER;
		}
	}

	force->response = response;

	jsmessages = json_object_get(jsresponse, "messages");
	if (jsmessages == NULL) {
		return NT_STATUS_OK;
	}

	if (!json_is_array(jsmessages)) {
		DBG_ERR("'messages' in 'response' needs to be an array\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	num_messages = json_array_size(jsmessages);
	if (num_messages > UINT32_MAX) {
		DBG_ERR("Too many elements in 'messages': %zu\n",
			num_messages);
		return NT_STATUS_INVALID_PARAMETER;
	}

	messages = talloc_zero_array(response,
				     union witness_notifyResponse_message,
				     num_messages);
	if (messages == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	for (mi = 0; mi < num_messages; mi++) {
		json_t *jsmsg = json_array_get(jsmessages, mi);
		union witness_notifyResponse_message *message = &messages[mi];
		NTSTATUS status;

		switch (response->type) {
		case WITNESS_NOTIFY_RESOURCE_CHANGE:
			status = net_witness_force_response_parse_rc(state,
								     jsmsg,
								     messages,
								     mi,
								     message);
			if (!NT_STATUS_IS_OK(status)) {
				const char *fn =
					"net_witness_force_response_parse_rc";
				DBG_ERR("%s failed: %s\n",
					fn, nt_errstr(status));
				return status;
			}

			break;
		case WITNESS_NOTIFY_CLIENT_MOVE:
		case WITNESS_NOTIFY_SHARE_MOVE:
		case WITNESS_NOTIFY_IP_CHANGE:
			status = net_witness_force_response_parse_ipl(state,
								      jsmsg,
								      messages,
								      mi,
								      message);
			if (!NT_STATUS_IS_OK(status)) {
				const char *fn =
					"net_witness_force_response_parse_ipl";
				DBG_ERR("%s failed: %s\n",
					fn, nt_errstr(status));
				return status;
			}

			break;
		}
	}

	response->num = num_messages;
	response->messages = messages;

	return NT_STATUS_OK;
#else /* not HAVE_JANSSON */
	d_fprintf(stderr, _("JSON support not available\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
#endif /* not HAVE_JANSSON */
}

static bool net_witness_force_response_prepare_fn(void *private_data)
{
	struct net_witness_force_response_state *state =
		(struct net_witness_force_response_state *)private_data;

	if (state->headline != NULL) {
		d_printf("%s\n", state->headline);
		TALLOC_FREE(state->headline);
	}

	return true;
}

static bool net_witness_force_response_match_fn(void *private_data,
			const struct rpcd_witness_registration *rg)
{
	return true;
}

static NTSTATUS net_witness_force_response_process_fn(void *private_data,
			const struct rpcd_witness_registration *rg)
{
	struct net_witness_force_response_state *state =
		(struct net_witness_force_response_state *)private_data;
	struct net_context *c = state->c;
	struct rpcd_witness_registration_updateB update = {
		.context_handle = rg->context_handle,
		.type = state->m.type,
		.update = state->m.update,
	};
	DATA_BLOB blob = { .length = 0, };
	enum ndr_err_code ndr_err;
	NTSTATUS status;

	SMB_ASSERT(update.type != 0);

	if (DEBUGLVL(DBGLVL_DEBUG)) {
		NDR_PRINT_DEBUG(rpcd_witness_registration_updateB, &update);
	}

	ndr_err = ndr_push_struct_blob(&blob, talloc_tos(), &update,
			(ndr_push_flags_fn_t)ndr_push_rpcd_witness_registration_updateB);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		status = ndr_map_error2ntstatus(ndr_err);
		DBG_ERR("ndr_push_struct_blob - %s\n", nt_errstr(status));
		return status;
	}

	status = messaging_send(c->msg_ctx,
				rg->server_id,
				MSG_RPCD_WITNESS_REGISTRATION_UPDATE,
				&blob);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("messaging_send() - %s\n", nt_errstr(status));
		return status;
	}

	return NT_STATUS_OK;
}

static void net_witness_force_response_usage(void)
{
	d_printf("%s\n"
		 "net witness force-response\n"
		 "    %s\n\n",
		 _("Usage:"),
		 _("Force an AsyncNotify response based on "
		   "json input (mostly for testing)"));
	net_witness_filter_usage();
	net_witness_update_usage();
	d_printf("    Note this is designed for testing and debugging!\n"
		 "\n"
		 "    In short it is not designed to be used by "
		     "administrators,\n"
		 "    but developers and automated tests.\n"
		 "\n"
		 "    By default an empty response with WERR_OK is generated,\n"
		 "    but basically any valid response can be specified by a\n"
		 "    specifying a JSON string:\n"
		 "\n"
		 "        --witness-forced-response=JSON\n"
		 "          This allows the generation of very complex\n"
		 "          witness_notifyResponse structures.\n"
		 "\n"
		 "    As this is for developers, please read the code\n"
		 "    in order to understand all possible values\n"
		 "    of the JSON string format...\n"
		 "\n"
		 "    Simple examples are:\n"
		 "\n"
		 "# Resource Change:\n%s\n"
		 "\n"
		 "# Client Move:\n%s\n"
		 "\n"
		 "# Share Move:\n%s\n"
		 "\n"
		 "# IP Change:\n%s\n"
		 "\n",
			"'{ \"result\": 0, \"response\": { \"type\": 1, "
				"\"messages\": [ { "
					"\"type\": 255 , "
					"\"name\": \"some-resource-name\" "
				"} ]"
			"}}'",
			"'{ \"result\": 0, \"response\": { \"type\": 2, "
				"\"messages\": ["
					"[{ "
						"\"flags\": 9, "
						"\"ipv4\": \"10.0.10.1\" "
					"}]"
				"]"
			"}}'",
			"'{ \"result\": 0, \"response\": { \"type\": 3, "
				"\"messages\": ["
					"[{ "
						"\"flags\": 9, "
						"\"ipv4\": \"10.0.10.1\" "
					"}]"
				"]"
			"}}'",
			"'{ \"result\": 0, \"response\": { \"type\": 4, "
				"\"messages\": ["
					"[{ "
						"\"flags\": 9, "
						"\"ipv4\": \"10.0.10.1\" "
					"}]"
				"]"
			"}}'");
}

static int net_witness_force_response(struct net_context *c, int argc, const char **argv)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct net_witness_force_response_state state = { .c = c, };
#ifdef HAVE_JANSSON
	struct json_object _message_json = json_empty_object;
#endif /* HAVE_JANSSON */
	struct json_object *message_json = NULL;
	struct net_witness_scan_registrations_action_state action = {
		.prepare_fn = net_witness_force_response_prepare_fn,
		.match_fn = net_witness_force_response_match_fn,
		.process_fn = net_witness_force_response_process_fn,
		.private_data = &state,
	};
	NTSTATUS status;
	int ret = -1;
	bool ok;

	if (c->display_usage) {
		net_witness_force_response_usage();
		goto out;
	}

	if (argc != 0) {
		net_witness_force_response_usage();
		goto out;
	}

	if (!lp_clustering()) {
		d_printf("ERROR: Only supported with clustering=yes!\n\n");
		goto out;
	}

	ok = net_witness_verify_update_options(c);
	if (!ok) {
		goto out;
	}

	status = net_witness_force_response_parse(&state);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("net_witness_force_response_parse failed: %s\n",
			nt_errstr(status));
		goto out;
	}

	state.headline = talloc_asprintf(frame, "FORCE_RESPONSE:%s%s",
					 c->opt_witness_forced_response != NULL ?
					 " " : "",
					 c->opt_witness_forced_response != NULL ?
					 c->opt_witness_forced_response : "");

	if (state.headline == NULL) {
		goto out;
	}

#ifdef HAVE_JANSSON
	if (c->opt_json) {
		TALLOC_FREE(state.headline);

		_message_json = json_new_object();
		if (json_is_invalid(&_message_json)) {
			goto out;
		}

		ret = json_add_string(&_message_json,
				      "type",
				      "FORCE_RESPONSE");
		if (ret != 0) {
			goto out;
		}

		if (!json_is_invalid(&state.json_root)) {
			ret = json_add_object(&_message_json,
					      "json",
					      &state.json_root);
			if (ret != 0) {
				goto out;
			}
			state.json_root = json_empty_object;
		}
		message_json = &_message_json;
	}
#endif /* HAVE_JANSSON */

	ret = net_witness_scan_registrations(c, message_json, &action);
	if (ret != 0) {
		d_printf("net_witness_scan_registrations() failed\n");
		goto out;
	}

	ret = 0;
out:
#ifdef HAVE_JANSSON
	if (!json_is_invalid(&_message_json)) {
		json_free(&_message_json);
	}
	if (!json_is_invalid(&state.json_root)) {
		json_free(&state.json_root);
	}
#endif /* HAVE_JANSSON */
	TALLOC_FREE(frame);
	return ret;
}

int net_witness(struct net_context *c, int argc, const char **argv)
{
	struct functable func[] = {
		{
			"list",
			net_witness_list,
			NET_TRANSPORT_LOCAL,
			N_("List witness registrations "
			   "from rpcd_witness_registration.tdb"),
			N_("net witness list\n"
			   "    List witness registrations "
			   "from rpcd_witness_registration.tdb"),
		},
		{
			"client-move",
			net_witness_client_move,
			NET_TRANSPORT_LOCAL,
			N_("Generate client move notifications for "
			   "witness registrations to a new ip or node"),
			N_("net witness client-move\n"
			   "    Generate client move notifications for "
			       "witness registrations to a new ip or node"),
		},
		{
			"share-move",
			net_witness_share_move,
			NET_TRANSPORT_LOCAL,
			N_("Generate share move notifications for "
			   "witness registrations to a new ip or node"),
			N_("net witness share-move\n"
			   "    Generate share move notifications for "
			       "witness registrations to a new ip or node"),
		},
		{
			"force-unregister",
			net_witness_force_unregister,
			NET_TRANSPORT_LOCAL,
			N_("Force unregistrations for witness registrations"),
			N_("net witness force-unregister\n"
			   "    Force unregistrations for "
			       "witness registrations"),
		},
		{
			"force-response",
			net_witness_force_response,
			NET_TRANSPORT_LOCAL,
			N_("Force an AsyncNotify response based on "
			   "json input (mostly for testing)"),
			N_("net witness force-response\n"
			   "    Force an AsyncNotify response based on "
			       "json input (mostly for testing)"),
		},
		{NULL, NULL, 0, NULL, NULL}
	};

	return net_run_function(c, argc, argv, "net witness", func);
}
