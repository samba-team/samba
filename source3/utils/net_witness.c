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
		{NULL, NULL, 0, NULL, NULL}
	};

	return net_run_function(c, argc, argv, "net witness", func);
}
