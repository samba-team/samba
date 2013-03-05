/*
   Samba Unix/Linux SMB client library
   net serverid commands
   Copyright (C) Volker Lendecke 2010

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "utils/net.h"
#include "dbwrap/dbwrap.h"
#include "dbwrap/dbwrap_rbt.h"
#include "serverid.h"
#include "session.h"
#include "lib/conn_tdb.h"
#include "smbd/globals.h"
#include "util_tdb.h"

static int net_serverid_list_fn(const struct server_id *id,
				uint32_t msg_flags, void *priv)
{
	char *str = server_id_str(talloc_tos(), id);
	d_printf("%s %llu 0x%x\n", str, (unsigned long long)id->unique_id,
		 (unsigned int)msg_flags);
	TALLOC_FREE(str);
	return 0;
}

static int net_serverid_list(struct net_context *c, int argc,
			     const char **argv)
{
	d_printf("pid unique_id msg_flags\n");
	return serverid_traverse_read(net_serverid_list_fn, NULL) ? 0 : -1;
}

static int net_serverid_wipe_fn(struct db_record *rec,
				const struct server_id *id,
				uint32_t msg_flags, void *private_data)
{
	NTSTATUS status;

	if (id->vnn != get_my_vnn()) {
		return 0;
	}
	status = dbwrap_record_delete(rec);
	if (!NT_STATUS_IS_OK(status)) {
		char *str = server_id_str(talloc_tos(), id);
		DEBUG(1, ("Could not delete serverid.tdb record %s: %s\n",
			  str, nt_errstr(status)));
		TALLOC_FREE(str);
	}
	return 0;
}

static int net_serverid_wipe(struct net_context *c, int argc,
			     const char **argv)
{
	return serverid_traverse(net_serverid_wipe_fn, NULL) ? 0 : -1;
}


struct wipedbs_record_marker {
	struct wipedbs_record_marker *prev, *next;
	TDB_DATA key, val;
	const char *desc;
};

struct wipedbs_server_data {
	struct server_id server_id;
	const char *server_id_str;
	bool exists;
	struct wipedbs_record_marker *session_records;
	struct wipedbs_record_marker *tcon_records;
	struct wipedbs_record_marker *open_records;
};

struct wipedbs_state {
	struct db_context *id2server_data;
	struct {
		struct {
			int total;
			int existing;
			int disconnected;
		} server;
		struct {
			int total;
			int disconnected;
			int todelete;
			int failure;
		} session, tcon, open;
		int open_timed_out;
	} stat;
	struct server_id *server_ids;
	bool *server_exists;
	int idx;
	struct db_context *session_db;
	struct db_context *tcon_db;
	struct db_context *open_db;
	struct timeval now;
	bool testmode;
	bool verbose;
};

static struct wipedbs_server_data *get_server_data(struct wipedbs_state *state,
						   const struct server_id *id)
{
	struct wipedbs_server_data *ret = NULL;
	TDB_DATA key, val = tdb_null;
	NTSTATUS status;

	key = make_tdb_data((const void*)&id->unique_id, sizeof(id->unique_id));
	status = dbwrap_fetch(state->id2server_data, talloc_tos(), key, &val);
	if (NT_STATUS_IS_OK(status)) {
		ret = *(struct wipedbs_server_data**) val.dptr;
		TALLOC_FREE(val.dptr);
	} else if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
		ret = talloc_zero(state->id2server_data,
				  struct wipedbs_server_data);
		if (ret == NULL) {
			DEBUG(0, ("Failed to allocate server entry for %s\n",
				  server_id_str(talloc_tos(), id)));
			goto done;
		}
		ret->server_id = *id;
		ret->server_id_str = server_id_str(ret, id);
		ret->exists = true;
		val = make_tdb_data((const void*)&ret, sizeof(ret));
		status = dbwrap_store(state->id2server_data,
				      key, val, TDB_INSERT);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("Failed to store server entry for %s: %s\n",
				  server_id_str(talloc_tos(), id),
				  nt_errstr(status)));
		}
		goto done;
	} else {
		DEBUG(0, ("Failed to fetch server entry for %s: %s\n",
			  server_id_str(talloc_tos(), id), nt_errstr(status)));
		goto done;
	}
	if (!server_id_equal(id, &ret->server_id)) {
		DEBUG(0, ("uniq id collision for %s and %s\n",
			  server_id_str(talloc_tos(), id),
			  server_id_str(talloc_tos(), &ret->server_id)));
		smb_panic("server_id->unique_id not unique!");
	}
done:
	return ret;
}

static int wipedbs_traverse_sessions(struct smbXsrv_session_global0 *session,
				     void *wipedbs_state)
{
	struct wipedbs_state *state =
		talloc_get_type_abort(wipedbs_state,
		struct wipedbs_state);
	struct wipedbs_server_data *sd;
	struct wipedbs_record_marker *rec;
	TDB_DATA tmp;
	int ret = -1;

	assert(session->num_channels == 1);

	state->stat.session.total++;

	sd = get_server_data(state, &session->channels[0].server_id);
	if (sd == NULL) {
		goto done;
	}

	if (server_id_is_disconnected(&sd->server_id)) {
		state->stat.session.disconnected++;
	}

	rec = talloc_zero(sd, struct wipedbs_record_marker);
	if (rec == NULL) {
		DEBUG(0, ("Out of memory!\n"));
		goto done;
	}

	tmp = dbwrap_record_get_key(session->db_rec);
	rec->key = tdb_data_talloc_copy(rec, tmp);
	tmp = dbwrap_record_get_value(session->db_rec);
	rec->val = tdb_data_talloc_copy(rec, tmp);

	rec->desc = talloc_asprintf(
		rec, "session[global: %u wire: %llu]",
		session->session_global_id,
		(long long unsigned)session->session_wire_id);

	if ((rec->key.dptr == NULL) || (rec->val.dptr == NULL) ||
	    (rec->desc == NULL))
	{
		DEBUG(0, ("Out of memory!\n"));
		goto done;
	}

	state->session_db = dbwrap_record_get_db(session->db_rec);

	DLIST_ADD(sd->session_records, rec);
	ret = 0;
done:
	return ret;
}

static int wipedbs_traverse_tcon(struct smbXsrv_tcon_global0 *tcon,
				 void *wipedbs_state)
{
	struct wipedbs_state *state =
		talloc_get_type_abort(wipedbs_state,
		struct wipedbs_state);
	struct wipedbs_server_data *sd;
	struct wipedbs_record_marker *rec;
	TDB_DATA tmp;
	int ret = -1;

	state->stat.tcon.total++;

	sd = get_server_data(state, &tcon->server_id);
	if (sd == NULL) {
		goto done;
	}

	if (server_id_is_disconnected(&sd->server_id)) {
		state->stat.tcon.disconnected++;
	}

	rec = talloc_zero(sd, struct wipedbs_record_marker);
	if (rec == NULL) {
		DEBUG(0, ("Out of memory!\n"));
		goto done;
	}

	tmp = dbwrap_record_get_key(tcon->db_rec);
	rec->key = tdb_data_talloc_copy(rec, tmp);
	tmp = dbwrap_record_get_value(tcon->db_rec);
	rec->val = tdb_data_talloc_copy(rec, tmp);

	rec->desc = talloc_asprintf(
		rec, "tcon[global: %u wire: %u session: %u share: %s]",
		tcon->tcon_global_id, tcon->tcon_wire_id,
		tcon->session_global_id, tcon->share_name);

	if ((rec->key.dptr == NULL) || (rec->val.dptr == NULL) ||
	    (rec->desc == NULL))
	{
		DEBUG(0, ("Out of memory!\n"));
		goto done;
	}

	state->tcon_db = dbwrap_record_get_db(tcon->db_rec);

	DLIST_ADD(sd->tcon_records, rec);
	ret = 0;

done:
	return ret;
}

static int wipedbs_traverse_open(struct smbXsrv_open_global0 *open,
				 void *wipedbs_state)
{
	struct wipedbs_state *state =
		talloc_get_type_abort(wipedbs_state,
		struct wipedbs_state);
	struct wipedbs_server_data *sd;
	struct wipedbs_record_marker *rec;
	TDB_DATA tmp;
	int ret = -1;

	state->stat.open.total++;

	sd = get_server_data(state, &open->server_id);
	if (sd == NULL) {
		goto done;
	}

	if (server_id_is_disconnected(&sd->server_id)) {
		struct timeval disconnect_time;
		int64_t tdiff;
		bool reached;

		state->stat.open.disconnected++;

		nttime_to_timeval(&disconnect_time, open->disconnect_time);
		tdiff = usec_time_diff(&state->now, &disconnect_time);
		reached = (tdiff >= 1000*open->durable_timeout_msec);

		if (state->verbose) {
			TALLOC_CTX *mem_ctx = talloc_new(talloc_tos());
			d_printf("open[global: %u] disconnected at "
				 "[%s] %us ago with timeout of %us "
				 "-%s reached\n",
				 open->open_global_id,
				 nt_time_string(mem_ctx, open->disconnect_time),
				 (unsigned)(tdiff/1000000),
				 open->durable_timeout_msec / 1000,
				 reached ? "" : " not");
			talloc_free(mem_ctx);
		}

		if (!reached) {
			ret = 0;
			goto done;
		}
		state->stat.open_timed_out++;
	}

	rec = talloc_zero(sd, struct wipedbs_record_marker);
	if (rec == NULL) {
		DEBUG(0, ("Out of memory!\n"));
		goto done;
	}

	tmp = dbwrap_record_get_key(open->db_rec);
	rec->key = tdb_data_talloc_copy(rec, tmp);
	tmp = dbwrap_record_get_value(open->db_rec);
	rec->val = tdb_data_talloc_copy(rec, tmp);

	rec->desc = talloc_asprintf(
		rec, "open[global: %u persistent: %llu volatile: %llu]",
		open->open_global_id,
		(long long unsigned)open->open_persistent_id,
		(long long unsigned)open->open_volatile_id);

	if ((rec->key.dptr == NULL) || (rec->val.dptr == NULL) ||
	    (rec->desc == NULL))
	{
		DEBUG(0, ("Out of memory!\n"));
		goto done;
	}

	state->open_db = dbwrap_record_get_db(open->db_rec);

	DLIST_ADD(sd->open_records, rec);
	ret = 0;

done:
	return ret;
}

static int wipedbs_traverse_nop(struct db_record *rec, void *private_data)
{
	return 0;
}

static int wipedbs_traverse_fill_ids(struct db_record *rec, void *wipedbs_state)
{
	struct wipedbs_state *state = talloc_get_type_abort(
		wipedbs_state, struct wipedbs_state);

	TDB_DATA val = dbwrap_record_get_value(rec);

	struct wipedbs_server_data *sd = talloc_get_type_abort(
		*(void**)val.dptr, struct wipedbs_server_data);

	state->server_ids[state->idx] = sd->server_id;
	state->idx++;
	return 0;
}

static int wipedbs_traverse_set_exists(struct db_record *rec,
				       void *wipedbs_state)
{
	struct wipedbs_state *state = talloc_get_type_abort(
		wipedbs_state, struct wipedbs_state);

	TDB_DATA val = dbwrap_record_get_value(rec);

	struct wipedbs_server_data *sd = talloc_get_type_abort(
		*(void**)val.dptr, struct wipedbs_server_data);

	/* assume a stable traverse order for rbt */
	SMB_ASSERT(server_id_equal(&state->server_ids[state->idx],
				   &sd->server_id));
	sd->exists = state->server_exists[state->idx];

	if (sd->exists) {
		state->stat.server.existing++;
	}
	if (server_id_is_disconnected(&sd->server_id)) {
		state->stat.server.disconnected++;
	}

	state->idx++;
	return 0;
}

static NTSTATUS wipedbs_check_server_exists(struct wipedbs_state *state)
{
	NTSTATUS status;
	bool ok;
	int num_servers;

	status = dbwrap_traverse_read(state->id2server_data,
				      wipedbs_traverse_nop, NULL, &num_servers);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to traverse temporary database\n"));
		goto done;
	}
	state->stat.server.total = num_servers;

	state->server_ids = talloc_array(state, struct server_id, num_servers);
	state->server_exists = talloc_array(state, bool, num_servers);
	if (state->server_ids == NULL || state->server_exists == NULL) {
		DEBUG(0, ("Out of memory\n"));
		goto done;
	}

	state->idx = 0;
	status = dbwrap_traverse_read(state->id2server_data,
				      wipedbs_traverse_fill_ids,
				      state, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to traverse temporary database\n"));
		goto done;
	}

	ok = serverids_exist(state->server_ids, num_servers, state->server_exists);
	if (!ok) {
		DEBUG(0, ("Calling serverids_exist failed\n"));
		status = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	state->idx = 0;
	status = dbwrap_traverse_read(state->id2server_data,
				      wipedbs_traverse_set_exists, state, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to traverse temporary database\n"));
		goto done;
	}
done:
	TALLOC_FREE(state->server_ids);
	TALLOC_FREE(state->server_exists);
	return status;
}

static int wipedbs_delete_records(struct db_context *db,
				  struct wipedbs_record_marker *records,
				  bool dry_run, bool verbose, int *count)
{
	struct wipedbs_record_marker *cur;
	struct db_record *rec;
	TDB_DATA val;
	NTSTATUS status;
	unsigned num=0, total=0;

	if (db == NULL) {
		return 0;
	}

	for (cur = records; cur != NULL; cur = cur->next) {
		total++;
		rec = dbwrap_fetch_locked(db, talloc_tos(), cur->key);
		if (rec == NULL) {
			DEBUG(0, ("Failed to fetch record <%s> from %s",
				  cur->desc, dbwrap_name(db)));
			continue;
		}
		val = dbwrap_record_get_value(rec);
		if (tdb_data_equal(val, cur->val)) {
			if (dry_run) {
				status = NT_STATUS_OK;
			} else {
				status = dbwrap_record_delete(rec);
			}
			if (NT_STATUS_IS_OK(status)) {
				num ++;
			} else {
				DEBUG(0, ("Failed to delete record <%s> from %s"
					  ": %s\n", cur->desc, dbwrap_name(db),
					  nt_errstr(status)));
			}
		} else {
			DEBUG(0, ("Warning: record <%s> from %s changed"
				  ", skip record!\n",
				  cur->desc, dbwrap_name(db)));
		}
		if (verbose) {
			d_printf("deleting %s\n", cur->desc);
		}
		TALLOC_FREE(rec);
	}

	if (verbose) {
		d_printf("Deleted %u of %u records from %s\n",
			 num, total, dbwrap_name(db));
	}

	if (count) {
		*count += total;
	}

	return total - num;
}

static int wipedbs_traverse_server_data(struct db_record *rec,
					void *wipedbs_state)
{
	struct wipedbs_state *state = talloc_get_type_abort(
		wipedbs_state, struct wipedbs_state);
	bool dry_run = state->testmode;
	TDB_DATA val = dbwrap_record_get_value(rec);
	int ret;
	struct wipedbs_server_data *sd = talloc_get_type_abort(
		*(void**)val.dptr, struct wipedbs_server_data);

	if (state->verbose) {
		d_printf("Server: '%s' %s\n", sd->server_id_str,
			 sd->exists ?
			 "exists" :
			 "does not exist, cleaning up...");
	}

	if (sd->exists) {
		return 0;
	}

	ret = wipedbs_delete_records(state->session_db, sd->session_records,
				     dry_run, state->verbose,
				     &state->stat.session.todelete);
	state->stat.session.failure += ret;

	ret = wipedbs_delete_records(state->tcon_db, sd->tcon_records,
				     dry_run, state->verbose,
				     &state->stat.tcon.todelete);
	state->stat.tcon.failure += ret;

	ret = wipedbs_delete_records(state->open_db, sd->open_records,
				     dry_run, state->verbose,
				     &state->stat.open.todelete);
	state->stat.open.failure += ret;

	return 0;
}

static int net_serverid_wipedbs(struct net_context *c, int argc,
				const char **argv)
{
	int ret = -1;
	NTSTATUS status;
	struct wipedbs_state *state = talloc_zero(talloc_tos(),
						  struct wipedbs_state);

	if (c->display_usage) {
		d_printf("%s\n%s",
			 _("Usage:"),
			 _("net serverid wipedbs [--test] [--verbose]\n"));
		d_printf("%s\n%s",
			 _("Example:"),
			 _("net serverid wipedbs -v\n"));
		return -1;
	}

	state->now = timeval_current();
	state->testmode = c->opt_testmode;
	state->verbose = c->opt_verbose;

	state->id2server_data = db_open_rbt(state);
	if (state->id2server_data == NULL) {
		DEBUG(0, ("Failed to open temporary database\n"));
		goto done;
	}

	status = smbXsrv_session_global_traverse(wipedbs_traverse_sessions,
						 state);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	status = smbXsrv_tcon_global_traverse(wipedbs_traverse_tcon, state);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	status = smbXsrv_open_global_traverse(wipedbs_traverse_open, state);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	status = wipedbs_check_server_exists(state);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	status = dbwrap_traverse_read(state->id2server_data,
				      wipedbs_traverse_server_data,
				      state, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to traverse db: %s\n", nt_errstr(status)));
		goto done;
	}

	d_printf("Found %d serverids, %d alive and %d disconnected\n",
		 state->stat.server.total,
		 state->stat.server.existing,
		 state->stat.server.disconnected);
	d_printf("Found %d sessions, %d alive and %d disconnected"
		 ", cleaned up %d of %d entries\n",
		 state->stat.session.total,
		 state->stat.session.total - state->stat.session.todelete,
		 state->stat.session.disconnected,
		 state->stat.session.todelete - state->stat.session.failure,
		 state->stat.session.todelete);
	d_printf("Found %d tcons, %d alive and %d disconnected"
		 ", cleaned up %d of %d entries\n",
		 state->stat.tcon.total,
		 state->stat.tcon.total - state->stat.tcon.todelete,
		 state->stat.tcon.disconnected,
		 state->stat.tcon.todelete - state->stat.tcon.failure,
		 state->stat.tcon.todelete);
	d_printf("Found %d opens, %d alive, %d disconnected and %d timed out"
		 ", cleaned up %d of %d entries\n",
		 state->stat.open.total,
		 state->stat.open.total - state->stat.open.todelete
		 - (state->stat.open.disconnected - state->stat.open_timed_out),
		 state->stat.open.disconnected,
		 state->stat.open_timed_out,
		 state->stat.open.todelete - state->stat.open.failure,
		 state->stat.open.todelete);

	ret = 0;
done:
	talloc_free(state);
	return ret;
}

int net_serverid(struct net_context *c, int argc, const char **argv)
{
	struct functable func[] = {
		{
			"list",
			net_serverid_list,
			NET_TRANSPORT_LOCAL,
			N_("List all entries from serverid.tdb"),
			N_("net serverid list\n"
			   "    List all entries from serverid.tdb")
		},
		{
			"wipe",
			net_serverid_wipe,
			NET_TRANSPORT_LOCAL,
			N_("Wipe the serverid.tdb for the current node"),
			N_("net serverid wipe\n"
			   "    Wipe the serverid.tdb for the current node")
		},
		{
			"wipedbs",
			net_serverid_wipedbs,
			NET_TRANSPORT_LOCAL,
			N_("Clean dead entries from temporary databases"),
			N_("net serverid wipedbs\n"
			   "    Clean dead entries from temporary databases")
		},
		{NULL, NULL, 0, NULL, NULL}
	};

	return net_run_function(c, argc, argv, "net serverid", func);
}
