/*
 * Samba Unix/Linux SMB client library
 * Distributed SMB/CIFS Server Management Utility
 * fiddle with connections tdb
 *
 * Copyright (C) Gregor Beck 2012
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
#include "net.h"
#include "serverid.h"
#include "popt_common.h"
#include "dbwrap/dbwrap.h"
#include "util_tdb.h"
#include "messages.h"
#include "system/filesys.h"
#include "interact.h"
#include "lib/conn_tdb.h"

struct cclean_ctx {
	struct server_id *ids;
	int *cnums;
	const char **names;
	unsigned num;

	bool *exists;
	unsigned num_orphans;

	bool verbose;
	bool dry_run;
};


static char *serverid_str(const struct server_id id)
{
	return talloc_asprintf(talloc_tos(), "pid %u, vnn %u, uid %llu",
			       (unsigned)id.pid, (unsigned)id.vnn, (unsigned long long)id.unique_id);
}

static void print_record(const char *msg,
			 const struct connections_key *k,
			 const struct connections_data *d)
{
	char *idstr = serverid_str(k->pid);
	d_printf("%s: connection %d (%s) ", msg, k->cnum, idstr);
	if (d == NULL) {
		d_printf("<no data>\n");
	} else {
		d_printf("to \"%s\" from %u:%u@%s[%s] %s\n", d->servicename,
			 (unsigned)d->uid, (unsigned)d->gid, d->machine,
			 d->addr, time_to_asc(d->start));
	}
	talloc_free(idstr);
}

static int read_connections_fn(const struct connections_key *key,
			       const struct connections_data *data,
			       void *cclean_ctx)
{
	struct cclean_ctx *ctx = (struct cclean_ctx *)cclean_ctx;
	unsigned length = talloc_array_length(ctx->cnums);
	if (length <= ctx->num) {
		int n = MAX(2*length, 16);
		void *tmp;

		tmp = talloc_realloc(ctx, ctx->ids, struct server_id, n);
		if (tmp == NULL) {
			goto talloc_failed;
		}
		ctx->ids = (struct server_id *)tmp;

		tmp = talloc_realloc(ctx, ctx->cnums, int, n);
		if (tmp == NULL) {
			goto talloc_failed;
		}
		ctx->cnums = (int *)tmp;

		tmp = talloc_realloc(ctx, ctx->names, const char *, n);
		if (tmp == NULL) {
			goto talloc_failed;
		}
		ctx->names = (const char **)tmp;
	}

	if (ctx->verbose) {
		print_record("Read", key, data);
	}

	ctx->ids[ctx->num] = key->pid;
	ctx->cnums[ctx->num] = key->cnum;
	ctx->names[ctx->num] = talloc_strndup(ctx, key->name, FSTRING_LEN);
	if (ctx->names[ctx->num] == NULL) {
		goto talloc_failed;
	}
	ctx->num++;

	return 0;

talloc_failed:
	DEBUG(0, ("Out of memory\n"));
	return -1;
}

static int read_connections(struct cclean_ctx *ctx)
{
	int ret = connections_forall_read(
		&read_connections_fn,
		ctx);
	if (ret < 0) {
		return ret;
	}
	if (ret != ctx->num) {
		DEBUG(0, ("Skipped %d invalid entries\n", ret - ctx->num));
	}
	return 0;
}

static int check_connections(struct cclean_ctx *ctx)
{
	int i, ret = -1;

	ctx->exists = talloc_realloc(ctx, ctx->exists, bool, MAX(1, ctx->num));
	if (ctx->exists == NULL) {
		DEBUG(0, ("Out of memory\n"));
		goto done;
	}

	if (!serverids_exist(ctx->ids, ctx->num, ctx->exists)) {
		DEBUG(0, ("serverids_exist() failed\n"));
		goto done;
	}

	ctx->num_orphans = 0;
	for (i=0; i<ctx->num; i++) {
		if (!ctx->exists[i]) {
			char *idstr = serverid_str(ctx->ids[i]);
			d_printf("Orphaned entry: %s\n", idstr);
			talloc_free(idstr);
			ctx->num_orphans++;
		}
	}
	ret = 0;
done:
	return ret;
}

static int delete_orphans(struct cclean_ctx *ctx)
{
	NTSTATUS status;
	struct db_record *conn;
	int i, ret = 0;

	for (i=0; i<ctx->num; i++) {
		if (!ctx->exists[i]) {
			TDB_DATA key, value;
			conn = connections_fetch_entry_ext(NULL,
							   ctx->ids[i],
							   ctx->cnums[i],
							   ctx->names[i]);

			key = dbwrap_record_get_key(conn);
			value = dbwrap_record_get_value(conn);

			print_record("Delete record",
				     (struct connections_key *)key.dptr,
				     (struct connections_data *)value.dptr);

			if (!ctx->dry_run) {
				status = dbwrap_record_delete(conn);
				if (!NT_STATUS_IS_OK(status)) {
					DEBUG(0, ("Failed to delete record: %s\n",
						  nt_errstr(status)));
					ret = -2;
				}
			}
			TALLOC_FREE(conn);
		}
	}
	return ret;
}

static int cclean(bool verbose, bool dry_run, bool automatic)
{
	int ret = -1;
	struct cclean_ctx *ctx = talloc_zero(talloc_tos(), struct cclean_ctx);
	if (ctx == NULL) {
		d_printf("Out of memory\n");
		goto done;
	}

	ctx->verbose = verbose;
	ctx->dry_run = dry_run;

	ret = read_connections(ctx);
	if (ret != 0) {
		d_printf("Failed to read connections\n");
		goto done;
	}
	d_printf("Read %u connections\n", ctx->num);

	ret = check_connections(ctx);
	if (ret != 0) {
		d_printf("Failed to check connections\n");
		goto done;
	}
	d_printf("Found %u orphans\n", ctx->num_orphans);

	if (ctx->num_orphans == 0) {
		goto done;
	}

	if (!automatic) {
		int act = interact_prompt("Delete ([y]es/[n]o)", "yn", 'n');
		if (tolower(act) != 'y') {
			ret = 0;
			goto done;
		}
	}
	ret = delete_orphans(ctx);
	if (ret != 0) {
		d_printf("Failed to delete all orphans\n");
	}
done:
	talloc_free(ctx);
	return ret;
}

static int net_connections_cleanup(struct net_context *c,
				   int argc, const char **argv)
{
	return cclean(c->opt_verbose, c->opt_testmode, c->opt_auto);
}

int net_connections(struct net_context *c, int argc, const char **argv)
{
	int ret = -1;

	struct functable func[] = {
		{
			"cleanup",
			net_connections_cleanup,
			NET_TRANSPORT_LOCAL,
			N_("Remove orphaned entries from connections.tdb"),
			N_("net connections cleanup\n"
			   "    Remove orphaned entries from connections.tdb")
		},
		{ NULL, NULL, 0, NULL, NULL }
	};

	if (!c->display_usage) {
		if (!connections_init(!c->opt_testmode)) {
			DEBUG(0, ("Failed to open connections tdb\n"));
			return -1;
		}
	}

	ret = net_run_function(c, argc, argv, "net connections", func);

	return ret;
}
