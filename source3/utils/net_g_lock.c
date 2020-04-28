/*
 * Samba Unix/Linux SMB client library
 * Interface to the g_lock facility
 * Copyright (C) Volker Lendecke 2009
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
#include "lib/util/server_id.h"
#include "g_lock.h"
#include "messages.h"
#include "lib/util/util_tdb.h"

static bool net_g_lock_init(TALLOC_CTX *mem_ctx,
			    struct tevent_context **pev,
			    struct messaging_context **pmsg,
			    struct g_lock_ctx **pg_ctx)
{
	struct tevent_context *ev = NULL;
	struct messaging_context *msg = NULL;
	struct g_lock_ctx *g_ctx = NULL;

	ev = samba_tevent_context_init(mem_ctx);
	if (ev == NULL) {
		d_fprintf(stderr, "ERROR: could not init event context\n");
		goto fail;
	}
	msg = messaging_init(mem_ctx, ev);
	if (msg == NULL) {
		d_fprintf(stderr, "ERROR: could not init messaging context\n");
		goto fail;
	}
	g_ctx = g_lock_ctx_init(mem_ctx, msg);
	if (g_ctx == NULL) {
		d_fprintf(stderr, "ERROR: could not init g_lock context\n");
		goto fail;
	}

	*pev = ev;
	*pmsg = msg;
	*pg_ctx = g_ctx;
	return true;
fail:
	TALLOC_FREE(g_ctx);
	TALLOC_FREE(msg);
	TALLOC_FREE(ev);
	return false;
}

static int net_g_lock_do(struct net_context *c, int argc, const char **argv)
{
	struct g_lock_ctx *ctx = NULL;
	TDB_DATA key = {0};
	const char *cmd = NULL;
	int timeout;
	NTSTATUS status;
	int result = -1;

	if (argc != 3) {
		d_printf("Usage: net g_lock do <lockname> <timeout> "
			 "<command>\n");
		return -1;
	}
	key = string_term_tdb_data(argv[0]);
	timeout = atoi(argv[1]);
	cmd = argv[2];

	ctx = g_lock_ctx_init(c, c->msg_ctx);
	if (ctx == NULL) {
		d_fprintf(stderr, _("g_lock_ctx_init failed\n"));
		return -1;
	}
	status = g_lock_lock(
		ctx,
		key,
		G_LOCK_WRITE,
		timeval_set(timeout / 1000, timeout % 1000));
	if (!NT_STATUS_IS_OK(status)) {
		d_fprintf(stderr,
			  _("g_lock_lock failed: %s\n"),
			  nt_errstr(status));
		goto done;
	}

	result = system(cmd);

	g_lock_unlock(ctx, key);

	if (result == -1) {
		d_fprintf(stderr, "ERROR: system() returned %s\n",
			  strerror(errno));
		goto done;
	}
	d_fprintf(stderr, "command returned %d\n", result);

done:
	TALLOC_FREE(ctx);
	return result;
}

static void net_g_lock_dump_fn(struct server_id exclusive,
				size_t num_shared,
				struct server_id *shared,
				const uint8_t *data,
				size_t datalen,
				void *private_data)
{
	struct server_id_buf idbuf;

	if (exclusive.pid != 0) {
		d_printf("%s: WRITE\n",
			 server_id_str_buf(exclusive, &idbuf));
	} else {
		size_t i;
		for (i=0; i<num_shared; i++) {
			d_printf("%s: READ\n",
				 server_id_str_buf(shared[i], &idbuf));
		}
	}
	dump_data_file(data, datalen, true, stdout);
}

static int net_g_lock_dump(struct net_context *c, int argc, const char **argv)
{
	struct tevent_context *ev = NULL;
	struct messaging_context *msg = NULL;
	struct g_lock_ctx *g_ctx = NULL;
	int ret = -1;

	if (argc != 1) {
		d_printf("Usage: net g_lock dump <lockname>\n");
		return -1;
	}

	if (!net_g_lock_init(talloc_tos(), &ev, &msg, &g_ctx)) {
		goto done;
	}

	(void)g_lock_dump(g_ctx, string_term_tdb_data(argv[0]),
			  net_g_lock_dump_fn, NULL);

	ret = 0;
done:
	TALLOC_FREE(g_ctx);
	TALLOC_FREE(msg);
	TALLOC_FREE(ev);
	return ret;
}

static int net_g_lock_dumpall_fn(TDB_DATA key, void *private_data)
{
	struct g_lock_ctx *g_ctx = talloc_get_type_abort(
		private_data, struct g_lock_ctx);

	dump_data_file(key.dptr, key.dsize, true, stdout);
	g_lock_dump(g_ctx, key, net_g_lock_dump_fn, NULL);
	printf("\n");

	return 0;
}

static int net_g_lock_dumpall(
	struct net_context *c, int argc, const char **argv)
{
	struct tevent_context *ev = NULL;
	struct messaging_context *msg = NULL;
	struct g_lock_ctx *g_ctx = NULL;
	int ret = -1;

	if (argc != 0) {
		d_printf("Usage: net g_lock locks\n");
		return -1;
	}

	if (!net_g_lock_init(talloc_tos(), &ev, &msg, &g_ctx)) {
		goto done;
	}

	ret = g_lock_locks(g_ctx, net_g_lock_dumpall_fn, g_ctx);
done:
	TALLOC_FREE(g_ctx);
	TALLOC_FREE(msg);
	TALLOC_FREE(ev);
	return ret < 0 ? -1 : ret;
}

static int net_g_lock_locks_fn(TDB_DATA key, void *private_data)
{
	dump_data_file(key.dptr, key.dsize, true, stdout);
	return 0;
}

static int net_g_lock_locks(struct net_context *c, int argc, const char **argv)
{
	struct tevent_context *ev = NULL;
	struct messaging_context *msg = NULL;
	struct g_lock_ctx *g_ctx = NULL;
	int ret = -1;

	if (argc != 0) {
		d_printf("Usage: net g_lock locks\n");
		return -1;
	}

	if (!net_g_lock_init(talloc_tos(), &ev, &msg, &g_ctx)) {
		goto done;
	}

	ret = g_lock_locks(g_ctx, net_g_lock_locks_fn, NULL);
done:
	TALLOC_FREE(g_ctx);
	TALLOC_FREE(msg);
	TALLOC_FREE(ev);
	return ret < 0 ? -1 : ret;
}

int net_g_lock(struct net_context *c, int argc, const char **argv)
{
	struct functable func[] = {
		{
			"do",
			net_g_lock_do,
			NET_TRANSPORT_LOCAL,
			N_("Execute a shell command under a lock"),
			N_("net g_lock do <lock name> <timeout> <command>\n")
		},
		{
			"locks",
			net_g_lock_locks,
			NET_TRANSPORT_LOCAL,
			N_("List all locknames"),
			N_("net g_lock locks\n")
		},
		{
			"dump",
			net_g_lock_dump,
			NET_TRANSPORT_LOCAL,
			N_("Dump a g_lock locking table"),
			N_("net g_lock dump <lock name>\n")
		},
		{
			"dumpall",
			net_g_lock_dumpall,
			NET_TRANSPORT_LOCAL,
			N_("Dump all g_lock locking tables"),
			N_("net g_lock dumpall\n")
		},
		{NULL, NULL, 0, NULL, NULL}
	};

	return net_run_function(c, argc, argv, "net g_lock", func);
}
