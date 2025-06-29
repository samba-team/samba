/*
 * Samba Unix/Linux client library
 * net tdb commands to query tdb record information
 * Copyright (C) 2016, 2017 Christof Schmitt <cs@samba.org>
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
#include "locking/share_mode_lock.h"
#include "locking/proto.h"
#include "librpc/gen_ndr/open_files.h"
#include "librpc/gen_ndr/ndr_open_files.h"

static int net_tdb_locking(struct net_context *c, int argc, const char **argv)
{
	TALLOC_CTX *mem_ctx = talloc_stackframe();
	struct share_mode_lock *lock;
	DATA_BLOB blob = { .data = NULL };
	struct file_id id = { .inode = 0 };
	int ret = -1;
	bool ok;

	if (argc < 1) {
		d_printf("Usage: net tdb locking <key> [ dump ]\n");
		goto out;
	}

	ok = locking_init_readonly();
	if (!ok) {
		d_printf("locking_init_readonly failed\n");
		goto out;
	}

	blob = strhex_to_data_blob(mem_ctx, argv[0]);
	if (blob.length != sizeof(struct file_id)) {
		d_printf("Invalid length %zu of key, expected %zu\n",
			 blob.length,
			 sizeof(struct file_id));
		goto out;
	}

	memcpy(&id, blob.data, blob.length);

	lock = fetch_share_mode_unlocked(mem_ctx, id);
	if (lock == NULL) {
		d_printf("Record with key %s not found.\n", argv[1]);
		goto out;
	}

	if (argc == 2 && strequal(argv[1], "dump")) {
		char *dump = share_mode_data_dump(mem_ctx, lock);
		d_printf("%s\n", dump);
		TALLOC_FREE(dump);
	} else {
		NTSTATUS status;
		size_t num_share_modes = 0;

		status = share_mode_count_entries(id, &num_share_modes);
		if (!NT_STATUS_IS_OK(status)) {
			d_fprintf(stderr,
				  "Could not count share entries: %s\n",
				  nt_errstr(status));
			goto out;
		}

		d_printf("Share path:            %s\n",
			 share_mode_servicepath(lock));
		d_printf("Name:                  %s\n",
			 share_mode_filename(mem_ctx, lock));
		d_printf("Number of share modes: %zu\n", num_share_modes);
	}

	ret = 0;
out:
	TALLOC_FREE(mem_ctx);
	return ret;
}
static int net_tdb_smbXsrv(struct net_context *c, int argc, const char **argv)
{
	struct functable func[] = {
		{
			"wipedbs",
			net_serverid_wipedbs,
			NET_TRANSPORT_LOCAL,
			N_("Clean dead entries from smbXsrv databases"),
			N_("net tdb smbXsrv wipedbs\n"
			   "    Clean dead entries from smbXsrv databases")
		},
		{NULL, NULL, 0, NULL, NULL}
	};

	return net_run_function(c, argc, argv, "net tdb smbXsrv", func);
}

int net_tdb(struct net_context *c, int argc, const char **argv)
{
	struct functable func[] = {
		{ "locking",
		  net_tdb_locking,
		  NET_TRANSPORT_LOCAL,
		  N_("Show information for a record in locking.tdb"),
		  N_("net tdb locking <key>")
		},
		{
			"smbXsrv",
			net_tdb_smbXsrv,
			NET_TRANSPORT_LOCAL,
			N_("Manage smbXsrv databases"),
			N_("net tdb smbXsrv\n"
			   "    Manage smbXsrv databases")
		},
		{NULL, NULL, 0, NULL, NULL}
	};

	return net_run_function(c, argc, argv, "net tdb", func);
}
