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
#include "locking/proto.h"
#include "librpc/gen_ndr/open_files.h"
#include "librpc/gen_ndr/ndr_open_files.h"

static int net_tdb_locking_dump(TALLOC_CTX *mem_ctx,
				struct share_mode_data *data)
{
	struct ndr_print *ndr_print;

	ndr_print = talloc_zero(mem_ctx, struct ndr_print);
	if (ndr_print == NULL) {
		d_printf("Could not allocate memory.\n");
		return -1;
	}

	ndr_print->print = ndr_print_printf_helper;
	ndr_print->depth = 1;
	ndr_print_share_mode_data(ndr_print, "SHARE_MODE_DATA", data);
	TALLOC_FREE(ndr_print);

	return 0;
}

static int net_tdb_locking_fetch(TALLOC_CTX *mem_ctx, const char *hexkey,
				 struct share_mode_lock **lock)
{
	DATA_BLOB blob;
	struct file_id id;
	bool ok;

	blob = strhex_to_data_blob(mem_ctx, hexkey);
	if (blob.length != sizeof(struct file_id)) {
		d_printf("Invalid length %zu of key, expected %zu\n",
			 blob.length,
			 sizeof(struct file_id));
		return -1;
	}

	id = *(struct file_id *)blob.data;

	ok = locking_init_readonly();
	if (!ok) {
		d_printf("locking_init_readonly failed\n");
		return -1;
	}

	*lock = fetch_share_mode_unlocked(mem_ctx, id);

	if (*lock == NULL) {
		d_printf("Record with key %s not found.\n", hexkey);
		return -1;
	}

	return 0;
}

static int net_tdb_locking(struct net_context *c, int argc, const char **argv)
{
	TALLOC_CTX *mem_ctx = talloc_stackframe();
	struct share_mode_lock *lock;
	int ret;

	if (argc < 1) {
		d_printf("Usage: net tdb locking <key> [ dump ]\n");
		ret = -1;
		goto out;
	}

	ret = net_tdb_locking_fetch(mem_ctx, argv[0], &lock);
	if (ret != 0) {
		goto out;
	}

	if (argc == 2 && strequal(argv[1], "dump")) {
		ret = net_tdb_locking_dump(mem_ctx, lock->data);
	} else {
		NTSTATUS status;
		size_t num_share_modes = 0;

		status = share_mode_count_entries(
			lock->data->id, &num_share_modes);
		if (!NT_STATUS_IS_OK(status)) {
			d_fprintf(stderr,
				  "Could not count share entries: %s\n",
				  nt_errstr(status));
		}

		d_printf("Share path:            %s\n", lock->data->servicepath);
		d_printf("Name:                  %s\n", lock->data->base_name);
		d_printf("Number of share modes: %zu\n", num_share_modes);
	}

out:
	TALLOC_FREE(mem_ctx);
	return ret;
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
		{NULL, NULL, 0, NULL, NULL}
	};

	return net_run_function(c, argc, argv, "net tdb", func);
}
