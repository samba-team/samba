/*
 * Unix SMB/CIFS implementation.
 * Garble the netlogon_creds_cli key for testing purposes
 * Copyright (C) Volker Lendecke 2018
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
#include "system/filesys.h"
#include <talloc.h>
#include <tevent.h>
#include "messages.h"
#include "lib/util/talloc_stack.h"
#include "popt_common.h"
#include "lib/param/loadparm.h"
#include "lib/param/param.h"
#include "libcli/auth/netlogon_creds_cli.h"
#include "lib/dbwrap/dbwrap.h"
#include "lib/dbwrap/dbwrap_open.h"

int main(int argc, const char *argv[])
{
	TALLOC_CTX *mem_ctx = talloc_stackframe();
	struct tevent_context *ev;
	struct messaging_context *msg_ctx;
	struct loadparm_context *lp_ctx;
	struct db_context *global_db;
	struct netlogon_creds_cli_context *ctx;
	struct netlogon_creds_CredentialState *creds;
	NTSTATUS status;
	int ret = 1;

	smb_init_locale();

	if (!lp_load_global(get_dyn_CONFIGFILE())) {
		fprintf(stderr, "error opening config file %s. Error was %s\n",
			get_dyn_CONFIGFILE(), strerror(errno));
		goto done;
	}

	if (argc != 4) {
		fprintf(stderr, "usage: %s cli_computer domain dc\n", argv[0]);
		goto done;
	}

	lp_ctx = loadparm_init_s3(mem_ctx, loadparm_s3_helpers());
	if (lp_ctx == NULL) {
		fprintf(stderr, "loadparm_init_s3 failed\n");
		goto done;
	}

	ev = samba_tevent_context_init(mem_ctx);
	if (ev == NULL) {
		fprintf(stderr, "samba3_tevent_context_init failed\n");
		goto done;
	}
	msg_ctx = messaging_init(mem_ctx, ev);
	if (msg_ctx == NULL) {
		fprintf(stderr, "messaging_init failed\n");
		goto done;
	}

	global_db = db_open(
		mem_ctx,
		lpcfg_private_db_path(mem_ctx, lp_ctx, "netlogon_creds_cli"),
		0, TDB_CLEAR_IF_FIRST|TDB_INCOMPATIBLE_HASH,
		O_RDWR|O_CREAT, 0600, DBWRAP_LOCK_ORDER_2,
		DBWRAP_FLAG_OPTIMIZE_READONLY_ACCESS);
	if (global_db == NULL) {
		fprintf(stderr, "db_open failed\n");
		goto done;
	}

	status = netlogon_creds_cli_set_global_db(&global_db);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr,
			"netlogon_creds_cli_set_global_db failed: %s\n",
			nt_errstr(status));
		goto done;
	}

	status = netlogon_creds_cli_context_global(
		lp_ctx,
		msg_ctx,
		talloc_asprintf(mem_ctx, "%s$", argv[1]),
		SEC_CHAN_WKSTA,
		argv[3],
		argv[2],
		"",
		mem_ctx,
		&ctx);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr,
			"netlogon_creds_cli_context_global failed: %s\n",
			nt_errstr(status));
		goto done;
	}

	status = netlogon_creds_cli_lock(ctx,
					 mem_ctx,
					 &creds);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr,
			"netlogon_creds_cli_get failed: %s\n",
			nt_errstr(status));
		goto done;
	}

	creds->session_key[0]++;

	status = netlogon_creds_cli_store(ctx, creds);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr,
			"netlogon_creds_cli_store failed: %s\n",
			nt_errstr(status));
		goto done;
	}

	TALLOC_FREE(creds);

	ret = 0;
done:
	TALLOC_FREE(mem_ctx);
	return ret;
}
