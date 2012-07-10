/*
 * Samba Unix/Linux SMB client library
 * Registry Editor
 * Copyright (C) Christopher Davis 2012
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
#include "popt_common.h"
#include "lib/util/data_blob.h"
#include "lib/registry/registry.h"
#include "regedit.h"
#include <ncurses.h>
#include <menu.h>

int main(int argc, char **argv)
{
	struct poptOption long_options[] = {
		POPT_AUTOHELP
		/* ... */
		POPT_COMMON_SAMBA
		POPT_COMMON_CONNECTION
		POPT_COMMON_CREDENTIALS
		POPT_TABLEEND
	};
	int opt;
	poptContext pc;
	struct user_auth_info *auth_info;
	TALLOC_CTX *frame;
	struct registry_context *ctx;
	struct registry_key *hklm;
	struct registry_key *smbconf;
	uint32_t n;
	WERROR rv;

	initscr();
	endwin();

	frame = talloc_stackframe();

	setup_logging("regedit", DEBUG_DEFAULT_STDERR);
	lp_set_cmdline("log level", "0");
	lp_load_global(get_dyn_CONFIGFILE());

	/* process options */
	auth_info = user_auth_info_init(frame);
	if (auth_info == NULL) {
		exit(1);
	}
	popt_common_set_auth_info(auth_info);
	pc = poptGetContext("regedit", argc, (const char **)argv, long_options, 0);

	while ((opt = poptGetNextOpt(pc)) != -1) {
		/* TODO */
	}

	/* some simple tests */

	rv = reg_open_samba3(frame, &ctx);
	SMB_ASSERT(W_ERROR_IS_OK(rv));

	rv = reg_get_predefined_key_by_name(ctx, "HKEY_LOCAL_MACHINE", &hklm);
	SMB_ASSERT(W_ERROR_IS_OK(rv));

	printf("contents of hklm/SOFTWARE/Samba/smbconf...\n");

	rv = reg_open_key(ctx, hklm, "SOFTWARE\\Samba\\smbconf", &smbconf);
	SMB_ASSERT(W_ERROR_IS_OK(rv));

	printf("subkeys...\n");

	for (n = 0; ;++n) {
		const char *name, *klass;
		NTTIME modified;

		rv = reg_key_get_subkey_by_index(ctx, smbconf, n, &name,
						&klass, &modified);
		if (!W_ERROR_IS_OK(rv)) {
			break;
		}

		printf("%u: %s\n", (unsigned)n, name);
	}

	TALLOC_FREE(frame);

	return 0;
}
