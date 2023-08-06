/*
 * Unix SMB/CIFS implementation.
 * Test for lp_load()
 * Copyright (C) Michael Adam 2008
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
#include "lib/cmdline/cmdline.h"
#include "lib/param/param.h"

int main(int argc, const char **argv)
{
	const char *config_file = NULL;
	int ret = 0;
	poptContext pc;
	char *count_str = NULL;
	int i, count = 1;
	int opt;
	bool ok;

	struct poptOption long_options[] = {
		POPT_AUTOHELP
		{
			.longName   = "count",
			.shortName  = 'c',
			.argInfo    = POPT_ARG_STRING,
			.arg        = &count_str,
			.val        = 1,
			.descrip    = "Load config <count> number of times"
		},
		POPT_COMMON_DEBUG_ONLY
		POPT_COMMON_VERSION
		POPT_TABLEEND
	};

	TALLOC_CTX *frame = talloc_stackframe();
	struct loadparm_context *lp_ctx = NULL;

	smb_init_locale();

	ok = samba_cmdline_init(frame,
				SAMBA_CMDLINE_CONFIG_NONE,
				false /* require_smbconf */);
	if (!ok) {
		DBG_ERR("Failed to init cmdline parser!\n");
		TALLOC_FREE(frame);
		exit(ENOMEM);
	}
	lp_ctx = samba_cmdline_get_lp_ctx();
	lpcfg_set_cmdline(lp_ctx, "log level", "0");

	pc = samba_popt_get_context(getprogname(),
				    argc,
				    argv,
				    long_options,
				    0);
	if (pc == NULL) {
		DBG_ERR("Failed to setup popt context!\n");
		TALLOC_FREE(frame);
		exit(1);
	}
	poptSetOtherOptionHelp(pc, "[OPTION...] <config-file>");

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case POPT_ERROR_BADOPT:
			fprintf(stderr, "\nInvalid option %s: %s\n\n",
				poptBadOption(pc, 0), poptStrerror(opt));
			poptPrintUsage(pc, stderr, 0);
			exit(1);
		}
	}

	if (poptPeekArg(pc)) {
		config_file = talloc_strdup(frame, poptGetArg(pc));
		if (config_file == NULL) {
			DBG_ERR("out of memory\n");
			TALLOC_FREE(frame);
			exit(1);
		}
	} else {
		config_file = get_dyn_CONFIGFILE();
	}

	poptFreeContext(pc);

	if (count_str != NULL) {
		count = atoi(count_str);
	}

	for (i=0; i < count; i++) {
		printf("call lp_load() #%d: ", i+1);
		if (!lp_load_with_registry_shares(config_file)) {
			printf("ERROR.\n");
			ret = 1;
			goto done;
		}
		printf("ok.\n");
	}


done:
	gfree_loadparm();
	TALLOC_FREE(frame);
	return ret;
}

