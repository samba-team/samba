/*
   Unix SMB/CIFS implementation.
   test program for the next_token() function

   Copyright (C) 2009 Michael Adam

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

/*
 * Diagnostic output for "next_token()".
 */

#include "includes.h"
#include "lib/cmdline/cmdline.h"

int main(int argc, const char *argv[])
{
	const char *sequence = "";
	poptContext pc;
	char *buff;
	TALLOC_CTX *ctx = talloc_stackframe();
	int opt;
	bool ok;

	struct poptOption long_options[] = {
		POPT_AUTOHELP
		POPT_COMMON_VERSION
		POPT_TABLEEND
	};

	smb_init_locale();

	ok = samba_cmdline_init(ctx,
				SAMBA_CMDLINE_CONFIG_CLIENT,
				false /* require_smbconf */);
	if (!ok) {
		DBG_ERR("Failed to init cmdline parser!\n");
		TALLOC_FREE(ctx);
		exit(1);
	}

	pc = samba_popt_get_context(getprogname(),
				    argc,
				    argv,
				    long_options,
				    POPT_CONTEXT_KEEP_FIRST);
	if (pc == NULL) {
		DBG_ERR("Failed to setup popt context!\n");
		TALLOC_FREE(ctx);
		exit(1);
	}

	poptSetOtherOptionHelp(pc, "[OPTION...] <sequence-string>");

	while((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case POPT_ERROR_BADOPT:
			fprintf(stderr, "\nInvalid option %s: %s\n\n",
				poptBadOption(pc, 0), poptStrerror(opt));
			poptPrintUsage(pc, stderr, 0);
			exit(1);
		}
	}

	sequence = poptGetArg(pc);

	if (sequence == NULL) {
		fprintf(stderr, "ERROR: missing sequence string\n");
		return 1;
	}

	lp_set_cmdline("log level", "0");

	while(next_token_talloc(ctx, &sequence, &buff, NULL)) {
		printf("[%s]\n", buff);
	}

	poptFreeContext(pc);
	talloc_free(ctx);

	return 0;
}

