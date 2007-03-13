/* 
   Unix SMB/CIFS implementation.
   simple registry frontend
   
   Copyright (C) 2004-2005 Jelmer Vernooij, jelmer@samba.org

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

#include "includes.h"
#include "lib/events/events.h"
#include "lib/registry/registry.h"
#include "lib/cmdline/popt_common.h"

int main(int argc, char **argv)
{
  	int opt;
	poptContext pc;
	const char *patch;
	struct registry_context *h;
	const char *remote = NULL;
	struct reg_diff *diff;
	WERROR error;
	struct poptOption long_options[] = {
		POPT_AUTOHELP
		{"remote", 'R', POPT_ARG_STRING, &remote, 0, "connect to specified remote server", NULL},
		POPT_COMMON_SAMBA
		POPT_COMMON_CREDENTIALS
		{ NULL }
	};

	pc = poptGetContext(argv[0], argc, (const char **) argv, long_options,0);

	while((opt = poptGetNextOpt(pc)) != -1) {
	}

	registry_init();

	if (remote) {
		error = reg_open_remote (&h, NULL, cmdline_credentials, remote, NULL);
	} else {
		error = reg_open_local (NULL, &h, NULL, cmdline_credentials);
	}

	if (W_ERROR_IS_OK(error)) {
		fprintf(stderr, "Error: %s\n", win_errstr(error));
		return 1;
	}
		
	patch = poptGetArg(pc);
	poptFreeContext(pc);

	diff = reg_diff_load(NULL, patch);
	if (!diff) {
		fprintf(stderr, "Unable to load registry patch from `%s'\n", patch);
		return 1;
	}

	reg_diff_apply(diff, h);

	return 0;
}
