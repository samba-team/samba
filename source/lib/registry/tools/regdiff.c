/* 
   Unix SMB/CIFS implementation.
   simple registry frontend
   
   Copyright (C) Jelmer Vernooij 2004-2005

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
#include "lib/registry/registry.h"
#include "lib/events/events.h"
#include "lib/cmdline/popt_common.h"

int main(int argc, char **argv)
{
	int opt;
	poptContext pc;
	char *outputfile = NULL;
	struct registry_context *h1 = NULL, *h2 = NULL;
	int from_null = 0;
	WERROR error;
	struct reg_diff *diff;
	struct poptOption long_options[] = {
		POPT_AUTOHELP
		{"output", 'o', POPT_ARG_STRING, &outputfile, 'o', "output file to use", NULL },
		{"null", 'n', POPT_ARG_NONE, &from_null, 'n', "Diff from NULL", NULL },
		{"remote", 'R', POPT_ARG_STRING, NULL, 0, "Connect to remote server" , NULL },
		{"local", 'L', POPT_ARG_NONE, NULL, 0, "Open local registry", NULL },
		POPT_COMMON_SAMBA
		POPT_COMMON_CREDENTIALS
		POPT_COMMON_VERSION
		{ NULL }
	};

	registry_init();

	pc = poptGetContext(argv[0], argc, (const char **) argv, long_options,0);

	while((opt = poptGetNextOpt(pc)) != -1) {
		error = WERR_OK;
		switch(opt)	{
		case 'L':
			if (!h1 && !from_null) error = reg_open_local(NULL, &h1, NULL, cmdline_credentials);
			else if (!h2) error = reg_open_local(NULL, &h2, NULL, cmdline_credentials);
			break;
		case 'R':
			if (!h1 && !from_null) 
				error = reg_open_remote(&h1, NULL, cmdline_credentials, 
							poptGetOptArg(pc), NULL);
			else if (!h2) error = reg_open_remote(&h2, NULL, cmdline_credentials, 
							      poptGetOptArg(pc), NULL);
			break;
		}

		if (!W_ERROR_IS_OK(error)) {
			fprintf(stderr, "Error: %s\n", win_errstr(error));
			return 1;
		}
	}

	poptFreeContext(pc);

	diff = reg_generate_diff(NULL, h1, h2);
	if (!diff) {
		fprintf(stderr, "Unable to generate diff between keys\n");
		return -1;
	}

	reg_diff_save(diff, outputfile);

	return 0;
}
