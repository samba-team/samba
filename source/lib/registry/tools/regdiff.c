/* 
   Unix SMB/CIFS implementation.
   simple registry frontend
   
   Copyright (C) Jelmer Vernooij 2004

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

static void writediff(REG_KEY *oldkey, REG_KEY *newkey, FILE *out)
{
	int i;
	REG_KEY *t1, *t2;
	REG_VAL *v1, *v2;
	WERROR error1, error2;

	for(i = 0; W_ERROR_IS_OK(error1 = reg_key_get_subkey_by_index(oldkey, i, &t1)); i++) {
		error2 = reg_key_get_subkey_by_name(newkey, reg_key_name(t1), &t2);
		if(W_ERROR_EQUAL(error2, WERR_DEST_NOT_FOUND)) {
			fprintf(out, "-%s\n", reg_key_get_path(t1)+1);
		} else if(!W_ERROR_IS_OK(error2)) {
			DEBUG(0, ("Error occured while getting subkey by name: %d\n", W_ERROR_V(error2)));
		}
	}

	if(!W_ERROR_EQUAL(error1, WERR_NO_MORE_ITEMS)) {
		DEBUG(0, ("Error occured while getting subkey by index: %d\n", W_ERROR_V(error1)));
		return;
	}

	for(i = 0; W_ERROR_IS_OK(error1 = reg_key_get_subkey_by_index(newkey, i, &t1)); i++) {
		error2 = reg_key_get_subkey_by_name(oldkey, reg_key_name(t1), &t2);
		if(W_ERROR_EQUAL(error2, WERR_DEST_NOT_FOUND)) {
			fprintf(out, "\n[%s]\n", reg_key_get_path(t1)+1);
		} else if(!W_ERROR_IS_OK(error2)) {
			DEBUG(0, ("Error occured while getting subkey by name: %d\n", W_ERROR_V(error2)));
		}
		writediff(t2, t1, out);
	}

	if(!W_ERROR_EQUAL(error1, WERR_NO_MORE_ITEMS)) {
		DEBUG(0, ("Error occured while getting subkey by index: %d\n", W_ERROR_V(error1)));
		return;
	}

	for(i = 0; W_ERROR_IS_OK(error1 = reg_key_get_value_by_index(newkey, i, &v1)); i++) {
		error2 = reg_key_get_value_by_name(oldkey, reg_val_name(v1), &v2);
		if ((W_ERROR_IS_OK(error2) && (reg_val_size(v2) != reg_val_size(v1) || memcmp(reg_val_data_blk(v1), reg_val_data_blk(v2), reg_val_size(v1)))) 
			|| W_ERROR_EQUAL(error2, WERR_DEST_NOT_FOUND)) {
			fprintf(out, "\"%s\"=%s:%s\n", reg_val_name(v1), str_regtype(reg_val_type(v1)), reg_val_data_string(v1));
		}

		if(!W_ERROR_IS_OK(error2) && !W_ERROR_EQUAL(error2, WERR_DEST_NOT_FOUND)) {
			DEBUG(0, ("Error occured while getting value by name: %d\n", W_ERROR_V(error2)));
		}
	}

	if(!W_ERROR_EQUAL(error1, WERR_NO_MORE_ITEMS)) {
		DEBUG(0, ("Error occured while getting value by index: %d\n", W_ERROR_V(error1)));
		return;
	}


	for(i = 0; W_ERROR_IS_OK(error1 = reg_key_get_value_by_index(oldkey, i, &v1)); i++) {
		error2 = reg_key_get_value_by_name(newkey, reg_val_name(v1), &v2);
		if(W_ERROR_IS_OK(error2)) {
		} else if(W_ERROR_EQUAL(error2, WERR_DEST_NOT_FOUND)) {
			fprintf(out, "\"%s\"=-\n", reg_val_name(v1));
		} else {
			DEBUG(0, ("Error occured while getting value by name: %d\n", W_ERROR_V(error2)));
		}
	}

	if(!W_ERROR_EQUAL(error1, WERR_NO_MORE_ITEMS)) {
		DEBUG(0, ("Error occured while getting value by index: %d\n", W_ERROR_V(error1)));
		return;
	}
}

int main(int argc, char **argv)
{
	int opt;
	poptContext pc;
	const char *backend1 = NULL, *backend2 = NULL;
	const char *location2;
	const char *credentials1= NULL, *credentials2 = NULL;
	char *outputfile = NULL;
	FILE *fd = stdout;
	REG_HANDLE *h1, *h2;
	REG_KEY *root1 = NULL, *root2;
	int from_null = 0;
	int i;
	WERROR error, error2;
	struct poptOption long_options[] = {
		POPT_AUTOHELP
		{"backend", 'b', POPT_ARG_STRING, NULL, 'b', "backend to use", NULL},
		{"credentials", 'c', POPT_ARG_STRING, NULL, 'c', "credentials", NULL},
		{"output", 'o', POPT_ARG_STRING, &outputfile, 'o', "output file to use", NULL },
		{"null", 'n', POPT_ARG_NONE, &from_null, 'n', "Diff from NULL" },
		POPT_TABLEEND
	};

	pc = poptGetContext(argv[0], argc, (const char **) argv, long_options,0);

	while((opt = poptGetNextOpt(pc)) != -1) {
		switch(opt)	{
		case 'c':
			if(!credentials1 && !from_null) credentials1 = poptGetOptArg(pc);
			else if(!credentials2) credentials2 = poptGetOptArg(pc);
			break;
		case 'b':
			if(!backend1 && !from_null) backend1 = poptGetOptArg(pc);
			else if(!backend2) backend2 = poptGetOptArg(pc);
			break;
		}
	}
	setup_logging(argv[0], True);

	if(!from_null) {
		const char *location1;
		location1 = poptGetArg(pc);
		if(!location1) {
			poptPrintUsage(pc, stderr, 0);
			return 1;
		}

		if(!backend1) backend1 = "dir";

		error = reg_open(backend1, location1, credentials1, &h1);
		if(!W_ERROR_IS_OK(error)) {
			fprintf(stderr, "Unable to open '%s' with backend '%s'\n", location1, backend1);
			return 1;
		}
	}

	location2 = poptGetArg(pc);
	if(!location2) {
		poptPrintUsage(pc, stderr, 0);
		return 2;
	}

	if(!backend2) backend2 = "dir";

	error = reg_open(backend2, location2, credentials2, &h2);
	if(!W_ERROR_IS_OK(error)) {
		fprintf(stderr, "Unable to open '%s' with backend '%s'\n", location2, backend2);
		return 1;
	}

	poptFreeContext(pc);

	if(outputfile) {
		fd = fopen(outputfile, "w+");
		if(!fd) {
			fprintf(stderr, "Unable to open '%s'\n", outputfile);
			return 1;
		}
	}

	fprintf(fd, "REGEDIT4\n\n");
	fprintf(fd, "; Generated using regdiff\n");

	error2 = error = WERR_OK; 

	for(i = 0; ; i++) {
		if(backend1) error = reg_get_hive(h1, i, &root1);
		else root1 = NULL;

		if(!W_ERROR_IS_OK(error)) break;

		if(backend2) error2 = reg_get_hive(h2, i, &root2);
		else root2 = NULL;

		if(!W_ERROR_IS_OK(error2)) break;

		writediff(root1, root2, fd); 

		if(!root1 && !root2) break;
	}

	fclose(fd);

	return 0;
}
