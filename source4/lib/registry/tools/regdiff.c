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

void writediff(REG_KEY *oldkey, REG_KEY *newkey, FILE *out)
{
	int i, numkeys1, numvals1, numvals2, numkeys2;

	numkeys1 = reg_key_num_subkeys(oldkey);
	for(i = 0; i < numkeys1; i++) {
		REG_KEY *t1 = reg_key_get_subkey_by_index(oldkey, i);
		if(!reg_key_get_subkey_by_name(newkey, reg_key_name(t1))) {
			fprintf(out, "-%s\n", reg_key_get_path(t1)+1);
		}
	}

	numkeys2 = reg_key_num_subkeys(newkey);
	for(i = 0; i < numkeys2; i++) {
		REG_KEY *t1 = reg_key_get_subkey_by_index(newkey, i);
		REG_KEY *t2 = reg_key_get_subkey_by_name(oldkey, reg_key_name(t1));
		if(!t2) {
			fprintf(out, "\n[%s]\n", reg_key_get_path(t1)+1);
		}
		writediff(t2, t1, out);
	}

	numvals2 = reg_key_num_values(newkey);
	for(i = 0; i < numvals2; i++) {
		REG_VAL *t1 = reg_key_get_value_by_index(newkey, i);
		REG_VAL *t2 = reg_key_get_value_by_name(oldkey, reg_val_name(t1));
		if(!t2 || reg_val_size(t2) != reg_val_size(t1) || memcmp(reg_val_data_blk(t1), reg_val_data_blk(t2), reg_val_size(t1))) {
			fprintf(out, "\"%s\"=%s:%s\n", reg_val_name(t1), str_regtype(reg_val_type(t1)), reg_val_data_string(t1));
		}
	}

	numvals1 = reg_key_num_values(oldkey);
	for(i = 0; i < numvals1; i++) {
		REG_VAL *t1 = reg_key_get_value_by_index(oldkey, i);
		if(!reg_key_get_value_by_name(newkey, reg_val_name(t1))) {
			fprintf(out, "\"%s\"=-\n", reg_val_name(t1));
		}
	}
}

int main (int argc, char **argv)
{
	uint32	setparms, checkparms;
	int opt;
	poptContext pc;
	REG_KEY *root;
	const char *backend1 = NULL, *backend2 = NULL;
	const char *location2;
	char *outputfile = NULL;
	FILE *fd = stdout;
	REG_HANDLE *h2;
	REG_KEY *root1 = NULL, *root2;
	int from_null = 0;
	int fullpath = 0, no_values = 0;
	struct poptOption long_options[] = {
		POPT_AUTOHELP
		{"backend", 'b', POPT_ARG_STRING, NULL, 'b', "backend to use", NULL},
		{"output", 'o', POPT_ARG_STRING, &outputfile, 'o', "output file to use", NULL },
		{"null", 'n', POPT_ARG_NONE, &from_null, 'n', "Diff from NULL" },
		POPT_TABLEEND
	};

	pc = poptGetContext(argv[0], argc, (const char **) argv, long_options,0);
	
	while((opt = poptGetNextOpt(pc)) != -1) {
		switch(opt)	{
			case 'b':
				if(!backend1 && !from_null) backend1 = poptGetOptArg(pc);
				else if(!backend2) backend2 = poptGetOptArg(pc);
				break;
		}
	}
	setup_logging(argv[0], True);

	if(!from_null) {
		REG_HANDLE *h1;
		const char *location1;
		location1 = poptGetArg(pc);
		if(!location1) {
			poptPrintUsage(pc, stderr, 0);
			return 1;
		}

		if(!backend1) backend1 = "dir";

		h1 = reg_open(backend1, location1, True);
		if(!h1) {
			fprintf(stderr, "Unable to open '%s' with backend '%s'\n", location1, backend1);
			return 1;
		}

		root1 = reg_get_root(h1);
	}

	location2 = poptGetArg(pc);
	if(!location2) {
		poptPrintUsage(pc, stderr, 0);
		return 2;
	}

	if(!backend2) backend2 = "dir";
	
	h2 = reg_open(backend2, location2, True);
	if(!h2) {
		fprintf(stderr, "Unable to open '%s' with backend '%s'\n", location2, backend2);
		return 1;
	}
	
	root2 = reg_get_root(h2);
	if(!root2) {
		fprintf(stderr, "Can't open root key for '%s:%s'\n", backend2, location2);
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

	writediff(root1, root2, fd); 

	fclose(fd);
	
	return 0;
}
