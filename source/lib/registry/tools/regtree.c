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

void print_tree(int l, REG_KEY *p, int fullpath, int novals)
{
	int num_subkeys, i, num_values;

	for(i = 0; i < l; i++) putchar(' ');
	if(fullpath) printf("%s\n", reg_key_get_path(p));
	else printf("%s\n", reg_key_name(p));

	num_subkeys = reg_key_num_subkeys(p);
	for(i = 0; i < num_subkeys; i++) {
		REG_KEY *subkey = reg_key_get_subkey_by_index(p, i);
		print_tree(l+1, subkey, fullpath, novals);
		reg_key_free(subkey);
	}

	if(!novals) {
		num_values = reg_key_num_values(p);
		for(i = 0; i < num_values; i++) {
			int j;
			char *desc;
			REG_VAL *value = reg_key_get_value_by_index(p, i);
			for(j = 0; j < l+1; j++) putchar(' ');
			desc = reg_val_description(value);
			printf("%s\n", desc);
			free(desc);
			reg_val_free(value);
		}
	}
}

int main (int argc, char **argv)
{
	uint32	setparms, checkparms;
	int opt;
	char *backend = "dir";
	poptContext pc;
	REG_KEY *root;
	REG_HANDLE *h;
	int fullpath = 0, no_values = 0;
	struct poptOption long_options[] = {
		POPT_AUTOHELP
		{"backend", 'b', POPT_ARG_STRING, &backend, 0, "backend to use", NULL},
		{"fullpath", 'f', POPT_ARG_NONE, &fullpath, 0, "show full paths", NULL},
		{"no-values", 'V', POPT_ARG_NONE, &no_values, 0, "don't show values", NULL},
		POPT_TABLEEND
	};

	pc = poptGetContext(argv[0], argc, (const char **) argv, long_options,0);
	
	while((opt = poptGetNextOpt(pc)) != -1) {
	}

	setup_logging("regtree", True);

	h = reg_open(backend, poptPeekArg(pc), True);
	if(!h) {
		fprintf(stderr, "Unable to open '%s' with backend '%s'\n", poptGetArg(pc), backend);
		return 1;
	}
	poptFreeContext(pc);

	root = reg_get_root(h);
	if(!root) return 1;

	print_tree(0, root, fullpath, no_values);
	
	return 0;
}
