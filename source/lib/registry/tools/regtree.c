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

static void print_tree(int l, REG_KEY *p, int fullpath, int novals)
{
	REG_KEY *subkey;
	REG_VAL *value;
	WERROR error;
	int i;

	for(i = 0; i < l; i++) putchar(' ');
	if(fullpath) printf("%s\n", reg_key_get_path(p));
	else printf("%s\n", reg_key_name(p));

	for(i = 0; W_ERROR_IS_OK(error = reg_key_get_subkey_by_index(p, i, &subkey)); i++) {
		print_tree(l+1, subkey, fullpath, novals);
		reg_key_free(subkey);
	}

	if(!W_ERROR_EQUAL(error, WERR_NO_MORE_ITEMS)) {
		DEBUG(0, ("Error occured while fetching subkeys for '%s': %s\n", reg_key_get_path(p), win_errstr(error)));
	}

	if(!novals) {
		for(i = 0; W_ERROR_IS_OK(error = reg_key_get_value_by_index(p, i, &value)); i++) {
			int j;
			char *desc;
			for(j = 0; j < l+1; j++) putchar(' ');
			desc = reg_val_description(value);
			printf("%s\n", desc);
			free(desc);
			reg_val_free(value);
		}

		if(!W_ERROR_EQUAL(error, WERR_NO_MORE_ITEMS)) {
			DEBUG(0, ("Error occured while fetching values for '%s': %s\n", reg_key_get_path(p), win_errstr(error)));
		}
	}
}

 int main(int argc, char **argv)
{
	int opt, i;
	const char *backend = "dir";
	const char *credentials = NULL;
	poptContext pc;
	REG_KEY *root;
	REG_HANDLE *h;
	WERROR error;
	int fullpath = 0, no_values = 0;
	struct poptOption long_options[] = {
		POPT_AUTOHELP
		{"backend", 'b', POPT_ARG_STRING, &backend, 0, "backend to use", NULL},
		{"fullpath", 'f', POPT_ARG_NONE, &fullpath, 0, "show full paths", NULL},
		{"credentials", 'c', POPT_ARG_STRING, &credentials, 0, "credentials (user%password)", NULL},
		{"no-values", 'V', POPT_ARG_NONE, &no_values, 0, "don't show values", NULL},
		POPT_TABLEEND
	};

	pc = poptGetContext(argv[0], argc, (const char **) argv, long_options,0);
	
	while((opt = poptGetNextOpt(pc)) != -1) {
	}

	setup_logging("regtree", True);

	error = reg_open(backend, poptPeekArg(pc), credentials, &h);
	if(!W_ERROR_IS_OK(error)) {
		fprintf(stderr, "Unable to open '%s' with backend '%s':%s \n", poptGetArg(pc), backend, win_errstr(error));
		return 1;
	}
	poptFreeContext(pc);

	error = WERR_OK;

	for(i = 0; W_ERROR_IS_OK(error); i++) {
		error = reg_get_hive(h, i, &root);
		if(!W_ERROR_IS_OK(error)) return 1;

		print_tree(0, root, fullpath, no_values);
	}
	
	return 0;
}
