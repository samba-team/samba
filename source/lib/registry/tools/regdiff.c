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
#include "dynconfig.h"
#include "registry.h"
#include "lib/cmdline/popt_common.h"

static void writediff(struct registry_key *oldkey, struct registry_key *newkey, FILE *out)
{
	int i;
	struct registry_key *t1, *t2;
	struct registry_value *v1, *v2;
	WERROR error1, error2;
	TALLOC_CTX *mem_ctx = talloc_init("writediff");

	for(i = 0; W_ERROR_IS_OK(error1 = reg_key_get_subkey_by_index(mem_ctx, oldkey, i, &t1)); i++) {
		error2 = reg_key_get_subkey_by_name(mem_ctx, newkey, t1->name, &t2);
		if(W_ERROR_EQUAL(error2, WERR_DEST_NOT_FOUND)) {
			fprintf(out, "-%s\n", t1->path+1);
		} else if(!W_ERROR_IS_OK(error2)) {
			DEBUG(0, ("Error occured while getting subkey by name: %d\n", W_ERROR_V(error2)));
		}
	}

	talloc_destroy(mem_ctx);

	if(!W_ERROR_EQUAL(error1, WERR_NO_MORE_ITEMS)) {
		DEBUG(0, ("Error occured while getting subkey by index: %d\n", W_ERROR_V(error1)));
		return;
	}

	mem_ctx = talloc_init("writediff");

	for(i = 0; W_ERROR_IS_OK(error1 = reg_key_get_subkey_by_index(mem_ctx, newkey, i, &t1)); i++) {
		error2 = reg_key_get_subkey_by_name(mem_ctx, oldkey, t1->name, &t2);
		if(W_ERROR_EQUAL(error2, WERR_DEST_NOT_FOUND)) {
			fprintf(out, "\n[%s]\n", t1->path+1);
		} else if(!W_ERROR_IS_OK(error2)) {
			DEBUG(0, ("Error occured while getting subkey by name: %d\n", W_ERROR_V(error2)));
		}
		writediff(t2, t1, out);
	}

	talloc_destroy(mem_ctx);

	if(!W_ERROR_EQUAL(error1, WERR_NO_MORE_ITEMS)) {
		DEBUG(0, ("Error occured while getting subkey by index: %d\n", W_ERROR_V(error1)));
		return;
	}


	mem_ctx = talloc_init("writediff");

	for(i = 0; W_ERROR_IS_OK(error1 = reg_key_get_value_by_index(mem_ctx, newkey, i, &v1)); i++) {
		error2 = reg_key_get_value_by_name(mem_ctx, oldkey, v1->name, &v2);
		if ((W_ERROR_IS_OK(error2) && (v2->data_len != v1->data_len || memcmp(v1->data_blk, v2->data_blk, v1->data_len))) 
			|| W_ERROR_EQUAL(error2, WERR_DEST_NOT_FOUND)) {
			fprintf(out, "\"%s\"=%s:%s\n", v1->name, str_regtype(v1->data_type), reg_val_data_string(mem_ctx, v1));
		}

		if(!W_ERROR_IS_OK(error2) && !W_ERROR_EQUAL(error2, WERR_DEST_NOT_FOUND)) {
			DEBUG(0, ("Error occured while getting value by name: %d\n", W_ERROR_V(error2)));
		}
	}

	talloc_destroy(mem_ctx);

	if(!W_ERROR_EQUAL(error1, WERR_NO_MORE_ITEMS)) {
		DEBUG(0, ("Error occured while getting value by index: %d\n", W_ERROR_V(error1)));
		return;
	}

	mem_ctx = talloc_init("writediff");

	for(i = 0; W_ERROR_IS_OK(error1 = reg_key_get_value_by_index(mem_ctx, oldkey, i, &v1)); i++) {
		error2 = reg_key_get_value_by_name(mem_ctx, newkey, v1->name, &v2);
		if(W_ERROR_IS_OK(error2)) {
		} else if(W_ERROR_EQUAL(error2, WERR_DEST_NOT_FOUND)) {
			fprintf(out, "\"%s\"=-\n", v1->name);
		} else {
			DEBUG(0, ("Error occured while getting value by name: %d\n", W_ERROR_V(error2)));
		}
	}

	talloc_destroy(mem_ctx);

	if(!W_ERROR_EQUAL(error1, WERR_NO_MORE_ITEMS)) {
		DEBUG(0, ("Error occured while getting value by index: %d\n", W_ERROR_V(error1)));
		return;
	}
}

 int main(int argc, char **argv)
{
	int opt;
	poptContext pc;
	char *outputfile = NULL;
	FILE *fd = stdout;
	struct registry_context *h1 = NULL, *h2 = NULL;
	int from_null = 0;
	int i;
	WERROR error, error2;
	struct poptOption long_options[] = {
		POPT_AUTOHELP
		POPT_COMMON_CREDENTIALS
		{"output", 'o', POPT_ARG_STRING, &outputfile, 'o', "output file to use", NULL },
		{"null", 'n', POPT_ARG_NONE, &from_null, 'n', "Diff from NULL", NULL },
		{"remote", 'R', POPT_ARG_STRING, NULL, 0, "Connect to remote server" , NULL },
		{"local", 'L', POPT_ARG_NONE, NULL, 0, "Open local registry", NULL },
		POPT_TABLEEND
	};

	regdiff_init_subsystems;

	if (!lp_load(dyn_CONFIGFILE,True,False,False)) {
		fprintf(stderr, "Can't load %s - run testparm to debug it\n", dyn_CONFIGFILE);
	}


	pc = poptGetContext(argv[0], argc, (const char **) argv, long_options,0);

	while((opt = poptGetNextOpt(pc)) != -1) {
		error = WERR_OK;
		switch(opt)	{
		case 'L':
			if (!h1 && !from_null) error = reg_open_local(&h1);
			else if (!h2) error = reg_open_local(&h2);
			break;
		case 'R':
			if (!h1 && !from_null) error = reg_open_remote(&h1, cmdline_get_username(), cmdline_get_userpassword(), poptGetOptArg(pc));
			else if (!h2) error = reg_open_remote(&h2, cmdline_get_username(), cmdline_get_userpassword(), poptGetOptArg(pc));
			break;
		}

		if (!W_ERROR_IS_OK(error)) {
			fprintf(stderr, "Error: %s\n", win_errstr(error));
			return 1;
		}
	}
	setup_logging(argv[0], True);

	poptFreeContext(pc);

	if(outputfile) {
		fd = fopen(outputfile, "w+");
		if(!fd) {
			fprintf(stderr, "Unable to open '%s'\n", outputfile);
			return 1;
		}
	}

	fprintf(fd, "REGEDIT4\n\n");
	fprintf(fd, "; Generated using regdiff, part of Samba\n");

	error2 = error = WERR_OK; 

	for(i = HKEY_CLASSES_ROOT; i <= HKEY_PN; i++) {
		struct registry_key *r1, *r2;
		error = reg_get_hive(h1, i, &r1);
		if (!W_ERROR_IS_OK(error)) {
			DEBUG(0, ("Unable to open hive %s for backend 1\n", reg_get_hkey_name(i)));
			continue;
		}
		
		error = reg_get_hive(h2, i, &r2);
		if (!W_ERROR_IS_OK(error)) {
			DEBUG(0, ("Unable to open hive %s for backend 2\n", reg_get_hkey_name(i)));
			continue;
		}

		writediff(r1, r2, fd); 
	}

	fclose(fd);

	return 0;
}
