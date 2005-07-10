/* 
   Unix SMB/CIFS implementation.

   Standalone client for ejs scripting.

   Copyright (C) Tim Potter <tpot@samba.org> 2005
   Copyright (C) Andrew Tridgell 2005

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
#include "lib/cmdline/popt_common.h"
#include "dynconfig.h"
#include "lib/ejs/ejs.h"

void ejs_exception(const char *reason)
{
	fprintf(stderr, "smbscript exception: %s", reason);
	exit(127);
}

 int main(int argc, const char **argv)
{
	EjsId eid;
	EjsHandle handle = 0;
	MprVar result;
	char *emsg, *script;
	size_t script_size;
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	const char **argv_list = NULL;
	const char *fname;
	struct MprVar v, *return_var;
	int exit_status, i;
	poptContext pc;
	int opt;
	struct poptOption long_options[] = {
		POPT_AUTOHELP
		POPT_COMMON_SAMBA
		POPT_COMMON_CREDENTIALS
		POPT_COMMON_VERSION
		POPT_TABLEEND
	};

	popt_common_dont_ask();

	pc = poptGetContext("smbscript", argc, argv, long_options, 0);

	poptSetOtherOptionHelp(pc, "<script> <args> ...");

	while((opt = poptGetNextOpt(pc)) != -1) /* noop */ ;

	smbscript_init_subsystems;

	mprSetCtx(mem_ctx);

	argv = poptGetArgs(pc);
	if (argv == NULL ||
	    argv[0] == NULL) {
		poptPrintUsage(pc, stdout, 0);
		exit(1);
	}
	fname = argv[0];

	if (ejsOpen(NULL, NULL, NULL) != 0) {
		fprintf(stderr, "smbscript: ejsOpen(): unable to initialise "
			"EJ subsystem\n");
		exit(127);
	}

	smb_setup_ejs_functions();

	if ((eid = ejsOpenEngine(handle, 0)) == (EjsId)-1) {
		fprintf(stderr, "smbscript: ejsOpenEngine(): unable to "
			"initialise an EJS engine\n");
		exit(127);
	}

	smb_setup_ejs_constants(eid);

	/* setup ARGV[] in the ejs environment */
	for (i=1;argv[i];i++) {
		argv_list = str_list_add(argv_list, argv[i]);
	}
	talloc_steal(mem_ctx, argv_list);
	v = mprList("ARGV", argv_list);
	mprSetPropertyValue(&v, "length", mprCreateIntegerVar(i-1));
	mprCreateProperty(ejsGetGlobalObject(eid), "ARGV", &v);

	/* load the script and advance past interpreter line*/
	script = file_load(fname, &script_size, mem_ctx);

	if ((script_size > 2) && script[0] == '#' && script[1] == '!') {
		script += 2;
		script_size -= 2;
		while (script_size) {
			if (*script == '\r' || *script == '\n')
				break;
			script++;
			script_size--;
		}
	}

	/* run the script */
	if (ejsEvalScript(eid, script, &result, &emsg) == -1) {
		fprintf(stderr, "smbscript: ejsEvalScript(): %s\n", emsg);
		exit(127);
	}

	return_var = ejsGetReturnValue(eid);
	exit_status = return_var->integer;

	ejsClose();

	talloc_free(mem_ctx);

	return exit_status;
}
