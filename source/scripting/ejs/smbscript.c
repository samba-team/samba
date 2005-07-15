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
#include "dynconfig.h"
#include "lib/appweb/ejs/ejs.h"
#include "scripting/ejs/smbcalls.h"

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
	struct MprVar *return_var;
	int exit_status, i;

	smbscript_init_subsystems;
	mprSetCtx(mem_ctx);

	lp_load(dyn_CONFIGFILE);

	if (argc < 2) {
		fprintf(stderr, "You must supply a script name\n");
		exit(1);
	}

	fname = argv[1];

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

	/* setup ARGV[] in the ejs environment */
	for (i=1;argv[i];i++) {
		argv_list = str_list_add(argv_list, argv[i]);
	}
	talloc_steal(mem_ctx, argv_list);
	mprSetVar(ejsGetGlobalObject(eid), "ARGV", mprList("ARGV", argv_list));

	/* load the script and advance past interpreter line*/
	script = file_load(fname, &script_size, mem_ctx);

	/* allow scriptable js */
	if (strncmp(script, "#!", 2) == 0) {
		script += strcspn(script, "\r\n");
		script += strspn(script, "\r\n");
	}
	/* and this copes with the ugly exec hack */
	if (strncmp(script, "exec ", 5) == 0) {
		script += strcspn(script, "\r\n");
		script += strspn(script, "\r\n");
	}

	/* run the script */
	if (ejsEvalScript(eid, script, &result, &emsg) == -1) {
		fprintf(stderr, "smbscript: ejsEvalScript(): %s\n", emsg);
		exit(127);
	}

	return_var = ejsGetReturnValue(eid);
	exit_status = mprVarToNumber(return_var);

	ejsClose();

	talloc_free(mem_ctx);

	return exit_status;
}
