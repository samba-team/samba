/* 
   Unix SMB/CIFS implementation.

   Standalone client for ESP scripting.

   Copyright (C) Tim Potter <tpot@samba.org> 2005

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
#include "web_server/ejs/ejs.h"

void http_exception(const char *reason)
{
	fprintf(stderr, "smbscript exception: %s", reason);
	exit(1);
}

extern void		ejsDefineStringCFunction(EjsId eid, const char *functionName, 
					MprStringCFunction fn, void *thisPtr, int flags);

static int writeProc(MprVarHandle userHandle, int argc, char **argv)
{
	int i;

	mprAssert(argv);
	for (i = 0; i < argc; i++) {
		printf("%s", argv[i]);
	}
	return 0;
}

 int main(int argc, const char *argv[])
{
	EjsId eid;
	EjsHandle primary, alternate;
	MprVar result;
	char *emsg;

	ejsOpen(0, 0, 0);
	eid = ejsOpenEngine(primary, alternate);
	ejsDefineStringCFunction(eid, "write", writeProc, NULL, 0);
	ejsEvalScript(0, "write(\"hello\n\");", &result, &emsg);
	ejsClose();

	printf("emsg = %s\n", emsg);

	return 0;
}
