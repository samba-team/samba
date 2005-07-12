/* 
   Unix SMB/CIFS implementation.

   provide access to string functions

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
#include "scripting/ejs/smbcalls.h"
#include "lib/ejs/ejs.h"
#include "system/passwd.h"

/*
  usage:
      var s = strlower("UPPER");
*/
static int ejs_strlower(MprVarHandle eid, int argc, char **argv)
{
	char *s;
	if (argc != 1) {
		ejsSetErrorMsg(eid, "strlower invalid arguments");
		return -1;
	}
	s = strlower_talloc(mprMemCtx(), argv[0]);
	mpr_Return(eid, mprString(s));
	talloc_free(s);
	return 0;
}

/*
  usage:
      var s = strupper("lower");
*/
static int ejs_strupper(MprVarHandle eid, int argc, char **argv)
{
	char *s;
	if (argc != 1) {
		ejsSetErrorMsg(eid, "strupper invalid arguments");
		return -1;
	}
	s = strupper_talloc(mprMemCtx(), argv[0]);
	mpr_Return(eid, mprString(s));
	talloc_free(s);
	return 0;
}

/*
  usage:
     list = split(".", "a.foo.bar");

  NOTE: does not take a regular expression, unlink perl split()
*/
static int ejs_split(MprVarHandle eid, int argc, char **argv)
{
	const char *separator;
	char *s, *p;
	struct MprVar ret;
	int count = 0;
	TALLOC_CTX *tmp_ctx = talloc_new(mprMemCtx());
	if (argc != 2) {
		ejsSetErrorMsg(eid, "split invalid arguments");
		return -1;
	}
	separator = argv[0];
	s = argv[1];

	ret = mprObject("list");

	while ((p = strstr(s, separator))) {
		char *s2 = talloc_strndup(tmp_ctx, s, (int)(p-s));
		mprAddArray(&ret, count++, mprString(s2));
		talloc_free(s2);
		s = p + strlen(separator);
	}
	if (*s) {
		mprAddArray(&ret, count++, mprString(s));
	}
	talloc_free(tmp_ctx);
	mpr_Return(eid, ret);
	return 0;
}


/*
  usage:
     str = join("DC=", list);
*/
static int ejs_join(MprVarHandle eid, int argc, struct MprVar **argv)
{
	int i;
	const char *separator;
	char *ret = NULL;
	const char **list;
	TALLOC_CTX *tmp_ctx = talloc_new(mprMemCtx());
	if (argc != 2 ||
	    argv[0]->type != MPR_TYPE_STRING ||
	    argv[1]->type != MPR_TYPE_OBJECT) {
		ejsSetErrorMsg(eid, "join invalid arguments");
		return -1;
	}

	separator = mprToString(argv[0]);
	list      = mprToArray(tmp_ctx, argv[1]);

	if (list == NULL || list[0] == NULL) {
		talloc_free(tmp_ctx);
		mpr_Return(eid, mprString(NULL));
		return 0;
	}
	
	ret = talloc_strdup(tmp_ctx, list[0]);
	if (ret == NULL) {
		goto failed;
	}
	for (i=1;list[i];i++) {
		ret = talloc_asprintf_append(ret, "%s%s", separator, list[i]);
		if (ret == NULL) {
			goto failed;
		}
	}
	mpr_Return(eid, mprString(ret));
	talloc_free(tmp_ctx);
	return 0;
failed:
	ejsSetErrorMsg(eid, "out of memory");
	return -1;
}

/*
  load a file as a string
  usage:
     string = FileLoad(filename);
*/
static int ejs_FileLoad(MprVarHandle eid, int argc, char **argv)
{
	char *s;
	if (argc != 1) {
		ejsSetErrorMsg(eid, "FileLoad invalid arguments");
		return -1;
	}

	s = file_load(argv[0], NULL, mprMemCtx());
	mpr_Return(eid, mprString(s));
	talloc_free(s);
	return 0;
}

/*
  setup C functions that be called from ejs
*/
void smb_setup_ejs_string(void)
{
	ejsDefineStringCFunction(-1, "strlower", ejs_strlower, NULL, MPR_VAR_SCRIPT_HANDLE);
	ejsDefineStringCFunction(-1, "strupper", ejs_strupper, NULL, MPR_VAR_SCRIPT_HANDLE);
	ejsDefineStringCFunction(-1, "split", ejs_split, NULL, MPR_VAR_SCRIPT_HANDLE);
	ejsDefineStringCFunction(-1, "FileLoad", ejs_FileLoad, NULL, MPR_VAR_SCRIPT_HANDLE);
	ejsDefineCFunction(-1, "join", ejs_join, NULL, MPR_VAR_SCRIPT_HANDLE);
}
