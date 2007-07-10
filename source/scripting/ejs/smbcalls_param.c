/* 
   Unix SMB/CIFS implementation.

   provide hooks into smbd C calls from ejs scripts

   Copyright (C) Jelmer Vernooij 2005
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "scripting/ejs/smbcalls.h"
#include "lib/appweb/ejs/ejs.h"
#include "param/param.h"

/*
  get parameter

  value = param.get("name");
  value = param.get("section", "name");
*/
static int ejs_param_get(MprVarHandle eid, int argc, char **argv)
{
	struct param_context *ctx;
	const char *ret;
	if (argc != 1 && argc != 2) {
		ejsSetErrorMsg(eid, "param.get invalid argument count");
		return -1;
	}

	ctx = mprGetThisPtr(eid, "param");
	mprAssert(ctx);
	
	if (argc == 2) {
		ret = param_get_string(ctx, argv[0], argv[1]);
	} else {
		ret = param_get_string(ctx, NULL, argv[0]);
	}

	if (ret) {
		mpr_Return(eid, mprString(ret));
	} else {
		mpr_Return(eid, mprCreateUndefinedVar());
	}
	return 0;
}

/*
  get list parameter

  ok = param.get_list("name");
  ok = param.get_list("section", "name");
*/
static int ejs_param_get_list(MprVarHandle eid, int argc, char **argv)
{
	struct param_context *ctx;
	const char **ret;

	if (argc != 1 && argc != 2) {
		ejsSetErrorMsg(eid, "param.get_list invalid argument count");
		return -1;
	}

	ctx = mprGetThisPtr(eid, "param");
	mprAssert(ctx);
	
	if (argc == 2) {
		ret = param_get_string_list(ctx, argv[0], argv[1], NULL);
	} else {
		ret = param_get_string_list(ctx, NULL, argv[0], NULL);
	}

	if (ret != NULL) {
		mpr_Return(eid, mprList("array", ret));
	} else {
		mpr_Return(eid, mprCreateUndefinedVar());
	}
	return 0;
}

/*
  set parameter

  ok = param.set("name", "value");
  ok = param.set("section", "name", "value");
*/
static int ejs_param_set(MprVarHandle eid, int argc, struct MprVar **argv)
{
	struct param_context *ctx;
	const char **list;
	const char *section, *paramname;
	struct MprVar *value;
	bool ret;
	if (argc != 2 && argc != 3) {
		ejsSetErrorMsg(eid, "param.set invalid argument count");
		return -1;
	}

	ctx = mprGetThisPtr(eid, "param");
	mprAssert(ctx);

	
	if (argc == 3) {
		section = mprToString(argv[0]);
		paramname = mprToString(argv[1]);
		value = argv[2];
	} else {
		section = NULL;
		paramname = mprToString(argv[0]);
		value = argv[1];
	}
	
	list = mprToList(mprMemCtx(), value);
	if (list) {
		ret = param_set_string_list(ctx, section, paramname, list);
	} else {
		ret = param_set_string(ctx, section, paramname, mprToString(value));
	}

	mpr_Return(eid, mprCreateBoolVar(ret));
	return 0;
}

/* 
  param data as a two-level array

  data = param.data;
  */
static int ejs_param_data(MprVarHandle eid, int argc, char **argv)
{
	struct param_context *ctx;
	struct MprVar ret;
	struct param_section *sec;

	if (argc != 0) {
		ejsSetErrorMsg(eid, "param.data does not take arguments");
		return -1;
	}

	ctx = mprGetThisPtr(eid, "param");
	mprAssert(ctx);

	ret = mprObject("array");

	for (sec = ctx->sections; sec; sec = sec->next) {
		struct MprVar ps = mprObject("array");
		struct param *p;

		for (p = sec->parameters; p; p = p->next) {
			mprSetVar(&ps, p->name, mprString(p->value));
		}
		
		mprSetVar(&ret, sec->name, ps);
	}

	mpr_Return(eid, ret);
	
	return 0;
}

/*
  load file
  
  ok = param.load(file);
*/
static int ejs_param_load(MprVarHandle eid, int argc, char **argv)
{
	struct param_context *ctx;
	bool ret;

	if (argc != 1) {
		ejsSetErrorMsg(eid, "param.load invalid argument count");
		return -1;
	}

	ctx = mprGetThisPtr(eid, "param");
	mprAssert(ctx);

	ret = param_read(ctx, argv[0]);
	
	mpr_Return(eid, mprCreateBoolVar(ret));
	return 0;
}


/*
  save file
  
  ok = param.save(file);
*/
static int ejs_param_save(MprVarHandle eid, int argc, char **argv)
{
	struct param_context *ctx;
	bool ret;

	if (argc != 1) {
		ejsSetErrorMsg(eid, "param.save invalid argument count");
		return -1;
	}

	ctx = mprGetThisPtr(eid, "param");
	mprAssert(ctx);

	ret = param_write(ctx, argv[0]);
	
	mpr_Return(eid, mprCreateBoolVar(ret));
	return 0;
}

static void param_add_members(struct MprVar *obj)
{
	mprSetStringCFunction(obj, "get", ejs_param_get);
	mprSetStringCFunction(obj, "get_list", ejs_param_get_list);
	mprSetCFunction(obj, "set", ejs_param_set);
	mprSetStringCFunction(obj, "load", ejs_param_load);
	mprSetStringCFunction(obj, "save", ejs_param_save);
	mprSetStringCFunction(obj, "data", ejs_param_data);
}

/*
  initialise param ejs subsystem
*/
static int ejs_param_init(MprVarHandle eid, int argc, struct MprVar **argv)
{
	struct MprVar *obj = mprInitObject(eid, "param", argc, argv);

	mprSetPtrChild(obj, "param", param_init(mprMemCtx()));

	param_add_members(obj);

	return 0;
}

struct MprVar mprParam(struct param_context *ctx)
{
	struct MprVar mpv = mprObject("param");
	mprSetPtrChild(&mpv, "param", ctx);
	param_add_members(&mpv);
	return mpv;
}

/*
  setup C functions that be called from ejs
*/
void smb_setup_ejs_param(void)
{
	ejsDefineCFunction(-1, "param_init", ejs_param_init, NULL, MPR_VAR_SCRIPT_HANDLE);
}
