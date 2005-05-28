/* 
   Unix SMB/CIFS implementation.

   provide hooks into C calls from esp scripts

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
#include "web_server/esp/esp.h"
#include "param/loadparm.h"
#include "lib/ldb/include/ldb.h"


/*
  add an indexed array element to a property
*/
static void mprAddArray(struct MprVar *var, int i, struct MprVar v)
{
	char idx[16];
	mprItoa(i, idx, sizeof(idx));
	mprCreateProperty(var, idx, &v);
}

/*
  construct a MprVar from a list
*/
static struct MprVar mprList(const char *name, const char **list)
{
	struct MprVar var;
	int i;

	var = mprCreateObjVar(name, ESP_HASH_SIZE);
	for (i=0;list && list[i];i++) {
		mprAddArray(&var, i, mprCreateStringVar(list[i], 1));
	}
	return var;
}

/*
  construct a string MprVar from a lump of data
*/
static struct MprVar mprData(const uint8_t *p, size_t length)
{
	struct MprVar var;
	char *s = talloc_strndup(NULL, p, length);
	if (s == NULL) {
		return mprCreateUndefinedVar();
	}
	var = mprCreateStringVar(s, 1);
	talloc_free(s);
	return var;
}

/*
  turn a ldb_message into a ejs object variable
*/
static struct MprVar mprLdbMessage(struct ldb_message *msg)
{
	struct MprVar var;
	int i;
	/* we force some attributes to always be an array in the
	   returned structure. This makes the scripting easier, as you don't 
	   need a special case for the single value case */
	const char *multivalued[] = { "objectClass", "memberOf", "privilege", 
					    "member", NULL };

	var = mprCreateObjVar(msg->dn, ESP_HASH_SIZE);
	for (i=0;i<msg->num_elements;i++) {
		struct ldb_message_element *el = &msg->elements[i];
		struct MprVar val;
		if (el->num_values == 1 &&
		    !str_list_check_ci(multivalued, el->name)) {
			val = mprData(el->values[0].data, el->values[0].length);
		} else {
			int j;
			val = mprCreateObjVar(el->name, ESP_HASH_SIZE);
			for (j=0;j<el->num_values;j++) {
				mprAddArray(&val, j, 
					    mprData(el->values[j].data, 
						    el->values[j].length));
			}
		}
		mprCreateProperty(&var, el->name, &val);
	}
	
	return var;		
}


/*
  turn an array of ldb_messages into a ejs object variable
*/
static struct MprVar mprLdbArray(struct ldb_message **msg, int count, 
				 const char *name)
{
	struct MprVar res;
	int i;

	res = mprCreateObjVar(name?name:"(NULL)", ESP_HASH_SIZE);
	for (i=0;i<count;i++) {
		mprAddArray(&res, i, mprLdbMessage(msg[i]));
	}
	return res;	
}


/*
  turn a MprVar string variable into a const char *
 */
static const char *mprToString(const struct MprVar *v)
{
	if (v->type != MPR_TYPE_STRING) return NULL;
	return v->string;
}

/*
  turn a MprVar object variable into a string list
  this assumes the object variable consists only of strings
*/
static const char **mprToList(TALLOC_CTX *mem_ctx, struct MprVar *v)
{
	const char **list = NULL;
	struct MprVar *el;

	if (v->type != MPR_TYPE_OBJECT ||
	    v->properties == NULL) {
		return NULL;
	}
	for (el=mprGetFirstProperty(v, MPR_ENUM_DATA);
	     el;
	     el=mprGetNextProperty(v, el, MPR_ENUM_DATA)) {
		const char *s = mprToString(el);
		if (s) {
			list = str_list_add(list, s);
		}
	}
	talloc_steal(mem_ctx, list);
	return list;
}

/*
  return the type of a variable
*/
static int esp_typeof(struct EspRequest *ep, int argc, struct MprVar **argv)
{
	const struct {
		MprType type;
		const char *name;
	} types[] = {
		{ MPR_TYPE_UNDEFINED, "undefined" },
		{ MPR_TYPE_NULL, "null" },
		{ MPR_TYPE_BOOL, "boolean" },
		{ MPR_TYPE_CFUNCTION, "function" },
		{ MPR_TYPE_FLOAT, "float" },
		{ MPR_TYPE_INT, "int" },
		{ MPR_TYPE_INT64, "int64" },
		{ MPR_TYPE_OBJECT, "object" },
		{ MPR_TYPE_FUNCTION, "function" },
		{ MPR_TYPE_STRING, "string" },
		{ MPR_TYPE_STRING_CFUNCTION, "function" }
	};
	int i;
	const char *type = "unknown";

	if (argc != 1) return -1;
	
	for (i=0;i<ARRAY_SIZE(types);i++) {
		if (argv[0]->type == types[i].type) {
			type = types[i].name;
			break;
		}
	}

	espSetReturnString(ep, type);
	return 0;
}

/*
  setup a return of a string list
*/
static void esp_returnlist(struct EspRequest *ep, 
			   const char *name, const char **list)
{
	espSetReturn(ep, mprList(name, list));
}

/*
  return a list of defined services
*/
static int esp_lpServices(struct EspRequest *ep, int argc, char **argv)
{
	int i;
	const char **list = NULL;
	if (argc != 0) return -1;
	
	for (i=0;i<lp_numservices();i++) {
		list = str_list_add(list, lp_servicename(i));
	}
	talloc_steal(ep, list);
	esp_returnlist(ep, "services", list);
	return 0;
}


/*
  allow access to loadparm variables from inside esp scripts in swat
  
  can be called in 4 ways:

    v = lpGet("type:parm");             gets a parametric variable
    v = lpGet("share", "type:parm");    gets a parametric variable on a share
    v = lpGet("parm");                  gets a global variable
    v = lpGet("share", "parm");         gets a share variable

  the returned variable is a ejs object. It is an array object for lists.  
*/
static int esp_lpGet(struct EspRequest *ep, int argc, char **argv)
{
	struct parm_struct *parm = NULL;
	void *parm_ptr = NULL;
	int i;

	if (argc < 1) return -1;

	if (argc == 2) {
		/* its a share parameter */
		int snum = lp_servicenumber(argv[0]);
		if (snum == -1) {
			return -1;
		}
		if (strchr(argv[1], ':')) {
			/* its a parametric option on a share */
			const char *type = talloc_strndup(ep, argv[1], strcspn(argv[1], ":"));
			const char *option = strchr(argv[1], ':') + 1;
			const char *value;
			if (type == NULL || option == NULL) return -1;
			value = lp_get_parametric(snum, type, option);
			if (value == NULL) return -1;
			espSetReturnString(ep, value);
			return 0;
		}

		parm = lp_parm_struct(argv[1]);
		if (parm == NULL || parm->class == P_GLOBAL) {
			return -1;
		}
		parm_ptr = lp_parm_ptr(snum, parm);
	} else if (strchr(argv[0], ':')) {
		/* its a global parametric option */
		const char *type = talloc_strndup(ep, argv[0], strcspn(argv[0], ":"));
		const char *option = strchr(argv[0], ':') + 1;
		const char *value;
		if (type == NULL || option == NULL) return -1;
		value = lp_get_parametric(-1, type, option);
		if (value == NULL) return -1;
		espSetReturnString(ep, value);
		return 0;
	} else {
		/* its a global parameter */
		parm = lp_parm_struct(argv[0]);
		if (parm == NULL) return -1;
		parm_ptr = parm->ptr;
	}

	if (parm == NULL || parm_ptr == NULL) {
		return -1;
	}

	/* construct and return the right type of ejs object */
	switch (parm->type) {
	case P_STRING:
	case P_USTRING:
		espSetReturnString(ep, *(char **)parm_ptr);
		break;
	case P_BOOL:
		espSetReturn(ep, mprCreateBoolVar(*(BOOL *)parm_ptr));
		break;
	case P_INTEGER:
		espSetReturn(ep, mprCreateIntegerVar(*(int *)parm_ptr));
		break;
	case P_ENUM:
		for (i=0; parm->enum_list[i].name; i++) {
			if (*(int *)parm_ptr == parm->enum_list[i].value) {
				espSetReturnString(ep, parm->enum_list[i].name);
				return 0;
			}
		}
		return -1;	
	case P_LIST: 
		esp_returnlist(ep, parm->label, *(const char ***)parm_ptr);
		break;
	case P_SEP:
		return -1;
	}
	return 0;
}


/*
  perform an ldb search, returning an array of results

  syntax:
     ldbSearch("dbfile", "expression");
     var attrs = new Array("attr1", "attr2", "attr3");
     ldbSearch("dbfile", "expression", attrs);
*/
static int esp_ldbSearch(struct EspRequest *ep, int argc, struct MprVar **argv)
{
	const char **attrs = NULL;
	const char *expression, *dbfile;
	TALLOC_CTX *tmp_ctx = talloc_new(ep);
	struct ldb_context *ldb;
	int ret;
	struct ldb_message **res;

	/* validate arguments */
	if (argc < 2 || argc > 3 ||
	    argv[0]->type != MPR_TYPE_STRING) {
		espError(ep, "ldbSearch invalid arguments");
		goto failed;
	}
	if (argc == 3 && argv[2]->type != MPR_TYPE_OBJECT) {
		espError(ep, "ldbSearch attributes must be an object");
		goto failed;
	}

	dbfile     = mprToString(argv[0]);
	expression = mprToString(argv[1]);
	if (argc > 2) {
		attrs = mprToList(tmp_ctx, argv[2]);
	}
	if (dbfile == NULL || expression == NULL) {
		espError(ep, "ldbSearch invalid arguments");
		goto failed;
	}

	ldb = ldb_wrap_connect(tmp_ctx, dbfile, 0, NULL);
	if (ldb == NULL) {
		espError(ep, "ldbSearch failed to open %s", dbfile);
		goto failed;
	}

	ret = ldb_search(ldb, NULL, LDB_SCOPE_DEFAULT, expression, attrs, &res);
	if (ret == -1) {
		espError(ep, "ldbSearch failed - %s", ldb_errstring(ldb));
		goto failed;
	}

	espSetReturn(ep, mprLdbArray(res, ret, "ldb_message"));

	talloc_free(tmp_ctx);
	return 0;

failed:
	talloc_free(tmp_ctx);
	return -1;
}


/*
  setup the C functions that be called from ejs
*/
void http_setup_ejs_functions(void)
{
	espDefineStringCFunction(NULL, "lpGet", esp_lpGet, NULL);
	espDefineStringCFunction(NULL, "lpServices", esp_lpServices, NULL);
	espDefineCFunction(NULL, "typeof", esp_typeof, NULL);
	espDefineCFunction(NULL, "ldbSearch", esp_ldbSearch, NULL);
}
