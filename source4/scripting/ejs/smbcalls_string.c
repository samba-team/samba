/* 
   Unix SMB/CIFS implementation.

   provide access to string functions

   Copyright (C) Andrew Tridgell 2005
   Copyright (C) Jelmer Vernooij 2005 (substr)
   
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

/*
  usage:
      var len = strlen(str);
*/
static int ejs_strlen(MprVarHandle eid, int argc, char **argv)
{
	if (argc != 1) {
		ejsSetErrorMsg(eid, "strlen invalid arguments");
		return -1;
	}
	mpr_Return(eid, mprCreateIntegerVar(strlen_m(argv[0])));
	return 0;
}

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
      var s = strstr(string, substring);
*/
static int ejs_strstr(MprVarHandle eid, int argc, char **argv)
{
	char *s;
	if (argc != 2) {
		ejsSetErrorMsg(eid, "strstr invalid arguments");
		return -1;
	}
	s = strstr(argv[0], argv[1]);
	mpr_Return(eid, mprString(s));
	return 0;
}

/*
  usage:
      var s = strspn(string, legal_chars_string);
*/
static int ejs_strspn(MprVarHandle eid, int argc, char **argv)
{
        int len;
	if (argc != 2) {
		ejsSetErrorMsg(eid, "strspn invalid arguments");
		return -1;
	}
	len = strspn(argv[0], argv[1]);
	mpr_Return(eid, mprCreateIntegerVar(len));
	return 0;
}

/*
  usage:
     list = split(".", "a.foo.bar");
     list = split(".", "a.foo.bar", count);

  count is an optional count of how many splits to make

  NOTE: does not take a regular expression, unlike perl split()
*/
static int ejs_split(MprVarHandle eid, int argc, struct MprVar **argv)
{
	const char *separator, *s;
	char *p;
	struct MprVar ret;
	int count = 0, maxcount=0;
	TALLOC_CTX *tmp_ctx = talloc_new(mprMemCtx());
	if (argc < 2 ||
	    argv[0]->type != MPR_TYPE_STRING ||
	    argv[1]->type != MPR_TYPE_STRING) {
		ejsSetErrorMsg(eid, "split invalid arguments");
		return -1;
	}
	separator = mprToString(argv[0]);
	s         = mprToString(argv[1]);
	if (argc == 3) {
		maxcount = mprToInt(argv[2]);
	}

	ret = mprArray("list");

	while ((p = strstr(s, separator))) {
		char *s2 = talloc_strndup(tmp_ctx, s, (int)(p-s));
		mprAddArray(&ret, count++, mprString(s2));
		talloc_free(s2);
		s = p + strlen(separator);
		if (maxcount != 0 && count >= maxcount) {
			break;
		}
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
    str = substr(orig[, start_offset[, length]]);

	special cases:
		if start_offset < 0 then start_offset+=strlen(orig)
		if length < 0 then length+=strlen(orig)-start_offset

	(as found in many other languages)
*/
static int ejs_substr(MprVarHandle eid, int argc, struct MprVar **argv)
{
	int start_offset = 0;
	int length = 0;
	const char *orig;
	char *target;
	
	if (argc < 1 || argc > 3 ||
	    argv[0]->type != MPR_TYPE_STRING) {
		ejsSetErrorMsg(eid, "substr invalid arguments");
		return -1;
	}

	if (argc == 1) {
		mpr_Return(eid, *argv[0]);
		return 0;
	}

	orig = mprToString(argv[0]);
	start_offset = mprToInt(argv[1]);
	length = strlen(orig);
	if (start_offset < 0) start_offset += strlen(orig);
	if (start_offset < 0 || start_offset > strlen(orig)) {
		ejsSetErrorMsg(eid, "substr arg 2 out of bounds ([%s], %d)", orig, start_offset);
		return -1;
	}

	if (argc == 3) {
		length = mprToInt(argv[2]);
		if (length < 0) length += strlen(orig) - start_offset;
		if (length < 0 || length+start_offset > strlen(orig)) {
			ejsSetErrorMsg(eid, "substr arg 3 out of bounds ([%s], %d, %d)", orig, start_offset, length);
			return -1;
		}
	}

	target = talloc_strndup(mprMemCtx(), orig+start_offset, length);
	
	mpr_Return(eid, mprString(target));

	talloc_free(target);

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
  blergh, C certainly makes this hard!
  usage:
     str = sprintf("i=%d s=%7s", 7, "foo");
*/
typedef char *(*_asprintf_append_t)(char *, const char *, ...);
static int ejs_sprintf(MprVarHandle eid, int argc, struct MprVar **argv)
{
	const char *format;
	const char *p;
	char *ret;
	int a = 1;
	_asprintf_append_t _asprintf_append;
	TALLOC_CTX *tmp_ctx;
	if (argc < 1 || argv[0]->type != MPR_TYPE_STRING) {
		ejsSetErrorMsg(eid, "sprintf invalid arguments");
		return -1;
	}
	format = mprToString(argv[0]);
	tmp_ctx = talloc_new(mprMemCtx());
	ret = talloc_strdup(tmp_ctx, "");

	/* avoid all the format string warnings */
	_asprintf_append = (_asprintf_append_t)talloc_asprintf_append;

	/*
	  hackity hack ...
	*/
	while ((p = strchr(format, '%'))) {
		char *fmt2;
		int len, len_count=0;
		char *tstr;
		ret = talloc_asprintf_append(ret, "%*.*s", 
					     (int)(p-format), (int)(p-format), 
					     format);
		if (ret == NULL) goto failed;
		format += (int)(p-format);
		len = strcspn(p+1, "dxuiofgGpXeEFcs%") + 1;
		fmt2 = talloc_strndup(tmp_ctx, p, len+1);
		if (fmt2 == NULL) goto failed;
		len_count = count_chars(fmt2, '*');
		/* find the type string */
		tstr = &fmt2[len];
		while (tstr > fmt2 && isalpha((unsigned char)tstr[-1])) {
			tstr--;
		}
		if (strcmp(tstr, "%") == 0) {
			ret = talloc_asprintf_append(ret, "%%");
			if (ret == NULL) {
				goto failed;
			}
			format += len+1;
			continue;
		}
		if (len_count > 2 || 
		    argc < a + len_count + 1) {
			ejsSetErrorMsg(eid, "sprintf: not enough arguments for format");
			goto failed;
		}
#define FMT_ARG(fn, type) do { \
			switch (len_count) { \
			case 0: \
				ret = _asprintf_append(ret, fmt2, \
							     (type)fn(argv[a])); \
				break; \
			case 1: \
				ret = _asprintf_append(ret, fmt2, \
							     (int)mprVarToNumber(argv[a]), \
							     (type)fn(argv[a+1])); \
				break; \
			case 2: \
				ret = _asprintf_append(ret, fmt2, \
							     (int)mprVarToNumber(argv[a]), \
							     (int)mprVarToNumber(argv[a+1]), \
							     (type)fn(argv[a+2])); \
				break; \
			} \
			a += len_count + 1; \
			if (ret == NULL) { \
				goto failed; \
			} \
} while (0)

		if (strcmp(tstr, "s")==0)        FMT_ARG(mprToString,    const char *);
		else if (strcmp(tstr, "c")==0)   FMT_ARG(*mprToString,   char);
		else if (strcmp(tstr, "d")==0)   FMT_ARG(mprVarToNumber, int);
		else if (strcmp(tstr, "ld")==0)  FMT_ARG(mprVarToNumber, long);
		else if (strcmp(tstr, "lld")==0) FMT_ARG(mprVarToNumber, long long);
		else if (strcmp(tstr, "x")==0)   FMT_ARG(mprVarToNumber, int);
		else if (strcmp(tstr, "lx")==0)  FMT_ARG(mprVarToNumber, long);
		else if (strcmp(tstr, "llx")==0) FMT_ARG(mprVarToNumber, long long);
		else if (strcmp(tstr, "X")==0)   FMT_ARG(mprVarToNumber, int);
		else if (strcmp(tstr, "lX")==0)  FMT_ARG(mprVarToNumber, long);
		else if (strcmp(tstr, "llX")==0) FMT_ARG(mprVarToNumber, long long);
		else if (strcmp(tstr, "u")==0)   FMT_ARG(mprVarToNumber, int);
		else if (strcmp(tstr, "lu")==0)  FMT_ARG(mprVarToNumber, long);
		else if (strcmp(tstr, "llu")==0) FMT_ARG(mprVarToNumber, long long);
		else if (strcmp(tstr, "i")==0)   FMT_ARG(mprVarToNumber, int);
		else if (strcmp(tstr, "li")==0)  FMT_ARG(mprVarToNumber, long);
		else if (strcmp(tstr, "lli")==0) FMT_ARG(mprVarToNumber, long long);
		else if (strcmp(tstr, "o")==0)   FMT_ARG(mprVarToNumber, int);
		else if (strcmp(tstr, "lo")==0)  FMT_ARG(mprVarToNumber, long);
		else if (strcmp(tstr, "llo")==0) FMT_ARG(mprVarToNumber, long long);
		else if (strcmp(tstr, "f")==0)   FMT_ARG(mprVarToFloat,  double);
		else if (strcmp(tstr, "lf")==0)  FMT_ARG(mprVarToFloat,  double);
		else if (strcmp(tstr, "g")==0)   FMT_ARG(mprVarToFloat,  double);
		else if (strcmp(tstr, "lg")==0)  FMT_ARG(mprVarToFloat,  double);
		else if (strcmp(tstr, "e")==0)   FMT_ARG(mprVarToFloat,  double);
		else if (strcmp(tstr, "le")==0)  FMT_ARG(mprVarToFloat,  double);
		else if (strcmp(tstr, "E")==0)   FMT_ARG(mprVarToFloat,  double);
		else if (strcmp(tstr, "lE")==0)  FMT_ARG(mprVarToFloat,  double);
		else if (strcmp(tstr, "F")==0)   FMT_ARG(mprVarToFloat,  double);
		else if (strcmp(tstr, "lF")==0)  FMT_ARG(mprVarToFloat,  double);
		else {
			ejsSetErrorMsg(eid, "sprintf: unknown format string '%s'", fmt2);
			goto failed;
		}
		format += len+1;
	}

	ret = talloc_asprintf_append(ret, "%s", format);
	mpr_Return(eid, mprString(ret));
	talloc_free(tmp_ctx);
	return 0;	   
	
failed:
	talloc_free(tmp_ctx);
	return -1;
}

/*
  used to build your own print function
     str = vsprintf(args);
*/
static int ejs_vsprintf(MprVarHandle eid, int argc, struct MprVar **argv)
{
	struct MprVar **args, *len, *v;
	int i, ret, length;
	if (argc != 1 || argv[0]->type != MPR_TYPE_OBJECT) {
		ejsSetErrorMsg(eid, "vsprintf invalid arguments");
		return -1;
	}
	v = argv[0];
	len = mprGetProperty(v, "length", NULL);
	if (len == NULL) {
		ejsSetErrorMsg(eid, "vsprintf takes an array");
		return -1;
	}
	length = mprToInt(len);
	args = talloc_array(mprMemCtx(), struct MprVar *, length);
	if (args == NULL) {
		return -1;
	}

	for (i=0;i<length;i++) {
		char idx[16];
		mprItoa(i, idx, sizeof(idx));
		args[i] = mprGetProperty(v, idx, NULL);
	}
	
	ret = ejs_sprintf(eid, length, args);
	talloc_free(args);
	return ret;
}


/*
  encode a string, replacing all non-alpha with %02x form
*/
static int ejs_encodeURIComponent(MprVarHandle eid, int argc, char **argv)
{
	int i, j, count=0;
	const char *s;
	char *ret;
	if (argc != 1) {
		ejsSetErrorMsg(eid, "encodeURIComponent invalid arguments");
		return -1;
	}
	
	s = argv[0];

	for (i=0;s[i];i++) {
		if (!isalnum(s[i])) count++;
	}
	
	ret = talloc_size(mprMemCtx(), i + count*2 + 1);
	if (ret == NULL) {
		return -1;
	}
	for (i=j=0;s[i];i++,j++) {
		if (!isalnum(s[i])) {
			snprintf(ret+j, 4, "%%%02X", (unsigned)s[i]);
			j += 2;
		} else {
			ret[j] = s[i];
		}
	}
	ret[j] = 0;
	mpr_Return(eid, mprString(ret));
	talloc_free(ret);
	return 0;
}

/*
  encode a string, replacing all non-alpha of %02x form
*/
static int ejs_decodeURIComponent(MprVarHandle eid, int argc, char **argv)
{
	int i, j, count=0;
	const char *s;
	char *ret;
	if (argc != 1) {
		ejsSetErrorMsg(eid, "decodeURIComponent invalid arguments");
		return -1;
	}
	
	s = argv[0];

	ret = talloc_size(mprMemCtx(), strlen(s) + 1);
	if (ret == NULL) {
		return -1;
	}

	for (i=j=0;s[i];i++,j++) {
		if (s[i] == '%') {
			unsigned c;
			if (sscanf(s+i+1, "%02X", &c) != 1) {
				ejsSetErrorMsg(eid, "decodeURIComponent bad format");
				return -1;
			}
			ret[j] = c;
			i += 2;
		} else {
			ret[j] = s[i];
		}
		if (!isalnum(s[i])) count++;
	}
	
	ret[j] = 0;
	mpr_Return(eid, mprString(ret));
	talloc_free(ret);
	return 0;
}

/*
  initialise string ejs subsystem
*/
static int ejs_string_init(MprVarHandle eid, int argc, struct MprVar **argv)
{
	struct MprVar *obj = mprInitObject(eid, "string", argc, argv);

	mprSetCFunction(obj, "substr", ejs_substr);
	mprSetStringCFunction(obj, "strlen", ejs_strlen);
	mprSetStringCFunction(obj, "strlower", ejs_strlower);
	mprSetStringCFunction(obj, "strupper", ejs_strupper);
	mprSetStringCFunction(obj, "strstr", ejs_strstr);
	mprSetStringCFunction(obj, "strspn", ejs_strspn);
	mprSetCFunction(obj, "split", ejs_split);
	mprSetCFunction(obj, "join", ejs_join);
	mprSetCFunction(obj, "sprintf", ejs_sprintf);
	mprSetCFunction(obj, "vsprintf", ejs_vsprintf);
	mprSetStringCFunction(obj, "encodeURIComponent", ejs_encodeURIComponent);
	mprSetStringCFunction(obj, "decodeURIComponent", ejs_decodeURIComponent);

	return 0;
}

/*
  setup C functions that be called from ejs
*/
NTSTATUS smb_setup_ejs_string(void)
{
	ejsDefineCFunction(-1, "string_init", ejs_string_init, NULL, MPR_VAR_SCRIPT_HANDLE);
	return NT_STATUS_OK;
}
