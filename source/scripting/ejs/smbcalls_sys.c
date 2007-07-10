/* 
   Unix SMB/CIFS implementation.

   provide access to system functions

   Copyright (C) Andrew Tridgell 2005
   
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
#include "lib/ldb/include/ldb.h"
#include "system/time.h"
#include "system/network.h"
#include "lib/socket/netif.h"

/*
  return the list of configured network interfaces
*/
static int ejs_sys_interfaces(MprVarHandle eid, int argc, struct MprVar **argv)
{
	int i, count = iface_count();
	struct MprVar ret = mprArray("interfaces");
	for (i=0;i<count;i++) {
		mprAddArray(&ret, i, mprString(iface_n_ip(i)));
	}
	mpr_Return(eid, ret);
	return 0;	
}

/*
  return the hostname from gethostname()
*/
static int ejs_sys_hostname(MprVarHandle eid, int argc, struct MprVar **argv)
{
	char name[200];
	if (gethostname(name, sizeof(name)-1) == -1) {
		ejsSetErrorMsg(eid, "gethostname failed - %s", strerror(errno));
		return -1;
	}
	mpr_Return(eid, mprString(name));
	return 0;	
}


/*
  return current time as seconds and microseconds
*/
static int ejs_sys_gettimeofday(MprVarHandle eid, int argc, struct MprVar **argv)
{
	struct timeval tv = timeval_current();
        struct MprVar v = mprObject("timeval");
	struct MprVar sec = mprCreateIntegerVar(tv.tv_sec);
	struct MprVar usec = mprCreateIntegerVar(tv.tv_usec);

        mprCreateProperty(&v, "sec", &sec);
        mprCreateProperty(&v, "usec", &usec);
	mpr_Return(eid, v);
	return 0;
}

/*
  return current time as a 64 bit nttime value
*/
static int ejs_sys_nttime(MprVarHandle eid, int argc, struct MprVar **argv)
{
	struct timeval tv = timeval_current();
	struct MprVar v = mprCreateNumberVar(timeval_to_nttime(&tv));
	mpr_Return(eid, v);
	return 0;
}

/*
  return time as a 64 bit nttime value from a 32 bit time_t value
*/
static int ejs_sys_unix2nttime(MprVarHandle eid, int argc, struct MprVar **argv)
{
	NTTIME nt;
	struct MprVar v;
	if (argc != 1 || !mprVarIsNumber(argv[0]->type)) {
		ejsSetErrorMsg(eid, "sys_unix2nttime invalid arguments");
		return -1;
	}
	unix_to_nt_time(&nt, mprVarToNumber(argv[0]));
	v = mprCreateNumberVar(nt);
	mpr_Return(eid, v);
	return 0;
}

/*
  return the GMT time represented by the struct tm argument, as a time_t value
*/
static int ejs_sys_gmmktime(MprVarHandle eid, int argc, struct MprVar **argv)
{
	struct MprVar *o;
	struct tm tm;
	if (argc != 1 || !mprVarIsObject(argv[0]->type)) {
		ejsSetErrorMsg(eid, "sys_gmmktime invalid arguments");
		return -1;
	}

        o = argv[0];
#define TM_EL(n) tm.n = mprVarToNumber(mprGetProperty(o, #n, NULL))
	TM_EL(tm_sec);
	TM_EL(tm_min);
	TM_EL(tm_hour);
	TM_EL(tm_mday);
	TM_EL(tm_mon);
	TM_EL(tm_year);
	TM_EL(tm_wday);
	TM_EL(tm_yday);
	TM_EL(tm_isdst);
#undef TM_EL        

	mpr_Return(eid, mprCreateIntegerVar(mktime(&tm)));
	return 0;
}

/*
  return the given time as a gmtime structure
*/
static int ejs_sys_gmtime(MprVarHandle eid, int argc, struct MprVar **argv)
{
	time_t t;
	struct MprVar ret;
	struct tm *tm;
	if (argc != 1 || !mprVarIsNumber(argv[0]->type)) {
		ejsSetErrorMsg(eid, "sys_gmtime invalid arguments");
		return -1;
	}
	t = (time_t) mprVarToNumber(argv[0]);
	tm = gmtime(&t);
	if (tm == NULL) {
		mpr_Return(eid, mprCreateUndefinedVar());
		return 0;
	}
	ret = mprObject("gmtime");
#define TM_EL(n) mprSetVar(&ret, #n, mprCreateIntegerVar(tm->n))
	TM_EL(tm_sec);
	TM_EL(tm_min);
	TM_EL(tm_hour);
	TM_EL(tm_mday);
	TM_EL(tm_mon);
	TM_EL(tm_year);
	TM_EL(tm_wday);
	TM_EL(tm_yday);
	TM_EL(tm_isdst);
#undef TM_EL

	mpr_Return(eid, ret);
	return 0;
}

/*
  return the given NT time as a time_t value
*/
static int ejs_sys_nttime2unix(MprVarHandle eid, int argc, struct MprVar **argv)
{
	time_t t;
	struct MprVar v;
	if (argc != 1 || !mprVarIsNumber(argv[0]->type)) {
		ejsSetErrorMsg(eid, "sys_ntgmtime invalid arguments");
		return -1;
	}
	t = nt_time_to_unix(mprVarToNumber(argv[0]));
	v = mprCreateNumberVar(t);
	mpr_Return(eid, v);
        return 0;
}

/*
  return the given NT time as a gmtime structure
*/
static int ejs_sys_ntgmtime(MprVarHandle eid, int argc, struct MprVar **argv)
{
	time_t t;
	struct MprVar ret;
	struct tm *tm;
	if (argc != 1 || !mprVarIsNumber(argv[0]->type)) {
		ejsSetErrorMsg(eid, "sys_ntgmtime invalid arguments");
		return -1;
	}
	t = nt_time_to_unix(mprVarToNumber(argv[0]));
	tm = gmtime(&t);
	if (tm == NULL) {
		mpr_Return(eid, mprCreateUndefinedVar());
		return 0;
	}
	ret = mprObject("gmtime");
#define TM_EL(n) mprSetVar(&ret, #n, mprCreateIntegerVar(tm->n))
	TM_EL(tm_sec);
	TM_EL(tm_min);
	TM_EL(tm_hour);
	TM_EL(tm_mday);
	TM_EL(tm_mon);
	TM_EL(tm_year);
	TM_EL(tm_wday);
	TM_EL(tm_yday);
	TM_EL(tm_isdst);
#undef TM_EL

	mpr_Return(eid, ret);
	return 0;
}

/*
  return a ldap time string from a nttime
*/
static int ejs_sys_ldaptime(MprVarHandle eid, int argc, struct MprVar **argv)
{
	char *s;
	time_t t;
	if (argc != 1 || !mprVarIsNumber(argv[0]->type)) {
		ejsSetErrorMsg(eid, "sys_ldaptime invalid arguments");
		return -1;
	}
	t = nt_time_to_unix(mprVarToNumber(argv[0]));
	s = ldb_timestring(mprMemCtx(), t);
	mpr_Return(eid, mprString(s));
	talloc_free(s);
	return 0;
}

/*
  return a http time string from a nttime
*/
static int ejs_sys_httptime(MprVarHandle eid, int argc, struct MprVar **argv)
{
	char *s;
	time_t t;
	if (argc != 1 || !mprVarIsNumber(argv[0]->type)) {
		ejsSetErrorMsg(eid, "sys_httptime invalid arguments");
		return -1;
	}
	t = nt_time_to_unix(mprVarToNumber(argv[0]));
	s = http_timestring(mprMemCtx(), t);
	mpr_Return(eid, mprString(s));
	talloc_free(s);
	return 0;
}

/*
  unlink a file
   ok = sys.unlink(fname);
*/
static int ejs_sys_unlink(MprVarHandle eid, int argc, char **argv)
{
	int ret;
	if (argc != 1) {
		ejsSetErrorMsg(eid, "sys_unlink invalid arguments");
		return -1;
	}
	ret = unlink(argv[0]);
	mpr_Return(eid, mprCreateBoolVar(ret == 0));
	return 0;
}

/*
  load a file as a string
  usage:
     string = sys.file_load(filename);
*/
static int ejs_sys_file_load(MprVarHandle eid, int argc, char **argv)
{
	char *s;
	if (argc != 1) {
		ejsSetErrorMsg(eid, "sys_file_load invalid arguments");
		return -1;
	}

	s = file_load(argv[0], NULL, mprMemCtx());
	mpr_Return(eid, mprString(s));
	talloc_free(s);
	return 0;
}

/*
  save a file from a string
  usage:
     ok = sys.file_save(filename, str);
*/
static int ejs_sys_file_save(MprVarHandle eid, int argc, char **argv)
{
	BOOL ret;
	if (argc != 2) {
		ejsSetErrorMsg(eid, "sys_file_save invalid arguments");
		return -1;
	}
	ret = file_save(argv[0], argv[1], strlen(argv[1]));
	mpr_Return(eid, mprCreateBoolVar(ret));
	return 0;
}

/*
  mkdir()
  usage:
     ok = sys.mkdir(dirname, mode);
*/
static int ejs_sys_mkdir(MprVarHandle eid, int argc, struct MprVar **argv)
{
	BOOL ret;
	char *name;
	if (argc != 2) {
		ejsSetErrorMsg(eid, "sys_mkdir invalid arguments, need mkdir(dirname, mode)");
		return -1;
	}
	if (!mprVarIsString(argv[0]->type)) {
		ejsSetErrorMsg(eid, "sys_mkdir dirname not a string");
		return -1;
	}
	if (!mprVarIsNumber(argv[1]->type)) {
		ejsSetErrorMsg(eid, "sys_mkdir mode not a number");
		return -1;
	}
	mprVarToString(&name, 0, NULL, argv[0]);
	ret = mkdir(name, mprVarToNumber(argv[1]));
	mpr_Return(eid, mprCreateBoolVar(ret == 0));
	return 0;
}


/*
  return fields of a stat() call
*/
static struct MprVar mpr_stat(struct stat *st)
{
	struct MprVar ret;
	ret = mprObject("stat");

#define ST_EL(n) mprSetVar(&ret, #n, mprCreateNumberVar(st->n))
	ST_EL(st_dev);
	ST_EL(st_ino);
	ST_EL(st_mode);
	ST_EL(st_nlink);
	ST_EL(st_uid);
	ST_EL(st_gid);
	ST_EL(st_rdev);
	ST_EL(st_size);
	ST_EL(st_blksize);
	ST_EL(st_blocks);
	ST_EL(st_atime);
	ST_EL(st_mtime);
	ST_EL(st_ctime);

	return ret;
}

/*
  usage:
      var st = sys.stat(filename);
  returns an object containing struct stat elements
*/
static int ejs_sys_stat(MprVarHandle eid, int argc, char **argv)
{
	struct stat st;
	/* validate arguments */
	if (argc != 1) {
		ejsSetErrorMsg(eid, "sys.stat invalid arguments");
		return -1;
	}
	if (stat(argv[0], &st) != 0) {
		mpr_Return(eid, mprCreateUndefinedVar());
	} else {
		mpr_Return(eid, mpr_stat(&st));
	}
	return 0;
}

/*
  usage:
      var st = sys.lstat(filename);
  returns an object containing struct stat elements
*/
static int ejs_sys_lstat(MprVarHandle eid, int argc, char **argv)
{
	struct stat st;
	/* validate arguments */
	if (argc != 1) {
		ejsSetErrorMsg(eid, "sys.stat invalid arguments");
		return -1;
	}
	if (lstat(argv[0], &st) != 0) {
		mpr_Return(eid, mprCreateUndefinedVar());
	} else {
		mpr_Return(eid, mpr_stat(&st));
	}
	return 0;
}

/*
  bitwise AND
  usage:
      var z = sys.bitAND(x, 0x70);
*/
static int ejs_sys_bitAND(MprVarHandle eid, int argc, struct MprVar **argv)
{
	int x, y, z;

	if (argc != 2 || 
	    !mprVarIsNumber(argv[0]->type) ||
	    !mprVarIsNumber(argv[1]->type)) {
		ejsSetErrorMsg(eid, "bitand invalid arguments");
		return -1;
	}
	x = mprToInt(argv[0]);
	y = mprToInt(argv[1]);
	z = x & y;

	mpr_Return(eid, mprCreateIntegerVar(z));
	return 0;
}

/*
  bitwise OR
  usage:
      var z = sys.bitOR(x, 0x70);
*/
static int ejs_sys_bitOR(MprVarHandle eid, int argc, struct MprVar **argv)
{
	int x, y, z;

	if (argc != 2 || 
	    !mprVarIsNumber(argv[0]->type) ||
	    !mprVarIsNumber(argv[1]->type)) {
		ejsSetErrorMsg(eid, "bitand invalid arguments");
		return -1;
	}
	x = mprToInt(argv[0]);
	y = mprToInt(argv[1]);
	z = x | y;

	mpr_Return(eid, mprCreateIntegerVar(z));
	return 0;
}

/*
  initialise sys ejs subsystem
*/
static int ejs_sys_init(MprVarHandle eid, int argc, struct MprVar **argv)
{
	struct MprVar *obj = mprInitObject(eid, "sys", argc, argv);

	mprSetCFunction(obj, "interfaces", ejs_sys_interfaces);
	mprSetCFunction(obj, "hostname", ejs_sys_hostname);
	mprSetCFunction(obj, "nttime", ejs_sys_nttime);
	mprSetCFunction(obj, "gettimeofday", ejs_sys_gettimeofday);
	mprSetCFunction(obj, "unix2nttime", ejs_sys_unix2nttime);
	mprSetCFunction(obj, "gmmktime", ejs_sys_gmmktime);
	mprSetCFunction(obj, "gmtime", ejs_sys_gmtime);
	mprSetCFunction(obj, "nttime2unix", ejs_sys_nttime2unix);
	mprSetCFunction(obj, "ntgmtime", ejs_sys_ntgmtime);
	mprSetCFunction(obj, "ldaptime", ejs_sys_ldaptime);
	mprSetCFunction(obj, "httptime", ejs_sys_httptime);
	mprSetCFunction(obj, "mkdir", ejs_sys_mkdir);
	mprSetStringCFunction(obj, "unlink", ejs_sys_unlink);
	mprSetStringCFunction(obj, "file_load", ejs_sys_file_load);
	mprSetStringCFunction(obj, "file_save", ejs_sys_file_save);
	mprSetStringCFunction(obj, "stat", ejs_sys_stat);
	mprSetStringCFunction(obj, "lstat", ejs_sys_lstat);
	mprSetCFunction(obj, "bitAND", ejs_sys_bitAND);
	mprSetCFunction(obj, "bitOR", ejs_sys_bitOR);

	return 0;
}


/*
  setup C functions that be called from ejs
*/
NTSTATUS smb_setup_ejs_system(void)
{
	ejsDefineCFunction(-1, "sys_init", ejs_sys_init, NULL, MPR_VAR_SCRIPT_HANDLE);
	return NT_STATUS_OK;
}
