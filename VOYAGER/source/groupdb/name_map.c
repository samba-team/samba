/* 
 *  Unix SMB/CIFS implementation.
 *  NT to Unix name table.
 *  Copyright (C) Volker Lendecke	       2004
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/* The idea is the following: The table is keyed on the lower-case
 * unix-charset of the nt-name to be able to search case-insensitively. The
 * values contain the correct-case ntname, the unix name and a BOOL is_user.
 *
 * nt_to_unix_name simply looks into the table.
 *
 * unix_to_nt_name never fails and auto-generates the appropriate entry. The
 * unified namespace problem is solved the following way: If we have to create
 * an entry, look whether an entry for the opposite side already exists. If
 * so, then append ".user" or ".group". If that happens to also exist try
 * random stuff.
 */

#include "includes.h"

#define NAME_PREFIX "NAMEMAP/"

static TDB_CONTEXT *tdb; /* used for driver files */

static BOOL init_name_mapping(void)
{
	static pid_t local_pid;
	
	if (tdb && local_pid == sys_getpid())
		return True;
	tdb = tdb_open_log(lock_path("name_map.tdb"), 0, TDB_DEFAULT,
			   O_RDWR|O_CREAT, 0644);
	if (!tdb) {
		DEBUG(0,("Failed to open group mapping database\n"));
		return False;
	}

	local_pid = sys_getpid();
	return True;
}

BOOL nt_to_unix_name(TALLOC_CTX *mem_ctx, const char *nt_name,
		     char **unix_name, BOOL *is_user)
{
	TDB_DATA kbuf, dbuf;
	char *lcname;
	char *key;
	int ret;
	fstring tmp_ntname;
	fstring tmp_unixname;

	if (!init_name_mapping()) {
		DEBUG(0,("failed to initialize group mapping\n"));
		return(False);
	}

	lcname = strdup(nt_name);
	strlower_m(lcname);

	asprintf(&key, "%s%s", NAME_PREFIX, lcname);

	SAFE_FREE(lcname);

	kbuf.dptr = key;
	kbuf.dsize = strlen(key)+1;

	dbuf = tdb_fetch(tdb, kbuf);

	SAFE_FREE(key);

	if (!dbuf.dptr)
		return False;

	ret = tdb_unpack(dbuf.dptr, dbuf.dsize, "ffd", tmp_ntname,
			 tmp_unixname, is_user);

	SAFE_FREE(dbuf.dptr);

	if (ret > 0) {
		*unix_name = maybe_talloc_strdup(mem_ctx, tmp_unixname);
		return True;
	}

	return False;
}

struct find_unixname_closure {
	TALLOC_CTX *mem_ctx;
	BOOL want_user;
	const char *unixname;
	char **ntname;
	BOOL found;
};

static BOOL find_name_entry(TDB_CONTEXT *ctx, TDB_DATA key, TDB_DATA dbuf,
			    void *data)
{
	struct find_unixname_closure *closure =
		(struct find_unixname_closure *)data;

	fstring ntname;
	fstring unixname;
	BOOL is_user;
	int ret;

	if (strncmp(key.dptr, NAME_PREFIX, strlen(NAME_PREFIX)) != 0)
		return False;

	ret = tdb_unpack(dbuf.dptr, dbuf.dsize, "ffd", ntname, unixname,
			 &is_user);

	if (ret == -1)
		return False;

	if ((closure->want_user != is_user) ||
	    (strcmp(closure->unixname, unixname) != 0))
		return False;

	*(closure->ntname) = maybe_talloc_strdup(closure->mem_ctx, ntname);

	closure->found = True;
	return True;
}

static BOOL set_name_mapping(const char *unixname, const char *ntname,
			     BOOL is_user, int tdb_flag)
{
	TDB_DATA kbuf, dbuf;
	char *lcname;
	char *key;
	pstring buf;
	int len;
	BOOL res;

	len = tdb_pack(buf, sizeof(buf), "ffd", ntname, unixname, is_user);

	if (len > sizeof(buf))
		return False;

	dbuf.dptr = buf;
	dbuf.dsize = len;

	lcname = strdup(ntname);
	strlower_m(lcname);

	asprintf(&key, "%s%s", NAME_PREFIX, lcname);

	kbuf.dptr = key;
	kbuf.dsize = strlen(key)+1;

	res = (tdb_store(tdb, kbuf, dbuf, tdb_flag) == 0);

	SAFE_FREE(lcname);
	SAFE_FREE(key);
	return res;
}

BOOL create_name_mapping(const char *unixname, const char *ntname,
			 BOOL is_user)
{
	return set_name_mapping(unixname, ntname, is_user, TDB_INSERT);
}

static void generate_name_mapping(TALLOC_CTX *mem_ctx,
				  const char *unixname, char **ntname,
				  BOOL is_user)
{
	fstring generated_name;
	int attempts;

	if (set_name_mapping(unixname, unixname, is_user, TDB_INSERT)) {
		*ntname = maybe_talloc_strdup(mem_ctx, unixname);
		return;
	}

	slprintf(generated_name, sizeof(generated_name), "%s.%s",
		 unixname, is_user ? "user" : "group");

	if (set_name_mapping(unixname, generated_name, is_user, TDB_INSERT)) {
		*ntname = maybe_talloc_strdup(mem_ctx, generated_name);
		return;
	}

	/* Ok... Now try random stuff appended */

	for (attempts = 0; attempts < 5; attempts++) {
		slprintf(generated_name, sizeof(generated_name), "%s.%s",
			 unixname, generate_random_str(4));
		if (set_name_mapping(unixname, generated_name, is_user,
				     TDB_INSERT)) {
			*ntname = maybe_talloc_strdup(mem_ctx, generated_name);
			return;
		}
	}

	/* Weird... Completely random now */

	for (attempts = 0; attempts < 5; attempts++) {
		slprintf(generated_name, sizeof(generated_name), "%s",
			 generate_random_str(8));
		if (set_name_mapping(unixname, generated_name, is_user,
				     TDB_INSERT)) {
			*ntname = strdup(generated_name);
			return;
		}
	}

	smb_panic("Could not generate a NT name\n");
}

static void unix_name_to_nt_name(TALLOC_CTX *mem_ctx,
				 const char *unixname, char **ntname,
				 BOOL want_user)
{
	struct find_unixname_closure closure;
	closure.mem_ctx = mem_ctx;
	closure.want_user = want_user;
	closure.unixname = unixname;
	closure.ntname = ntname;
	closure.found = False;

	if (!init_name_mapping()) {
		DEBUG(0,("failed to initialize group mapping\n"));
		return;
	}

	tdb_traverse(tdb, find_name_entry, &closure);

	if (closure.found) {
		return;
	}

	generate_name_mapping(mem_ctx, unixname, ntname, want_user);
}

void unix_username_to_ntname(TALLOC_CTX *mem_ctx,
			     const char *unixname, char **ntname)
{
	unix_name_to_nt_name(mem_ctx, unixname, ntname, True);
}

void unix_groupname_to_ntname(TALLOC_CTX *mem_ctx,
			      const char *unixname, char **ntname)
{
	unix_name_to_nt_name(mem_ctx, unixname, ntname, False);
}
