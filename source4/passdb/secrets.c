/* 
   Unix SMB/CIFS implementation.
   Copyright (C) Andrew Tridgell 1992-2001
   Copyright (C) Andrew Bartlett      2002
   Copyright (C) Rafal Szczesniak     2002
   
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

/* the Samba secrets database stores any generated, private information
   such as the local SID and machine trust password */

#include "includes.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_PASSDB

static TDB_CONTEXT *tdb;

/* open up the secrets database */
BOOL secrets_init(void)
{
	pstring fname;

	if (tdb)
		return True;

	pstrcpy(fname, lp_private_dir());
	pstrcat(fname,"/secrets.tdb");

	tdb = tdb_open_log(fname, 0, TDB_DEFAULT, O_RDWR|O_CREAT, 0600);

	if (!tdb) {
		DEBUG(0,("Failed to open %s\n", fname));
		return False;
	}
	return True;
}

/* read a entry from the secrets database - the caller must free the result
   if size is non-null then the size of the entry is put in there
 */
static void *secrets_fetch(const char *key, size_t *size)
{
	TDB_DATA kbuf, dbuf;
	secrets_init();
	if (!tdb)
		return NULL;
	kbuf.dptr = strdup(key);
	kbuf.dsize = strlen(key);
	dbuf = tdb_fetch(tdb, kbuf);
	if (size)
		*size = dbuf.dsize;
	free(kbuf.dptr);
	return dbuf.dptr;
}

/************************************************************************
 Routine to fetch the plaintext machine account password for a realm
the password is assumed to be a null terminated ascii string
************************************************************************/
char *secrets_fetch_machine_password(const char *domain)
{
	char *key;
	char *ret;
	asprintf(&key, "%s/%s", SECRETS_MACHINE_PASSWORD, domain);
	strupper(key);
	ret = (char *)secrets_fetch(key, NULL);
	free(key);
	return ret;
}



/*******************************************************************************
 Lock the secrets tdb based on a string - this is used as a primitive form of mutex
 between smbd instances.
*******************************************************************************/

BOOL secrets_named_mutex(const char *name, uint_t timeout, size_t *p_ref_count)
{
	size_t ref_count = *p_ref_count;
	int ret = 0;

	if (!message_init())
		return False;

	if (ref_count == 0) {
		ret = tdb_lock_bystring(tdb, name, timeout);
		if (ret == 0)
			DEBUG(10,("secrets_named_mutex: got mutex for %s\n", name ));
	}

	if (ret == 0) {
		*p_ref_count = ++ref_count;
		DEBUG(10,("secrets_named_mutex: ref_count for mutex %s = %u\n", name, (uint_t)ref_count ));
	}
	return (ret == 0);
}

/*******************************************************************************
 Unlock a named mutex.
*******************************************************************************/

void secrets_named_mutex_release(const char *name, size_t *p_ref_count)
{
	size_t ref_count = *p_ref_count;

	SMB_ASSERT(ref_count != 0);

	if (ref_count == 1) {
		tdb_unlock_bystring(tdb, name);
		DEBUG(10,("secrets_named_mutex: released mutex for %s\n", name ));
	}

	*p_ref_count = --ref_count;
	DEBUG(10,("secrets_named_mutex_release: ref_count for mutex %s = %u\n", name, (uint_t)ref_count ));
}

