/* 
   Unix SMB/Netbios implementation.
   Version 3.0.
   Samba registry functions
   Copyright (C) Andrew Tridgell 1992-1998
   
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

static TDB_CONTEXT *tdb;

/* open up the secrets database */
BOOL secrets_init(void)
{
	pstring fname;

	if (tdb)
		return True;

	get_private_directory(fname);

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
void *secrets_fetch(const char *key, size_t *size)
{
	TDB_DATA kbuf, dbuf;

	if (!tdb)
		return False;
	kbuf.dptr = key;
	kbuf.dsize = strlen(key);
	dbuf = tdb_fetch(tdb, kbuf);
	if (size)
		*size = dbuf.dsize;
	return dbuf.dptr;
}

/* store a secrets entry 
 */
BOOL secrets_store(const char *key, const void *data, size_t size)
{
	TDB_DATA kbuf, dbuf;
	if (!tdb)
		return False;
	kbuf.dptr = key;
	kbuf.dsize = strlen(key);
	dbuf.dptr = data;
	dbuf.dsize = size;
	return tdb_store(tdb, kbuf, dbuf, TDB_REPLACE) == 0;
}


/* delete a secets database entry
 */
BOOL secrets_delete(const char *key)
{
	TDB_DATA kbuf;
	if (!tdb)
		return False;
	kbuf.dptr = key;
	kbuf.dsize = strlen(key);
	return tdb_delete(tdb, kbuf) == 0;
}

BOOL secrets_store_domain_sid(const char *domain, DOM_SID *sid)
{
	fstring key;

	slprintf(key, sizeof(key)-1, "%s/%s", SECRETS_DOMAIN_SID, domain);
	strupper(key);
	return secrets_store(key, sid, sizeof(DOM_SID));
}

BOOL secrets_fetch_domain_sid(const char *domain, DOM_SID *sid)
{
	DOM_SID *dyn_sid;
	fstring key;
	size_t size;

	slprintf(key, sizeof(key)-1, "%s/%s", SECRETS_DOMAIN_SID, domain);
	strupper(key);

	dos_to_unix(key);                /* Convert key to unix-codepage */

	dyn_sid = (DOM_SID *)secrets_fetch(key, &size);

	if (dyn_sid == NULL)
		return False;

	if (size != sizeof(DOM_SID))
	{ 
		SAFE_FREE(dyn_sid);
		return False;
	}

	*sid = *dyn_sid;
	SAFE_FREE(dyn_sid);
	return True;
}

/************************************************************************
form a key for fetching a domain trust password
************************************************************************/

const char *trust_keystr(const char *domain)
{
	static fstring keystr;
	fstring dos_domain;

	fstrcpy(dos_domain, domain);
	unix_to_dos(dos_domain);

	slprintf(keystr,sizeof(keystr)-1,"%s/%s", 
		 SECRETS_MACHINE_ACCT_PASS, dos_domain);

	strupper(keystr);
	return keystr;
}

/************************************************************************
 Lock the trust password entry.
************************************************************************/

BOOL secrets_lock_trust_account_password(const char *domain, BOOL dolock)
{
	if (!tdb)
		return False;

	if (dolock)
		return (tdb_lock_bystring(tdb, trust_keystr(domain),0) == 0);
	else
		tdb_unlock_bystring(tdb, trust_keystr(domain));
	return True;
}

/************************************************************************
 Routine to get the trust account password for a domain.
 The user of this function must have locked the trust password file using
 the above call.
************************************************************************/

BOOL secrets_fetch_trust_account_password(const char *domain, uint8 ret_pwd[16],
					  time_t *pass_last_set_time)
{
	struct machine_acct_pass *pass;
	size_t size;

	if (!(pass = secrets_fetch(trust_keystr(domain), &size)) || 
	    size != sizeof(*pass))
		return False;

	if (pass_last_set_time) *pass_last_set_time = pass->mod_time;
	memcpy(ret_pwd, pass->hash, 16);
	SAFE_FREE(pass);
	return True;
}

/************************************************************************
 Routine to set the trust account password for a domain.
************************************************************************/

BOOL secrets_store_trust_account_password(const char *domain, uint8 new_pwd[16])
{
	struct machine_acct_pass pass;

	pass.mod_time = time(NULL);
	memcpy(pass.hash, new_pwd, 16);

	return secrets_store(trust_keystr(domain), (void *)&pass, sizeof(pass));
}

/************************************************************************
 Routine to delete the trust account password file for a domain.
************************************************************************/

BOOL trust_password_delete(const char *domain)
{
	return secrets_delete(trust_keystr(domain));
}

/*******************************************************************
 Reset the 'done' variables so after a client process is created
 from a fork call these calls will be re-done. This should be
 expanded if more variables need reseting.
 ******************************************************************/

void reset_globals_after_fork(void)
{
	unsigned char dummy;

	/*
	 * Increment the global seed value to ensure every smbd starts
	 * with a new random seed.
	 */

	if (tdb) {
		int32 initial_val = sys_getpid();
		tdb_change_int32_atomic(tdb, "INFO/random_seed", (int *)&initial_val, 1);
		set_rand_reseed_data((unsigned char *)&initial_val, sizeof(initial_val));
	}

	/*
	 * Re-seed the random crypto generator, so all smbd's
	 * started from the same parent won't generate the same
	 * sequence.
	 */
	generate_random_buffer( &dummy, 1, True);
}

BOOL secrets_store_ldap_pw(const char* dn, const char* pw)
{
	fstring key;
	char *p;
	
	pstrcpy(key, dn);
	for (p=key; *p; p++)
		if (*p == ',') *p = '/';
	
	return secrets_store(key, pw, strlen(pw));
}

BOOL fetch_ldap_pw(const char *dn, char* pw, int len)
{
	fstring key;
	char *p;
	void *data = NULL;
	size_t size;
	
	pstrcpy(key, dn);
	for (p=key; *p; p++)
		if (*p == ',') *p = '/';
	
	data=secrets_fetch(key, &size);
	if (!size) {
		DEBUG(0,("fetch_ldap_pw: no ldap secret retrieved!\n"));
		return False;
	}
	
	if (size > len-1)
	{
		DEBUG(0,("fetch_ldap_pw: ldap secret is too long (%d > %d)!\n", size, len-1));
		return False;
	}

	memcpy(pw, data, size);
	pw[size] = '\0';
	
	return True;
}

/*
  lock the secrets tdb based on a string - this is used as a primitive form of mutex
  between smbd instances. 
*/
BOOL secrets_named_mutex(const char *name, unsigned int timeout)
{
	int ret;

	if (!message_init())
		return False;

	ret = tdb_lock_bystring(tdb, name, timeout);
	if (ret == 0)
		DEBUG(10,("secrets_named_mutex: got mutex for %s\n", name ));

	return (ret == 0);
}

/*
  unlock a named mutex
*/
void secrets_named_mutex_release(const char *name)
{
	tdb_unlock_bystring(tdb, name);
	DEBUG(10,("secrets_named_mutex: released mutex for %s\n", name ));
}
