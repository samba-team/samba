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
	TDB_DATA kbuf;
	TDB_DATA dbuf;
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
BOOL secrets_store(char *key, void *data, size_t size)
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

	dyn_sid = (DOM_SID *)secrets_fetch(key, &size);

	if (dyn_sid == NULL)
		return False;

	if (size != sizeof(DOM_SID)) {
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

char *trust_keystr(const char *domain)
{
	static fstring keystr;

	slprintf(keystr,sizeof(keystr)-1,"%s/%s", 
		 SECRETS_MACHINE_ACCT_PASS, domain);

	strupper_unix(keystr);
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

	if (pass_last_set_time)
		*pass_last_set_time = pass->mod_time;
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

BOOL secrets_trust_password_delete(const char *domain)
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

BOOL secrets_store_ldap_pw(char* dn, char* pw)
{
	fstring key;
	char *p;
	
	pstrcpy(key, dn);
	for (p=key; *p; p++)
		if (*p == ',') *p = '/';
	
	return secrets_store(key, pw, strlen(pw));
}

BOOL fetch_ldap_pw(char *dn, char* pw, int len)
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

static SIG_ATOMIC_T gotalarm;

static void gotalarm_sig(void)
{
	gotalarm = 1;
}

static unsigned long mutex_hash_offset(const char *v)
{
	const char *p;
	unsigned long h=0;
	for(p = v; *p != '\0'; p += 1) {
		h = ( h << 5 ) - h + *p;
	}
	return (h % 0x1FFFFFFFL) + 0x1FFFFFFFL;
}

/*****************************************************************************************
 Grab a mutex based on name with a timeout. ref_count allows this to be recursive.
*****************************************************************************************/
 
BOOL secrets_named_mutex(const char *name, unsigned int timeout, size_t *p_ref_count)
{
	size_t ref_count = *p_ref_count;
	int ret = 0;

	if (ref_count == 0) {
		struct flock fl;
		unsigned long offset = mutex_hash_offset(name);

		gotalarm = 0;
		fl.l_type = F_WRLCK;
		fl.l_whence = SEEK_SET;
		fl.l_start = offset;
		fl.l_len = 1;
		fl.l_pid = 0;

		if (timeout) {
			CatchSignal(SIGALRM, SIGNAL_CAST gotalarm_sig);
			alarm(timeout);
		}

		do {
			ret = fcntl(tdb->fd,F_SETLKW,&fl);
			if (ret == -1 && errno == EINTR && timeout)
				break;
		} while (ret == -1 && errno == EINTR);

		if (timeout) {
			alarm(0);
			CatchSignal(SIGALRM, SIGNAL_CAST SIG_IGN);
			if (gotalarm) {
				DEBUG(0,("secrets_named_mutex: Timeout after %u seconds \
getting mutex at offset %lu for server %s\n", timeout, offset, name ));
				return False;
			}
		}

		if (ret == 0) {
			DEBUG(10,("secrets_named_mutex: got mutex for %s\n", name ));
		} else
			DEBUG(0,("secrets_named_mutex: Error in acquiring mutex for %s (%s)\n",
				name, strerror(errno) ));
	}

	if (ret == 0) {
		*p_ref_count = ++ref_count;
		DEBUG(10,("secrets_named_mutex: ref_count for mutex %s = %u\n", name, (unsigned int)ref_count ));
	}
	return (ret == 0);
}

/*
  unlock a named mutex
*/
void secrets_named_mutex_release(const char *name, size_t *p_ref_count)
{
	struct flock fl;
	size_t ref_count = *p_ref_count;

	SMB_ASSERT(ref_count != 0);

	if (ref_count == 1) {
		fl.l_type = F_UNLCK;
		fl.l_whence = SEEK_SET;
		fl.l_start = mutex_hash_offset(name);
		fl.l_len = 1;
		fl.l_pid = 0;

		if (fcntl(tdb->fd,F_SETLKW,&fl) == -1) {
			DEBUG(0,("secrets_named_mutex_release: Error in releasing mutex for %s (%s)\n",
				name, strerror(errno) ));
		}
		DEBUG(10,("secrets_named_mutex_release: released mutex for %s\n", name ));
	}

	*p_ref_count = --ref_count;
	DEBUG(10,("secrets_named_mutex_release: ref_count for mutex %s = %u\n", name, (unsigned int)ref_count ));
}

/*********************************************************
 Check to see if we must talk to the PDC to avoid sam 
 sync delays
 ********************************************************/
 
BOOL must_use_pdc( const char *domain )
{
	time_t	now = time(NULL);
	time_t  last_change_time;
	unsigned char	passwd[16];   
	
	if ( !secrets_fetch_trust_account_password(domain, passwd, &last_change_time) )
		return False;
		
	/*
	 * If the time the machine password has changed
	 * was less than about 15 minutes then we need to contact
	 * the PDC only, as we cannot be sure domain replication
	 * has yet taken place. Bug found by Gerald (way to go
	 * Gerald !). JRA.
	 */
	 
	if ( now - last_change_time < SAM_SYNC_WINDOW )
		return True;
		
	return False;

}

