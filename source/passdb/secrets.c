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
void *secrets_fetch(const char *key, size_t *size)
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

/* store a secrets entry 
 */
BOOL secrets_store(const char *key, const void *data, size_t size)
{
	TDB_DATA kbuf, dbuf;
	int ret;

	secrets_init();
	if (!tdb)
		return False;
	kbuf.dptr = strdup(key);
	kbuf.dsize = strlen(key);
	dbuf.dptr = memdup(data, size);
	dbuf.dsize = size;

	ret = tdb_store(tdb, kbuf, dbuf, TDB_REPLACE);

	free(kbuf.dptr);
	free(dbuf.dptr);

	return ret == 0;
}


/* delete a secets database entry
 */
BOOL secrets_delete(const char *key)
{
	TDB_DATA kbuf;
	int ret;

	secrets_init();
	if (!tdb)
		return False;
	kbuf.dptr = strdup(key);
	kbuf.dsize = strlen(key);
	ret = tdb_delete(tdb, kbuf);
	free(kbuf.dptr);
	return ret == 0;
}

BOOL secrets_store_domain_sid(const char *domain, const DOM_SID *sid)
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

	if (size != sizeof(DOM_SID))
	{ 
		SAFE_FREE(dyn_sid);
		return False;
	}

	*sid = *dyn_sid;
	SAFE_FREE(dyn_sid);
	return True;
}

BOOL secrets_store_domain_guid(const char *domain, struct GUID *guid)
{
	const char *s;
	fstring key;
	TALLOC_CTX *mem_ctx;
	BOOL ret;
	
	mem_ctx = talloc_init("secrets_store_domain_guid");
	if (!mem_ctx) {
		return False;
	}

	s = GUID_string(mem_ctx, guid);
	if (!s) {
		talloc_destroy(mem_ctx);
		return False;
	}


	slprintf(key, sizeof(key)-1, "%s/%s", SECRETS_DOMAIN_GUID, domain);
	strupper(key);
	ret = secrets_store(key, s, strlen(s)+1);
	
	talloc_destroy(mem_ctx);
	return ret;
}

BOOL secrets_fetch_domain_guid(const char *domain, struct GUID *guid)
{
	char *dyn_guid;
	fstring key;
	size_t size;
	struct GUID new_guid;
	NTSTATUS status;

	slprintf(key, sizeof(key)-1, "%s/%s", SECRETS_DOMAIN_GUID, domain);
	strupper(key);
	dyn_guid = secrets_fetch(key, &size);

	DEBUG(6,("key is %s, size is %d\n", key, (int)size));

	if ((NULL == dyn_guid) && (ROLE_DOMAIN_PDC == lp_server_role())) {
		uuid_generate_random(&new_guid);
		if (!secrets_store_domain_guid(domain, &new_guid))
			return False;
		dyn_guid = secrets_fetch(key, &size);
		if (dyn_guid == NULL)
			return False;
	}

	status = GUID_from_string(dyn_guid, guid);
	SAFE_FREE(dyn_guid);

	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	return True;
}

/**
 * Form a key for fetching the machine trust account password
 *
 * @param domain domain name
 *
 * @return stored password's key
 **/
const char *trust_keystr(const char *domain)
{
	static fstring keystr;

	slprintf(keystr,sizeof(keystr)-1,"%s/%s", 
		 SECRETS_MACHINE_ACCT_PASS, domain);
	strupper(keystr);

	return keystr;
}

/**
 * Form a key for fetching a trusted domain password
 *
 * @param domain trusted domain name
 *
 * @return stored password's key
 **/
char *trustdom_keystr(const char *domain)
{
	static char* keystr;

	asprintf(&keystr, "%s/%s", SECRETS_DOMTRUST_ACCT_PASS, domain);
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
	char *plaintext;
	size_t size;

	plaintext = secrets_fetch_machine_password();
	if (plaintext) {
		/* we have an ADS password - use that */
		DEBUG(4,("Using ADS machine password\n"));
		E_md4hash(plaintext, ret_pwd);
		SAFE_FREE(plaintext);
		pass_last_set_time = 0;
		return True;
	}

	if (!(pass = secrets_fetch(trust_keystr(domain), &size))) {
		DEBUG(5, ("secrets_fetch failed!\n"));
		return False;
	}
	
	if (size != sizeof(*pass)) {
		DEBUG(0, ("secrets were of incorrect size!\n"));
		return False;
	}

	if (pass_last_set_time) *pass_last_set_time = pass->mod_time;
	memcpy(ret_pwd, pass->hash, 16);
	SAFE_FREE(pass);
	return True;
}

/************************************************************************
 Routine to get account password to trusted domain
************************************************************************/

BOOL secrets_fetch_trusted_domain_password(const char *domain, char** pwd,
					   DOM_SID *sid, time_t *pass_last_set_time)
{
	struct trusted_dom_pass *pass;
	size_t size;

	/* fetching trusted domain password structure */
	if (!(pass = secrets_fetch(trustdom_keystr(domain), &size))) {
		DEBUG(5, ("secrets_fetch failed!\n"));
		return False;
	}

	if (size != sizeof(*pass)) {
		DEBUG(0, ("secrets were of incorrect size!\n"));
		return False;
	}

	/* the trust's password */	
	if (pwd) {
		*pwd = strdup(pass->pass);
		if (!*pwd) {
			return False;
		}
	}

	/* last change time */
	if (pass_last_set_time) *pass_last_set_time = pass->mod_time;

	/* domain sid */
	memcpy(&sid, &(pass->domain_sid), sizeof(sid));
	
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

/**
 * Routine to set the password for trusted domain
 *
 * @param domain remote domain name
 * @param pwd plain text password of trust relationship
 * @param sid remote domain sid
 *
 * @return true if succeeded
 **/

BOOL secrets_store_trusted_domain_password(const char* domain, smb_ucs2_t *uni_dom_name,
					   size_t uni_name_len, const char* pwd,
					   DOM_SID sid)
{
	struct trusted_dom_pass pass;
	ZERO_STRUCT(pass);

	/* unicode domain name and its length */
	if (!uni_dom_name)
		return False;
		
	strncpy_w(pass.uni_name, uni_dom_name, sizeof(pass.uni_name) - 1);
	pass.uni_name_len = uni_name_len;

	/* last change time */
	pass.mod_time = time(NULL);

	/* password of the trust */
	pass.pass_len = strlen(pwd);
	fstrcpy(pass.pass, pwd);

	/* domain sid */
	memcpy(&(pass.domain_sid), &sid, sizeof(sid));

	return secrets_store(trustdom_keystr(domain), (void *)&pass, sizeof(pass));
}

/************************************************************************
 Routine to set the plaintext machine account password for a realm
the password is assumed to be a null terminated ascii string
************************************************************************/

BOOL secrets_store_machine_password(const char *pass)
{
	char *key;
	BOOL ret;
	asprintf(&key, "%s/%s", SECRETS_MACHINE_PASSWORD, lp_workgroup());
	strupper(key);
	ret = secrets_store(key, pass, strlen(pass)+1);
	free(key);
	return ret;
}


/************************************************************************
 Routine to fetch the plaintext machine account password for a realm
the password is assumed to be a null terminated ascii string
************************************************************************/
char *secrets_fetch_machine_password(void)
{
	char *key;
	char *ret;
	asprintf(&key, "%s/%s", SECRETS_MACHINE_PASSWORD, lp_workgroup());
	strupper(key);
	ret = (char *)secrets_fetch(key, NULL);
	free(key);
	return ret;
}



/************************************************************************
 Routine to delete the machine trust account password file for a domain.
************************************************************************/

BOOL trust_password_delete(const char *domain)
{
	return secrets_delete(trust_keystr(domain));
}

/************************************************************************
 Routine to delete the password for trusted domain
************************************************************************/

BOOL trusted_domain_password_delete(const char *domain)
{
	return secrets_delete(trustdom_keystr(domain));
}


BOOL secrets_store_ldap_pw(const char* dn, char* pw)
{
	char *key = NULL;
	BOOL ret;
	
	if (asprintf(&key, "%s/%s", SECRETS_LDAP_BIND_PW, dn) < 0) {
		DEBUG(0, ("secrets_store_ldap_pw: asprintf failed!\n"));
		return False;
	}
		
	ret = secrets_store(key, pw, strlen(pw)+1);
	
	SAFE_FREE(key);
	return ret;
}

/*******************************************************************************
 Lock the secrets tdb based on a string - this is used as a primitive form of mutex
 between smbd instances.
*******************************************************************************/

BOOL secrets_named_mutex(const char *name, unsigned int timeout, size_t *p_ref_count)
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
		DEBUG(10,("secrets_named_mutex: ref_count for mutex %s = %u\n", name, (unsigned int)ref_count ));
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
	DEBUG(10,("secrets_named_mutex_release: ref_count for mutex %s = %u\n", name, (unsigned int)ref_count ));
}

