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
	secrets_init();
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
	secrets_init();
	if (!tdb)
		return False;
	kbuf.dptr = key;
	kbuf.dsize = strlen(key);
	return tdb_delete(tdb, kbuf) == 0;
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

BOOL secrets_store_domain_guid(const char *domain, GUID *guid)
{
	fstring key;

	slprintf(key, sizeof(key)-1, "%s/%s", SECRETS_DOMAIN_GUID, domain);
	strupper(key);
	return secrets_store(key, guid, sizeof(GUID));
}

BOOL secrets_fetch_domain_guid(const char *domain, GUID *guid)
{
	GUID *dyn_guid;
	fstring key;
	size_t size;
	GUID new_guid;

	slprintf(key, sizeof(key)-1, "%s/%s", SECRETS_DOMAIN_GUID, domain);
	strupper(key);
	dyn_guid = (GUID *)secrets_fetch(key, &size);

	DEBUG(6,("key is %s, size is %d\n", key, (int)size));

	if ((NULL == dyn_guid) && (ROLE_DOMAIN_PDC == lp_server_role())) {
		uuid_generate_random(&new_guid);
		if (!secrets_store_domain_guid(domain, &new_guid))
			return False;
		dyn_guid = (GUID *)secrets_fetch(key, &size);
		if (dyn_guid == NULL)
			return False;
	}

	if (size != sizeof(GUID))
	{ 
		SAFE_FREE(dyn_guid);
		return False;
	}

	*guid = *dyn_guid;
	SAFE_FREE(dyn_guid);
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


/*******************************************************************
 Reset the 'done' variables so after a client process is created
 from a fork call these calls will be re-done. This should be
 expanded if more variables need reseting.
 ******************************************************************/

void reset_globals_after_fork(void)
{
	unsigned char dummy;

	secrets_init();

	/*
	 * Increment the global seed value to ensure every smbd starts
	 * with a new random seed.
	 */

	if (tdb) {
		uint32 initial_val = sys_getpid();
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


/**
 * Get trusted domains info from secrets.tdb.
 *
 * The linked list is allocated on the supplied talloc context, caller gets to destroy
 * when done.
 *
 * @param ctx Allocation context
 * @param enum_ctx Starting index, eg. we can start fetching at third
 *        or sixth trusted domain entry. Zero is the first index.
 *        Value it is set to is the enum context for the next enumeration.
 * @param num_domains Number of domain entries to fetch at one call
 * @param domains Pointer to array of trusted domain structs to be filled up
 *
 * @return nt status code of rpc response
 **/ 

NTSTATUS secrets_get_trusted_domains(TALLOC_CTX* ctx, int* enum_ctx, unsigned int max_num_domains, int *num_domains, TRUSTDOM ***domains)
{
	TDB_LIST_NODE *keys, *k;
	TRUSTDOM *dom = NULL;
	char *pattern;
	unsigned int start_idx;
	uint32 idx = 0;
	size_t size;
	fstring dom_name;
	struct trusted_dom_pass *pass;
	NTSTATUS status;

	if (!secrets_init()) return NT_STATUS_ACCESS_DENIED;

	*num_domains = 0;
	start_idx = *enum_ctx;

	/* generate searching pattern */
	if (!(pattern = talloc_asprintf(ctx, "%s/*", SECRETS_DOMTRUST_ACCT_PASS))) {
		DEBUG(0, ("secrets_get_trusted_domains: talloc_asprintf() failed!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	DEBUG(5, ("secrets_get_trusted_domains: looking for %d domains, starting at index %d\n", 
		  max_num_domains, *enum_ctx));

	*domains = talloc_zero(ctx, sizeof(**domains)*max_num_domains);

	/* fetching trusted domains' data and collecting them in a list */
	keys = tdb_search_keys(tdb, pattern);

	/* 
	 * if there's no keys returned ie. no trusted domain,
	 * return "no more entries" code
	 */
	status = NT_STATUS_NO_MORE_ENTRIES;

	/* searching for keys in sectrets db -- way to go ... */
	for (k = keys; k; k = k->next) {
		char *secrets_key;
		
		/* important: ensure null-termination of the key string */
		secrets_key = strndup(k->node_key.dptr, k->node_key.dsize);
		if (!secrets_key) {
			DEBUG(0, ("strndup failed!\n"));
			return NT_STATUS_NO_MEMORY;
		}
				
		pass = secrets_fetch(secrets_key, &size);
		
		if (size != sizeof(*pass)) {
			DEBUG(2, ("Secrets record %s is invalid!\n", secrets_key));
			SAFE_FREE(pass);
			continue;
		}
		
		pull_ucs2_fstring(dom_name, pass->uni_name);
		DEBUG(18, ("Fetched secret record num %d.\nDomain name: %s, SID: %s\n",
			   idx, dom_name, sid_string_static(&pass->domain_sid)));

		SAFE_FREE(secrets_key);

		if (idx >= start_idx && idx < start_idx + max_num_domains) {
			dom = talloc_zero(ctx, sizeof(*dom));
			if (!dom) {
				/* free returned tdb record */
				SAFE_FREE(pass);
				
				return NT_STATUS_NO_MEMORY;
			}
			
			/* copy domain sid */
			SMB_ASSERT(sizeof(dom->sid) == sizeof(pass->domain_sid));
			memcpy(&(dom->sid), &(pass->domain_sid), sizeof(dom->sid));
			
			/* copy unicode domain name */
			dom->name = talloc_strdup_w(ctx, pass->uni_name);
			
			(*domains)[idx - start_idx] = dom;
			
			DEBUG(18, ("Secret record is in required range.\n \
				   start_idx = %d, max_num_domains = %d. Added to returned array.\n",
				   start_idx, max_num_domains));

			*enum_ctx = idx + 1;
			(*num_domains)++;
		
			/* set proper status code to return */
			if (k->next) {
				/* there are yet some entries to enumerate */
				status = STATUS_MORE_ENTRIES;
			} else {
				/* this is the last entry in the whole enumeration */
				status = NT_STATUS_OK;
			}
		} else {
			DEBUG(18, ("Secret is outside the required range.\n \
				   start_idx = %d, max_num_domains = %d. Not added to returned array\n",
				   start_idx, max_num_domains));
		}
		
		idx++;
		
		/* free returned tdb record */
		SAFE_FREE(pass);
	}
	
	DEBUG(5, ("secrets_get_trusted_domains: got %d domains\n", *num_domains));

	/* free the results of searching the keys */
	tdb_search_list_free(keys);

	return status;
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

