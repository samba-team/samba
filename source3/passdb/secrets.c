/* 
   Unix SMB/CIFS implementation.
   Copyright (C) Andrew Tridgell 1992-2001
   Copyright (C) Andrew Bartlett      2002
   
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
void *secrets_fetch(char *key, size_t *size)
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
BOOL secrets_store(char *key, void *data, size_t size)
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
BOOL secrets_delete(char *key)
{
	TDB_DATA kbuf;
	secrets_init();
	if (!tdb)
		return False;
	kbuf.dptr = key;
	kbuf.dsize = strlen(key);
	return tdb_delete(tdb, kbuf) == 0;
}

BOOL secrets_store_domain_sid(char *domain, DOM_SID *sid)
{
	fstring key;

	slprintf(key, sizeof(key)-1, "%s/%s", SECRETS_DOMAIN_SID, domain);
	strupper(key);
	return secrets_store(key, sid, sizeof(DOM_SID));
}

BOOL secrets_fetch_domain_sid(char *domain, DOM_SID *sid)
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


/**
 * Form a key for fetching the machine trust account password
 *
 * @param domain domain name
 *
 * @return stored password's key
 **/
char *trust_keystr(char *domain)
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
char *trustdom_keystr(char *domain)
{
	static char* keystr;

	asprintf(&keystr, "%s/%s", SECRETS_DOMTRUST_ACCT_PASS, domain);
	strupper(keystr);
		
	return keystr;
}

/************************************************************************
 Routine to get the machine trust account password for a domain.
************************************************************************/
BOOL secrets_fetch_trust_account_password(char *domain, uint8 ret_pwd[16],
					  time_t *pass_last_set_time)
{
	struct machine_acct_pass *pass;
	char *plaintext;
	size_t size;

	plaintext = secrets_fetch_machine_password();
	if (plaintext) {
		/* we have an ADS password - use that */
		DEBUG(4,("Using ADS machine password\n"));
		E_md4hash((uchar *)plaintext, ret_pwd);
		SAFE_FREE(plaintext);
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
BOOL secrets_fetch_trusted_domain_password(char *domain, char** pwd,
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
BOOL secrets_store_trust_account_password(char *domain, uint8 new_pwd[16])
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

BOOL secrets_store_trusted_domain_password(char* domain, smb_ucs2_t *uni_dom_name,
					   size_t uni_name_len, char* pwd,
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
BOOL secrets_store_machine_password(char *pass)
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

BOOL trust_password_delete(char *domain)
{
	return secrets_delete(trust_keystr(domain));
}

/************************************************************************
 Routine to delete the password for trusted domain
************************************************************************/
BOOL trusted_domain_password_delete(char *domain)
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

BOOL secrets_store_ldap_pw(char* dn, char* pw)
{
	fstring key;
	char *p;
	
	pstrcpy(key, dn);
	for (p=key; *p; p++)
		if (*p == ',') *p = '/';
	
	return secrets_store(key, pw, strlen(pw));
}


/**
 * The linked list is allocated on the supplied talloc context, caller gets to destory
 * when done.
 *
 * @param start_idx starting index, eg. we can start fetching
 *	  at third or sixth trusted domain entry
 * @param num_domains number of domain entries to fetch at one call
 *
 * @return list of trusted domains structs (unicode name, sid and password)
 **/ 

NTSTATUS secrets_get_trusted_domains(TALLOC_CTX* ctx, int start_idx, int max_num_domains, int *num_domains, TRUSTDOM ***domains)
{
	TDB_LIST_NODE *keys, *k;
	TRUSTDOM *dom = NULL;
	char *pattern;
	uint32 idx = 0;
	size_t size;
	struct trusted_dom_pass *pass;

	secrets_init();

	*num_domains = 0;

	/* generate searching pattern */
	if (!(pattern = talloc_asprintf(ctx, "%s/*", SECRETS_DOMTRUST_ACCT_PASS))) {
		DEBUG(0, ("secrets_get_trusted_domains: talloc_asprintf() failed!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	DEBUG(5, ("secrets_get_trusted_domains: looking for %d domains, starting at index %d\n", 
		  max_num_domains, start_idx));

	*domains = talloc_zero(ctx, sizeof(**domains)*max_num_domains);

	/* fetching trusted domains' data and collecting them in a list */
	keys = tdb_search_keys(tdb, pattern);

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
			
			(*domains)[*num_domains] = dom;

			(*num_domains)++;
			
		}
		
		idx++;
		
		/* free returned tdb record */
		SAFE_FREE(pass);
	}
	
	DEBUG(5, ("secrets_get_trusted_domains: got %d of %d domains\n", 
		  *num_domains, max_num_domains));

	/* free the results of searching the keys */
	tdb_search_list_free(keys);

	return NT_STATUS_OK;
}

