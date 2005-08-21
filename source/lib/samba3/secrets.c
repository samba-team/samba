/* 
   Unix SMB/CIFS implementation.
   Copyright (C) Andrew Tridgell 1992-2001
   Copyright (C) Andrew Bartlett      2002
   Copyright (C) Rafal Szczesniak     2002
   Copyright (C) Tim Potter           2001
   Copyright (C) Jelmer Vernooij	  2005

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

#define SECRETS_DOMAIN_SID "SECRETS/SID"
#define SECRETS_DOMAIN_GUID "SECRETS/DOMGUID"
#define SECRETS_LDAP_BIND_PW "SECRETS/LDAP_BIND_PW"
#define SECRETS_MACHINE_ACCT_PASS "SECRETS/$MACHINE.ACC"
#define SECRETS_DOMTRUST_ACCT_PASS "SECRETS/$DOMTRUST.ACC"
#define SECRETS_MACHINE_PASSWORD "SECRETS/MACHINE_PASSWORD"
#define SECRETS_MACHINE_LAST_CHANGE_TIME "SECRETS/MACHINE_LAST_CHANGE_TIME"
#define SECRETS_MACHINE_SEC_CHANNEL_TYPE "SECRETS/MACHINE_SEC_CHANNEL_TYPE"
#define SECRETS_AFS_KEYFILE "SECRETS/AFS_KEYFILE"
#define SECRETS_AUTH_USER      "SECRETS/AUTH_USER"
#define SECRETS_AUTH_DOMAIN      "SECRETS/AUTH_DOMAIN"
#define SECRETS_AUTH_PASSWORD  "SECRETS/AUTH_PASSWORD"


#include "includes.h"
#include "tdb.h"
#include "system/filesys.h"
#include "librpc/gen_ndr/ndr_security.h"

/* structure for storing machine account password
   (ie. when samba server is member of a domain */
struct machine_acct_pass {
	uint8_t hash[16];
	time_t mod_time;
};

#define SECRETS_AFS_MAXKEYS 8

struct afs_key {
	uint32_t kvno;
	char key[8];
};

static TDB_CONTEXT *secrets_open(const char *fname)
{
	TDB_CONTEXT *tdb = tdb_open(fname, 0, TDB_DEFAULT, O_RDONLY, 0600);

	if (!tdb) {
		DEBUG(0,("Failed to open %s\n", fname));
		return NULL;
	}

	return tdb;
}

/* read a entry from the secrets database - the caller must free the result
   if size is non-null then the size of the entry is put in there
 */
static void *secrets_fetch(TDB_CONTEXT *tdb, const char *key, size_t *size)
{
	TDB_DATA kbuf, dbuf;
	
	kbuf.dptr = strdup(key);
	kbuf.dsize = strlen(key);
	dbuf = tdb_fetch(tdb, kbuf);
	if (size)
		*size = dbuf.dsize;
	free(kbuf.dptr);
	return dbuf.dptr;
}

static BOOL secrets_fetch_domain_sid(TDB_CONTEXT *tdb, const char *domain, struct dom_sid *sid)
{
	struct dom_sid *dyn_sid;
	char *key;
	size_t size;

	asprintf(&key, "%s/%s", SECRETS_DOMAIN_SID, domain);
	strupper_m(key);
	dyn_sid = (struct dom_sid *)secrets_fetch(tdb, key, &size);
	SAFE_FREE(key);

	if (dyn_sid == NULL)
		return False;

	if (size != sizeof(struct dom_sid))
	{ 
		SAFE_FREE(dyn_sid);
		return False;
	}

	*sid = *dyn_sid;
	SAFE_FREE(dyn_sid);
	return True;
}

static BOOL secrets_fetch_domain_guid(TDB_CONTEXT *tdb, const char *domain, struct GUID *guid)
{
	struct GUID *dyn_guid;
	char *key;
	size_t size;

	asprintf(&key, "%s/%s", SECRETS_DOMAIN_GUID, domain);
	strupper_m(key);
	dyn_guid = (struct GUID *)secrets_fetch(tdb, key, &size);

	if (!dyn_guid) {
		return False;
	}

	if (size != sizeof(struct GUID))
	{ 
		DEBUG(1,("GUID size %d is wrong!\n", (int)size));
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
static char *trust_keystr(const char *domain)
{
	char *keystr;

	asprintf(&keystr, "%s/%s", SECRETS_MACHINE_ACCT_PASS, domain);
	strupper_m(keystr);

	return keystr;
}

/**
 * Form a key for fetching a trusted domain password
 *
 * @param domain trusted domain name
 *
 * @return stored password's key
 **/
static char *trustdom_keystr(const char *domain)
{
	char *keystr;

	asprintf(&keystr, "%s/%s", SECRETS_DOMTRUST_ACCT_PASS, domain);
	strupper_m(keystr);
		
	return keystr;
}

/************************************************************************
 Routine to get the trust account password for a domain.
 The user of this function must have locked the trust password file using
 the above secrets_lock_trust_account_password().
************************************************************************/

static BOOL secrets_fetch_trust_account_password(TDB_CONTEXT *tdb, 
					  const char *domain, uint8_t ret_pwd[16],
					  time_t *pass_last_set_time,
					  uint32_t *channel)
{
	struct machine_acct_pass *pass;
	char *plaintext;
	size_t size;

	plaintext = secrets_fetch_machine_password(tdb, domain, pass_last_set_time, 
						   channel);
	if (plaintext) {
		DEBUG(4,("Using cleartext machine password\n"));
		E_md4hash(plaintext, ret_pwd);
		SAFE_FREE(plaintext);
		return True;
	}

	if (!(pass = secrets_fetch(tdb, trust_keystr(domain), &size))) {
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

	if (channel) 
		*channel = get_default_sec_channel();

	return True;
}

/************************************************************************
 Routine to get account password to trusted domain
************************************************************************/

static BOOL secrets_fetch_trusted_domain_password(TDB_CONTEXT *tdb, const char *domain, char** pwd, struct dom_sid **sid, time_t *pass_last_set_time)
{
	struct trusted_dom_pass pass;
	size_t size;
	
	/* unpacking structures */
	char* pass_buf;
	int pass_len = 0;

	ZERO_STRUCT(pass);

	/* fetching trusted domain password structure */
	if (!(pass_buf = secrets_fetch(tdb, trustdom_keystr(domain), &size))) {
		DEBUG(5, ("secrets_fetch failed!\n"));
		return False;
	}

	/* unpack trusted domain password */
	pass_len = tdb_trusted_dom_pass_unpack(pass_buf, size, &pass);
	SAFE_FREE(pass_buf);

	if (pass_len != size) {
		DEBUG(5, ("Invalid secrets size. Unpacked data doesn't match trusted_dom_pass structure.\n"));
		return False;
	}
			
	/* the trust's password */	
	if (pwd) {
		*pwd = strdup(pass.pass);
		if (!*pwd) {
			return False;
		}
	}

	/* last change time */
	if (pass_last_set_time) *pass_last_set_time = pass.mod_time;

	/* domain sid */
	
	*sid = dom_sid_dup(tdb, &pass.domain_sid);
		
	return True;
}

/************************************************************************
 Routine to fetch the plaintext machine account password for a realm
the password is assumed to be a null terminated ascii string
************************************************************************/
static char *secrets_fetch_machine_password(TDB_CONTEXT *tdb, const char *domain, 
				     time_t *pass_last_set_time,
				     uint32_t *channel)
{
	char *key = NULL;
	char *ret;
	asprintf(&key, "%s/%s", SECRETS_MACHINE_PASSWORD, domain);
	strupper_m(key);
	ret = (char *)secrets_fetch(tdb, key, NULL);
	SAFE_FREE(key);
	
	if (pass_last_set_time) {
		size_t size;
		uint32_t *last_set_time;
		asprintf(&key, "%s/%s", SECRETS_MACHINE_LAST_CHANGE_TIME, domain);
		strupper_m(key);
		last_set_time = secrets_fetch(tdb, key, &size);
		if (last_set_time) {
			*pass_last_set_time = IVAL(last_set_time,0);
			SAFE_FREE(last_set_time);
		} else {
			*pass_last_set_time = 0;
		}
		SAFE_FREE(key);
	}
	
	if (channel) {
		size_t size;
		uint32_t *channel_type;
		asprintf(&key, "%s/%s", SECRETS_MACHINE_SEC_CHANNEL_TYPE, domain);
		strupper_m(key);
		channel_type = secrets_fetch(tdb, key, &size);
		if (channel_type) {
			*channel = IVAL(channel_type,0);
			SAFE_FREE(channel_type);
		} else {
			*channel = get_default_sec_channel();
		}
		SAFE_FREE(key);
	}
	
	return ret;
}

/*******************************************************************
 find the ldap password
******************************************************************/
static BOOL fetch_ldap_pw(TDB_CONTEXT *tdb, const char *dn, char** pw)
{
	char *key = NULL;
	size_t size;
	
	if (asprintf(&key, "%s/%s", SECRETS_LDAP_BIND_PW, dn) < 0) {
		DEBUG(0, ("fetch_ldap_pw: asprintf failed!\n"));
	}
	
	*pw=secrets_fetch(tdb, key, &size);
	SAFE_FREE(key);

	if (!size) {
		return False;
	}
	
	return True;
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

static NTSTATUS secrets_get_trusted_domains(TDB_CONTEXT *tdb, TALLOC_CTX* ctx, int* enum_ctx, unsigned int max_num_domains,
                                     int *num_domains, struct samba3_trustdom ***domains)
{
	TDB_LIST_NODE *keys, *k;
	struct samba3_trustdom *dom = NULL;
	char *pattern;
	unsigned int start_idx;
	uint32_t idx = 0;
	size_t size, packed_size = 0;
	fstring dom_name;
	char *packed_pass;
	struct trusted_dom_pass *pass = talloc(ctx, struct trusted_dom_pass);
	NTSTATUS status;

	if (!secrets_init()) return NT_STATUS_ACCESS_DENIED;
	
	if (!pass) {
		DEBUG(0, ("talloc_zero failed!\n"));
		return NT_STATUS_NO_MEMORY;
	}
				
	*num_domains = 0;
	start_idx = *enum_ctx;

	/* generate searching pattern */
	if (!(pattern = talloc_asprintf(ctx, "%s/*", SECRETS_DOMTRUST_ACCT_PASS))) {
		DEBUG(0, ("secrets_get_trusted_domains: talloc_asprintf() failed!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	DEBUG(5, ("secrets_get_trusted_domains: looking for %d domains, starting at index %d\n", 
		  max_num_domains, *enum_ctx));

	*domains = talloc_zero_array(ctx, struct samba3_trustdom *, max_num_domains);

	/* fetching trusted domains' data and collecting them in a list */
	keys = tdb_search_keys(tdb, pattern);

	/* 
	 * if there's no keys returned ie. no trusted domain,
	 * return "no more entries" code
	 */
	status = NT_STATUS_NO_MORE_ENTRIES;

	/* searching for keys in secrets db -- way to go ... */
	for (k = keys; k; k = k->next) {
		char *secrets_key;
		
		/* important: ensure null-termination of the key string */
		secrets_key = strndup(k->node_key.dptr, k->node_key.dsize);
		if (!secrets_key) {
			DEBUG(0, ("strndup failed!\n"));
			return NT_STATUS_NO_MEMORY;
		}

		packed_pass = secrets_fetch(tdb, secrets_key, &size);
		packed_size = tdb_trusted_dom_pass_unpack(packed_pass, size, pass);
		/* packed representation isn't needed anymore */
		SAFE_FREE(packed_pass);
		
		if (size != packed_size) {
			DEBUG(2, ("Secrets record %s is invalid!\n", secrets_key));
			continue;
		}
		
		pull_ucs2_fstring(dom_name, pass->uni_name);
		DEBUG(18, ("Fetched secret record num %d.\nDomain name: %s, SID: %s\n",
			   idx, dom_name, sid_string_static(&pass->domain_sid)));

		SAFE_FREE(secrets_key);

		if (idx >= start_idx && idx < start_idx + max_num_domains) {
			dom = talloc(ctx, struct samba3_trustdom);
			if (!dom) {
				/* free returned tdb record */
				return NT_STATUS_NO_MEMORY;
			}
			
			/* copy domain sid */
			SMB_ASSERT(sizeof(dom->sid) == sizeof(pass->domain_sid));
			memcpy(&(dom->sid), &(pass->domain_sid), sizeof(dom->sid));
			
			/* copy unicode domain name */
			dom->name = talloc_memdup(ctx, pass->uni_name,
						  (strlen_w(pass->uni_name) + 1) * sizeof(smb_ucs2_t));
			
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
	}
	
	DEBUG(5, ("secrets_get_trusted_domains: got %d domains\n", *num_domains));

	/* free the results of searching the keys */
	tdb_search_list_free(keys);

	return status;
}

/*******************************************************************************
 Fetch the current (highest) AFS key from secrets.tdb
*******************************************************************************/
static BOOL secrets_fetch_afs_key(TDB_CONTEXT *tdb, const char *cell, struct afs_key *result)
{
	fstring key;
	struct afs_keyfile *keyfile;
	size_t size;
	uint32_t i;

	slprintf(key, sizeof(key)-1, "%s/%s", SECRETS_AFS_KEYFILE, cell);

	keyfile = (struct afs_keyfile *)secrets_fetch(tdb, key, &size);

	if (keyfile == NULL)
		return False;

	if (size != sizeof(struct afs_keyfile)) {
		SAFE_FREE(keyfile);
		return False;
	}

	i = ntohl(keyfile->nkeys);

	if (i > SECRETS_AFS_MAXKEYS) {
		SAFE_FREE(keyfile);
		return False;
	}

	*result = keyfile->entry[i-1];

	result->kvno = ntohl(result->kvno);

	return True;
}

/******************************************************************************
  When kerberos is not available, choose between anonymous or
  authenticated connections.  

  We need to use an authenticated connection if DCs have the
  RestrictAnonymous registry entry set > 0, or the "Additional
  restrictions for anonymous connections" set in the win2k Local
  Security Policy.

  Caller to free() result in domain, username, password
*******************************************************************************/
static void secrets_fetch_ipc_userpass(TDB_CONTEXT *tdb, char **username, char **domain, char **password)
{
	*username = secrets_fetch(tdb, SECRETS_AUTH_USER, NULL);
	*domain = secrets_fetch(tdb, SECRETS_AUTH_DOMAIN, NULL);
	*password = secrets_fetch(tdb, SECRETS_AUTH_PASSWORD, NULL);
	
	if (*username && **username) {

		if (!*domain || !**domain)
			*domain = smb_xstrdup(lp_workgroup());
		
		if (!*password || !**password)
			*password = smb_xstrdup("");

		DEBUG(3, ("IPC$ connections done by user %s\\%s\n", 
			  *domain, *username));

	} else {
		DEBUG(3, ("IPC$ connections done anonymously\n"));
		*username = smb_xstrdup("");
		*domain = smb_xstrdup("");
		*password = smb_xstrdup("");
	}
}
