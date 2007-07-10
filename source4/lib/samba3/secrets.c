/* 
   Unix SMB/CIFS implementation.
   Copyright (C) Andrew Tridgell 1992-2001
   Copyright (C) Andrew Bartlett      2002
   Copyright (C) Rafal Szczesniak     2002
   Copyright (C) Tim Potter           2001
   Copyright (C) Jelmer Vernooij	  2005

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

/* the Samba secrets database stores any generated, private information
   such as the local SID and machine trust password */

#include "includes.h"
#include "lib/tdb/include/tdb.h"
#include "lib/util/util_tdb.h"
#include "lib/samba3/samba3.h"
#include "system/filesys.h"
#include "librpc/gen_ndr/security.h"
#include "auth/credentials/credentials.h"

/**
 * Unpack SID into a pointer
 *
 * @param pack_buf pointer to buffer with packed representation
 * @param bufsize size of the buffer
 * @param sid pointer to sid structure to be filled with unpacked data
 *
 * @return size of structure unpacked from buffer
 **/
static size_t tdb_sid_unpack(TDB_CONTEXT *tdb, char* pack_buf, int bufsize, struct dom_sid* sid)
{
	int idx, len = 0;
	
	if (!sid || !pack_buf) return -1;

	len += tdb_unpack(tdb, pack_buf + len, bufsize - len, "bb",
	                  &sid->sid_rev_num, &sid->num_auths);
			  
	for (idx = 0; idx < 6; idx++) {
		len += tdb_unpack(tdb, pack_buf + len, bufsize - len, "b", &sid->id_auth[idx]);
	}
	
	for (idx = 0; idx < 15; idx++) {
		len += tdb_unpack(tdb, pack_buf + len, bufsize - len, "d", &sid->sub_auths[idx]);
	}
	
	return len;
}

static struct samba3_domainsecrets *secrets_find_domain(TALLOC_CTX *ctx, struct samba3_secrets *db, const char *key)
{
	int i;

	for (i = 0; i < db->domain_count; i++) 
	{
		if (!strcasecmp_m(db->domains[i].name, key)) 
			return &db->domains[i];
	}

	db->domains = talloc_realloc(ctx, db->domains, struct samba3_domainsecrets, db->domain_count+1);
	ZERO_STRUCT(db->domains[db->domain_count]);
	db->domains[db->domain_count].name = talloc_strdup(db->domains, key); 

	db->domain_count++;
	
	return &db->domains[db->domain_count-1];
}

static NTSTATUS ipc_password (TDB_CONTEXT *tdb, const char *key, TDB_DATA vbuf, TALLOC_CTX *ctx, struct samba3_secrets *db) 
{
	cli_credentials_set_password(db->ipc_cred, (const char *)vbuf.dptr, CRED_SPECIFIED);
	return NT_STATUS_OK;
}

static NTSTATUS ipc_username (TDB_CONTEXT *tdb, const char *key, TDB_DATA vbuf, TALLOC_CTX *ctx, struct samba3_secrets *db) 
{
	cli_credentials_set_username(db->ipc_cred, (const char *)vbuf.dptr, CRED_SPECIFIED);
	return NT_STATUS_OK;
}
	
static NTSTATUS ipc_domain (TDB_CONTEXT *tdb, const char *key, TDB_DATA vbuf, TALLOC_CTX *ctx, struct samba3_secrets *db) 
{
	cli_credentials_set_domain(db->ipc_cred, (const char *)vbuf.dptr, CRED_SPECIFIED);
	return NT_STATUS_OK;
}

static NTSTATUS domain_sid (TDB_CONTEXT *tdb, const char *key, TDB_DATA vbuf, TALLOC_CTX *ctx, struct samba3_secrets *db) 
{
	struct samba3_domainsecrets *domainsec = secrets_find_domain(ctx, db, key);
	domainsec->sid.sub_auths = talloc_array(ctx, uint32_t, 15);
	tdb_sid_unpack(tdb, (char *)vbuf.dptr, vbuf.dsize, &domainsec->sid);
	return NT_STATUS_OK;
}

static NTSTATUS domain_guid (TDB_CONTEXT *tdb, const char *key, TDB_DATA vbuf, TALLOC_CTX *ctx, struct samba3_secrets *db) 
{
	struct samba3_domainsecrets *domainsec = secrets_find_domain(ctx, db, key);
	memcpy(&domainsec->guid, vbuf.dptr, vbuf.dsize);
	return NT_STATUS_OK;
}

static NTSTATUS ldap_bind_pw (TDB_CONTEXT *tdb, const char *key, TDB_DATA vbuf, TALLOC_CTX *ctx, struct samba3_secrets *db) 
{
	struct samba3_ldappw pw;
	pw.dn = talloc_strdup(ctx, key);
	pw.password = talloc_strdup(ctx, (const char *)vbuf.dptr);

	db->ldappws = talloc_realloc(ctx, db->ldappws, struct samba3_ldappw, db->ldappw_count+1);
	db->ldappws[db->ldappw_count] = pw;
	db->ldappw_count++;
	return NT_STATUS_OK;
}

static NTSTATUS afs_keyfile (TDB_CONTEXT *tdb, const char *key, TDB_DATA vbuf, TALLOC_CTX *ctx, struct samba3_secrets *db) 
{
	struct samba3_afs_keyfile keyfile;
	memcpy(&keyfile, vbuf.dptr, vbuf.dsize);
	keyfile.cell = talloc_strdup(ctx, key);

	db->afs_keyfiles = talloc_realloc(ctx, db->afs_keyfiles, struct samba3_afs_keyfile, db->afs_keyfile_count+1);
	db->afs_keyfiles[db->afs_keyfile_count] = keyfile;
	db->afs_keyfile_count++;
	
	return NT_STATUS_OK;
}

static NTSTATUS machine_sec_channel_type (TDB_CONTEXT *tdb, const char *key, TDB_DATA vbuf, TALLOC_CTX *ctx, struct samba3_secrets *db) 
{
	struct samba3_domainsecrets *domainsec = secrets_find_domain(ctx, db, key);

	domainsec->sec_channel_type = IVAL(vbuf.dptr, 0);
	return NT_STATUS_OK;
}

static NTSTATUS machine_last_change_time (TDB_CONTEXT *tdb, const char *key, TDB_DATA vbuf, TALLOC_CTX *ctx, struct samba3_secrets *db) 
{
	struct samba3_domainsecrets *domainsec = secrets_find_domain(ctx, db, key);
	domainsec->last_change_time = IVAL(vbuf.dptr, 0);
	return NT_STATUS_OK;
}

static NTSTATUS machine_password (TDB_CONTEXT *tdb, const char *key, TDB_DATA vbuf, TALLOC_CTX *ctx, struct samba3_secrets *db) 
{
	struct samba3_domainsecrets *domainsec = secrets_find_domain(ctx, db, key);
	domainsec->plaintext_pw = talloc_strdup(ctx, (const char *)vbuf.dptr);
	return NT_STATUS_OK;
}

static NTSTATUS machine_acc (TDB_CONTEXT *tdb, const char *key, TDB_DATA vbuf, TALLOC_CTX *ctx, struct samba3_secrets *db) 
{
	struct samba3_domainsecrets *domainsec = secrets_find_domain(ctx, db, key);

	memcpy(&domainsec->hash_pw, vbuf.dptr, vbuf.dsize);

	return NT_STATUS_OK;
}

static NTSTATUS random_seed (TDB_CONTEXT *tdb, const char *key, TDB_DATA vbuf, TALLOC_CTX *ctx, struct samba3_secrets *db) 
{
	/* Ignore */	
	return NT_STATUS_OK;
}

static NTSTATUS domtrust_acc (TDB_CONTEXT *tdb, const char *key, TDB_DATA vbuf, TALLOC_CTX *ctx, struct samba3_secrets *db) 
{
	int idx, len = 0;
	struct samba3_trusted_dom_pass pass;
	int pass_len;
	
	if (!vbuf.dptr) 
		return NT_STATUS_UNSUCCESSFUL;

	/* unpack unicode domain name and plaintext password */
	len += tdb_unpack(tdb, (char *)vbuf.dptr, vbuf.dsize - len, "d", &pass.uni_name_len);
	
	for (idx = 0; idx < 32; idx++)
		len +=  tdb_unpack(tdb, (char *)(vbuf.dptr + len), vbuf.dsize - len, "w", &pass.uni_name[idx]);

	len += tdb_unpack(tdb, (char *)(vbuf.dptr + len), vbuf.dsize - len, "d", &pass_len);
	pass.pass = talloc_strdup(ctx, (char *)(vbuf.dptr+len));
	len += strlen((const char *)vbuf.dptr)+1;
	len += tdb_unpack(tdb, (char *)(vbuf.dptr + len), vbuf.dsize - len, "d", &pass.mod_time);
	
	pass.domain_sid.sub_auths = talloc_array(ctx, uint32_t, 15);
	/* unpack domain sid */
	len += tdb_sid_unpack(tdb, (char *)(vbuf.dptr + len), vbuf.dsize - len, &pass.domain_sid);

	/* FIXME: Add to list */

	return NT_STATUS_OK;
}

static const struct {
	const char *prefix;
	NTSTATUS (*handler) (TDB_CONTEXT *tdb, const char *key, TDB_DATA vbuf, TALLOC_CTX *ctx, struct samba3_secrets *db);
} secrets_handlers[] = {
	{ "SECRETS/AUTH_PASSWORD", ipc_password },
	{ "SECRETS/AUTH_DOMAIN", ipc_domain },
	{ "SECRETS/AUTH_USER", ipc_username },
	{ "SECRETS/SID/", domain_sid },
	{ "SECRETS/DOMGUID/", domain_guid },
	{ "SECRETS/LDAP_BIND_PW/", ldap_bind_pw },
	{ "SECRETS/AFS_KEYFILE/", afs_keyfile },
	{ "SECRETS/MACHINE_SEC_CHANNEL_TYPE/", machine_sec_channel_type },
	{ "SECRETS/MACHINE_LAST_CHANGE_TIME/", machine_last_change_time },
	{ "SECRETS/MACHINE_PASSWORD/", machine_password },
	{ "SECRETS/$MACHINE.ACC/", machine_acc },
	{ "SECRETS/$DOMTRUST.ACC/", domtrust_acc },
	{ "INFO/random_seed", random_seed },
};


NTSTATUS samba3_read_secrets(const char *fname, TALLOC_CTX *ctx, struct samba3_secrets *db)
{
	TDB_CONTEXT *tdb = tdb_open(fname, 0, TDB_DEFAULT, O_RDONLY, 0600);
	TDB_DATA kbuf, vbuf;

	if (!tdb) {
		DEBUG(0,("Failed to open %s\n", fname));
		return NT_STATUS_UNSUCCESSFUL;
	}

	ZERO_STRUCTP(db);
	
	db->ipc_cred = cli_credentials_init(ctx);
	
	for (kbuf = tdb_firstkey(tdb); kbuf.dptr; kbuf = tdb_nextkey(tdb, kbuf))
	{
		int i;
		char *key;
		vbuf = tdb_fetch(tdb, kbuf);

		for (i = 0; secrets_handlers[i].prefix; i++) {
			if (!strncmp((const char *)kbuf.dptr, secrets_handlers[i].prefix, strlen(secrets_handlers[i].prefix))) {
				key = talloc_strndup(ctx, (const char *)(kbuf.dptr+strlen(secrets_handlers[i].prefix)), kbuf.dsize-strlen(secrets_handlers[i].prefix));
				secrets_handlers[i].handler(tdb, key, vbuf, ctx, db);
				talloc_free(key);
				break;
			}
		}

		if (!secrets_handlers[i].prefix) {
			DEBUG(0, ("Unable to find handler for string %s\n", kbuf.dptr));
		}
	}
	
	tdb_close(tdb);

	return NT_STATUS_OK;
}
