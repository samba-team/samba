/* 
 *  Unix SMB/CIFS implementation.
 *  Copyright (C) Jelmer Vernooij			2005
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

#include "includes.h"
#include "lib/samba3/samba3.h"

struct smbconf_data {
	TALLOC_CTX *ctx;
	struct samba3 *db;
	struct samba3_share_info *current_share;
};

struct samba3_domainsecrets *samba3_find_domainsecrets(struct samba3 *db, const char *name)
{
	int i;
	
	for (i = 0; i < db->secrets.domain_count; i++) {
		if (!StrCaseCmp(db->secrets.domains[i].name, name)) 
			return &db->secrets.domains[i];
	}

	return NULL;
}

struct samba3_share_info *samba3_find_share(struct samba3 *db, const char *name)
{
	int i;
	for (i = 0; i < db->share_count; i++) {
		if (!StrCaseCmp(db->shares[i].name, name)) 
			return &db->shares[i];
	}

	return NULL;
}


struct samba3_share_info *samba3_find_add_share(struct samba3 *db, TALLOC_CTX* ctx, const char *name)
{
	struct samba3_share_info *share = samba3_find_share(db, name);

	if (share)
		return share;

	db->shares = talloc_realloc(ctx, db->shares, struct samba3_share_info, db->share_count+1);
	ZERO_STRUCT(db->shares[db->share_count]);
	db->shares[db->share_count].name = talloc_strdup(ctx, name);
	db->share_count++;
	
	return &db->shares[db->share_count-1];
}

const char *samba3_get_param(struct samba3 *samba3, const char *section, const char *param)
{
	int i;
	struct samba3_share_info *share = samba3_find_share(samba3, section);

	if (share == NULL)
		return NULL;

	for (i = 0; i < share->parameter_count; i++) {
		if (!StrCaseCmp(share->parameters[i].name, param))
			return share->parameters[i].value;
	}

	return NULL;
}


static BOOL samba3_sfunc (const char *name, void *_db)
{
	struct smbconf_data *privdat = _db;

	privdat->current_share = samba3_find_add_share(privdat->db, privdat->ctx, name);

	return True;
}

static BOOL samba3_pfunc (const char *name, const char *value, void *_db)
{
	struct smbconf_data *privdat = _db;
	struct samba3_parameter *p;

	privdat->current_share->parameters = 
		talloc_realloc(privdat->ctx, privdat->current_share->parameters,
					   struct samba3_parameter, 
					   privdat->current_share->parameter_count+1);

	p = &privdat->current_share->parameters[privdat->current_share->parameter_count];
	p->name = talloc_strdup(privdat->ctx, name);
	p->value = talloc_strdup(privdat->ctx, value);

	privdat->current_share->parameter_count++;

	return True;
}

NTSTATUS samba3_read_smbconf(const char *fn, TALLOC_CTX *ctx, struct samba3 *db)
{
	struct smbconf_data privdat;

	privdat.ctx = ctx;
	privdat.db = db;
	privdat.current_share = samba3_find_add_share(db, ctx, "global");
	
	if (!pm_process( fn, samba3_sfunc, samba3_pfunc, &privdat )) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	return NT_STATUS_OK;
}

NTSTATUS samba3_read(const char *smbconf, const char *libdir, TALLOC_CTX *ctx, struct samba3 **samba3)
{
	struct samba3 *ret;
	char *dbfile = NULL;

	ret = talloc_zero(ctx, struct samba3);

	if (smbconf) 
		samba3_read_smbconf(smbconf, ctx, ret);

	dbfile = talloc_asprintf(ctx, "%s/account_policy.tdb", libdir);
	samba3_read_account_policy(dbfile, ctx, &ret->policy);
	talloc_free(dbfile);

	dbfile = talloc_asprintf(ctx, "%s/registry.tdb", libdir);
	samba3_read_regdb(dbfile, ctx, &ret->registry);
	talloc_free(dbfile);

	dbfile = talloc_asprintf(ctx, "%s/secrets.tdb", libdir);
	samba3_read_secrets(dbfile, ctx, &ret->secrets);
	talloc_free(dbfile);

	dbfile = talloc_asprintf(ctx, "%s/share_info.tdb", libdir);
	samba3_read_share_info(dbfile, ctx, ret);
	talloc_free(dbfile);

	dbfile = talloc_asprintf(ctx, "%s/winbindd_idmap.tdb", libdir);
	samba3_read_idmap(dbfile, ctx, &ret->idmap);
	talloc_free(dbfile);

	dbfile = talloc_asprintf(ctx, "%s/wins.dat", libdir);
	samba3_read_winsdb(dbfile, ret, &ret->winsdb_entries, &ret->winsdb_count);
	talloc_free(dbfile);

	dbfile = talloc_asprintf(ctx, "%s/passdb.tdb", libdir);
	samba3_read_tdbsam(dbfile, ctx, &ret->samaccounts, &ret->samaccount_count);
	talloc_free(dbfile);

	dbfile = talloc_asprintf(ctx, "%s/group_mapping.tdb", libdir);
	samba3_read_grouptdb(dbfile, ctx, &ret->group);
	talloc_free(dbfile);

	*samba3 = ret;

	return NT_STATUS_OK;
}
