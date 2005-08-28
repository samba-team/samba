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

struct samba3_share_info *samba3_find_share(struct samba3 *db, TALLOC_CTX* ctx, const char *name)
{
	int i;
	for (i = 0; i < db->share_count; i++) {
		if (!StrCaseCmp(db->shares[i].name, name)) 
			return &db->shares[i];
	}

	db->shares = talloc_realloc(ctx, db->shares, struct samba3_share_info, db->share_count+1);
	ZERO_STRUCT(db->shares[i]);
	db->shares[i].name = talloc_strdup(ctx, name);
	db->share_count++;
	
	return &db->shares[i];
}

static BOOL samba3_sfunc (const char *name, void *_db)
{
	struct smbconf_data *privdat = _db;

	privdat->current_share = samba3_find_share(privdat->db, privdat->ctx, name);

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
	privdat.current_share = samba3_find_share(db, ctx, "global");
	
	if (!pm_process( fn, samba3_sfunc, samba3_pfunc, &privdat )) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	return NT_STATUS_OK;
}

NTSTATUS samba3_read(const char *smbconf, const char *libdir, TALLOC_CTX *ctx, struct samba3 **samba3)
{
	struct samba3 *ret;
	char *dbfile;

	ret = talloc_zero(ctx, struct samba3);

	if (smbconf) 
		samba3_read_smbconf(smbconf, ctx, ret);

	asprintf(&dbfile, "%s/wins.dat", libdir);
	samba3_read_winsdb(dbfile, ret, &ret->winsdb_entries, &ret->winsdb_count);
	SAFE_FREE(dbfile);

	asprintf(&dbfile, "%s/passdb.tdb", libdir);
	samba3_read_tdbsam(dbfile, ctx, &ret->samaccounts, &ret->samaccount_count);
	SAFE_FREE(dbfile);

	asprintf(&dbfile, "%s/group_mapping.tdb", libdir);
	samba3_read_grouptdb(dbfile, ctx, &ret->group);
	SAFE_FREE(dbfile);

	asprintf(&dbfile, "%s/winbindd_idmap.tdb", libdir);
	samba3_read_idmap(dbfile, ctx, &ret->idmap);
	SAFE_FREE(dbfile);

	asprintf(&dbfile, "%s/account_policy.tdb", libdir);
	samba3_read_account_policy(dbfile, ctx, &ret->policy);
	SAFE_FREE(dbfile);

	asprintf(&dbfile, "%s/registry.tdb", libdir);
	samba3_read_regdb(dbfile, ctx, &ret->registry);
	SAFE_FREE(dbfile);

	asprintf(&dbfile, "%s/secrets.tdb", libdir);
	samba3_read_secrets(dbfile, ctx, &ret->secrets);
	SAFE_FREE(dbfile);

	asprintf(&dbfile, "%s/share_info.tdb", libdir);
	samba3_read_share_info(dbfile, ctx, ret);
	SAFE_FREE(dbfile);

	*samba3 = ret;

	return NT_STATUS_OK;
}
