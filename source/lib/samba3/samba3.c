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

struct samba3_domainsecrets *samba3_find_domainsecrets(struct samba3 *db, const char *name)
{
	int i;
	
	for (i = 0; i < db->secrets.domain_count; i++) {
		if (!strcasecmp_m(db->secrets.domains[i].name, name)) 
			return &db->secrets.domains[i];
	}

	return NULL;
}

NTSTATUS samba3_read(const char *libdir, const char *smbconf, TALLOC_CTX *ctx, struct samba3 **samba3)
{
	struct samba3 *ret;
	char *dbfile = NULL;

	ret = talloc_zero(ctx, struct samba3);

	if (smbconf) {
		ret->configuration = param_init(ret);
		param_read(ret->configuration, smbconf);
	}

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
