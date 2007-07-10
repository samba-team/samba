/* 
 *  Unix SMB/CIFS implementation.
 *  Copyright (C) Jelmer Vernooij			2005
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
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

NTSTATUS samba3_read_passdb_backends(TALLOC_CTX *ctx, const char *libdir, struct samba3 *samba3)
{
	char *dbfile;
	NTSTATUS status = NT_STATUS_OK;
	int i;
	const char **backends = param_get_string_list(samba3->configuration, NULL, "passdb backend", NULL);

	/* Default to smbpasswd */
	if (backends == NULL) 
		backends = str_list_make(ctx, "smbpasswd", LIST_SEP);
	else
		backends = str_list_copy(ctx, backends);


	for (i = 0; backends[i]; i++) {
		if (!strncmp(backends[i], "tdbsam", strlen("tdbsam"))) {
			const char *p = strchr(backends[i], ':');
			if (p && p[1]) {
				dbfile = talloc_strdup(ctx, p+1);
			} else {
				dbfile = talloc_asprintf(ctx, "%s/passdb.tdb", libdir);
			}
			samba3_read_tdbsam(dbfile, ctx, &samba3->samaccounts, &samba3->samaccount_count);
			talloc_free(dbfile);
		} else if (!strncmp(backends[i], "smbpasswd", strlen("smbpasswd"))) {
			const char *p = strchr(backends[i], ':');
			if (p && p[1]) {
				dbfile = talloc_strdup(ctx, p+1);
			} else if ((p = param_get_string(samba3->configuration, NULL, "smb passwd file"))) {
				dbfile = talloc_strdup(ctx, p);
			} else {
				dbfile = talloc_strdup(ctx, "/etc/samba/smbpasswd");
			}

			samba3_read_smbpasswd(dbfile, ctx, &samba3->samaccounts, &samba3->samaccount_count);
			talloc_free(dbfile);
		} else if (!strncmp(backends[i], "ldapsam", strlen("ldapsam"))) {
			/* Will use samba3sam mapping module */			
		} else {
			DEBUG(0, ("Upgrade from %s database not supported", backends[i]));
			status = NT_STATUS_NOT_SUPPORTED;
			continue;
		}
	}

	talloc_free(backends);

	return status;
}

NTSTATUS samba3_read(const char *libdir, const char *smbconf, TALLOC_CTX *ctx, struct samba3 **samba3)
{
	struct samba3 *ret;
	char *dbfile = NULL;

	ret = talloc_zero(ctx, struct samba3);

	if (smbconf != NULL) {
		ret->configuration = param_init(ret);
		if (param_read(ret->configuration, smbconf) == -1) {
			talloc_free(ret);
			return NT_STATUS_UNSUCCESSFUL;
		}
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

	samba3_read_passdb_backends(ctx, libdir, ret);

	dbfile = talloc_asprintf(ctx, "%s/group_mapping.tdb", libdir);
	samba3_read_grouptdb(dbfile, ctx, &ret->group);
	talloc_free(dbfile);

	*samba3 = ret;

	return NT_STATUS_OK;
}
