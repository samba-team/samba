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

struct samba3 *samba3_read(const char *libdir, TALLOC_CTX *ctx)
{
	struct samba3 *ret;
	char *dbfile;

	ret = talloc(ctx, struct samba3);
	
	asprintf(&dbfile, "%s/winsdb.dat", libdir);
	samba3_read_winsdb(dbfile, ret, &ret->winsdb_entries, &ret->winsdb_count);
	SAFE_FREE(dbfile);

	asprintf(&dbfile, "%s/passdb.tdb", libdir);
	samba3_read_tdbsam(dbfile, ctx, &ret->samaccounts, &ret->samaccount_count);
	SAFE_FREE(dbfile);

	asprintf(&dbfile, "%s/groupdb.tdb", libdir);
	samba3_read_grouptdb(dbfile, ctx, &ret->group);
	SAFE_FREE(dbfile);

	asprintf(&dbfile, "%s/idmap.tdb", libdir);
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

	return ret;
}
