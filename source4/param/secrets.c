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
#include "secrets.h"
#include "param/param.h"
#include "system/filesys.h"
#include "db_wrap.h"
#include "lib/ldb/include/ldb.h"
#include "lib/tdb/include/tdb.h"
#include "lib/util/util_tdb.h"
#include "dsdb/samdb/samdb.h"

static struct tdb_wrap *tdb;

/**
 * Use a TDB to store an incrementing random seed.
 *
 * Initialised to the current pid, the very first time Samba starts,
 * and incremented by one each time it is needed.  
 * 
 * @note Not called by systems with a working /dev/urandom.
 */
static void get_rand_seed(int *new_seed) 
{
	*new_seed = getpid();
	if (tdb) {
		tdb_change_int32_atomic(tdb->tdb, "INFO/random_seed", new_seed, 1);
	}
}

/* close the secrets database */
void secrets_shutdown(void)
{
       talloc_free(tdb);
}

/* open up the secrets database */
BOOL secrets_init(void)
{
	char *fname;
	uint8_t dummy;

	if (tdb)
		return True;

	asprintf(&fname, "%s/secrets.tdb", lp_private_dir());

	tdb = tdb_wrap_open(talloc_autofree_context(), fname, 0, TDB_DEFAULT, O_RDWR|O_CREAT, 0600);

	if (!tdb) {
		DEBUG(0,("Failed to open %s\n", fname));
		SAFE_FREE(fname);
		return False;
	}
	SAFE_FREE(fname);

	/**
	 * Set a reseed function for the crypto random generator 
	 * 
	 * This avoids a problem where systems without /dev/urandom
	 * could send the same challenge to multiple clients
	 */
	set_rand_reseed_callback(get_rand_seed);

	/* Ensure that the reseed is done now, while we are root, etc */
	generate_random_buffer(&dummy, sizeof(dummy));

	return True;
}

/*
  connect to the schannel ldb
*/
struct ldb_context *secrets_db_connect(TALLOC_CTX *mem_ctx)
{
	char *path;
	struct ldb_context *ldb;
	BOOL existed;
	const char *init_ldif = 
		"dn: @ATTRIBUTES\n" \
		"computerName: CASE_INSENSITIVE\n" \
		"flatname: CASE_INSENSITIVE\n";

	path = private_path(mem_ctx, "secrets.ldb");
	if (!path) {
		return NULL;
	}
	
	existed = file_exist(path);

	/* Secrets.ldb *must* always be local.  If we call for a
	 * system_session() we will recurse */
	ldb = ldb_wrap_connect(mem_ctx, path, NULL, NULL, 0, NULL);
	talloc_free(path);
	if (!ldb) {
		return NULL;
	}
	
	if (!existed) {
		gendb_add_ldif(ldb, init_ldif);
	}

	return ldb;
}

struct dom_sid *secrets_get_domain_sid(TALLOC_CTX *mem_ctx,
				       const char *domain)
{
	struct ldb_context *ldb;
	struct ldb_message **msgs;
	int ldb_ret;
	const char *attrs[] = { "objectSid", NULL };
	struct dom_sid *result = NULL;

	ldb = secrets_db_connect(mem_ctx);
	if (ldb == NULL) {
		DEBUG(5, ("secrets_db_connect failed\n"));
		return NULL;
	}

	ldb_ret = gendb_search(ldb, ldb,
			       ldb_dn_new(mem_ctx, ldb, SECRETS_PRIMARY_DOMAIN_DN), 
			       &msgs, attrs,
			       SECRETS_PRIMARY_DOMAIN_FILTER, domain);

	if (ldb_ret == -1) {
		DEBUG(5, ("Error searching for domain SID for %s: %s", 
			  domain, ldb_errstring(ldb))); 
		talloc_free(ldb);
		return NULL;
	}

	if (ldb_ret == 0) {
		DEBUG(5, ("Did not find domain record for %s\n", domain));
		talloc_free(ldb);
		return NULL;
	}

	if (ldb_ret > 1) {
		DEBUG(5, ("Found more than one (%d) domain records for %s\n",
			  ldb_ret, domain));
		talloc_free(ldb);
		return NULL;
	}

	result = samdb_result_dom_sid(mem_ctx, msgs[0], "objectSid");
	if (result == NULL) {
		DEBUG(0, ("Domain object for %s does not contain a SID!\n",
			  domain));
		talloc_free(ldb);
		return NULL;
	}

	return result;
}
