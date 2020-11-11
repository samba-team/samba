/* 
   Unix SMB/CIFS implementation.
   Samba utility functions
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Jeremy Allison 2001-2002
   Copyright (C) Simo Sorce 2001
   Copyright (C) Jim McDonough (jmcd@us.ibm.com)  2003.
   Copyright (C) James J Myers 2003
   Copyright (C) Jelmer Vernooij 2005-2007
   
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

#include "includes.h"
#include "dynconfig/dynconfig.h"
#include "system/network.h"
#include "system/filesys.h"
#include "system/dir.h"
#include "param/param.h"
#include "libds/common/roles.h"
#include "tdb.h"

/**
 * @file
 * @brief Misc utility functions
 */


bool lpcfg_is_mydomain(struct loadparm_context *lp_ctx,
			     const char *domain)
{
	return strequal(lpcfg_workgroup(lp_ctx), domain);
}

bool lpcfg_is_my_domain_or_realm(struct loadparm_context *lp_ctx,
			     const char *domain)
{
	return strequal(lpcfg_workgroup(lp_ctx), domain) ||
		strequal(lpcfg_realm(lp_ctx), domain);
}

/**
  see if a string matches either our primary or one of our secondary 
  netbios aliases. do a case insensitive match
*/
bool lpcfg_is_myname(struct loadparm_context *lp_ctx, const char *name)
{
	const char **aliases;
	int i;

	if (strcasecmp_m(name, lpcfg_netbios_name(lp_ctx)) == 0) {
		return true;
	}

	aliases = lpcfg_netbios_aliases(lp_ctx);
	for (i=0; aliases && aliases[i]; i++) {
		if (strcasecmp_m(name, aliases[i]) == 0) {
			return true;
		}
	}

	return false;
}

static char *lpcfg_common_path(TALLOC_CTX* mem_ctx,
			       const char *parent,
			       const char *name)
{
	char *fname, *dname;
	bool ok;

	if (name == NULL) {
		return NULL;
	}
	if (name[0] == 0 || name[0] == '/' || strstr(name, ":/")) {
		return talloc_strdup(mem_ctx, name);
	}

	dname = talloc_strdup(mem_ctx, parent);
	if (dname == NULL) {
		return NULL;
	}
	trim_string(dname,"","/");

	ok = directory_create_or_exist(dname, 0755);
	if (!ok) {
		DEBUG(1, ("Unable to create directory %s for file %s. "
			  "Error was %s\n", dname, name, strerror(errno)));
		return NULL;
	}

	fname = talloc_asprintf(mem_ctx, "%s/%s", dname, name);
	if (fname == NULL) {
		return dname;
	}
	talloc_free(dname);

	return fname;
}


/**
 A useful function for returning a path in the Samba lock directory.
**/
char *lpcfg_lock_path(TALLOC_CTX* mem_ctx, struct loadparm_context *lp_ctx,
			 const char *name)
{
	return lpcfg_common_path(mem_ctx, lpcfg_lock_directory(lp_ctx), name);
}

/**
 A useful function for returning a path in the Samba state directory.
**/
char *lpcfg_state_path(TALLOC_CTX* mem_ctx, struct loadparm_context *lp_ctx,
		       const char *name)
{
	return lpcfg_common_path(mem_ctx, lpcfg_state_directory(lp_ctx), name);
}

/**
 A useful function for returning a path in the Samba cache directory.
**/
char *lpcfg_cache_path(TALLOC_CTX* mem_ctx, struct loadparm_context *lp_ctx,
		       const char *name)
{
	return lpcfg_common_path(mem_ctx, lpcfg_cache_directory(lp_ctx), name);
}

/**
 * @brief Returns an absolute path to a file in the directory containing the current config file
 *
 * @param name File to find, relative to the config file directory.
 *
 * @retval Pointer to a talloc'ed string containing the full path.
 **/

char *lpcfg_config_path(TALLOC_CTX* mem_ctx, struct loadparm_context *lp_ctx,
			   const char *name)
{
	char *fname, *config_dir, *p;
	config_dir = talloc_strdup(mem_ctx, lpcfg_configfile(lp_ctx));
	if (config_dir == NULL) {
		config_dir = talloc_strdup(mem_ctx, lp_default_path());
	}
	p = strrchr(config_dir, '/');
	if (p == NULL) {
		talloc_free(config_dir);
		config_dir = talloc_strdup(mem_ctx, ".");
		if (config_dir == NULL) {
			return NULL;
		}
	} else {
		p[0] = '\0';
	}
	fname = talloc_asprintf(mem_ctx, "%s/%s", config_dir, name);
	talloc_free(config_dir);
	return fname;
}

/**
 * @brief Returns an absolute path to a file in the Samba private directory.
 *
 * @param name File to find, relative to PRIVATEDIR.
 * if name is not relative, then use it as-is
 *
 * @retval Pointer to a talloc'ed string containing the full path.
 **/
char *lpcfg_private_path(TALLOC_CTX* mem_ctx,
			    struct loadparm_context *lp_ctx,
			    const char *name)
{
	char *fname;
	if (name == NULL) {
		return NULL;
	}
	if (name[0] == 0 || name[0] == '/' || strstr(name, ":/")) {
		return talloc_strdup(mem_ctx, name);
	}
	fname = talloc_asprintf(mem_ctx, "%s/%s", lpcfg_private_dir(lp_ctx), name);
	return fname;
}

/**
 * @brief Returns an absolute path to a NTDB or TDB file in the Samba
 * private directory.
 *
 * @param name File to find, relative to PRIVATEDIR, without .tdb extension.
 *
 * @retval Pointer to a talloc'ed string containing the full path, for
 * use with dbwrap_local_open().
 **/
char *lpcfg_private_db_path(TALLOC_CTX *mem_ctx,
			    struct loadparm_context *lp_ctx,
			    const char *name)
{
	return talloc_asprintf(mem_ctx, "%s/%s.tdb",
			       lpcfg_private_dir(lp_ctx), name);
}

/**
  return a path in the smbd.tmp directory, where all temporary file
  for smbd go. If NULL is passed for name then return the directory 
  path itself
*/
char *smbd_tmp_path(TALLOC_CTX *mem_ctx, 
			     struct loadparm_context *lp_ctx,
			     const char *name)
{
	char *fname, *dname;
	bool ok;

	dname = lpcfg_private_path(mem_ctx, lp_ctx, "smbd.tmp");
	if (dname == NULL) {
		return NULL;
	}

	ok = directory_create_or_exist(dname, 0755);
	if (!ok) {
		return NULL;
	}

	if (name == NULL) {
		return dname;
	}

	fname = talloc_asprintf(mem_ctx, "%s/%s", dname, name);
	if (fname == NULL) {
		return dname;
	}
	talloc_free(dname);

	return fname;
}

const char *lpcfg_imessaging_path(TALLOC_CTX *mem_ctx,
				       struct loadparm_context *lp_ctx)
{
	return smbd_tmp_path(mem_ctx, lp_ctx, "msg");
}

const char *lpcfg_sam_name(struct loadparm_context *lp_ctx)
{
	switch (lpcfg_server_role(lp_ctx)) {
	case ROLE_DOMAIN_BDC:
	case ROLE_DOMAIN_PDC:
	case ROLE_ACTIVE_DIRECTORY_DC:
	case ROLE_IPA_DC:
		return lpcfg_workgroup(lp_ctx);
	default:
		return lpcfg_netbios_name(lp_ctx);
	}
}

const char *lpcfg_sam_dnsname(struct loadparm_context *lp_ctx)
{
	switch (lpcfg_server_role(lp_ctx)) {
	case ROLE_ACTIVE_DIRECTORY_DC:
		return lpcfg_dnsdomain(lp_ctx);
	default:
		return NULL;
	}
}

static long tdb_fetch_lifetime(TALLOC_CTX *mem_ctx, struct tdb_context *tdb, const char *keystr)
{
	TDB_DATA key;
	TDB_DATA ret;
	char *tmp = NULL;
	long result;

	key.dptr = discard_const_p(unsigned char, keystr);
	key.dsize = strlen(keystr);

	if (!key.dptr)
		return -1;

	ret = tdb_fetch(tdb, key);
	if (ret.dsize == 0)
		return -1;

	tmp = talloc_realloc(mem_ctx, tmp, char, ret.dsize+1);
	memset(tmp, 0, ret.dsize+1);
	memcpy(tmp, ret.dptr, ret.dsize);
	free(ret.dptr);

	result = atol(tmp);
	talloc_free(tmp);
	return result;
}

void lpcfg_default_kdc_policy(TALLOC_CTX *mem_ctx,
				struct loadparm_context *lp_ctx,
				time_t *svc_tkt_lifetime,
				time_t *usr_tkt_lifetime,
				time_t *renewal_lifetime)
{
	long val;
	TDB_CONTEXT *ctx = NULL;
	const char *kdc_tdb = NULL;

	kdc_tdb = lpcfg_cache_path(mem_ctx, lp_ctx, "gpo.tdb");
	if (kdc_tdb)
		ctx = tdb_open(kdc_tdb, 0, TDB_DEFAULT, O_RDWR, 0600);

	if (!ctx || ( val = tdb_fetch_lifetime(mem_ctx, ctx, "kdc:service_ticket_lifetime") ) == -1 )
		val = lpcfg_parm_long(lp_ctx, NULL, "kdc", "service ticket lifetime", 10);
	*svc_tkt_lifetime = val * 60 * 60;

	if (!ctx || ( val = tdb_fetch_lifetime(mem_ctx, ctx, "kdc:user_ticket_lifetime") ) == -1 )
		val = lpcfg_parm_long(lp_ctx, NULL, "kdc", "user ticket lifetime", 10);
	*usr_tkt_lifetime = val * 60 * 60;

	if (!ctx || ( val = tdb_fetch_lifetime(mem_ctx, ctx, "kdc:renewal_lifetime") ) == -1 )
		val = lpcfg_parm_long(lp_ctx, NULL, "kdc", "renewal lifetime", 24 * 7);
	*renewal_lifetime = val * 60 * 60;
}
