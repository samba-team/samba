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


/**
 A useful function for returning a path in the Samba lock directory.
**/
char *lpcfg_lock_path(TALLOC_CTX* mem_ctx, struct loadparm_context *lp_ctx,
			 const char *name)
{
	char *fname, *dname;
	if (name == NULL) {
		return NULL;
	}
	if (name[0] == 0 || name[0] == '/' || strstr(name, ":/")) {
		return talloc_strdup(mem_ctx, name);
	}

	dname = talloc_strdup(mem_ctx, lpcfg_lockdir(lp_ctx));
	trim_string(dname,"","/");
	
	if (!directory_exist(dname)) {
		if (!mkdir(dname,0755))
			DEBUG(1, ("Unable to create directory %s for file %s. "
			      "Error was %s\n", dname, name, strerror(errno)));
	}
	
	fname = talloc_asprintf(mem_ctx, "%s/%s", dname, name);

	talloc_free(dname);

	return fname;
}

/**
 A useful function for returning a path in the Samba state directory.
**/
char *lpcfg_state_path(TALLOC_CTX* mem_ctx, struct loadparm_context *lp_ctx,
		       const char *name)
{
	char *fname, *dname;
	if (name == NULL) {
		return NULL;
	}
	if (name[0] == 0 || name[0] == '/' || strstr(name, ":/")) {
		return talloc_strdup(mem_ctx, name);
	}

	dname = talloc_strdup(mem_ctx, lpcfg_statedir(lp_ctx));
	trim_string(dname,"","/");

	if (!directory_exist(dname)) {
		mkdir(dname,0755);
	}

	fname = talloc_asprintf(mem_ctx, "%s/%s", dname, name);

	talloc_free(dname);

	return fname;
}

/**
 A useful function for returning a path in the Samba cache directory.
**/
char *lpcfg_cache_path(TALLOC_CTX* mem_ctx, struct loadparm_context *lp_ctx,
		       const char *name)
{
	char *fname, *dname;
	if (name == NULL) {
		return NULL;
	}
	if (name[0] == 0 || name[0] == '/' || strstr(name, ":/")) {
		return talloc_strdup(mem_ctx, name);
	}

	dname = talloc_strdup(mem_ctx, lpcfg_cachedir(lp_ctx));
	trim_string(dname,"","/");

	if (!directory_exist(dname)) {
		mkdir(dname,0755);
	}

	fname = talloc_asprintf(mem_ctx, "%s/%s", dname, name);

	talloc_free(dname);

	return fname;
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
  return a path in the smbd.tmp directory, where all temporary file
  for smbd go. If NULL is passed for name then return the directory 
  path itself
*/
char *smbd_tmp_path(TALLOC_CTX *mem_ctx, 
			     struct loadparm_context *lp_ctx,
			     const char *name)
{
	char *fname, *dname;

	dname = lpcfg_private_path(mem_ctx, lp_ctx, "smbd.tmp");
	if (!directory_exist(dname)) {
		mkdir(dname,0755);
	}

	if (name == NULL) {
		return dname;
	}

	fname = talloc_asprintf(mem_ctx, "%s/%s", dname, name);
	talloc_free(dname);

	return fname;
}

const char *lpcfg_imessaging_path(TALLOC_CTX *mem_ctx,
				       struct loadparm_context *lp_ctx)
{
	return smbd_tmp_path(mem_ctx, lp_ctx, "msg");
}

struct smb_iconv_handle *smb_iconv_handle_reinit_lp(TALLOC_CTX *mem_ctx,
							      struct loadparm_context *lp_ctx,
							      struct smb_iconv_handle *old_ic)
{
	return smb_iconv_handle_reinit(mem_ctx, lpcfg_dos_charset(lp_ctx),
				       lpcfg_unix_charset(lp_ctx),
				       true,
				       old_ic);
}


const char *lpcfg_sam_name(struct loadparm_context *lp_ctx)
{
	switch (lpcfg_server_role(lp_ctx)) {
	case ROLE_DOMAIN_BDC:
	case ROLE_DOMAIN_PDC:
	case ROLE_ACTIVE_DIRECTORY_DC:
		return lpcfg_workgroup(lp_ctx);
	default:
		return lpcfg_netbios_name(lp_ctx);
	}
}

void lpcfg_default_kdc_policy(struct loadparm_context *lp_ctx,
				time_t *svc_tkt_lifetime,
				time_t *usr_tkt_lifetime,
				time_t *renewal_lifetime)
{
	long val;

	val = lpcfg_parm_long(lp_ctx, NULL,
				"kdc", "service ticket lifetime", 10);
	*svc_tkt_lifetime = val * 60 * 60;

	val = lpcfg_parm_long(lp_ctx, NULL,
				"kdc", "user ticket lifetime", 10);
	*usr_tkt_lifetime = val * 60 * 60;

	val = lpcfg_parm_long(lp_ctx, NULL,
				"kdc", "renewal lifetime", 24 * 7);
	*renewal_lifetime = val * 60 * 60;
}
