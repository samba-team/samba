/* 
   Unix SMB/CIFS implementation.
   
   Classic file based shares configuration
   
   Copyright (C) Simo Sorce	2006
   
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
#include "param/share.h"
#include "param/param.h"

NTSTATUS share_classic_init(void);

static NTSTATUS sclassic_init(TALLOC_CTX *mem_ctx, 
			      const struct share_ops *ops, 
			      struct tevent_context *event_ctx,
			      struct loadparm_context *lp_ctx,
			      struct share_context **ctx)
{
	*ctx = talloc(mem_ctx, struct share_context);
	if (!*ctx) {
		DEBUG(0, ("ERROR: Out of memory!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	(*ctx)->ops = ops;
	(*ctx)->priv_data = lp_ctx;

	return NT_STATUS_OK;
}

static char *sclassic_string_option(TALLOC_CTX *mem_ctx,
				    struct share_config *scfg,
				    const char *opt_name,
				    const char *defval)
{
	struct loadparm_service *s = talloc_get_type(scfg->opaque, 
						     struct loadparm_service);
	struct loadparm_context *lp_ctx = talloc_get_type(scfg->ctx->priv_data,
							  struct loadparm_context);
	char *parm, *val;
	const char *ret;

	if (strchr(opt_name, ':')) {
		parm = talloc_strdup(scfg, opt_name);
		if (!parm) {
			return NULL;
		}
		val = strchr(parm, ':');
		*val = '\0';
		val++;

		ret = lpcfg_parm_string(lp_ctx, s, parm, val);
		if (!ret) {
			ret = defval;
		}
		talloc_free(parm);
		return talloc_strdup(mem_ctx, ret);
	}

	if (strcmp(opt_name, SHARE_NAME) == 0) {
		return talloc_strdup(mem_ctx, scfg->name);
	}

	if (strcmp(opt_name, SHARE_PATH) == 0) {
		return lpcfg_path(s, lpcfg_default_service(lp_ctx), mem_ctx);
	}

	if (strcmp(opt_name, SHARE_COMMENT) == 0) {
		return lpcfg_comment(s, lpcfg_default_service(lp_ctx), mem_ctx);
	}

	if (strcmp(opt_name, SHARE_VOLUME) == 0) {
		return talloc_strdup(mem_ctx, lpcfg_volume_label(s, lpcfg_default_service(lp_ctx)));
	}

	if (strcmp(opt_name, SHARE_TYPE) == 0) {
		if (lpcfg_printable(s, lpcfg_default_service(lp_ctx))) {
			return talloc_strdup(mem_ctx, "PRINTER");
		}
		if (strcmp("NTFS", lpcfg_fstype(s, lpcfg_default_service(lp_ctx))) == 0) {
			return talloc_strdup(mem_ctx, "DISK");
		}
		return talloc_strdup(mem_ctx, lpcfg_fstype(s, lpcfg_default_service(lp_ctx)));
	}

	if (strcmp(opt_name, SHARE_PASSWORD) == 0) {
		return talloc_strdup(mem_ctx, defval);
	}

	DEBUG(0,("request for unknown share string option '%s'\n",
		 opt_name));

	return talloc_strdup(mem_ctx, defval);
}

static int sclassic_int_option(struct share_config *scfg, const char *opt_name, int defval)
{
	struct loadparm_service *s = talloc_get_type(scfg->opaque, 
						     struct loadparm_service);
	struct loadparm_context *lp_ctx = talloc_get_type(scfg->ctx->priv_data,
							  struct loadparm_context);
	char *parm, *val;
	int ret;

	if (strchr(opt_name, ':')) {
		parm = talloc_strdup(scfg, opt_name);
		if (!parm) {
			return -1;
		}
		val = strchr(parm, ':');
		*val = '\0';
		val++;

		ret = lpcfg_parm_int(lp_ctx, s, parm, val, defval);
		if (!ret) {
			ret = defval;
		}
		talloc_free(parm);
		return ret;
	}

	if (strcmp(opt_name, SHARE_CSC_POLICY) == 0) {
		return lpcfg_csc_policy(s, lpcfg_default_service(lp_ctx));
	}

	if (strcmp(opt_name, SHARE_MAX_CONNECTIONS) == 0) {
		return lpcfg_max_connections(s, lpcfg_default_service(lp_ctx));
	}

	if (strcmp(opt_name, SHARE_CREATE_MASK) == 0) {
		return lpcfg_create_mask(s, lpcfg_default_service(lp_ctx));
	}

	if (strcmp(opt_name, SHARE_DIR_MASK) == 0) {
		return lpcfg_directory_mask(s, lpcfg_default_service(lp_ctx));
	}

	if (strcmp(opt_name, SHARE_FORCE_DIR_MODE) == 0) {
		return lpcfg_force_directory_mode(s, lpcfg_default_service(lp_ctx));
	}

	if (strcmp(opt_name, SHARE_FORCE_CREATE_MODE) == 0) {
		return lpcfg_force_create_mode(s, lpcfg_default_service(lp_ctx));
	}


	DEBUG(0,("request for unknown share int option '%s'\n",
		 opt_name));

	return defval;
}

static bool sclassic_bool_option(struct share_config *scfg, const char *opt_name, 
			  bool defval)
{
	struct loadparm_service *s = talloc_get_type(scfg->opaque, 
						     struct loadparm_service);
	struct loadparm_context *lp_ctx = talloc_get_type(scfg->ctx->priv_data,
							  struct loadparm_context);
	char *parm, *val;
	bool ret;

	if (strchr(opt_name, ':')) {
		parm = talloc_strdup(scfg, opt_name);
		if(!parm) {
			return false;
		}
		val = strchr(parm, ':');
		*val = '\0';
		val++;

		ret = lpcfg_parm_bool(lp_ctx, s, parm, val, defval);
		talloc_free(parm);
		return ret;
	}

	if (strcmp(opt_name, SHARE_AVAILABLE) == 0) {
		return s != NULL;
	}

	if (strcmp(opt_name, SHARE_BROWSEABLE) == 0) {
		return lpcfg_browseable(s, lpcfg_default_service(lp_ctx));
	}

	if (strcmp(opt_name, SHARE_READONLY) == 0) {
		return lpcfg_read_only(s, lpcfg_default_service(lp_ctx));
	}

	if (strcmp(opt_name, SHARE_MAP_SYSTEM) == 0) {
		return lpcfg_map_system(s, lpcfg_default_service(lp_ctx));
	}

	if (strcmp(opt_name, SHARE_MAP_HIDDEN) == 0) {
		return lpcfg_map_hidden(s, lpcfg_default_service(lp_ctx));
	}

	if (strcmp(opt_name, SHARE_MAP_ARCHIVE) == 0) {
		return lpcfg_map_archive(s, lpcfg_default_service(lp_ctx));
	}

	if (strcmp(opt_name, SHARE_STRICT_LOCKING) == 0) {
		return lpcfg_strict_locking(s, lpcfg_default_service(lp_ctx));
	}

	if (strcmp(opt_name, SHARE_OPLOCKS) == 0) {
		return lpcfg_oplocks(s, lpcfg_default_service(lp_ctx));
	}

	if (strcmp(opt_name, SHARE_STRICT_SYNC) == 0) {
		return lpcfg_strict_sync(s, lpcfg_default_service(lp_ctx));
	}

	if (strcmp(opt_name, SHARE_MSDFS_ROOT) == 0) {
		return lpcfg_msdfs_root(s, lpcfg_default_service(lp_ctx));
	}

	if (strcmp(opt_name, SHARE_CI_FILESYSTEM) == 0) {
		int case_sensitive = lpcfg_case_sensitive(s, lpcfg_default_service(lp_ctx));
		/*
		 * Yes, this confusingly named option means Samba acts
		 * case sensitive, so that the filesystem can act case
		 * insensitive.
		 *
		 */
		if (case_sensitive == Auto) {
			/* Auto is for unix extensions and unix
			 * clients, which we don't support here.
			 * Samba needs to do the case changing,
			 * because the filesystem is case
			 * sensitive  */
			return false;
		} else if (case_sensitive) {
			/* True means that Samba won't do anything to
			 * change the case of incoming requests.
			 * Essentially this means we trust the file
			 * system to be case insensitive */
			return true;
		} else {
			/* False means that Smaba needs to do the case
			 * changing, because the filesystem is case
			 * sensitive */
			return false;
		}
	}

	DEBUG(0,("request for unknown share bool option '%s'\n",
		 opt_name));

	return defval;
}

static const char **sclassic_string_list_option(TALLOC_CTX *mem_ctx, struct share_config *scfg, const char *opt_name)
{
	struct loadparm_service *s = talloc_get_type(scfg->opaque, 
						     struct loadparm_service);
	struct loadparm_context *lp_ctx = talloc_get_type(scfg->ctx->priv_data,
							  struct loadparm_context);
	char *parm, *val;
	const char **ret;

	if (strchr(opt_name, ':')) {
		parm = talloc_strdup(scfg, opt_name);
		if (!parm) {
			return NULL;
		}
		val = strchr(parm, ':');
		*val = '\0';
		val++;

		ret = lpcfg_parm_string_list(mem_ctx, lp_ctx, s, parm, val, ",;");
		talloc_free(parm);
		return ret;
	}

	if (strcmp(opt_name, SHARE_HOSTS_ALLOW) == 0) {
		return lpcfg_hosts_allow(s, lpcfg_default_service(lp_ctx));
	}

	if (strcmp(opt_name, SHARE_HOSTS_DENY) == 0) {
		return lpcfg_hosts_deny(s, lpcfg_default_service(lp_ctx));
	}

	if (strcmp(opt_name, SHARE_NTVFS_HANDLER) == 0) {
		return lpcfg_ntvfs_handler(s, lpcfg_default_service(lp_ctx));
	}

	DEBUG(0,("request for unknown share list option '%s'\n",
		 opt_name));

	return NULL;
}

static NTSTATUS sclassic_list_all(TALLOC_CTX *mem_ctx,
				  struct share_context *ctx,
				  int *count,
				  const char ***names)
{
	int i;
	int num_services;
	const char **n;
       
	num_services = lpcfg_numservices((struct loadparm_context *)ctx->priv_data);

	n = talloc_array(mem_ctx, const char *, num_services);
	if (!n) {
		DEBUG(0,("ERROR: Out of memory!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	for (i = 0; i < num_services; i++) {
		n[i] = talloc_strdup(n, lpcfg_servicename(lpcfg_servicebynum((struct loadparm_context *)ctx->priv_data, i)));
		if (!n[i]) {
			DEBUG(0,("ERROR: Out of memory!\n"));
			talloc_free(n);
			return NT_STATUS_NO_MEMORY;
		}
	}

	*names = n;
	*count = num_services;

	return NT_STATUS_OK;
}

static NTSTATUS sclassic_get_config(TALLOC_CTX *mem_ctx,
				    struct share_context *ctx,
				    const char *name,
				    struct share_config **scfg)
{
	struct share_config *s;
	struct loadparm_service *service;

	service = lpcfg_service((struct loadparm_context *)ctx->priv_data, name);

	if (service == NULL) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	s = talloc(mem_ctx, struct share_config);
	if (!s) {
		DEBUG(0,("ERROR: Out of memory!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	s->name = talloc_strdup(s, lpcfg_servicename(service));
	if (!s->name) {
		DEBUG(0,("ERROR: Out of memory!\n"));
		talloc_free(s);
		return NT_STATUS_NO_MEMORY;
	}

	s->opaque = (void *)service;
	s->ctx = ctx;
	
	*scfg = s;

	return NT_STATUS_OK;
}

static const struct share_ops ops = {
	.name = "classic",
	.init = sclassic_init,
	.string_option = sclassic_string_option,
	.int_option = sclassic_int_option,
	.bool_option = sclassic_bool_option,
	.string_list_option = sclassic_string_list_option,
	.list_all = sclassic_list_all,
	.get_config = sclassic_get_config
};

NTSTATUS share_classic_init(void)
{
	return share_register(&ops);
}

