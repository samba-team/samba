/*
 *  Unix SMB/CIFS implementation.
 *  Group Policy Object Support
 *  Copyright (C) Guenther Deschner 2005-2008 (from samba 3 gpo.h)
 *  Copyright (C) Wilco Baan Hofman 2010
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

#ifndef __GPO_H__
#define __GPO_H__


#define GPLINK_OPT_DISABLE		(1 << 0)
#define GPLINK_OPT_ENFORCE		(1 << 1)


#define GPO_FLAG_USER_DISABLE		(1 << 0)
#define GPO_FLAG_MACHINE_DISABLE	(1 << 1)

enum gpo_inheritance {
	GPO_INHERIT = 0,
	GPO_BLOCK_INHERITANCE = 1,
};

struct gp_context {
	struct ldb_context *ldb_ctx;
	struct loadparm_context *lp_ctx;
	struct cli_credentials *credentials;
	struct tevent_context *ev_ctx;
};

struct gp_object {
	uint32_t version;
	uint32_t flags;
	const char *display_name;
	const char *name;
	const char *dn;
	const char *file_sys_path;
	struct security_descriptor *security_descriptor;
};


struct gp_link {
	uint32_t options;
	const char *dn;
};

#if 0 /* Not used yet */
NTSTATUS gp_fetch_gpo(TALLOC_CTX *mem_ctx, struct ldb_context *ldb);
NTSTATUS gp_apply_gpo(TALLOC_CTX *mem_ctx, struct ldb_context *ldb);
NTSTATUS gp_check_refresh_gpo(TALLOC_CTX *mem_ctx, struct ldb_context *ldb);
#endif

NTSTATUS gp_init(TALLOC_CTX *mem_ctx,
				struct loadparm_context *lp_ctx,
				struct cli_credentials *creds,
				struct tevent_context *ev_ctx,
				struct gp_context **gp_ctx);
NTSTATUS gp_list_all_gpos(struct gp_context *gp_ctx, struct gp_object ***ret);
NTSTATUS gp_get_gplinks(struct gp_context *gp_ctx, const char *req_dn, struct gp_link ***ret);
NTSTATUS gp_list_gpos(struct gp_context *gp_ctx, struct security_token *token, const char ***ret);

NTSTATUS gp_get_gpo_info(struct gp_context *gp_ctx, const char *dn_str, struct gp_object **ret);
NTSTATUS gp_set_gpo_info(struct gp_context *gp_ctx, const char *dn_str, struct gp_object *gpo);
NTSTATUS gp_del_gpo(struct gp_context *gp_ctx, const char *dn_str);


NTSTATUS gp_get_gplink_options(TALLOC_CTX *mem_ctx, uint32_t flags, const char ***ret);
NTSTATUS gp_get_gpo_flags(TALLOC_CTX *mem_ctx, uint32_t flags, const char ***ret);

NTSTATUS gp_set_gplink(struct gp_context *gp_ctx, const char *dn_str, struct gp_link *gplink);
NTSTATUS gp_del_gplink(struct gp_context *gp_ctx, const char *dn_str, const char *gp_dn);

#endif
