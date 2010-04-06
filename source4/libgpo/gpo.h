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


/* GPO_OPTIONS */
#define GPO_FLAG_DISABLE        0x00000001
#define GPO_FLAG_FORCE          0x00000002

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

NTSTATUS gp_fetch_gpo(TALLOC_CTX *mem_ctx, struct ldb_context *ldb);
NTSTATUS gp_apply_gpo(TALLOC_CTX *mem_ctx, struct ldb_context *ldb);
NTSTATUS gp_check_refresh_gpo(TALLOC_CTX *mem_ctx, struct ldb_context *ldb);

NTSTATUS gp_init(TALLOC_CTX *mem_ctx,
				struct loadparm_context *lp_ctx,
				struct cli_credentials *creds,
				struct tevent_context *ev_ctx,
				struct gp_context **gp_ctx);
NTSTATUS gp_list_all_gpos(struct gp_context *gp_ctx, struct gp_object ***ret);
#endif
