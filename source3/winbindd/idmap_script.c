/*
   Unix SMB/CIFS implementation.

   idmap script backend, used for Samba setups where you need to map SIDs to
   specific UIDs/GIDs.

   Copyright (C) Richard Sharpe 2014.

   This is heavily based upon idmap_tdb2.c, which is:

   Copyright (C) Tim Potter 2000
   Copyright (C) Jim McDonough <jmcd@us.ibm.com> 2003
   Copyright (C) Jeremy Allison 2006
   Copyright (C) Simo Sorce 2003-2006
   Copyright (C) Michael Adam 2009-2010

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

#include "includes.h"
#include "system/filesys.h"
#include "winbindd.h"
#include "idmap.h"
#include "idmap_rw.h"
#include "../libcli/security/dom_sid.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_IDMAP

struct idmap_script_context {
	const char *script; /* script to provide idmaps */
};

/*
  run a script to perform a mapping

  The script should accept the following command lines:

      SIDTOID S-1-xxxx -> XID:<id> | ERR:<str>
      SIDTOID S-1-xxxx -> UID:<id> | ERR:<str>
      SIDTOID S-1-xxxx -> GID:<id> | ERR:<str>
      IDTOSID XID xxxx -> SID:<sid> | ERR:<str>
      IDTOSID UID xxxx -> SID:<sid> | ERR:<str>
      IDTOSID GID xxxx -> SID:<sid> | ERR:<str>

  where XID means both a UID and a GID. This is the case for ID_TYPE_BOTH.

  TODO: Needs more validation ... like that we got a UID when we asked for one.
 */
static NTSTATUS idmap_script_script(struct idmap_script_context *ctx,
				    struct id_map *map, const char *fmt, ...)
{
	va_list ap;
	char *cmd, **lines;
	int numlines = 0;
	unsigned long v;

	cmd = talloc_asprintf(ctx, "%s ", ctx->script);
	if (!cmd) {
		DEBUG(10, ("Unable to allocate memory for the script command!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	va_start(ap, fmt);
	cmd = talloc_vasprintf_append(cmd, fmt, ap);
	va_end(ap);
	if (!cmd) {
		DEBUG(10, ("Unable to allocate memory for the script command!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	lines = file_lines_pload(cmd, &numlines);
	talloc_free(cmd);
	if (!lines) {
		return NT_STATUS_NONE_MAPPED;
	}

	DEBUG(10,("idmap script gave %d lines, first: %s\n", numlines,
		lines[0]));

	if (sscanf(lines[0], "XID:%lu", &v) == 1) {
		map->xid.id   = v;
		map->xid.type = ID_TYPE_BOTH;
	} else if (sscanf(lines[0], "UID:%lu", &v) == 1) {
		map->xid.id   = v;
		map->xid.type = ID_TYPE_UID;
	} else if (sscanf(lines[0], "GID:%lu", &v) == 1) {
		map->xid.id   = v;
		map->xid.type = ID_TYPE_GID;
	} else if (strncmp(lines[0], "SID:S-", 6) == 0) {
		if (!string_to_sid(map->sid, &lines[0][4])) {
			DEBUG(0,("Bad SID in '%s' from idmap script %s\n",
				 lines[0], ctx->script));
			talloc_free(lines);
			return NT_STATUS_NONE_MAPPED;
		}
	} else {
		DEBUG(0,("Bad reply '%s' from idmap script %s\n",
			 lines[0], ctx->script));
		talloc_free(lines);
		return NT_STATUS_NONE_MAPPED;
	}

	talloc_free(lines);
	return NT_STATUS_OK;
}

/*
  Single id to sid lookup function.
*/
static NTSTATUS idmap_script_id_to_sid(struct idmap_domain *dom,
				       struct id_map *map)
{
	NTSTATUS ret;
	char *keystr;
	char *sidstr;
	struct idmap_script_context *ctx = dom->private_data;

	if (!dom || !map) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* apply filters before checking */
	if (!idmap_unix_id_is_in_range(map->xid.id, dom)) {
		DEBUG(5, ("Requested id (%u) out of range (%u - %u). Filtered!\n",
				map->xid.id, dom->low_id, dom->high_id));
		return NT_STATUS_NONE_MAPPED;
	}

	switch (map->xid.type) {

	case ID_TYPE_UID:
		keystr = talloc_asprintf(ctx, "UID %lu", (unsigned long)map->xid.id);
		break;

	case ID_TYPE_GID:
		keystr = talloc_asprintf(ctx, "GID %lu", (unsigned long)map->xid.id);
		break;

	case ID_TYPE_BOTH:
		keystr = talloc_asprintf(ctx, "XID %lu", (unsigned long)map->xid.id);
		break;

	default:
		DEBUG(2, ("INVALID unix ID type: 0x02%x\n", map->xid.type));
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (keystr == NULL) {
		DEBUG(0, ("Out of memory!\n"));
		ret = NT_STATUS_NO_MEMORY;
		goto done;
	}

	DEBUG(10,("Running script to fetch mapping %s\n", keystr));

	ret = idmap_script_script(ctx, map, "IDTOSID %s", keystr);
	if (!NT_STATUS_IS_OK(ret)) {
		goto done;
	}

	sidstr = sid_string_talloc(keystr, map->sid);
	if (!sidstr) {
		ret = NT_STATUS_NO_MEMORY;
		goto done;
	}

	DEBUG(10,("Found id %s:%d -> %s\n", keystr, map->xid.id,
		  (const char *)sidstr));
	ret = NT_STATUS_OK;

done:
	talloc_free(keystr);
	return ret;
}

/*
 Single sid to id lookup function.
*/
static NTSTATUS idmap_script_sid_to_id(struct idmap_domain *dom,
				       struct id_map *map)
{
	NTSTATUS ret;
	char *keystr;
	struct idmap_script_context *ctx = dom->private_data;
	TALLOC_CTX *tmp_ctx = talloc_stackframe();

	keystr = sid_string_talloc(tmp_ctx, map->sid);
	if (keystr == NULL) {
		DEBUG(0, ("Out of memory!\n"));
		ret = NT_STATUS_NO_MEMORY;
		goto done;
	}

	DEBUG(10,("Fetching record %s\n", keystr));

	if (ctx->script == NULL) {
		ret = NT_STATUS_NONE_MAPPED;
		goto done;
	}

	ret = idmap_script_script(ctx, map, "SIDTOID %s", keystr);
	if (!NT_STATUS_IS_OK(ret)) {
		goto done;
	}

	/* apply filters before returning result */
	if (!idmap_unix_id_is_in_range(map->xid.id, dom)) {
		DEBUG(5, ("Script returned id (%u) out of range (%u - %u)."
			  " Filtered!\n",
			  map->xid.id, dom->low_id, dom->high_id));
		ret = NT_STATUS_NONE_MAPPED;
		goto done;
	}

done:
	talloc_free(tmp_ctx);
	return ret;
}

static NTSTATUS idmap_script_unixids_to_sids(struct idmap_domain *dom,
				      struct id_map **ids)
{
	NTSTATUS ret;
	int i, num_mapped = 0;

	DEBUG(10, ("%s called ...\n", __func__));
	/* Init status to avoid surprise ... */
	for (i = 0; ids[i]; i++) {
		ids[i]->status = ID_UNKNOWN;
	}

	for (i = 0; ids[i]; i++) {
		ret = idmap_script_id_to_sid(dom, ids[i]);
		if (!NT_STATUS_IS_OK(ret)) {
			if (NT_STATUS_EQUAL(ret, NT_STATUS_NONE_MAPPED)) {
				ids[i]->status = ID_UNMAPPED;
				continue;
			}

			/*
			 * We cannot keep going if it is other than mapping
			 * failed.
			 */
			goto done;
		}

		ids[i]->status = ID_MAPPED;
		num_mapped++;
	}

	ret = NT_STATUS_OK;

done:
	if (NT_STATUS_IS_OK(ret)) {
		if (i == 0 || num_mapped == 0) {
			ret = NT_STATUS_NONE_MAPPED;
		}
		else if (num_mapped < i) {
			ret = STATUS_SOME_UNMAPPED;
		} else {
			DEBUG(10, ("Returning NT_STATUS_OK\n"));
			ret = NT_STATUS_OK;
		}
	}

	return ret;
}

static NTSTATUS idmap_script_sids_to_unixids(struct idmap_domain *dom,
				      struct id_map **ids)
{
	NTSTATUS ret;
	int i, num_mapped = 0;

	DEBUG(10, ("%s called ...\n", __func__));
	/* Init status to avoid surprise ... */
	for (i = 0; ids[i]; i++) {
		ids[i]->status = ID_UNKNOWN;
	}

	for (i = 0; ids[i]; i++) {
		ret = idmap_script_sid_to_id(dom, ids[i]);
		if (!NT_STATUS_IS_OK(ret)) {
			if (NT_STATUS_EQUAL(ret, NT_STATUS_NONE_MAPPED)) {
				ids[i]->status = ID_UNMAPPED;
				continue;
			}

			/*
			 * We cannot keep going if it is other than mapping
			 * failed.
			 */
			goto done;
		}

		ids[i]->status = ID_MAPPED;
		num_mapped++;
	}

	ret = NT_STATUS_OK;

done:
	if (NT_STATUS_IS_OK(ret)) {
		if (i == 0 || num_mapped == 0) {
			ret = NT_STATUS_NONE_MAPPED;
		}
		else if (num_mapped < i) {
			ret = STATUS_SOME_UNMAPPED;
		} else {
			DEBUG(10, ("Returning NT_STATUS_OK\n"));
			ret = NT_STATUS_OK;
		}
	}

	return ret;
}

/*
 *   Initialise idmap_script database.
 */
static NTSTATUS idmap_script_db_init(struct idmap_domain *dom)
{
	NTSTATUS ret;
	struct idmap_script_context *ctx;
	char *config_option = NULL;
	const char * idmap_script = NULL;

	DEBUG(10, ("%s called ...\n", __func__));

	ctx = talloc_zero(dom, struct idmap_script_context);
	if (!ctx) {
		DEBUG(0, ("Out of memory!\n"));
		ret = NT_STATUS_NO_MEMORY;
		goto failed;
	}

	config_option = talloc_asprintf(ctx, "idmap config %s", dom->name);
	if (config_option == NULL) {
		DEBUG(0, ("Out of memory!\n"));
		ret = NT_STATUS_NO_MEMORY;
		goto failed;
	}
	ctx->script = lp_parm_const_string(-1, config_option, "script", NULL);
	talloc_free(config_option);

	/* Do we even need to handle this? */
	idmap_script = lp_parm_const_string(-1, "idmap", "script", NULL);
	if (idmap_script != NULL) {
		DEBUG(0, ("Warning: 'idmap:script' is deprecated. "
			  " Please use 'idmap config * : script' instead!\n"));
	}

	if (strequal(dom->name, "*") && ctx->script == NULL) {
		/* fall back to idmap:script for backwards compatibility */
		ctx->script = idmap_script;
	}

	if (ctx->script) {
		DEBUG(1, ("using idmap script '%s'\n", ctx->script));
	}

	dom->private_data = ctx;
	dom->read_only = true; /* We do not allocate!*/

	return NT_STATUS_OK;

failed:
	talloc_free(ctx);
	return ret;
}

static struct idmap_methods db_methods = {
	.init            = idmap_script_db_init,
	.unixids_to_sids = idmap_script_unixids_to_sids,
	.sids_to_unixids = idmap_script_sids_to_unixids,
};

static_decl_idmap;
NTSTATUS idmap_script_init(void)
{
	return smb_register_idmap(SMB_IDMAP_INTERFACE_VERSION, "script", &db_methods);
}
