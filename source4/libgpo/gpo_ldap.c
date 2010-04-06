/*
 *  Unix SMB/CIFS implementation.
 *  Group Policy Object Support
 *  Copyright (C) Jelmer Vernooij 2008
 *  Copyright (C) Wilco Baan Hofman 2008-2010
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
#include "param/param.h"
#include "lib/ldb/include/ldb.h"
#include "lib/ldb_wrap.h"
#include "auth/credentials/credentials.h"
#include "../librpc/gen_ndr/nbt.h"
#include "libcli/libcli.h"
#include "libnet/libnet.h"
#include "gpo.h"

NTSTATUS gp_init(TALLOC_CTX *mem_ctx,
				struct loadparm_context *lp_ctx,
				struct cli_credentials *credentials,
				struct tevent_context *ev_ctx,
				struct gp_context **gp_ctx)
{

        struct libnet_LookupDCs *io;
        char *url;
	struct libnet_context *net_ctx;
	struct ldb_context *ldb_ctx;
	NTSTATUS rv;

	/* Initialise the libnet context */
	net_ctx = libnet_context_init(ev_ctx, lp_ctx);
	net_ctx->cred = credentials;

        /* Prepare libnet lookup structure for looking a DC (PDC is correct). */
        io = talloc_zero(mem_ctx, struct libnet_LookupDCs);
        io->in.name_type = NBT_NAME_PDC;
        io->in.domain_name = lp_workgroup(lp_ctx);

	/* Find Active DC's */
        rv = libnet_LookupDCs(net_ctx, mem_ctx, io);
	if (!NT_STATUS_IS_OK(rv)) {
		DEBUG(0, ("Failed to lookup DCs in domain\n"));
		return rv;
	}

	/* Connect to ldap://DC_NAME with all relevant contexts*/
        url = talloc_asprintf(mem_ctx, "ldap://%s", io->out.dcs[0].name);
	ldb_ctx = ldb_wrap_connect(mem_ctx, net_ctx->event_ctx, lp_ctx,
                         url, NULL, net_ctx->cred, 0);
        if (ldb_ctx == NULL) {
                return NT_STATUS_UNSUCCESSFUL;
        }

	talloc_free(net_ctx);

	*gp_ctx = talloc_zero(mem_ctx, struct gp_context);
	(*gp_ctx)->lp_ctx = lp_ctx;
	(*gp_ctx)->credentials = credentials;
	(*gp_ctx)->ev_ctx = ev_ctx;
	(*gp_ctx)->ldb_ctx = ldb_ctx;
        return NT_STATUS_OK;

}

NTSTATUS gp_list_all_gpos(struct gp_context *gp_ctx, struct gp_object ***ret)
{
	struct ldb_result *result;
	int rv;
	TALLOC_CTX *mem_ctx;
	struct ldb_dn *dn;
	struct gp_object **gpo;
	unsigned int i, j; /* same as in struct ldb_result */

	/* Create a forked memory context, as a base for everything here */
	mem_ctx = talloc_new(gp_ctx);
	dn = ldb_get_default_basedn(gp_ctx->ldb_ctx);
	rv = ldb_dn_add_child(dn, ldb_dn_new(mem_ctx, gp_ctx->ldb_ctx, "CN=Policies,CN=System"));
	if (!rv) {
		DEBUG(0, ("Can't append subtree to DN\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	DEBUG(10, ("Searching for policies in DN: %s\n", ldb_dn_get_linearized(dn)));

	rv = ldb_search(gp_ctx->ldb_ctx, mem_ctx, &result, dn, LDB_SCOPE_ONELEVEL, NULL, "(objectClass=groupPolicyContainer)");
	if (rv != LDB_SUCCESS) {
		DEBUG(0, ("LDB search failed: %s\n%s\n", ldb_strerror(rv),ldb_errstring(gp_ctx->ldb_ctx)));
		return NT_STATUS_UNSUCCESSFUL;
	}

	gpo = talloc_array(gp_ctx, struct gp_object *, result->count+1);
	gpo[result->count] = NULL;

	for (i = 0; i < result->count; i++) {
		gpo[i] = talloc(gp_ctx, struct gp_object);

		gpo[i]->dn = ldb_dn_get_linearized(result->msgs[i]->dn);

		DEBUG(9, ("Parsing GPO LDAP data for %s\n", gpo[i]->dn));
		for (j = 0; j < result->msgs[i]->num_elements; j++) {
			struct ldb_message_element *element = &result->msgs[i]->elements[j];

			if (strcmp(element->name, "displayName") == 0) {
				SMB_ASSERT(element->num_values > 0);
				gpo[i]->display_name = talloc_strdup(gp_ctx, (char *)element->values[0].data);
				DEBUG(10, ("Found displayname: %s\n", gpo[i]->display_name));
			}
			if (strcmp(element->name, "name") == 0) {
				SMB_ASSERT(element->num_values > 0);
				gpo[i]->name = talloc_strdup(gp_ctx, (char *)element->values[0].data);
				DEBUG(10, ("Found name: %s\n", gpo[i]->name));
			}
			if (strcmp(element->name, "flags") == 0) {
				char *end;
				SMB_ASSERT(element->num_values > 0);
				gpo[i]->flags = (uint32_t) strtoll((char *)element->values[0].data, &end, 0);
				SMB_ASSERT(*end == 0);
				DEBUG(10, ("Found flags: %d\n", gpo[i]->flags));
			}
			if (strcmp(element->name, "versionNumber") == 0) {
				char *end;
				SMB_ASSERT(element->num_values > 0);
				gpo[i]->version = (uint32_t) strtoll((char *)element->values[0].data, &end, 0);
				SMB_ASSERT(*end == 0);
				DEBUG(10, ("Found version: %d\n", gpo[i]->version));
			}
			if (strcmp(element->name, "gPCFileSysPath") == 0) {
				SMB_ASSERT(element->num_values > 0);
				gpo[i]->file_sys_path = talloc_strdup(gp_ctx, (char *)element->values[0].data);
				DEBUG(10, ("Found file system path: %s\n", gpo[i]->file_sys_path));
			}
		}
	}
	*ret = gpo;
	talloc_free(mem_ctx);
	return NT_STATUS_OK;
}
