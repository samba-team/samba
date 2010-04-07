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

struct gpo_stringmap {
	const char *str;
	uint32_t flags;
};
static const struct gpo_stringmap gplink_options [] = {
	{ "GPLINK_OPT_DISABLE", GPLINK_OPT_DISABLE },
	{ "GPLINK_OPT_ENFORCE", GPLINK_OPT_ENFORCE },
	{ NULL, 0 }
};
static const struct gpo_stringmap gpo_flags [] = {
	{ "GPO_FLAG_USER_DISABLE", GPO_FLAG_USER_DISABLE },
	{ "GPO_FLAG_MACHINE_DISABLE", GPO_FLAG_MACHINE_DISABLE },
	{ NULL, 0 }
};
static const struct gpo_stringmap gpo_inheritance [] = {
	{ "GPO_INHERIT", GPO_INHERIT },
	{ "GPO_BLOCK_INHERITANCE", GPO_BLOCK_INHERITANCE },
	{ NULL, 0 }
};

static NTSTATUS parse_gpo(TALLOC_CTX *mem_ctx, struct ldb_message *msg, struct gp_object **ret)
{
	unsigned int i;
	struct gp_object *gpo = talloc(mem_ctx, struct gp_object);
	gpo->dn = ldb_dn_get_linearized(msg->dn);

	DEBUG(9, ("Parsing GPO LDAP data for %s\n", gpo->dn));
	for (i = 0; i < msg->num_elements; i++) {
		struct ldb_message_element *element = &msg->elements[i];

		if (strcmp(element->name, "displayName") == 0) {
			SMB_ASSERT(element->num_values > 0);
			gpo->display_name = talloc_strdup(gpo, (char *)element->values[0].data);
			DEBUG(10, ("Found displayname: %s\n", gpo->display_name));
		}
		if (strcmp(element->name, "name") == 0) {
			SMB_ASSERT(element->num_values > 0);
			gpo->name = talloc_strdup(gpo, (char *)element->values[0].data);
			DEBUG(10, ("Found name: %s\n", gpo->name));
		}
		if (strcmp(element->name, "flags") == 0) {
			char *end;
			SMB_ASSERT(element->num_values > 0);
			gpo->flags = (uint32_t) strtoll((char *)element->values[0].data, &end, 0);
			SMB_ASSERT(*end == 0);
			DEBUG(10, ("Found flags: %d\n", gpo->flags));
		}
		if (strcmp(element->name, "versionNumber") == 0) {
			char *end;
			SMB_ASSERT(element->num_values > 0);
			gpo->version = (uint32_t) strtoll((char *)element->values[0].data, &end, 0);
			SMB_ASSERT(*end == 0);
			DEBUG(10, ("Found version: %d\n", gpo->version));
		}
		if (strcmp(element->name, "gPCFileSysPath") == 0) {
			SMB_ASSERT(element->num_values > 0);
			gpo->file_sys_path = talloc_strdup(gpo, (char *)element->values[0].data);
			DEBUG(10, ("Found file system path: %s\n", gpo->file_sys_path));
		}
	}

	*ret = gpo;
	return NT_STATUS_OK;
}

NTSTATUS gp_get_gpo_flags(TALLOC_CTX *mem_ctx, uint32_t flags, const char ***ret)
{
	unsigned int i, count=0;
	const char **flag_strs = talloc_array(mem_ctx, const char *, 1);

	flag_strs[0] = NULL;

	for (i = 0; gpo_flags[i].str != NULL; i++) {
		if (flags & gpo_flags[i].flags) {
			flag_strs = talloc_realloc(mem_ctx, flag_strs, const char *, count+2);
			flag_strs[count] = gpo_flags[i].str;
			flag_strs[count+1] = NULL;
			count++;
		}
	}
	*ret = flag_strs;
	return NT_STATUS_OK;
}

NTSTATUS gp_get_gplink_options(TALLOC_CTX *mem_ctx, uint32_t options, const char ***ret)
{
	unsigned int i, count=0;
	const char **flag_strs = talloc_array(mem_ctx, const char *, 1);

	flag_strs[0] = NULL;

	for (i = 0; gplink_options[i].str != NULL; i++) {
		if (options & gplink_options[i].flags) {
			flag_strs = talloc_realloc(mem_ctx, flag_strs, const char *, count+2);
			flag_strs[count] = gplink_options[i].str;
			flag_strs[count+1] = NULL;
			count++;
		}
	}
	*ret = flag_strs;
	return NT_STATUS_OK;
}

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

	/* We don't need to keep the libnet context */
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
	NTSTATUS status;
	TALLOC_CTX *mem_ctx;
	struct ldb_dn *dn;
	struct gp_object **gpo;
	unsigned int i; /* same as in struct ldb_result */

	/* Create a forked memory context, as a base for everything here */
	mem_ctx = talloc_new(gp_ctx);

	/* Create full ldb dn of the policies base object */
	dn = ldb_get_default_basedn(gp_ctx->ldb_ctx);
	rv = ldb_dn_add_child(dn, ldb_dn_new(mem_ctx, gp_ctx->ldb_ctx, "CN=Policies,CN=System"));
	if (!rv) {
		DEBUG(0, ("Can't append subtree to DN\n"));
		talloc_free(mem_ctx);
		return NT_STATUS_UNSUCCESSFUL;
	}

	DEBUG(10, ("Searching for policies in DN: %s\n", ldb_dn_get_linearized(dn)));

	rv = ldb_search(gp_ctx->ldb_ctx, mem_ctx, &result, dn, LDB_SCOPE_ONELEVEL, NULL, "(objectClass=groupPolicyContainer)");
	if (rv != LDB_SUCCESS) {
		DEBUG(0, ("LDB search failed: %s\n%s\n", ldb_strerror(rv),ldb_errstring(gp_ctx->ldb_ctx)));
		talloc_free(mem_ctx);
		return NT_STATUS_UNSUCCESSFUL;
	}

	gpo = talloc_array(gp_ctx, struct gp_object *, result->count+1);
	gpo[result->count] = NULL;

	for (i = 0; i < result->count; i++) {
		status = parse_gpo(gp_ctx, result->msgs[i], &gpo[i]);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("Failed to parse GPO.\n"));
			talloc_free(mem_ctx);
			return status;
		}
	}

	talloc_free(mem_ctx);

	*ret = gpo;
	return NT_STATUS_OK;
}

NTSTATUS gp_get_gpo_info(struct gp_context *gp_ctx, const char *name, struct gp_object **ret)
{
	struct ldb_result *result;
	struct ldb_dn *dn;
	struct gp_object *gpo;
	int rv;
	NTSTATUS status;
	TALLOC_CTX *mem_ctx;

	/* Create a forked memory context, as a base for everything here */
	mem_ctx = talloc_new(gp_ctx);

	/* Create full ldb dn of the policies base object */
	dn = ldb_get_default_basedn(gp_ctx->ldb_ctx);
	rv = ldb_dn_add_child(dn, ldb_dn_new(mem_ctx, gp_ctx->ldb_ctx, "CN=Policies,CN=System"));
	if (!rv) {
		DEBUG(0, ("Can't append subtree to DN\n"));
		talloc_free(mem_ctx);
		return NT_STATUS_UNSUCCESSFUL;
	}

	rv = ldb_search(gp_ctx->ldb_ctx,
	                mem_ctx,
	                &result,
	                dn,
	                LDB_SCOPE_ONELEVEL,
	                NULL,
	                "(&(objectClass=groupPolicyContainer)(name=%s))",
	                name);
	if (rv != LDB_SUCCESS) {
		DEBUG(0, ("LDB search failed: %s\n%s\n", ldb_strerror(rv),ldb_errstring(gp_ctx->ldb_ctx)));
		talloc_free(mem_ctx);
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* We expect exactly one record */
	if (result->count != 1) {
		DEBUG(0, ("Could not find GPC with name %s\n", name));
		talloc_free(mem_ctx);
		return NT_STATUS_NOT_FOUND;
	}

	status = parse_gpo(gp_ctx, result->msgs[0], &gpo);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to parse GPO.\n"));
		talloc_free(mem_ctx);
		return status;
	}

	talloc_free(mem_ctx);

	*ret = gpo;
	return NT_STATUS_OK;
}

static NTSTATUS parse_gplink (TALLOC_CTX *mem_ctx, const char *gplink_str, struct gp_link ***ret)
{
	int start, idx=0;
	int pos;
	struct gp_link **gplinks;
	char *buf, *end;

	gplinks = talloc_array(mem_ctx, struct gp_link *, 1);

	/* Assuming every gPLink starts with "[LDAP://" */
	start = 8;

	for (pos = start; pos < strlen(gplink_str); pos++) {
		if (gplink_str[pos] == ';') {
			gplinks = talloc_realloc(mem_ctx, gplinks, struct gp_link *, idx+2);
			gplinks[idx] = talloc(mem_ctx, struct gp_link);
			gplinks[idx]->dn = talloc_strndup(mem_ctx,
			                                gplink_str + start,
			                                pos - start);

			for (start = pos + 1; gplink_str[pos] != ']'; pos++);

			buf = talloc_strndup(mem_ctx, gplink_str + start, pos - start);

			gplinks[idx]->options = (uint32_t) strtoll(buf, &end, 0);

			/* Set the last entry in the array to be NULL */
			gplinks[idx + 1] = NULL;

			/* Increment the array index, the string position, and the start reference */
			idx++;
			pos += 9;
			start = pos;
		}
	}

	*ret = gplinks;
	return NT_STATUS_OK;
}


NTSTATUS gp_get_gplinks(struct gp_context *gp_ctx, const char *req_dn, struct gp_link ***ret)
{
	TALLOC_CTX *mem_ctx;
	struct ldb_dn *dn;
	struct ldb_result *result;
	struct gp_link **gplinks;
	char *gplink_str;
	int rv;
	unsigned int i, j;
	NTSTATUS status;

	/* Create a forked memory context, as a base for everything here */
	mem_ctx = talloc_new(gp_ctx);

	dn = ldb_dn_new(mem_ctx, gp_ctx->ldb_ctx, req_dn);

	rv = ldb_search(gp_ctx->ldb_ctx, mem_ctx, &result, dn, LDB_SCOPE_BASE, NULL, "(objectclass=*)");
	if (rv != LDB_SUCCESS) {
		DEBUG(0, ("LDB search failed: %s\n%s\n", ldb_strerror(rv),ldb_errstring(gp_ctx->ldb_ctx)));
		talloc_free(mem_ctx);
		return NT_STATUS_UNSUCCESSFUL;
	}

	for (i = 0; i < result->count; i++) {
		for (j = 0; j < result->msgs[i]->num_elements; j++) {
			struct ldb_message_element *element = &result->msgs[i]->elements[j];

			if (strcmp(element->name, "gPLink") == 0) {
				SMB_ASSERT(element->num_values > 0);
				gplink_str = talloc_strdup(mem_ctx, (char *) element->values[0].data);
				goto found;
			}
		}
	}
	DEBUG(0, ("Object or gPLink attribute not found.\n"));
	return NT_STATUS_NOT_FOUND;

	found:

	status = parse_gplink(gp_ctx, gplink_str, &gplinks);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to parse gPLinks\n"));
		return status;
	}

	*ret = gplinks;
	return NT_STATUS_OK;
}
