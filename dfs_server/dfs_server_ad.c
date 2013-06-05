/*
   Unix SMB/CIFS implementation.

   Copyright Matthieu Patou <mat@matws.net> 2010-2011
   Copyright Stefan Metzmacher 2011

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
#include "librpc/gen_ndr/dfsblobs.h"
#include "librpc/gen_ndr/ndr_dfsblobs.h"
#include "dsdb/samdb/samdb.h"
#include "auth/session.h"
#include "param/param.h"
#include "lib/tsocket/tsocket.h"
#include "dfs_server/dfs_server_ad.h"
#include "lib/util/util_net.h"

#define MAX_DFS_RESPONSE 56*1024 /* 56 Kb */

/* A DC set is a group of DC, they might have been grouped together
   because they belong to the same site, or to site with same cost ...
*/
struct dc_set {
	const char **names;
	uint32_t count;
};

/*
  fill a referral type structure
 */
static NTSTATUS fill_normal_dfs_referraltype(TALLOC_CTX *mem_ctx,
					     struct dfs_referral_type *ref,
					     uint16_t version,
					     const char *dfs_path,
					     const char *server_path, int isfirstoffset)
{
	ZERO_STRUCTP(ref);
	switch (version) {
	case 4:
		ref->version = version;
		/* For the moment there is a bug with XP that don't seems to appriciate much
		 * level4 so we return just level 3 for everyone
		 */
		ref->referral.v4.server_type = DFS_SERVER_NON_ROOT;
		/* "normal" referral seems to always include the GUID */
		ref->referral.v4.size = 34;

		if (isfirstoffset) {
			ref->referral.v4.entry_flags =  DFS_HEADER_FLAG_TARGET_BCK;
		}
		ref->referral.v4.ttl = 900; /* As w2k8r2 */
		ref->referral.v4.referrals.r1.DFS_path = talloc_strdup(mem_ctx, dfs_path);
		if (ref->referral.v4.referrals.r1.DFS_path == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		ref->referral.v4.referrals.r1.DFS_alt_path = talloc_strdup(mem_ctx, dfs_path);
		if (ref->referral.v4.referrals.r1.DFS_alt_path == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		ref->referral.v4.referrals.r1.netw_address = talloc_strdup(mem_ctx, server_path);
		if (ref->referral.v4.referrals.r1.netw_address == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		return NT_STATUS_OK;
	case 3:
		ref->version = version;
		ref->referral.v3.server_type = DFS_SERVER_NON_ROOT;
		/* "normal" referral seems to always include the GUID */
		ref->referral.v3.size = 34;

		ref->referral.v3.entry_flags = 0;
		ref->referral.v3.ttl = 600; /* As w2k3 */
		ref->referral.v3.referrals.r1.DFS_path = talloc_strdup(mem_ctx, dfs_path);
		if (ref->referral.v3.referrals.r1.DFS_path == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		ref->referral.v3.referrals.r1.DFS_alt_path = talloc_strdup(mem_ctx, dfs_path);
		if (ref->referral.v3.referrals.r1.DFS_alt_path == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		ref->referral.v3.referrals.r1.netw_address = talloc_strdup(mem_ctx, server_path);
		if (ref->referral.v3.referrals.r1.netw_address == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		return NT_STATUS_OK;
	}
	return NT_STATUS_INVALID_LEVEL;
}

/*
  fill a domain refererral
 */
static NTSTATUS fill_domain_dfs_referraltype(TALLOC_CTX *mem_ctx,
					     struct dfs_referral_type *ref,
					     uint16_t version,
					     const char *domain,
					     const char **names,
					     uint16_t numnames)
{
	switch (version) {
	case 3:
		ZERO_STRUCTP(ref);
		DEBUG(8, ("Called fill_domain_dfs_referraltype\n"));
		ref->version = version;
		ref->referral.v3.server_type = DFS_SERVER_NON_ROOT;
#if 0
		/* We use to have variable size, on Windows 2008R2 it's the same
		 * and it seems that it gives better results so ... let's use the same
		 * size.
		 *
		 * Additional note: XP SP2 will ask for version 3 and SP3 for version 4.
		 */
		/*
		 * It's hard coded ... don't think it's a good way but the
		 * sizeof return not the correct values
		 *
		 * We have 18 if the GUID is not included 34 otherwise
		 */
		if (numnames == 0) {
			/* Windows return without the guid when returning domain list
			 */
			ref->referral.v3.size = 18;
		} else {
			ref->referral.v3.size = 34;
		}
#endif
		/* As seen in w2k8r2 it always return the null GUID */
		ref->referral.v3.size = 34;
		ref->referral.v3.entry_flags = DFS_FLAG_REFERRAL_DOMAIN_RESP;
		ref->referral.v3.ttl = 600; /* As w2k3 and w2k8r2*/
		ref->referral.v3.referrals.r2.special_name = talloc_strdup(mem_ctx,
									domain);
		if (ref->referral.v3.referrals.r2.special_name == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		ref->referral.v3.referrals.r2.nb_expanded_names = numnames;
		/* Put the final terminator */
		if (names) {
			int i;
			const char **names2 = talloc_array(mem_ctx, const char *,
							   numnames+1);
			NT_STATUS_HAVE_NO_MEMORY(names2);
			for (i = 0; i<numnames; i++) {
				names2[i] = talloc_asprintf(names2, "\\%s", names[i]);
				NT_STATUS_HAVE_NO_MEMORY(names2[i]);
			}
			names2[numnames] = NULL;
			ref->referral.v3.referrals.r2.expanded_names = names2;
		}
		return NT_STATUS_OK;
	}
	return NT_STATUS_INVALID_LEVEL;
}

/*
  get the DCs list within a site
 */
static NTSTATUS get_dcs_insite(TALLOC_CTX *ctx, struct ldb_context *ldb,
			       struct ldb_dn *sitedn, struct dc_set *list,
			       bool dofqdn)
{
	static const char *attrs[] = { "serverReference", NULL };
	static const char *attrs2[] = { "dNSHostName", "sAMAccountName", NULL };
	struct ldb_result *r;
	unsigned int i;
	int ret;
	const char **dc_list;

	ret = ldb_search(ldb, ctx, &r, sitedn, LDB_SCOPE_SUBTREE, attrs,
			 "(&(objectClass=server)(serverReference=*))");
	if (ret != LDB_SUCCESS) {
		DEBUG(2,(__location__ ": Failed to get list of servers - %s\n",
			 ldb_errstring(ldb)));
		return NT_STATUS_INTERNAL_ERROR;
	}

	if (r->count == 0) {
		/* none in this site */
		talloc_free(r);
		return NT_STATUS_OK;
	}

	/*
	 * need to search for all server object to know the size of the array.
	 * Search all the object of class server in this site
	 */
	dc_list = talloc_array(r, const char *, r->count);
	NT_STATUS_HAVE_NO_MEMORY_AND_FREE(dc_list, r);

	/* TODO put some random here in the order */
	list->names = talloc_realloc(list, list->names, const char *, list->count + r->count);
	NT_STATUS_HAVE_NO_MEMORY_AND_FREE(list->names, r);

	for (i = 0; i<r->count; i++) {
		struct ldb_dn  *dn;
		struct ldb_result *r2;

		dn = ldb_msg_find_attr_as_dn(ldb, ctx, r->msgs[i], "serverReference");
		if (!dn) {
			return NT_STATUS_INTERNAL_ERROR;
		}

		ret = ldb_search(ldb, r, &r2, dn, LDB_SCOPE_BASE, attrs2, "(objectClass=computer)");
		if (ret != LDB_SUCCESS) {
			DEBUG(2,(__location__ ": Search for computer on %s failed - %s\n",
				 ldb_dn_get_linearized(dn), ldb_errstring(ldb)));
			return NT_STATUS_INTERNAL_ERROR;
		}

		if (dofqdn) {
			const char *dns = ldb_msg_find_attr_as_string(r2->msgs[0], "dNSHostName", NULL);
			if (dns == NULL) {
				DEBUG(2,(__location__ ": dNSHostName missing on %s\n",
					 ldb_dn_get_linearized(dn)));
				talloc_free(r);
				return NT_STATUS_INTERNAL_ERROR;
			}

			list->names[list->count] = talloc_strdup(list->names, dns);
			NT_STATUS_HAVE_NO_MEMORY_AND_FREE(list->names[list->count], r);
		} else {
			char *tmp;
			const char *aname = ldb_msg_find_attr_as_string(r2->msgs[0], "sAMAccountName", NULL);
			if (aname == NULL) {
				DEBUG(2,(__location__ ": sAMAccountName missing on %s\n",
					 ldb_dn_get_linearized(dn)));
				talloc_free(r);
				return NT_STATUS_INTERNAL_ERROR;
			}

			tmp = talloc_strdup(list->names, aname);
			NT_STATUS_HAVE_NO_MEMORY_AND_FREE(tmp, r);

			/* Netbios name is also the sAMAccountName for
			   computer but without the final $ */
			tmp[strlen(tmp) - 1] = '\0';
			list->names[list->count] = tmp;
		}
		list->count++;
		talloc_free(r2);
	}

	talloc_free(r);
	return NT_STATUS_OK;
}


/*
  get all DCs
 */
static NTSTATUS get_dcs(TALLOC_CTX *ctx, struct ldb_context *ldb,
			const char *searched_site, bool need_fqdn,
			struct dc_set ***pset_list, uint32_t flags)
{
	/*
	 * Flags will be used later to indicate things like least-expensive
	 * or same-site options
	 */
	const char *attrs_none[] = { NULL };
	const char *attrs3[] = { "name", NULL };
	struct ldb_dn *configdn, *sitedn, *dn, *sitescontainerdn;
	struct ldb_result *r;
	struct dc_set **set_list = NULL;
	uint32_t i;
	int ret;
	uint32_t current_pos = 0;
	NTSTATUS status;
	TALLOC_CTX *subctx = talloc_new(ctx);

	*pset_list = set_list = NULL;

	subctx = talloc_new(ctx);
	NT_STATUS_HAVE_NO_MEMORY(subctx);

	configdn = ldb_get_config_basedn(ldb);

	/* Let's search for the Site container */
	ret = ldb_search(ldb, subctx, &r, configdn, LDB_SCOPE_SUBTREE, attrs_none,
			 "(objectClass=sitesContainer)");
	if (ret != LDB_SUCCESS) {
		DEBUG(2,(__location__ ": Failed to find sitesContainer within %s - %s\n",
			 ldb_dn_get_linearized(configdn), ldb_errstring(ldb)));
		talloc_free(subctx);
		return NT_STATUS_INTERNAL_ERROR;
	}
	if (r->count > 1) {
		DEBUG(2,(__location__ ": Expected 1 sitesContainer - found %u within %s\n",
			 r->count, ldb_dn_get_linearized(configdn)));
		talloc_free(subctx);
		return NT_STATUS_INTERNAL_ERROR;
	}

	sitescontainerdn = talloc_steal(subctx, r->msgs[0]->dn);
	talloc_free(r);

	/*
	 * TODO: Here we should have a more subtle handling
	 * for the case "same-site"
	 */
	ret = ldb_search(ldb, subctx, &r, sitescontainerdn, LDB_SCOPE_SUBTREE,
			 attrs_none, "(objectClass=server)");
	if (ret != LDB_SUCCESS) {
		DEBUG(2,(__location__ ": Failed to find servers within %s - %s\n",
			 ldb_dn_get_linearized(sitescontainerdn), ldb_errstring(ldb)));
		talloc_free(subctx);
		return NT_STATUS_INTERNAL_ERROR;
	}
	talloc_free(r);

	if (searched_site != NULL && searched_site[0] != '\0') {
		ret = ldb_search(ldb, subctx, &r, configdn, LDB_SCOPE_SUBTREE,
				 attrs_none, "(&(name=%s)(objectClass=site))", searched_site);
		if (ret != LDB_SUCCESS) {
			talloc_free(subctx);
			return NT_STATUS_FOOBAR;
		} else if (r->count != 1) {
			talloc_free(subctx);
			return NT_STATUS_FOOBAR;
		}

		/* All of this was to get the DN of the searched_site */
		sitedn = r->msgs[0]->dn;

		set_list = talloc_realloc(subctx, set_list, struct dc_set *, current_pos+1);
		NT_STATUS_HAVE_NO_MEMORY_AND_FREE(set_list, subctx);

		set_list[current_pos] = talloc(set_list, struct dc_set);
		NT_STATUS_HAVE_NO_MEMORY_AND_FREE(set_list[current_pos], subctx);

		set_list[current_pos]->names = NULL;
		set_list[current_pos]->count = 0;
		status = get_dcs_insite(subctx, ldb, sitedn,
					set_list[current_pos], need_fqdn);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(2,(__location__ ": Failed to get DC from site %s - %s\n",
				 ldb_dn_get_linearized(sitedn), nt_errstr(status)));
			talloc_free(subctx);
			return status;
		}
		talloc_free(r);
		current_pos++;
	}

	/* Let's find all the sites */
	ret = ldb_search(ldb, subctx, &r, configdn, LDB_SCOPE_SUBTREE, attrs3, "(objectClass=site)");
	if (ret != LDB_SUCCESS) {
		DEBUG(2,(__location__ ": Failed to find any site containers in %s\n",
			 ldb_dn_get_linearized(configdn)));
		talloc_free(subctx);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	/*
	 * TODO:
	 * We should randomize the order in the main site,
	 * it's mostly needed for sysvol/netlogon referral.
	 * Depending of flag we either randomize order of the
	 * not "in the same site DCs"
	 * or we randomize by group of site that have the same cost
	 * In the long run we want to manipulate an array of site_set
	 * All the site in one set have the same cost (if least-expansive options is selected)
	 * and we will put all the dc related to 1 site set into 1 DCs set.
	 * Within a site set, site order has to be randomized
	 *
	 * But for the moment we just return the list of sites
	 */
	if (r->count) {
		/*
		 * We will realloc + 2 because we will need one additional place
		 * for element at current_pos + 1 for the NULL element
		 */
		set_list = talloc_realloc(subctx, set_list, struct dc_set *,
					  current_pos+2);
		NT_STATUS_HAVE_NO_MEMORY_AND_FREE(set_list, subctx);

		set_list[current_pos] = talloc(ctx, struct dc_set);
		NT_STATUS_HAVE_NO_MEMORY_AND_FREE(set_list[current_pos], subctx);

		set_list[current_pos]->names = NULL;
		set_list[current_pos]->count = 0;

		set_list[current_pos+1] = NULL;
	}

	for (i=0; i<r->count; i++) {
		const char *site_name = ldb_msg_find_attr_as_string(r->msgs[i], "name", NULL);
		if (site_name == NULL) {
			DEBUG(2,(__location__ ": Failed to find name attribute in %s\n",
				 ldb_dn_get_linearized(r->msgs[i]->dn)));
			talloc_free(subctx);
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		if (searched_site == NULL ||
		    strcmp(searched_site, site_name) != 0) {
			DEBUG(2,(__location__ ": Site: %s %s\n",
				searched_site, site_name));

			/*
			 * Do all the site but the one of the client
			 * (because it has already been done ...)
			 */
			dn = r->msgs[i]->dn;

			status = get_dcs_insite(subctx, ldb, dn,
						set_list[current_pos],
						need_fqdn);
			if (!NT_STATUS_IS_OK(status)) {
				talloc_free(subctx);
				return status;
			}
		}
	}
	current_pos++;
	set_list[current_pos] = NULL;

	*pset_list = talloc_move(ctx, &set_list);
	talloc_free(subctx);
	return NT_STATUS_OK;
}

static NTSTATUS dodomain_referral(struct loadparm_context *lp_ctx,
				  struct ldb_context *sam_ctx,
				  const struct tsocket_address *client,
				  struct dfs_GetDFSReferral *r)
{
	/*
	 * TODO for the moment we just return the local domain
	 */
	NTSTATUS status;
	const char *dns_domain = lpcfg_dnsdomain(lp_ctx);
	const char *netbios_domain = lpcfg_workgroup(lp_ctx);
	struct dfs_referral_type *referrals;
	const char *referral_str;
	/* In the future this needs to be fetched from the ldb */
	uint32_t found_domain = 2;

	if (lpcfg_server_role(lp_ctx) != ROLE_ACTIVE_DIRECTORY_DC) {
		DEBUG(10 ,("Received a domain referral request on a non DC\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (r->in.req.max_referral_level < 3) {
		DEBUG(2,("invalid max_referral_level %u\n",
			 r->in.req.max_referral_level));
		return NT_STATUS_UNSUCCESSFUL;
	}

	r->out.resp = talloc_zero(r, struct dfs_referral_resp);
	if (r->out.resp == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	r->out.resp->path_consumed = 0;
	r->out.resp->header_flags = 0; /* Do like w2k3 */
	r->out.resp->nb_referrals = found_domain; /* the fqdn one + the NT domain */

	referrals = talloc_zero_array(r->out.resp,
				      struct dfs_referral_type,
				      r->out.resp->nb_referrals);
	if (referrals == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	r->out.resp->referral_entries = referrals;

	referral_str = talloc_asprintf(r, "\\%s", netbios_domain);
	if (referral_str == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = fill_domain_dfs_referraltype(referrals,
					      &referrals[0], 3,
					      referral_str,
					      NULL, 0);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(2,("%s: Unable to fill domain referral structure - %s\n",
			 __location__, nt_errstr(status)));
		return status;
	}

	referral_str = talloc_asprintf(r, "\\%s", dns_domain);
	if (referral_str == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = fill_domain_dfs_referraltype(referrals,
					      &referrals[1], 3,
					      referral_str,
					      NULL, 0);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(2,("%s: Unable to fill domain referral structure - %s\n",
			 __location__, nt_errstr(status)));
		return status;
	}

	return NT_STATUS_OK;
}

/*
 * Handle the logic for dfs referral request like
 * \\dns_domain or \\netbios_domain.
 */
static NTSTATUS dodc_referral(struct loadparm_context *lp_ctx,
			      struct ldb_context *sam_ctx,
			      const struct tsocket_address *client,
			      struct dfs_GetDFSReferral *r,
			      const char *domain_name)
{
	NTSTATUS status;
	const char *site_name = NULL; /* Name of the site where the client is */
	bool need_fqdn = false;
	unsigned int i;
	const char **dc_list = NULL;
	uint32_t num_dcs = 0;
	struct dc_set **set;
	char *client_str = NULL;
	struct dfs_referral_type *referrals;
	const char *referral_str;

	if (lpcfg_server_role(lp_ctx) != ROLE_ACTIVE_DIRECTORY_DC) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (r->in.req.max_referral_level < 3) {
		DEBUG(2,("invalid max_referral_level %u\n",
			 r->in.req.max_referral_level));
		return NT_STATUS_UNSUCCESSFUL;
	}

	DEBUG(10, ("in this we have request for %s requested is %s\n",
		   domain_name, r->in.req.servername));

	if (strchr(domain_name,'.')) {
		need_fqdn = 1;
	}

	if (tsocket_address_is_inet(client, "ip")) {
		client_str = tsocket_address_inet_addr_string(client, r);
		if (client_str == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	site_name = samdb_client_site_name(sam_ctx, r, client_str, NULL);

	status = get_dcs(r, sam_ctx, site_name, need_fqdn, &set, 0);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(3,("Unable to get list of DCs - %s\n",
			 nt_errstr(status)));
		return status;
	}

	for(i=0; set[i]; i++) {
		uint32_t j;

		dc_list = talloc_realloc(r, dc_list, const char*,
					 num_dcs + set[i]->count + 1);
		if (dc_list == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		for(j=0; j<set[i]->count; j++) {
			dc_list[num_dcs + j] = talloc_move(dc_list,
							   &set[i]->names[j]);
		}
		num_dcs = num_dcs + set[i]->count;
		TALLOC_FREE(set[i]);
		dc_list[num_dcs] = NULL;
	}

	r->out.resp = talloc_zero(r, struct dfs_referral_resp);
	if (r->out.resp == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	r->out.resp->path_consumed = 0;
	r->out.resp->header_flags = 0; /* Do like w2k3 */
	r->out.resp->nb_referrals = 1;

	referrals = talloc_zero_array(r->out.resp,
				      struct dfs_referral_type,
				      r->out.resp->nb_referrals);
	if (referrals == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	r->out.resp->referral_entries = referrals;

	if (r->in.req.servername[0] == '\\') {
		referral_str = talloc_asprintf(referrals, "%s",
					       domain_name);
	} else {
		referral_str = talloc_asprintf(referrals, "\\%s",
					       domain_name);
	}
	if (referral_str == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = fill_domain_dfs_referraltype(referrals,
					      &referrals[0], 3,
					      referral_str,
					      dc_list, num_dcs);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(2,("%s: Unable to fill domain referral structure - %s\n",
			 __location__, nt_errstr(status)));
		return status;
	}

	return NT_STATUS_OK;
}

/*
 * Handle the logic for dfs referral request like
 * \\domain\sysvol or \\domain\netlogon
 */
static NTSTATUS dosysvol_referral(struct loadparm_context *lp_ctx,
				  struct ldb_context *sam_ctx,
				  const struct tsocket_address *client,
				  struct dfs_GetDFSReferral *r,
				  const char *domain_name,
				  const char *dfs_name)
{
	const char *site_name = NULL; /* Name of the site where the client is */
	bool need_fqdn = false;
	unsigned int i, c = 0, nb_entries = 0;
	struct dc_set **set;
	char *client_str = NULL;
	NTSTATUS status;
	struct dfs_referral_type *referrals;

	if (lpcfg_server_role(lp_ctx) != ROLE_ACTIVE_DIRECTORY_DC) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (r->in.req.max_referral_level < 3) {
		DEBUG(2,("invalid max_referral_level %u\n",
			 r->in.req.max_referral_level));
		return NT_STATUS_UNSUCCESSFUL;
	}

	DEBUG(10, ("in this we have request for %s and share %s requested is %s\n",
		   domain_name, dfs_name, r->in.req.servername));

	if (strchr(domain_name,'.')) {
		need_fqdn = 1;
	}

	if (tsocket_address_is_inet(client, "ip")) {
		client_str = tsocket_address_inet_addr_string(client, r);
		if (client_str == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	site_name = samdb_client_site_name(sam_ctx, r, client_str, NULL);

	status = get_dcs(r, sam_ctx, site_name, need_fqdn, &set, 0);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(3,("Unable to get list of DCs - %s\n",
			 nt_errstr(status)));
		return status;
	}

	for(i=0; set[i]; i++) {
		nb_entries = nb_entries + set[i]->count;
	}

	r->out.resp = talloc_zero(r, struct dfs_referral_resp);
	if (r->out.resp == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/* The length is expected in bytes */
	r->out.resp->path_consumed = strlen_m(r->in.req.servername) * 2;
	/* Do like w2k3 and like in 3.3.5.3 of MS-DFSC*/
	r->out.resp->header_flags = DFS_HEADER_FLAG_STORAGE_SVR;
	r->out.resp->nb_referrals = nb_entries;

	referrals = talloc_zero_array(r->out.resp,
				      struct dfs_referral_type,
				      r->out.resp->nb_referrals);
	if (referrals == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	r->out.resp->referral_entries = referrals;

	c = 0;
	for(i=0; set[i]; i++) {
		uint32_t j;

		for(j=0; j< set[i]->count; j++) {
			struct dfs_referral_type *ref = &referrals[c];
			const char *referral_str;

			referral_str = talloc_asprintf(referrals, "\\%s\\%s",
						       set[i]->names[j], dfs_name);
			if (referral_str == NULL) {
				return NT_STATUS_NO_MEMORY;
			}

			DEBUG(8,("Doing a dfs referral for %s with this value "
				 "%s requested %s\n",
				 set[i]->names[j], referral_str,
				 r->in.req.servername));

			status = fill_normal_dfs_referraltype(referrals, ref,
					r->in.req.max_referral_level,
					r->in.req.servername,
					referral_str, c==0);


			if (!NT_STATUS_IS_OK(status)) {
				DEBUG(2,("%s: Unable to fill domain referral "
					 "structure - %s\n",
					 __location__, nt_errstr(status)));
				return status;
			}

			c++;
		}
	}

	return NT_STATUS_OK;
}

/*
  trans2 getdfsreferral implementation
*/
NTSTATUS dfs_server_ad_get_referrals(struct loadparm_context *lp_ctx,
				     struct ldb_context *sam_ctx,
				     const struct tsocket_address *client,
				     struct dfs_GetDFSReferral *r)
{
	char *server_name = NULL;
	char *dfs_name = NULL;
	char *link_path = NULL;
	const char *netbios_domain;
	const char *dns_domain;
	const char *netbios_name;
	const char *dns_name;
	const char **netbios_aliases;

	if (!lpcfg_host_msdfs(lp_ctx)) {
		return NT_STATUS_FS_DRIVER_REQUIRED;
	}

	if (r->in.req.servername == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	DEBUG(8, ("Requested DFS name: %s length: %u\n",
		  r->in.req.servername,
		  (unsigned int)strlen_m(r->in.req.servername)*2));

	/*
	 * If the servername is "" then we are in a case of domain dfs
	 * and the client just searches for the list of local domain
	 * it is attached and also trusted ones.
	 */
	if (strlen(r->in.req.servername) == 0) {
		return dodomain_referral(lp_ctx, sam_ctx, client, r);
	}

	server_name = talloc_strdup(r, r->in.req.servername);
	if (server_name == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	while(*server_name && *server_name == '\\') {
		server_name++;
	}

	dfs_name = strchr(server_name, '\\');
	if (dfs_name != NULL) {
		dfs_name[0] = '\0';
		dfs_name++;

		link_path = strchr(dfs_name, '\\');
		if (link_path != NULL) {
			link_path[0] = '\0';
			link_path++;
		}
	}

	if (link_path != NULL) {
		/*
		 * If it is a DFS Link we do not
		 * handle it here.
		 */
		return NT_STATUS_NOT_FOUND;
	}

	netbios_domain = lpcfg_workgroup(lp_ctx);
	dns_domain = lpcfg_dnsdomain(lp_ctx);
	netbios_name = lpcfg_netbios_name(lp_ctx);
	dns_name = talloc_asprintf(r, "%s.%s", netbios_name, dns_domain);
	if (dns_name == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	if ((strcasecmp_m(server_name, netbios_name) == 0) ||
	    (strcasecmp_m(server_name, dns_name) == 0)) {
		/*
		 * If it is not domain related do not
		 * handle it here.
		 */
		return NT_STATUS_NOT_FOUND;
	}

	if (is_ipaddress(server_name)) {
		/*
		 * If it is not domain related do not
		 * handle it here.
		 */
		return NT_STATUS_NOT_FOUND;
	}

	netbios_aliases = lpcfg_netbios_aliases(lp_ctx);
	while (netbios_aliases && *netbios_aliases) {
		const char *netbios_alias = *netbios_aliases;
		char *dns_alias;
		int cmp;

		cmp = strcasecmp_m(server_name, netbios_alias);
		if (cmp == 0) {
			/*
			 * If it is not domain related do not
			 * handle it here.
			 */
			return NT_STATUS_NOT_FOUND;
		}

		dns_alias = talloc_asprintf(r, "%s.%s",
					    netbios_alias,
					    dns_domain);
		if (dns_alias == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		cmp = strcasecmp_m(server_name, dns_alias);
		talloc_free(dns_alias);
		if (cmp == 0) {
			/*
			 * If it is not domain related do not
			 * handle it here.
			 */
			return NT_STATUS_NOT_FOUND;
		}
		netbios_aliases++;
	}

	if ((strcasecmp_m(server_name, netbios_domain) != 0) &&
	    (strcasecmp_m(server_name, dns_domain) != 0)) {
		/*
		 * Not a domain we handle.
		 */
		return NT_STATUS_INVALID_PARAMETER;
	}

	/*
	 * Here we have filtered the thing the requested name don't contain our DNS name.
	 * So if the share == NULL or if share in ("sysvol", "netlogon")
	 * then we proceed. In the first case it will be a dc refereal in the second it will
	 * be just a sysvol/netlogon referral.
	 */
	if (dfs_name == NULL) {
		return dodc_referral(lp_ctx, sam_ctx,
				     client, r, server_name);
	}

	/*
	 * Here we have filtered the thing the requested name don't contain our DNS name.
	 * So if the share == NULL or if share in ("sysvol", "netlogon")
	 * then we proceed. In the first case it will be a dc refereal in the second it will
	 * be just a sysvol/netlogon referral.
	 */
	if (strcasecmp(dfs_name, "sysvol") == 0 ||
	    strcasecmp(dfs_name, "netlogon") == 0) {
		return dosysvol_referral(lp_ctx, sam_ctx, client, r,
					 server_name, dfs_name);
	}

	/* By default until all the case are handled */
	return NT_STATUS_NOT_FOUND;
}
