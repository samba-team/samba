/*
 *  idmap_hash.c
 *
 * Copyright (C) Gerald Carter  <jerry@samba.org>      2007 - 2008
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
 *
 */

#include "includes.h"
#include "winbindd/winbindd.h"
#include "idmap.h"
#include "idmap_hash.h"
#include "ads.h"
#include "nss_info.h"
#include "../libcli/security/dom_sid.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_IDMAP

struct sid_hash_table {
	struct dom_sid *sid;
};

/*********************************************************************
 Hash a domain SID (S-1-5-12-aaa-bbb-ccc) to a 12bit number
 ********************************************************************/

static uint32_t hash_domain_sid(const struct dom_sid *sid)
{
	uint32_t hash;

	if (sid->num_auths != 4)
		return 0;

	/* XOR the last three subauths */

	hash = ((sid->sub_auths[1] ^ sid->sub_auths[2]) ^ sid->sub_auths[3]);

	/* Take all 32-bits into account when generating the 12-bit
	   hash value */
	hash = (((hash & 0xFFF00000) >> 20)
		+ ((hash & 0x000FFF00) >> 8)
		+ (hash & 0x000000FF)) & 0x0000FFF;

	/* return a 12-bit hash value */

	return hash;
}

/*********************************************************************
 Hash a Relative ID to a 20 bit number
 ********************************************************************/

static uint32_t hash_rid(uint32_t rid)
{
	/* 20 bits for the rid which allows us to support
	   the first 100K users/groups in a domain */

	return (rid & 0x0007FFFF);
}

/*********************************************************************
 ********************************************************************/

static uint32_t combine_hashes(uint32_t h_domain,
			       uint32_t h_rid)
{
	uint32_t return_id = 0;

	/* shift the hash_domain 19 bits to the left and OR with the
	   hash_rid */

	return_id = ((h_domain<<19) | h_rid);

	return return_id;
}

/*********************************************************************
 ********************************************************************/

static void separate_hashes(uint32_t id,
			    uint32_t *h_domain,
			    uint32_t *h_rid)
{
	*h_rid = id & 0x0007FFFF;
	*h_domain = (id & 0x7FF80000) >> 19;

	return;
}


/*********************************************************************
 ********************************************************************/

static NTSTATUS idmap_hash_initialize(struct idmap_domain *dom)
{
	struct sid_hash_table *hashed_domains;
	NTSTATUS nt_status = NT_STATUS_UNSUCCESSFUL;
	struct winbindd_tdc_domain *dom_list = NULL;
	size_t num_domains = 0;
	size_t i;

	DBG_ERR("The idmap_hash module is deprecated and should not be used. "
		"Please migrate to a different plugin. This module will be "
		"removed in a future version of Samba\n");

	if (!strequal(dom->name, "*")) {
		DBG_ERR("Error: idmap_hash configured for domain '%s'. "
			"But the hash module can only be used for the default "
			"idmap configuration.\n", dom->name);
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* If the domain SID hash table has been initialized, assume
	   that we completed this function previously */

	if (dom->private_data != NULL) {
		nt_status = NT_STATUS_OK;
		goto done;
	}

	if (!wcache_tdc_fetch_list(&dom_list, &num_domains)) {
		nt_status = NT_STATUS_TRUSTED_DOMAIN_FAILURE;
		BAIL_ON_NTSTATUS_ERROR(nt_status);
	}

	/* Create the hash table of domain SIDs */

	hashed_domains = talloc_zero_array(dom, struct sid_hash_table, 4096);
	BAIL_ON_PTR_NT_ERROR(hashed_domains, nt_status);

	/* create the hash table of domain SIDs */

	for (i=0; i<num_domains; i++) {
		struct dom_sid_buf buf;
		uint32_t hash;

		if (is_null_sid(&dom_list[i].sid))
			continue;

		/*
		 * Check if the domain from the list is not already configured
		 * to use another idmap backend. Not checking this makes the
		 * idmap_hash module map IDs for *all* domains implicitly.  This
		 * is quite dangerous in setups that use multiple idmap
		 * configurations.
		 */

		if (domain_has_idmap_config(dom_list[i].domain_name)) {
			continue;
		}

		if ((hash = hash_domain_sid(&dom_list[i].sid)) == 0)
			continue;

		DBG_INFO("Adding %s (%s) -> %d\n",
			 dom_list[i].domain_name,
			 dom_sid_str_buf(&dom_list[i].sid, &buf),
			 hash);

		hashed_domains[hash].sid = talloc(hashed_domains, struct dom_sid);
		sid_copy(hashed_domains[hash].sid, &dom_list[i].sid);
	}

	dom->private_data = hashed_domains;

done:
	return nt_status;
}

/*********************************************************************
 ********************************************************************/

static NTSTATUS unixids_to_sids(struct idmap_domain *dom,
				struct id_map **ids)
{
	struct sid_hash_table *hashed_domains = talloc_get_type_abort(
		dom->private_data, struct sid_hash_table);
	NTSTATUS nt_status = NT_STATUS_UNSUCCESSFUL;
	int i;

	if (!ids) {
		nt_status = NT_STATUS_INVALID_PARAMETER;
		BAIL_ON_NTSTATUS_ERROR(nt_status);
	}

	/* initialize the status to avoid suprise */
	for (i = 0; ids[i]; i++) {
		ids[i]->status = ID_UNKNOWN;
	}

	nt_status = idmap_hash_initialize(dom);
	BAIL_ON_NTSTATUS_ERROR(nt_status);

	for (i=0; ids[i]; i++) {
		uint32_t h_domain, h_rid;

		ids[i]->status = ID_UNMAPPED;

		separate_hashes(ids[i]->xid.id, &h_domain, &h_rid);

		/* Make sure the caller allocated memor for us */

		if (!ids[i]->sid) {
			nt_status = NT_STATUS_INVALID_PARAMETER;
			BAIL_ON_NTSTATUS_ERROR(nt_status);
		}

		/* If the domain hash doesn't find a SID in the table,
		   skip it */

		if (!hashed_domains[h_domain].sid)
			continue;

		sid_compose(ids[i]->sid, hashed_domains[h_domain].sid, h_rid);
		ids[i]->status = ID_MAPPED;
	}

done:
	return nt_status;
}

/*********************************************************************
 ********************************************************************/

static NTSTATUS sids_to_unixids(struct idmap_domain *dom,
				struct id_map **ids)
{
	NTSTATUS nt_status = NT_STATUS_UNSUCCESSFUL;
	int i;

	if (!ids) {
		nt_status = NT_STATUS_INVALID_PARAMETER;
		BAIL_ON_NTSTATUS_ERROR(nt_status);
	}

	/* initialize the status to avoid suprise */
	for (i = 0; ids[i]; i++) {
		ids[i]->status = ID_UNKNOWN;
	}

	nt_status = idmap_hash_initialize(dom);
	BAIL_ON_NTSTATUS_ERROR(nt_status);

	for (i=0; ids[i]; i++) {
		struct dom_sid sid;
		uint32_t rid;
		uint32_t h_domain, h_rid;

		ids[i]->status = ID_UNMAPPED;

		if (ids[i]->xid.type == ID_TYPE_NOT_SPECIFIED) {
			/*
			 * idmap_hash used to bounce back the requested type,
			 * which was ID_TYPE_UID, ID_TYPE_GID or
			 * ID_TYPE_NOT_SPECIFIED before as the winbindd parent
			 * always used a lookupsids.  When the lookupsids
			 * failed because of an unknown domain, the idmap child
			 * weren't requested at all and the caller sees
			 * ID_TYPE_NOT_SPECIFIED.
			 *
			 * Now that the winbindd parent will pass ID_TYPE_BOTH
			 * in order to indicate that the domain exists.
			 * We should ask the parent to fallback to lookupsids
			 * if the domain is not known yet.
			 */
			ids[i]->status = ID_REQUIRE_TYPE;
			continue;
		}

		sid_copy(&sid, ids[i]->sid);
		sid_split_rid(&sid, &rid);

		h_domain = hash_domain_sid(&sid);
		h_rid = hash_rid(rid);

		/* Check that both hashes are non-zero*/

		if (h_domain && h_rid) {
			/*
			 * idmap_hash used to bounce back the requested type,
			 * which was ID_TYPE_UID, ID_TYPE_GID or
			 * ID_TYPE_NOT_SPECIFIED before as the winbindd parent
			 * always used a lookupsids.
			 *
			 * This module should have supported ID_TYPE_BOTH since
			 * samba-4.1.0, similar to idmap_rid and idmap_autorid.
			 *
			 * Now that the winbindd parent will pass ID_TYPE_BOTH
			 * in order to indicate that the domain exists, it's
			 * better to always return ID_TYPE_BOTH instead of a
			 * random mix of ID_TYPE_UID, ID_TYPE_GID or
			 * ID_TYPE_BOTH.
			 */
			ids[i]->xid.type = ID_TYPE_BOTH;
			ids[i]->xid.id = combine_hashes(h_domain, h_rid);
			ids[i]->status = ID_MAPPED;
		}
	}

done:
	return nt_status;
}

/*********************************************************************
 ********************************************************************/

static NTSTATUS nss_hash_init(struct nss_domain_entry *e )
{
	return NT_STATUS_OK;
}

/**********************************************************************
 *********************************************************************/

static NTSTATUS nss_hash_map_to_alias(TALLOC_CTX *mem_ctx,
					struct nss_domain_entry *e,
					const char *name,
					char **alias)
{
	NTSTATUS nt_status = NT_STATUS_UNSUCCESSFUL;
	const char *value;

	value = talloc_asprintf(mem_ctx, "%s\\%s", e->domain, name);
	BAIL_ON_PTR_NT_ERROR(value, nt_status);

	nt_status = mapfile_lookup_key(mem_ctx, value, alias);
	BAIL_ON_NTSTATUS_ERROR(nt_status);

done:
	return nt_status;
}

/**********************************************************************
 *********************************************************************/

static NTSTATUS nss_hash_map_from_alias(TALLOC_CTX *mem_ctx,
					  struct nss_domain_entry *e,
					  const char *alias,
					  char **name)
{
	return mapfile_lookup_value(mem_ctx, alias, name);
}

/**********************************************************************
 *********************************************************************/

static NTSTATUS nss_hash_close(void)
{
	return NT_STATUS_OK;
}

/*********************************************************************
 Dispatch Tables for IDMap and NssInfo Methods
********************************************************************/

static const struct idmap_methods hash_idmap_methods = {
	.init            = idmap_hash_initialize,
	.unixids_to_sids = unixids_to_sids,
	.sids_to_unixids = sids_to_unixids,
};

static const struct nss_info_methods hash_nss_methods = {
	.init           = nss_hash_init,
	.map_to_alias   = nss_hash_map_to_alias,
	.map_from_alias = nss_hash_map_from_alias,
	.close_fn       = nss_hash_close
};

/**********************************************************************
 Register with the idmap and idmap_nss subsystems. We have to protect
 against the idmap and nss_info interfaces being in a half-registered
 state.
 **********************************************************************/

static_decl_idmap;
NTSTATUS idmap_hash_init(TALLOC_CTX *ctx)
{
	static NTSTATUS idmap_status = NT_STATUS_UNSUCCESSFUL;
	static NTSTATUS nss_status = NT_STATUS_UNSUCCESSFUL;

	if ( !NT_STATUS_IS_OK(idmap_status) ) {
		idmap_status =  smb_register_idmap(SMB_IDMAP_INTERFACE_VERSION,
						   "hash", &hash_idmap_methods);

		if ( !NT_STATUS_IS_OK(idmap_status) ) {
			DEBUG(0,("Failed to register hash idmap plugin.\n"));
			return idmap_status;
		}
	}

	if ( !NT_STATUS_IS_OK(nss_status) ) {
		nss_status = smb_register_idmap_nss(SMB_NSS_INFO_INTERFACE_VERSION,
						    "hash", &hash_nss_methods);
		if ( !NT_STATUS_IS_OK(nss_status) ) {
			DEBUG(0,("Failed to register hash idmap nss plugin.\n"));
			return nss_status;
		}
	}

	return NT_STATUS_OK;
}
