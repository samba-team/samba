/*
   Unix SMB/CIFS implementation.

   Copyright (C) Stefan Metzmacher 2015

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
#include "ldb.h"
#include "../lib/util/util_ldb.h"
#include "dsdb/samdb/samdb.h"
#include "libcli/security/security.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "librpc/gen_ndr/ndr_misc.h"
#include "../libds/common/flags.h"
#include "dsdb/common/proto.h"
#include "param/param.h"
#include "librpc/gen_ndr/ndr_drsblobs.h"
#include "lib/util/tsort.h"
#include "dsdb/common/util.h"
#include "libds/common/flag_mapping.h"
#include "../lib/util/dlinklist.h"
#include "../lib/crypto/crypto.h"

static NTSTATUS dsdb_trust_forest_record_to_lsa(TALLOC_CTX *mem_ctx,
					 const struct ForestTrustInfoRecord *ftr,
					 struct lsa_ForestTrustRecord **_lftr)
{
	struct lsa_ForestTrustRecord *lftr = NULL;
	const struct ForestTrustString *str = NULL;
	struct lsa_StringLarge *lstr = NULL;
	const struct ForestTrustDataDomainInfo *info = NULL;
	struct lsa_ForestTrustDomainInfo *linfo = NULL;

	*_lftr = NULL;

	lftr = talloc_zero(mem_ctx, struct lsa_ForestTrustRecord);
	if (lftr == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	lftr->flags = ftr->flags;
	lftr->time = ftr->timestamp;
	lftr->type = ftr->type;

	switch (lftr->type) {
	case LSA_FOREST_TRUST_TOP_LEVEL_NAME:
		lstr = &lftr->forest_trust_data.top_level_name;
		str = &ftr->data.name;

		lstr->string = talloc_strdup(mem_ctx, str->string);
		if (lstr->string == NULL) {
			TALLOC_FREE(lftr);
			return NT_STATUS_NO_MEMORY;
		}

		break;

	case LSA_FOREST_TRUST_TOP_LEVEL_NAME_EX:
		lstr = &lftr->forest_trust_data.top_level_name_ex;
		str = &ftr->data.name;

		lstr->string = talloc_strdup(mem_ctx, str->string);
		if (lstr->string == NULL) {
			TALLOC_FREE(lftr);
			return NT_STATUS_NO_MEMORY;
		}

		break;

	case LSA_FOREST_TRUST_DOMAIN_INFO:
		linfo = &lftr->forest_trust_data.domain_info;
		info = &ftr->data.info;

		linfo->domain_sid = dom_sid_dup(lftr, &info->sid);
		if (linfo->domain_sid == NULL) {
			TALLOC_FREE(lftr);
			return NT_STATUS_NO_MEMORY;
		}

		lstr = &linfo->dns_domain_name;
		str = &info->dns_name;
		lstr->string = talloc_strdup(mem_ctx, str->string);
		if (lstr->string == NULL) {
			TALLOC_FREE(lftr);
			return NT_STATUS_NO_MEMORY;
		}

		lstr = &linfo->netbios_domain_name;
		str = &info->netbios_name;
		lstr->string = talloc_strdup(mem_ctx, str->string);
		if (lstr->string == NULL) {
			TALLOC_FREE(lftr);
			return NT_STATUS_NO_MEMORY;
		}

		break;

	default:
		return NT_STATUS_NOT_SUPPORTED;
	}

	*_lftr = lftr;
	return NT_STATUS_OK;
}

NTSTATUS dsdb_trust_forest_info_to_lsa(TALLOC_CTX *mem_ctx,
				       const struct ForestTrustInfo *fti,
				       struct lsa_ForestTrustInformation **_lfti)
{
	struct lsa_ForestTrustInformation *lfti;
	uint32_t i;

	*_lfti = NULL;

	if (fti->version != 1) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	lfti = talloc_zero(mem_ctx, struct lsa_ForestTrustInformation);
	if (fti == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	lfti->count = fti->count;
	lfti->entries = talloc_zero_array(mem_ctx,
					  struct lsa_ForestTrustRecord *,
					  lfti->count);
	if (lfti->entries == NULL) {
		TALLOC_FREE(lfti);
		return NT_STATUS_NO_MEMORY;
	}

	for (i = 0; i < fti->count; i++) {
		struct ForestTrustInfoRecord *ftr = &fti->records[i].record;
		struct lsa_ForestTrustRecord *lftr = NULL;
		NTSTATUS status;

		status = dsdb_trust_forest_record_to_lsa(lfti->entries, ftr,
							 &lftr);
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(lfti);
			return NT_STATUS_NO_MEMORY;
		}
		lfti->entries[i] = lftr;
	}

	*_lfti = lfti;
	return NT_STATUS_OK;
}

static NTSTATUS dsdb_trust_forest_info_add_record(struct lsa_ForestTrustInformation *fti,
						  const struct lsa_ForestTrustRecord *ftr)
{
	struct lsa_ForestTrustRecord **es = NULL;
	struct lsa_ForestTrustRecord *e = NULL;
	const struct lsa_StringLarge *dns1 = NULL;
	struct lsa_StringLarge *dns2 = NULL;
	const struct lsa_ForestTrustDomainInfo *d1 = NULL;
	struct lsa_ForestTrustDomainInfo *d2 = NULL;
	size_t len = 0;

	es = talloc_realloc(fti, fti->entries,
			    struct lsa_ForestTrustRecord *,
			    fti->count + 1);
	if (!es) {
		return NT_STATUS_NO_MEMORY;
	}
	fti->entries = es;

	e = talloc_zero(es, struct lsa_ForestTrustRecord);
	if (e == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	e->type = ftr->type;
	e->flags = ftr->flags;
	e->time = ftr->time;

	switch (ftr->type) {
	case LSA_FOREST_TRUST_TOP_LEVEL_NAME:
		dns1 = &ftr->forest_trust_data.top_level_name;
		dns2 = &e->forest_trust_data.top_level_name;
		break;

	case LSA_FOREST_TRUST_TOP_LEVEL_NAME_EX:
		dns1 = &ftr->forest_trust_data.top_level_name_ex;
		dns2 = &e->forest_trust_data.top_level_name_ex;
		break;

	case LSA_FOREST_TRUST_DOMAIN_INFO:
		dns1 = &ftr->forest_trust_data.domain_info.dns_domain_name;
		dns2 = &e->forest_trust_data.domain_info.dns_domain_name;
		d1 = &ftr->forest_trust_data.domain_info;
		d2 = &e->forest_trust_data.domain_info;
		break;
	default:
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (dns1->string == NULL) {
		TALLOC_FREE(e);
		return NT_STATUS_INVALID_PARAMETER;
	}

	len = strlen(dns1->string);
	if (len == 0) {
		TALLOC_FREE(e);
		return NT_STATUS_INVALID_PARAMETER;
	}

	dns2->string = talloc_strdup(e, dns1->string);
	if (dns2->string == NULL) {
		TALLOC_FREE(e);
		return NT_STATUS_NO_MEMORY;
	}

	if (d1 != NULL) {
		const struct lsa_StringLarge *nb1 = &d1->netbios_domain_name;
		struct lsa_StringLarge *nb2 = &d2->netbios_domain_name;

		if (nb1->string == NULL) {
			TALLOC_FREE(e);
			return NT_STATUS_INVALID_PARAMETER;
		}

		len = strlen(nb1->string);
		if (len == 0) {
			TALLOC_FREE(e);
			return NT_STATUS_INVALID_PARAMETER;
		}
		if (len > 15) {
			TALLOC_FREE(e);
			return NT_STATUS_INVALID_PARAMETER;
		}

		nb2->string = talloc_strdup(e, nb1->string);
		if (nb2->string == NULL) {
			TALLOC_FREE(e);
			return NT_STATUS_NO_MEMORY;
		}

		if (d1->domain_sid == NULL) {
			TALLOC_FREE(e);
			return NT_STATUS_INVALID_PARAMETER;
		}

		d2->domain_sid = dom_sid_dup(e, d1->domain_sid);
		if (d2->domain_sid == NULL) {
			TALLOC_FREE(e);
			return NT_STATUS_NO_MEMORY;
		}
	}

	fti->entries[fti->count++] = e;
	return NT_STATUS_OK;
}

static NTSTATUS dsdb_trust_parse_crossref_info(TALLOC_CTX *mem_ctx,
					struct ldb_context *sam_ctx,
					const struct ldb_message *msg,
					struct lsa_TrustDomainInfoInfoEx **_tdo)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct lsa_TrustDomainInfoInfoEx *tdo = NULL;
	const char *dns = NULL;
	const char *netbios = NULL;
	struct ldb_dn *nc_dn = NULL;
	struct dom_sid sid = {};
	NTSTATUS status;

	*_tdo = NULL;
	tdo = talloc_zero(mem_ctx, struct lsa_TrustDomainInfoInfoEx);
	if (tdo == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}
	talloc_steal(frame, tdo);

	dns = ldb_msg_find_attr_as_string(msg, "dnsRoot", NULL);
	if (dns == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	tdo->domain_name.string = talloc_strdup(tdo, dns);
	if (tdo->domain_name.string == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	netbios = ldb_msg_find_attr_as_string(msg, "nETBIOSName", NULL);
	if (netbios == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	tdo->netbios_name.string = talloc_strdup(tdo, netbios);
	if (tdo->netbios_name.string == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	nc_dn = samdb_result_dn(sam_ctx, frame, msg, "ncName", NULL);
	if (nc_dn == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	status = dsdb_get_extended_dn_sid(nc_dn, &sid, "SID");
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}
	tdo->sid = dom_sid_dup(tdo, &sid);
	if (tdo->sid == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	tdo->trust_type = LSA_TRUST_TYPE_UPLEVEL;
	tdo->trust_direction = LSA_TRUST_DIRECTION_INBOUND |
			       LSA_TRUST_DIRECTION_OUTBOUND;
	tdo->trust_attributes = LSA_TRUST_ATTRIBUTE_WITHIN_FOREST;

	*_tdo = talloc_move(mem_ctx, &tdo);
	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}

static NTSTATUS dsdb_trust_crossref_tdo_info(TALLOC_CTX *mem_ctx,
			struct ldb_context *sam_ctx,
			struct ldb_dn *domain_dn,
			const char *extra_filter,
			struct lsa_TrustDomainInfoInfoEx **_tdo,
			struct lsa_TrustDomainInfoInfoEx **_root_trust_tdo,
			struct lsa_TrustDomainInfoInfoEx **_trust_parent_tdo)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct lsa_TrustDomainInfoInfoEx *tdo = NULL;
	struct lsa_TrustDomainInfoInfoEx *root_trust_tdo = NULL;
	struct lsa_TrustDomainInfoInfoEx *trust_parent_tdo = NULL;
	struct ldb_dn *partitions_dn = NULL;
	const char * const cross_attrs[] = {
		"dnsRoot",
		"nETBIOSName",
		"nCName",
		"rootTrust",
		"trustParent",
		NULL,
	};
	struct ldb_result *cross_res = NULL;
	struct ldb_message *msg = NULL;
	struct ldb_dn *root_trust_dn = NULL;
	struct ldb_dn *trust_parent_dn = NULL;
	NTSTATUS status;
	int ret;

	if (extra_filter == NULL) {
		extra_filter = "";
	}

	*_tdo = NULL;
	if (_root_trust_tdo != NULL) {
		*_root_trust_tdo = NULL;
	}
	if (_trust_parent_tdo != NULL) {
		*_trust_parent_tdo = NULL;
	}

	domain_dn = ldb_get_default_basedn(sam_ctx);
	if (domain_dn == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_INTERNAL_ERROR;
	}

	partitions_dn = samdb_partitions_dn(sam_ctx, frame);
	if (partitions_dn == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	ret = dsdb_search(sam_ctx, partitions_dn, &cross_res,
			  partitions_dn, LDB_SCOPE_ONELEVEL,
			  cross_attrs,
			  DSDB_SEARCH_ONE_ONLY |
			  DSDB_SEARCH_SHOW_EXTENDED_DN,
			  "(&"
			    "(ncName=%s)"
			    "(objectClass=crossRef)"
			    "(systemFlags:%s:=%u)"
			    "%s"
			  ")",
			  ldb_dn_get_linearized(domain_dn),
			  LDB_OID_COMPARATOR_AND,
			  SYSTEM_FLAG_CR_NTDS_DOMAIN,
			  extra_filter);
	if (ret != LDB_SUCCESS) {
		TALLOC_FREE(frame);
		return dsdb_ldb_err_to_ntstatus(ret);
	}
	msg = cross_res->msgs[0];

	status = dsdb_trust_parse_crossref_info(mem_ctx, sam_ctx, msg, &tdo);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}
	talloc_steal(frame, tdo);

	if (_root_trust_tdo != NULL) {
		root_trust_dn = samdb_result_dn(sam_ctx, frame, msg,
						"rootTrust", NULL);
	}
	if (_trust_parent_tdo != NULL) {
		trust_parent_dn = samdb_result_dn(sam_ctx, frame, msg,
						   "trustParent", NULL);
	}

	if (root_trust_dn != NULL) {
		struct ldb_message *root_trust_msg = NULL;

		ret = dsdb_search_one(sam_ctx, frame,
				      &root_trust_msg,
				      root_trust_dn,
				      LDB_SCOPE_BASE,
				      cross_attrs,
				      DSDB_SEARCH_NO_GLOBAL_CATALOG,
				      "(objectClass=crossRef)");
		if (ret != LDB_SUCCESS) {
			status = dsdb_ldb_err_to_ntstatus(ret);
			DEBUG(3, ("Failed to search for %s: %s - %s\n",
				  ldb_dn_get_linearized(root_trust_dn),
				  nt_errstr(status), ldb_errstring(sam_ctx)));
			TALLOC_FREE(frame);
			return status;
		}

		status = dsdb_trust_parse_crossref_info(mem_ctx, sam_ctx,
							root_trust_msg,
							&root_trust_tdo);
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(frame);
			return status;
		}
		talloc_steal(frame, root_trust_tdo);
	}

	if (trust_parent_dn != NULL) {
		struct ldb_message *trust_parent_msg = NULL;

		ret = dsdb_search_one(sam_ctx, frame,
				      &trust_parent_msg,
				      trust_parent_dn,
				      LDB_SCOPE_BASE,
				      cross_attrs,
				      DSDB_SEARCH_NO_GLOBAL_CATALOG,
				      "(objectClass=crossRef)");
		if (ret != LDB_SUCCESS) {
			status = dsdb_ldb_err_to_ntstatus(ret);
			DEBUG(3, ("Failed to search for %s: %s - %s\n",
				  ldb_dn_get_linearized(trust_parent_dn),
				  nt_errstr(status), ldb_errstring(sam_ctx)));
			TALLOC_FREE(frame);
			return status;
		}

		status = dsdb_trust_parse_crossref_info(mem_ctx, sam_ctx,
							trust_parent_msg,
							&trust_parent_tdo);
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(frame);
			return status;
		}
		talloc_steal(frame, trust_parent_tdo);
	}

	*_tdo = talloc_move(mem_ctx, &tdo);
	if (_root_trust_tdo != NULL) {
		*_root_trust_tdo = talloc_move(mem_ctx, &root_trust_tdo);
	}
	if (_trust_parent_tdo != NULL) {
		*_trust_parent_tdo = talloc_move(mem_ctx, &trust_parent_tdo);
	}
	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}

#define DNS_CMP_FIRST_IS_CHILD -2
#define DNS_CMP_FIRST_IS_LESS -1
#define DNS_CMP_MATCH 0
#define DNS_CMP_SECOND_IS_LESS 1
#define DNS_CMP_SECOND_IS_CHILD 2

#define DNS_CMP_IS_NO_MATCH(__cmp) \
	((__cmp == DNS_CMP_FIRST_IS_LESS) || (__cmp == DNS_CMP_SECOND_IS_LESS))

/*
 * this function assumes names are well formed DNS names.
 * it doesn't validate them
 *
 * It allows strings up to a length of UINT16_MAX - 1
 * with up to UINT8_MAX components. On overflow this
 * just returns the result of strcasecmp_m().
 *
 * Trailing dots (only one) are ignored.
 *
 * The DNS names are compared per component, starting from
 * the last one.
 */
static int dns_cmp(const char *s1, const char *s2)
{
	size_t l1 = 0;
	const char *p1 = NULL;
	size_t num_comp1 = 0;
	uint16_t comp1[UINT8_MAX] = {};
	size_t l2 = 0;
	const char *p2 = NULL;
	size_t num_comp2 = 0;
	uint16_t comp2[UINT8_MAX] = {};
	size_t i;

	if (s1 != NULL) {
		l1 = strlen(s1);
	}

	if (s2 != NULL) {
		l2 = strlen(s2);
	}

	/*
	 * trailing '.' are ignored.
	 */
	if (l1 > 1 && s1[l1 - 1] == '.') {
		l1--;
	}
	if (l2 > 1 && s2[l2 - 1] == '.') {
		l2--;
	}

	for (i = 0; i < ARRAY_SIZE(comp1); i++) {
		char *p;

		if (i == 0) {
			p1 = s1;

			if (l1 == 0 && l1 >= UINT16_MAX) {
				/* just use one single component on overflow */
				break;
			}
		}

		comp1[num_comp1++] = PTR_DIFF(p1, s1);

		p = strchr_m(p1, '.');
		if (p == NULL) {
			p1 = NULL;
			break;
		}

		p1 = p + 1;
	}

	if (p1 != NULL) {
		/* just use one single component on overflow */
		num_comp1 = 0;
		comp1[num_comp1++] = 0;
		p1 = NULL;
	}

	for (i = 0; i < ARRAY_SIZE(comp2); i++) {
		char *p;

		if (i == 0) {
			p2 = s2;

			if (l2 == 0 && l2 >= UINT16_MAX) {
				/* just use one single component on overflow */
				break;
			}
		}

		comp2[num_comp2++] = PTR_DIFF(p2, s2);

		p = strchr_m(p2, '.');
		if (p == NULL) {
			p2 = NULL;
			break;
		}

		p2 = p + 1;
	}

	if (p2 != NULL) {
		/* just use one single component on overflow */
		num_comp2 = 0;
		comp2[num_comp2++] = 0;
		p2 = NULL;
	}

	for (i = 0; i < UINT8_MAX; i++) {
		int cmp;

		if (i < num_comp1) {
			size_t idx = num_comp1 - (i + 1);
			p1 = s1 + comp1[idx];
		} else {
			p1 = NULL;
		}

		if (i < num_comp2) {
			size_t idx = num_comp2 - (i + 1);
			p2 = s2 + comp2[idx];
		} else {
			p2 = NULL;
		}

		if (p1 == NULL && p2 == NULL) {
			return DNS_CMP_MATCH;
		}
		if (p1 != NULL && p2 == NULL) {
			return DNS_CMP_FIRST_IS_CHILD;
		}
		if (p1 == NULL && p2 != NULL) {
			return DNS_CMP_SECOND_IS_CHILD;
		}

		cmp = strcasecmp_m(p1, p2);
		if (cmp < 0) {
			return DNS_CMP_FIRST_IS_LESS;
		}
		if (cmp > 0) {
			return DNS_CMP_SECOND_IS_LESS;
		}
	}

	smb_panic(__location__);
	return -1;
}

static int dsdb_trust_find_tln_match_internal(const struct lsa_ForestTrustInformation *info,
					      enum lsa_ForestTrustRecordType type,
					      uint32_t disable_mask,
					      const char *tln)
{
	uint32_t i;

	for (i = 0; i < info->count; i++) {
		struct lsa_ForestTrustRecord *e = info->entries[i];
		struct lsa_StringLarge *t = NULL;
		int cmp;

		if (e == NULL) {
			continue;
		}

		if (e->type != type) {
			continue;
		}

		if (e->flags & disable_mask) {
			continue;
		}

		switch (type) {
		case LSA_FOREST_TRUST_TOP_LEVEL_NAME:
			t = &e->forest_trust_data.top_level_name;
			break;
		case LSA_FOREST_TRUST_TOP_LEVEL_NAME_EX:
			t = &e->forest_trust_data.top_level_name_ex;
			break;
		default:
			break;
		}

		if (t == NULL) {
			continue;
		}

		cmp = dns_cmp(tln, t->string);
		switch (cmp) {
		case DNS_CMP_MATCH:
		case DNS_CMP_FIRST_IS_CHILD:
			return i;
		}
	}

	return -1;
}

static bool dsdb_trust_find_tln_match(const struct lsa_ForestTrustInformation *info,
				      const char *tln)
{
	int m;

	m = dsdb_trust_find_tln_match_internal(info,
					       LSA_FOREST_TRUST_TOP_LEVEL_NAME,
					       LSA_TLN_DISABLED_MASK,
					       tln);
	if (m != -1) {
		return true;
	}

	return false;
}

static bool dsdb_trust_find_tln_ex_match(const struct lsa_ForestTrustInformation *info,
					 const char *tln)
{
	int m;

	m = dsdb_trust_find_tln_match_internal(info,
					       LSA_FOREST_TRUST_TOP_LEVEL_NAME_EX,
					       0,
					       tln);
	if (m != -1) {
		return true;
	}

	return false;
}

static int dsdb_trust_xref_sort_msgs(struct ldb_message **_m1,
				     struct ldb_message **_m2)
{
	struct ldb_message *m1 = *_m1;
	struct ldb_message *m2 = *_m2;
	const char *dns1 = NULL;
	const char *dns2 = NULL;
	int cmp;
	struct ldb_message_element *rootTrust1 = NULL;
	struct ldb_message_element *trustParent1 = NULL;
	struct ldb_message_element *rootTrust2 = NULL;
	struct ldb_message_element *trustParent2 = NULL;

	dns1 = ldb_msg_find_attr_as_string(m1, "dnsRoot", NULL);
	dns2 = ldb_msg_find_attr_as_string(m2, "dnsRoot", NULL);

	cmp = dns_cmp(dns1, dns2);
	switch (cmp) {
	case DNS_CMP_FIRST_IS_CHILD:
		return -1;
	case DNS_CMP_SECOND_IS_CHILD:
		return 1;
	}

	rootTrust1 = ldb_msg_find_element(m1, "rootTrust");
	trustParent1 = ldb_msg_find_element(m1, "trustParent");
	rootTrust2 = ldb_msg_find_element(m2, "rootTrust");
	trustParent2 = ldb_msg_find_element(m2, "trustParent");

	if (rootTrust1 == NULL && trustParent1 == NULL) {
		/* m1 is the forest root */
		return -1;
	}
	if (rootTrust2 == NULL && trustParent2 == NULL) {
		/* m2 is the forest root */
		return 1;
	}

	return cmp;
}

static int dsdb_trust_xref_sort_vals(struct ldb_val *v1,
				     struct ldb_val *v2)
{
	const char *dns1 = (const char *)v1->data;
	const char *dns2 = (const char *)v2->data;

	return dns_cmp(dns1, dns2);
}

NTSTATUS dsdb_trust_xref_forest_info(TALLOC_CTX *mem_ctx,
				     struct ldb_context *sam_ctx,
				     struct lsa_ForestTrustInformation **_info)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct lsa_ForestTrustInformation *info = NULL;
	struct ldb_dn *partitions_dn = NULL;
	const char * const cross_attrs1[] = {
		"uPNSuffixes",
		"msDS-SPNSuffixes",
		NULL,
	};
	struct ldb_result *cross_res1 = NULL;
	struct ldb_message_element *upn_el = NULL;
	struct ldb_message_element *spn_el = NULL;
	struct ldb_message *tln_msg = NULL;
	struct ldb_message_element *tln_el = NULL;
	const char * const cross_attrs2[] = {
		"dnsRoot",
		"nETBIOSName",
		"nCName",
		"rootTrust",
		"trustParent",
		NULL,
	};
	struct ldb_result *cross_res2 = NULL;
	int ret;
	unsigned int i;
	bool restart = false;

	*_info = NULL;
	info = talloc_zero(mem_ctx, struct lsa_ForestTrustInformation);
	if (info == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}
	talloc_steal(frame, info);

	partitions_dn = samdb_partitions_dn(sam_ctx, frame);
	if (partitions_dn == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	ret = dsdb_search_dn(sam_ctx, partitions_dn, &cross_res1,
			     partitions_dn, cross_attrs1, 0);
	if (ret != LDB_SUCCESS) {
		TALLOC_FREE(frame);
		return dsdb_ldb_err_to_ntstatus(ret);
	}

	ret = dsdb_search(sam_ctx, partitions_dn, &cross_res2,
			  partitions_dn, LDB_SCOPE_ONELEVEL,
			  cross_attrs2,
			  DSDB_SEARCH_SHOW_EXTENDED_DN,
			  "(&(objectClass=crossRef)"
			   "(systemFlags:%s:=%u))",
			  LDB_OID_COMPARATOR_AND,
			  SYSTEM_FLAG_CR_NTDS_DOMAIN);
	if (ret != LDB_SUCCESS) {
		TALLOC_FREE(frame);
		return dsdb_ldb_err_to_ntstatus(ret);
	}

	/*
	 * Sort the domains as trees, starting with the forest root
	 */
	TYPESAFE_QSORT(cross_res2->msgs, cross_res2->count,
		       dsdb_trust_xref_sort_msgs);

	upn_el = ldb_msg_find_element(cross_res1->msgs[0], "uPNSuffixes");
	if (upn_el != NULL) {
		upn_el->name = "__tln__";
	}
	spn_el = ldb_msg_find_element(cross_res1->msgs[0], "msDS-SPNSuffixes");
	if (spn_el != NULL) {
		spn_el->name = "__tln__";
	}
	ret = ldb_msg_normalize(sam_ctx, frame, cross_res1->msgs[0], &tln_msg);
	if (ret != LDB_SUCCESS) {
		TALLOC_FREE(frame);
		return dsdb_ldb_err_to_ntstatus(ret);
	}
	tln_el = ldb_msg_find_element(tln_msg, "__tln__");
	if (tln_el != NULL) {
		/*
		 * Sort the domains as trees
		 */
		TYPESAFE_QSORT(tln_el->values, tln_el->num_values,
			       dsdb_trust_xref_sort_vals);
	}

	for (i=0; i < cross_res2->count; i++) {
		struct ldb_message *m = cross_res2->msgs[i];
		const char *dns = NULL;
		const char *netbios = NULL;
		struct ldb_dn *nc_dn = NULL;
		struct dom_sid sid = {};
		struct lsa_ForestTrustRecord e = {};
		struct lsa_ForestTrustDomainInfo *d = NULL;
		struct lsa_StringLarge *t = NULL;
		bool match = false;
		NTSTATUS status;

		dns = ldb_msg_find_attr_as_string(m, "dnsRoot", NULL);
		if (dns == NULL) {
			TALLOC_FREE(frame);
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		netbios = ldb_msg_find_attr_as_string(m, "nETBIOSName", NULL);
		if (netbios == NULL) {
			TALLOC_FREE(frame);
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		nc_dn = samdb_result_dn(sam_ctx, m, m, "ncName", NULL);
		if (nc_dn == NULL) {
			TALLOC_FREE(frame);
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		status = dsdb_get_extended_dn_sid(nc_dn, &sid, "SID");
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(frame);
			return status;
		}

		match = dsdb_trust_find_tln_match(info, dns);
		if (!match) {
			/*
			 * First the TOP_LEVEL_NAME, if required
			 */
			e = (struct lsa_ForestTrustRecord) {
				.flags = 0,
				.type = LSA_FOREST_TRUST_TOP_LEVEL_NAME,
				.time = 0, /* so far always 0 in traces. */
			};

			t = &e.forest_trust_data.top_level_name;
			t->string = dns;

			status = dsdb_trust_forest_info_add_record(info, &e);
			if (!NT_STATUS_IS_OK(status)) {
				TALLOC_FREE(frame);
				return status;
			}
		}

		/*
		 * Then the DOMAIN_INFO
		 */
		e = (struct lsa_ForestTrustRecord) {
			.flags = 0,
			.type = LSA_FOREST_TRUST_DOMAIN_INFO,
			.time = 0, /* so far always 0 in traces. */
		};
		d = &e.forest_trust_data.domain_info;
		d->domain_sid = &sid;
		d->dns_domain_name.string = dns;
		d->netbios_domain_name.string = netbios;

		status = dsdb_trust_forest_info_add_record(info, &e);
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(frame);
			return status;
		}
	}

	for (i=0; (tln_el != NULL) && i < tln_el->num_values; i++) {
		const struct ldb_val *v = &tln_el->values[i];
		const char *dns = (const char *)v->data;
		struct lsa_ForestTrustRecord e = {};
		struct lsa_StringLarge *t = NULL;
		bool match = false;
		NTSTATUS status;

		if (dns == NULL) {
			TALLOC_FREE(frame);
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		match = dsdb_trust_find_tln_match(info, dns);
		if (match) {
			continue;
		}

		/*
		 * an additional the TOP_LEVEL_NAME
		 */
		e = (struct lsa_ForestTrustRecord) {
			.flags = 0,
			.type = LSA_FOREST_TRUST_TOP_LEVEL_NAME,
			.time = 0, /* so far always 0 in traces. */
		};
		t = &e.forest_trust_data.top_level_name;
		t->string = dns;

		status = dsdb_trust_forest_info_add_record(info, &e);
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(frame);
			return status;
		}
	}

	for (i=0; i < info->count; restart ? i=0 : i++) {
		struct lsa_ForestTrustRecord *tr = info->entries[i];
		const struct lsa_StringLarge *ts = NULL;
		uint32_t c;

		restart = false;

		if (tr->type != LSA_FOREST_TRUST_TOP_LEVEL_NAME) {
			continue;
		}

		ts = &tr->forest_trust_data.top_level_name;

		for (c = i + 1; c < info->count; c++) {
			struct lsa_ForestTrustRecord *cr = info->entries[c];
			const struct lsa_StringLarge *cs = NULL;
			uint32_t j;
			int cmp;

			if (cr->type != LSA_FOREST_TRUST_TOP_LEVEL_NAME) {
				continue;
			}

			cs = &cr->forest_trust_data.top_level_name;

			cmp = dns_cmp(ts->string, cs->string);
			if (DNS_CMP_IS_NO_MATCH(cmp)) {
				continue;
			}
			if (cmp != DNS_CMP_FIRST_IS_CHILD) {
				/* can't happen ... */
				continue;
			}

			ts = NULL;
			tr = NULL;
			TALLOC_FREE(info->entries[i]);
			info->entries[i] = info->entries[c];

			for (j = c + 1; j < info->count; j++) {
				info->entries[j-1] = info->entries[j];
			}
			info->count -= 1;
			restart = true;
			break;
		}
	}

	*_info = talloc_move(mem_ctx, &info);
	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}

NTSTATUS dsdb_trust_parse_tdo_info(TALLOC_CTX *mem_ctx,
				   struct ldb_message *m,
				   struct lsa_TrustDomainInfoInfoEx **_tdo)
{
	struct lsa_TrustDomainInfoInfoEx *tdo = NULL;
	const char *dns = NULL;
	const char *netbios = NULL;

	*_tdo = NULL;

	tdo = talloc_zero(mem_ctx, struct lsa_TrustDomainInfoInfoEx);
	if (tdo == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	dns = ldb_msg_find_attr_as_string(m, "trustPartner", NULL);
	if (dns == NULL) {
		TALLOC_FREE(tdo);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	tdo->domain_name.string = talloc_strdup(tdo, dns);
	if (tdo->domain_name.string == NULL) {
		TALLOC_FREE(tdo);
		return NT_STATUS_NO_MEMORY;
	}

	netbios = ldb_msg_find_attr_as_string(m, "flatName", NULL);
	if (netbios == NULL) {
		TALLOC_FREE(tdo);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	tdo->netbios_name.string = talloc_strdup(tdo, netbios);
	if (tdo->netbios_name.string == NULL) {
		TALLOC_FREE(tdo);
		return NT_STATUS_NO_MEMORY;
	}

	tdo->sid = samdb_result_dom_sid(tdo, m, "securityIdentifier");
	if (tdo->sid == NULL) {
		TALLOC_FREE(tdo);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	tdo->trust_type = ldb_msg_find_attr_as_uint(m, "trustType", 0);
	tdo->trust_direction = ldb_msg_find_attr_as_uint(m, "trustDirection", 0);
	tdo->trust_attributes = ldb_msg_find_attr_as_uint(m, "trustAttributes", 0);

	*_tdo = tdo;
	return NT_STATUS_OK;
}

NTSTATUS dsdb_trust_parse_forest_info(TALLOC_CTX *mem_ctx,
				      struct ldb_message *m,
				      struct ForestTrustInfo **_fti)
{
	const struct ldb_val *ft_blob = NULL;
	struct ForestTrustInfo *fti = NULL;
	enum ndr_err_code ndr_err;

	*_fti = NULL;

	ft_blob = ldb_msg_find_ldb_val(m, "msDS-TrustForestTrustInfo");
	if (ft_blob == NULL) {
		return NT_STATUS_NOT_FOUND;
	}

	fti = talloc_zero(mem_ctx, struct ForestTrustInfo);
	if (fti == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/* ldb_val is equivalent to DATA_BLOB */
	ndr_err = ndr_pull_struct_blob_all(ft_blob, fti, fti,
				(ndr_pull_flags_fn_t)ndr_pull_ForestTrustInfo);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		TALLOC_FREE(fti);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	*_fti = fti;
	return NT_STATUS_OK;
}

NTSTATUS dsdb_trust_search_tdos(struct ldb_context *sam_ctx,
				const char *exclude,
				const char * const *attrs,
				TALLOC_CTX *mem_ctx,
				struct ldb_result **res)
{
	TALLOC_CTX *frame = talloc_stackframe();
	int ret;
	struct ldb_dn *system_dn = NULL;
	const char *filter = NULL;
	char *exclude_encoded = NULL;

	*res = NULL;

	system_dn = ldb_dn_copy(frame, ldb_get_default_basedn(sam_ctx));
	if (system_dn == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	if (!ldb_dn_add_child_fmt(system_dn, "CN=System")) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	if (exclude != NULL) {
		exclude_encoded = ldb_binary_encode_string(frame, exclude);
		if (exclude_encoded == NULL) {
			TALLOC_FREE(frame);
			return NT_STATUS_NO_MEMORY;
		}

		filter = talloc_asprintf(frame,
				"(&(objectClass=trustedDomain)"
				  "(!(|(trustPartner=%s)(flatName=%s)))"
				")",
				exclude_encoded, exclude_encoded);
		if (filter == NULL) {
			TALLOC_FREE(frame);
			return NT_STATUS_NO_MEMORY;
		}
	} else {
		filter = "(objectClass=trustedDomain)";
	}

	ret = dsdb_search(sam_ctx, mem_ctx, res,
			  system_dn,
			  LDB_SCOPE_ONELEVEL, attrs,
			  DSDB_SEARCH_NO_GLOBAL_CATALOG,
			  "%s", filter);
	if (ret != LDB_SUCCESS) {
		NTSTATUS status = dsdb_ldb_err_to_ntstatus(ret);
		DEBUG(3, ("Failed to search for %s: %s - %s\n",
			  filter, nt_errstr(status), ldb_errstring(sam_ctx)));
		TALLOC_FREE(frame);
		return status;
	}

	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}

struct dsdb_trust_routing_domain;

struct dsdb_trust_routing_table {
	struct dsdb_trust_routing_domain *domains;
};

struct dsdb_trust_routing_domain {
	struct dsdb_trust_routing_domain *prev, *next;

	struct lsa_TrustDomainInfoInfoEx *tdo;
	struct lsa_ForestTrustInformation *fti;
};

NTSTATUS dsdb_trust_routing_table_load(struct ldb_context *sam_ctx,
				       TALLOC_CTX *mem_ctx,
				       struct dsdb_trust_routing_table **_table)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct dsdb_trust_routing_table *table;
	struct dsdb_trust_routing_domain *d = NULL;
	struct ldb_dn *domain_dn = NULL;
	struct lsa_TrustDomainInfoInfoEx *root_trust_tdo = NULL;
	struct lsa_TrustDomainInfoInfoEx *trust_parent_tdo = NULL;
	struct lsa_TrustDomainInfoInfoEx *root_direction_tdo = NULL;
	const char * const trusts_attrs[] = {
		"securityIdentifier",
		"flatName",
		"trustPartner",
		"trustAttributes",
		"trustDirection",
		"trustType",
		"msDS-TrustForestTrustInfo",
		NULL
	};
	struct ldb_result *trusts_res = NULL;
	unsigned int i;
	NTSTATUS status;

	*_table = NULL;

	domain_dn = ldb_get_default_basedn(sam_ctx);
	if (domain_dn == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_INTERNAL_ERROR;
	}

	table = talloc_zero(mem_ctx, struct dsdb_trust_routing_table);
	if (table == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}
	talloc_steal(frame, table);

	d = talloc_zero(table, struct dsdb_trust_routing_domain);
	if (d == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	status = dsdb_trust_crossref_tdo_info(d, sam_ctx,
					      domain_dn, NULL,
					      &d->tdo,
					      &root_trust_tdo,
					      &trust_parent_tdo);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	if (root_trust_tdo != NULL) {
		root_direction_tdo = root_trust_tdo;
	} else if (trust_parent_tdo != NULL) {
		root_direction_tdo = trust_parent_tdo;
	}

	if (root_direction_tdo == NULL) {
		/* we're the forest root */
		status = dsdb_trust_xref_forest_info(d, sam_ctx, &d->fti);
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(frame);
			return status;
		}
	}

	DLIST_ADD(table->domains, d);

	status = dsdb_trust_search_tdos(sam_ctx, NULL, trusts_attrs,
					frame, &trusts_res);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	for (i = 0; i < trusts_res->count; i++) {
		bool ok;
		int cmp;

		d = talloc_zero(table, struct dsdb_trust_routing_domain);
		if (d == NULL) {
			TALLOC_FREE(frame);
			return NT_STATUS_NO_MEMORY;
		}

		status = dsdb_trust_parse_tdo_info(d,
						   trusts_res->msgs[i],
						   &d->tdo);
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(frame);
			return status;
		}

		DLIST_ADD_END(table->domains, d, NULL);

		if (d->tdo->trust_attributes & LSA_TRUST_ATTRIBUTE_FOREST_TRANSITIVE) {
			struct ForestTrustInfo *fti = NULL;

			status = dsdb_trust_parse_forest_info(frame,
							      trusts_res->msgs[i],
							      &fti);
			if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
				fti = NULL;
				status = NT_STATUS_OK;
			}
			if (!NT_STATUS_IS_OK(status)) {
				TALLOC_FREE(frame);
				return status;
			}

			if (fti == NULL) {
				continue;
			}

			status = dsdb_trust_forest_info_to_lsa(d, fti, &d->fti);
			if (!NT_STATUS_IS_OK(status)) {
				TALLOC_FREE(frame);
				return status;
			}

			continue;
		}

		if (!(d->tdo->trust_attributes & LSA_TRUST_ATTRIBUTE_WITHIN_FOREST)) {
			continue;
		}

		if (root_direction_tdo == NULL) {
			continue;
		}

		ok = dom_sid_equal(root_direction_tdo->sid, d->tdo->sid);
		if (!ok) {
			continue;
		}

		cmp = strcasecmp_m(root_direction_tdo->netbios_name.string,
				   d->tdo->netbios_name.string);
		if (cmp != 0) {
			continue;
		}

		cmp = strcasecmp_m(root_direction_tdo->domain_name.string,
				   d->tdo->domain_name.string);
		if (cmp != 0) {
			continue;
		}

		/* this our route to the forest root */
		status = dsdb_trust_xref_forest_info(d, sam_ctx, &d->fti);
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(frame);
			return status;
		}
	}

	*_table = talloc_move(mem_ctx, &table);
	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}

static void dsdb_trust_update_best_tln(
	const struct dsdb_trust_routing_domain **best_d,
	const char **best_tln,
	const struct dsdb_trust_routing_domain *d,
	const char *tln)
{
	int cmp;

	if (*best_tln == NULL) {
		*best_tln = tln;
		*best_d = d;
		return;
	}

	cmp = dns_cmp(*best_tln, tln);
	if (cmp != DNS_CMP_FIRST_IS_CHILD) {
		return;
	}

	*best_tln = tln;
	*best_d = d;
}

const struct lsa_TrustDomainInfoInfoEx *dsdb_trust_routing_by_name(
		const struct dsdb_trust_routing_table *table,
		const char *name)
{
	const struct dsdb_trust_routing_domain *best_d = NULL;
	const char *best_tln = NULL;
	const struct dsdb_trust_routing_domain *d = NULL;

	if (name == NULL) {
		return NULL;
	}

	for (d = table->domains; d != NULL; d = d->next) {
		bool transitive = false;
		bool allow_netbios = false;
		bool exclude = false;
		uint32_t i;

		if (d->tdo->trust_type != LSA_TRUST_TYPE_UPLEVEL) {
			/*
			 * Only uplevel trusts have top level names
			 */
			continue;
		}

		if (d->tdo->trust_attributes & LSA_TRUST_ATTRIBUTE_WITHIN_FOREST) {
			transitive = true;
		}

		if (d->tdo->trust_attributes & LSA_TRUST_ATTRIBUTE_FOREST_TRANSITIVE) {
			transitive = true;
		}

		if (d->tdo->trust_attributes & LSA_TRUST_ATTRIBUTE_NON_TRANSITIVE) {
			transitive = false;
		}

		if (d->tdo->trust_type != LSA_TRUST_TYPE_UPLEVEL) {
			transitive = false;
		}

		switch (d->tdo->trust_type) {
		case LSA_TRUST_TYPE_UPLEVEL:
			if (d->tdo->trust_attributes & LSA_TRUST_ATTRIBUTE_UPLEVEL_ONLY) {
				break;
			}
			allow_netbios = true;
			break;
		case LSA_TRUST_TYPE_DOWNLEVEL:
			allow_netbios = true;
			break;
		default:
			allow_netbios = false;
			break;
		}

		if (!transitive || d->fti == NULL) {
			int cmp;

			if (allow_netbios) {
				cmp = dns_cmp(name, d->tdo->netbios_name.string);
				if (cmp == DNS_CMP_MATCH) {
					/*
					 * exact match
					 */
					return d->tdo;
				}
			}

			cmp = dns_cmp(name, d->tdo->domain_name.string);
			if (cmp == DNS_CMP_MATCH) {
				/*
				 * exact match
				 */
				return d->tdo;
			}
			if (cmp != DNS_CMP_FIRST_IS_CHILD) {
				continue;
			}

			if (!transitive) {
				continue;
			}

			dsdb_trust_update_best_tln(&best_d, &best_tln, d,
						   d->tdo->domain_name.string);
			continue;
		}

		exclude = dsdb_trust_find_tln_ex_match(d->fti, name);
		if (exclude) {
			continue;
		}

		for (i = 0; i < d->fti->count; i++ ) {
			const struct lsa_ForestTrustRecord *f = d->fti->entries[i];
			const struct lsa_ForestTrustDomainInfo *di = NULL;
			const char *fti_nbt = NULL;
			int cmp;

			if (!allow_netbios) {
				break;
			}

			if (f == NULL) {
				/* broken record */
				continue;
			}

			if (f->type != LSA_FOREST_TRUST_DOMAIN_INFO) {
				continue;
			}

			if (f->flags & LSA_NB_DISABLED_MASK) {
				/*
				 * any flag disables the entry.
				 */
				continue;
			}

			di = &f->forest_trust_data.domain_info;
			fti_nbt = di->netbios_domain_name.string;
			if (fti_nbt == NULL) {
				/* broken record */
				continue;
			}

			cmp = dns_cmp(name, fti_nbt);
			if (cmp == DNS_CMP_MATCH) {
				/*
				 * exact match
				 */
				return d->tdo;
			}
		}

		for (i = 0; i < d->fti->count; i++ ) {
			const struct lsa_ForestTrustRecord *f = d->fti->entries[i];
			const union lsa_ForestTrustData *u = NULL;
			const char *fti_tln = NULL;
			int cmp;

			if (f == NULL) {
				/* broken record */
				continue;
			}

			if (f->type != LSA_FOREST_TRUST_TOP_LEVEL_NAME) {
				continue;
			}

			if (f->flags & LSA_TLN_DISABLED_MASK) {
				/*
				 * any flag disables the entry.
				 */
				continue;
			}

			u = &f->forest_trust_data;
			fti_tln = u->top_level_name.string;
			if (fti_tln == NULL) {
				continue;
			}

			cmp = dns_cmp(name, fti_tln);
			switch (cmp) {
			case DNS_CMP_MATCH:
			case DNS_CMP_FIRST_IS_CHILD:
				dsdb_trust_update_best_tln(&best_d, &best_tln,
							   d, fti_tln);
				break;
			default:
				break;
			}
		}
	}

	if (best_d != NULL) {
		return best_d->tdo;
	}

	return NULL;
}
