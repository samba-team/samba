/*
   Unix SMB/CIFS implementation.

   DNS Server

   Copyright (C) Amitay Isaacs 2011

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
#include "dnsserver.h"
#include "lib/util/dlinklist.h"
#include "librpc/gen_ndr/ndr_dnsp.h"

struct dnsserver_zone *dnsserver_db_enumerate_zones(TALLOC_CTX *mem_ctx,
						struct ldb_context *samdb,
						bool is_forest)
{
	TALLOC_CTX *tmp_ctx;
	const char *domain_prefix = "DC=DomainDnsZones";
	const char *forest_prefix = "DC=ForestDnsZones";
	const char *prefix;
	const char * const attrs[] = {"name", NULL};
	struct ldb_dn *dn_base, *partition_dn, *dn;
	struct ldb_result *res;
	struct dnsserver_zone *zones, *z;
	int i, ret;

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		return NULL;
	}

	if (is_forest) {
		dn_base = ldb_get_root_basedn(samdb);
	} else {
		dn_base = ldb_get_default_basedn(samdb);
	}

	partition_dn = ldb_dn_copy(tmp_ctx, dn_base);
	if (partition_dn == NULL) {
		goto failed;
	}

	if (is_forest) {
		prefix = forest_prefix;
	} else {
		prefix = domain_prefix;
	}

	if (!ldb_dn_add_child_fmt(partition_dn, "%s", prefix)) {
		goto failed;
	}

	dn = ldb_dn_copy(tmp_ctx, partition_dn);
	if (dn == NULL) {
		goto failed;
	}
	if (!ldb_dn_add_child_fmt(dn, "CN=MicrosoftDNS")) {
		goto failed;
	}

	ret = ldb_search(samdb, tmp_ctx, &res, dn, LDB_SCOPE_SUBTREE,
			  attrs, "(&(objectClass=dnsZone)(!(name=RootDNSServers)))");
	if (ret != LDB_SUCCESS) {
		DEBUG(0, ("dnsserver: Failed to find DNS Zones in %s\n",
			ldb_dn_get_linearized(dn)));
		goto failed;
	}

	zones = NULL;
	for(i=0; i<res->count; i++) {
		z = talloc_zero(mem_ctx, struct dnsserver_zone);
		if (z == NULL) {
			goto failed;
		}

		z->name = talloc_strdup(z,
				ldb_msg_find_attr_as_string(res->msgs[i], "name", NULL));
		DEBUG(2, ("dnsserver: Found DNS zone %s\n", z->name));
		z->zone_dn = talloc_steal(z, res->msgs[i]->dn);
		z->partition_dn = talloc_steal(z, partition_dn);

		DLIST_ADD_END(zones, z, NULL);
	}

	return zones;

failed:
	talloc_free(tmp_ctx);
	return NULL;
}


static unsigned int dnsserver_update_soa(TALLOC_CTX *mem_ctx,
				struct ldb_context *samdb,
				struct dnsserver_zone *z)
{
	const char * const attrs[] = { "dnsRecord", NULL };
	struct ldb_result *res;
	struct dnsp_DnssrvRpcRecord rec;
	struct ldb_message_element *el;
	enum ndr_err_code ndr_err;
	int ret, i, serial = -1;
	NTTIME t;

	unix_to_nt_time(&t, time(NULL));
	t /= 10*1000*1000; /* convert to seconds (NT time is in 100ns units) */
	t /= 3600;         /* convert to hours */

	ret = ldb_search(samdb, mem_ctx, &res, z->zone_dn, LDB_SCOPE_ONELEVEL, attrs,
			"(&(objectClass=dnsNode)(name=@))");
	if (ret != LDB_SUCCESS || res->count == 0) {
		return -1;
	}

	el = ldb_msg_find_element(res->msgs[0], "dnsRecord");
	if (el == NULL) {
		return -1;
	}

	for (i=0; i<el->num_values; i++) {
		ndr_err = ndr_pull_struct_blob(&el->values[i], mem_ctx, &rec,
					(ndr_pull_flags_fn_t)ndr_pull_dnsp_DnssrvRpcRecord);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			continue;
		}

		if (rec.wType == DNS_TYPE_SOA) {
			serial = rec.data.soa.serial + 1;
			rec.dwSerial = serial;
			rec.dwTimeStamp = (uint32_t)t;
			rec.data.soa.serial = serial;

			ndr_err = ndr_push_struct_blob(&el->values[i], mem_ctx, &rec,
					(ndr_push_flags_fn_t)ndr_push_dnsp_DnssrvRpcRecord);
			if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
				return -1;
			}
			break;
		}
	}

	if (serial != -1) {
		el->flags = LDB_FLAG_MOD_REPLACE;
		ret = ldb_modify(samdb, res->msgs[0]);
		if (ret != LDB_SUCCESS) {
			return -1;
		}
	}

	return serial;
}


static WERROR dnsserver_db_do_add_rec(TALLOC_CTX *mem_ctx,
				struct ldb_context *samdb,
				struct ldb_dn *dn,
				struct dnsp_DnssrvRpcRecord *rec)
{
	struct ldb_message *msg;
	struct ldb_val v;
	int ret;
	enum ndr_err_code ndr_err;

	msg = ldb_msg_new(mem_ctx);
	W_ERROR_HAVE_NO_MEMORY(msg);

	msg->dn = dn;
	ret = ldb_msg_add_string(msg, "objectClass", "dnsNode");
	if (ret != LDB_SUCCESS) {
		return WERR_NOMEM;
	}

	if (rec) {
		ndr_err = ndr_push_struct_blob(&v, mem_ctx, rec,
				(ndr_push_flags_fn_t)ndr_push_dnsp_DnssrvRpcRecord);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			return WERR_GENERAL_FAILURE;
		}

		ret = ldb_msg_add_value(msg, "dnsRecord", &v, NULL);
		if (ret != LDB_SUCCESS) {
			return WERR_NOMEM;
		}
	}

	ret = ldb_add(samdb, msg);
	if (ret != LDB_SUCCESS) {
		return WERR_INTERNAL_DB_ERROR;
	}

	return WERR_OK;
}


WERROR dnsserver_db_add_empty_node(TALLOC_CTX *mem_ctx,
					struct ldb_context *samdb,
					struct dnsserver_zone *z,
					const char *name)
{
	const char * const attrs[] = { "name", NULL };
	struct ldb_result *res;
	struct ldb_dn *dn;
	int ret;

	ret = ldb_search(samdb, mem_ctx, &res, z->zone_dn, LDB_SCOPE_BASE, attrs,
			"(&(objectClass=dnsNode)(name=%s))", name);
	if (ret != LDB_SUCCESS) {
		return WERR_INTERNAL_DB_ERROR;
	}

	if (res->count > 0) {
		talloc_free(res);
		return WERR_DNS_ERROR_RECORD_ALREADY_EXISTS;
	}

	dn = ldb_dn_copy(mem_ctx, z->zone_dn);
	W_ERROR_HAVE_NO_MEMORY(dn);

	if (!ldb_dn_add_child_fmt(dn, "DC=%s", name)) {
		return WERR_NOMEM;
	}

	return dnsserver_db_do_add_rec(mem_ctx, samdb, dn, NULL);
}


WERROR dnsserver_db_add_record(TALLOC_CTX *mem_ctx,
					struct ldb_context *samdb,
					struct dnsserver_zone *z,
					const char *name,
					struct DNS_RPC_RECORD *add_record)
{
	const char * const attrs[] = { "dnsRecord", NULL };
	struct ldb_result *res;
	struct dnsp_DnssrvRpcRecord *rec;
	struct ldb_message_element *el;
	struct ldb_dn *dn;
	enum ndr_err_code ndr_err;
	NTTIME t;
	int ret, i;
	int serial;

	rec = dns_to_dnsp_copy(mem_ctx, add_record);
	W_ERROR_HAVE_NO_MEMORY(rec);

	serial = dnsserver_update_soa(mem_ctx, samdb, z);
	if (serial < 0) {
		return WERR_INTERNAL_DB_ERROR;
	}

	unix_to_nt_time(&t, time(NULL));
	t /= 10*1000*1000; /* convert to seconds (NT time is in 100ns units) */
	t /= 3600;         /* convert to hours */

	rec->dwSerial = serial;
	rec->dwTimeStamp = t;

	ret = ldb_search(samdb, mem_ctx, &res, z->zone_dn, LDB_SCOPE_ONELEVEL, attrs,
			"(&(objectClass=dnsNode)(name=%s))", name);
	if (ret != LDB_SUCCESS) {
		return WERR_INTERNAL_DB_ERROR;
	}

	if (res->count == 0) {
		dn = dnsserver_name_to_dn(mem_ctx, z, name);
		W_ERROR_HAVE_NO_MEMORY(dn);

		return dnsserver_db_do_add_rec(mem_ctx, samdb, dn, rec);
	}

	el = ldb_msg_find_element(res->msgs[0], "dnsRecord");
	if (el == NULL) {
		ret = ldb_msg_add_empty(res->msgs[0], "dnsRecord", 0, &el);
		if (ret != LDB_SUCCESS) {
			return WERR_NOMEM;
		}
	}

	for (i=0; i<el->num_values; i++) {
		struct dnsp_DnssrvRpcRecord rec2;

		ndr_err = ndr_pull_struct_blob(&el->values[i], mem_ctx, &rec2,
						(ndr_pull_flags_fn_t)ndr_pull_dnsp_DnssrvRpcRecord);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			return WERR_GENERAL_FAILURE;
		}

		if (dns_record_match(rec, &rec2)) {
			break;
		}
	}
	if (i < el->num_values) {
		return WERR_DNS_ERROR_RECORD_ALREADY_EXISTS;
	}
	if (i == el->num_values) {
		/* adding a new value */
		el->values = talloc_realloc(el, el->values, struct ldb_val, el->num_values+1);
		W_ERROR_HAVE_NO_MEMORY(el->values);
		el->num_values++;
	}

	ndr_err = ndr_push_struct_blob(&el->values[i], mem_ctx, rec,
					(ndr_push_flags_fn_t)ndr_push_dnsp_DnssrvRpcRecord);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return WERR_GENERAL_FAILURE;
	}

	el->flags = LDB_FLAG_MOD_REPLACE;
	ret = ldb_modify(samdb, res->msgs[0]);
	if (ret != LDB_SUCCESS) {
		return WERR_INTERNAL_DB_ERROR;
	}

	return WERR_OK;
}

WERROR dnsserver_db_update_record(TALLOC_CTX *mem_ctx,
					struct ldb_context *samdb,
					struct dnsserver_zone *z,
					const char *name,
					struct DNS_RPC_RECORD *add_record,
					struct DNS_RPC_RECORD *del_record)
{
	const char * const attrs[] = { "dnsRecord", NULL };
	struct ldb_result *res;
	struct dnsp_DnssrvRpcRecord *arec, *drec;
	struct ldb_message_element *el;
	enum ndr_err_code ndr_err;
	NTTIME t;
	int ret, i;
	int serial;

	serial = dnsserver_update_soa(mem_ctx, samdb, z);
	if (serial < 0) {
		return WERR_INTERNAL_DB_ERROR;
	}

	arec = dns_to_dnsp_copy(mem_ctx, add_record);
	W_ERROR_HAVE_NO_MEMORY(arec);

	drec = dns_to_dnsp_copy(mem_ctx, del_record);
	W_ERROR_HAVE_NO_MEMORY(drec);

	unix_to_nt_time(&t, time(NULL));
	t /= 10*1000*1000;

	arec->dwSerial = serial;
	arec->dwTimeStamp = t;

	ret = ldb_search(samdb, mem_ctx, &res, z->zone_dn, LDB_SCOPE_ONELEVEL, attrs,
			"(&(objectClass=dnsNode)(name=%s))", name);
	if (ret != LDB_SUCCESS) {
		return WERR_INTERNAL_DB_ERROR;
	}

	if (res->count == 0) {
		return WERR_DNS_ERROR_RECORD_DOES_NOT_EXIST;
	}

	el = ldb_msg_find_element(res->msgs[0], "dnsRecord");
	if (el == NULL || el->num_values == 0) {
		return WERR_DNS_ERROR_RECORD_DOES_NOT_EXIST;
	}

	for (i=0; i<el->num_values; i++) {
		struct dnsp_DnssrvRpcRecord rec2;

		ndr_err = ndr_pull_struct_blob(&el->values[i], mem_ctx, &rec2,
						(ndr_pull_flags_fn_t)ndr_pull_dnsp_DnssrvRpcRecord);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			return WERR_GENERAL_FAILURE;
		}

		if (dns_record_match(arec, &rec2)) {
			break;
		}
	}
	if (i < el->num_values) {
		return WERR_DNS_ERROR_RECORD_ALREADY_EXISTS;
	}


	for (i=0; i<el->num_values; i++) {
		struct dnsp_DnssrvRpcRecord rec2;

		ndr_err = ndr_pull_struct_blob(&el->values[i], mem_ctx, &rec2,
						(ndr_pull_flags_fn_t)ndr_pull_dnsp_DnssrvRpcRecord);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			return WERR_GENERAL_FAILURE;
		}

		if (dns_record_match(drec, &rec2)) {
			break;
		}
	}
	if (i == el->num_values) {
		return WERR_DNS_ERROR_RECORD_DOES_NOT_EXIST;
	}

	ndr_err = ndr_push_struct_blob(&el->values[i], mem_ctx, arec,
					(ndr_push_flags_fn_t)ndr_push_dnsp_DnssrvRpcRecord);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return WERR_GENERAL_FAILURE;
	}

	el->flags = LDB_FLAG_MOD_REPLACE;
	ret = ldb_modify(samdb, res->msgs[0]);
	if (ret != LDB_SUCCESS) {
		return WERR_INTERNAL_DB_ERROR;
	}

	return WERR_OK;
}

WERROR dnsserver_db_delete_record(TALLOC_CTX *mem_ctx,
					struct ldb_context *samdb,
					struct dnsserver_zone *z,
					const char *name,
					struct DNS_RPC_RECORD *del_record)
{
	const char * const attrs[] = { "dnsRecord", NULL };
	struct ldb_result *res;
	struct dnsp_DnssrvRpcRecord *rec;
	struct ldb_message_element *el;
	enum ndr_err_code ndr_err;
	int ret, i;
	int serial;

	serial = dnsserver_update_soa(mem_ctx, samdb, z);
	if (serial < 0) {
		return WERR_INTERNAL_DB_ERROR;
	}

	rec = dns_to_dnsp_copy(mem_ctx, del_record);
	W_ERROR_HAVE_NO_MEMORY(rec);

	ret = ldb_search(samdb, mem_ctx, &res, z->zone_dn, LDB_SCOPE_ONELEVEL, attrs,
			"(&(objectClass=dnsNode)(name=%s))", name);
	if (ret != LDB_SUCCESS) {
		return WERR_INTERNAL_DB_ERROR;
	}

	if (res->count == 0) {
		return WERR_DNS_ERROR_RECORD_DOES_NOT_EXIST;
	}

	el = ldb_msg_find_element(res->msgs[0], "dnsRecord");
	if (el == NULL || el->num_values == 0) {
		return WERR_DNS_ERROR_RECORD_DOES_NOT_EXIST;
	}

	for (i=0; i<el->num_values; i++) {
		struct dnsp_DnssrvRpcRecord rec2;

		ndr_err = ndr_pull_struct_blob(&el->values[i], mem_ctx, &rec2,
						(ndr_pull_flags_fn_t)ndr_pull_dnsp_DnssrvRpcRecord);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			return WERR_GENERAL_FAILURE;
		}

		if (dns_record_match(rec, &rec2)) {
			break;
		}
	}
	if (i == el->num_values) {
		return WERR_DNS_ERROR_RECORD_DOES_NOT_EXIST;
	}
	if (i < el->num_values-1) {
		memmove(&el->values[i], &el->values[i+1], sizeof(el->values[0])*((el->num_values-1)-i));
	}
	el->num_values--;

	if (el->num_values == 0) {
		ret = ldb_delete(samdb, res->msgs[0]->dn);
	} else {
		el->flags = LDB_FLAG_MOD_REPLACE;
		ret = ldb_modify(samdb, res->msgs[0]);
	}
	if (ret != LDB_SUCCESS) {
		return WERR_INTERNAL_DB_ERROR;
	}

	return WERR_OK;
}
