/*
   Unix SMB/CIFS implementation.

   bind9 dlz driver for Samba

   Copyright (C) 2010 Andrew Tridgell

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
#include "talloc.h"
#include "param/param.h"
#include "dsdb/samdb/samdb.h"
#include "dsdb/common/util.h"
#include "auth/session.h"
#include "gen_ndr/ndr_dnsp.h"
#include "dlz_bind9.h"

struct dlz_bind9_data {
	struct ldb_context *samdb;
	struct tevent_context *ev_ctx;
	struct loadparm_context *lp;

	/* helper functions from the dlz_dlopen driver */
	void (*log)(int level, const char *fmt, ...);
	isc_result_t (*putrr)(dns_sdlzlookup_t *handle, const char *type,
			      dns_ttl_t ttl, const char *data);
	isc_result_t (*putnamedrr)(dns_sdlzlookup_t *handle, const char *name,
				   const char *type, dns_ttl_t ttl, const char *data);
};

/*
  return the version of the API
 */
_PUBLIC_ int dlz_version(unsigned int *flags)
{
	return DLZ_DLOPEN_VERSION;
}

/*
   remember a helper function from the bind9 dlz_dlopen driver
 */
static void b9_add_helper(struct dlz_bind9_data *state, const char *helper_name, void *ptr)
{
	if (strcmp(helper_name, "log") == 0) {
		state->log = ptr;
	}
	if (strcmp(helper_name, "putrr") == 0) {
		state->putrr = ptr;
	}
	if (strcmp(helper_name, "putnamedrr") == 0) {
		state->putnamedrr = ptr;
	}
}

/*
  format a record for bind9
 */
static bool b9_format(struct dlz_bind9_data *state,
		      TALLOC_CTX *mem_ctx,
		      struct dnsp_DnssrvRpcRecord *rec,
		      const char **type, const char **data)
{
	switch (rec->wType) {
	case DNS_TYPE_A:
		*type = "a";
		*data = rec->data.ipv4;
		break;

	case DNS_TYPE_AAAA:
		*type = "aaaa";
		*data = rec->data.ipv6;
		break;

	case DNS_TYPE_CNAME:
		*type = "cname";
		*data = rec->data.cname;
		break;

	case DNS_TYPE_TXT:
		*type = "txt";
		*data = rec->data.txt;
		break;

	case DNS_TYPE_PTR:
		*type = "ptr";
		*data = rec->data.ptr;
		break;

	case DNS_TYPE_SRV:
		*type = "srv";
		*data = talloc_asprintf(mem_ctx, "%u %u %u %s",
					rec->data.srv.wPriority,
					rec->data.srv.wWeight,
					rec->data.srv.wPort,
					rec->data.srv.nameTarget);
		break;

	case DNS_TYPE_MX:
		*type = "mx";
		*data = talloc_asprintf(mem_ctx, "%u %s",
					rec->data.srv.wPriority,
					rec->data.srv.nameTarget);
		break;

	case DNS_TYPE_HINFO:
		*type = "hinfo";
		*data = talloc_asprintf(mem_ctx, "%s %s",
					rec->data.hinfo.cpu,
					rec->data.hinfo.os);
		break;

	case DNS_TYPE_NS:
		*type = "ns";
		*data = rec->data.ns;
		break;

	case DNS_TYPE_SOA:
		*type = "soa";
		*data = talloc_asprintf(mem_ctx, "%s %s %u %u %u %u %u",
					rec->data.soa.mname,
					rec->data.soa.rname,
					rec->data.soa.serial,
					rec->data.soa.refresh,
					rec->data.soa.retry,
					rec->data.soa.expire,
					rec->data.soa.minimum);
		break;

	default:
		state->log(ISC_LOG_ERROR, "samba b9_putrr: unhandled record type %u",
			   rec->wType);
		return false;
	}

	return true;
}

/*
  send a resource recond to bind9
 */
static isc_result_t b9_putrr(struct dlz_bind9_data *state,
			     void *handle, struct dnsp_DnssrvRpcRecord *rec,
			     const char **types)
{
	isc_result_t result;
	const char *type, *data;
	TALLOC_CTX *tmp_ctx = talloc_new(state);

	if (!b9_format(state, tmp_ctx, rec, &type, &data)) {
		return ISC_R_FAILURE;
	}

	if (data == NULL) {
		talloc_free(tmp_ctx);
		return ISC_R_NOMEMORY;
	}

	if (types) {
		int i;
		for (i=0; types[i]; i++) {
			if (strcmp(types[i], type) == 0) break;
		}
		if (types[i] == NULL) {
			/* skip it */
			return ISC_R_SUCCESS;
		}
	}

	/* FIXME: why does dlz insist on all TTL values being the same
	   for the same name? */
	result = state->putrr(handle, type, /* rec->dwTtlSeconds */ 900, data);
	if (result != ISC_R_SUCCESS) {
		state->log(ISC_LOG_ERROR, "Failed to put rr");
	}
	talloc_free(tmp_ctx);
	return result;
}


/*
  send a named resource recond to bind9
 */
static isc_result_t b9_putnamedrr(struct dlz_bind9_data *state,
				  void *handle, const char *name,
				  struct dnsp_DnssrvRpcRecord *rec)
{
	isc_result_t result;
	const char *type, *data;
	TALLOC_CTX *tmp_ctx = talloc_new(state);

	if (!b9_format(state, tmp_ctx, rec, &type, &data)) {
		return ISC_R_FAILURE;
	}

	if (data == NULL) {
		talloc_free(tmp_ctx);
		return ISC_R_NOMEMORY;
	}

	/* FIXME: why does dlz insist on all TTL values being the same
	   for the same name? */
	result = state->putnamedrr(handle, name, type, /* rec->dwTtlSeconds */ 900, data);
	if (result != ISC_R_SUCCESS) {
		state->log(ISC_LOG_ERROR, "Failed to put named rr '%s'", name);
	}
	talloc_free(tmp_ctx);
	return result;
}


/*
  called to initialise the driver
 */
_PUBLIC_ isc_result_t dlz_create(const char *dlzname,
				 unsigned int argc, char *argv[],
				 void *driverarg, void **dbdata, ...)
{
	struct dlz_bind9_data *state;
	const char *helper_name;
	va_list ap;
	isc_result_t result;
	const char *url;
	TALLOC_CTX *tmp_ctx;
	int ret;
	struct ldb_dn *dn;

	state = talloc_zero(NULL, struct dlz_bind9_data);
	if (state == NULL) {
		return ISC_R_NOMEMORY;
	}

	tmp_ctx = talloc_new(state);

	/* fill in the helper functions */
	va_start(ap, dbdata);
	while ((helper_name = va_arg(ap, const char *)) != NULL) {
		b9_add_helper(state, helper_name, va_arg(ap, void*));
	}
	va_end(ap);

	state->lp = loadparm_init_global(true);
	if (state->lp == NULL) {
		result = ISC_R_NOMEMORY;
		goto failed;
	}

	state->ev_ctx = tevent_context_init(state);
	if (state->ev_ctx == NULL) {
		result = ISC_R_NOMEMORY;
		goto failed;
	}

	state->samdb = ldb_init(state, state->ev_ctx);
	if (state->samdb == NULL) {
		state->log(ISC_LOG_ERROR, "samba dlz_bind9: Failed to create ldb");
		result = ISC_R_FAILURE;
		goto failed;
	}

	url = talloc_asprintf(tmp_ctx, "ldapi://%s",
			      private_path(tmp_ctx, state->lp, "ldap_priv/ldapi"));
	if (url == NULL) {
		result = ISC_R_NOMEMORY;
		goto failed;
	}

	ret = ldb_connect(state->samdb, url, 0, NULL);
	if (ret == -1) {
		state->log(ISC_LOG_ERROR, "samba dlz_bind9: Failed to connect to %s - %s",
			   url, ldb_errstring(state->samdb));
		result = ISC_R_FAILURE;
		goto failed;
	}

	dn = ldb_get_default_basedn(state->samdb);
	if (dn == NULL) {
		state->log(ISC_LOG_ERROR, "samba dlz_bind9: Unable to get basedn for %s - %s",
			   url, ldb_errstring(state->samdb));
		result = ISC_R_FAILURE;
		goto failed;
	}

	state->log(ISC_LOG_INFO, "samba dlz_bind9: started for DN %s",
		   ldb_dn_get_linearized(dn));

	*dbdata = state;

	talloc_free(tmp_ctx);
	return ISC_R_SUCCESS;

failed:
	talloc_free(state);
	return result;
}

/*
  shutdown the backend
 */
_PUBLIC_ void dlz_destroy(void *driverarg, void *dbdata)
{
	struct dlz_bind9_data *state = talloc_get_type_abort(dbdata, struct dlz_bind9_data);
	state->log(ISC_LOG_INFO, "samba dlz_bind9: shutting down");
	talloc_free(state);
}


/*
  see if we handle a given zone
 */
_PUBLIC_ isc_result_t dlz_findzonedb(void *driverarg, void *dbdata, const char *name)
{
	struct dlz_bind9_data *state = talloc_get_type_abort(dbdata, struct dlz_bind9_data);
	if (strcasecmp(lpcfg_dnsdomain(state->lp), name) == 0) {
		return ISC_R_SUCCESS;
	}
	return ISC_R_NOTFOUND;
}


/*
  lookup one record
 */
_PUBLIC_ isc_result_t dlz_lookup_types(struct dlz_bind9_data *state,
				       const char *zone, const char *name,
				       void *driverarg, dns_sdlzlookup_t *lookup,
				       const char **types)
{
	struct ldb_dn *dn;
	TALLOC_CTX *tmp_ctx = talloc_new(state);
	const char *attrs[] = { "dnsRecord", NULL };
	int ret, i;
	struct ldb_result *res;
	struct ldb_message_element *el;

	dn = ldb_dn_copy(tmp_ctx, ldb_get_default_basedn(state->samdb));
	if (dn == NULL) {
		talloc_free(tmp_ctx);
		return ISC_R_NOMEMORY;
	}

	if (!ldb_dn_add_child_fmt(dn, "DC=%s,DC=%s,CN=MicrosoftDNS,DC=DomainDnsZones",
				  name, zone)) {
		talloc_free(tmp_ctx);
		return ISC_R_NOMEMORY;
	}

	ret = ldb_search(state->samdb, tmp_ctx, &res, dn, LDB_SCOPE_BASE,
			 attrs, "objectClass=dnsNode");
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ISC_R_NOTFOUND;
	}

	el = ldb_msg_find_element(res->msgs[0], "dnsRecord");
	if (el == NULL || el->num_values == 0) {
		state->log(ISC_LOG_INFO, "failed to find %s",
			   ldb_dn_get_linearized(dn));
		talloc_free(tmp_ctx);
		return ISC_R_NOTFOUND;
	}

	for (i=0; i<el->num_values; i++) {
		struct dnsp_DnssrvRpcRecord rec;
		enum ndr_err_code ndr_err;
		isc_result_t result;

		ndr_err = ndr_pull_struct_blob(&el->values[i], tmp_ctx, &rec,
					       (ndr_pull_flags_fn_t)ndr_pull_dnsp_DnssrvRpcRecord);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			state->log(ISC_LOG_ERROR, "samba dlz_bind9: failed to parse dnsRecord for %s",
				   ldb_dn_get_linearized(dn));
			talloc_free(tmp_ctx);
			return ISC_R_FAILURE;
		}

		result = b9_putrr(state, lookup, &rec, types);
		if (result != ISC_R_SUCCESS) {
			talloc_free(tmp_ctx);
			return result;
		}
	}

	talloc_free(tmp_ctx);
	return ISC_R_SUCCESS;
}

/*
  lookup one record
 */
_PUBLIC_ isc_result_t dlz_lookup(const char *zone, const char *name, void *driverarg,
				 void *dbdata, dns_sdlzlookup_t *lookup)
{
	struct dlz_bind9_data *state = talloc_get_type_abort(dbdata, struct dlz_bind9_data);
	return dlz_lookup_types(state, zone, name, driverarg, lookup, NULL);
}


/*
  see if a zone transfer is allowed
 */
_PUBLIC_ isc_result_t dlz_allowzonexfr(void *driverarg, void *dbdata, const char *name,
				       const char *client)
{
	struct dlz_bind9_data *state = talloc_get_type_abort(dbdata, struct dlz_bind9_data);

	if (strcasecmp(lpcfg_dnsdomain(state->lp), name) == 0) {
		/* TODO: check an ACL here? client is the IP of the requester */
		state->log(ISC_LOG_INFO, "samba dlz_bind9: allowing zone transfer for '%s' by '%s'",
			   name, client);
		return ISC_R_SUCCESS;
	}
	return ISC_R_NOTFOUND;
}

/*
  perform a zone transfer
 */
_PUBLIC_ isc_result_t dlz_allnodes(const char *zone, void *driverarg, void *dbdata,
				   dns_sdlzallnodes_t *allnodes)
{
	struct dlz_bind9_data *state = talloc_get_type_abort(dbdata, struct dlz_bind9_data);
	const char *attrs[] = { "dnsRecord", NULL };
	int ret, i, j;
	struct ldb_dn *dn;
	struct ldb_result *res;
	TALLOC_CTX *tmp_ctx = talloc_new(state);


	dn = ldb_dn_copy(tmp_ctx, ldb_get_default_basedn(state->samdb));
	if (dn == NULL) {
		talloc_free(tmp_ctx);
		return ISC_R_NOMEMORY;
	}

	if (!ldb_dn_add_child_fmt(dn, "DC=%s,CN=MicrosoftDNS,DC=DomainDnsZones", zone)) {
		talloc_free(tmp_ctx);
		return ISC_R_NOMEMORY;
	}

	ret = ldb_search(state->samdb, tmp_ctx, &res, dn, LDB_SCOPE_SUBTREE,
			 attrs, "objectClass=dnsNode");
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ISC_R_NOTFOUND;
	}

	for (i=0; i<res->count; i++) {
		struct ldb_message_element *el;
		TALLOC_CTX *el_ctx = talloc_new(tmp_ctx);
		const char *rdn, *name;
		const struct ldb_val *v;

		el = ldb_msg_find_element(res->msgs[i], "dnsRecord");
		if (el == NULL || el->num_values == 0) {
			state->log(ISC_LOG_INFO, "failed to find dnsRecord for %s",
				   ldb_dn_get_linearized(dn));
			talloc_free(el_ctx);
			continue;
		}

		v = ldb_dn_get_rdn_val(res->msgs[i]->dn);
		if (v == NULL) {
			state->log(ISC_LOG_INFO, "failed to find RDN for %s",
				   ldb_dn_get_linearized(dn));
			talloc_free(el_ctx);
			continue;
		}

		rdn = talloc_strndup(el_ctx, (char *)v->data, v->length);
		if (rdn == NULL) {
			talloc_free(tmp_ctx);
			return ISC_R_NOMEMORY;
		}

		if (strcmp(rdn, "@") == 0) {
			name = zone;
		} else {
			name = talloc_asprintf(el_ctx, "%s.%s", rdn, zone);
		}
		if (name == NULL) {
			talloc_free(tmp_ctx);
			return ISC_R_NOMEMORY;
		}

		for (j=0; j<el->num_values; j++) {
			struct dnsp_DnssrvRpcRecord rec;
			enum ndr_err_code ndr_err;
			isc_result_t result;

			ndr_err = ndr_pull_struct_blob(&el->values[j], el_ctx, &rec,
						       (ndr_pull_flags_fn_t)ndr_pull_dnsp_DnssrvRpcRecord);
			if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
				state->log(ISC_LOG_ERROR, "samba dlz_bind9: failed to parse dnsRecord for %s",
					   ldb_dn_get_linearized(dn));
				talloc_free(el_ctx);
				continue;
			}

			result = b9_putnamedrr(state, allnodes, name, &rec);
			if (result != ISC_R_SUCCESS) {
				talloc_free(el_ctx);
				continue;
			}
		}
	}

	talloc_free(tmp_ctx);

	return ISC_R_SUCCESS;
}
