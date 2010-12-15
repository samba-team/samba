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
#include "lib/events/events.h"
#include "dsdb/samdb/samdb.h"
#include "dsdb/common/util.h"
#include "auth/session.h"
#include "auth/gensec/gensec.h"
#include "gen_ndr/ndr_dnsp.h"
#include "lib/cmdline/popt_common.h"
#include "lib/cmdline/popt_credentials.h"
#include "ldb_module.h"
#include "dlz_minimal.h"

struct dlz_bind9_data {
	struct ldb_context *samdb;
	struct tevent_context *ev_ctx;
	struct loadparm_context *lp;
	bool transaction_started;

	/* helper functions from the dlz_dlopen driver */
	void (*log)(int level, const char *fmt, ...);
	isc_result_t (*putrr)(dns_sdlzlookup_t *handle, const char *type,
			      dns_ttl_t ttl, const char *data);
	isc_result_t (*putnamedrr)(dns_sdlzlookup_t *handle, const char *name,
				   const char *type, dns_ttl_t ttl, const char *data);
	isc_result_t (*writeable_zone)(dns_view_t *view, const char *zone_name);
};


static const char *zone_prefixes[] = {
	"CN=MicrosoftDNS,DC=DomainDnsZones",
	"CN=MicrosoftDNS,DC=ForestDnsZones",
	NULL
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
	if (strcmp(helper_name, "writeable_zone") == 0) {
		state->writeable_zone = ptr;
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
  parse a record from bind9
 */
static bool b9_parse(struct dlz_bind9_data *state,
		     TALLOC_CTX *mem_ctx,
		     struct dnsp_DnssrvRpcRecord *rec,
		     const char **type, const char **data)
{
	return false;
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

	result = state->putrr(handle, type, rec->dwTtlSeconds, data);
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

	result = state->putnamedrr(handle, name, type, rec->dwTtlSeconds, data);
	if (result != ISC_R_SUCCESS) {
		state->log(ISC_LOG_ERROR, "Failed to put named rr '%s'", name);
	}
	talloc_free(tmp_ctx);
	return result;
}

struct b9_options {
	const char *url;
};

/*
   parse options
 */
static isc_result_t parse_options(struct dlz_bind9_data *state,
				  unsigned int argc, char *argv[],
				  struct b9_options *options)
{
	int opt;
	poptContext pc;
	struct poptOption long_options[] = {
		{ "url",       'H', POPT_ARG_STRING, &options->url, 0, "database URL", "URL" },
		{ NULL }
	};
	struct poptOption **popt_options;
	int ret;

	popt_options = ldb_module_popt_options(state->samdb);
	(*popt_options) = long_options;

	ret = ldb_modules_hook(state->samdb, LDB_MODULE_HOOK_CMDLINE_OPTIONS);
	if (ret != LDB_SUCCESS) {
		state->log(ISC_LOG_ERROR, "dlz samba: failed cmdline hook");
		return ISC_R_FAILURE;
	}

	pc = poptGetContext("dlz_bind9", argc, (const char **)argv, *popt_options,
			    POPT_CONTEXT_KEEP_FIRST);

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		default:
			state->log(ISC_LOG_ERROR, "dlz samba: Invalid option %s: %s",
				   poptBadOption(pc, 0), poptStrerror(opt));
			return ISC_R_FAILURE;
		}
	}

	ret = ldb_modules_hook(state->samdb, LDB_MODULE_HOOK_CMDLINE_PRECONNECT);
	if (ret != LDB_SUCCESS) {
		state->log(ISC_LOG_ERROR, "dlz samba: failed cmdline preconnect");
		return ISC_R_FAILURE;
	}

	return ISC_R_SUCCESS;
}


/*
  called to initialise the driver
 */
_PUBLIC_ isc_result_t dlz_create(const char *dlzname,
				 unsigned int argc, char *argv[],
				 void **dbdata, ...)
{
	struct dlz_bind9_data *state;
	const char *helper_name;
	va_list ap;
	isc_result_t result;
	TALLOC_CTX *tmp_ctx;
	int ret;
	struct ldb_dn *dn;
	struct b9_options options;

	ZERO_STRUCT(options);

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

	state->ev_ctx = s4_event_context_init(state);
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

	result = parse_options(state, argc, argv, &options);
	if (result != ISC_R_SUCCESS) {
		goto failed;
	}

	state->lp = loadparm_init_global(true);
	if (state->lp == NULL) {
		result = ISC_R_NOMEMORY;
		goto failed;
	}

	if (options.url == NULL) {
		options.url = talloc_asprintf(tmp_ctx, "ldapi://%s",
					      private_path(tmp_ctx, state->lp, "ldap_priv/ldapi"));
		if (options.url == NULL) {
			result = ISC_R_NOMEMORY;
			goto failed;
		}
	}

	ret = ldb_connect(state->samdb, options.url, 0, NULL);
	if (ret == -1) {
		state->log(ISC_LOG_ERROR, "samba dlz_bind9: Failed to connect to %s - %s",
			   options.url, ldb_errstring(state->samdb));
		result = ISC_R_FAILURE;
		goto failed;
	}

	ret = ldb_modules_hook(state->samdb, LDB_MODULE_HOOK_CMDLINE_POSTCONNECT);
	if (ret != LDB_SUCCESS) {
		state->log(ISC_LOG_ERROR, "samba dlz_bind9: Failed postconnect for %s - %s",
			   options.url, ldb_errstring(state->samdb));
		result = ISC_R_FAILURE;
		goto failed;
	}

	dn = ldb_get_default_basedn(state->samdb);
	if (dn == NULL) {
		state->log(ISC_LOG_ERROR, "samba dlz_bind9: Unable to get basedn for %s - %s",
			   options.url, ldb_errstring(state->samdb));
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
_PUBLIC_ void dlz_destroy(void *dbdata)
{
	struct dlz_bind9_data *state = talloc_get_type_abort(dbdata, struct dlz_bind9_data);
	state->log(ISC_LOG_INFO, "samba dlz_bind9: shutting down");
	talloc_free(state);
}


/*
  see if we handle a given zone
 */
_PUBLIC_ isc_result_t dlz_findzonedb(void *dbdata, const char *name)
{
	struct dlz_bind9_data *state = talloc_get_type_abort(dbdata, struct dlz_bind9_data);
	int ret;
	TALLOC_CTX *tmp_ctx = talloc_new(state);
	const char *attrs[] = { NULL };
	int i;

	for (i=0; zone_prefixes[i]; i++) {
		struct ldb_dn *dn;
		struct ldb_result *res;

		dn = ldb_dn_copy(tmp_ctx, ldb_get_default_basedn(state->samdb));
		if (dn == NULL) {
			talloc_free(tmp_ctx);
			return ISC_R_NOMEMORY;
		}

		if (!ldb_dn_add_child_fmt(dn, "DC=%s,%s", name, zone_prefixes[i])) {
			talloc_free(tmp_ctx);
			return ISC_R_NOMEMORY;
		}

		ret = ldb_search(state->samdb, tmp_ctx, &res, dn, LDB_SCOPE_BASE, attrs, "objectClass=dnsZone");
		if (ret == LDB_SUCCESS) {
			talloc_free(tmp_ctx);
			return ISC_R_SUCCESS;
		}
		talloc_free(dn);
	}

	talloc_free(tmp_ctx);
	return ISC_R_NOTFOUND;
}


/*
  lookup one record
 */
static isc_result_t dlz_lookup_types(struct dlz_bind9_data *state,
				     const char *zone, const char *name,
				     dns_sdlzlookup_t *lookup,
				     const char **types)
{
	TALLOC_CTX *tmp_ctx = talloc_new(state);
	const char *attrs[] = { "dnsRecord", NULL };
	int ret, i;
	struct ldb_result *res;
	struct ldb_message_element *el;
	struct ldb_dn *dn;

	for (i=0; zone_prefixes[i]; i++) {
		dn = ldb_dn_copy(tmp_ctx, ldb_get_default_basedn(state->samdb));
		if (dn == NULL) {
			talloc_free(tmp_ctx);
			return ISC_R_NOMEMORY;
		}

		if (!ldb_dn_add_child_fmt(dn, "DC=%s,DC=%s,%s", name, zone, zone_prefixes[i])) {
			talloc_free(tmp_ctx);
			return ISC_R_NOMEMORY;
		}

		ret = ldb_search(state->samdb, tmp_ctx, &res, dn, LDB_SCOPE_BASE,
				 attrs, "objectClass=dnsNode");
		if (ret == LDB_SUCCESS) {
			break;
		}
	}
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ISC_R_NOTFOUND;
	}

	el = ldb_msg_find_element(res->msgs[0], "dnsRecord");
	if (el == NULL || el->num_values == 0) {
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
_PUBLIC_ isc_result_t dlz_lookup(const char *zone, const char *name,
				 void *dbdata, dns_sdlzlookup_t *lookup)
{
	struct dlz_bind9_data *state = talloc_get_type_abort(dbdata, struct dlz_bind9_data);
	return dlz_lookup_types(state, zone, name, lookup, NULL);
}


/*
  see if a zone transfer is allowed
 */
_PUBLIC_ isc_result_t dlz_allowzonexfr(void *dbdata, const char *name, const char *client)
{
	/* just say yes for all our zones for now */
	return dlz_findzonedb(dbdata, name);
}

/*
  perform a zone transfer
 */
_PUBLIC_ isc_result_t dlz_allnodes(const char *zone, void *dbdata,
				   dns_sdlzallnodes_t *allnodes)
{
	struct dlz_bind9_data *state = talloc_get_type_abort(dbdata, struct dlz_bind9_data);
	const char *attrs[] = { "dnsRecord", NULL };
	int ret, i, j;
	struct ldb_dn *dn;
	struct ldb_result *res;
	TALLOC_CTX *tmp_ctx = talloc_new(state);

	for (i=0; zone_prefixes[i]; i++) {
		dn = ldb_dn_copy(tmp_ctx, ldb_get_default_basedn(state->samdb));
		if (dn == NULL) {
			talloc_free(tmp_ctx);
			return ISC_R_NOMEMORY;
		}

		if (!ldb_dn_add_child_fmt(dn, "DC=%s,%s", zone, zone_prefixes[i])) {
			talloc_free(tmp_ctx);
			return ISC_R_NOMEMORY;
		}

		ret = ldb_search(state->samdb, tmp_ctx, &res, dn, LDB_SCOPE_SUBTREE,
				 attrs, "objectClass=dnsNode");
		if (ret == LDB_SUCCESS) {
			break;
		}
	}
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


/*
  start a transaction
 */
_PUBLIC_ isc_result_t dlz_newversion(const char *zone, void *dbdata, void **versionp)
{
	struct dlz_bind9_data *state = talloc_get_type_abort(dbdata, struct dlz_bind9_data);

	state->log(ISC_LOG_INFO, "samba dlz_bind9: starting transaction on zone %s", zone);

	if (state->transaction_started) {
		state->log(ISC_LOG_INFO, "samba dlz_bind9: transaction already started for zone %s", zone);
		return ISC_R_FAILURE;
	}

	state->transaction_started = true;

	*versionp = (void *) &state->transaction_started;

	return ISC_R_SUCCESS;
}

/*
  end a transaction
 */
_PUBLIC_ void dlz_closeversion(const char *zone, isc_boolean_t commit,
			       void *dbdata, void **versionp)
{
	struct dlz_bind9_data *state = talloc_get_type_abort(dbdata, struct dlz_bind9_data);

	if (!state->transaction_started) {
		state->log(ISC_LOG_INFO, "samba dlz_bind9: transaction not started for zone %s", zone);
		*versionp = NULL;
		return;
	}

	state->transaction_started = false;

	*versionp = NULL;

	if (commit) {
		state->log(ISC_LOG_INFO, "samba dlz_bind9: committing transaction on zone %s", zone);
	} else {
		state->log(ISC_LOG_INFO, "samba dlz_bind9: cancelling transaction on zone %s", zone);
	}
}


/*
  see if there is a SOA record for a zone
 */
static bool b9_has_soa(struct dlz_bind9_data *state, struct ldb_dn *dn, const char *zone)
{
	const char *attrs[] = { "dnsRecord", NULL };
	struct ldb_result *res;
	struct ldb_message_element *el;
	TALLOC_CTX *tmp_ctx = talloc_new(state);
	int ret, i;

	if (!ldb_dn_add_child_fmt(dn, "DC=@,DC=%s", zone)) {
		talloc_free(tmp_ctx);
		return false;
	}

	ret = ldb_search(state->samdb, tmp_ctx, &res, dn, LDB_SCOPE_BASE,
			 attrs, "objectClass=dnsNode");
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return false;
	}

	el = ldb_msg_find_element(res->msgs[0], "dnsRecord");
	if (el == NULL) {
		talloc_free(tmp_ctx);
		return false;
	}
	for (i=0; i<el->num_values; i++) {
		struct dnsp_DnssrvRpcRecord rec;
		enum ndr_err_code ndr_err;

		ndr_err = ndr_pull_struct_blob(&el->values[i], tmp_ctx, &rec,
					       (ndr_pull_flags_fn_t)ndr_pull_dnsp_DnssrvRpcRecord);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			continue;
		}
		if (rec.wType == DNS_TYPE_SOA) {
			talloc_free(tmp_ctx);
			return true;
		}
	}

	talloc_free(tmp_ctx);
	return false;
}

/*
  configure a writeable zone
 */
_PUBLIC_ isc_result_t dlz_configure(dns_view_t *view, void *dbdata)
{
	struct dlz_bind9_data *state = talloc_get_type_abort(dbdata, struct dlz_bind9_data);
	TALLOC_CTX *tmp_ctx;
	struct ldb_dn *dn;
	int i;

	state->log(ISC_LOG_INFO, "samba dlz_bind9: starting configure");
	if (state->writeable_zone == NULL) {
		state->log(ISC_LOG_INFO, "samba dlz_bind9: no writeable_zone method available");
		return ISC_R_FAILURE;
	}

	tmp_ctx = talloc_new(state);

	for (i=0; zone_prefixes[i]; i++) {
		const char *attrs[] = { "name", NULL };
		int j, ret;
		struct ldb_result *res;

		dn = ldb_dn_copy(tmp_ctx, ldb_get_default_basedn(state->samdb));
		if (dn == NULL) {
			talloc_free(tmp_ctx);
			return ISC_R_NOMEMORY;
		}

		if (!ldb_dn_add_child_fmt(dn, "%s", zone_prefixes[i])) {
			talloc_free(tmp_ctx);
			return ISC_R_NOMEMORY;
		}

		ret = ldb_search(state->samdb, tmp_ctx, &res, dn, LDB_SCOPE_SUBTREE,
				 attrs, "objectClass=dnsZone");
		if (ret != LDB_SUCCESS) {
			continue;
		}

		for (j=0; j<res->count; j++) {
			isc_result_t result;
			const char *zone = ldb_msg_find_attr_as_string(res->msgs[j], "name", NULL);
			if (zone == NULL) {
				continue;
			}
			if (!b9_has_soa(state, dn, zone)) {
				continue;
			}
			result = state->writeable_zone(view, zone);
			if (result != ISC_R_SUCCESS) {
				state->log(ISC_LOG_ERROR, "samba dlz_bind9: Failed to configure zone '%s'",
					   zone);
				talloc_free(tmp_ctx);
				return result;
			}
			state->log(ISC_LOG_INFO, "samba dlz_bind9: configured writeable zone '%s'", zone);
		}
	}

	talloc_free(tmp_ctx);
	return ISC_R_SUCCESS;
}

/*
  authorize a zone update
 */
_PUBLIC_ isc_boolean_t dlz_ssumatch(const char *signer, const char *name, const char *tcpaddr,
				    const char *type, const char *key, uint32_t keydatalen, uint8_t *keydata,
				    void *dbdata)
{
	struct dlz_bind9_data *state = talloc_get_type_abort(dbdata, struct dlz_bind9_data);

	state->log(ISC_LOG_INFO, "samba dlz_bind9: allowing update of signer=%s name=%s tcpaddr=%s type=%s key=%s keydatalen=%u",
		   signer, name, tcpaddr, type, key, keydatalen);
	return true;
}


_PUBLIC_ isc_result_t dlz_addrdataset(const char *name, const char *rdatastr, void *dbdata, void *version)
{
	struct dlz_bind9_data *state = talloc_get_type_abort(dbdata, struct dlz_bind9_data);

	if (version != (void *) &state->transaction_started) {
		return ISC_R_FAILURE;
	}

	state->log(ISC_LOG_INFO, "samba dlz_bind9: adding rdataset %s '%s'", name, rdatastr);

	return ISC_R_SUCCESS;
}

_PUBLIC_ isc_result_t dlz_subrdataset(const char *name, const char *rdatastr, void *dbdata, void *version)
{
	struct dlz_bind9_data *state = talloc_get_type_abort(dbdata, struct dlz_bind9_data);

	if (version != (void *) &state->transaction_started) {
		return ISC_R_FAILURE;
	}

	state->log(ISC_LOG_INFO, "samba dlz_bind9: subtracting rdataset %s '%s'", name, rdatastr);

	return ISC_R_SUCCESS;
}


_PUBLIC_ isc_result_t dlz_delrdataset(const char *name, void *dbdata, void *version)
{
	struct dlz_bind9_data *state = talloc_get_type_abort(dbdata, struct dlz_bind9_data);

	if (version != (void *) &state->transaction_started) {
		return ISC_R_FAILURE;
	}

	state->log(ISC_LOG_INFO, "samba dlz_bind9: deleting rdataset %s", name);

	return ISC_R_SUCCESS;
}
