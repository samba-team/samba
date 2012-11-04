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
#include "auth/auth.h"
#include "auth/session.h"
#include "auth/gensec/gensec.h"
#include "librpc/gen_ndr/security.h"
#include "auth/credentials/credentials.h"
#include "system/kerberos.h"
#include "auth/kerberos/kerberos.h"
#include "gen_ndr/ndr_dnsp.h"
#include "gen_ndr/server_id.h"
#include "messaging/messaging.h"
#include "lib/cmdline/popt_common.h"
#include "dlz_minimal.h"


struct b9_options {
	const char *url;
	const char *debug;
};

struct dlz_bind9_data {
	struct b9_options options;
	struct ldb_context *samdb;
	struct tevent_context *ev_ctx;
	struct loadparm_context *lp;
	int *transaction_token;
	uint32_t soa_serial;

	/* Used for dynamic update */
	struct smb_krb5_context *smb_krb5_ctx;
	struct auth4_context *auth_context;
	struct auth_session_info *session_info;
	char *update_name;

	/* helper functions from the dlz_dlopen driver */
	log_t *log;
	dns_sdlz_putrr_t *putrr;
	dns_sdlz_putnamedrr_t *putnamedrr;
	dns_dlz_writeablezone_t *writeable_zone;
};

static struct dlz_bind9_data *dlz_bind9_state = NULL;
static int dlz_bind9_state_ref_count = 0;

static const char *zone_prefixes[] = {
	"CN=MicrosoftDNS,DC=DomainDnsZones",
	"CN=MicrosoftDNS,DC=ForestDnsZones",
	"CN=MicrosoftDNS,CN=System",
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
	uint32_t i;
	char *tmp;

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
		tmp = talloc_asprintf(mem_ctx, "\"%s\"", rec->data.txt.str[0]);
		for (i=1; i<rec->data.txt.count; i++) {
			tmp = talloc_asprintf_append(tmp, " \"%s\"", rec->data.txt.str[i]);
		}
		*data = tmp;
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
					rec->data.mx.wPriority,
					rec->data.mx.nameTarget);
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

	case DNS_TYPE_SOA: {
		const char *mname;
		*type = "soa";

		/* we need to fake the authoritative nameserver to
		 * point at ourselves. This is how AD DNS servers
		 * force clients to send updates to the right local DC
		 */
		mname = talloc_asprintf(mem_ctx, "%s.%s",
					lpcfg_netbios_name(state->lp), lpcfg_dnsdomain(state->lp));
		if (mname == NULL) {
			return false;
		}
		mname = strlower_talloc(mem_ctx, mname);
		if (mname == NULL) {
			return false;
		}

		state->soa_serial = rec->data.soa.serial;

		*data = talloc_asprintf(mem_ctx, "%s %s %u %u %u %u %u",
					mname,
					rec->data.soa.rname,
					rec->data.soa.serial,
					rec->data.soa.refresh,
					rec->data.soa.retry,
					rec->data.soa.expire,
					rec->data.soa.minimum);
		break;
	}

	default:
		state->log(ISC_LOG_ERROR, "samba b9_putrr: unhandled record type %u",
			   rec->wType);
		return false;
	}

	return true;
}

static const struct {
	enum dns_record_type dns_type;
	const char *typestr;
	bool single_valued;
} dns_typemap[] = {
	{ DNS_TYPE_A,     "A"     , false},
	{ DNS_TYPE_AAAA,  "AAAA"  , false},
	{ DNS_TYPE_CNAME, "CNAME" , true},
	{ DNS_TYPE_TXT,   "TXT"   , false},
	{ DNS_TYPE_PTR,   "PTR"   , false},
	{ DNS_TYPE_SRV,   "SRV"   , false},
	{ DNS_TYPE_MX,    "MX"    , false},
	{ DNS_TYPE_HINFO, "HINFO" , false},
	{ DNS_TYPE_NS,    "NS"    , false},
	{ DNS_TYPE_SOA,   "SOA"   , true},
};


/*
  see if a DNS type is single valued
 */
static bool b9_single_valued(enum dns_record_type dns_type)
{
	int i;
	for (i=0; i<ARRAY_SIZE(dns_typemap); i++) {
		if (dns_typemap[i].dns_type == dns_type) {
			return dns_typemap[i].single_valued;
		}
	}
	return false;
}

/*
  see if a DNS type is single valued
 */
static bool b9_dns_type(const char *type, enum dns_record_type *dtype)
{
	int i;
	for (i=0; i<ARRAY_SIZE(dns_typemap); i++) {
		if (strcasecmp(dns_typemap[i].typestr, type) == 0) {
			*dtype = dns_typemap[i].dns_type;
			return true;
		}
	}
	return false;
}


#define DNS_PARSE_STR(ret, str, sep, saveptr) do {	\
	(ret) = strtok_r(str, sep, &saveptr); \
	if ((ret) == NULL) return false; \
	} while (0)

#define DNS_PARSE_UINT(ret, str, sep, saveptr) do {  \
	char *istr = strtok_r(str, sep, &saveptr); \
	if ((istr) == NULL) return false; \
	(ret) = strtoul(istr, NULL, 10); \
	} while (0)

/*
  parse a record from bind9
 */
static bool b9_parse(struct dlz_bind9_data *state,
		     const char *rdatastr,
		     struct dnsp_DnssrvRpcRecord *rec)
{
	char *full_name, *dclass, *type;
	char *str, *tmp, *saveptr=NULL;
	int i;

	str = talloc_strdup(rec, rdatastr);
	if (str == NULL) {
		return false;
	}

	/* parse the SDLZ string form */
	DNS_PARSE_STR(full_name, str, "\t", saveptr);
	DNS_PARSE_UINT(rec->dwTtlSeconds, NULL, "\t", saveptr);
	DNS_PARSE_STR(dclass, NULL, "\t", saveptr);
	DNS_PARSE_STR(type, NULL, "\t", saveptr);

	/* construct the record */
	for (i=0; i<ARRAY_SIZE(dns_typemap); i++) {
		if (strcasecmp(type, dns_typemap[i].typestr) == 0) {
			rec->wType = dns_typemap[i].dns_type;
			break;
		}
	}
	if (i == ARRAY_SIZE(dns_typemap)) {
		state->log(ISC_LOG_ERROR, "samba_dlz: unsupported record type '%s' for '%s'",
			   type, full_name);
		return false;
	}

	switch (rec->wType) {
	case DNS_TYPE_A:
		DNS_PARSE_STR(rec->data.ipv4, NULL, " ", saveptr);
		break;

	case DNS_TYPE_AAAA:
		DNS_PARSE_STR(rec->data.ipv6, NULL, " ", saveptr);
		break;

	case DNS_TYPE_CNAME:
		DNS_PARSE_STR(rec->data.cname, NULL, " ", saveptr);
		break;

	case DNS_TYPE_TXT:
		rec->data.txt.count = 0;
		rec->data.txt.str = talloc_array(rec, const char *, rec->data.txt.count);
		tmp = strtok_r(NULL, "\t", &saveptr);
		while (tmp) {
			rec->data.txt.str = talloc_realloc(rec, rec->data.txt.str, const char *,
							rec->data.txt.count+1);
			if (tmp[0] == '"') {
				/* Strip quotes */
				rec->data.txt.str[rec->data.txt.count] = talloc_strndup(rec, &tmp[1], strlen(tmp)-2);
			} else {
				rec->data.txt.str[rec->data.txt.count] = talloc_strdup(rec, tmp);
			}
			rec->data.txt.count++;
			tmp = strtok_r(NULL, " ", &saveptr);
		}
		break;

	case DNS_TYPE_PTR:
		DNS_PARSE_STR(rec->data.ptr, NULL, " ", saveptr);
		break;

	case DNS_TYPE_SRV:
		DNS_PARSE_UINT(rec->data.srv.wPriority, NULL, " ", saveptr);
		DNS_PARSE_UINT(rec->data.srv.wWeight, NULL, " ", saveptr);
		DNS_PARSE_UINT(rec->data.srv.wPort, NULL, " ", saveptr);
		DNS_PARSE_STR(rec->data.srv.nameTarget, NULL, " ", saveptr);
		break;

	case DNS_TYPE_MX:
		DNS_PARSE_UINT(rec->data.mx.wPriority, NULL, " ", saveptr);
		DNS_PARSE_STR(rec->data.mx.nameTarget, NULL, " ", saveptr);
		break;

	case DNS_TYPE_HINFO:
		DNS_PARSE_STR(rec->data.hinfo.cpu, NULL, " ", saveptr);
		DNS_PARSE_STR(rec->data.hinfo.os, NULL, " ", saveptr);
		break;

	case DNS_TYPE_NS:
		DNS_PARSE_STR(rec->data.ns, NULL, " ", saveptr);
		break;

	case DNS_TYPE_SOA:
		DNS_PARSE_STR(rec->data.soa.mname, NULL, " ", saveptr);
		DNS_PARSE_STR(rec->data.soa.rname, NULL, " ", saveptr);
		DNS_PARSE_UINT(rec->data.soa.serial, NULL, " ", saveptr);
		DNS_PARSE_UINT(rec->data.soa.refresh, NULL, " ", saveptr);
		DNS_PARSE_UINT(rec->data.soa.retry, NULL, " ", saveptr);
		DNS_PARSE_UINT(rec->data.soa.expire, NULL, " ", saveptr);
		DNS_PARSE_UINT(rec->data.soa.minimum, NULL, " ", saveptr);
		break;

	default:
		state->log(ISC_LOG_ERROR, "samba b9_parse: unhandled record type %u",
			   rec->wType);
		return false;
	}

	/* we should be at the end of the buffer now */
	if (strtok_r(NULL, "\t ", &saveptr) != NULL) {
		state->log(ISC_LOG_ERROR, "samba b9_parse: unexpected data at end of string for '%s'",
		           rdatastr);
		return false;
	}

	return true;
}

/*
  send a resource record to bind9
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
  send a named resource record to bind9
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
		{ "url", 'H', POPT_ARG_STRING, &options->url, 0, "database URL", "URL" },
		{ "debug", 'd', POPT_ARG_STRING, &options->debug, 0, "debug level", "DEBUG" },
		{ NULL }
	};

	pc = poptGetContext("dlz_bind9", argc, (const char **)argv, long_options,
			POPT_CONTEXT_KEEP_FIRST);
	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		default:
			state->log(ISC_LOG_ERROR, "dlz_bind9: Invalid option %s: %s",
				   poptBadOption(pc, 0), poptStrerror(opt));
			return ISC_R_FAILURE;
		}
	}

	return ISC_R_SUCCESS;
}


/*
 * Create session info from PAC
 * This is called as auth_context->generate_session_info_pac()
 */
static NTSTATUS b9_generate_session_info_pac(struct auth4_context *auth_context,
					     TALLOC_CTX *mem_ctx,
					     struct smb_krb5_context *smb_krb5_context,
					     DATA_BLOB *pac_blob,
					     const char *principal_name,
					     const struct tsocket_address *remote_addr,
					     uint32_t session_info_flags,
					     struct auth_session_info **session_info)
{
	NTSTATUS status;
	struct auth_user_info_dc *user_info_dc;
	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_new(mem_ctx);
	NT_STATUS_HAVE_NO_MEMORY(tmp_ctx);

	status = kerberos_pac_blob_to_user_info_dc(tmp_ctx,
						   *pac_blob,
						   smb_krb5_context->krb5_context,
						   &user_info_dc,
						   NULL,
						   NULL);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(tmp_ctx);
		return status;
	}

	if (user_info_dc->info->authenticated) {
		session_info_flags |= AUTH_SESSION_INFO_AUTHENTICATED;
	}

	session_info_flags |= AUTH_SESSION_INFO_SIMPLE_PRIVILEGES;

	status = auth_generate_session_info(mem_ctx, NULL, NULL, user_info_dc,
					    session_info_flags, session_info);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(tmp_ctx);
		return status;
	}

	talloc_free(tmp_ctx);
	return status;
}

/* Callback for the DEBUG() system, to catch the remaining messages */
static void b9_debug(void *private_ptr, int msg_level, const char *msg)
{
	static const int isc_log_map[] = {
		ISC_LOG_CRITICAL, /* 0 */
		ISC_LOG_ERROR,    /* 1 */
		ISC_LOG_WARNING,   /* 2 */
		ISC_LOG_NOTICE    /* 3 */
	};
	struct dlz_bind9_data *state = private_ptr;
	int     isc_log_level;
	
	if (msg_level >= ARRAY_SIZE(isc_log_map) || msg_level < 0) {
		isc_log_level = ISC_LOG_INFO;
	} else {
		isc_log_level = isc_log_map[msg_level];
	}
	state->log(isc_log_level, "samba_dlz: %s", msg);
}

static int dlz_state_debug_unregister(struct dlz_bind9_data *state)
{
	/* Stop logging (to the bind9 logs) */
	debug_set_callback(NULL, NULL);
	return 0;
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
	struct ldb_dn *dn;
	NTSTATUS nt_status;

	if (dlz_bind9_state != NULL) {
		*dbdata = dlz_bind9_state;
		dlz_bind9_state_ref_count++;
		return ISC_R_SUCCESS;
	}

	state = talloc_zero(NULL, struct dlz_bind9_data);
	if (state == NULL) {
		return ISC_R_NOMEMORY;
	}

	talloc_set_destructor(state, dlz_state_debug_unregister);

	/* fill in the helper functions */
	va_start(ap, dbdata);
	while ((helper_name = va_arg(ap, const char *)) != NULL) {
		b9_add_helper(state, helper_name, va_arg(ap, void*));
	}
	va_end(ap);

	/* Do not install samba signal handlers */
	fault_setup_disable();

	/* Start logging (to the bind9 logs) */
	debug_set_callback(state, b9_debug);

	state->ev_ctx = s4_event_context_init(state);
	if (state->ev_ctx == NULL) {
		result = ISC_R_NOMEMORY;
		goto failed;
	}

	result = parse_options(state, argc, argv, &state->options);
	if (result != ISC_R_SUCCESS) {
		goto failed;
	}

	state->lp = loadparm_init_global(true);
	if (state->lp == NULL) {
		result = ISC_R_NOMEMORY;
		goto failed;
	}

	if (state->options.debug) {
		lpcfg_do_global_parameter(state->lp, "log level", state->options.debug);
	} else {
		lpcfg_do_global_parameter(state->lp, "log level", "0");
	}

	if (smb_krb5_init_context(state, state->ev_ctx, state->lp, &state->smb_krb5_ctx) != 0) {
		result = ISC_R_NOMEMORY;
		goto failed;
	}

	nt_status = gensec_init();
	if (!NT_STATUS_IS_OK(nt_status)) {
		result = ISC_R_NOMEMORY;
		goto failed;
	}

	state->auth_context = talloc_zero(state, struct auth4_context);
	if (state->auth_context == NULL) {
		result = ISC_R_NOMEMORY;
		goto failed;
	}

	if (state->options.url == NULL) {
		state->options.url = lpcfg_private_path(state, state->lp, "dns/sam.ldb");
		if (state->options.url == NULL) {
			result = ISC_R_NOMEMORY;
			goto failed;
		}
	}

	state->samdb = samdb_connect_url(state, state->ev_ctx, state->lp,
					system_session(state->lp), 0, state->options.url);
	if (state->samdb == NULL) {
		state->log(ISC_LOG_ERROR, "samba_dlz: Failed to connect to %s",
			state->options.url);
		result = ISC_R_FAILURE;
		goto failed;
	}

	dn = ldb_get_default_basedn(state->samdb);
	if (dn == NULL) {
		state->log(ISC_LOG_ERROR, "samba_dlz: Unable to get basedn for %s - %s",
			   state->options.url, ldb_errstring(state->samdb));
		result = ISC_R_FAILURE;
		goto failed;
	}

	state->log(ISC_LOG_INFO, "samba_dlz: started for DN %s",
		   ldb_dn_get_linearized(dn));

	state->auth_context->event_ctx = state->ev_ctx;
	state->auth_context->lp_ctx = state->lp;
	state->auth_context->sam_ctx = state->samdb;
	state->auth_context->generate_session_info_pac = b9_generate_session_info_pac;

	*dbdata = state;
	dlz_bind9_state = state;
	dlz_bind9_state_ref_count++;

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
	state->log(ISC_LOG_INFO, "samba_dlz: shutting down");

	dlz_bind9_state_ref_count--;
	if (dlz_bind9_state_ref_count == 0) {
		talloc_unlink(state, state->samdb);
		talloc_free(state);
		dlz_bind9_state = NULL;
	}
}


/*
  return the base DN for a zone
 */
static isc_result_t b9_find_zone_dn(struct dlz_bind9_data *state, const char *zone_name,
				    TALLOC_CTX *mem_ctx, struct ldb_dn **zone_dn)
{
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

		if (!ldb_dn_add_child_fmt(dn, "DC=%s,%s", zone_name, zone_prefixes[i])) {
			talloc_free(tmp_ctx);
			return ISC_R_NOMEMORY;
		}

		ret = ldb_search(state->samdb, tmp_ctx, &res, dn, LDB_SCOPE_BASE, attrs, "objectClass=dnsZone");
		if (ret == LDB_SUCCESS) {
			if (zone_dn != NULL) {
				*zone_dn = talloc_steal(mem_ctx, dn);
			}
			talloc_free(tmp_ctx);
			return ISC_R_SUCCESS;
		}
		talloc_free(dn);
	}

	talloc_free(tmp_ctx);
	return ISC_R_NOTFOUND;
}


/*
  return the DN for a name. The record does not need to exist, but the
  zone must exist
 */
static isc_result_t b9_find_name_dn(struct dlz_bind9_data *state, const char *name,
				    TALLOC_CTX *mem_ctx, struct ldb_dn **dn)
{
	const char *p;

	/* work through the name piece by piece, until we find a zone */
	for (p=name; p; ) {
		isc_result_t result;
		result = b9_find_zone_dn(state, p, mem_ctx, dn);
		if (result == ISC_R_SUCCESS) {
			/* we found a zone, now extend the DN to get
			 * the full DN
			 */
			bool ret;
			if (p == name) {
				ret = ldb_dn_add_child_fmt(*dn, "DC=@");
			} else {
				ret = ldb_dn_add_child_fmt(*dn, "DC=%.*s", (int)(p-name)-1, name);
			}
			if (!ret) {
				talloc_free(*dn);
				return ISC_R_NOMEMORY;
			}
			return ISC_R_SUCCESS;
		}
		p = strchr(p, '.');
		if (p == NULL) {
			break;
		}
		p++;
	}
	return ISC_R_NOTFOUND;
}


/*
  see if we handle a given zone
 */
_PUBLIC_ isc_result_t dlz_findzonedb(void *dbdata, const char *name)
{
	struct dlz_bind9_data *state = talloc_get_type_abort(dbdata, struct dlz_bind9_data);
	return b9_find_zone_dn(state, name, NULL, NULL);
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
	int ret = LDB_SUCCESS, i;
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
			state->log(ISC_LOG_ERROR, "samba_dlz: failed to parse dnsRecord for %s",
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
#ifdef BIND_VERSION_9_8
_PUBLIC_ isc_result_t dlz_lookup(const char *zone, const char *name,
				 void *dbdata, dns_sdlzlookup_t *lookup)
#else
_PUBLIC_ isc_result_t dlz_lookup(const char *zone, const char *name,
				 void *dbdata, dns_sdlzlookup_t *lookup,
				 dns_clientinfomethods_t *methods,
				 dns_clientinfo_t *clientinfo)
#endif
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
	int ret = LDB_SUCCESS, i, j;
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
				state->log(ISC_LOG_ERROR, "samba_dlz: failed to parse dnsRecord for %s",
					   ldb_dn_get_linearized(dn));
				continue;
			}

			result = b9_putnamedrr(state, allnodes, name, &rec);
			if (result != ISC_R_SUCCESS) {
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

	state->log(ISC_LOG_INFO, "samba_dlz: starting transaction on zone %s", zone);

	if (state->transaction_token != NULL) {
		state->log(ISC_LOG_INFO, "samba_dlz: transaction already started for zone %s", zone);
		return ISC_R_FAILURE;
	}

	state->transaction_token = talloc_zero(state, int);
	if (state->transaction_token == NULL) {
		return ISC_R_NOMEMORY;
	}

	if (ldb_transaction_start(state->samdb) != LDB_SUCCESS) {
		state->log(ISC_LOG_INFO, "samba_dlz: failed to start a transaction for zone %s", zone);
		talloc_free(state->transaction_token);
		state->transaction_token = NULL;
		return ISC_R_FAILURE;
	}

	*versionp = (void *)state->transaction_token;

	return ISC_R_SUCCESS;
}

/*
  end a transaction
 */
_PUBLIC_ void dlz_closeversion(const char *zone, isc_boolean_t commit,
			       void *dbdata, void **versionp)
{
	struct dlz_bind9_data *state = talloc_get_type_abort(dbdata, struct dlz_bind9_data);

	if (state->transaction_token != (int *)*versionp) {
		state->log(ISC_LOG_INFO, "samba_dlz: transaction not started for zone %s", zone);
		return;
	}

	if (commit) {
		if (ldb_transaction_commit(state->samdb) != LDB_SUCCESS) {
			state->log(ISC_LOG_INFO, "samba_dlz: failed to commit a transaction for zone %s", zone);
			return;
		}
		state->log(ISC_LOG_INFO, "samba_dlz: committed transaction on zone %s", zone);
	} else {
		if (ldb_transaction_cancel(state->samdb) != LDB_SUCCESS) {
			state->log(ISC_LOG_INFO, "samba_dlz: failed to cancel a transaction for zone %s", zone);
			return;
		}
		state->log(ISC_LOG_INFO, "samba_dlz: cancelling transaction on zone %s", zone);
	}

	talloc_free(state->transaction_token);
	state->transaction_token = NULL;
	*versionp = NULL;
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

	state->log(ISC_LOG_INFO, "samba_dlz: starting configure");
	if (state->writeable_zone == NULL) {
		state->log(ISC_LOG_INFO, "samba_dlz: no writeable_zone method available");
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
			struct ldb_dn *zone_dn;

			if (zone == NULL) {
				continue;
			}
			/* Ignore zones that are not handled in BIND */
			if ((strcmp(zone, "RootDNSServers") == 0) ||
			    (strcmp(zone, "..TrustAnchors") == 0)) {
				continue;
			}
			zone_dn = ldb_dn_copy(tmp_ctx, dn);
			if (zone_dn == NULL) {
				talloc_free(tmp_ctx);
				return ISC_R_NOMEMORY;
			}

			if (!b9_has_soa(state, zone_dn, zone)) {
				continue;
			}
			result = state->writeable_zone(view, zone);
			if (result != ISC_R_SUCCESS) {
				state->log(ISC_LOG_ERROR, "samba_dlz: Failed to configure zone '%s'",
					   zone);
				talloc_free(tmp_ctx);
				return result;
			}
			state->log(ISC_LOG_INFO, "samba_dlz: configured writeable zone '%s'", zone);
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
	TALLOC_CTX *tmp_ctx;
	DATA_BLOB ap_req;
	struct cli_credentials *server_credentials;
	char *keytab_name;
	int ret;
	int ldb_ret;
	NTSTATUS nt_status;
	struct gensec_security *gensec_ctx;
	struct auth_session_info *session_info;
	struct ldb_dn *dn;
	isc_result_t result;
	struct ldb_result *res;
	const char * attrs[] = { NULL };
	uint32_t access_mask;

	/* Remove cached credentials, if any */
	if (state->session_info) {
		talloc_free(state->session_info);
		state->session_info = NULL;
	}
	if (state->update_name) {
		talloc_free(state->update_name);
		state->update_name = NULL;
	}

	tmp_ctx = talloc_new(NULL);
	if (tmp_ctx == NULL) {
		state->log(ISC_LOG_ERROR, "samba_dlz: no memory");
		return ISC_FALSE;
	}

	ap_req = data_blob_const(keydata, keydatalen);
	server_credentials = cli_credentials_init(tmp_ctx);
	if (!server_credentials) {
		state->log(ISC_LOG_ERROR, "samba_dlz: failed to init server credentials");
		talloc_free(tmp_ctx);
		return ISC_FALSE;
	}

	cli_credentials_set_krb5_context(server_credentials, state->smb_krb5_ctx);
	cli_credentials_set_conf(server_credentials, state->lp);

	keytab_name = talloc_asprintf(tmp_ctx, "file:%s/dns.keytab",
					lpcfg_private_dir(state->lp));
	ret = cli_credentials_set_keytab_name(server_credentials, state->lp, keytab_name,
						CRED_SPECIFIED);
	if (ret != 0) {
		state->log(ISC_LOG_ERROR, "samba_dlz: failed to obtain server credentials from %s",
			   keytab_name);
		talloc_free(tmp_ctx);
		return ISC_FALSE;
	}
	talloc_free(keytab_name);

	nt_status = gensec_server_start(tmp_ctx,
					lpcfg_gensec_settings(tmp_ctx, state->lp),
					state->auth_context, &gensec_ctx);
	if (!NT_STATUS_IS_OK(nt_status)) {
		state->log(ISC_LOG_ERROR, "samba_dlz: failed to start gensec server");
		talloc_free(tmp_ctx);
		return ISC_FALSE;
	}

	gensec_set_credentials(gensec_ctx, server_credentials);

	nt_status = gensec_start_mech_by_name(gensec_ctx, "spnego");
	if (!NT_STATUS_IS_OK(nt_status)) {
		state->log(ISC_LOG_ERROR, "samba_dlz: failed to start spnego");
		talloc_free(tmp_ctx);
		return ISC_FALSE;
	}

	nt_status = gensec_update(gensec_ctx, tmp_ctx, state->ev_ctx, ap_req, &ap_req);
	if (!NT_STATUS_IS_OK(nt_status)) {
		state->log(ISC_LOG_ERROR, "samba_dlz: spnego update failed");
		talloc_free(tmp_ctx);
		return ISC_FALSE;
	}

	nt_status = gensec_session_info(gensec_ctx, tmp_ctx, &session_info);
	if (!NT_STATUS_IS_OK(nt_status)) {
		state->log(ISC_LOG_ERROR, "samba_dlz: failed to create session info");
		talloc_free(tmp_ctx);
		return ISC_FALSE;
	}

	/* Get the DN from name */
	result = b9_find_name_dn(state, name, tmp_ctx, &dn);
	if (result != ISC_R_SUCCESS) {
		state->log(ISC_LOG_ERROR, "samba_dlz: failed to find name %s", name);
		talloc_free(tmp_ctx);
		return ISC_FALSE;
	}

	/* make sure the dn exists, or find parent dn in case new object is being added */
	ldb_ret = ldb_search(state->samdb, tmp_ctx, &res, dn, LDB_SCOPE_BASE,
				attrs, "objectClass=dnsNode");
	if (ldb_ret == LDB_ERR_NO_SUCH_OBJECT) {
		ldb_dn_remove_child_components(dn, 1);
		access_mask = SEC_ADS_CREATE_CHILD;
		talloc_free(res);
	} else if (ldb_ret == LDB_SUCCESS) {
		access_mask = SEC_STD_REQUIRED | SEC_ADS_SELF_WRITE;
		talloc_free(res);
	} else {
		talloc_free(tmp_ctx);
		return ISC_FALSE;
	}

	/* Do ACL check */
	ldb_ret = dsdb_check_access_on_dn(state->samdb, tmp_ctx, dn,
						session_info->security_token,
						access_mask, NULL);
	if (ldb_ret != LDB_SUCCESS) {
		state->log(ISC_LOG_INFO,
			"samba_dlz: disallowing update of signer=%s name=%s type=%s error=%s",
			signer, name, type, ldb_strerror(ldb_ret));
		talloc_free(tmp_ctx);
		return ISC_FALSE;
	}

	/* Cache session_info, so it can be used in the actual add/delete operation */
	state->update_name = talloc_strdup(state, name);
	if (state->update_name == NULL) {
		state->log(ISC_LOG_ERROR, "samba_dlz: memory allocation error");
		talloc_free(tmp_ctx);
		return ISC_FALSE;
	}
	state->session_info = talloc_steal(state, session_info);

	state->log(ISC_LOG_INFO, "samba_dlz: allowing update of signer=%s name=%s tcpaddr=%s type=%s key=%s",
		   signer, name, tcpaddr, type, key);

	talloc_free(tmp_ctx);
	return ISC_TRUE;
}


/*
  add a new record
 */
static isc_result_t b9_add_record(struct dlz_bind9_data *state, const char *name,
				  struct ldb_dn *dn,
				  struct dnsp_DnssrvRpcRecord *rec)
{
	struct ldb_message *msg;
	enum ndr_err_code ndr_err;
	struct ldb_val v;
	int ret;

	msg = ldb_msg_new(rec);
	if (msg == NULL) {
		return ISC_R_NOMEMORY;
	}
	msg->dn = dn;
	ret = ldb_msg_add_string(msg, "objectClass", "dnsNode");
	if (ret != LDB_SUCCESS) {
		return ISC_R_FAILURE;
	}

	ndr_err = ndr_push_struct_blob(&v, rec, rec, (ndr_push_flags_fn_t)ndr_push_dnsp_DnssrvRpcRecord);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ISC_R_FAILURE;
	}
	ret = ldb_msg_add_value(msg, "dnsRecord", &v, NULL);
	if (ret != LDB_SUCCESS) {
		return ISC_R_FAILURE;
	}

	ret = ldb_add(state->samdb, msg);
	if (ret != LDB_SUCCESS) {
		return ISC_R_FAILURE;
	}

	return ISC_R_SUCCESS;
}

/*
  see if two DNS names are the same
 */
static bool dns_name_equal(const char *name1, const char *name2)
{
	size_t len1 = strlen(name1);
	size_t len2 = strlen(name2);
	if (name1[len1-1] == '.') len1--;
	if (name2[len2-1] == '.') len2--;
	if (len1 != len2) {
		return false;
	}
	return strncasecmp_m(name1, name2, len1) == 0;
}


/*
  see if two dns records match
 */
static bool b9_record_match(struct dlz_bind9_data *state,
			    struct dnsp_DnssrvRpcRecord *rec1, struct dnsp_DnssrvRpcRecord *rec2)
{
	bool status;
	int i;

	if (rec1->wType != rec2->wType) {
		return false;
	}
	/* see if this type is single valued */
	if (b9_single_valued(rec1->wType)) {
		return true;
	}

	/* see if the data matches */
	switch (rec1->wType) {
	case DNS_TYPE_A:
		return strcmp(rec1->data.ipv4, rec2->data.ipv4) == 0;
	case DNS_TYPE_AAAA:
		return strcmp(rec1->data.ipv6, rec2->data.ipv6) == 0;
	case DNS_TYPE_CNAME:
		return dns_name_equal(rec1->data.cname, rec2->data.cname);
	case DNS_TYPE_TXT:
		status = (rec1->data.txt.count == rec2->data.txt.count);
		if (!status) return status;
		for (i=0; i<rec1->data.txt.count; i++) {
			status &= (strcmp(rec1->data.txt.str[i], rec2->data.txt.str[i]) == 0);
		}
		return status;
	case DNS_TYPE_PTR:
		return dns_name_equal(rec1->data.ptr, rec2->data.ptr);
	case DNS_TYPE_NS:
		return dns_name_equal(rec1->data.ns, rec2->data.ns);

	case DNS_TYPE_SRV:
		return rec1->data.srv.wPriority == rec2->data.srv.wPriority &&
			rec1->data.srv.wWeight  == rec2->data.srv.wWeight &&
			rec1->data.srv.wPort    == rec2->data.srv.wPort &&
			dns_name_equal(rec1->data.srv.nameTarget, rec2->data.srv.nameTarget);

	case DNS_TYPE_MX:
		return rec1->data.mx.wPriority == rec2->data.mx.wPriority &&
			dns_name_equal(rec1->data.mx.nameTarget, rec2->data.mx.nameTarget);

	case DNS_TYPE_HINFO:
		return strcmp(rec1->data.hinfo.cpu, rec2->data.hinfo.cpu) == 0 &&
			strcmp(rec1->data.hinfo.os, rec2->data.hinfo.os) == 0;

	case DNS_TYPE_SOA:
		return dns_name_equal(rec1->data.soa.mname, rec2->data.soa.mname) &&
			dns_name_equal(rec1->data.soa.rname, rec2->data.soa.rname) &&
			rec1->data.soa.serial == rec2->data.soa.serial &&
			rec1->data.soa.refresh == rec2->data.soa.refresh &&
			rec1->data.soa.retry == rec2->data.soa.retry &&
			rec1->data.soa.expire == rec2->data.soa.expire &&
			rec1->data.soa.minimum == rec2->data.soa.minimum;
	default:
		state->log(ISC_LOG_ERROR, "samba b9_putrr: unhandled record type %u",
			   rec1->wType);
		break;
	}

	return false;
}

/*
 * Update session_info on samdb using the cached credentials
 */
static bool b9_set_session_info(struct dlz_bind9_data *state, const char *name)
{
	int ret;

	if (state->update_name == NULL || state->session_info == NULL) {
		state->log(ISC_LOG_ERROR, "samba_dlz: invalid credentials");
		return false;
	}

	/* Do not use client credentials, if we're not updating the client specified name */
	if (strcmp(state->update_name, name) != 0) {
		return true;
	}

	ret = ldb_set_opaque(state->samdb, "sessionInfo", state->session_info);
	if (ret != LDB_SUCCESS) {
		state->log(ISC_LOG_ERROR, "samba_dlz: unable to set session info");
		return false;
	}

	return true;
}

/*
 * Reset session_info on samdb as system session
 */
static void b9_reset_session_info(struct dlz_bind9_data *state)
{
	ldb_set_opaque(state->samdb, "sessionInfo", system_session(state->lp));
}

/*
  add or modify a rdataset
 */
_PUBLIC_ isc_result_t dlz_addrdataset(const char *name, const char *rdatastr, void *dbdata, void *version)
{
	struct dlz_bind9_data *state = talloc_get_type_abort(dbdata, struct dlz_bind9_data);
	struct dnsp_DnssrvRpcRecord *rec;
	struct ldb_dn *dn;
	isc_result_t result;
	struct ldb_result *res;
	const char *attrs[] = { "dnsRecord", NULL };
	int ret, i;
	struct ldb_message_element *el;
	enum ndr_err_code ndr_err;
	NTTIME t;

	if (state->transaction_token != (void*)version) {
		state->log(ISC_LOG_INFO, "samba_dlz: bad transaction version");
		return ISC_R_FAILURE;
	}

	rec = talloc_zero(state, struct dnsp_DnssrvRpcRecord);
	if (rec == NULL) {
		return ISC_R_NOMEMORY;
	}

	unix_to_nt_time(&t, time(NULL));
	t /= 10*1000*1000; /* convert to seconds (NT time is in 100ns units) */
	t /= 3600;         /* convert to hours */

	rec->rank        = DNS_RANK_ZONE;
	rec->dwSerial    = state->soa_serial;
	rec->dwTimeStamp = (uint32_t)t;

	if (!b9_parse(state, rdatastr, rec)) {
		state->log(ISC_LOG_INFO, "samba_dlz: failed to parse rdataset '%s'", rdatastr);
		talloc_free(rec);
		return ISC_R_FAILURE;
	}

	/* find the DN of the record */
	result = b9_find_name_dn(state, name, rec, &dn);
	if (result != ISC_R_SUCCESS) {
		talloc_free(rec);
		return result;
	}

	/* get any existing records */
	ret = ldb_search(state->samdb, rec, &res, dn, LDB_SCOPE_BASE, attrs, "objectClass=dnsNode");
	if (ret == LDB_ERR_NO_SUCH_OBJECT) {
		if (!b9_set_session_info(state, name)) {
			talloc_free(rec);
			return ISC_R_FAILURE;
		}
		result = b9_add_record(state, name, dn, rec);
		b9_reset_session_info(state);
		talloc_free(rec);
		if (result == ISC_R_SUCCESS) {
			state->log(ISC_LOG_INFO, "samba_dlz: added %s %s", name, rdatastr);
		}
		return result;
	}

	el = ldb_msg_find_element(res->msgs[0], "dnsRecord");
	if (el == NULL) {
		ret = ldb_msg_add_empty(res->msgs[0], "dnsRecord", LDB_FLAG_MOD_ADD, &el);
		if (ret != LDB_SUCCESS) {
			state->log(ISC_LOG_ERROR, "samba_dlz: failed to add dnsRecord for %s",
				   ldb_dn_get_linearized(dn));
			talloc_free(rec);
			return ISC_R_FAILURE;
		}
	}

	/* there are existing records. We need to see if this will
	 * replace a record or add to it
	 */
	for (i=0; i<el->num_values; i++) {
		struct dnsp_DnssrvRpcRecord rec2;

		ndr_err = ndr_pull_struct_blob(&el->values[i], rec, &rec2,
					       (ndr_pull_flags_fn_t)ndr_pull_dnsp_DnssrvRpcRecord);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			state->log(ISC_LOG_ERROR, "samba_dlz: failed to parse dnsRecord for %s",
				   ldb_dn_get_linearized(dn));
			talloc_free(rec);
			return ISC_R_FAILURE;
		}

		if (b9_record_match(state, rec, &rec2)) {
			break;
		}
	}
	if (i == el->num_values) {
		/* adding a new value */
		el->values = talloc_realloc(el, el->values, struct ldb_val, el->num_values+1);
		if (el->values == NULL) {
			talloc_free(rec);
			return ISC_R_NOMEMORY;
		}
		el->num_values++;
	}

	ndr_err = ndr_push_struct_blob(&el->values[i], rec, rec,
				       (ndr_push_flags_fn_t)ndr_push_dnsp_DnssrvRpcRecord);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		state->log(ISC_LOG_ERROR, "samba_dlz: failed to push dnsRecord for %s",
			   ldb_dn_get_linearized(dn));
		talloc_free(rec);
		return ISC_R_FAILURE;
	}


	if (!b9_set_session_info(state, name)) {
		talloc_free(rec);
		return ISC_R_FAILURE;
	}

	/* modify the record */
	el->flags = LDB_FLAG_MOD_REPLACE;
	ret = ldb_modify(state->samdb, res->msgs[0]);
	b9_reset_session_info(state);
	if (ret != LDB_SUCCESS) {
		state->log(ISC_LOG_ERROR, "samba_dlz: failed to modify %s - %s",
			   ldb_dn_get_linearized(dn), ldb_errstring(state->samdb));
		talloc_free(rec);
		return ISC_R_FAILURE;
	}

	state->log(ISC_LOG_INFO, "samba_dlz: added rdataset %s '%s'", name, rdatastr);

	talloc_free(rec);
	return ISC_R_SUCCESS;
}

/*
  remove a rdataset
 */
_PUBLIC_ isc_result_t dlz_subrdataset(const char *name, const char *rdatastr, void *dbdata, void *version)
{
	struct dlz_bind9_data *state = talloc_get_type_abort(dbdata, struct dlz_bind9_data);
	struct dnsp_DnssrvRpcRecord *rec;
	struct ldb_dn *dn;
	isc_result_t result;
	struct ldb_result *res;
	const char *attrs[] = { "dnsRecord", NULL };
	int ret, i;
	struct ldb_message_element *el;
	enum ndr_err_code ndr_err;

	if (state->transaction_token != (void*)version) {
		state->log(ISC_LOG_ERROR, "samba_dlz: bad transaction version");
		return ISC_R_FAILURE;
	}

	rec = talloc_zero(state, struct dnsp_DnssrvRpcRecord);
	if (rec == NULL) {
		return ISC_R_NOMEMORY;
	}

	if (!b9_parse(state, rdatastr, rec)) {
		state->log(ISC_LOG_ERROR, "samba_dlz: failed to parse rdataset '%s'", rdatastr);
		talloc_free(rec);
		return ISC_R_FAILURE;
	}

	/* find the DN of the record */
	result = b9_find_name_dn(state, name, rec, &dn);
	if (result != ISC_R_SUCCESS) {
		talloc_free(rec);
		return result;
	}

	/* get the existing records */
	ret = ldb_search(state->samdb, rec, &res, dn, LDB_SCOPE_BASE, attrs, "objectClass=dnsNode");
	if (ret == LDB_ERR_NO_SUCH_OBJECT) {
		talloc_free(rec);
		return ISC_R_NOTFOUND;
	}

	/* there are existing records. We need to see if any match
	 */
	el = ldb_msg_find_element(res->msgs[0], "dnsRecord");
	if (el == NULL || el->num_values == 0) {
		state->log(ISC_LOG_ERROR, "samba_dlz: no dnsRecord attribute for %s",
			   ldb_dn_get_linearized(dn));
		talloc_free(rec);
		return ISC_R_FAILURE;
	}

	for (i=0; i<el->num_values; i++) {
		struct dnsp_DnssrvRpcRecord rec2;

		ndr_err = ndr_pull_struct_blob(&el->values[i], rec, &rec2,
					       (ndr_pull_flags_fn_t)ndr_pull_dnsp_DnssrvRpcRecord);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			state->log(ISC_LOG_ERROR, "samba_dlz: failed to parse dnsRecord for %s",
				   ldb_dn_get_linearized(dn));
			talloc_free(rec);
			return ISC_R_FAILURE;
		}

		if (b9_record_match(state, rec, &rec2)) {
			break;
		}
	}
	if (i == el->num_values) {
		talloc_free(rec);
		return ISC_R_NOTFOUND;
	}

	if (i < el->num_values-1) {
		memmove(&el->values[i], &el->values[i+1], sizeof(el->values[0])*((el->num_values-1)-i));
	}
	el->num_values--;

	if (!b9_set_session_info(state, name)) {
		talloc_free(rec);
		return ISC_R_FAILURE;
	}

	if (el->num_values == 0) {
		el->flags = LDB_FLAG_MOD_DELETE;
	} else {
		el->flags = LDB_FLAG_MOD_REPLACE;
	}
	ret = ldb_modify(state->samdb, res->msgs[0]);

	b9_reset_session_info(state);
	if (ret != LDB_SUCCESS) {
		state->log(ISC_LOG_ERROR, "samba_dlz: failed to modify %s - %s",
			   ldb_dn_get_linearized(dn), ldb_errstring(state->samdb));
		talloc_free(rec);
		return ISC_R_FAILURE;
	}

	state->log(ISC_LOG_INFO, "samba_dlz: subtracted rdataset %s '%s'", name, rdatastr);

	talloc_free(rec);
	return ISC_R_SUCCESS;
}


/*
  delete all records of the given type
 */
_PUBLIC_ isc_result_t dlz_delrdataset(const char *name, const char *type, void *dbdata, void *version)
{
	struct dlz_bind9_data *state = talloc_get_type_abort(dbdata, struct dlz_bind9_data);
	TALLOC_CTX *tmp_ctx;
	struct ldb_dn *dn;
	isc_result_t result;
	struct ldb_result *res;
	const char *attrs[] = { "dnsRecord", NULL };
	int ret, i;
	struct ldb_message_element *el;
	enum ndr_err_code ndr_err;
	enum dns_record_type dns_type;
	bool found = false;

	if (state->transaction_token != (void*)version) {
		state->log(ISC_LOG_ERROR, "samba_dlz: bad transaction version");
		return ISC_R_FAILURE;
	}

	if (!b9_dns_type(type, &dns_type)) {
		state->log(ISC_LOG_ERROR, "samba_dlz: bad dns type %s in delete", type);
		return ISC_R_FAILURE;
	}

	tmp_ctx = talloc_new(state);

	/* find the DN of the record */
	result = b9_find_name_dn(state, name, tmp_ctx, &dn);
	if (result != ISC_R_SUCCESS) {
		talloc_free(tmp_ctx);
		return result;
	}

	/* get the existing records */
	ret = ldb_search(state->samdb, tmp_ctx, &res, dn, LDB_SCOPE_BASE, attrs, "objectClass=dnsNode");
	if (ret == LDB_ERR_NO_SUCH_OBJECT) {
		talloc_free(tmp_ctx);
		return ISC_R_NOTFOUND;
	}

	/* there are existing records. We need to see if any match the type
	 */
	el = ldb_msg_find_element(res->msgs[0], "dnsRecord");
	if (el == NULL || el->num_values == 0) {
		talloc_free(tmp_ctx);
		return ISC_R_NOTFOUND;
	}

	for (i=0; i<el->num_values; i++) {
		struct dnsp_DnssrvRpcRecord rec2;

		ndr_err = ndr_pull_struct_blob(&el->values[i], tmp_ctx, &rec2,
					       (ndr_pull_flags_fn_t)ndr_pull_dnsp_DnssrvRpcRecord);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			state->log(ISC_LOG_ERROR, "samba_dlz: failed to parse dnsRecord for %s",
				   ldb_dn_get_linearized(dn));
			talloc_free(tmp_ctx);
			return ISC_R_FAILURE;
		}

		if (dns_type == rec2.wType) {
			if (i < el->num_values-1) {
				memmove(&el->values[i], &el->values[i+1],
					sizeof(el->values[0])*((el->num_values-1)-i));
			}
			el->num_values--;
			i--;
			found = true;
		}
	}

	if (!found) {
		talloc_free(tmp_ctx);
		return ISC_R_FAILURE;
	}

	if (!b9_set_session_info(state, name)) {
		talloc_free(tmp_ctx);
		return ISC_R_FAILURE;
	}

	if (el->num_values == 0) {
		el->flags = LDB_FLAG_MOD_DELETE;
	} else {
		el->flags = LDB_FLAG_MOD_REPLACE;
	}
	ret = ldb_modify(state->samdb, res->msgs[0]);

	b9_reset_session_info(state);
	if (ret != LDB_SUCCESS) {
		state->log(ISC_LOG_ERROR, "samba_dlz: failed to delete type %s in %s - %s",
			   type, ldb_dn_get_linearized(dn), ldb_errstring(state->samdb));
		talloc_free(tmp_ctx);
		return ISC_R_FAILURE;
	}

	state->log(ISC_LOG_INFO, "samba_dlz: deleted rdataset %s of type %s", name, type);

	talloc_free(tmp_ctx);
	return ISC_R_SUCCESS;
}
