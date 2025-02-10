/*
   Unix SMB/CIFS Implementation.
   forest trust scanner service

   Copyright (C) Stefan Metzmacher 2025

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
#include "dsdb/samdb/samdb.h"
#include "dsdb/common/util.h"
#include "samba/service.h"
#include "lib/param/param.h"
#include "libcli/resolve/resolve.h"
#include "libcli/finddc.h"
#include "librpc/gen_ndr/ads.h"
#include "auth/gensec/gensec.h"
#include "libcli/security/dom_sid.h"
#include "librpc/ndr/libndr.h"
#include "librpc/gen_ndr/ndr_drsblobs.h"
#include "lib/tsocket/tsocket.h"
#include "lib/tls/tls.h"
#include "../source3/include/tldap.h"
#include "../source3/include/tldap_util.h"
#include "../source3/lib/tldap_tls_connect.h"
#include "../source3/lib/tldap_gensec_bind.h"
#include "dsdb/ft_scanner/ft_scanner_service.h"
#include "dsdb/ft_scanner/ft_scanner_service_proto.h"
#include "lib/util/tevent_ntstatus.h"
#include <ldb_errors.h>

struct ft_scanner_scann_forest_state {
	struct tevent_context *ev;
	struct ft_scanner_service *service;
	const struct ldb_message *msg;
	const struct lsa_TrustDomainInfoInfoEx *tdo;
	struct resolve_context *resolve_ctx;
	struct finddcs finddcs_io;
	const char *dc_dns_name;
	const char *target_principal;
	unsigned tcp_port;
	bool use_tls;
	bool use_starttls;
	uint32_t gensec_features;
	struct tsocket_address *local_addr;
	struct tsocket_address *ldap_addr;
	struct tldap_context *ld;
	const char *partitions_dn;
	struct ForestTrustDataDomainInfo *domains;
};

static void ft_scanner_scann_forest_found_dc(struct tevent_req *subreq);
static void ft_scanner_scann_forest_tcp_connected(struct tevent_req *subreq);
static void ft_scanner_scann_forest_starttls(struct tevent_req *req);
static void ft_scanner_scann_forest_starttls_done(struct tevent_req *subreq);
static void ft_scanner_scann_forest_tls_connect(struct tevent_req *req);
static void ft_scanner_scann_forest_tls_connected(struct tevent_req *subreq);
static void ft_scanner_scann_forest_gensec_bind(struct tevent_req *req);
static void ft_scanner_scann_forest_gensec_bound(struct tevent_req *subreq);
static void ft_scanner_scann_forest_config_dn_search(struct tevent_req *req);
static void ft_scanner_scann_forest_config_dn_done(struct tevent_req *subreq);
static void ft_scanner_scann_forest_partition_dn_search(struct tevent_req *req);
static void ft_scanner_scann_forest_partition_dn_done(struct tevent_req *subreq);
static void ft_scanner_scann_forest_partitions_search(struct tevent_req *req);
static void ft_scanner_scann_forest_partitions_done(struct tevent_req *subreq);

static struct tevent_req *ft_scanner_scann_forest_send(TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct ft_scanner_service *service,
				const struct ldb_message *msg,
				const struct lsa_TrustDomainInfoInfoEx *tdo)
{
	struct loadparm_context *lp_ctx = service->task->lp_ctx;
	struct tevent_req *req = NULL;
	struct ft_scanner_scann_forest_state *state = NULL;
	struct tevent_req *subreq = NULL;
	int wrap_flags = -1;

	req = tevent_req_create(mem_ctx, &state,
				struct ft_scanner_scann_forest_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->service = service;
	state->msg = msg;
	state->tdo = tdo;

	wrap_flags = lpcfg_client_ldap_sasl_wrapping(service->task->lp_ctx);

	state->tcp_port = 389;
	if (wrap_flags & ADS_AUTH_SASL_LDAPS) {
		state->use_tls = true;
		state->tcp_port = 636;
	} else if (wrap_flags & ADS_AUTH_SASL_STARTTLS) {
		state->use_tls = true;
		state->use_starttls = true;
	} else {
		state->gensec_features |= GENSEC_FEATURE_LDAP_STYLE;
		state->gensec_features |= GENSEC_FEATURE_SIGN;
		if (wrap_flags & ADS_AUTH_SASL_SEAL) {
			state->gensec_features |= GENSEC_FEATURE_SEAL;
		}
	}

	state->resolve_ctx = lpcfg_resolve_context(lp_ctx);

	state->finddcs_io.in.domain_name = tdo->domain_name.string;
	state->finddcs_io.in.minimum_dc_flags = NBT_SERVER_LDAP |
						NBT_SERVER_DS |
						NBT_SERVER_GC;
	state->finddcs_io.in.proto = lpcfg_client_netlogon_ping_protocol(lp_ctx);

	subreq = finddcs_cldap_send(state,
				    &state->finddcs_io,
				    state->resolve_ctx,
				    state->ev);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq,
				ft_scanner_scann_forest_found_dc,
				req);

	return req;
}

static void ft_scanner_scann_forest_found_dc(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct ft_scanner_scann_forest_state *state =
		tevent_req_data(req,
		struct ft_scanner_scann_forest_state);
	NTSTATUS status;
	const char *dupper = NULL;
	int ret;

	status = finddcs_cldap_recv(subreq, state, &state->finddcs_io);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	if (state->finddcs_io.out.netlogon == NULL) {
		tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
		return;
	}

	if (state->finddcs_io.out.netlogon->data.nt5_ex.pdc_dns_name == NULL) {
		tevent_req_nterror(req, NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND);
		return;
	}
	state->dc_dns_name = state->finddcs_io.out.netlogon->data.nt5_ex.pdc_dns_name;

	dupper = talloc_strdup_upper(state, state->tdo->domain_name.string);
	if (tevent_req_nomem(dupper, req)) {
		return;
	}

	state->target_principal = talloc_asprintf(state,
						  "ldap/%s/%s@%s",
						  state->dc_dns_name,
						  state->tdo->domain_name.string,
						  dupper);
	if (tevent_req_nomem(state->target_principal, req)) {
		return;
	}

	/* parse the address of explicit kdc */
	ret = tsocket_address_inet_from_strings(state,
						"ip",
						state->finddcs_io.out.address,
						state->tcp_port,
						&state->ldap_addr);
	if (ret != 0) {
		status = map_nt_error_from_unix_common(errno);
		tevent_req_nterror(req, status);
		return;
	}

	/* get an address for us to use locally */
	ret = tsocket_address_inet_from_strings(state,
						"ip",
						NULL,
						0,
						&state->local_addr);
	if (ret != 0) {
		status = map_nt_error_from_unix_common(errno);
		tevent_req_nterror(req, status);
		return;
	}

	subreq = tstream_inet_tcp_connect_send(state,
					       state->ev,
					       state->local_addr,
					       state->ldap_addr);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq,
				ft_scanner_scann_forest_tcp_connected,
				req);
}

static void PRINTF_ATTRIBUTE(3, 0) ft_scanner_scann_forest_tldap_debug(
	void *log_private,
	enum tldap_debug_level level,
	const char *fmt,
	va_list ap)
{
	int samba_level = -1;

	switch (level) {
	case TLDAP_DEBUG_FATAL:
		samba_level = DBGLVL_ERR;
		break;
	case TLDAP_DEBUG_ERROR:
		samba_level = DBGLVL_ERR;
		break;
	case TLDAP_DEBUG_WARNING:
		samba_level = DBGLVL_WARNING;
		break;
	case TLDAP_DEBUG_TRACE:
		samba_level = DBGLVL_DEBUG;
		break;
	}

	if (CHECK_DEBUGLVL(samba_level)) {
		char *s = NULL;
		int ret;

		ret = vasprintf(&s, fmt, ap);
		if (ret == -1) {
			return;
		}
		DEBUG(samba_level, ("ft_scanner_scann_forest_tldap: %s", s));
		free(s);
	}
}

static void ft_scanner_scann_forest_tcp_connected(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct ft_scanner_scann_forest_state *state =
		tevent_req_data(req,
		struct ft_scanner_scann_forest_state);
	struct tstream_context *plain_stream = NULL;
	int ret, sys_errno;

	ret = tstream_inet_tcp_connect_recv(subreq,
					    &sys_errno,
					    state,
					    &plain_stream,
					    NULL);
	TALLOC_FREE(subreq);
	if (ret != 0) {
		NTSTATUS status = map_nt_error_from_unix_common(sys_errno);
		tevent_req_nterror(req, status);
		return;
	}

	state->ld = tldap_context_create_from_plain_stream(state,
							   &plain_stream);
	if (tevent_req_nomem(state->ld, req)) {
		return;
	}

	tldap_set_debug(state->ld, ft_scanner_scann_forest_tldap_debug, NULL);

	if (state->use_tls && state->use_starttls) {
		ft_scanner_scann_forest_starttls(req);
		return;
	}

	if (state->use_tls) {
		ft_scanner_scann_forest_tls_connect(req);
		return;
	}

	ft_scanner_scann_forest_gensec_bind(req);
	return;
}

static void ft_scanner_scann_forest_starttls(struct tevent_req *req)
{
	struct ft_scanner_scann_forest_state *state =
		tevent_req_data(req,
		struct ft_scanner_scann_forest_state);
	struct tevent_req *subreq = NULL;

	subreq = tldap_extended_send(state,
				     state->ev,
				     state->ld,
				     LDB_EXTENDED_START_TLS_OID,
				     NULL, /* in_blob */
				     NULL, /* sctrls */
				     0,    /* num_sctrls */
				     NULL, /* cctrls */
				     0);   /* num_cctrls */
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq,
				ft_scanner_scann_forest_starttls_done,
				req);
}

static void ft_scanner_scann_forest_starttls_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct ft_scanner_scann_forest_state *state =
		tevent_req_data(req,
		struct ft_scanner_scann_forest_state);
	TLDAPRC rc;

	rc = tldap_extended_recv(subreq,
				 NULL,  /* mem_ctx */
				 NULL,  /* out_oid */
				 NULL); /* out_blob */
	TALLOC_FREE(subreq);
	if (!TLDAP_RC_IS_SUCCESS(rc)) {
		NTSTATUS status = NT_STATUS_LDAP(TLDAP_RC_V(rc));
		DBG_ERR("tldap_extended(%s) failed: %s\n",
			LDB_EXTENDED_START_TLS_OID,
			tldap_errstr(state, state->ld, rc));
		tevent_req_nterror(req, status);
		return;
	}

	ft_scanner_scann_forest_tls_connect(req);
}

static void ft_scanner_scann_forest_tls_connect(struct tevent_req *req)
{
	struct ft_scanner_scann_forest_state *state =
		tevent_req_data(req,
		struct ft_scanner_scann_forest_state);
	struct ft_scanner_service *service = state->service;
	struct tstream_tls_params *tls_params = NULL;
	struct tevent_req *subreq = NULL;
	NTSTATUS status;

	status = tstream_tls_params_client_lpcfg(state,
						 service->task->lp_ctx,
						 state->dc_dns_name,
						 &tls_params);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("tstream_tls_params_client_lpcfg(%s) failed: %s\n",
			state->dc_dns_name, nt_errstr(status));
		tevent_req_nterror(req, status);
		return;
	}

	subreq = tldap_tls_connect_send(state,
					state->ev,
					state->ld,
					tls_params);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq,
				ft_scanner_scann_forest_tls_connected,
				req);
}

static void ft_scanner_scann_forest_tls_connected(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct ft_scanner_scann_forest_state *state =
		tevent_req_data(req,
		struct ft_scanner_scann_forest_state);
	TLDAPRC rc;

	rc = tldap_tls_connect_recv(subreq);
	TALLOC_FREE(subreq);
	if (!TLDAP_RC_IS_SUCCESS(rc)) {
		NTSTATUS status = NT_STATUS_LDAP(TLDAP_RC_V(rc));
		DBG_ERR("tldap_tls_connect(%s) failed: %s\n",
			state->dc_dns_name,
			tldap_errstr(state, state->ld, rc));
		tevent_req_nterror(req, status);
		return;
	}

	ft_scanner_scann_forest_gensec_bind(req);
}

static void ft_scanner_scann_forest_gensec_bind(struct tevent_req *req)
{
	struct ft_scanner_scann_forest_state *state =
		tevent_req_data(req,
		struct ft_scanner_scann_forest_state);
	struct ft_scanner_service *service = state->service;
	struct auth_session_info *system_session_info = NULL;
	struct tevent_req *subreq = NULL;

	system_session_info = system_session(service->task->lp_ctx);
	if (system_session_info == NULL) {
		tevent_req_nterror(req, NT_STATUS_CANT_ACCESS_DOMAIN_INFO);
		return;
	}

	subreq = tldap_gensec_bind_send(state,
					state->ev,
					state->ld,
					system_session_info->credentials,
					"ldap",
					state->dc_dns_name,
					state->target_principal,
					service->task->lp_ctx,
					state->gensec_features);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq,
				ft_scanner_scann_forest_gensec_bound,
				req);
}

static void ft_scanner_scann_forest_gensec_bound(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct ft_scanner_scann_forest_state *state =
		tevent_req_data(req,
		struct ft_scanner_scann_forest_state);
	TLDAPRC rc;

	rc = tldap_gensec_bind_recv(subreq);
	TALLOC_FREE(subreq);
	if (!TLDAP_RC_IS_SUCCESS(rc)) {
		NTSTATUS status = NT_STATUS_LDAP(TLDAP_RC_V(rc));
		DBG_ERR("tldap_gensec_bind(%s) failed: %s\n",
			state->dc_dns_name,
			tldap_errstr(state, state->ld, rc));
		tevent_req_nterror(req, status);
		return;
	}

	ft_scanner_scann_forest_config_dn_search(req);
}

static void ft_scanner_scann_forest_config_dn_search(struct tevent_req *req)
{
	struct ft_scanner_scann_forest_state *state =
		tevent_req_data(req,
		struct ft_scanner_scann_forest_state);
	static const char * const attrs[] = { "configurationNamingContext" };
	struct tevent_req *subreq = NULL;

	/*
	 * Do a rootdse search for configurationNamingContext
	 */
	subreq = tldap_search_all_send(state,
				       state->ev,
				       state->ld,
				       "",
				       TLDAP_SCOPE_BASE,
				       "(objectclass=*)",
				       attrs,
				       ARRAY_SIZE(attrs),
				       0,    /* attrsonly */
				       NULL, /* sctrls */
				       0,    /* num_sctrls */
				       NULL, /* cctrls */
				       0,    /* num_cctrls */
				       0,    /* timelimit */
				       0,    /* sizelimit */
				       0);   /* deref */
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq,
				ft_scanner_scann_forest_config_dn_done,
				req);
}

static void ft_scanner_scann_forest_config_dn_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct ft_scanner_scann_forest_state *state =
		tevent_req_data(req,
		struct ft_scanner_scann_forest_state);
	struct tldap_message **msgs = NULL;
	size_t num_msgs;
	struct tldap_message *res = NULL;
	const char *config_dn = NULL;
	TLDAPRC rc;

	rc = tldap_search_all_recv(subreq, state, &msgs, &res);
	TALLOC_FREE(subreq);
	if (!TLDAP_RC_IS_SUCCESS(rc)) {
		NTSTATUS status = NT_STATUS_LDAP(TLDAP_RC_V(rc));
		DBG_ERR("tldap_search_all() failed: %s\n",
			tldap_errstr(state, state->ld, rc));
		tevent_req_nterror(req, status);
		return;
	}

	rc = tldap_msg_rc(res);
	if (!TLDAP_RC_IS_SUCCESS(rc)) {
		NTSTATUS status = NT_STATUS_LDAP(TLDAP_RC_V(rc));
		DBG_ERR("tldap_search_all() res failed: %s\n",
			tldap_errstr(state, state->ld, rc));
		tevent_req_nterror(req, status);
		return;
	}

	num_msgs = talloc_array_length(msgs);
	if (num_msgs != 1) {
		NTSTATUS status = NT_STATUS_INVALID_NETWORK_RESPONSE;
		DBG_NOTICE("tldap_search_all() num_msgs=%zu: %s\n",
			   num_msgs, nt_errstr(status));
		tevent_req_nterror(req, status);
		return;
	}

	config_dn = tldap_talloc_single_attribute(msgs[0],
						  "configurationNamingContext",
						  state);
	if (tevent_req_nomem(config_dn, req)) {
		return;
	}

	state->partitions_dn = talloc_asprintf(state,
					       "CN=Partitions,%s",
					       config_dn);
	if (tevent_req_nomem(state->partitions_dn, req)) {
		return;
	}

	ft_scanner_scann_forest_partition_dn_search(req);
}

static void ft_scanner_scann_forest_partition_dn_search(struct tevent_req *req)
{
	struct ft_scanner_scann_forest_state *state =
		tevent_req_data(req,
		struct ft_scanner_scann_forest_state);
	static const char * const attrs[] = { "msDS-Behavior-Version" };
	struct tevent_req *subreq = NULL;

	/*
	 * Do a search CN=Partitions,CN=Configuration,...
	 * Filter: (objectClass=crossRefContainer)
	 * Attrs: msDS-Behavior-Version
	 */
	subreq = tldap_search_all_send(state,
				       state->ev,
				       state->ld,
				       state->partitions_dn,
				       TLDAP_SCOPE_BASE,
				       "(objectclass=crossRefContainer)",
				       attrs,
				       ARRAY_SIZE(attrs),
				       0,    /* attrsonly */
				       NULL, /* sctrls */
				       0,    /* num_sctrls */
				       NULL, /* cctrls */
				       0,    /* num_cctrls */
				       0,    /* timelimit */
				       0,    /* sizelimit */
				       0);   /* deref */
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq,
				ft_scanner_scann_forest_partition_dn_done,
				req);
}

static void ft_scanner_scann_forest_partition_dn_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct ft_scanner_scann_forest_state *state =
		tevent_req_data(req,
		struct ft_scanner_scann_forest_state);
	struct tldap_message **msgs = NULL;
	size_t num_msgs;
	struct tldap_message *res = NULL;
	TLDAPRC rc;

	rc = tldap_search_all_recv(subreq, state, &msgs, &res);
	TALLOC_FREE(subreq);
	if (!TLDAP_RC_IS_SUCCESS(rc)) {
		NTSTATUS status = NT_STATUS_LDAP(TLDAP_RC_V(rc));
		DBG_ERR("tldap_search_all() failed: %s\n",
			tldap_errstr(state, state->ld, rc));
		tevent_req_nterror(req, status);
		return;
	}

	rc = tldap_msg_rc(res);
	if (!TLDAP_RC_IS_SUCCESS(rc)) {
		NTSTATUS status = NT_STATUS_LDAP(TLDAP_RC_V(rc));
		DBG_ERR("tldap_search_all() res failed: %s\n",
			tldap_errstr(state, state->ld, rc));
		tevent_req_nterror(req, status);
		return;
	}

	num_msgs = talloc_array_length(msgs);
	if (num_msgs != 1) {
		NTSTATUS status = NT_STATUS_INVALID_NETWORK_RESPONSE;
		DBG_NOTICE("tldap_search_all() num_msgs=%zu: %s\n",
			   num_msgs, nt_errstr(status));
		tevent_req_nterror(req, status);
		return;
	}

	/*
	 * TODO: does Windows check the msDS-Behavior-Version value ?
	 *
	 * Currently I don't see a reason to check it...
	 */

	ft_scanner_scann_forest_partitions_search(req);
}

static void ft_scanner_scann_forest_partitions_search(struct tevent_req *req)
{
	struct ft_scanner_scann_forest_state *state =
		tevent_req_data(req,
		struct ft_scanner_scann_forest_state);
	static const char * const attrs[] = {
		"dnsRoot",
		"msDS-DnsRootAlias",
		"nETBIOSName",
		"systemFlags",
		"msDS-Behavior-Version",
		"trustParent",
	};
	struct tevent_req *subreq = NULL;
	const char *filter = NULL;

	/*
	 * Do a search CN=Partitions,CN=Configuration,...
	 * Filter:
	 * (&(objectClass=crossRef)(systemFlags:1.2.840.113556.1.4.803:=3))
	 * Attrs:
	 * dnsRoot
	 * msDS-DnsRootAlias
	 * nETBIOSName
	 * systemFlags
	 * msDS-Behavior-Version
	 * trustParent
	 */

	filter = talloc_asprintf(state,
				 "(&(objectClass=crossRef)(systemFlags:%s:=%u))",
				 LDB_OID_COMPARATOR_AND,
				 SYSTEM_FLAG_CR_NTDS_NC|
				 SYSTEM_FLAG_CR_NTDS_DOMAIN);
	if (tevent_req_nomem(filter, req)) {
		return;
	}

	subreq = tldap_search_all_send(state,
				       state->ev,
				       state->ld,
				       state->partitions_dn,
				       TLDAP_SCOPE_ONE,
				       filter,
				       attrs,
				       ARRAY_SIZE(attrs),
				       0,    /* attrsonly */
				       NULL, /* sctrls */
				       0,    /* num_sctrls */
				       NULL, /* cctrls */
				       0,    /* num_cctrls */
				       0,    /* timelimit */
				       0,    /* sizelimit */
				       0);   /* deref */
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq,
				ft_scanner_scann_forest_partitions_done,
				req);
}

static void ft_scanner_scann_forest_partitions_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct ft_scanner_scann_forest_state *state =
		tevent_req_data(req,
		struct ft_scanner_scann_forest_state);
	struct tldap_message **msgs = NULL;
	size_t num_msgs;
	struct tldap_message *res = NULL;
	size_t i;
	TLDAPRC rc;

	rc = tldap_search_all_recv(subreq, state, &msgs, &res);
	TALLOC_FREE(subreq);
	if (!TLDAP_RC_IS_SUCCESS(rc)) {
		NTSTATUS status = NT_STATUS_LDAP(TLDAP_RC_V(rc));
		DBG_ERR("tldap_search_all() failed: %s\n",
			tldap_errstr(state, state->ld, rc));
		tevent_req_nterror(req, status);
		return;
	}

	rc = tldap_msg_rc(res);
	if (!TLDAP_RC_IS_SUCCESS(rc)) {
		NTSTATUS status = NT_STATUS_LDAP(TLDAP_RC_V(rc));
		DBG_ERR("tldap_search_all() res failed: %s\n",
			tldap_errstr(state, state->ld, rc));
		tevent_req_nterror(req, status);
		return;
	}

	/*
	 * At least the forest root should be there!
	 */
	num_msgs = talloc_array_length(msgs);
	if (num_msgs == 0) {
		NTSTATUS status = NT_STATUS_INVALID_NETWORK_RESPONSE;
		DBG_NOTICE("tldap_search_all() num_msgs=%zu: %s\n",
			   num_msgs, nt_errstr(status));
		tevent_req_nterror(req, status);
		return;
	}

	state->domains = talloc_zero_array(state,
					   struct ForestTrustDataDomainInfo,
					   num_msgs);
	if (tevent_req_nomem(state->domains, req)) {
		return;
	}

	for (i = 0; i < num_msgs; i++) {
		struct tldap_message *m = msgs[i];
		struct ForestTrustDataDomainInfo *d = &state->domains[i];

		d->dns_name.string = tldap_talloc_single_attribute(m,
								"dnsRoot",
								state->domains);
		if (tevent_req_nomem(d->dns_name.string, req)) {
			return;
		}

		d->netbios_name.string = tldap_talloc_single_attribute(m,
								"nETBIOSName",
								state->domains);
		if (tevent_req_nomem(d->netbios_name.string, req)) {
			return;
		}
	}

	/*
	 * disconnect
	 */
	TALLOC_FREE(state->ld);

	tevent_req_done(req);
}

static NTSTATUS ft_scanner_scann_forest_recv(struct tevent_req *req,
				TALLOC_CTX *mem_ctx,
				struct ForestTrustDataDomainInfo **_domains)
{
	struct ft_scanner_scann_forest_state *state =
		tevent_req_data(req,
		struct ft_scanner_scann_forest_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	*_domains = talloc_move(mem_ctx, &state->domains);
	tevent_req_received(req);
	return NT_STATUS_OK;
}

struct ft_scanner_check_trusts_state;

struct ft_scanner_check_trusts_domain {
	struct ft_scanner_check_trusts_state *state;

	struct GUID tdo_guid;
	struct lsa_TrustDomainInfoInfoEx *tdo;
	struct ldb_message *msg;
};

struct ft_scanner_check_trusts_state {
	struct ft_scanner_service *service;

	struct ft_scanner_check_trusts_domain *domains;
};

static void ft_scanner_check_trusts_scanned(struct tevent_req *subreq);

NTSTATUS ft_scanner_check_trusts(struct ft_scanner_service *service)
{
	static const char * const trust_attrs[] = {
		"objectGUID",
		"securityIdentifier",
		"flatName",
		"trustPartner",
		"trustType",
		"trustAttributes",
		"trustDirection",
		"msDS-TrustForestTrustInfo",
		NULL
	};
	struct ldb_result *trusts_res = NULL;
	unsigned int i;
	NTSTATUS status;
	struct ft_scanner_check_trusts_state *state = NULL;
	size_t num_ft = 0;
	uint32_t timeout_secs;
	struct timeval endtime;

	timeout_secs = service->periodic.interval;
	if (timeout_secs > 75) {
		timeout_secs -= 15;
	}

	endtime = timeval_current_ofs(timeout_secs, 0);

	state = talloc_zero(service, struct ft_scanner_check_trusts_state);
	if (state == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	state->service = service;

	/* fetch all trusted domain objects */
	status = dsdb_trust_search_tdos(service->l_samdb,
					NULL,
					trust_attrs,
					state,
					&trusts_res);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("dsdb_trust_search_tdos() failed %s\n",
			nt_errstr(status));
		TALLOC_FREE(state);
		return status;
	}

	if (trusts_res->count == 0) {
		/*
		 * No trusts => nothing to do...
		 */
		DBG_DEBUG("dsdb_trust_search_tdos() gave 0 results\n");
		TALLOC_FREE(state);
		return NT_STATUS_OK;
	}

	state->domains = talloc_zero_array(state,
					struct ft_scanner_check_trusts_domain,
					trusts_res->count);
	if (state->domains == NULL) {
		/*
		 * We ignore errors and
		 * retry later
		 */
		TALLOC_FREE(state);
		return NT_STATUS_NO_MEMORY;
	}

	for (i = 0; i < trusts_res->count; i++) {
		struct ft_scanner_check_trusts_domain *d =
			&state->domains[i];
		struct tevent_req *subreq = NULL;
		bool ok;

		d->msg = trusts_res->msgs[i];

		d->tdo_guid = samdb_result_guid(d->msg, "objectGUID");

		status = dsdb_trust_parse_tdo_info(state->domains,
						   d->msg,
						   &d->tdo);
		if (!NT_STATUS_IS_OK(status)) {
			/*
			 * We ignore error and continue with the
			 * next domain
			 *
			 * In the hope it will work better later.
			 */
			d->tdo = NULL;
			continue;
		}

		if (!(d->tdo->trust_direction & LSA_TRUST_DIRECTION_INBOUND)) {
			/*
			 * Only inbound trusts should be scanned
			 */
			TALLOC_FREE(d->tdo);
			continue;
		}

		if (!(d->tdo->trust_attributes & LSA_TRUST_ATTRIBUTE_FOREST_TRANSITIVE)) {
			/*
			 * Only forest trusts should be scanned
			 */
			TALLOC_FREE(d->tdo);
			continue;
		}

		subreq = ft_scanner_scann_forest_send(state,
						      service->task->event_ctx,
						      service,
						      d->msg,
						      d->tdo);
		if (subreq == NULL) {
			/*
			 * Ignore errors...
			 *
			 * We'll retry later
			 */
			TALLOC_FREE(d->tdo);
			continue;
		}
		tevent_req_set_callback(subreq,
					ft_scanner_check_trusts_scanned,
					d);

		ok = tevent_req_set_endtime(subreq,
					    service->task->event_ctx,
					    endtime);
		if (!ok) {
			/*
			 * Ignore errors...
			 *
			 * We'll retry later
			 */
			TALLOC_FREE(subreq);
			TALLOC_FREE(d->tdo);
			continue;
		}

		d->state = state;

		num_ft += 1;
	}

	if (num_ft == 0) {
		/*
		 * No inbound forest trusts => nothing to do...
		 */
		DBG_DEBUG("no forest trusts found\n");
		TALLOC_FREE(state);
		return NT_STATUS_OK;
	}

	/*
	 * Keep state for the callbacks
	 */
	DBG_DEBUG("Waiting for %zu forest trusts\n", num_ft);
	return NT_STATUS_OK;
}

static bool ft_scanner_check_trusts_di_equal(const struct ForestTrustDataDomainInfo *s1,
					     const struct ForestTrustDataDomainInfo *s2)
{
	if (!dom_sid_equal(&s1->sid, &s2->sid)) {
		return false;
	}

	if (!strequal(s1->dns_name.string, s2->dns_name.string)) {
		return false;
	}

	if (!strequal(s1->netbios_name.string, s2->netbios_name.string)) {
		return false;
	}

	return true;
}

static void ft_scanner_check_trusts_scanned(struct tevent_req *subreq)
{
	struct ft_scanner_check_trusts_domain *d =
		(struct ft_scanner_check_trusts_domain *)
		tevent_req_callback_data_void(subreq);
	struct ft_scanner_check_trusts_state *state =
		talloc_get_type_abort(d->state,
		struct ft_scanner_check_trusts_state);
	struct ft_scanner_service *service = state->service;
	static const char * const trust_attrs[] = {
		"objectGUID",
		"securityIdentifier",
		"flatName",
		"trustPartner",
		"trustType",
		"trustAttributes",
		"trustDirection",
		"msDS-TrustForestTrustInfo",
		NULL
	};
	struct ForestTrustDataDomainInfo *sdis = NULL;
	size_t num_sdis;
	size_t si;
	struct ldb_result *res = NULL;
	struct lsa_TrustDomainInfoInfoEx *tdo = NULL;
	struct ForestTrustInfo *fti = NULL;
	size_t new_count;
	size_t ri;
	bool modified = false;
	DATA_BLOB ft_blob = {};
	enum ndr_err_code ndr_err;
	struct timeval tv = timeval_current();
	NTTIME now = timeval_to_nttime(&tv);
	struct ldb_message *mod_msg = NULL;
	size_t num_fts;
	size_t num_pending;
	NTSTATUS status;
	size_t fi;
	int ret;

	d->state = NULL;

	status = ft_scanner_scann_forest_recv(subreq,
					      state->domains,
					      &sdis);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_NOTICE("Forest[%s][%s] scann failed: %s\n",
			   d->tdo->domain_name.string,
			   d->tdo->netbios_name.string,
			   nt_errstr(status));
		goto cleanup_state;
	}

	num_sdis = talloc_array_length(sdis);
	DBG_DEBUG("Forest[%s][%s] num_domains[%zu]\n",
		  d->tdo->domain_name.string,
		  d->tdo->netbios_name.string,
		  num_sdis);
	for (si = 0; si < num_sdis; si++) {
		DBG_DEBUG("domain[%zu][%s][%s]\n",
			  si,
			  sdis[si].dns_name.string,
			  sdis[si].netbios_name.string);
	}

	ret = ldb_transaction_start(service->l_samdb);
	if (ret != LDB_SUCCESS) {
		goto cleanup_state;
	}

	ret = dsdb_search_by_dn_guid(service->l_samdb,
				     state->domains,
				     &res,
				     &d->tdo_guid,
				     trust_attrs,
				     DSDB_SEARCH_ONE_ONLY);
	if (ret != LDB_SUCCESS) {
		ldb_transaction_cancel(service->l_samdb);
		goto cleanup_state;
	}

	status = dsdb_trust_parse_tdo_info(state->domains,
					   res->msgs[0],
					   &tdo);
	if (!NT_STATUS_IS_OK(status)) {
		ldb_transaction_cancel(service->l_samdb);
		goto cleanup_state;
	}

	if (!dom_sid_equal(d->tdo->sid, tdo->sid)) {
		ldb_transaction_cancel(service->l_samdb);
		goto cleanup_state;
	}

	if (!strequal(d->tdo->domain_name.string, tdo->domain_name.string)) {
		ldb_transaction_cancel(service->l_samdb);
		goto cleanup_state;
	}

	if (!strequal(d->tdo->netbios_name.string, tdo->netbios_name.string)) {
		ldb_transaction_cancel(service->l_samdb);
		goto cleanup_state;
	}

	if (!(tdo->trust_direction & LSA_TRUST_DIRECTION_INBOUND)) {
		/*
		 * Only inbound trusts should be scanned
		 */
		ldb_transaction_cancel(service->l_samdb);
		goto cleanup_state;
	}

	if (!(tdo->trust_attributes & LSA_TRUST_ATTRIBUTE_FOREST_TRANSITIVE)) {
		/*
		 * Only forest trusts should be scanned
		 */
		ldb_transaction_cancel(service->l_samdb);
		goto cleanup_state;
	}

	status = dsdb_trust_parse_forest_info(state->domains,
					      res->msgs[0],
					      &fti);
	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
		/*
		 * If there's no msDS-TrustForestTrustInfo
		 * create the defeault one
		 */
		status = dsdb_trust_default_forest_info(state->domains,
							tdo->sid,
							tdo->domain_name.string,
							tdo->netbios_name.string,
							now,
							&fti);
		if (!NT_STATUS_IS_OK(status)) {
			ldb_transaction_cancel(service->l_samdb);
			goto cleanup_state;
		}
	}
	if (!NT_STATUS_IS_OK(status)) {
		ldb_transaction_cancel(service->l_samdb);
		goto cleanup_state;
	}

	TALLOC_FREE(tdo);
	if (CHECK_DEBUGLVL(DBGLVL_DEBUG)) {
		NDR_PRINT_DEBUG(ForestTrustInfo, fti);
	}

	/*
	 * First remove stale scanner info records
	 */
	new_count = 0;
	for (ri = 0; ri < fti->count; ri++) {
		struct ForestTrustInfoRecord *dst = &fti->records[new_count].record;
		const struct ForestTrustInfoRecord *r = &fti->records[ri].record;
		const struct ForestTrustDataDomainInfo *es = NULL;
		bool keep = false;

		if (r->type != FOREST_TRUST_SCANNER_INFO) {
			if (dst != r) {
				*dst = *r;
			}
			new_count += 1;
			continue;
		}

		es = &r->data.scanner_info.info;

		for (si = 0; si < num_sdis; si++) {
			const struct ForestTrustDataDomainInfo *cs = &sdis[si];
			bool match;

			match = ft_scanner_check_trusts_di_equal(es, cs);
			if (!match) {
				continue;
			}

			keep = true;
			break;
		}

		if (keep) {
			if (dst != r) {
				*dst = *r;
			}
			new_count += 1;
			continue;
		}

		modified = true;
	}
	fti->count = new_count;

	/*
	 * Now add the missing scanner infos
	 */
	for (si = 0; si < num_sdis; si++) {
		struct ForestTrustDataDomainInfo *cs = &sdis[si];
		struct ForestTrustInfoRecord *dst = NULL;
		bool found = false;

		for (ri = 0; ri < fti->count; ri++) {
			const struct ForestTrustInfoRecord *r = &fti->records[ri].record;
			const struct ForestTrustDataDomainInfo *es = NULL;
			bool match;

			if (r->type != FOREST_TRUST_SCANNER_INFO) {
				continue;
			}

			es = &r->data.scanner_info.info;

			match = ft_scanner_check_trusts_di_equal(es, cs);
			if (!match) {
				continue;
			}

			found = true;
			break;
		}

		if (found) {
			continue;
		}

		fti->records = talloc_realloc(fti,
					      fti->records,
					      struct ForestTrustInfoRecordArmor,
					      fti->count + 1);
		if (fti->records == NULL) {
			ldb_transaction_cancel(service->l_samdb);
			goto cleanup_state;
		}
		dst = &fti->records[fti->count].record;

		dst->flags = 0;
		dst->timestamp = now;
		dst->type = FOREST_TRUST_SCANNER_INFO;
		dst->data.scanner_info.sub_type = FOREST_TRUST_SCANNER_INFO;
		dst->data.scanner_info.info = *cs;

		fti->count += 1;
		modified = true;
	}

	if (!modified) {
		DBG_DEBUG("Forest[%s][%s] no updates\n",
			  d->tdo->domain_name.string,
			  d->tdo->netbios_name.string);
		ldb_transaction_cancel(service->l_samdb);
		goto cleanup_state;
	}

	if (CHECK_DEBUGLVL(DBGLVL_DEBUG)) {
		NDR_PRINT_DEBUG(ForestTrustInfo, fti);
	}

	ndr_err = ndr_push_struct_blob(&ft_blob, state->domains, fti,
				       (ndr_push_flags_fn_t)ndr_push_ForestTrustInfo);
	TALLOC_FREE(fti);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		ldb_transaction_cancel(service->l_samdb);
		goto cleanup_state;
	}

	mod_msg = ldb_msg_new(state->domains);
	if (mod_msg == NULL) {
		ldb_transaction_cancel(service->l_samdb);
		goto cleanup_state;
	}
	mod_msg->dn = ldb_dn_copy(state->domains, res->msgs[0]->dn);
	if (mod_msg->dn == NULL) {
		ldb_transaction_cancel(service->l_samdb);
		goto cleanup_state;
	}

	ret = ldb_msg_append_value(mod_msg,
				   "msDS-TrustForestTrustInfo",
				   &ft_blob,
				   LDB_FLAG_MOD_REPLACE);
	if (ret != LDB_SUCCESS) {
		ldb_transaction_cancel(service->l_samdb);
		goto cleanup_state;
	}

	ret = dsdb_modify(service->l_samdb, mod_msg, 0);
	if (ret != LDB_SUCCESS) {
		ldb_transaction_cancel(service->l_samdb);
		goto cleanup_state;
	}

	ret = ldb_transaction_commit(service->l_samdb);
	if (ret != LDB_SUCCESS) {
		goto cleanup_state;
	}

	DBG_DEBUG("Forest[%s][%s] updated\n",
		  d->tdo->domain_name.string,
		  d->tdo->netbios_name.string);

cleanup_state:
	d = NULL;
	num_fts = 0;
	num_pending = 0;
	for (fi = 0; fi < talloc_array_length(state->domains); fi++) {
		if (state->domains[fi].tdo != NULL) {
			num_fts += 1;
		}

		if (state->domains[fi].state != NULL) {
			num_pending += 1;
		}
	}

	if (num_pending != 0) {
		/* still pending */
		DBG_DEBUG("Pending %zu for %zu forest trusts in %zu domains\n",
			  num_pending, num_fts,
			  talloc_array_length(state->domains));
		return;
	}

	DBG_DEBUG("Done for %zu forest trusts in %zu domains\n",
		  num_fts, talloc_array_length(state->domains));
	talloc_free(state);
}
