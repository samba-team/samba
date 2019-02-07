/*
   Unix SMB/CIFS implementation.
   async implementation of commands submitted over IRPC
   Copyright (C) Volker Lendecke 2009
   Copyright (C) Guenther Deschner 2009
   Copyright (C) Andrew Bartlett 2014
   Copyright (C) Andrew Tridgell 2009

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
#include "winbindd.h"
#include "librpc/gen_ndr/ndr_winbind_c.h"
#include "source4/lib/messaging/irpc.h"
#include "librpc/gen_ndr/ndr_winbind.h"
#include "librpc/gen_ndr/ndr_lsa.h"
#include "librpc/gen_ndr/ndr_lsa_c.h"
#include "libcli/security/dom_sid.h"
#include "passdb/lookup_sid.h" /* only for LOOKUP_NAME_NO_NSS flag */
#include "librpc/gen_ndr/ndr_irpc.h"
#include "librpc/gen_ndr/ndr_netlogon.h"

struct wb_irpc_forward_state {
	struct irpc_message *msg;
	const char *opname;
	struct dcesrv_call_state *dce_call;
};

/*
  called when the forwarded rpc request is finished
 */
static void wb_irpc_forward_callback(struct tevent_req *subreq)
{
	struct wb_irpc_forward_state *st =
		tevent_req_callback_data(subreq,
		struct wb_irpc_forward_state);
	const char *opname = st->opname;
	NTSTATUS status;

	status = dcerpc_binding_handle_call_recv(subreq);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("RPC callback failed for %s - %s\n",
			 opname, nt_errstr(status)));
		irpc_send_reply(st->msg, status);
		return;
	}

	irpc_send_reply(st->msg, status);
}



/**
 * Forward a RPC call using IRPC to another task
 */

static NTSTATUS wb_irpc_forward_rpc_call(struct irpc_message *msg, TALLOC_CTX *mem_ctx,
					 struct tevent_context *ev,
					 void *r, uint32_t callid,
					 const char *opname,
					 struct winbindd_domain *domain,
					 uint32_t timeout)
{
	struct wb_irpc_forward_state *st;
	struct dcerpc_binding_handle *binding_handle;
	struct tevent_req *subreq;

	st = talloc(mem_ctx, struct wb_irpc_forward_state);
	if (st == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	st->msg = msg;
	st->opname   = opname;

	binding_handle =  dom_child_handle(domain);
	if (binding_handle == NULL) {
		DEBUG(0,("%s: Failed to forward request to winbind handler for %s\n",
			 opname, domain->name));
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* reset timeout for the handle */
	dcerpc_binding_handle_set_timeout(binding_handle, timeout);

	/* forward the call */
	subreq = dcerpc_binding_handle_call_send(st, ev,
						 binding_handle,
						 NULL, &ndr_table_winbind,
						 callid,
						 msg, r);
	if (subreq == NULL) {
		DEBUG(0,("%s: Failed to forward request to winbind handler for %s\n",
			 opname, domain->name));
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* mark the request as replied async */
	msg->defer_reply = true;

	/* setup the callback */
	tevent_req_set_callback(subreq, wb_irpc_forward_callback, st);
	return NT_STATUS_OK;
}

static NTSTATUS wb_irpc_DsrUpdateReadOnlyServerDnsRecords(struct irpc_message *msg,
						   struct winbind_DsrUpdateReadOnlyServerDnsRecords *req)
{
	struct winbindd_domain *domain = find_our_domain();
	if (domain == NULL) {
		return NT_STATUS_NO_SUCH_DOMAIN;
	}

	DEBUG(5, ("wb_irpc_DsrUpdateReadOnlyServerDnsRecords called\n"));

	return wb_irpc_forward_rpc_call(msg, msg,
					global_event_context(),
					req, NDR_WINBIND_DSRUPDATEREADONLYSERVERDNSRECORDS,
					"winbind_DsrUpdateReadOnlyServerDnsRecords",
					domain, IRPC_CALL_TIMEOUT);
}

static NTSTATUS wb_irpc_SamLogon(struct irpc_message *msg,
				 struct winbind_SamLogon *req)
{
	struct winbindd_domain *domain;
	struct netr_IdentityInfo *identity_info;
	const char *target_domain_name = NULL;
	const char *account_name = NULL;

	switch (req->in.logon_level) {
	case NetlogonInteractiveInformation:
	case NetlogonServiceInformation:
	case NetlogonInteractiveTransitiveInformation:
	case NetlogonServiceTransitiveInformation:
		if (req->in.logon.password == NULL) {
			return NT_STATUS_REQUEST_NOT_ACCEPTED;
		}
		identity_info = &req->in.logon.password->identity_info;
		break;

	case NetlogonNetworkInformation:
	case NetlogonNetworkTransitiveInformation:
		if (req->in.logon.network == NULL) {
			return NT_STATUS_REQUEST_NOT_ACCEPTED;
		}

		identity_info = &req->in.logon.network->identity_info;
		break;

	case NetlogonGenericInformation:
		if (req->in.logon.generic == NULL) {
			return NT_STATUS_REQUEST_NOT_ACCEPTED;
		}

		identity_info = &req->in.logon.generic->identity_info;
		break;

	default:
		return NT_STATUS_REQUEST_NOT_ACCEPTED;
	}

	target_domain_name = identity_info->domain_name.string;
	if (target_domain_name == NULL) {
		target_domain_name = "";
	}

	account_name = identity_info->account_name.string;
	if (account_name == NULL) {
		account_name = "";
	}

	if (IS_DC && target_domain_name[0] == '\0') {
		const char *p = NULL;

		p = strchr_m(account_name, '@');
		if (p != NULL) {
			target_domain_name = p + 1;
		}
	}

	if (IS_DC && target_domain_name[0] == '\0') {
		DBG_ERR("target_domain[%s] account[%s]\n",
			target_domain_name, account_name);
		return NT_STATUS_REQUEST_NOT_ACCEPTED;
	}

	domain = find_auth_domain(0, target_domain_name);
	if (domain == NULL) {
		DBG_INFO("target_domain[%s] for account[%s] not known\n",
			target_domain_name, account_name);
		req->out.result = NT_STATUS_NO_SUCH_USER;
		req->out.authoritative = 0;
		return NT_STATUS_OK;
	}

	DEBUG(5, ("wb_irpc_SamLogon called\n"));

	return wb_irpc_forward_rpc_call(msg, msg,
					global_event_context(),
					req, NDR_WINBIND_SAMLOGON,
					"winbind_SamLogon",
					domain, IRPC_CALL_TIMEOUT);
}

static NTSTATUS wb_irpc_LogonControl(struct irpc_message *msg,
				     struct winbind_LogonControl *req)
{
	TALLOC_CTX *frame = talloc_stackframe();
	char *domain_name = NULL;
	struct winbindd_domain *domain = NULL;

	DEBUG(5, ("wb_irpc_LogonControl called\n"));

	switch (req->in.function_code) {
	case NETLOGON_CONTROL_REDISCOVER:
	case NETLOGON_CONTROL_TC_QUERY:
	case NETLOGON_CONTROL_CHANGE_PASSWORD:
	case NETLOGON_CONTROL_TC_VERIFY:
		if (req->in.data->domain == NULL) {
			TALLOC_FREE(frame);
			return NT_STATUS_INVALID_PARAMETER;
		}

		domain_name = talloc_strdup(frame, req->in.data->domain);
		if (domain_name == NULL) {
			req->out.result = WERR_NOT_ENOUGH_MEMORY;
			TALLOC_FREE(frame);
			return NT_STATUS_OK;
		}

		break;
	default:
		TALLOC_FREE(frame);
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	if (req->in.function_code == NETLOGON_CONTROL_REDISCOVER) {
		char *p = NULL;

		/*
		 * NETLOGON_CONTROL_REDISCOVER
		 * get's an optional \dcname appended to the domain name
		 */
		p = strchr_m(domain_name, '\\');
		if (p != NULL) {
			*p = '\0';
		}
	}

	domain = find_domain_from_name_noinit(domain_name);
	if (domain == NULL) {
		req->out.result = WERR_NO_SUCH_DOMAIN;
		TALLOC_FREE(frame);
		return NT_STATUS_OK;
	}

	TALLOC_FREE(frame);
	return wb_irpc_forward_rpc_call(msg, msg,
					global_event_context(),
					req, NDR_WINBIND_LOGONCONTROL,
					"winbind_LogonControl",
					domain, 45 /* timeout */);
}

static NTSTATUS wb_irpc_GetForestTrustInformation(struct irpc_message *msg,
				     struct winbind_GetForestTrustInformation *req)
{
	struct winbindd_domain *domain = NULL;

	if (req->in.trusted_domain_name == NULL) {
		req->out.result = WERR_NO_SUCH_DOMAIN;
		return NT_STATUS_OK;
	}

	domain = find_trust_from_name_noinit(req->in.trusted_domain_name);
	if (domain == NULL) {
		req->out.result = WERR_NO_SUCH_DOMAIN;
		return NT_STATUS_OK;
	}

	/*
	 * checking for domain->internal and domain->primary
	 * makes sure we only do some work when running as DC.
	 */

	if (domain->internal) {
		req->out.result = WERR_NO_SUCH_DOMAIN;
		return NT_STATUS_OK;
	}

	if (domain->primary) {
		req->out.result = WERR_NO_SUCH_DOMAIN;
		return NT_STATUS_OK;
	}

	DEBUG(5, ("wb_irpc_GetForestTrustInformation called\n"));

	return wb_irpc_forward_rpc_call(msg, msg,
					global_event_context(),
					req, NDR_WINBIND_GETFORESTTRUSTINFORMATION,
					"winbind_GetForestTrustInformation",
					domain, 45 /* timeout */);
}

static NTSTATUS wb_irpc_SendToSam(struct irpc_message *msg,
				  struct winbind_SendToSam *req)
{
	/* TODO make sure that it is RWDC */
	struct winbindd_domain *domain = find_our_domain();
	if (domain == NULL) {
		return NT_STATUS_NO_SUCH_DOMAIN;
	}

	DEBUG(5, ("wb_irpc_SendToSam called\n"));

	return wb_irpc_forward_rpc_call(msg, msg,
					global_event_context(),
					req, NDR_WINBIND_SENDTOSAM,
					"winbind_SendToSam",
					domain, IRPC_CALL_TIMEOUT);
}

struct wb_irpc_lsa_LookupSids3_state {
	struct irpc_message *msg;
	struct lsa_LookupSids3 *req;
};

static void wb_irpc_lsa_LookupSids3_done(struct tevent_req *subreq);

static NTSTATUS wb_irpc_lsa_LookupSids3_call(struct irpc_message *msg,
					     struct lsa_LookupSids3 *req)
{
	struct wb_irpc_lsa_LookupSids3_state *state = NULL;
	struct tevent_req *subreq = NULL;
	struct dom_sid *sids = NULL;
	uint32_t i;

	state = talloc_zero(msg, struct wb_irpc_lsa_LookupSids3_state);
	if (state == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	state->msg = msg;
	state->req = req;

	state->req->out.domains = talloc_zero(state->msg,
					struct lsa_RefDomainList *);
	if (state->req->out.domains == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	state->req->out.names = talloc_zero(state->msg,
					    struct lsa_TransNameArray2);
	if (state->req->out.names == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	state->req->out.count = talloc_zero(state->msg, uint32_t);
	if (state->req->out.count == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	state->req->out.names->names = talloc_zero_array(state->msg,
						struct lsa_TranslatedName2,
						req->in.sids->num_sids);
	if (state->req->out.names->names == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	sids = talloc_zero_array(state, struct dom_sid,
				 req->in.sids->num_sids);
	if (sids == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i = 0; i < req->in.sids->num_sids; i++) {
		if (req->in.sids->sids[i].sid == NULL) {
			return NT_STATUS_REQUEST_NOT_ACCEPTED;
		}

		sids[i] = *req->in.sids->sids[i].sid;
	}

	subreq = wb_lookupsids_send(msg,
				    global_event_context(),
				    sids, req->in.sids->num_sids);
	if (subreq == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	tevent_req_set_callback(subreq, wb_irpc_lsa_LookupSids3_done, state);
	msg->defer_reply = true;

	return NT_STATUS_OK;
}

static void wb_irpc_lsa_LookupSids3_done(struct tevent_req *subreq)
{
	struct wb_irpc_lsa_LookupSids3_state *state =
		tevent_req_callback_data(subreq,
		struct wb_irpc_lsa_LookupSids3_state);
	struct lsa_RefDomainList *domains = NULL;
	struct lsa_TransNameArray *names = NULL;
	NTSTATUS status;
	uint32_t i;

	status = wb_lookupsids_recv(subreq, state->msg,
				    &domains, &names);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("RPC callback failed for %s - %s\n",
			 __func__, nt_errstr(status)));
		irpc_send_reply(state->msg, status);
		return;
	}

	if (names->count > state->req->in.sids->num_sids) {
		status = NT_STATUS_INTERNAL_ERROR;
		DEBUG(0,("RPC callback failed for %s - %s\n",
			 __func__, nt_errstr(status)));
		irpc_send_reply(state->msg, status);
		return;
	}

	*state->req->out.domains = domains;
	for (i = 0; i < names->count; i++) {
		struct lsa_TranslatedName2 *n2 =
			&state->req->out.names->names[i];

		n2->sid_type = names->names[i].sid_type;
		n2->name = names->names[i].name;
		n2->sid_index = names->names[i].sid_index;
		n2->unknown = 0;

		if (n2->sid_type != SID_NAME_UNKNOWN) {
			(*state->req->out.count)++;
		}
	}
	state->req->out.names->count = names->count;

	if (*state->req->out.count == 0) {
		state->req->out.result = NT_STATUS_NONE_MAPPED;
	} else if (*state->req->out.count != names->count) {
		state->req->out.result = NT_STATUS_SOME_NOT_MAPPED;
	} else {
		state->req->out.result = NT_STATUS_OK;
	}

	irpc_send_reply(state->msg, NT_STATUS_OK);
	return;
}

struct wb_irpc_lsa_LookupNames4_name {
	void *state;
	uint32_t idx;
	const char *namespace;
	const char *domain;
	char *name;
	struct dom_sid sid;
	enum lsa_SidType type;
	struct dom_sid *authority_sid;
};

struct wb_irpc_lsa_LookupNames4_state {
	struct irpc_message *msg;
	struct lsa_LookupNames4 *req;
	struct wb_irpc_lsa_LookupNames4_name *names;
	uint32_t num_pending;
	uint32_t num_domain_sids;
	struct dom_sid *domain_sids;
};

static void wb_irpc_lsa_LookupNames4_done(struct tevent_req *subreq);

static NTSTATUS wb_irpc_lsa_LookupNames4_call(struct irpc_message *msg,
					      struct lsa_LookupNames4 *req)
{
	struct wb_irpc_lsa_LookupNames4_state *state = NULL;
	struct tevent_req *subreq = NULL;
	uint32_t i;


	state = talloc_zero(msg, struct wb_irpc_lsa_LookupNames4_state);
	if (state == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	state->msg = msg;
	state->req = req;

	state->req->out.domains = talloc_zero(state->msg,
					struct lsa_RefDomainList *);
	if (state->req->out.domains == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	state->req->out.sids = talloc_zero(state->msg,
					   struct lsa_TransSidArray3);
	if (state->req->out.sids == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	state->req->out.count = talloc_zero(state->msg, uint32_t);
	if (state->req->out.count == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	state->req->out.sids->sids = talloc_zero_array(state->msg,
						struct lsa_TranslatedSid3,
						req->in.num_names);
	if (state->req->out.sids->sids == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	state->names = talloc_zero_array(state,
					 struct wb_irpc_lsa_LookupNames4_name,
					 req->in.num_names);
	if (state->names == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i = 0; i < req->in.num_names; i++) {
		struct wb_irpc_lsa_LookupNames4_name *nstate =
			&state->names[i];
		char *p = NULL;

		if (req->in.names[i].string == NULL) {
			DBG_ERR("%s: name[%s] NT_STATUS_REQUEST_NOT_ACCEPTED.\n",
				__location__, req->in.names[i].string);
			return NT_STATUS_REQUEST_NOT_ACCEPTED;
		}
		nstate->state = state;
		nstate->idx = i;
		nstate->name = talloc_strdup(state->names,
					     req->in.names[i].string);
		if (nstate->name == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		nstate->type = SID_NAME_UNKNOWN;

		/* cope with the name being a fully qualified name */
		p = strchr(nstate->name, '\\');
		if (p != NULL) {
			*p = 0;
			nstate->domain = nstate->name;
			nstate->namespace = nstate->domain;
			nstate->name = p+1;
		} else if ((p = strchr(nstate->name, '@')) != NULL) {
			/* upn */
			nstate->domain = "";
			nstate->namespace = p + 1;
		} else {
			/*
			 * TODO: select the domain based on
			 * req->in.level and req->in.client_revision
			 *
			 * For now we don't allow this.
			 */
			DBG_ERR("%s: name[%s] NT_STATUS_REQUEST_NOT_ACCEPTED.\n",
				__location__, nstate->name);
			return NT_STATUS_REQUEST_NOT_ACCEPTED;
		}

		subreq = wb_lookupname_send(msg,
					    global_event_context(),
					    nstate->namespace,
					    nstate->domain,
					    nstate->name,
					    LOOKUP_NAME_NO_NSS);
		if (subreq == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		tevent_req_set_callback(subreq,
					wb_irpc_lsa_LookupNames4_done,
					nstate);
		state->num_pending++;
	}

	msg->defer_reply = true;

	return NT_STATUS_OK;
}

static void wb_irpc_lsa_LookupNames4_domains_done(struct tevent_req *subreq);

static void wb_irpc_lsa_LookupNames4_done(struct tevent_req *subreq)
{
	struct wb_irpc_lsa_LookupNames4_name *nstate =
		(struct wb_irpc_lsa_LookupNames4_name *)
		tevent_req_callback_data_void(subreq);
	struct wb_irpc_lsa_LookupNames4_state *state =
		talloc_get_type_abort(nstate->state,
		struct wb_irpc_lsa_LookupNames4_state);
	struct dom_sid_buf buf;
	NTSTATUS status;

	SMB_ASSERT(state->num_pending > 0);
	state->num_pending--;
	status = wb_lookupname_recv(subreq, &nstate->sid, &nstate->type);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("RPC callback failed for %s - %s\n",
			 __func__, nt_errstr(status)));
		irpc_send_reply(state->msg, status);
		return;
	}

	status = dom_sid_split_rid(state, &nstate->sid,
				   &nstate->authority_sid, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("dom_sid_split_rid(%s) failed - %s\n",
			dom_sid_str_buf(&nstate->sid, &buf),
			nt_errstr(status));
		irpc_send_reply(state->msg, status);
		return;
	}

	status = add_sid_to_array_unique(state,
					 nstate->authority_sid,
					 &state->domain_sids,
					 &state->num_domain_sids);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("add_sid_to_array_unique(%s) failed - %s\n",
			dom_sid_str_buf(nstate->authority_sid, &buf),
			nt_errstr(status));
		irpc_send_reply(state->msg, status);
		return;
	}

	if (state->num_pending > 0) {
		/*
		 * wait for more...
		 */
		return;
	}

	/*
	 * Now resolve all domains back to a name
	 * to get a good lsa_RefDomainList
	 */
	subreq = wb_lookupsids_send(state,
				    global_event_context(),
				    state->domain_sids,
				    state->num_domain_sids);
	if (subreq == NULL) {
		status = NT_STATUS_NO_MEMORY;
		DBG_ERR("wb_lookupsids_send - %s\n",
			nt_errstr(status));
		irpc_send_reply(state->msg, status);
		return;
	}
	tevent_req_set_callback(subreq,
				wb_irpc_lsa_LookupNames4_domains_done,
				state);

	return;
}

static void wb_irpc_lsa_LookupNames4_domains_done(struct tevent_req *subreq)
{
	struct wb_irpc_lsa_LookupNames4_state *state =
		tevent_req_callback_data(subreq,
		struct wb_irpc_lsa_LookupNames4_state);
	struct lsa_RefDomainList *domains = NULL;
	struct lsa_TransNameArray *names = NULL;
	NTSTATUS status;
	uint32_t i;

	status = wb_lookupsids_recv(subreq, state->msg,
				    &domains, &names);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("RPC callback failed for %s - %s\n",
			 __func__, nt_errstr(status)));
		irpc_send_reply(state->msg, status);
		return;
	}

	*state->req->out.domains = domains;
	for (i = 0; i < state->req->in.num_names; i++) {
		struct wb_irpc_lsa_LookupNames4_name *nstate =
			&state->names[i];
		struct lsa_TranslatedSid3 *s3 =
			&state->req->out.sids->sids[i];
		uint32_t di;

		s3->sid_type = nstate->type;
		if (s3->sid_type != SID_NAME_UNKNOWN) {
			s3->sid = &nstate->sid;
		} else {
			s3->sid = NULL;
		}
		s3->sid_index = UINT32_MAX;
		for (di = 0; di < domains->count; di++) {
			bool match;

			if (domains->domains[di].sid == NULL) {
				continue;
			}

			match = dom_sid_equal(nstate->authority_sid,
					      domains->domains[di].sid);
			if (match) {
				s3->sid_index = di;
				break;
			}
		}
		if (s3->sid_type != SID_NAME_UNKNOWN) {
			(*state->req->out.count)++;
		}
	}
	state->req->out.sids->count = state->req->in.num_names;

	if (*state->req->out.count == 0) {
		state->req->out.result = NT_STATUS_NONE_MAPPED;
	} else if (*state->req->out.count != state->req->in.num_names) {
		state->req->out.result = NT_STATUS_SOME_NOT_MAPPED;
	} else {
		state->req->out.result = NT_STATUS_OK;
	}

	irpc_send_reply(state->msg, NT_STATUS_OK);
	return;
}

struct wb_irpc_GetDCName_state {
	struct irpc_message *msg;
	struct wbint_DsGetDcName *req;
};

static void wb_irpc_GetDCName_done(struct tevent_req *subreq);

static NTSTATUS wb_irpc_GetDCName(struct irpc_message *msg,
				  struct wbint_DsGetDcName *req)
{

	struct tevent_req *subreq = NULL;
	struct wb_irpc_GetDCName_state *state = NULL;

	state = talloc_zero(msg, struct wb_irpc_GetDCName_state);
	if (state == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	state->msg = msg;
	state->req = req;

	subreq = wb_dsgetdcname_send(msg,
				     global_event_context(),
				     req->in.domain_name,
				     req->in.domain_guid,
				     req->in.site_name,
				     req->in.flags);
	if (subreq == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	tevent_req_set_callback(subreq,
				wb_irpc_GetDCName_done,
				state);

	msg->defer_reply = true;

	return NT_STATUS_OK;
}

static void wb_irpc_GetDCName_done(struct tevent_req *subreq)
{
	struct wb_irpc_GetDCName_state *state = tevent_req_callback_data(
		subreq, struct wb_irpc_GetDCName_state);
	NTSTATUS status;

	status = wb_dsgetdcname_recv(subreq, state->msg,
				     state->req->out.dc_info);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_INFO("RPC callback failed for %s - %s\n", "DSGETDCNAME",
			 nt_errstr(status));
	}

	state->req->out.result = status;

	irpc_send_reply(state->msg, NT_STATUS_OK);
}

NTSTATUS wb_irpc_register(void)
{
	NTSTATUS status;

	status = IRPC_REGISTER(winbind_imessaging_context(), winbind, WINBIND_DSRUPDATEREADONLYSERVERDNSRECORDS,
			       wb_irpc_DsrUpdateReadOnlyServerDnsRecords, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	status = IRPC_REGISTER(winbind_imessaging_context(), winbind, WINBIND_SAMLOGON,
			       wb_irpc_SamLogon, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	status = IRPC_REGISTER(winbind_imessaging_context(), winbind,
			       WINBIND_LOGONCONTROL,
			       wb_irpc_LogonControl, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	status = IRPC_REGISTER(winbind_imessaging_context(), winbind,
			       WINBIND_GETFORESTTRUSTINFORMATION,
			       wb_irpc_GetForestTrustInformation, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	status = IRPC_REGISTER(winbind_imessaging_context(), winbind, WINBIND_SENDTOSAM,
			       wb_irpc_SendToSam, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	status = IRPC_REGISTER(winbind_imessaging_context(),
			       lsarpc, LSA_LOOKUPSIDS3,
			       wb_irpc_lsa_LookupSids3_call, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	status = IRPC_REGISTER(winbind_imessaging_context(),
			       lsarpc, LSA_LOOKUPNAMES4,
			       wb_irpc_lsa_LookupNames4_call, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	status = IRPC_REGISTER(winbind_imessaging_context(),
			       winbind, WBINT_DSGETDCNAME,
			       wb_irpc_GetDCName, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}
