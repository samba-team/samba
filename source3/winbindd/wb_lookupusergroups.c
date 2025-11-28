/*
   Unix SMB/CIFS implementation.
   async lookupusergroups
   Copyright (C) Volker Lendecke 2009

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
#include "../libcli/security/security.h"
#include "rpc_client/util_netlogon.h"

struct wb_lookupusergroups_state {
	struct tevent_context *ev;
	struct dom_sid sid;
	struct wbint_SidArray sids;
	struct wbint_KerberosImpersonationTokenValidation validation;
	struct winbindd_domain *domain;
};

static void wb_lookupusergroups_done(struct tevent_req *subreq);
static void wb_lookupusergroups_impersonated_done(struct tevent_req *subreq);

struct tevent_req *wb_lookupusergroups_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    const struct dom_sid *sid,
					    const char *domain_name,
					    const char *acct_name)
{
	struct tevent_req *req, *subreq;
	struct wb_lookupusergroups_state *state;
	struct winbindd_domain *domain;
	struct winbindd_domain *our_domain = NULL;
	NTSTATUS status;
	struct dom_sid_buf buf;
	int global_winbind_use_s4u2self = false;
	bool attempt_s4u2self = false;

	req = tevent_req_create(mem_ctx, &state,
				struct wb_lookupusergroups_state);
	if (req == NULL) {
		return NULL;
	}
	D_INFO("WB command lookupusergroups start.\nLooking up SID %s "
	       "(domain_name: %s, acct_name: %s).\n",
	       dom_sid_str_buf(sid, &buf),
	       domain_name,
	       acct_name);
	sid_copy(&state->sid, sid);

	if (acct_name == NULL || domain_name == NULL) {
		DBG_ERR("No account name for %s\n",
			dom_sid_str_buf(&state->sid, &buf));
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return tevent_req_post(req, ev);
	}

	status = lookup_usergroups_cached(state,
					  &state->sid,
					  &state->sids.num_sids,
					  &state->sids.sids);
	if (NT_STATUS_IS_OK(status)) {
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	domain = find_domain_from_sid_noinit(&state->sid);
	if (domain == NULL) {
		DBG_WARNING("could not find domain entry for sid %s\n",
			    dom_sid_str_buf(&state->sid, &buf));
		tevent_req_nterror(req, NT_STATUS_NO_SUCH_DOMAIN);
		return tevent_req_post(req, ev);
	}

	if (!strequal(domain_name, domain->name)) {
		DBG_WARNING("Account domain name %s does not match winbindd "
			    "domain name %s for %s\n",
			    domain_name,
			    domain->name,
			    dom_sid_str_buf(&state->sid, &buf));
		tevent_req_nterror(req, NT_STATUS_NO_SUCH_DOMAIN);
		return tevent_req_post(req, ev);
	}

	state->ev = ev;
	state->domain = domain;

	/*
	 * allow overwrite per domain
	 * winbind use s4u2self:<netbios_domain>
	 */
	global_winbind_use_s4u2self = lp_winbind_use_s4u2self();
	attempt_s4u2self = global_winbind_use_s4u2self;
	if (!domain->primary) {
		/*
		 * As winbind use s4u2self = yes, is
		 * still experimental, it should only
		 * apply to the primary domain.
		 *
		 * winbind use s4u2self:NBTDOMAIN = yes,
		 * can be used to activate it for other
		 * domains as well, but depending on
		 * the krb5 library it can only work
		 * for the primary domain.
		 * E.g. heimdal only supports the primary domain.
		 */
		attempt_s4u2self = false;
	}
	attempt_s4u2self = lp_parm_bool(-1,
					"winbind use s4u2self",
					domain->name,
					attempt_s4u2self);

	our_domain = find_our_domain();
	SMB_ASSERT(our_domain != NULL);

	/*
	 * Only if our domain is active directory
	 * we can try s4u2self, as we contact the
	 * kdc of our domain first.
	 */
	if (!our_domain->active_directory) {
		attempt_s4u2self = false;
	}

	/*
	 * For now we only try s4u2self on
	 * members of AD domains, but not AD DCs yet.
	 */
	if (IS_AD_DC) {
		attempt_s4u2self = false;
	}

	/*
	 * If the krb5 library doesn't support
	 * s4u2self, we can skip the attempt to
	 * use it here, instead of having the
	 * child rejecting it
	 */
	if (!winbind_s4u2self_krb5_api_support()) {
		attempt_s4u2self = false;
	}

	if (attempt_s4u2self) {
		const char *impersonate_principal = NULL;
		const char *our_realm = lp_realm();

		if (strequal(domain->alt_name, our_realm)) {
			/*
			 * For our own domain we don't
			 * need an enterprise principal.
			 *
			 * That also avoids strange AS-REQ
			 * done by the MIT library in order
			 * to find a realm for NBTDOMAIN as
			 * user realm.
			 */
			impersonate_principal = talloc_asprintf(
				state,
				"%s@%s",
				acct_name,
				our_realm);
			if (tevent_req_nomem(impersonate_principal, req)) {
				return tevent_req_post(req, ev);
			}
		} else {
			const char *u_realm = NULL;

			/*
			 * If we have enough
			 * information about the
			 * users domain, we can use
			 * the realm directly.
			 *
			 * Otherwise we use the
			 * netbios domain name
			 * and let our KDC
			 * canonicalize it while
			 * returning referrals
			 */
			if (domain->alt_name != NULL) {
				u_realm = talloc_strdup_upper(state,
							      domain->alt_name);
				if (tevent_req_nomem(u_realm, req)) {
					return tevent_req_post(req, ev);
				}
			} else {
				/*
				 * This should only be upper
				 */
				u_realm = domain->name;
			}

			impersonate_principal = talloc_asprintf(
				state,
				"%s@%s@%s",
				acct_name,
				u_realm,
				our_realm);
			if (tevent_req_nomem(impersonate_principal, req)) {
				return tevent_req_post(req, ev);
			}
		}

		D_INFO("WB command lookupusergroups impersonate %s\n",
		       impersonate_principal);

		subreq = dcerpc_wbint_KerberosImpersonationToken_send(
			state,
			ev,
			dom_child_handle(our_domain),
			impersonate_principal,
			&state->validation);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq,
					wb_lookupusergroups_impersonated_done,
					req);
		return req;
	}

	subreq = dcerpc_wbint_LookupUserGroups_send(
		state, ev, dom_child_handle(domain), &state->sid, &state->sids);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, wb_lookupusergroups_done, req);
	return req;
}

static void wb_lookupusergroups_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wb_lookupusergroups_state *state = tevent_req_data(
		req, struct wb_lookupusergroups_state);
	NTSTATUS status, result;

	status = dcerpc_wbint_LookupUserGroups_recv(subreq, state, &result);
	TALLOC_FREE(subreq);
	if (any_nt_status_not_ok(status, result, &status)) {
		D_WARNING("Failed with %s.\n", nt_errstr(status));
		tevent_req_nterror(req, status);
		return;
	}
	tevent_req_done(req);
}

static void wb_lookupusergroups_impersonated_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
							  struct tevent_req);
	struct wb_lookupusergroups_state *state = tevent_req_data(
		req, struct wb_lookupusergroups_state);
	NTSTATUS status, result;
	bool ok;
	struct netr_SamInfo3 *info3;
	bool retry_lookupusergroups = false;

	status = dcerpc_wbint_KerberosImpersonationToken_recv(subreq,
							      state,
							      &result);
	TALLOC_FREE(subreq);

	if (any_nt_status_not_ok(status, result, &status)) {
		D_WARNING("Failed S4U2SELF impersonation with %s.\n",
			  nt_errstr(status));
	}

	if (NT_STATUS_EQUAL(status, NT_STATUS_NO_S4U_PROT_SUPPORT)) {
		/* no s4u2self krb5 api support */
		retry_lookupusergroups = true;
	}

	if (NT_STATUS_EQUAL(status, NT_STATUS_LOGON_FAILURE) ||
	    NT_STATUS_EQUAL(status, NT_STATUS_TIME_DIFFERENCE_AT_DC))
	{
		/* clock skew or disabled account in AD */
		retry_lookupusergroups = true;
	}

	if (NT_STATUS_EQUAL(status, NT_STATUS_ACCOUNT_LOCKED_OUT)) {
		/* disabled account when not using enterprise principals */
		retry_lookupusergroups = true;
	}

	if (retry_lookupusergroups) {
		subreq = dcerpc_wbint_LookupUserGroups_send(
			state,
			state->ev,
			dom_child_handle(state->domain),
			&state->sid,
			&state->sids);
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq, wb_lookupusergroups_done, req);
		return;
	}

	if (any_nt_status_not_ok(status, result, &status)) {
		tevent_req_nterror(req, status);
		return;
	}

	/*
	 * TODO: replace the next two calls with a new
	 * sid_array_from_validation() call - gd
	 */

	status = map_validation_to_info3(state,
					 state->validation.level,
					 state->validation.validation,
					 &info3);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}

	status = sid_array_from_info3(
		state, info3, &state->sids.sids, &state->sids.num_sids, true);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}

	/*
	 * Cross-check state->sid with token primary sid to make sure we don't
	 * process incorrect information from a PAC.
	 */

	ok = dom_sid_equal(&state->sid, &state->sids.sids[0]);
	if (!ok) {
		struct dom_sid_buf buf;
		D_WARNING("SID mismatch after S4U2SELF impersonation "
			  "(requested: %s, returned: %s)\n",
			  dom_sid_str_buf(&state->sid, &buf),
			  dom_sid_str_buf(&state->sids.sids[0], &buf));
		tevent_req_nterror(req, NT_STATUS_SERVER_SID_MISMATCH);
		return;
	}

	tevent_req_done(req);
}

NTSTATUS wb_lookupusergroups_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
				  uint32_t *num_sids, struct dom_sid **sids)
{
	struct wb_lookupusergroups_state *state = tevent_req_data(
		req, struct wb_lookupusergroups_state);
	NTSTATUS status;
	uint32_t i;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	*num_sids = state->sids.num_sids;
	*sids = talloc_move(mem_ctx, &state->sids.sids);

	D_INFO("WB command lookupusergroups end.\nReceived %"PRIu32" SID(s).\n",
	       *num_sids);
	if (CHECK_DEBUGLVL(DBGLVL_INFO)) {
		for (i = 0; i < *num_sids; i++) {
			struct dom_sid_buf buf;
			D_INFO("%"PRIu32": %s\n",
			       i, dom_sid_str_buf(&(*sids)[i], &buf));
		}
	}
	return NT_STATUS_OK;
}
