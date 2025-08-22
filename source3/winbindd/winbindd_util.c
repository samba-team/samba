/*
   Unix SMB/CIFS implementation.

   Winbind daemon for ntdom nss module

   Copyright (C) Tim Potter 2000-2001
   Copyright (C) 2001 by Martin Pool <mbp@samba.org>

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
#include "lib/util_unixsids.h"
#include "secrets.h"
#include "../libcli/lsarpc/util_lsarpc.h"
#include "../libcli/security/security.h"
#include "../libcli/auth/pam_errors.h"
#include "passdb/machine_sid.h"
#include "passdb.h"
#include "source4/lib/messaging/messaging.h"
#include "librpc/gen_ndr/ndr_lsa.h"
#include "librpc/gen_ndr/ndr_drsblobs.h"
#include "auth/credentials/credentials.h"
#include "libsmb/samlogon_cache.h"
#include "lib/util/smb_strtox.h"
#include "lib/util/string_wrappers.h"
#include "lib/global_contexts.h"
#include "librpc/gen_ndr/ndr_winbind_c.h"
#include "../libcli/lsarpc/util_lsarpc.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_WINBIND

/**
 * @file winbindd_util.c
 *
 * Winbind daemon for NT domain authentication nss module.
 **/

/* The list of trusted domains.  Note that the list can be deleted and
   recreated using the init_domain_list() function so pointers to
   individual winbindd_domain structures cannot be made.  Keep a copy of
   the domain name instead. */

static struct winbindd_domain *_domain_list = NULL;
static uint64_t domain_list_generation;

struct winbindd_domain *domain_list(void)
{
	/* Initialise list */

	if ((!_domain_list) && (!init_domain_list())) {
		smb_panic("Init_domain_list failed");
	}

	return _domain_list;
}

/**
 * Iterator for winbindd's domain list.
 * To be used (e.g.) in tevent based loops.
 */
struct winbindd_domain *wb_next_domain(struct winbindd_domain *domain)
{
	if (domain == NULL) {
		domain = domain_list();
	} else {
		domain = domain->next;
	}

	if ((domain != NULL) &&
	    (lp_server_role() != ROLE_ACTIVE_DIRECTORY_DC) &&
	    sid_check_is_our_sam(&domain->sid))
	{
		domain = domain->next;
	}

	return domain;
}

void _winbindd_domain_ref_set(struct winbindd_domain_ref *ref,
			      struct winbindd_domain *domain,
			      const char *location,
			      const char *func)
{
	if (domain == NULL) {
		ref->internals = (struct winbindd_domain_ref_internals) {
			.location = location,
			.func = func,
		};
		return;
	}

	ref->internals = (struct winbindd_domain_ref_internals) {
		.location = location,
		.func = func,
		.sid = domain->sid,
		.generation = domain_list_generation,
		.domain = domain,
	};
}

bool _winbindd_domain_ref_get(struct winbindd_domain_ref *ref,
			      struct winbindd_domain **_domain,
			      const char *location,
			      const char *func)
{
	struct winbindd_domain *domain = NULL;

	if (ref->internals.stale) {
		goto stale;
	}

	if (ref->internals.domain == NULL) {
		*_domain = NULL;
		return true;
	}

	if (ref->internals.generation == domain_list_generation) {
		*_domain = ref->internals.domain;
		return true;
	}

	domain = find_domain_from_sid_noinit(&ref->internals.sid);
stale:
	if (domain == NULL) {
		struct dom_sid_buf sbuf = {};

		D_ERR("%s:%s: stale domain %s, set in %s\n",
		      func,
		      location,
		      dom_sid_str_buf(&ref->internals.sid, &sbuf),
		      ref->internals.location);

		ref->internals.stale = true;
		ref->internals.domain = NULL;

		*_domain = NULL;
		return false;
	}

	ref->internals = (struct winbindd_domain_ref_internals) {
		.location = location,
		.func = func,
		.sid = domain->sid,
		.generation = domain_list_generation,
		.domain = domain,
	};

	*_domain = domain;
	return true;
}

static bool is_internal_domain(const struct dom_sid *sid)
{
	if (sid == NULL)
		return False;

	return (sid_check_is_our_sam(sid) || sid_check_is_builtin(sid));
}

/* Add a trusted domain to our list of domains.
   If the domain already exists in the list,
   return it and don't re-initialize.  */

static NTSTATUS add_trusted_domain(const char *domain_name,
				   const char *dns_name,
				   const struct dom_sid *sid,
				   uint32_t trust_type,
				   uint32_t trust_flags,
				   uint32_t trust_attribs,
				   enum netr_SchannelType secure_channel_type,
				   struct winbindd_domain *routing_domain,
				   struct winbindd_domain **_d)
{
	struct winbindd_domain *domain = NULL;
	int role = lp_server_role();
	struct dom_sid_buf buf;

	if (is_null_sid(sid)) {
		DBG_ERR("Got null SID for domain [%s]\n", domain_name);
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (secure_channel_type == SEC_CHAN_NULL && !is_allowed_domain(domain_name)) {
		return NT_STATUS_NO_SUCH_DOMAIN;
	}

	/*
	 * We can't call domain_list() as this function is called from
	 * init_domain_list() and we'll get stuck in a loop.
	 */
	for (domain = _domain_list; domain; domain = domain->next) {
		if (strequal(domain_name, domain->name)) {
			break;
		}
	}

	if (domain != NULL) {
		struct winbindd_domain *check_domain = NULL;

		if (!dom_sid_equal(&domain->sid, sid)) {
			struct dom_sid_buf buf2;
			DBG_ERR("SID [%s] changed for domain [%s], "
				"expected [%s]\n",
				dom_sid_str_buf(sid, &buf),
				domain->name,
				dom_sid_str_buf(sid, &buf2));
			return NT_STATUS_INVALID_PARAMETER;
		}

		for (check_domain = _domain_list;
		     check_domain != NULL;
		     check_domain = check_domain->next)
		{
			if (check_domain == domain) {
				continue;
			}

			if (dom_sid_equal(&check_domain->sid, sid)) {
				break;
			}
		}

		if (check_domain != NULL) {
			DBG_ERR("SID [%s] already used by domain [%s], "
				"expected [%s]\n",
				dom_sid_str_buf(sid, &buf),
				check_domain->name,
				domain->name);
			return NT_STATUS_INVALID_PARAMETER;
		}
	}

	if ((domain != NULL) && (dns_name != NULL)) {
		struct winbindd_domain *check_domain = NULL;

		if (!strequal(domain->alt_name, dns_name)) {
			DBG_ERR("DNS name [%s] changed for domain [%s], "
				"expected [%s]\n",
				dns_name, domain->name,
				domain->alt_name);
			return NT_STATUS_INVALID_PARAMETER;
		}

		for (check_domain = _domain_list;
		     check_domain != NULL;
		     check_domain = check_domain->next)
		{
			if (check_domain == domain) {
				continue;
			}

			if (strequal(check_domain->alt_name, dns_name)) {
				break;
			}
		}

		if (check_domain != NULL) {
			DBG_ERR("DNS name [%s] used by domain [%s], "
				"expected [%s]\n",
				dns_name, check_domain->name,
				domain->name);
			return NT_STATUS_INVALID_PARAMETER;
		}
	}

	if (domain != NULL) {
		*_d = domain;
		return NT_STATUS_OK;
	}

	/* Create new domain entry */
	domain = talloc_zero(NULL, struct winbindd_domain);
	if (domain == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	domain->children = talloc_zero_array(domain,
					     struct winbindd_child,
					     lp_winbind_max_domain_connections());
	if (domain->children == NULL) {
		TALLOC_FREE(domain);
		return NT_STATUS_NO_MEMORY;
	}

	domain->queue = tevent_queue_create(domain, "winbind_domain");
	if (domain->queue == NULL) {
		TALLOC_FREE(domain);
		return NT_STATUS_NO_MEMORY;
	}

	domain->binding_handle = wbint_binding_handle(domain, domain, NULL);
	if (domain->binding_handle == NULL) {
		TALLOC_FREE(domain);
		return NT_STATUS_NO_MEMORY;
	}

	domain->name = talloc_strdup(domain, domain_name);
	if (domain->name == NULL) {
		TALLOC_FREE(domain);
		return NT_STATUS_NO_MEMORY;
	}

	if (dns_name != NULL) {
		domain->alt_name = talloc_strdup(domain, dns_name);
		if (domain->alt_name == NULL) {
			TALLOC_FREE(domain);
			return NT_STATUS_NO_MEMORY;
		}
	}

	domain->backend = NULL;
	domain->internal = is_internal_domain(sid);
	domain->secure_channel_type = secure_channel_type;
	domain->sequence_number = DOM_SEQUENCE_NONE;
	domain->last_seq_check = 0;
	domain->initialized = false;
	domain->online = is_internal_domain(sid);
	domain->domain_flags = trust_flags;
	domain->domain_type = trust_type;
	domain->domain_trust_attribs = trust_attribs;
	domain->routing_domain = routing_domain;
	sid_copy(&domain->sid, sid);

	/* Is this our primary domain ? */
	if (role == ROLE_DOMAIN_MEMBER) {
		domain->primary = strequal(domain_name, lp_workgroup());
	} else {
		domain->primary = strequal(domain_name, get_global_sam_name());
	}

	if (domain->primary) {
		if (role == ROLE_ACTIVE_DIRECTORY_DC) {
			domain->active_directory = true;
		}
		if (lp_security() == SEC_ADS) {
			domain->active_directory = true;
		}
	} else if (!domain->internal) {
		if (domain->domain_type == LSA_TRUST_TYPE_UPLEVEL) {
			domain->active_directory = true;
		}
	}

	domain->can_do_ncacn_ip_tcp = domain->active_directory;

	if (secure_channel_type != SEC_CHAN_NULL) {
		/*
		 * If we loaded the domain from
		 * our config it is initialized
		 * completely.
		 */
		domain->initialized = true;
	}

	/* Link to domain list */
	DLIST_ADD_END(_domain_list, domain);
	domain_list_generation += 1;

	wcache_tdc_add_domain( domain );

	setup_domain_child(domain);

	DBG_NOTICE("Added domain [%s] [%s] [%s]\n",
		   domain->name, domain->alt_name,
		   dom_sid_str_buf(&domain->sid, &buf));

	*_d = domain;
	return NT_STATUS_OK;
}

bool add_trusted_domain_from_auth(uint16_t validation_level,
				  struct info3_text *info3,
				  struct info6_text *info6)
{
	struct winbindd_domain *domain = NULL;
	struct dom_sid domain_sid;
	const char *dns_domainname = NULL;
	NTSTATUS status;
	bool ok;

	/*
	 * We got a successful auth from a domain that might not yet be in our
	 * domain list. If we're a member we trust our DC who authenticated the
	 * user from that domain and add the domain to our list on-the-fly. If
	 * we're a DC we rely on configured trusts and don't add on-the-fly.
	 */

	if (IS_DC) {
		return true;
	}

	ok = dom_sid_parse(info3->dom_sid, &domain_sid);
	if (!ok) {
		DBG_NOTICE("dom_sid_parse [%s] failed\n", info3->dom_sid);
		return false;
	}

	if (validation_level == 6) {
		if (!strequal(info6->dns_domainname, "")) {
			dns_domainname = info6->dns_domainname;
		}
	}

	status = add_trusted_domain(info3->logon_dom,
				    dns_domainname,
				    &domain_sid,
				    0,
				    NETR_TRUST_FLAG_OUTBOUND,
				    0,
				    SEC_CHAN_NULL,
				    find_default_route_domain(),
				    &domain);
	if (!NT_STATUS_IS_OK(status) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_NO_SUCH_DOMAIN))
	{
		DBG_DEBUG("Adding domain [%s] with sid [%s] failed\n",
			  info3->logon_dom, info3->dom_sid);
		return false;
	}

	return true;
}

bool domain_is_forest_root(const struct winbindd_domain *domain)
{
	const uint32_t fr_flags =
		(NETR_TRUST_FLAG_TREEROOT|NETR_TRUST_FLAG_IN_FOREST);

	return ((domain->domain_flags & fr_flags) == fr_flags);
}

/********************************************************************
  rescan our domains looking for new trusted domains
********************************************************************/

struct trustdom_state {
	struct winbindd_domain_ref domain;
	struct netr_DomainTrustList trusts;
};

static void trustdom_list_done(struct tevent_req *req);
static void rescan_forest_root_trusts( void );
static void rescan_forest_trusts( void );

static void add_trusted_domains( struct winbindd_domain *domain )
{
	struct tevent_context *ev = global_event_context();
	struct trustdom_state *state;
	struct tevent_req *req;
	const char *client_name = NULL;
	pid_t client_pid;

	state = talloc_zero(NULL, struct trustdom_state);
	if (state == NULL) {
		DEBUG(0, ("talloc failed\n"));
		return;
	}
	winbindd_domain_ref_set(&state->domain, domain);

	/* Called from timer, not from a real client */
	client_name = getprogname();
	client_pid = getpid();

	req = dcerpc_wbint_ListTrustedDomains_send(state,
						   ev,
						   dom_child_handle(domain),
						   client_name,
						   client_pid,
						   &state->trusts);
	if (req == NULL) {
		DBG_ERR("dcerpc_wbint_ListTrustedDomains_send failed\n");
		TALLOC_FREE(state);
		return;
	}
	tevent_req_set_callback(req, trustdom_list_done, state);
}

static void trustdom_list_done(struct tevent_req *req)
{
	struct trustdom_state *state = tevent_req_callback_data(
		req, struct trustdom_state);
	bool within_forest = false;
	NTSTATUS status, result;
	uint32_t i;
	struct winbindd_domain *domain = NULL;
	bool valid;

	valid = winbindd_domain_ref_get(&state->domain, &domain);
	if (!valid) {
		/*
		 * winbindd_domain_ref_get() already generated
		 * a debug message for the stale domain!
		 */
		TALLOC_FREE(state);
		return;
	}

	/*
	 * Only when we enumerate our primary domain
	 * or our forest root domain, we should keep
	 * the NETR_TRUST_FLAG_IN_FOREST flag, in
	 * all other cases we need to clear it as the domain
	 * is not part of our forest.
	 */
	if (domain->primary) {
		within_forest = true;
	} else if (domain_is_forest_root(domain)) {
		within_forest = true;
	}

	status = dcerpc_wbint_ListTrustedDomains_recv(req, state, &result);
	if (any_nt_status_not_ok(status, result, &status)) {
		DBG_WARNING("Could not receive trusts for domain %s: %s-%s\n",
			    domain->name, nt_errstr(status),
			    nt_errstr(result));
		TALLOC_FREE(state);
		return;
	}

	for (i=0; i<state->trusts.count; i++) {
		struct netr_DomainTrust *trust = &state->trusts.array[i];
		struct winbindd_domain *new_domain = NULL;

		if (!within_forest) {
			trust->trust_flags &= ~NETR_TRUST_FLAG_IN_FOREST;
		}

		if (!domain->primary) {
			trust->trust_flags &= ~NETR_TRUST_FLAG_PRIMARY;
		}

		/*
		 * We always call add_trusted_domain() cause on an existing
		 * domain structure, it will update the SID if necessary.
		 * This is important because we need the SID for sibling
		 * domains.
		 */
		status = add_trusted_domain(trust->netbios_name,
					    trust->dns_name,
					    trust->sid,
					    trust->trust_type,
					    trust->trust_flags,
					    trust->trust_attributes,
					    SEC_CHAN_NULL,
					    find_default_route_domain(),
					    &new_domain);
		if (!NT_STATUS_IS_OK(status) &&
		    !NT_STATUS_EQUAL(status, NT_STATUS_NO_SUCH_DOMAIN))
		{
			DBG_NOTICE("add_trusted_domain returned %s\n",
				   nt_errstr(status));
			TALLOC_FREE(state);
			return;
		}
	}

	/*
	   Cases to consider when scanning trusts:
	   (a) we are calling from a child domain (primary && !forest_root)
	   (b) we are calling from the root of the forest (primary && forest_root)
	   (c) we are calling from a trusted forest domain (!primary
	       && !forest_root)
	*/

	if (domain->primary) {
		/* If this is our primary domain and we are not in the
		   forest root, we have to scan the root trusts first */

		if (!domain_is_forest_root(domain))
			rescan_forest_root_trusts();
		else
			rescan_forest_trusts();

	} else if (domain_is_forest_root(domain)) {
		/* Once we have done root forest trust search, we can
		   go on to search the trusted forests */

		rescan_forest_trusts();
	}

	TALLOC_FREE(state);

	return;
}

/********************************************************************
 Scan the trusts of our forest root
********************************************************************/

static void rescan_forest_root_trusts( void )
{
	struct winbindd_tdc_domain *dom_list = NULL;
        size_t num_trusts = 0;
	size_t i;
	NTSTATUS status;

	/* The only transitive trusts supported by Windows 2003 AD are
	   (a) Parent-Child, (b) Tree-Root, and (c) Forest.   The
	   first two are handled in forest and listed by
	   DsEnumerateDomainTrusts().  Forest trusts are not so we
	   have to do that ourselves. */

	if ( !wcache_tdc_fetch_list( &dom_list, &num_trusts ) )
		return;

	for ( i=0; i<num_trusts; i++ ) {
		struct winbindd_domain *d = NULL;

		/* Find the forest root.  Don't necessarily trust
		   the domain_list() as our primary domain may not
		   have been initialized. */

		if ( !(dom_list[i].trust_flags & NETR_TRUST_FLAG_TREEROOT) ) {
			continue;
		}

		/* Here's the forest root */

		d = find_domain_from_name_noinit( dom_list[i].domain_name );
		if (d == NULL) {
			status = add_trusted_domain(dom_list[i].domain_name,
						    dom_list[i].dns_name,
						    &dom_list[i].sid,
						    dom_list[i].trust_type,
						    dom_list[i].trust_flags,
						    dom_list[i].trust_attribs,
						    SEC_CHAN_NULL,
						    find_default_route_domain(),
						    &d);

			if (!NT_STATUS_IS_OK(status) &&
			    NT_STATUS_EQUAL(status, NT_STATUS_NO_SUCH_DOMAIN))
			{
				DBG_ERR("add_trusted_domain returned %s\n",
					nt_errstr(status));
				return;
			}
		}
		if (d == NULL) {
			continue;
		}

       		DEBUG(10,("rescan_forest_root_trusts: Following trust path "
			  "for domain tree root %s (%s)\n",
	       		  d->name, d->alt_name ));

		d->domain_flags = dom_list[i].trust_flags;
		d->domain_type  = dom_list[i].trust_type;
		d->domain_trust_attribs = dom_list[i].trust_attribs;

		add_trusted_domains( d );

		break;
	}

	TALLOC_FREE( dom_list );

	return;
}

/********************************************************************
 scan the transitive forest trusts (not our own)
********************************************************************/


static void rescan_forest_trusts( void )
{
	struct winbindd_domain *d = NULL;
	struct winbindd_tdc_domain *dom_list = NULL;
        size_t num_trusts = 0;
	size_t i;
	NTSTATUS status;

	/* The only transitive trusts supported by Windows 2003 AD are
	   (a) Parent-Child, (b) Tree-Root, and (c) Forest.   The
	   first two are handled in forest and listed by
	   DsEnumerateDomainTrusts().  Forest trusts are not so we
	   have to do that ourselves. */

	if ( !wcache_tdc_fetch_list( &dom_list, &num_trusts ) )
		return;

	for ( i=0; i<num_trusts; i++ ) {
		uint32_t flags   = dom_list[i].trust_flags;
		uint32_t type    = dom_list[i].trust_type;
		uint32_t attribs = dom_list[i].trust_attribs;

		d = find_domain_from_name_noinit( dom_list[i].domain_name );

		/* ignore our primary and internal domains */

		if ( d && (d->internal || d->primary ) )
			continue;

		if ( (flags & NETR_TRUST_FLAG_INBOUND) &&
		     (type == LSA_TRUST_TYPE_UPLEVEL) &&
		     (attribs & LSA_TRUST_ATTRIBUTE_FOREST_TRANSITIVE) )
		{
			/* add the trusted domain if we don't know
			   about it */

			if (d == NULL) {
				status = add_trusted_domain(
					dom_list[i].domain_name,
					dom_list[i].dns_name,
					&dom_list[i].sid,
					type,
					flags,
					attribs,
					SEC_CHAN_NULL,
					find_default_route_domain(),
					&d);
				if (!NT_STATUS_IS_OK(status) &&
				    NT_STATUS_EQUAL(status,
						    NT_STATUS_NO_SUCH_DOMAIN))
				{
					DBG_ERR("add_trusted_domain: %s\n",
						nt_errstr(status));
					return;
				}
			}

			if (d == NULL) {
				continue;
			}

			DEBUG(10,("Following trust path for domain %s (%s)\n",
				  d->name, d->alt_name ));
			add_trusted_domains( d );
		}
	}

	TALLOC_FREE( dom_list );

	return;
}

/*********************************************************************
 The process of updating the trusted domain list is a three step
 async process:
 (a) ask our domain
 (b) ask the root domain in our forest
 (c) ask a DC in any Win2003 trusted forests
*********************************************************************/

void rescan_trusted_domains(struct tevent_context *ev, struct tevent_timer *te,
			    struct timeval now, void *private_data)
{
	TALLOC_FREE(te);

	/* I used to clear the cache here and start over but that
	   caused problems in child processes that needed the
	   trust dom list early on.  Removing it means we
	   could have some trusted domains listed that have been
	   removed from our primary domain's DC until a full
	   restart.  This should be ok since I think this is what
	   Windows does as well. */

	/* this will only add new domains we didn't already know about
	   in the domain_list()*/

	add_trusted_domains( find_our_domain() );

	te = tevent_add_timer(
		ev, NULL, timeval_current_ofs(WINBINDD_RESCAN_FREQ, 0),
		rescan_trusted_domains, NULL);
	/*
	 * If te == NULL, there's not much we can do here. Don't fail, the
	 * only thing we miss is new trusted domains.
	 */

	return;
}

static void wbd_ping_dc_done(struct tevent_req *subreq);

void winbindd_ping_offline_domains(struct tevent_context *ev,
				   struct tevent_timer *te,
				   struct timeval now,
				   void *private_data)
{
	struct winbindd_domain *domain = NULL;

	TALLOC_FREE(te);

	for (domain = domain_list(); domain != NULL; domain = domain->next) {
		DBG_DEBUG("Domain %s is %s\n",
			  domain->name,
			  domain->online ? "online" : "offline");

		if (get_global_winbindd_state_offline()) {
			DBG_DEBUG("We are globally offline, do nothing.\n");
			break;
		}

		if (domain->online ||
		    domain->check_online_event != NULL ||
		    domain->secure_channel_type == SEC_CHAN_NULL) {
			continue;
		}

		winbindd_flush_negative_conn_cache(domain);

		domain->check_online_event =
			dcerpc_wbint_PingDc_send(domain,
						 ev,
						 dom_child_handle(domain),
						 &domain->ping_dcname);
		if (domain->check_online_event == NULL) {
			DBG_WARNING("Failed to schedule ping, no-memory\n");
			continue;
		}

		tevent_req_set_callback(domain->check_online_event,
					wbd_ping_dc_done, domain);
	}

	te = tevent_add_timer(ev,
			      NULL,
			      timeval_current_ofs(lp_winbind_reconnect_delay(),
			                          0),
			      winbindd_ping_offline_domains,
			      NULL);
	if (te == NULL) {
		DBG_ERR("Failed to schedule winbindd_ping_offline_domains()\n");
	}

	return;
}

static void wbd_ping_dc_done(struct tevent_req *subreq)
{
	struct winbindd_domain *domain =
		tevent_req_callback_data(subreq,
		struct winbindd_domain);
	NTSTATUS status, result;

	SMB_ASSERT(subreq == domain->check_online_event);
	domain->check_online_event = NULL;

	status = dcerpc_wbint_PingDc_recv(subreq, domain, &result);
	TALLOC_FREE(subreq);
	if (any_nt_status_not_ok(status, result, &status)) {
		DBG_WARNING("dcerpc_wbint_PingDc_recv failed for domain: "
			    "%s - %s\n",
			    domain->name,
			    nt_errstr(status));
		return;
	}

	DBG_DEBUG("dcerpc_wbint_PingDc_recv() succeeded, "
		  "domain: %s, dc-name: %s\n",
                  domain->name,
		  domain->ping_dcname);

	talloc_free(discard_const(domain->ping_dcname));
	domain->ping_dcname = NULL;

	return;
}

static void wb_imsg_new_trusted_domain(struct imessaging_context *msg,
				       void *private_data,
				       uint32_t msg_type,
				       struct server_id server_id,
				       size_t num_fds,
				       int *fds,
				       DATA_BLOB *data)
{
	bool ok;

	if (num_fds != 0) {
		DBG_WARNING("Received %zu fds, ignoring message\n", num_fds);
		return;
	}

	DBG_NOTICE("Rescanning trusted domains\n");

	ok = update_trusted_domains_dc();
	if (!ok) {
		DBG_ERR("Failed to reload trusted domains\n");
	}
}

/*
 * We did not get the secret when we queried secrets.tdb, so read it
 * from secrets.tdb and re-sync the databases
 */
static bool migrate_secrets_tdb_to_ldb(struct winbindd_domain *domain)
{
	bool ok;
	struct cli_credentials *creds;
	NTSTATUS can_migrate = pdb_get_trust_credentials(domain->name,
							 NULL, domain, &creds);
	if (!NT_STATUS_IS_OK(can_migrate)) {
		DEBUG(0, ("Failed to fetch our own local AD domain join "
			"password for winbindd's internal use, both from "
			"secrets.tdb and secrets.ldb: %s\n",
			nt_errstr(can_migrate)));
		return false;
	}

	/*
	 * NOTE: It is very unlikely we end up here if there is an
	 * oldpass, because a new password is created at
	 * classicupgrade, so this is not a concern.
	 */
	ok = secrets_store_machine_pw_sync(cli_credentials_get_password(creds),
		   NULL /* oldpass */,
		   cli_credentials_get_domain(creds),
		   cli_credentials_get_realm(creds),
		   cli_credentials_get_salt_principal(creds, creds),
		   0, /* Supported enc types, unused */
		   &domain->sid,
		   cli_credentials_get_password_last_changed_time(creds),
		   cli_credentials_get_secure_channel_type(creds),
		   false /* do_delete: Do not delete */);
	TALLOC_FREE(creds);
	if (ok == false) {
		DEBUG(0, ("Failed to write our own "
			  "local AD domain join password for "
			  "winbindd's internal use into secrets.tdb\n"));
		return false;
	}
	return true;
}

static void free_domain(struct winbindd_domain *d)
{
	struct winbindd_domain *nd = NULL;
	struct dom_sid_buf sbuf = {};

	nd = find_domain_from_sid_noinit(&d->sid);
	if (nd != NULL) {
		DBG_WARNING("Free updated domain[%p] name[%s] %s "
			    "replaced by domain[%p] name[%s]\n",
			    d, d->name, dom_sid_str_buf(&d->sid, &sbuf),
			    nd, nd->name);
	} else {
		DBG_WARNING("Free removed domain[%p] name[%s] %s\n",
			    d, d->name, dom_sid_str_buf(&d->sid, &sbuf));
	}
	talloc_free(d);
}

static void terminate_child(struct tevent_req *subreq)
{
	struct winbindd_child *c =
		(struct winbindd_child *)
		tevent_req_callback_data_void(subreq);
	struct winbindd_domain *d = c->domain;
	size_t ci;
	bool ok;

	ok = tevent_queue_wait_recv(subreq);
	SMB_ASSERT(ok);
	TALLOC_FREE(subreq);

	if (c->pid != 0) {
		kill(c->pid, SIGTERM);
		c->pid = 0;
		if (c->sock != -1) {
			close(c->sock);
		}
		c->sock = -1;
		TALLOC_FREE(c->monitor_fde);
	}

	c = NULL;
	if (d == NULL) {
		return;
	}
	if (d->internal) {
		return;
	}

	for (ci = 0; ci < talloc_array_length(d->children); ci++) {
		c = &d->children[ci];

		if (c->pid != 0) {
			/*
			 * still waiting
			 */
			return;
		}
	}

	free_domain(d);
}

static void terminate_domain(struct tevent_req *subreq)
{
	struct winbindd_domain *d =
		tevent_req_callback_data(subreq,
		struct winbindd_domain);
	size_t ci;
	bool ok;

	ok = tevent_queue_wait_recv(subreq);
	SMB_ASSERT(ok);

	/* NO TALLOC_FREE(subreq); */
	subreq = NULL;

	for (ci = 0; ci < talloc_array_length(d->children); ci++) {
		struct winbindd_child *c = &d->children[ci];

		if (c->pid == 0) {
			continue;
		}

		subreq = tevent_queue_wait_send(d->children,
						global_event_context(),
						c->queue);
		if (subreq == NULL) {
			return;
		}
		tevent_req_set_callback(subreq,
					terminate_child,
					c);
	}

	if (subreq != NULL) {
		/*
		 * still waiting
		 */
		return;
	}

	free_domain(d);
}

static bool remove_trusted_domains_dc(void)
{
	struct winbindd_domain *d = NULL;
	struct winbindd_domain *n = NULL;
	struct winbindd_child *c = NULL;
	struct tevent_req *subreq = NULL;

	SMB_ASSERT(IS_DC);

	/*
	 * We need to terminate all
	 * child processes, but we need
	 * to go through the child and domain
	 * queues * in order to keep existing
	 * requests to finish.
	 *
	 * First start with the idmap and locator
	 * children
	 */

	c = idmap_child();
	if (c->pid != 0) {
		subreq = tevent_queue_wait_send(c,
						global_event_context(),
						c->queue);
		if (subreq == NULL) {
			return false;
		}
		tevent_req_set_callback(subreq,
					terminate_child,
					c);
	}

	c = locator_child();
	if (c->pid != 0) {
		subreq = tevent_queue_wait_send(c,
						global_event_context(),
						c->queue);
		if (subreq == NULL) {
			return false;
		}
		tevent_req_set_callback(subreq,
					terminate_child,
					c);
	}

	/*
	 * For internal domains BUILTIN and local SAM
	 * we just terminate the children, forcing
	 * a re-fork
	 */
	for (d = _domain_list; d != NULL; d = d->next) {
		size_t ci;

		if (!d->internal) {
			continue;
		}

		for (ci = 0; ci < talloc_array_length(d->children); ci++) {
			c = &d->children[ci];

			if (c->pid == 0) {
				continue;
			}

			subreq = tevent_queue_wait_send(d->children,
							global_event_context(),
							c->queue);
			if (subreq == NULL) {
				return false;
			}
			tevent_req_set_callback(subreq,
						terminate_child,
						c);
		}
	}

	/*
	 * For trusted domain
	 * we need to wait in
	 * the domain queue in order
	 * to let pending requests
	 * use the existing domain
	 * children.
	 */
	for (d = _domain_list; d != NULL; d = n) {
		n = d->next;

		if (d->internal) {
			continue;
		}

		subreq = tevent_queue_wait_send(d,
						global_event_context(),
						d->queue);
		if (subreq == NULL) {
			return false;
		}
		tevent_req_set_callback(subreq,
					terminate_domain,
					d);

		DLIST_REMOVE(_domain_list, d);
		domain_list_generation += 1;
	}

	return true;
}

static bool add_trusted_domains_dc(void)
{
	struct winbindd_domain *domain =  NULL;
	struct pdb_trusted_domain **domains = NULL;
	uint32_t num_domains = 0;
	uint32_t i;
	NTSTATUS status;

	SMB_ASSERT(IS_DC);

	if (!(pdb_capabilities() & PDB_CAP_TRUSTED_DOMAINS_EX)) {
		struct trustdom_info **ti = NULL;

		status = pdb_enum_trusteddoms(talloc_tos(), &num_domains, &ti);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("pdb_enum_trusteddoms() failed - %s\n",
				nt_errstr(status));
			return false;
		}

		for (i = 0; i < num_domains; i++) {
			status = add_trusted_domain(ti[i]->name,
						    NULL,
						    &ti[i]->sid,
						    LSA_TRUST_TYPE_DOWNLEVEL,
						    NETR_TRUST_FLAG_OUTBOUND,
						    0,
						    SEC_CHAN_DOMAIN,
						    NULL,
						    &domain);
			if (!NT_STATUS_IS_OK(status)) {
				DBG_NOTICE("add_trusted_domain returned %s\n",
					   nt_errstr(status));
				return false;
			}
		}

		return true;
	}

	status = pdb_enum_trusted_domains(talloc_tos(), &num_domains, &domains);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("pdb_enum_trusted_domains() failed - %s\n",
			nt_errstr(status));
		return false;
	}

	for (i = 0; i < num_domains; i++) {
		enum netr_SchannelType sec_chan_type = SEC_CHAN_DOMAIN;
		struct ForestTrustInfo fti = { .version = 0, };
		uint32_t trust_flags = 0;
		enum ndr_err_code ndr_err;

		if (domains[i]->trust_type == LSA_TRUST_TYPE_UPLEVEL) {
			sec_chan_type = SEC_CHAN_DNS_DOMAIN;
		}

		if (!(domains[i]->trust_direction & LSA_TRUST_DIRECTION_OUTBOUND)) {
			sec_chan_type = SEC_CHAN_NULL;
		}

		if (domains[i]->trust_direction & LSA_TRUST_DIRECTION_INBOUND) {
			trust_flags |= NETR_TRUST_FLAG_INBOUND;
		}
		if (domains[i]->trust_direction & LSA_TRUST_DIRECTION_OUTBOUND) {
			trust_flags |= NETR_TRUST_FLAG_OUTBOUND;
		}
		if (domains[i]->trust_attributes & LSA_TRUST_ATTRIBUTE_PIM_TRUST) {
			/*
			 * We don't support PIM_TRUST yet.
			 */
			DBG_WARNING("Ignoring PIM_TRUST trust to "
				    "domain[%s/%s]\n",
				    domains[i]->netbios_name,
				    domains[i]->domain_name);
			continue;
		}
		if (domains[i]->trust_attributes & LSA_TRUST_ATTRIBUTE_WITHIN_FOREST) {
			/*
			 * We don't support WITHIN_FOREST yet.
			 */
			DBG_WARNING("Ignoring WITHIN_FOREST trust to "
				    "domain[%s/%s]\n",
				    domains[i]->netbios_name,
				    domains[i]->domain_name);
			/* trust_flags |= NETR_TRUST_FLAG_IN_FOREST; */
			continue;
		}

		if (domains[i]->trust_attributes & LSA_TRUST_ATTRIBUTE_CROSS_ORGANIZATION) {
			/*
			 * We don't support selective authentication yet.
			 */
			DBG_WARNING("Ignoring CROSS_ORGANIZATION trust to "
				    "domain[%s/%s]\n",
				    domains[i]->netbios_name,
				    domains[i]->domain_name);
			continue;
		}

		status = add_trusted_domain(domains[i]->netbios_name,
					    domains[i]->domain_name,
					    &domains[i]->security_identifier,
					    domains[i]->trust_type,
					    trust_flags,
					    domains[i]->trust_attributes,
					    sec_chan_type,
					    NULL,
					    &domain);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_NOTICE("add_trusted_domain returned %s\n",
				   nt_errstr(status));
			return false;
		}

		if (domains[i]->trust_type != LSA_TRUST_TYPE_UPLEVEL) {
			continue;
		}

		if (!(domains[i]->trust_attributes & LSA_TRUST_ATTRIBUTE_FOREST_TRANSITIVE)) {
			continue;
		}

		if (domains[i]->trust_forest_trust_info.length == 0) {
			continue;
		}

		ndr_err = ndr_pull_struct_blob_all(
			&domains[i]->trust_forest_trust_info,
			talloc_tos(), &fti,
			(ndr_pull_flags_fn_t)ndr_pull_ForestTrustInfo);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			DBG_ERR("ndr_pull_ForestTrustInfo(%s) - %s\n",
				domains[i]->netbios_name,
				ndr_map_error2string(ndr_err));
			return false;
		}

		status = trust_forest_info_to_lsa2(domain,
						   &fti,
						   &domain->fti);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("dsdb_trust_forest_info_to_lsa(%s) - %s\n",
				domains[i]->netbios_name,
				nt_errstr(status));
			return false;
		}
	}

	for (i = 0; i < num_domains; i++) {
		struct winbindd_domain *routing_domain = NULL;
		uint32_t fi;

		routing_domain = find_domain_from_name_noinit(
			domains[i]->netbios_name);
		if (routing_domain == NULL) {
			DBG_ERR("Can't find winbindd domain [%s]\n",
				domains[i]->netbios_name);
			return false;
		}

		if (routing_domain->fti == NULL) {
			continue;
		}

		for (fi = 0; fi < routing_domain->fti->count; fi++) {
			const struct lsa_ForestTrustRecord2 *rec =
				routing_domain->fti->entries[fi];
			const struct lsa_ForestTrustDomainInfo *drec = NULL;

			if (rec == NULL) {
				continue;
			}

			if (rec->type != LSA_FOREST_TRUST_DOMAIN_INFO) {
				continue;
			}
			drec = &rec->forest_trust_data.domain_info;

			if (rec->flags & LSA_NB_DISABLED_MASK) {
				continue;
			}

			if (rec->flags & LSA_SID_DISABLED_MASK) {
				continue;
			}

			/*
			 * TODO:
			 * also try to find a matching
			 * LSA_TLN_DISABLED_MASK ???
			 */

			domain = find_domain_from_name_noinit(
					drec->netbios_domain_name.string);
			if (domain != NULL) {
				continue;
			}

			status = add_trusted_domain(drec->netbios_domain_name.string,
						    drec->dns_domain_name.string,
						    drec->domain_sid,
						    LSA_TRUST_TYPE_UPLEVEL,
						    NETR_TRUST_FLAG_OUTBOUND,
						    0,
						    SEC_CHAN_NULL,
						    routing_domain,
						    &domain);
			if (!NT_STATUS_IS_OK(status)) {
				DBG_NOTICE("add_trusted_domain returned %s\n",
					   nt_errstr(status));
				return false;
			}
			if (domain == NULL) {
				continue;
			}
		}
	}

	return true;
}

bool update_trusted_domains_dc(void)
{
	bool ok;

	if (!IS_DC) {
		return true;
	}

	ok = remove_trusted_domains_dc();
	if (!ok) {
		return false;
	}

	if (IS_AD_DC) {
		struct winbindd_domain *sam_domain = find_local_sam_domain();
		NTSTATUS status;

		SMB_ASSERT(sam_domain);

		TALLOC_FREE(sam_domain->fti);

		status = pdb_filter_hints(sam_domain,
					  NULL,  /* p_local_tdo */
					  &sam_domain->fti,
					  NULL); /* p_local_functional_level */
		if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("pdb_filter_hints(%s) - %s\n",
				sam_domain->name,
				nt_errstr(status));
			return false;
		}
	}

	ok = add_trusted_domains_dc();
	if (!ok) {
		return false;
	}

	return true;
}

/* Look up global info for the winbind daemon */
bool init_domain_list(void)
{
	int role = lp_server_role();
	struct pdb_domain_info *pdb_domain_info = NULL;
	struct winbindd_domain *domain =  NULL;
	NTSTATUS status;
	bool ok;

	/* the list should be empty! */
	SMB_ASSERT(_domain_list == NULL);

	/* BUILTIN domain */

	status = add_trusted_domain("BUILTIN",
				    NULL,
				    &global_sid_Builtin,
				    LSA_TRUST_TYPE_DOWNLEVEL,
				    0, /* trust_flags */
				    0, /* trust_attribs */
				    SEC_CHAN_LOCAL,
				    NULL,
				    &domain);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("add_trusted_domain BUILTIN returned %s\n",
			nt_errstr(status));
		return false;
	}

	/* Local SAM */

	/*
	 * In case the passdb backend is passdb_dsdb the domain SID comes from
	 * dsdb, not from secrets.tdb. As we use the domain SID in various
	 * places, we must ensure the domain SID is migrated from dsdb to
	 * secrets.tdb before get_global_sam_sid() is called the first time.
	 *
	 * The migration is done as part of the passdb_dsdb initialisation,
	 * calling pdb_get_domain_info() triggers it.
	 */
	pdb_domain_info = pdb_get_domain_info(talloc_tos());

	if ( role == ROLE_ACTIVE_DIRECTORY_DC ) {
		uint32_t trust_flags;
		bool is_root;
		enum netr_SchannelType sec_chan_type;
		const char *account_name;
		struct samr_Password current_nt_hash;

		if (pdb_domain_info == NULL) {
			DEBUG(0, ("Failed to fetch our own local AD "
				"domain info from sam.ldb\n"));
			return false;
		}

		trust_flags = NETR_TRUST_FLAG_PRIMARY;
		trust_flags |= NETR_TRUST_FLAG_IN_FOREST;
		trust_flags |= NETR_TRUST_FLAG_NATIVE;
		trust_flags |= NETR_TRUST_FLAG_OUTBOUND;

		is_root = strequal(pdb_domain_info->dns_domain,
				   pdb_domain_info->dns_forest);
		if (is_root) {
			trust_flags |= NETR_TRUST_FLAG_TREEROOT;
		}

		status = add_trusted_domain(pdb_domain_info->name,
					    pdb_domain_info->dns_domain,
					    &pdb_domain_info->sid,
					    LSA_TRUST_TYPE_UPLEVEL,
					    trust_flags,
					    LSA_TRUST_ATTRIBUTE_WITHIN_FOREST,
					    SEC_CHAN_BDC,
					    NULL,
					    &domain);
		TALLOC_FREE(pdb_domain_info);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("Failed to add our own local AD "
				"domain to winbindd's internal list\n");
			return false;
		}

		/*
		 * We need to call this to find out if we are an RODC
		 */
		ok = get_trust_pw_hash(domain->name,
				       current_nt_hash.hash,
				       &account_name,
				       &sec_chan_type);
		if (!ok) {
			/*
			 * If get_trust_pw_hash() fails, then try and
			 * fetch the password from the more recent of
			 * secrets.{ldb,tdb} using the
			 * pdb_get_trust_credentials()
			 */
			ok = migrate_secrets_tdb_to_ldb(domain);

			if (!ok) {
				DEBUG(0, ("Failed to migrate our own "
					  "local AD domain join password for "
					  "winbindd's internal use into "
					  "secrets.tdb\n"));
				return false;
			}
			ok = get_trust_pw_hash(domain->name,
					       current_nt_hash.hash,
					       &account_name,
					       &sec_chan_type);
			if (!ok) {
				DEBUG(0, ("Failed to find our own just "
					  "written local AD domain join "
					  "password for winbindd's internal "
					  "use in secrets.tdb\n"));
				return false;
			}
		}

		domain->secure_channel_type = sec_chan_type;
		if (sec_chan_type == SEC_CHAN_RODC) {
			domain->rodc = true;
		}

		status = pdb_filter_hints(domain,
					  NULL,  /* p_local_tdo */
					  &domain->fti,
					  NULL); /* p_local_functional_level */
		if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("pdb_filter_hints(%s) - %s\n",
				domain->name,
				nt_errstr(status));
			return false;
		}
	} else {
		uint32_t trust_flags;
		enum netr_SchannelType secure_channel_type;

		trust_flags = NETR_TRUST_FLAG_OUTBOUND;
		if (role != ROLE_DOMAIN_MEMBER) {
			trust_flags |= NETR_TRUST_FLAG_PRIMARY;
		}

		if (role > ROLE_DOMAIN_MEMBER) {
			secure_channel_type = SEC_CHAN_BDC;
		} else {
			secure_channel_type = SEC_CHAN_LOCAL;
		}

		if ((pdb_domain_info != NULL) && (role == ROLE_IPA_DC)) {
			/* This is IPA DC that presents itself as
			 * an Active Directory domain controller to trusted AD
			 * forests but in fact is a classic domain controller.
			 */
			trust_flags = NETR_TRUST_FLAG_PRIMARY;
			trust_flags |= NETR_TRUST_FLAG_IN_FOREST;
			trust_flags |= NETR_TRUST_FLAG_NATIVE;
			trust_flags |= NETR_TRUST_FLAG_OUTBOUND;
			trust_flags |= NETR_TRUST_FLAG_TREEROOT;
			status = add_trusted_domain(pdb_domain_info->name,
						    pdb_domain_info->dns_domain,
						    &pdb_domain_info->sid,
						    LSA_TRUST_TYPE_UPLEVEL,
						    trust_flags,
						    LSA_TRUST_ATTRIBUTE_WITHIN_FOREST,
						    secure_channel_type,
						    NULL,
						    &domain);
			TALLOC_FREE(pdb_domain_info);
		} else {
			status = add_trusted_domain(get_global_sam_name(),
						    NULL,
						    get_global_sam_sid(),
						    LSA_TRUST_TYPE_DOWNLEVEL,
						    trust_flags,
						    0, /* trust_attribs */
						    secure_channel_type,
						    NULL,
						    &domain);
		}
		if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("Failed to add local SAM to "
				"domain to winbindd's internal list\n");
			return false;
		}
	}

	if (IS_DC) {
		ok = add_trusted_domains_dc();
		if (!ok) {
			DBG_ERR("init_domain_list_dc failed\n");
			return false;
		}
	}

	if ( role == ROLE_DOMAIN_MEMBER ) {
		struct dom_sid our_sid;
		uint32_t trust_type;

		if (!secrets_fetch_domain_sid(lp_workgroup(), &our_sid)) {
			DEBUG(0, ("Could not fetch our SID - did we join?\n"));
			return False;
		}

		if (lp_realm() != NULL) {
			trust_type = LSA_TRUST_TYPE_UPLEVEL;
		} else {
			trust_type = LSA_TRUST_TYPE_DOWNLEVEL;
		}

		status = add_trusted_domain(lp_workgroup(),
					    lp_realm(),
					    &our_sid,
					    trust_type,
					    NETR_TRUST_FLAG_PRIMARY|
					    NETR_TRUST_FLAG_OUTBOUND,
					    0, /* trust_attribs */
					    SEC_CHAN_WKSTA,
					    NULL,
					    &domain);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("Failed to add local SAM to "
				"domain to winbindd's internal list\n");
			return false;
		}
	}

	status = imessaging_register(winbind_imessaging_context(), NULL,
				     MSG_WINBIND_RELOAD_TRUSTED_DOMAINS,
				     wb_imsg_new_trusted_domain);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("imessaging_register failed %s\n", nt_errstr(status));
		return false;
	}

	return True;
}

/**
 * Given a domain name, return the struct winbindd domain info for it
 *
 * @note Do *not* pass lp_workgroup() to this function.  domain_list
 *       may modify it's value, and free that pointer.  Instead, our local
 *       domain may be found by calling find_our_domain().
 *       directly.
 *
 *
 * @return The domain structure for the named domain, if it is working.
 */

struct winbindd_domain *find_domain_from_name_noinit(const char *domain_name)
{
	struct winbindd_domain *domain;

	/* Search through list */

	for (domain = domain_list(); domain != NULL; domain = domain->next) {
		if (strequal(domain_name, domain->name)) {
			return domain;
		}
		if (domain->alt_name == NULL) {
			continue;
		}
		if (strequal(domain_name, domain->alt_name)) {
			return domain;
		}
	}

	/* Not found */

	return NULL;
}

/**
 * Given a domain name, return the struct winbindd domain if it's a direct
 * outgoing trust
 *
 * @return The domain structure for the named domain, if it is a direct outgoing trust
 */
struct winbindd_domain *find_trust_from_name_noinit(const char *domain_name)
{
	struct winbindd_domain *domain = NULL;

	domain = find_domain_from_name_noinit(domain_name);
	if (domain == NULL) {
		return NULL;
	}

	if (domain->secure_channel_type != SEC_CHAN_NULL) {
		return domain;
	}

	return NULL;
}

struct winbindd_domain *find_routing_from_namespace_noinit(const char *namespace)
{
	struct winbindd_domain *domain;

	/* Search through list */

	for (domain = domain_list(); domain != NULL; domain = domain->next) {
		bool match;

		match = strequal(namespace, domain->name);
		if (match) {
			break;
		}

		if (domain->alt_name == NULL) {
			continue;
		}

		match = strequal(namespace, domain->alt_name);
		if (match) {
			break;
		}

		if (domain->fti == NULL) {
			continue;
		}

		match = trust_forest_info_match_tln_namespace(domain->fti,
							      namespace);
		if (match) {
			break;
		}
	}

	if (domain == NULL) {
		/* Not found */
		return NULL;
	}

	if (domain->routing_domain != NULL) {
		return domain->routing_domain;
	}

	return domain;
}

struct winbindd_domain *find_domain_from_name(const char *domain_name)
{
	struct winbindd_domain *domain;

	domain = find_domain_from_name_noinit(domain_name);

	if (domain == NULL)
		return NULL;

	if (!domain->initialized)
		init_dc_connection(domain, false);

	return domain;
}

/* Given a domain sid, return the struct winbindd domain info for it */

struct winbindd_domain *find_domain_from_sid_noinit(const struct dom_sid *sid)
{
	struct winbindd_domain *domain;

	/* Search through list */

	for (domain = domain_list(); domain != NULL; domain = domain->next) {
		if (dom_sid_compare_domain(sid, &domain->sid) == 0)
			return domain;
	}

	/* Not found */

	return NULL;
}

/**
 * Given a domain sid, return the struct winbindd domain if it's a direct
 * outgoing trust
 *
 * @return The domain structure for the specified domain, if it is a direct outgoing trust
 */
struct winbindd_domain *find_trust_from_sid_noinit(const struct dom_sid *sid)
{
	struct winbindd_domain *domain = NULL;

	domain = find_domain_from_sid_noinit(sid);
	if (domain == NULL) {
		return NULL;
	}

	if (domain->secure_channel_type != SEC_CHAN_NULL) {
		return domain;
	}

	return NULL;
}

/* Given a domain sid, return the struct winbindd domain info for it */

struct winbindd_domain *find_domain_from_sid(const struct dom_sid *sid)
{
	struct winbindd_domain *domain;

	domain = find_domain_from_sid_noinit(sid);

	if (domain == NULL)
		return NULL;

	if (!domain->initialized)
		init_dc_connection(domain, false);

	return domain;
}

struct winbindd_domain *find_our_domain(void)
{
	struct winbindd_domain *domain;

	/* Search through list */

	for (domain = domain_list(); domain != NULL; domain = domain->next) {
		if (domain->primary)
			return domain;
	}

	smb_panic("Could not find our domain");
	return NULL;
}

struct winbindd_domain *find_local_sam_domain(void)
{
	return find_domain_from_sid(get_global_sam_sid());
}

struct winbindd_domain *find_default_route_domain(void)
{
	if (!IS_DC) {
		return find_our_domain();
	}
	DBG_DEBUG("Routing logic not yet implemented on a DC\n");
	return NULL;
}

/* Find the appropriate domain to lookup a name or SID */

struct winbindd_domain *find_lookup_domain_from_sid(const struct dom_sid *sid)
{
	struct dom_sid_buf buf;

	DBG_DEBUG("SID [%s]\n", dom_sid_str_buf(sid, &buf));

	/*
	 * SIDs in the S-1-22-{1,2} domain and well-known SIDs should be handled
	 * by our passdb.
	 */

	if ( sid_check_is_in_unix_groups(sid) ||
	     sid_check_is_unix_groups(sid) ||
	     sid_check_is_in_unix_users(sid) ||
	     sid_check_is_unix_users(sid) ||
	     sid_check_is_our_sam(sid) ||
             sid_check_is_in_our_sam(sid) )
	{
		return find_domain_from_sid(get_global_sam_sid());
	}

	if ( sid_check_is_builtin(sid) ||
	     sid_check_is_in_builtin(sid) ||
	     sid_check_is_wellknown_domain(sid, NULL) ||
	     sid_check_is_in_wellknown_domain(sid) )
	{
		return find_domain_from_sid(&global_sid_Builtin);
	}

	if (IS_DC) {
		struct winbindd_domain *domain = NULL;

		domain = find_domain_from_sid_noinit(sid);
		if (domain == NULL) {
			return NULL;
		}

		if (domain->secure_channel_type != SEC_CHAN_NULL) {
			return domain;
		}

		return domain->routing_domain;
	}

	/* On a member server a query for SID or name can always go to our
	 * primary DC. */

	DEBUG(10, ("calling find_our_domain\n"));
	return find_our_domain();
}

struct winbindd_domain *find_lookup_domain_from_name(const char *domain_name)
{
	bool predefined;

	if ( strequal(domain_name, unix_users_domain_name() ) ||
	     strequal(domain_name, unix_groups_domain_name() ) )
	{
		/*
		 * The "Unix User" and "Unix Group" domain are handled by
		 * passdb
		 */
		return find_domain_from_name_noinit( get_global_sam_name() );
	}

	if (strequal(domain_name, "BUILTIN") ||
	    strequal(domain_name, get_global_sam_name())) {
		return find_domain_from_name_noinit(domain_name);
	}

	predefined = dom_sid_lookup_is_predefined_domain(domain_name);
	if (predefined) {
		return find_domain_from_name_noinit(builtin_domain_name());
	}

	if (IS_DC) {
		struct winbindd_domain *domain = NULL;

		domain = find_routing_from_namespace_noinit(domain_name);
		if (domain == NULL) {
			return NULL;
		}

		return domain;
	}

	return find_our_domain();
}

/* Is this a domain which we may assume no DOMAIN\ prefix? */

static bool assume_domain(const char *domain)
{
	/* never assume the domain on a standalone server */

	if ( lp_server_role() == ROLE_STANDALONE )
		return False;

	/* domain member servers may possibly assume for the domain name */

	if ( lp_server_role() == ROLE_DOMAIN_MEMBER ) {
		if ( !strequal(lp_workgroup(), domain) )
			return False;

		if ( lp_winbind_use_default_domain() )
			return True;
	}

	/* only left with a domain controller */

	if ( strequal(get_global_sam_name(), domain) )  {
		return True;
	}

	return False;
}

/* Parse a DOMAIN\user or UPN string into a domain, namespace and a user */
bool parse_domain_user(TALLOC_CTX *ctx,
		       const char *domuser,
		       char **pnamespace,
		       char **pdomain,
		       char **puser)
{
	char *p = NULL;
	char *namespace = NULL;
	char *domain = NULL;
	char *user = NULL;

	if (strlen(domuser) == 0) {
		return false;
	}

	p = strchr(domuser, *lp_winbind_separator());
	if (p != NULL) {
		user = talloc_strdup(ctx, p + 1);
		if (user == NULL) {
			goto fail;
		}
		domain = talloc_strdup(ctx,
				domuser);
		if (domain == NULL) {
			goto fail;
		}
		domain[PTR_DIFF(p, domuser)] = '\0';
		namespace = talloc_strdup(ctx, domain);
		if (namespace == NULL) {
			goto fail;
		}
	} else {
		user = talloc_strdup(ctx, domuser);
		if (user == NULL) {
			goto fail;
		}
		p = strchr(domuser, '@');
		if (p != NULL) {
			/* upn */
			namespace = talloc_strdup(ctx, p + 1);
			if (namespace == NULL) {
				goto fail;
			}
			domain = talloc_strdup(ctx, "");
			if (domain == NULL) {
				goto fail;
			}

		} else if (assume_domain(lp_workgroup())) {
			domain = talloc_strdup(ctx, lp_workgroup());
			if (domain == NULL) {
				goto fail;
			}
			namespace = talloc_strdup(ctx, domain);
			if (namespace == NULL) {
				goto fail;
			}
		} else {
			namespace = talloc_strdup(ctx, lp_netbios_name());
			if (namespace == NULL) {
				goto fail;
			}
			domain = talloc_strdup(ctx, "");
			if (domain == NULL) {
				goto fail;
			}
		}
	}

	if (!strupper_m(domain)) {
		goto fail;
	}

	*pnamespace = namespace;
	*pdomain = domain;
	*puser = user;
	return true;
fail:
	TALLOC_FREE(user);
	TALLOC_FREE(domain);
	TALLOC_FREE(namespace);
	return false;
}

bool canonicalize_username(TALLOC_CTX *mem_ctx,
			   char **pusername_inout,
			   char **pnamespace,
			   char **pdomain,
			   char **puser)
{
	bool ok;
	char *namespace = NULL;
	char *domain = NULL;
	char *user = NULL;
	char *username_inout = NULL;

	ok = parse_domain_user(mem_ctx,
			*pusername_inout,
			&namespace, &domain, &user);

	if (!ok) {
		return False;
	}

	username_inout = talloc_asprintf(mem_ctx, "%s%c%s",
		 domain, *lp_winbind_separator(),
		 user);

	if (username_inout == NULL) {
		goto fail;
	}

	*pnamespace = namespace;
	*puser = user;
	*pdomain = domain;
	*pusername_inout = username_inout;
	return True;
fail:
	TALLOC_FREE(username_inout);
	TALLOC_FREE(namespace);
	TALLOC_FREE(domain);
	TALLOC_FREE(user);
	return false;
}

/*
    Fill DOMAIN\\USERNAME entry accounting 'winbind use default domain' and
    'winbind separator' options.
    This means:
	- omit DOMAIN when 'winbind use default domain = true' and DOMAIN is
	lp_workgroup()

    If we are a PDC or BDC, and this is for our domain, do likewise.

    On an AD DC we always fill DOMAIN\\USERNAME.

    We always canonicalize as UPPERCASE DOMAIN, lowercase username.
*/
/**
 * talloc version of fill_domain_username()
 * return NULL on talloc failure.
 */
char *fill_domain_username_talloc(TALLOC_CTX *mem_ctx,
				  const char *domain,
				  const char *user,
				  bool can_assume)
{
	char *tmp_user, *name;

	if (lp_server_role() == ROLE_ACTIVE_DIRECTORY_DC) {
		can_assume = false;
	}

	if (user == NULL) {
		return NULL;
	}

	tmp_user = talloc_strdup(mem_ctx, user);
	if (tmp_user == NULL) {
		return NULL;
	}
	if (!strlower_m(tmp_user)) {
		TALLOC_FREE(tmp_user);
		return NULL;
	}

	if (can_assume && assume_domain(domain)) {
		name = tmp_user;
	} else {
		name = talloc_asprintf(mem_ctx, "%s%c%s",
				       domain,
				       *lp_winbind_separator(),
				       tmp_user);
		TALLOC_FREE(tmp_user);
	}

	return name;
}

/*
 * Client list accessor functions
 */

static struct winbindd_cli_state *_client_list;
static int _num_clients;

/* Return list of all connected clients */

struct winbindd_cli_state *winbindd_client_list(void)
{
	return _client_list;
}

/* Return list-tail of all connected clients */

struct winbindd_cli_state *winbindd_client_list_tail(void)
{
	return DLIST_TAIL(_client_list);
}

/* Return previous (read:newer) client in list */

struct winbindd_cli_state *
winbindd_client_list_prev(struct winbindd_cli_state *cli)
{
	return DLIST_PREV(cli);
}

/* Add a connection to the list */

void winbindd_add_client(struct winbindd_cli_state *cli)
{
	cli->last_access = time(NULL);
	DLIST_ADD(_client_list, cli);
	_num_clients++;
}

/* Remove a client from the list */

void winbindd_remove_client(struct winbindd_cli_state *cli)
{
	DLIST_REMOVE(_client_list, cli);
	_num_clients--;
}

/* Move a client to head or list */

void winbindd_promote_client(struct winbindd_cli_state *cli)
{
	cli->last_access = time(NULL);
	DLIST_PROMOTE(_client_list, cli);
}

/* Return number of open clients */

int winbindd_num_clients(void)
{
	return _num_clients;
}

NTSTATUS lookup_usergroups_cached(TALLOC_CTX *mem_ctx,
				  const struct dom_sid *user_sid,
				  uint32_t *p_num_groups, struct dom_sid **user_sids)
{
	struct netr_SamInfo3 *info3 = NULL;
	NTSTATUS status = NT_STATUS_NO_MEMORY;
	uint32_t num_groups = 0;

	DEBUG(3,(": lookup_usergroups_cached\n"));

	*user_sids = NULL;
	*p_num_groups = 0;

	info3 = netsamlogon_cache_get(mem_ctx, user_sid);

	if (info3 == NULL) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	/*
	 * Before bug #7843 the "Domain Local" groups were added with a
	 * lookupuseraliases call, but this isn't done anymore for our domain
	 * so we need to resolve resource groups here.
	 *
	 * When to use Resource Groups:
	 * http://technet.microsoft.com/en-us/library/cc753670%28v=WS.10%29.aspx
	 */
	status = sid_array_from_info3(mem_ctx, info3,
				      user_sids,
				      &num_groups,
				      false);

	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(info3);
		return status;
	}

	TALLOC_FREE(info3);
	*p_num_groups = num_groups;
	status = (user_sids != NULL) ? NT_STATUS_OK : NT_STATUS_NO_MEMORY;

	DEBUG(3,(": lookup_usergroups_cached succeeded\n"));

	return status;
}

/*********************************************************************
 We use this to remove spaces from user and group names
********************************************************************/

NTSTATUS normalize_name_map(TALLOC_CTX *mem_ctx,
			     const char *domain_name,
			     const char *name,
			     char **normalized)
{
	struct winbindd_domain *domain = NULL;
	NTSTATUS nt_status;

	if (!name || !normalized) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!lp_winbind_normalize_names()) {
		return NT_STATUS_PROCEDURE_NOT_FOUND;
	}

	domain = find_domain_from_name_noinit(domain_name);
	if (domain == NULL) {
		DBG_ERR("Failed to find domain '%s'\n",	domain_name);
		return NT_STATUS_NO_SUCH_DOMAIN;
	}

	/* Alias support and whitespace replacement are mutually
	   exclusive */

	nt_status = resolve_username_to_alias(mem_ctx, domain,
					      name, normalized );
	if (NT_STATUS_IS_OK(nt_status)) {
		/* special return code to let the caller know we
		   mapped to an alias */
		return NT_STATUS_FILE_RENAMED;
	}

	/* check for an unreachable domain */

	if (NT_STATUS_EQUAL(nt_status, NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND)) {
		DEBUG(5,("normalize_name_map: Setting domain %s offline\n",
			 domain->name));
		set_domain_offline(domain);
		return nt_status;
	}

	/* deal with whitespace */

	*normalized = talloc_strdup(mem_ctx, name);
	if (!(*normalized)) {
		return NT_STATUS_NO_MEMORY;
	}

	all_string_sub( *normalized, " ", "_", 0 );

	return NT_STATUS_OK;
}

/*********************************************************************
 We use this to do the inverse of normalize_name_map()
********************************************************************/

NTSTATUS normalize_name_unmap(TALLOC_CTX *mem_ctx,
			      const char *name,
			      char **normalized)
{
	NTSTATUS nt_status;
	struct winbindd_domain *domain = find_our_domain();

	if (!name || !normalized) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!lp_winbind_normalize_names()) {
		return NT_STATUS_PROCEDURE_NOT_FOUND;
	}

	/* Alias support and whitespace replacement are mutally
	   exclusive */

	/* When mapping from an alias to a username, we don't know the
	   domain.  But we only need a domain structure to cache
	   a successful lookup , so just our own domain structure for
	   the seqnum. */

	nt_status = resolve_alias_to_username(mem_ctx, domain,
					      name, normalized);
	if (NT_STATUS_IS_OK(nt_status)) {
		/* Special return code to let the caller know we mapped
		   from an alias */
		return NT_STATUS_FILE_RENAMED;
	}

	/* check for an unreachable domain */

	if (NT_STATUS_EQUAL(nt_status, NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND)) {
		DEBUG(5,("normalize_name_unmap: Setting domain %s offline\n",
			 domain->name));
		set_domain_offline(domain);
		return nt_status;
	}

	/* deal with whitespace */

	*normalized = talloc_strdup(mem_ctx, name);
	if (!(*normalized)) {
		return NT_STATUS_NO_MEMORY;
	}

	all_string_sub(*normalized, "_", " ", 0);

	return NT_STATUS_OK;
}

/*********************************************************************
 ********************************************************************/

bool winbindd_can_contact_domain(struct winbindd_domain *domain)
{
	struct winbindd_tdc_domain *tdc = NULL;
	TALLOC_CTX *frame = talloc_stackframe();
	bool ret = false;

	/* We can contact the domain if it is our primary domain */

	if (domain->primary) {
		ret = true;
		goto done;
	}

	/* Trust the TDC cache and not the winbindd_domain flags */

	if ((tdc = wcache_tdc_fetch_domain(frame, domain->name)) == NULL) {
		DEBUG(10,("winbindd_can_contact_domain: %s not found in cache\n",
			  domain->name));
		ret = false;
		goto done;
	}

	/* Can always contact a domain that is in out forest */

	if (tdc->trust_flags & NETR_TRUST_FLAG_IN_FOREST) {
		ret = true;
		goto done;
	}

	/*
	 * On a _member_ server, we cannot contact the domain if it
	 * is running AD and we have no inbound trust.
	 */

	if (!IS_DC &&
	     domain->active_directory &&
	    ((tdc->trust_flags & NETR_TRUST_FLAG_INBOUND) != NETR_TRUST_FLAG_INBOUND))
	{
		DEBUG(10, ("winbindd_can_contact_domain: %s is an AD domain "
			   "and we have no inbound trust.\n", domain->name));
		goto done;
	}

	/* Assume everything else is ok (probably not true but what
	   can you do?) */

	ret = true;

done:
	talloc_destroy(frame);

	return ret;
}

#ifdef HAVE_KRB5_LOCATE_PLUGIN_H

/*********************************************************************
 ********************************************************************/

static void winbindd_set_locator_kdc_env(const struct winbindd_domain *domain)
{
	char *var = NULL;
	char addr[INET6_ADDRSTRLEN];
	const char *kdc = NULL;
	int lvl = 11;

	if (!domain || !domain->alt_name || !*domain->alt_name) {
		return;
	}

	if (domain->initialized && !domain->active_directory) {
		DEBUG(lvl,("winbindd_set_locator_kdc_env: %s not AD\n",
			domain->alt_name));
		return;
	}

	print_sockaddr(addr, sizeof(addr), &domain->dcaddr);
	kdc = addr;
	if (!*kdc) {
		DEBUG(lvl,("winbindd_set_locator_kdc_env: %s no DC IP\n",
			domain->alt_name));
		kdc = domain->dcname;
	}

	if (!kdc || !*kdc) {
		DEBUG(lvl,("winbindd_set_locator_kdc_env: %s no DC at all\n",
			domain->alt_name));
		return;
	}

	var = talloc_asprintf_strupper_m(
		talloc_tos(),
		"%s_%s",
		WINBINDD_LOCATOR_KDC_ADDRESS,
		domain->alt_name);
	if (var == NULL) {
		return;
	}

	DEBUG(lvl,("winbindd_set_locator_kdc_env: setting var: %s to: %s\n",
		var, kdc));

	setenv(var, kdc, 1);
	TALLOC_FREE(var);
}

/*********************************************************************
 ********************************************************************/

void winbindd_set_locator_kdc_envs(const struct winbindd_domain *domain)
{
	struct winbindd_domain *our_dom = find_our_domain();

	winbindd_set_locator_kdc_env(domain);

	if (domain != our_dom) {
		winbindd_set_locator_kdc_env(our_dom);
	}
}

/*********************************************************************
 ********************************************************************/

void winbindd_unset_locator_kdc_env(const struct winbindd_domain *domain)
{
	char *var = NULL;

	if (!domain || !domain->alt_name || !*domain->alt_name) {
		return;
	}

	var = talloc_asprintf_strupper_m(
		talloc_tos(),
		"%s_%s",
		WINBINDD_LOCATOR_KDC_ADDRESS,
		domain->alt_name);
	if (var == NULL) {
		return;
	}

	unsetenv(var);
	TALLOC_FREE(var);
}
#else

void winbindd_set_locator_kdc_envs(const struct winbindd_domain *domain)
{
	return;
}

void winbindd_unset_locator_kdc_env(const struct winbindd_domain *domain)
{
	return;
}

#endif /* HAVE_KRB5_LOCATE_PLUGIN_H */

void set_auth_errors(struct winbindd_response *resp, NTSTATUS result)
{
	/*
	 * Make sure we start with authoritative=true,
	 * it will only set to false if we don't know the
	 * domain.
	 */
	resp->data.auth.authoritative = true;

	resp->data.auth.nt_status = NT_STATUS_V(result);
	fstrcpy(resp->data.auth.nt_status_string, nt_errstr(result));

	/* we might have given a more useful error above */
	if (*resp->data.auth.error_string == '\0')
		fstrcpy(resp->data.auth.error_string,
			get_friendly_nt_error_msg(result));
	resp->data.auth.pam_error = nt_status_to_pam(result);
}

bool is_domain_offline(const struct winbindd_domain *domain)
{
	if (get_global_winbindd_state_offline()) {
		return true;
	}
	return !domain->online;
}

bool is_domain_online(const struct winbindd_domain *domain)
{
	return !is_domain_offline(domain);
}

/**
 * Parse an char array into a list of sids.
 *
 * The input sidstr should consist of 0-terminated strings
 * representing sids, separated by newline characters '\n'.
 * The list is terminated by an empty string, i.e.
 * character '\0' directly following a character '\n'
 * (or '\0' right at the start of sidstr).
 */
bool parse_sidlist(TALLOC_CTX *mem_ctx, const char *sidstr,
		   struct dom_sid **sids, uint32_t *num_sids)
{
	const char *p;

	p = sidstr;
	if (p == NULL)
		return False;

	while (p[0] != '\0') {
		struct dom_sid sid;
		const char *q = NULL;

		if (!dom_sid_parse_endp(p, &sid, &q)) {
			DEBUG(1, ("Could not parse sid %s\n", p));
			return false;
		}
		if (q[0] != '\n') {
			DEBUG(1, ("Got invalid sidstr: %s\n", p));
			return false;
		}
		if (!NT_STATUS_IS_OK(add_sid_to_array(mem_ctx, &sid, sids,
						      num_sids)))
		{
			return False;
		}
		p = q+1;
	}
	return True;
}

bool parse_xidlist(TALLOC_CTX *mem_ctx, const char *xidstr,
		   struct unixid **pxids, uint32_t *pnum_xids)
{
	const char *p;
	struct unixid *xids = NULL;
	uint32_t num_xids = 0;

	p = xidstr;
	if (p == NULL) {
		return false;
	}

	while (p[0] != '\0') {
		struct unixid *tmp;
		struct unixid xid;
		unsigned long long id;
		char *endp;
		int error = 0;

		switch (p[0]) {
		case 'U':
			xid = (struct unixid) { .type = ID_TYPE_UID };
			break;
		case 'G':
			xid = (struct unixid) { .type = ID_TYPE_GID };
			break;
		default:
			return false;
		}

		p += 1;

		id = smb_strtoull(p, &endp, 10, &error, SMB_STR_STANDARD);
		if (error != 0) {
			goto fail;
		}
		if (*endp != '\n') {
			goto fail;
		}
		p = endp+1;

		xid.id = id;
		if ((unsigned long long)xid.id != id) {
			goto fail;
		}

		tmp = talloc_realloc(mem_ctx, xids, struct unixid, num_xids+1);
		if (tmp == NULL) {
			return 0;
		}
		xids = tmp;

		xids[num_xids] = xid;
		num_xids += 1;
	}

	*pxids = xids;
	*pnum_xids = num_xids;
	return true;

fail:
	TALLOC_FREE(xids);
	return false;
}

/**
 * Helper to extract the DNS Domain Name from a struct winbindd_domain
 */
const char *find_dns_domain_name(const char *domain_name)
{
	struct winbindd_domain *wbdom = NULL;

	wbdom = find_domain_from_name_noinit(domain_name);
	if (wbdom == NULL) {
		return domain_name;
	}

	if (wbdom->active_directory && wbdom->alt_name != NULL) {
		return wbdom->alt_name;
	}

	return wbdom->name;
}
