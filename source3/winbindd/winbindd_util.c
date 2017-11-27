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
#include "../libcli/security/security.h"
#include "../libcli/auth/pam_errors.h"
#include "passdb/machine_sid.h"
#include "passdb.h"
#include "source4/lib/messaging/messaging.h"
#include "librpc/gen_ndr/ndr_lsa.h"
#include "auth/credentials/credentials.h"
#include "libsmb/samlogon_cache.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_WINBIND

static struct winbindd_domain *
add_trusted_domain_from_tdc(const struct winbindd_tdc_domain *tdc);

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

struct winbindd_domain *domain_list(void)
{
	/* Initialise list */

	if ((!_domain_list) && (!init_domain_list())) {
		smb_panic("Init_domain_list failed");
	}

	return _domain_list;
}

/* Free all entries in the trusted domain list */

static void free_domain_list(void)
{
	struct winbindd_domain *domain = _domain_list;

	while(domain) {
		struct winbindd_domain *next = domain->next;

		DLIST_REMOVE(_domain_list, domain);
		TALLOC_FREE(domain);
		domain = next;
	}
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

static bool is_internal_domain(const struct dom_sid *sid)
{
	if (sid == NULL)
		return False;

	return (sid_check_is_our_sam(sid) || sid_check_is_builtin(sid));
}

static bool is_in_internal_domain(const struct dom_sid *sid)
{
	if (sid == NULL)
		return False;

	return (sid_check_is_in_our_sam(sid) || sid_check_is_in_builtin(sid));
}


/* Add a trusted domain to our list of domains.
   If the domain already exists in the list,
   return it and don't re-initialize.  */

static struct winbindd_domain *
add_trusted_domain(const char *domain_name, const char *alt_name,
		   const struct dom_sid *sid)
{
	struct winbindd_tdc_domain tdc;

	ZERO_STRUCT(tdc);

	tdc.domain_name = domain_name;
	tdc.dns_name = alt_name;
	if (sid) {
		sid_copy(&tdc.sid, sid);
	}

	return add_trusted_domain_from_tdc(&tdc);
}

/* Add a trusted domain out of a trusted domain cache
   entry
*/
static struct winbindd_domain *
add_trusted_domain_from_tdc(const struct winbindd_tdc_domain *tdc)
{
	struct winbindd_domain *domain;
	const char *alternative_name = NULL;
	const char **ignored_domains, **dom;
	int role = lp_server_role();
	const char *domain_name = tdc->domain_name;
	const struct dom_sid *sid = &tdc->sid;

	if (is_null_sid(sid)) {
		sid = NULL;
	}

	ignored_domains = lp_parm_string_list(-1, "winbind", "ignore domains", NULL);
	for (dom=ignored_domains; dom && *dom; dom++) {
		if (gen_fnmatch(*dom, domain_name) == 0) {
			DEBUG(2,("Ignoring domain '%s'\n", domain_name));
			return NULL;
		}
	}

	/* use alt_name if available to allow DNS lookups */

	if (tdc->dns_name && *tdc->dns_name) {
		alternative_name = tdc->dns_name;
	}

	/* We can't call domain_list() as this function is called from
	   init_domain_list() and we'll get stuck in a loop. */
	for (domain = _domain_list; domain; domain = domain->next) {
		if (strequal(domain_name, domain->name) ||
		    strequal(domain_name, domain->alt_name))
		{
			break;
		}

		if (alternative_name) {
			if (strequal(alternative_name, domain->name) ||
			    strequal(alternative_name, domain->alt_name))
			{
				break;
			}
		}

		if (sid != NULL) {
			if (dom_sid_equal(sid, &domain->sid)) {
				break;
			}
		}
	}

	if (domain != NULL) {
		/*
		 * We found a match on domain->name or
		 * domain->alt_name. Possibly update the SID
		 * if the stored SID was the NULL SID
		 * and return the matching entry.
		 */
		if ((sid != NULL)
		    && dom_sid_equal(&domain->sid, &global_sid_NULL)) {
			sid_copy( &domain->sid, sid );
		}
		return domain;
	}

	/* Create new domain entry */
	domain = talloc_zero(NULL, struct winbindd_domain);
	if (domain == NULL) {
		return NULL;
	}

	domain->children = talloc_zero_array(domain,
					     struct winbindd_child,
					     lp_winbind_max_domain_connections());
	if (domain->children == NULL) {
		TALLOC_FREE(domain);
		return NULL;
	}

	domain->name = talloc_strdup(domain, domain_name);
	if (domain->name == NULL) {
		TALLOC_FREE(domain);
		return NULL;
	}

	if (alternative_name) {
		domain->alt_name = talloc_strdup(domain, alternative_name);
		if (domain->alt_name == NULL) {
			TALLOC_FREE(domain);
			return NULL;
		}
	}

	domain->backend = NULL;
	domain->internal = is_internal_domain(sid);
	domain->sequence_number = DOM_SEQUENCE_NONE;
	domain->last_seq_check = 0;
	domain->initialized = false;
	domain->online = is_internal_domain(sid);
	domain->check_online_timeout = 0;
	domain->dc_probe_pid = (pid_t)-1;
	if (sid != NULL) {
		sid_copy(&domain->sid, sid);
	}
	domain->domain_flags = tdc->trust_flags;
	domain->domain_type = tdc->trust_type;
	domain->domain_trust_attribs = tdc->trust_attribs;

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

	/* Link to domain list */
	DLIST_ADD_END(_domain_list, domain);

	wcache_tdc_add_domain( domain );

	setup_domain_child(domain);

	DEBUG(2,
	      ("Added domain %s %s %s\n", domain->name, domain->alt_name,
	       !is_null_sid(&domain->sid) ? sid_string_dbg(&domain->sid) : ""));

	return domain;
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
	struct winbindd_domain *domain;
	struct winbindd_request request;
};

static void trustdom_list_done(struct tevent_req *req);
static void rescan_forest_root_trusts( void );
static void rescan_forest_trusts( void );

static void add_trusted_domains( struct winbindd_domain *domain )
{
	struct trustdom_state *state;
	struct tevent_req *req;

	state = talloc_zero(NULL, struct trustdom_state);
	if (state == NULL) {
		DEBUG(0, ("talloc failed\n"));
		return;
	}
	state->domain = domain;

	state->request.length = sizeof(state->request);
	state->request.cmd = WINBINDD_LIST_TRUSTDOM;

	req = wb_domain_request_send(state, server_event_context(),
				     domain, &state->request);
	if (req == NULL) {
		DEBUG(1, ("wb_domain_request_send failed\n"));
		TALLOC_FREE(state);
		return;
	}
	tevent_req_set_callback(req, trustdom_list_done, state);
}

static void trustdom_list_done(struct tevent_req *req)
{
	struct trustdom_state *state = tevent_req_callback_data(
		req, struct trustdom_state);
	struct winbindd_response *response;
	int res, err;
	char *p;
	struct winbindd_tdc_domain trust_params = {0};
	ptrdiff_t extra_len;
	bool within_forest = false;

	/*
	 * Only when we enumerate our primary domain
	 * or our forest root domain, we should keep
	 * the NETR_TRUST_FLAG_IN_FOREST flag, in
	 * all other cases we need to clear it as the domain
	 * is not part of our forest.
	 */
	if (state->domain->primary) {
		within_forest = true;
	} else if (domain_is_forest_root(state->domain)) {
		within_forest = true;
	}

	res = wb_domain_request_recv(req, state, &response, &err);
	if ((res == -1) || (response->result != WINBINDD_OK)) {
		DBG_WARNING("Could not receive trusts for domain %s\n",
			    state->domain->name);
		TALLOC_FREE(state);
		return;
	}

	if (response->length < sizeof(struct winbindd_response)) {
		DBG_ERR("ill-formed trustdom response - short length\n");
		TALLOC_FREE(state);
		return;
	}

	extra_len = response->length - sizeof(struct winbindd_response);

	p = (char *)response->extra_data.data;

	while ((p - (char *)response->extra_data.data) < extra_len) {
		char *q, *sidstr, *alt_name;

		DBG_DEBUG("parsing response line '%s'\n", p);

		ZERO_STRUCT(trust_params);
		trust_params.domain_name = p;

		alt_name = strchr(p, '\\');
		if (alt_name == NULL) {
			DBG_ERR("Got invalid trustdom response\n");
			break;
		}

		*alt_name = '\0';
		alt_name += 1;

		sidstr = strchr(alt_name, '\\');
		if (sidstr == NULL) {
			DBG_ERR("Got invalid trustdom response\n");
			break;
		}

		*sidstr = '\0';
		sidstr += 1;

		/* use the real alt_name if we have one, else pass in NULL */
		if (!strequal(alt_name, "(null)")) {
			trust_params.dns_name = alt_name;
		}

		q = strtok(sidstr, "\\");
		if (q == NULL) {
			DBG_ERR("Got invalid trustdom response\n");
			break;
		}

		if (!string_to_sid(&trust_params.sid, sidstr)) {
			DEBUG(0, ("Got invalid trustdom response\n"));
			break;
		}

		q = strtok(NULL, "\\");
		if (q == NULL) {
			DBG_ERR("Got invalid trustdom response\n");
			break;
		}

		trust_params.trust_flags = (uint32_t)strtoul(q, NULL, 10);

		q = strtok(NULL, "\\");
		if (q == NULL) {
			DBG_ERR("Got invalid trustdom response\n");
			break;
		}

		trust_params.trust_type = (uint32_t)strtoul(q, NULL, 10);

		q = strtok(NULL, "\n");
		if (q == NULL) {
			DBG_ERR("Got invalid trustdom response\n");
			break;
		}

		trust_params.trust_attribs = (uint32_t)strtoul(q, NULL, 10);

		if (!within_forest) {
			trust_params.trust_flags &= ~NETR_TRUST_FLAG_IN_FOREST;
		}

		if (!state->domain->primary) {
			trust_params.trust_flags &= ~NETR_TRUST_FLAG_PRIMARY;
		}

		/*
		 * We always call add_trusted_domain() cause on an existing
		 * domain structure, it will update the SID if necessary.
		 * This is important because we need the SID for sibling
		 * domains.
		 */
		(void)add_trusted_domain_from_tdc(&trust_params);

		p = q + strlen(q) + 1;
	}

	/*
	   Cases to consider when scanning trusts:
	   (a) we are calling from a child domain (primary && !forest_root)
	   (b) we are calling from the root of the forest (primary && forest_root)
	   (c) we are calling from a trusted forest domain (!primary
	       && !forest_root)
	*/

	if (state->domain->primary) {
		/* If this is our primary domain and we are not in the
		   forest root, we have to scan the root trusts first */

		if (!domain_is_forest_root(state->domain))
			rescan_forest_root_trusts();
		else
			rescan_forest_trusts();

	} else if (domain_is_forest_root(state->domain)) {
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
	int i;

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

		if ( !d ) {
			d = add_trusted_domain_from_tdc(&dom_list[i]);
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
	int i;

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
		     (attribs == LSA_TRUST_ATTRIBUTE_FOREST_TRANSITIVE) )
		{
			/* add the trusted domain if we don't know
			   about it */

			if ( !d ) {
				d = add_trusted_domain_from_tdc(&dom_list[i]);
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
 (c) ask the a DC in any Win2003 trusted forests
*********************************************************************/

void rescan_trusted_domains(struct tevent_context *ev, struct tevent_timer *te,
			    struct timeval now, void *private_data)
{
	TALLOC_FREE(te);

	/* I use to clear the cache here and start over but that
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

enum winbindd_result winbindd_dual_init_connection(struct winbindd_domain *domain,
						   struct winbindd_cli_state *state)
{
	/* Ensure null termination */
	state->request->domain_name
		[sizeof(state->request->domain_name)-1]='\0';
	state->request->data.init_conn.dcname
		[sizeof(state->request->data.init_conn.dcname)-1]='\0';

	if (strlen(state->request->data.init_conn.dcname) > 0) {
		fstrcpy(domain->dcname, state->request->data.init_conn.dcname);
	}

	init_dc_connection(domain, false);

	if (!domain->initialized) {
		/* If we return error here we can't do any cached authentication,
		   but we may be in disconnected mode and can't initialize correctly.
		   Do what the previous code did and just return without initialization,
		   once we go online we'll re-initialize.
		*/
		DEBUG(5, ("winbindd_dual_init_connection: %s returning without initialization "
			"online = %d\n", domain->name, (int)domain->online ));
	}

	fstrcpy(state->response->data.domain_info.name, domain->name);
	fstrcpy(state->response->data.domain_info.alt_name, domain->alt_name);
	sid_to_fstring(state->response->data.domain_info.sid, &domain->sid);

	state->response->data.domain_info.native_mode
		= domain->native_mode;
	state->response->data.domain_info.active_directory
		= domain->active_directory;
	state->response->data.domain_info.primary
		= domain->primary;

	return WINBINDD_OK;
}

static void wb_imsg_new_trusted_domain(struct imessaging_context *msg,
				       void *private_data,
				       uint32_t msg_type,
				       struct server_id server_id,
				       DATA_BLOB *data)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct lsa_TrustDomainInfoInfoEx info;
	enum ndr_err_code ndr_err;
	struct winbindd_domain *d = NULL;

	DEBUG(5, ("wb_imsg_new_trusted_domain\n"));

	if (data == NULL) {
		TALLOC_FREE(frame);
		return;
	}

	ndr_err = ndr_pull_struct_blob_all(data, frame, &info,
			(ndr_pull_flags_fn_t)ndr_pull_lsa_TrustDomainInfoInfoEx);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		TALLOC_FREE(frame);
		return;
	}

	d = find_domain_from_name_noinit(info.netbios_name.string);
	if (d != NULL) {
		TALLOC_FREE(frame);
		return;
	}

	d = add_trusted_domain(info.netbios_name.string,
			       info.domain_name.string,
			       info.sid);
	if (d == NULL) {
		TALLOC_FREE(frame);
		return;
	}

	if (d->internal) {
		TALLOC_FREE(frame);
		return;
	}

	if (d->primary) {
		TALLOC_FREE(frame);
		return;
	}

	if (info.trust_direction & LSA_TRUST_DIRECTION_INBOUND) {
		d->domain_flags |= NETR_TRUST_FLAG_INBOUND;
	}
	if (info.trust_direction & LSA_TRUST_DIRECTION_OUTBOUND) {
		d->domain_flags |= NETR_TRUST_FLAG_OUTBOUND;
	}
	if (info.trust_attributes & LSA_TRUST_ATTRIBUTE_WITHIN_FOREST) {
		d->domain_flags |= NETR_TRUST_FLAG_IN_FOREST;
	}
	d->domain_type = info.trust_type;
	d->domain_trust_attribs = info.trust_attributes;

	TALLOC_FREE(frame);
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
		DEBUG(0, ("Failed to fetch our own, local AD domain join "
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
		   cli_credentials_get_salt_principal(creds),
		   0, /* Supported enc types, unused */
		   &domain->sid,
		   cli_credentials_get_password_last_changed_time(creds),
		   cli_credentials_get_secure_channel_type(creds),
		   false /* do_delete: Do not delete */);
	TALLOC_FREE(creds);
	if (ok == false) {
		DEBUG(0, ("Failed to write our our own, "
			  "local AD domain join password for "
			  "winbindd's internal use into secrets.tdb\n"));
		return false;
	}
	return true;
}

/* Look up global info for the winbind daemon */
bool init_domain_list(void)
{
	int role = lp_server_role();
	struct pdb_domain_info *pdb_domain_info = NULL;
	NTSTATUS status;

	/* Free existing list */
	free_domain_list();

	/* BUILTIN domain */

	(void)add_trusted_domain("BUILTIN", NULL, &global_sid_Builtin);

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
		struct winbindd_domain *domain;
		enum netr_SchannelType sec_chan_type;
		const char *account_name;
		struct samr_Password current_nt_hash;
		bool ok;

		if (pdb_domain_info == NULL) {
			DEBUG(0, ("Failed to fetch our own, local AD "
				"domain info from sam.ldb\n"));
			return false;
		}
		domain = add_trusted_domain(pdb_domain_info->name,
					pdb_domain_info->dns_domain,
					&pdb_domain_info->sid);
		TALLOC_FREE(pdb_domain_info);
		if (domain == NULL) {
			DEBUG(0, ("Failed to add our own, local AD "
				"domain to winbindd's internal list\n"));
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
				DEBUG(0, ("Failed to migrate our own, "
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
				DEBUG(0, ("Failed to find our our own, just "
					  "written local AD domain join "
					  "password for winbindd's internal "
					  "use in secrets.tdb\n"));
				return false;
			}
		}
		if (sec_chan_type == SEC_CHAN_RODC) {
			domain->rodc = true;
		}

	} else {
		(void)add_trusted_domain(get_global_sam_name(), NULL,
					 get_global_sam_sid());
	}
	/* Add ourselves as the first entry. */

	if ( role == ROLE_DOMAIN_MEMBER ) {
		struct winbindd_domain *domain;
		struct dom_sid our_sid;

		if (!secrets_fetch_domain_sid(lp_workgroup(), &our_sid)) {
			DEBUG(0, ("Could not fetch our SID - did we join?\n"));
			return False;
		}

		domain = add_trusted_domain(lp_workgroup(), lp_realm(),
					    &our_sid);
		if (domain) {
			/* Even in the parent winbindd we'll need to
			   talk to the DC, so try and see if we can
			   contact it. Theoretically this isn't neccessary
			   as the init_dc_connection() in init_child_recv()
			   will do this, but we can start detecting the DC
			   early here. */
			set_domain_online_request(domain);
		}
	}

	status = imessaging_register(winbind_imessaging_context(), NULL,
				     MSG_WINBIND_NEW_TRUSTED_DOMAIN,
				     wb_imsg_new_trusted_domain);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("imessaging_register(MSG_WINBIND_NEW_TRUSTED_DOMAIN) - %s\n",
			  nt_errstr(status)));
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
		if (strequal(domain_name, domain->name) ||
		    (domain->alt_name != NULL &&
		     strequal(domain_name, domain->alt_name))) {
			return domain;
		}
	}

	/* Not found */

	return NULL;
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

/* Find the appropriate domain to lookup a name or SID */

struct winbindd_domain *find_lookup_domain_from_sid(const struct dom_sid *sid)
{
	DBG_DEBUG("SID [%s]\n", sid_string_dbg(sid));

	/*
	 * SIDs in the S-1-22-{1,2} domain and well-known SIDs should be handled
	 * by our passdb.
	 */

	if ( sid_check_is_in_unix_groups(sid) ||
	     sid_check_is_unix_groups(sid) ||
	     sid_check_is_in_unix_users(sid) ||
	     sid_check_is_unix_users(sid) ||
	     sid_check_is_wellknown_domain(sid, NULL) ||
	     sid_check_is_in_wellknown_domain(sid) )
	{
		return find_domain_from_sid(get_global_sam_sid());
	}

	/* A DC can't ask the local smbd for remote SIDs, here winbindd is the
	 * one to contact the external DC's. On member servers the internal
	 * domains are different: These are part of the local SAM. */

	if (IS_DC || is_internal_domain(sid) || is_in_internal_domain(sid)) {
		DEBUG(10, ("calling find_domain_from_sid\n"));
		return find_domain_from_sid(sid);
	}

	/* On a member server a query for SID or name can always go to our
	 * primary DC. */

	DEBUG(10, ("calling find_our_domain\n"));
	return find_our_domain();
}

struct winbindd_domain *find_lookup_domain_from_name(const char *domain_name)
{
	if ( strequal(domain_name, unix_users_domain_name() ) ||
	     strequal(domain_name, unix_groups_domain_name() ) )
	{
		/*
		 * The "Unix User" and "Unix Group" domain our handled by
		 * passdb
		 */
		return find_domain_from_name_noinit( get_global_sam_name() );
	}

	if (IS_DC || strequal(domain_name, "BUILTIN") ||
	    strequal(domain_name, get_global_sam_name()))
		return find_domain_from_name_noinit(domain_name);


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

		if ( lp_winbind_use_default_domain() || lp_winbind_trusted_domains_only() )
			return True;
	}

	/* only left with a domain controller */

	if ( strequal(get_global_sam_name(), domain) )  {
		return True;
	}

	return False;
}

/* Parse a string of the form DOMAIN\user into a domain and a user */

bool parse_domain_user(const char *domuser, fstring domain, fstring user)
{
	char *p = strchr(domuser,*lp_winbind_separator());

	if ( !p ) {
		fstrcpy(user, domuser);
		p = strchr(domuser, '@');

		if ( assume_domain(lp_workgroup()) && p == NULL) {
			fstrcpy(domain, lp_workgroup());
		} else if (p != NULL) {
			fstrcpy(domain, p + 1);
			user[PTR_DIFF(p, domuser)] = 0;
		} else {
			return False;
		}
	} else {
		fstrcpy(user, p+1);
		fstrcpy(domain, domuser);
		domain[PTR_DIFF(p, domuser)] = 0;
	}

	return strupper_m(domain);
}

bool parse_domain_user_talloc(TALLOC_CTX *mem_ctx, const char *domuser,
			      char **domain, char **user)
{
	fstring fstr_domain, fstr_user;
	if (!parse_domain_user(domuser, fstr_domain, fstr_user)) {
		return False;
	}
	*domain = talloc_strdup(mem_ctx, fstr_domain);
	*user = talloc_strdup(mem_ctx, fstr_user);
	return ((*domain != NULL) && (*user != NULL));
}

/* Ensure an incoming username from NSS is fully qualified. Replace the
   incoming fstring with DOMAIN <separator> user. Returns the same
   values as parse_domain_user() but also replaces the incoming username.
   Used to ensure all names are fully qualified within winbindd.
   Used by the NSS protocols of auth, chauthtok, logoff and ccache_ntlm_auth.
   The protocol definitions of auth_crap, chng_pswd_auth_crap
   really should be changed to use this instead of doing things
   by hand. JRA. */

bool canonicalize_username(fstring username_inout, fstring domain, fstring user)
{
	if (!parse_domain_user(username_inout, domain, user)) {
		return False;
	}
	slprintf(username_inout, sizeof(fstring) - 1, "%s%c%s",
		 domain, *lp_winbind_separator(),
		 user);
	return True;
}

/*
    Fill DOMAIN\\USERNAME entry accounting 'winbind use default domain' and
    'winbind separator' options.
    This means:
	- omit DOMAIN when 'winbind use default domain = true' and DOMAIN is
	lp_workgroup()

    If we are a PDC or BDC, and this is for our domain, do likewise.

    Also, if omit DOMAIN if 'winbind trusted domains only = true', as the
    username is then unqualified in unix

    On an AD DC we always fill DOMAIN\\USERNAME.

    We always canonicalize as UPPERCASE DOMAIN, lowercase username.
*/
void fill_domain_username(fstring name, const char *domain, const char *user, bool can_assume)
{
	fstring tmp_user;

	if (lp_server_role() == ROLE_ACTIVE_DIRECTORY_DC) {
		can_assume = false;
	}

	fstrcpy(tmp_user, user);
	(void)strlower_m(tmp_user);

	if (can_assume && assume_domain(domain)) {
		strlcpy(name, tmp_user, sizeof(fstring));
	} else {
		slprintf(name, sizeof(fstring) - 1, "%s%c%s",
			 domain, *lp_winbind_separator(),
			 tmp_user);
	}
}

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

	tmp_user = talloc_strdup(mem_ctx, user);
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
			      char *name,
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

/*********************************************************************
 ********************************************************************/

bool winbindd_internal_child(struct winbindd_child *child)
{
	if ((child == idmap_child()) || (child == locator_child())) {
		return True;
	}

	return False;
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

	if (asprintf_strupper_m(&var, "%s_%s", WINBINDD_LOCATOR_KDC_ADDRESS,
				domain->alt_name) == -1) {
		return;
	}

	DEBUG(lvl,("winbindd_set_locator_kdc_env: setting var: %s to: %s\n",
		var, kdc));

	setenv(var, kdc, 1);
	free(var);
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

	if (asprintf_strupper_m(&var, "%s_%s", WINBINDD_LOCATOR_KDC_ADDRESS,
				domain->alt_name) == -1) {
		return;
	}

	unsetenv(var);
	free(var);
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
	if (!lp_winbind_offline_logon()) {
		return false;
	}
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

		id = strtoull(p, &endp, 10);
		if ((id == ULLONG_MAX) && (errno == ERANGE)) {
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
