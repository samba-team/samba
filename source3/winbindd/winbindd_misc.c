/*
   Unix SMB/CIFS implementation.

   Winbind daemon - miscellaneous other functions

   Copyright (C) Tim Potter      2000
   Copyright (C) Andrew Bartlett 2002

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
#include "libcli/security/dom_sid.h"
#include "lib/util/string_wrappers.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_WINBIND

static char *get_trust_type_string(TALLOC_CTX *mem_ctx,
				   struct winbindd_tdc_domain *tdc,
				   struct winbindd_domain *domain)
{
	enum netr_SchannelType secure_channel_type = SEC_CHAN_NULL;
	char *s = NULL;

	if (domain != NULL) {
		secure_channel_type = domain->secure_channel_type;
	}

	switch (secure_channel_type) {
	case SEC_CHAN_NULL: {
		if (domain == NULL) {
			DBG_ERR("Missing domain [%s]\n",
				tdc->domain_name);
			return NULL;
		}
		if (domain->routing_domain == NULL) {
			DBG_ERR("Missing routing for domain [%s]\n",
				tdc->domain_name);
			return NULL;
		}
		s = talloc_asprintf(mem_ctx, "Routed (via %s)",
				    domain->routing_domain->name);
		if (s == NULL) {
			return NULL;
		}
		break;
	}

	case SEC_CHAN_LOCAL:
		s = talloc_strdup(mem_ctx, "Local");
		if (s == NULL) {
			return NULL;
		}
		break;

	case SEC_CHAN_WKSTA:
		s = talloc_strdup(mem_ctx, "Workstation");
		if (s == NULL) {
			return NULL;
		}
		break;

	case SEC_CHAN_BDC: {
		int role = lp_server_role();

		if (role == ROLE_DOMAIN_PDC || role == ROLE_IPA_DC) {
			s = talloc_strdup(mem_ctx, "PDC");
			if (s == NULL) {
				return NULL;
			}
			break;
		}

		if (role == ROLE_DOMAIN_BDC) {
			s = talloc_strdup(mem_ctx, "BDC");
			if (s == NULL) {
				return NULL;
			}
			break;
		}

		s = talloc_strdup(mem_ctx, "RWDC");
		if (s == NULL) {
			return NULL;
		}
		break;
	}

	case SEC_CHAN_RODC:
		s = talloc_strdup(mem_ctx, "RODC");
		if (s == NULL) {
			return NULL;
		}
		break;

	case SEC_CHAN_DNS_DOMAIN:
		if (tdc->trust_attribs & LSA_TRUST_ATTRIBUTE_QUARANTINED_DOMAIN) {
			s = talloc_strdup(mem_ctx, "External");
			if (s == NULL) {
				return NULL;
			}
			break;
		}
		if (tdc->trust_attribs & LSA_TRUST_ATTRIBUTE_WITHIN_FOREST) {
			s = talloc_strdup(mem_ctx, "In Forest");
			if (s == NULL) {
				return NULL;
			}
			break;
		}
		if (tdc->trust_attribs & LSA_TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL) {
			s = talloc_strdup(mem_ctx, "External");
			if (s == NULL) {
				return NULL;
			}
			break;
		}
		if (tdc->trust_attribs & LSA_TRUST_ATTRIBUTE_FOREST_TRANSITIVE) {
			s = talloc_strdup(mem_ctx, "Forest");
			if (s == NULL) {
				return NULL;
			}
			break;
		}
		s = talloc_strdup(mem_ctx, "External");
		if (s == NULL) {
			return NULL;
		}
		break;

	case SEC_CHAN_DOMAIN:
		s = talloc_strdup(mem_ctx, "External");
		if (s == NULL) {
			return NULL;
		}
		break;

	default:
		DBG_ERR("Unhandled secure_channel_type %d for domain[%s]\n",
			secure_channel_type, tdc->domain_name);
		return NULL;
	}

	return s;
}

static bool trust_is_inbound(struct winbindd_tdc_domain *domain)
{
	if (domain->trust_flags & NETR_TRUST_FLAG_INBOUND) {
		return true;
	}
	return false;
}

static bool trust_is_outbound(struct winbindd_tdc_domain *domain)
{
	if (domain->trust_flags & NETR_TRUST_FLAG_OUTBOUND) {
		return true;
	}
	return false;
}

static bool trust_is_transitive(struct winbindd_tdc_domain *domain)
{
	bool transitive = false;

	/*
	 * Beware: order matters
	 */

	if (domain->trust_attribs & LSA_TRUST_ATTRIBUTE_WITHIN_FOREST) {
		transitive = true;
	}

	if (domain->trust_attribs & LSA_TRUST_ATTRIBUTE_FOREST_TRANSITIVE) {
		transitive = true;
	}

	if (domain->trust_attribs & LSA_TRUST_ATTRIBUTE_NON_TRANSITIVE) {
		transitive = false;
	}

	if (domain->trust_attribs & LSA_TRUST_ATTRIBUTE_QUARANTINED_DOMAIN) {
		transitive = false;
	}

	if (domain->trust_flags & NETR_TRUST_FLAG_PRIMARY) {
		transitive = true;
	}

	return transitive;
}

bool winbindd_list_trusted_domains(struct winbindd_cli_state *state)
{
	struct winbindd_tdc_domain *dom_list = NULL;
	size_t num_domains = 0;
	int extra_data_len = 0;
	char *extra_data = NULL;
	size_t i = 0;
	bool ret = false;

	DBG_NOTICE("[%s (%u)]: list trusted domains\n",
		   state->client_name,
		   (unsigned int)state->pid);

	if( !wcache_tdc_fetch_list( &dom_list, &num_domains )) {
		goto done;
	}

	extra_data = talloc_strdup(state->mem_ctx, "");
	if (extra_data == NULL) {
		goto done;
	}

	for ( i = 0; i < num_domains; i++ ) {
		struct winbindd_domain *domain;
		bool is_online = true;
		struct winbindd_tdc_domain *d = NULL;
		char *trust_type = NULL;
		struct dom_sid_buf buf;

		d = &dom_list[i];
		domain = find_domain_from_name_noinit(d->domain_name);
		if (domain) {
			is_online = domain->online;
		}

		trust_type = get_trust_type_string(talloc_tos(), d, domain);
		if (trust_type == NULL) {
			continue;
		}

		extra_data = talloc_asprintf_append_buffer(
			extra_data,
			"%s\\%s\\%s\\%s\\%s\\%s\\%s\\%s\n",
			d->domain_name,
			d->dns_name ? d->dns_name : "",
			dom_sid_str_buf(&d->sid, &buf),
			trust_type,
			trust_is_transitive(d) ? "Yes" : "No",
			trust_is_inbound(d) ? "Yes" : "No",
			trust_is_outbound(d) ? "Yes" : "No",
			is_online ? "Online" : "Offline" );

		TALLOC_FREE(trust_type);
	}

	state->response->data.num_entries = num_domains;

	extra_data_len = strlen(extra_data);
	if (extra_data_len > 0) {

		/* Strip the last \n */
		extra_data[extra_data_len-1] = '\0';

		state->response->extra_data.data = extra_data;
		state->response->length += extra_data_len;
	}

	ret = true;
done:
	TALLOC_FREE( dom_list );
	return ret;
}

bool winbindd_dc_info(struct winbindd_cli_state *cli)
{
	struct winbindd_domain *domain;
	char *dc_name, *dc_ip;

	cli->request->domain_name[sizeof(cli->request->domain_name)-1] = '\0';

	DBG_NOTICE("[%s (%u)]: domain_info [%s]\n",
		   cli->client_name,
		   (unsigned int)cli->pid,
		   cli->request->domain_name);

	if (cli->request->domain_name[0] != '\0') {
		domain = find_trust_from_name_noinit(
			cli->request->domain_name);
		if (domain == NULL) {
			DEBUG(10, ("Could not find domain %s\n",
				   cli->request->domain_name));
			return false;
		}
	} else {
		domain = find_our_domain();
	}

	if (!fetch_current_dc_from_gencache(
		    talloc_tos(), domain->name, &dc_name, &dc_ip)) {
		DEBUG(10, ("fetch_current_dc_from_gencache(%s) failed\n",
			   domain->name));
		return false;
	}

	cli->response->data.num_entries = 1;
	cli->response->extra_data.data = talloc_asprintf(
		cli->mem_ctx, "%s\n%s\n", dc_name, dc_ip);

	TALLOC_FREE(dc_name);
	TALLOC_FREE(dc_ip);

	if (cli->response->extra_data.data == NULL) {
		return false;
	}

	/* must add one to length to copy the 0 for string termination */
	cli->response->length +=
		strlen((char *)cli->response->extra_data.data) + 1;

	return true;
}

bool winbindd_ping(struct winbindd_cli_state *state)
{
	DBG_NOTICE("[%s (%u)]: ping\n",
		   state->client_name,
		   (unsigned int)state->pid);
	return true;
}

/* List various tidbits of information */

bool winbindd_info(struct winbindd_cli_state *state)
{

	DBG_NOTICE("[%s (%u)]: request misc info\n",
		   state->client_name,
		   (unsigned int)state->pid);

	state->response->data.info.winbind_separator = *lp_winbind_separator();
	fstrcpy(state->response->data.info.samba_version, samba_version_string());
	return true;
}

/* Tell the client the current interface version */

bool winbindd_interface_version(struct winbindd_cli_state *state)
{
	DBG_NOTICE("[%s (%u)]: request interface version (version = %d)\n",
		   state->client_name,
		   (unsigned int)state->pid,
		   WINBIND_INTERFACE_VERSION);

	state->response->data.interface_version = WINBIND_INTERFACE_VERSION;
	return true;
}

/* What domain are we a member of? */

bool winbindd_domain_name(struct winbindd_cli_state *state)
{
	DBG_NOTICE("[%s (%u)]: request domain name\n",
		   state->client_name,
		   (unsigned int)state->pid);

	fstrcpy(state->response->data.domain_name, lp_workgroup());
	return true;
}

/* What's my name again? */

bool winbindd_netbios_name(struct winbindd_cli_state *state)
{
	DBG_NOTICE("[%s (%u)]: request netbios name\n",
		   state->client_name,
		   (unsigned int)state->pid);

	fstrcpy(state->response->data.netbios_name, lp_netbios_name());
	return true;
}

/* Where can I find the privileged pipe? */

char *get_winbind_priv_pipe_dir(void)
{
	return state_path(talloc_tos(), WINBINDD_PRIV_SOCKET_SUBDIR);
}

bool winbindd_priv_pipe_dir(struct winbindd_cli_state *state)
{
	char *priv_dir;

	DBG_NOTICE("[%s (%u)]: request location of privileged pipe\n",
		   state->client_name,
		   (unsigned int)state->pid);

	priv_dir = get_winbind_priv_pipe_dir();
	state->response->extra_data.data = talloc_move(state->mem_ctx,
						      &priv_dir);

	/* must add one to length to copy the 0 for string termination */
	state->response->length +=
		strlen((char *)state->response->extra_data.data) + 1;

	DBG_NOTICE("[%s (%u)]: response location of privileged pipe: %s\n",
		   state->client_name,
		   (unsigned int)state->pid,
		   priv_dir);

	return true;
}

static void winbindd_setup_max_fds(void)
{
	int num_fds = MAX_OPEN_FUDGEFACTOR;
	int actual_fds;

	num_fds += lp_winbind_max_clients();
	/* Add some more to account for 2 sockets open
	   when the client transitions from unprivileged
	   to privileged socket
	*/
	num_fds += lp_winbind_max_clients() / 10;

	/* Add one socket per child process
	   (yeah there are child processes other than the
	   domain children but only domain children can vary
	   with configuration
	*/
	num_fds += lp_winbind_max_domain_connections() *
		   (lp_allow_trusted_domains() ? WINBIND_MAX_DOMAINS_HINT : 1);

	actual_fds = set_maxfiles(num_fds);

	if (actual_fds < num_fds) {
		DEBUG(1, ("winbindd_setup_max_fds: Information only: "
			  "requested %d open files, %d are available.\n",
			  num_fds, actual_fds));
	}
}

bool winbindd_reload_services_file(const char *lfile)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	bool ret;

	if (lp_loaded()) {
		char *fname = lp_next_configfile(talloc_tos(), lp_sub);

		if (file_exist(fname) && !strcsequal(fname,get_dyn_CONFIGFILE())) {
			set_dyn_CONFIGFILE(fname);
		}
		TALLOC_FREE(fname);
	}

	reopen_logs();
	ret = lp_load_global(get_dyn_CONFIGFILE());

	/* if this is a child, restore the logfile to the special
	   name - <domain>, idmap, etc. */
	if (lfile && *lfile) {
		lp_set_logfile(lfile);
	}

	reopen_logs();
	load_interfaces();
	winbindd_setup_max_fds();

	return(ret);
}

static size_t *debug_call_depth = NULL;

void winbind_debug_call_depth_setup(size_t *depth)
{
	debug_call_depth = depth;
}

void winbind_call_flow(void *private_data,
		       enum tevent_thread_call_depth_cmd cmd,
		       struct tevent_req *req,
		       size_t depth,
		       const char *fname)
{
	switch (cmd) {
	case TEVENT_CALL_FLOW_REQ_CREATE:
		*debug_call_depth = depth;
		DEBUG(20, ("flow: -> %s\n", fname));
		break;
	case TEVENT_CALL_FLOW_REQ_NOTIFY_CB:
		*debug_call_depth = depth;
		DEBUG(20, ("flow: <- %s\n", fname));
		break;
	case TEVENT_CALL_FLOW_REQ_QUEUE_TRIGGER:
		*debug_call_depth = depth;
		break;
	case TEVENT_CALL_FLOW_REQ_RESET:
		*debug_call_depth = depth;
		break;
	case TEVENT_CALL_FLOW_REQ_CANCEL:
	case TEVENT_CALL_FLOW_REQ_CLEANUP:
	case TEVENT_CALL_FLOW_REQ_QUEUE_ENTER:
	case TEVENT_CALL_FLOW_REQ_QUEUE_LEAVE:
		break;
	}
}
