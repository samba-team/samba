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

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_WINBIND


static const struct winbindd_child_dispatch_table locator_dispatch_table[];

static struct winbindd_child static_locator_child;

void init_locator_child(void)
{
	setup_child(&static_locator_child,
		    locator_dispatch_table,
		    "log.winbindd", "locator");
}

struct winbindd_child *locator_child(void)
{
	return &static_locator_child;
}

void winbindd_dsgetdcname(struct winbindd_cli_state *state)
{
	state->request.domain_name
		[sizeof(state->request.domain_name)-1] = '\0';

	DEBUG(3, ("[%5lu]: dsgetdcname for %s\n", (unsigned long)state->pid,
		  state->request.domain_name));

	sendto_child(state, locator_child());
}

struct wbc_flag_map {
	uint32_t wbc_dc_flag;
	uint32_t ds_dc_flags;
};

static uint32_t get_dsgetdc_flags(uint32_t wbc_flags)
{
	struct wbc_flag_map lookup_dc_flags[] = {
		{ WBC_LOOKUP_DC_FORCE_REDISCOVERY, DS_FORCE_REDISCOVERY },
		{ WBC_LOOKUP_DC_DS_REQUIRED, DS_DIRECTORY_SERVICE_REQUIRED },
		{ WBC_LOOKUP_DC_DS_PREFERRED, DS_DIRECTORY_SERVICE_PREFERRED},
		{ WBC_LOOKUP_DC_GC_SERVER_REQUIRED, DS_GC_SERVER_REQUIRED },
		{ WBC_LOOKUP_DC_PDC_REQUIRED,  DS_PDC_REQUIRED},
		{ WBC_LOOKUP_DC_BACKGROUND_ONLY, DS_BACKGROUND_ONLY  },
		{ WBC_LOOKUP_DC_IP_REQUIRED, DS_IP_REQUIRED },
		{ WBC_LOOKUP_DC_KDC_REQUIRED, DS_KDC_REQUIRED },
		{ WBC_LOOKUP_DC_TIMESERV_REQUIRED, DS_TIMESERV_REQUIRED },
		{ WBC_LOOKUP_DC_WRITABLE_REQUIRED,  DS_WRITABLE_REQUIRED },
		{ WBC_LOOKUP_DC_GOOD_TIMESERV_PREFERRED, DS_GOOD_TIMESERV_PREFERRED },
		{ WBC_LOOKUP_DC_AVOID_SELF, DS_AVOID_SELF },
		{ WBC_LOOKUP_DC_ONLY_LDAP_NEEDED, DS_ONLY_LDAP_NEEDED },
		{ WBC_LOOKUP_DC_IS_FLAT_NAME, DS_IS_FLAT_NAME },
		{ WBC_LOOKUP_DC_IS_DNS_NAME, DS_IS_DNS_NAME },
		{ WBC_LOOKUP_DC_TRY_NEXTCLOSEST_SITE, DS_TRY_NEXTCLOSEST_SITE },
		{ WBC_LOOKUP_DC_DS_6_REQUIRED, DS_DIRECTORY_SERVICE_6_REQUIRED },
		{ WBC_LOOKUP_DC_RETURN_DNS_NAME, DS_RETURN_DNS_NAME },
		{ WBC_LOOKUP_DC_RETURN_FLAT_NAME, DS_RETURN_FLAT_NAME }
	};
	uint32_t ds_flags = 0;
	int i = 0 ;
	int num_entries = sizeof(lookup_dc_flags) / sizeof(struct wbc_flag_map);

	for (i=0; i<num_entries; i++) {
		if (wbc_flags & lookup_dc_flags[i].wbc_dc_flag)
			ds_flags |= lookup_dc_flags[i].ds_dc_flags;
	}

	return ds_flags;
}


static enum winbindd_result dual_dsgetdcname(struct winbindd_domain *domain,
					     struct winbindd_cli_state *state)
{
	NTSTATUS result;
	struct netr_DsRGetDCNameInfo *info = NULL;
	const char *dc = NULL;
	uint32_t ds_flags = 0;

	state->request.domain_name
		[sizeof(state->request.domain_name)-1] = '\0';

	DEBUG(3, ("[%5lu]: dsgetdcname for %s\n", (unsigned long)state->pid,
		  state->request.domain_name));

	ds_flags = get_dsgetdc_flags(state->request.flags);

	result = dsgetdcname(state->mem_ctx, winbind_messaging_context(),
			     state->request.domain_name,
			     NULL, NULL, ds_flags, &info);

	if (!NT_STATUS_IS_OK(result)) {
		return WINBINDD_ERROR;
	}

	if (info->dc_address) {
		dc = strip_hostname(info->dc_address);
	}

	if ((!dc || !is_ipaddress_v4(dc)) && info->dc_unc) {
		dc = strip_hostname(info->dc_unc);
	}

	if (!dc || !*dc) {
		return WINBINDD_ERROR;
	}

	fstrcpy(state->response.data.dc_name, dc);

	return WINBINDD_OK;
}

static const struct winbindd_child_dispatch_table locator_dispatch_table[] = {
	{
		.name		= "DSGETDCNAME",
		.struct_cmd	= WINBINDD_DSGETDCNAME,
		.struct_fn	= dual_dsgetdcname,
	},{
		.name		= NULL,
	}
};
