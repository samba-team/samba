/*
 *  Unix SMB/CIFS implementation.
 *  Virtual Windows Registry Layer
 *  Copyright (C) Gerald Carter     2002-2005
 *  Copyright (C) Michael Adam      2008
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/*
 * Netlogon parameters registry backend.
 *
 * This replaces the former dynamic netlogon parameters overlay.
 */

#include "includes.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_REGISTRY

extern REGISTRY_OPS regdb_ops;

static int netlogon_params_fetch_values(const char *key, REGVAL_CTR *regvals)
{
	uint32 dwValue;

	if (!pdb_get_account_policy(AP_REFUSE_MACHINE_PW_CHANGE, &dwValue)) {
		dwValue = 0;
	}

	regval_ctr_addvalue(regvals, "RefusePasswordChange", REG_DWORD,
			    (char*)&dwValue, sizeof(dwValue));

	return regval_ctr_numvals(regvals);
}

static int netlogon_params_fetch_subkeys(const char *key,
					 REGSUBKEY_CTR *subkey_ctr)
{
	return regdb_ops.fetch_subkeys(key, subkey_ctr);
}

REGISTRY_OPS netlogon_params_reg_ops = {
	.fetch_values = netlogon_params_fetch_values,
	.fetch_subkeys = netlogon_params_fetch_subkeys,
};
