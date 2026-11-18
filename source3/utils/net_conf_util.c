/*
 *  Samba Unix/Linux SMB client library
 *  Distributed SMB/CIFS Server Management Utility
 *  Configuration interface
 *
 *  Copyright (C) Michael Adam 2013
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
 * Utility functions for net conf and net rpc conf.
 */

#include "includes.h"
#include "lib/smbconf/smbconf.h"
#include "lib/smbconf/smbconf_reg.h"
#include "lib/param/loadparm.h"
#include "net_conf_util.h"

bool net_conf_param_valid(const char *service,
			  const char *param,
			  const char *valstr)
{
	const char *canon_param, *canon_valstr;

	if (!lp_parameter_is_valid(param)) {
		d_fprintf(stderr, "Invalid parameter '%s' given.\n", param);
		return false;
	}

	if (!smbconf_reg_parameter_is_settable(param)) {
		d_fprintf(stderr, "Parameter '%s' not allowed in registry.\n",
			  param);
		return false;
	}

	if (!strequal(service, GLOBAL_NAME) && lp_parameter_is_global(param)) {
		d_fprintf(stderr, "Global parameter '%s' not allowed in "
			  "service definition ('%s').\n", param, service);
		return false;
	}

	if (!lp_canonicalize_parameter_with_value(param, valstr,
						  &canon_param,
						  &canon_valstr))
	{
		/*
		 * We already know the parameter name is valid.
		 * So the value must be invalid.
		 */
		d_fprintf(stderr, "invalid value '%s' given for "
			  "parameter '%s'\n", valstr, param);
		return false;
	}

	return true;
}

/*
 * Configurations created by older versions may contain parameters,
 * which can't be set in the registry anymore, but are still
 * listed by 'net conf list'. Check them before an import changes
 * the registry, so that a failing import keeps the existing
 * configuration.
 */
bool net_conf_service_importable(const struct smbconf_service *service)
{
	bool ok = true;
	uint32_t i;

	for (i = 0; i < service->num_params; i++) {
		const char *param = service->param_names[i];

		if (!smbconf_reg_parameter_is_valid(param)) {
			/*
			 * e.g. 'include' is handled by the import itself
			 */
			continue;
		}

		if (smbconf_reg_parameter_is_settable(param)) {
			continue;
		}

		d_fprintf(stderr,
			  "Parameter '%s' not allowed in registry "
			  "(section '%s').\n",
			  param,
			  service->name != NULL ? service->name : GLOBAL_NAME);
		ok = false;
	}

	return ok;
}
