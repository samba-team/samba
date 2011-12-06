/*
   Unix SMB/Netbios implementation.
   Generic infrstructure for RPC Daemons
   Copyright (C) Simo Sorce 2011
   Copyright (C) Andreas Schneider 2011

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
#include "rpc_server/rpc_config.h"

/* the default is "embedded" so this table
 * lists only services that are not using
 * the default in order to keep enumerating it
 * in rpc_service_mode() as short as possible
 */
struct rpc_service_defaults {
	const char *name;
	const char *def_mode;
} rpc_service_defaults[] = {
	{ "epmapper", "disabled" },
	/* { "spoolss", "embedded" }, */
	/* { "lsarpc", "embedded" }, */
	/* { "samr", "embedded" }, */
	/* { "netlogon", "embedded" }, */

	{ NULL, NULL }
};

enum rpc_service_mode_e rpc_service_mode(const char *name)
{
	const char *pipe_name = name;
	const char *rpcsrv_type;
	enum rpc_service_mode_e state;
	const char *def;
	int i;

	/* Handle pipes with multiple names */
	if (strcmp(pipe_name, "lsass") == 0) {
		pipe_name = "lsarpc";
	} else if (strcmp(pipe_name, "plugplay") == 0) {
		pipe_name = "ntsvcs";
	}

	def = lp_parm_const_string(GLOBAL_SECTION_SNUM,
				   "rpc_server", "default", NULL);
	if (def == NULL) {
		for (i = 0; rpc_service_defaults[i].name; i++) {
			if (strcasecmp_m(pipe_name, rpc_service_defaults[i].name) == 0) {
				def = rpc_service_defaults[i].def_mode;
				break;
			}
		}
		/* if the default is unspecified then use 'embedded' */
		if (def == NULL) {
			def = "embedded";
		}
	}

	rpcsrv_type = lp_parm_const_string(GLOBAL_SECTION_SNUM,
					   "rpc_server", pipe_name, def);

	if (strcasecmp_m(rpcsrv_type, "embedded") == 0) {
		state = RPC_SERVICE_MODE_EMBEDDED;
	} else if (strcasecmp_m(rpcsrv_type, "external") == 0) {
		state = RPC_SERVICE_MODE_EXTERNAL;
	} else {
		state = RPC_SERVICE_MODE_DISABLED;
	}

	return state;
}


/* the default is "embedded" so this table
 * lists only daemons that are not using
 * the default in order to keep enumerating it
 * in rpc_daemon_type() as short as possible
 */
struct rpc_daemon_defaults {
	const char *name;
	const char *def_type;
} rpc_daemon_defaults[] = {
	{ "epmd", "disabled" },
	/* { "spoolssd", "embedded" }, */
	/* { "lsasd", "embedded" }, */

	{ NULL, NULL }
};

enum rpc_daemon_type_e rpc_daemon_type(const char *name)
{
	const char *rpcsrv_type;
	enum rpc_daemon_type_e type;
	const char *def;
	int i;

	def = "embedded";
	for (i = 0; rpc_daemon_defaults[i].name; i++) {
		if (strcasecmp_m(name, rpc_daemon_defaults[i].name) == 0) {
			def = rpc_daemon_defaults[i].def_type;
		}
	}

	rpcsrv_type = lp_parm_const_string(GLOBAL_SECTION_SNUM,
					   "rpc_daemon", name, def);

	if (strcasecmp_m(rpcsrv_type, "embedded") == 0) {
		type = RPC_DAEMON_EMBEDDED;
	} else if (strcasecmp_m(rpcsrv_type, "fork") == 0) {
		type = RPC_DAEMON_FORK;
	} else {
		type = RPC_DAEMON_DISABLED;
	}

	return type;
}
