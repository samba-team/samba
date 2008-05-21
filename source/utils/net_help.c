/*
   Samba Unix/Linux SMB client library
   net help commands
   Copyright (C) 2002 Jim McDonough (jmcd@us.ibm.com)

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
#include "utils/net.h"

static int net_help_usage(struct net_context *c, int argc, const char **argv)
{
	d_printf(
"\n"\
"Usage: net help <function>\n"\
"\n"\
"Valid functions are:\n"\
"  RPC RAP ADS FILE SHARE SESSION SERVER DOMAIN PRINTQ USER GROUP VALIDATE\n"\
"  GROUPMEMBER ADMIN SERVICE PASSWORD TIME LOOKUP GETLOCALSID SETLOCALSID\n"\
"  SETDOMAINSID CHANGESCRETPW LOOKUP SAM\n");
	return -1;
}

static int net_usage(struct net_context *c, int argc, const char **argv)
{
	d_printf("  net time\t\tto view or set time information\n"\
		 "  net lookup\t\tto lookup host name or ip address\n"\
		 "  net user\t\tto manage users\n"\
		 "  net group\t\tto manage groups\n"\
		 "  net sam\t\tto edit the local user database directly\n"\
		 "  net lookup\t\tto look up various things\n"\
		 "  net groupmap\t\tto manage group mappings\n"\
		 "  net join\t\tto join a domain\n"\
		 "  net cache\t\tto operate on cache tdb file\n"\
		 "  net getlocalsid [NAME]\tto get the SID for local name\n"\
		 "  net setlocalsid SID\tto set the local domain SID\n"\
		 "  net setdomainsid SID\tto set the domain SID on member servers\n"\
		 "  net changesecretpw\tto change the machine password in the local secrets database only\n"\
		 "                    \tthis requires the -f flag as a safety barrier\n"\
		 "  net status\t\tShow server status\n"\
		 "  net usersidlist\tto get a list of all users with their SIDs\n"
		 "  net usershare\t\tto add, delete and list locally user-modifiable shares\n"
		 "  net conf\t\tto view and edit samba's registry based configuration\n"
		 "\n"\
		 "  net ads <command>\tto run ADS commands\n"\
		 "  net rap <command>\tto run RAP (pre-RPC) commands\n"\
		 "  net rpc <command>\tto run RPC commands\n"\
		 "\n"\
		 "Type \"net help <option>\" to get more information on that option\n");
	net_common_flags_usage(c, argc, argv);
	return -1;
}

/*
  handle "net help *" subcommands
*/
int net_help(struct net_context *c, int argc, const char **argv)
{
	struct functable func[] = {
		{"ADS", net_ads_usage},
		{"RAP", net_rap_usage},
		{"RPC", net_rpc_usage},

		{"FILE", net_file_usage},
		{"SHARE", net_share_usage},
		{"SESSION", net_rap_session_usage},
		{"SERVER", net_rap_server_usage},
		{"DOMAIN", net_rap_domain_usage},
		{"PRINTQ", net_rap_printq_usage},
		{"USER", net_user_usage},
		{"GROUP", net_group_usage},
		{"GROUPMAP", net_groupmap_usage},
		{"JOIN", net_join_usage},
		{"DOM", net_dom_usage},
		{"VALIDATE", net_rap_validate_usage},
		{"GROUPMEMBER", net_rap_groupmember_usage},
		{"ADMIN", net_rap_admin_usage},
		{"SERVICE", net_rap_service_usage},
		{"PASSWORD", net_rap_password_usage},
		{"TIME", net_time_usage},
		{"LOOKUP", net_lookup_usage},
		{"USERSHARE", net_usershare_usage},
		{"USERSIDLIST", net_usersidlist_usage},
#ifdef WITH_FAKE_KASERVER
		{"AFS", net_afs_usage},
#endif

		{"HELP", net_help_usage},
		{NULL, NULL}};

	return net_run_function(c, argc, argv, func, net_usage);
}
