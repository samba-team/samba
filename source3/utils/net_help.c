/* 
   Samba Unix/Linux SMB client library 
   net help commands
   Copyright (C) 2002 Jim McDonough (jmcd@us.ibm.com)

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.  
*/

#include "includes.h"
#include "../utils/net.h"

int net_common_methods_usage(int argc, const char**argv)
{
	d_printf("Valid methods: (auto-detected if not specified)\n");
	d_printf("\tads\t\t\t\tActive Directory (LDAP/Kerberos)\n");
	d_printf("\trpc\t\t\t\tDCE-RPC\n");
	d_printf("\trap\t\t\t\tRAP (older systems)\n");
	d_printf("\n");
	return 0;
}

int net_common_flags_usage(int argc, const char **argv)
{
	d_printf("Valid targets: choose one (none defaults to localhost)\n");
	d_printf("\t-S or --server=<server>\t\tserver name\n");
	d_printf("\t-I or --ipaddress=<ipaddr>\taddress of target server\n");
	d_printf("\t-w or --workgroup=<wg>\t\ttarget workgroup or domain\n");

	d_printf("\n");
	d_printf("Valid miscellaneous options are:\n"); /* misc options */
	d_printf("\t-p or --port=<port>\t\tconnection port on target\n");
	d_printf("\t-W or --myworkgroup=<wg>\tclient workgroup\n");
	d_printf("\t-d or --debug=<level>\t\tdebug level (0-10)\n");
	d_printf("\t-n or --myname=<name>\t\tclient name\n");
	d_printf("\t-U or --user=<name>\t\tuser name\n");
	d_printf("\t-s or --conf=<path>\t\tpathname of smb.conf file\n");
	d_printf("\t-l or --long\t\t\tDisplay full information\n");
	return -1;
}

static int help_usage(int argc, const char **argv)
{
	d_printf(
"\n"\
"Usage: net help <function>\n"\
"\n"\
"Valid functions are:\n"\
"  RPC RAP ADS FILE SHARE SESSION SERVER DOMAIN PRINTQ USER GROUP VALIDATE\n"\
"  GROUPMEMBER ADMIN SERVICE PASSWORD TIME LOOKUP GETLOCALSID SETLOCALSID\n");
	return -1;
}

int net_help_user(int argc, const char **argv)
{
	d_printf("\nnet [<method>] user [misc. options] [targets]"\
		 "\n\tList users\n\n");
	d_printf("net [<method>] user DELETE <name> [misc. options] [targets]"\
		 "\n\tDelete specified user\n");
	d_printf("\nnet [<method>] user INFO <name> [misc. options] [targets]"\
		 "\n\tList the domain groups of the specified user\n");
	d_printf("\nnet [<method>] user ADD <name> [password] [-c container] "\
		 "[-F user flags] [misc. options]"\
		 " [targets]\n\tAdd specified user\n");

	net_common_methods_usage(argc, argv);
	net_common_flags_usage(argc, argv);
	d_printf("\t-C or --comment=<comment>\tdescriptive comment (for add only)\n");
	d_printf("\t-c or --container=<container>\tLDAP container, defaults to cn=Users (for add in ADS only)\n");
	return -1;
}

int net_help_group(int argc, const char **argv)
{
	d_printf("net [<method>] group [misc. options] [targets]"\
		 "\n\tList user groups\n\n");
	d_printf("net [<method>] group DELETE <name> "\
		 "[misc. options] [targets]"\
		 "\n\tDelete specified group\n");
	d_printf("\nnet [<method>] group ADD <name> [-C comment] [-c container]"\
		 " [misc. options] [targets]\n\tCreate specified group\n");
	net_common_methods_usage(argc, argv);
	net_common_flags_usage(argc, argv);
	d_printf("\t-C or --comment=<comment>\tdescriptive comment (for add only)\n");
	d_printf("\t-c or --container=<container>\tLDAP container, defaults to cn=Users (for add in ADS only)\n");
	return -1;
}


int net_help_join(int argc, const char **argv)
{
	d_printf("\nnet [<method>] join [misc. options]\n"
		 "\tjoins this server to a domain\n");
	d_printf("Valid methods: (auto-detected if not specified)\n");
	d_printf("\tads\t\t\t\tActive Directory (LDAP/Kerberos)\n");
	d_printf("\trpc\t\t\t\tDCE-RPC\n");
	net_common_flags_usage(argc, argv);
	return -1;
}

int net_help_share(int argc, const char **argv)
{
	d_printf(
	 "\nnet [<method>] share [misc. options] [targets] \n"
	 "\tenumerates all exported resources (network shares) "
	 "on target server\n\n"
	 "net [<method>] share ADD <name=serverpath> [misc. options] [targets]"
	 "\n\tAdds a share from a server (makes the export active)\n\n"
	 "net [<method>] share DELETE <sharename> [misc. options] [targets]\n"
	 "\n\tDeletes a share from a server (makes the export inactive)\n");
	net_common_methods_usage(argc, argv);
	net_common_flags_usage(argc, argv);
	d_printf(
	 "\t-C or --comment=<comment>\tdescriptive comment (for add only)\n"
	 "\t-M or --maxusers=<num>\t\tmax users allowed for share\n");
	return -1;
}

int net_help_file(int argc, const char **argv)
{
	d_printf("net [<method>] file [misc. options] [targets]\n"\
		 "\tlists all open files on file server\n\n");
	d_printf("net [<method>] file USER <username> "\
		 "[misc. options] [targets]"\
		 "\n\tlists all files opened by username on file server\n\n");
	d_printf("net [<method>] file CLOSE <id> [misc. options] [targets]\n"\
		 "\tcloses specified file on target server\n\n");
	d_printf("net [rap] file INFO <id> [misc. options] [targets]\n"\
		 "\tdisplays information about the specified open file\n");

	net_common_methods_usage(argc, argv);
	net_common_flags_usage(argc, argv);
	return -1;
}

static int net_usage(int argc, const char **argv)
{
	d_printf("  net time\t\tto view or set time information\n"\
		 "  net lookup\t\tto lookup host name or ip address\n"\
		 "  net user\t\tto manage users\n"\
		 "  net group\t\tto manage groups\n"\
		 "  net join\t\tto join a domain\n"\
		 "  net cache\t\tto operate on cache tdb file\n"\
		 "  net getlocalsid [NAME]\tto get the SID for local name\n"\
		 "  net setlocalsid SID\tto set the local domain SID\n"\
		 "\n"\
		 "  net ads <command>\tto run ADS commands\n"\
		 "  net rap <command>\tto run RAP (pre-RPC) commands\n"\
		 "  net rpc <command>\tto run RPC commands\n"\
		 "\n"\
		 "Type \"net help <option>\" to get more information on that option\n");
	return -1;
}

/*
  handle "net help *" subcommands
*/
int net_help(int argc, const char **argv)
{
	struct functable func[] = {
		{"ADS", net_ads_help},	
		{"RAP", net_rap_help},
		{"RPC", net_rpc_help},

		{"FILE", net_help_file},
		{"SHARE", net_help_share},
		{"SESSION", net_rap_session_usage},
		{"SERVER", net_rap_server_usage},
		{"DOMAIN", net_rap_domain_usage},
		{"PRINTQ", net_rap_printq_usage},
		{"USER", net_help_user},
		{"GROUP", net_help_group},
		{"JOIN", net_help_join},
		{"VALIDATE", net_rap_validate_usage},
		{"GROUPMEMBER", net_rap_groupmember_usage},
		{"ADMIN", net_rap_admin_usage},
		{"SERVICE", net_rap_service_usage},
		{"PASSWORD", net_rap_password_usage},
		{"TIME", net_time_usage},
		{"LOOKUP", net_lookup_usage},

		{"HELP", help_usage},
		{NULL, NULL}};

	return net_run_function(argc, argv, func, net_usage);
}
