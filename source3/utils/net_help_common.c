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

int net_common_methods_usage(struct net_context *c, int argc, const char**argv)
{
	d_printf(_("Valid methods: (auto-detected if not specified)\n"));
	d_printf(_("\tads\t\t\t\tActive Directory (LDAP/Kerberos)\n"));
	d_printf(_("\trpc\t\t\t\tDCE-RPC\n"));
	d_printf(_("\trap\t\t\t\tRAP (older systems)\n"));
	d_printf("\n");
	return 0;
}

int net_common_flags_usage(struct net_context *c, int argc, const char **argv)
{
	d_printf(_("Valid targets: choose one (none defaults to localhost)\n"));
	d_printf(_("\t-S|--server=<server>\t\t\tserver name\n"));
	d_printf(_("\t-I|--ipaddress=<ipaddr>\t\t\taddress of target server\n"));
	d_printf(_("\t-w|--target-workgroup=<wg>\t\ttarget workgroup or domain\n"));

	d_printf("\n");
	d_printf(_("Valid misc options are:\n")); /* misc options */
	d_printf(_("\t-p|--port=<port>\t\t\tconnection port on target\n"));
	d_printf(_("\t--myname=<name>\t\t\t\tclient name\n"));
	d_printf(_("\t--long\t\t\t\t\tDisplay full information\n"));

	d_printf("\n");
	d_printf(_("Valid common options are:\n")); /* misc options */
	d_printf(_("\t-d|--debuglevel=<level>\t\t\tdebug level (0-10)\n"));
	d_printf(_("\t--debug-stdout\t\t\t\tSend debug output to standard "
		   "output\n"));
	d_printf(_("\t--configfile=<path>\t\t\tpathname of smb.conf file\n"));
	d_printf(_("\t--option=name=value\t\t\tSet smb.conf option from "
		   "command line\n"));
	d_printf(_("\t-l|--log-basename=LOGFILEBASE\t\tBasename for "
		   "log/debug files\n"));
	d_printf(_("\t--leak-report\t\t\t\tenable talloc leak reporting on "
		   "exit\n"));
	d_printf(_("\t--leak-report-full\t\t\tenable full talloc leak "
		   "reporting on exit\n"));
	d_printf(_("\t-V|--version\t\t\t\tPrint samba version information\n"));

	d_printf("\n");
	d_printf(_("Valid connection options are:\n")); /* misc options */
	d_printf(_("\t-R|--name-resolve=NAME-RESOLVE-ORDER\tUse these name "
		   "resolution services only\n"));
	d_printf(_("\t-O|--socket-options=SOCKETOPTIONS\tsocket options to use\n"));
	d_printf(_("\t-m|--max-protocol=MAXPROTOCOL\t\tSet max protocol level\n"));
	d_printf(_("\t-n|--netbiosname=NETBIOSNAME\t\tPrimary netbios name\n"));
	d_printf(_("\t--netbios-scope=SCOPE\t\t\tUse this Netbios scope\n"));
	d_printf(_("\t-W|--workgroup=WORKGROUP\t\tSet the workgroup name\n"));
	d_printf(_("\t--realm=REALM\t\t\t\tSet the realm name\n"));

	d_printf("\n");
	d_printf(_("Valid credential options are:\n")); /* misc options */
	d_printf(_("\t-U|--user=[DOMAIN/]USERNAME[%%PASSWORD]\tSet the "
		   "network username\n"));
	d_printf(_("\t-N|--no-pass\t\t\t\tDon't ask for a password\n"));
	d_printf(_("\t--password=STRING\t\t\tSet a password\n"));
	d_printf(_("\t--pw-nt-hash\t\t\t\tThe supplied password is the NT hash\n"));
	d_printf(_("\t-A|--authentication-file=FILE\t\tGet the "
		   "credentials from a file\n"));
	d_printf(_("\t-P|--machine-pass\t\t\tUse stored machine account password\n"));
	d_printf(_("\t--simple-bind-dn=DN\t\t\tDN to use for a simple bind\n"));
	d_printf(_("\t--use-kerberos=desired|required|off\tUse kerberos "
		   "authentication\n"));
	d_printf(_("\t--use-krb5-ccache=CCACHE\t\tCredentials cache location "
		   "for Kerberos\n"));
	d_printf(_("\t--use-winbind-ccache\t\t\tUse the winbind ccache for "
		   "authentication\n"));
	d_printf(_("\t--client-protection=sign|encrypt|off\tConfigure used "
		   "protection for client connections\n"));

	return -1;
}

