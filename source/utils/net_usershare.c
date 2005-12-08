/* 
   Samba Unix/Linux SMB client library 
   Distributed SMB/CIFS Server Management Utility 

   Copyright (C) Jeremy Allison (jra@samba.org) 2005

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
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.  */

#include "includes.h"
#include "utils/net.h"

static int net_usershare_add(int argc, const char **argv)
{
	return -1;
}

static int net_usershare_delete(int argc, const char **argv)
{
	return -1;
}

static int net_usershare_info(int argc, const char **argv)
{
	return -1;
}

static int net_usershare_list(int argc, const char **argv)
{
	return -1;
}

static int net_usershare_listall(int argc, const char **argv)
{
	return -1;
}

/* The help subsystem for the USERSHARE subcommand */

static int net_usershare_add_usage(int argc, const char **argv)
{
	d_printf(
		"net usershare add <sharename> <path> [<comment>] [<acl>]\n"
		"\tAdds the specified share name for this user.\n"
		"\t<sharename> is the new share name.\n"
		"\t<path> is the path on the filesystem to export.\n"
		"\t<comment> is the (optional) comment for the new share.\n"
		"\t<acl> is a share acl in the format \"Username1:f|r|d,username2:f|r|d,....\"\n"
		"\t\twhere \"f\" means full control, \"r\" means read-only, \"d\" means deny access.\n"
		"\t\tThe default acl is \"Everyone:r\" which means everyone read-only.\n");
	return -1;
}

static int net_usershare_delete_usage(int argc, const char **argv)
{
	d_printf(
		"net usershare delete <sharename>\n"\
		"\tdeletes the specified share name for this user.\n");
	return -1;
}

static int net_usershare_info_usage(int argc, const char **argv)
{
	d_printf(
		"net usershare info <sharename>\n"\
		"\tPrints out the path, comment and acl elements of this share.\n");
	return -1;
}

static int net_usershare_list_usage(int argc, const char **argv)
{
	d_printf(
		"net usershare list\n"\
		"\tLists the names of all shares created by the current user.\n");
	return -1;
}

static int net_usershare_listall_usage(int argc, const char **argv)
{
	d_printf(
		"net usershare listall\n"\
		"\tLists the names of all user-modifiable shares created by any user on the system.\n");
	return -1;
}


int net_usershare_usage(int argc, const char **argv)
{
	d_printf("net usershare add <sharename> <path> [<comment>] [<acl>] to add a user defined share.\n"
		"net usershare delete <sharename> to delete a user defined share.\n"
		"net usershare info <sharename> to print info about a user defined share.\n"
		"net usershare list to list all the user defined shares for this user.\n"
		"net usershare listall to list the user defined shares for all users.\n"
		"net usershare help\n"\
		"\nType \"net help <option>\" to get more information on that option\n\n");

	net_common_flags_usage(argc, argv);
	return -1;
}

/*
  handle "net usershare help *" subcommands
*/
int net_usershare_help(int argc, const char **argv)
{
	struct functable func[] = {
		{"ADD", net_usershare_add_usage},
		{"DELETE", net_usershare_delete_usage},
		{"INFO", net_usershare_info_usage},
		{"LIST", net_usershare_list_usage},
		{"LISTALL", net_usershare_listall_usage},
		{NULL, NULL}};

	return net_run_function(argc, argv, func, net_usershare_usage);
}

/* Entry-point for all the USERSHARE functions. */

int net_usershare(int argc, const char **argv)
{
	struct functable func[] = {
		{"ADD", net_usershare_add},
		{"DELETE", net_usershare_delete},
		{"INFO", net_usershare_info},
		{"LIST", net_usershare_list},
		{"LISTALL", net_usershare_listall},
		{"HELP", net_usershare_help},
		{NULL, NULL}
	};
	
	return net_run_function(argc, argv, func, net_usershare_usage);
}
