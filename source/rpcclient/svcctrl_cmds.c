/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   SMB client
   Copyright (C) Andrew Tridgell              1994-2000
   Copyright (C) Luke Kenneth Casson Leighton 1996-2000
   
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
#include "ntdomain.h"
#include "rpcclient.h"

/****************************************************************************
 This defines the commands supported by this client
 ****************************************************************************/
static const struct command_set svc_commands[] = 
{
	/*
	 * service control
	 */

	{
		"svcenum",
		cmd_svc_enum,
		"[-i] Lists Services Manager",
		{NULL, NULL}
	},

	{
		"svcinfo",
		cmd_svc_info,
		"<service> Service Information",
		{complete_svcenum, NULL}
	},

	{
		"svcstart",
		cmd_svc_start,
		"<service> [arg 0] [arg 1] ... Start Service",
		{complete_svcenum, NULL}
	},

	{
		"svcset",
		cmd_svc_set,
		"<service> Test Set Service",
		{complete_svcenum, NULL}
	},

	{
		"svcstop",
		cmd_svc_stop,
		"<service> Stop Service",
		{complete_svcenum, NULL}
	},

	/*
	 * oop!
	 */

	{
		"",
		NULL,
		NULL,
		{NULL, NULL}
	}
};

void add_svc_commands(void)
{
	add_command_set(svc_commands);
}
