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
#include "rpcclient.h"

/****************************************************************************
 This defines the commands supported by this client
 ****************************************************************************/
static const struct command_set reg_commands[] = 
{
	/*
	 * registry
	 */

	{
		"regenum",
		cmd_reg_enum,
		"<keyname> Registry Enumeration (keys, values)",
		{complete_regenum, NULL}
	},
	{
		"regdeletekey",
		cmd_reg_delete_key,
		"<keyname> Registry Key Delete",
		{complete_regenum, NULL}
	},
	{
		"regcreatekey",
		cmd_reg_create_key,
		"<keyname> [keyclass] Registry Key Create",
		{complete_regenum, NULL}
	},
	{
		"shutdown",
		cmd_reg_shutdown,
		"[-m message] [-t timeout] [-r or --reboot] [-f or --force-close] Remote Shutdown",
		{NULL, NULL}
	},
	{
		"regqueryval",
		cmd_reg_query_info,
		"<valname> Registry Value Query",
		{complete_regenum, NULL}
	},
	{
		"regquerykey",
		cmd_reg_query_key,
		"<keyname> Registry Key Query",
		{complete_regenum, NULL}
	},
	{
		"regdeleteval",
		cmd_reg_delete_val,
		"<valname> Registry Value Delete",
		{complete_regenum, complete_regenum}
	},
	{
		"regcreateval",
		cmd_reg_create_val,
		"<valname> <valtype> <value> Registry Key Create",
		{complete_regenum, NULL}
	},
	{
		"reggetsec",
		cmd_reg_get_key_sec,
		"<keyname> Registry Key Security",
		{complete_regenum, NULL}
	},
	{
		"regtestsec",
		cmd_reg_test_key_sec,
		"<keyname> Test Registry Key Security",
		{complete_regenum, NULL}
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

void add_reg_commands(void)
{
	add_command_set(reg_commands);
}
