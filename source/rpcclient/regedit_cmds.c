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

extern struct client_info cli_info;

/* Complete a remote registry enum */

static uint32 reg_list_len = 0;
static char **reg_name = NULL;

static void reg_init(int val, const char *full_keyname, int num)
{
	switch (val)
	{
		case 0:
		{
			free_char_array(reg_list_len, reg_name);
			reg_list_len = 0;
			reg_name = NULL;
			break;
		}
		default:
		{
			break;
		}
	}
}

static void reg_key_list(const char *full_name,
			 const char *name, time_t key_mod_time)
{
	fstring key_name;
	slprintf(key_name, sizeof(key_name) - 1, "%s\\", name);
	add_chars_to_array(&reg_list_len, &reg_name, key_name);
}

static void reg_val_list(const char *full_name,
			 const char *name, uint32 type, const BUFFER2 * value)
{
	add_chars_to_array(&reg_list_len, &reg_name, name);
}

extern char** cmd_argv;
extern uint32 cmd_argc;

static char *complete_regenum(char *text, int state)
{
	pstring full_keyname;
	static uint32 i = 0;

	if (state == 0)
	{
		fstring srv_name;
		fstrcpy(srv_name, "\\\\");
		fstrcat(srv_name, cli_info.dest_host);
		strupper(srv_name);

		if (cmd_argc >= 2 && cmd_argv != NULL && cmd_argv[1] != NULL)
		{
			char *sep;
			split_server_keyname(srv_name, full_keyname,
					     cmd_argv[1]);

			sep = strrchr(full_keyname, '\\');
			if (sep != NULL)
			{
				*sep = 0;
			}
		}

		/* Iterate all keys / values */
		if (!msrpc_reg_enum_key(srv_name, full_keyname,
					reg_init, reg_key_list, reg_val_list))
		{
			return NULL;
		}

		i = 0;
	}

	for (; i < reg_list_len; i++)
	{
		if (text == NULL || text[0] == 0 ||
		    strnequal(text, reg_name[i], strlen(text)))
		{
			char *name = strdup(reg_name[i]);
			i++;
			return name;
		}
	}

	return NULL;
}
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
		"abortshutdown",
		cmd_reg_abort_shutdown,
		"Abort Shutdown",
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
