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
#include "rpc_parse.h"

extern struct client_info cli_info;

static char *complete_printersenum(char *text, int state)
{
	static uint32 i = 0;
	static uint32 num = 0;
	static PRINTER_INFO_1 **ctr = NULL;

	if (state == 0)
	{
		fstring srv_name;
		fstrcpy(srv_name, "\\\\");
		fstrcat(srv_name, cli_info.dest_host);
		strupper(srv_name);

		free_print1_array(num, ctr);
		ctr = NULL;
		num = 0;

		/* Iterate all users */
		if (!msrpc_spoolss_enum_printers(srv_name,
						 1, &num, (void ***)&ctr,
						 NULL))
		{
			return NULL;
		}

		i = 0;
	}

	for (; i < num; i++)
	{
		fstring name;
		unistr_to_ascii(name, ctr[i]->name.buffer, sizeof(name) - 1);

		if (text == NULL || text[0] == 0 ||
		    strnequal(text, name, strlen(text)))
		{
			char *copy = strdup(name);
			i++;
			return copy;
		}
	}

	return NULL;
}

/****************************************************************************
 This defines the commands supported by this client
 ****************************************************************************/
static const struct command_set spl_commands[] = {
	/*
	 * printer testing
	 */

	{
	 "spoolenum",
	 cmd_spoolss_enum_printers,
	 "Enumerate Printers",
	 {NULL, NULL}
	 },
	{
	 "spooljobs",
	 cmd_spoolss_enum_jobs,
	 "<printer name> Enumerate Printer Jobs",
	 {complete_printersenum, NULL}
	 },
	{
	 "spoolopen",
	 cmd_spoolss_open_printer_ex,
	 "<printer name> Spool Printer Open Test",
	 {complete_printersenum, NULL}
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

void add_spl_commands(void)
{
	add_command_set(spl_commands);
}
