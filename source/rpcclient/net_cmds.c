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
static const struct command_set net_commands[] = 
{
	/*
	 * server
	 */
	{
		"time",
		cmd_time,
		"Display remote time",
		{NULL, NULL}
	},
	{
		"brsinfo",
		cmd_brs_query_info,
		"Browser Query Info",
		{NULL, NULL}
	},
	{
		"wksinfo",
		cmd_wks_query_info,
		"Workstation Query Info",
		{NULL, NULL}
	},
	{
		"srvinfo",
		cmd_srv_query_info,
		"Server Query Info",
		{NULL, NULL}
	},
	{
		"srvsessions",
		cmd_srv_enum_sess,
		"List sessions on a server",
		{NULL, NULL}
	},
	{
		"srvshares",
		cmd_srv_enum_shares,
		"List shares on a server",
		{NULL, NULL}
	},
	{
		"srvshareinfo",
		cmd_srv_share_get_info,
		"SHARE [1|2|502]\tGet info for share",
		{NULL, NULL}
	},
	{
		"srvsharedel",
		cmd_srv_share_del,
		"SHARE\tDel share on server",
		{NULL, NULL}
	},
	{
		"srvtransports",
		cmd_srv_enum_tprt,
		"List transports on a server",
		{NULL, NULL}
	},
	{
		"srvconnections",
		cmd_srv_enum_conn,
		"List connections on a server",
		{NULL, NULL}
	},
	{
		"srvfiles",
		cmd_srv_enum_files,
		"List files on a server",
		{NULL, NULL}
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

void add_net_commands(void)
{
	add_command_set(net_commands);
}
