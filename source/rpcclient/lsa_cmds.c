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

extern int DEBUGLEVEL;

/****************************************************************************
 This defines the commands supported by this client
 ****************************************************************************/
struct command_set lsa_commands[] = 
{
	/*
	 * lsa
	 */

	{
		"lsaquery",
		cmd_lsa_query_info,
		"Query Info Policy (domain member or server)",
		{NULL, NULL}
	},
	{
		"lsaenumdomains",
		cmd_lsa_enum_trust_dom,
		"Enumerate Trusted Domains",
		{NULL, NULL}
	},
	{
		"lookupsids",
		cmd_lsa_lookup_sids,
		"Resolve names from SIDs",
		{NULL, NULL}
	},
	{
		"lookupnames",
		cmd_lsa_lookup_names,
		"Resolve SIDs from names",
		{NULL, NULL}
	},
	{
		"createsecret",
		cmd_lsa_create_secret,
		"LSA Create Secret (developer use)",
		{NULL, NULL}
	},
	{
		"setsecret",
		cmd_lsa_set_secret,
		"LSA Set Secret (developer use)",
		{NULL, NULL}
	},
	{
		"querysecret",
		cmd_lsa_query_secret,
		"LSA Query Secret (developer use)",
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
