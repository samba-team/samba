/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   NT Domain Authentication SMB / MSRPC client
   Copyright (C) Andrew Tridgell              1994-2000
   Copyright (C) Luke Kenneth Casson Leighton 1996-2000
   Copyright (C) Jean-Francois Micouleau      1999-2000
   
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
#include "nterr.h"
#include "rpc_parse.h"
#include "rpc_client.h"
#include "rpcclient.h"

extern int DEBUGLEVEL;

#define DEBUG_TESTING

extern FILE* out_hnd;

extern struct user_creds *usr_creds;

/****************************************************************************
nt spoolss query
****************************************************************************/
uint32 cmd_spoolss_enum_printers(struct client_info *info, int argc, char *argv[])
{
	PRINTER_INFO_CTR ctr;
	
	uint32 flags;
	uint32 level = 1;

	fstring srv_name;
	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);
	
	flags=PRINTER_ENUM_LOCAL;

	if (msrpc_spoolss_enum_printers(srv_name, flags, level, ctr))
		DEBUG(5,("cmd_spoolss_enum_printer: query succeeded\n"));
	else
		report(out_hnd, "FAILED\n");
		
	flags=PRINTER_ENUM_NAME;

	if (msrpc_spoolss_enum_printers(srv_name, flags, level, ctr))
		DEBUG(5,("cmd_spoolss_enum_printer: query succeeded\n"));
	else
		report(out_hnd, "FAILED\n");

	flags=PRINTER_ENUM_SHARED|PRINTER_ENUM_NAME;

	if (msrpc_spoolss_enum_printers(srv_name, flags, level, ctr))
		DEBUG(5,("cmd_spoolss_enum_printer: query succeeded\n"));
	else
		report(out_hnd, "FAILED\n");
		
	flags=PRINTER_ENUM_CONNECTIONS;

	if (msrpc_spoolss_enum_printers(srv_name, flags, level, ctr))
		DEBUG(5,("cmd_spoolss_enum_printer: query succeeded\n"));
	else
		report(out_hnd, "FAILED\n");
		
	flags=PRINTER_ENUM_NETWORK;

	if (msrpc_spoolss_enum_printers(srv_name, flags, level, ctr))
		DEBUG(5,("cmd_spoolss_enum_printer: query succeeded\n"));
	else
		report(out_hnd, "FAILED\n");
		
	flags=PRINTER_ENUM_REMOTE;

	if (msrpc_spoolss_enum_printers(srv_name, flags, level, ctr))
		DEBUG(5,("cmd_spoolss_enum_printer: query succeeded\n"));
	else
		report(out_hnd, "FAILED\n");
		
	return NT_STATUS_NOPROBLEMO;
}
