/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   NT Domain Authentication SMB / MSRPC client
   Copyright (C) Andrew Tridgell 1994-1999
   Copyright (C) Luke Kenneth Casson Leighton 1996-1999
   
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


#ifdef SYSLOG
#undef SYSLOG
#endif

#include "includes.h"
#include "nterr.h"

extern int DEBUGLEVEL;

#define DEBUG_TESTING

extern FILE* out_hnd;

extern struct cli_state *smb_cli;
extern int smb_tidx;

/****************************************************************************
nt spoolss query
****************************************************************************/
void cmd_spoolss_enum_printers(struct client_info *info)
{
	uint16 nt_pipe_fnum;
	fstring srv_name;
	void **printers = NULL;
	uint32 count = 0;

	BOOL res = True;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, smb_cli->desthost);
	strupper(srv_name);

	DEBUG(5, ("cmd_spoolss_open_printer_ex: smb_cli->fd:%d\n", smb_cli->fd));

	/* open SPOOLSS session. */
	res = res ? cli_nt_session_open(smb_cli, PIPE_SPOOLSS, &nt_pipe_fnum) : False;

	res = res ? spoolss_enum_printers(smb_cli, nt_pipe_fnum, 
	                        0x40, srv_name, 1, &count, &printers) : False;

	/* close the session */
	cli_nt_session_close(smb_cli, nt_pipe_fnum);

	if (res)
	{
		DEBUG(5,("cmd_spoolss_enum_printer: query succeeded\n"));
		report(out_hnd, "OK\n");
	}
	else
	{
		DEBUG(5,("cmd_spoolss_enum_printer: query failed\n"));
	}

	free_void_array(count, printers, free);
}

/****************************************************************************
nt spoolss query
****************************************************************************/
void cmd_spoolss_open_printer_ex(struct client_info *info)
{
	uint16 nt_pipe_fnum;
	fstring srv_name;
	fstring printer_name;
	PRINTER_HND hnd;

	BOOL res = True;

	if (!next_token(NULL, printer_name, NULL, sizeof(printer_name)))
	{
		report(out_hnd, "spoolopen <printer name>\n");
		return;
	}

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->myhostname);
	strupper(srv_name);

	DEBUG(4,("spoolopen - printer: %s server: %s user: %s\n",
		printer_name, srv_name, smb_cli->user_name));

	DEBUG(5, ("cmd_spoolss_open_printer_ex: smb_cli->fd:%d\n", smb_cli->fd));

	/* open SPOOLSS session. */
	res = res ? cli_nt_session_open(smb_cli, PIPE_SPOOLSS, &nt_pipe_fnum) : False;

	res = res ? spoolss_open_printer_ex(smb_cli, nt_pipe_fnum, 
	                        printer_name,
	                        0, 0, 0,
	                        srv_name, smb_cli->user_name,
	                        &hnd) : False;

	res = res ? spoolss_closeprinter(smb_cli, nt_pipe_fnum, &hnd) : False;

	/* close the session */
	cli_nt_session_close(smb_cli, nt_pipe_fnum);

	if (res)
	{
		DEBUG(5,("cmd_spoolss_open_printer_ex: query succeeded\n"));
		report(out_hnd, "OK\n");
	}
	else
	{
		DEBUG(5,("cmd_spoolss_open_printer_ex: query failed\n"));
	}
}

