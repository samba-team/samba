/* 
   Unix SMB/CIFS implementation.
   client error handling routines
   Copyright (C) Andrew Tridgell 1994-1998
   Copyright (C) James Myers 2003
   
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


/***************************************************************************
 Return an error message from the last response
****************************************************************************/
const char *cli_errstr(struct cli_tree *tree)
{   
	switch (tree->session->transport->error.etype) {
	case ETYPE_DOS:
		return dos_errstr(
			tree->session->transport->error.e.dos.eclass, 
			tree->session->transport->error.e.dos.ecode);
	case ETYPE_NT:
		return nt_errstr(tree->session->transport->error.e.nt_status);

	case ETYPE_SOCKET:
		return "socket_error";

	case ETYPE_NBT:
		return "nbt_error";

	case ETYPE_NONE:
		return "no_error";
	}
	return NULL;
}


/* Return the 32-bit NT status code from the last packet */
NTSTATUS cli_nt_error(struct cli_tree *tree)
{
	switch (tree->session->transport->error.etype) {
	case ETYPE_NT:
		return tree->session->transport->error.e.nt_status;

	case ETYPE_DOS:
		return dos_to_ntstatus(
			tree->session->transport->error.e.dos.eclass,
			tree->session->transport->error.e.dos.ecode);
	case ETYPE_SOCKET:
		return NT_STATUS_UNSUCCESSFUL;

	case ETYPE_NBT:
		return NT_STATUS_UNSUCCESSFUL;

	case ETYPE_NONE:
		return NT_STATUS_OK;
	}

	return NT_STATUS_UNSUCCESSFUL;
}


/* Return the DOS error from the last packet - an error class and an error
   code. */
void cli_dos_error(struct cli_state *cli, uint8 *eclass, uint32_t *ecode)
{
	if (cli->transport->error.etype == ETYPE_DOS) {
		ntstatus_to_dos(cli->transport->error.e.nt_status, 
				eclass, ecode);
		return;
	}

	if (eclass) *eclass = cli->transport->error.e.dos.eclass;
	if (ecode)  *ecode  = cli->transport->error.e.dos.ecode;
}


/* Return true if the last packet was an error */
BOOL cli_is_error(struct cli_tree *tree)
{
	return NT_STATUS_IS_ERR(cli_nt_error(tree));
}

/* Return true if the last error was a DOS error */
BOOL cli_is_dos_error(struct cli_tree *tree)
{
	return tree->session->transport->error.etype == ETYPE_DOS;
}
