/* 
   Unix SMB/CIFS implementation.
   client message handling routines
   Copyright (C) Andrew Tridgell 1994-1998
   Copyright (C) James J Myers 2003  <myersjj@samba.org>
   
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


/****************************************************************************
start a message sequence
****************************************************************************/
BOOL cli_message_start(struct cli_tree *tree, char *host, char *username, 
		       int *grp)
{
	struct cli_request *req; 
	
	req = cli_request_setup(tree, SMBsendstrt, 0, 0);
	cli_req_append_string(req, username, STR_TERMINATE);
	cli_req_append_string(req, host, STR_TERMINATE);
	if (!cli_request_send(req) || 
	    !cli_request_receive(req) ||
	    cli_is_error(tree)) {
		cli_request_destroy(req);
		return False;
	}

	*grp = SVAL(req->in.vwv, VWV(0));
	cli_request_destroy(req);

	return True;
}


/****************************************************************************
send a message 
****************************************************************************/
BOOL cli_message_text(struct cli_tree *tree, char *msg, int len, int grp)
{
	struct cli_request *req; 
	
	req = cli_request_setup(tree, SMBsendtxt, 1, 0);
	SSVAL(req->out.vwv, VWV(0), grp);

	cli_req_append_bytes(req, msg, len);

	if (!cli_request_send(req) || 
	    !cli_request_receive(req) ||
	    cli_is_error(tree)) {
		cli_request_destroy(req);
		return False;
	}

	cli_request_destroy(req);
	return True;
}      

/****************************************************************************
end a message 
****************************************************************************/
BOOL cli_message_end(struct cli_tree *tree, int grp)
{
	struct cli_request *req; 
	
	req = cli_request_setup(tree, SMBsendend, 1, 0);
	SSVAL(req->out.vwv, VWV(0), grp);

	if (!cli_request_send(req) || 
	    !cli_request_receive(req) ||
	    cli_is_error(tree)) {
		cli_request_destroy(req);
		return False;
	}

	cli_request_destroy(req);
	return True;
}      

