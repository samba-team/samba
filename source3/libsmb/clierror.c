/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   client error handling routines
   Copyright (C) Andrew Tridgell 1994-1998
   
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

#define NO_SYSLOG

#include "includes.h"


extern int DEBUGLEVEL;


/*****************************************************
 RAP error codes - a small start but will be extended.
*******************************************************/

static struct
{
  int err;
  char *message;
} rap_errmap[] =
{
  {5,    "User has insufficient privilege" },
  {86,   "The specified password is invalid" },
  {2226, "Operation only permitted on a Primary Domain Controller"  },
  {2242, "The password of this user has expired." },
  {2243, "The password of this user cannot change." },
  {2244, "This password cannot be used now (password history conflict)." },
  {2245, "The password is shorter than required." },
  {2246, "The password of this user is too recent to change."},

  /* these really shouldn't be here ... */
  {0x80, "Not listening on called name"},
  {0x81, "Not listening for calling name"},
  {0x82, "Called name not present"},
  {0x83, "Called name present, but insufficient resources"},

  {0, NULL}
};  

/****************************************************************************
  return a description of an SMB error
****************************************************************************/
static char *cli_smb_errstr(struct cli_state *cli)
{
	return smb_errstr(cli->inbuf);
}

/******************************************************
 Return an error message - either an SMB error or a RAP
 error.
*******************************************************/
    
char *cli_errstr(struct cli_state *cli)
{   
	static fstring error_message;
	uint8 errclass;
	uint32 errnum;
	uint32 nt_rpc_error;
	int i;      

	/*  
	 * Errors are of three kinds - smb errors,
	 * dealt with by cli_smb_errstr, NT errors,
	 * whose code is in cli.nt_error, and rap
	 * errors, whose error code is in cli.rap_error.
	 */ 

	cli_error(cli, &errclass, &errnum, &nt_rpc_error);

	if (errclass != 0)
	{
		return cli_smb_errstr(cli);
	}

	/*
	 * Was it an NT error ?
	 */

	if (nt_rpc_error)
	{
		char *nt_msg = get_nt_error_msg(nt_rpc_error);

		if (nt_msg == NULL)
		{
			slprintf(error_message, sizeof(fstring) - 1, "NT code %d", nt_rpc_error);
		}
		else
		{
			fstrcpy(error_message, nt_msg);
		}

		return error_message;
	}

	/*
	 * Must have been a rap error.
	 */

	slprintf(error_message, sizeof(error_message) - 1, "code %d", cli->rap_error);

	for (i = 0; rap_errmap[i].message != NULL; i++)
	{
		if (rap_errmap[i].err == cli->rap_error)
		{
			fstrcpy( error_message, rap_errmap[i].message);
			break;
		}
	} 

	return error_message;
}


/****************************************************************************
  return error codes for the last packet
  returns 0 if there was no error and the best approx of a unix errno
  otherwise

  for 32 bit "warnings", a return code of 0 is expected.

****************************************************************************/
int cli_error(struct cli_state *cli, uint8 *eclass, uint32 *num, uint32 *nt_rpc_error)
{
	int  flgs2;
	char rcls;
	int code;

	if (eclass) *eclass = 0;
	if (num   ) *num = 0;
	if (nt_rpc_error) *nt_rpc_error = 0;

	if(!cli->initialised)
		return EINVAL;

	if(!cli->inbuf)
		return ENOMEM;

	flgs2 = SVAL(cli->inbuf,smb_flg2);
	if (nt_rpc_error) *nt_rpc_error = cli->nt_error;

	if (flgs2 & FLAGS2_32_BIT_ERROR_CODES) {
		/* 32 bit error codes detected */
		uint32 nt_err = IVAL(cli->inbuf,smb_rcls);
		if (num) *num = nt_err;
		DEBUG(10,("cli_error: 32 bit codes: code=%08x\n", nt_err));
		if (!IS_BITS_SET_ALL(nt_err, 0xc0000000)) return 0;

		switch (nt_err) {
		case NT_STATUS_ACCESS_VIOLATION: return EACCES;
		case NT_STATUS_NO_SUCH_FILE: return ENOENT;
		case NT_STATUS_NO_SUCH_DEVICE: return ENODEV;
		case NT_STATUS_INVALID_HANDLE: return EBADF;
		case NT_STATUS_NO_MEMORY: return ENOMEM;
		case NT_STATUS_ACCESS_DENIED: return EACCES;
		case NT_STATUS_OBJECT_NAME_NOT_FOUND: return ENOENT;
		case NT_STATUS_SHARING_VIOLATION: return EBUSY;
		case NT_STATUS_OBJECT_PATH_INVALID: return ENOTDIR;
		case NT_STATUS_OBJECT_NAME_COLLISION: return EEXIST;
		}

		/* for all other cases - a default code */
		return EINVAL;
	}

	rcls  = CVAL(cli->inbuf,smb_rcls);
	code  = SVAL(cli->inbuf,smb_err);
	if (rcls == 0) return 0;

	if (eclass) *eclass = rcls;
	if (num   ) *num    = code;

	if (rcls == ERRDOS) {
		switch (code) {
		case ERRbadfile: return ENOENT;
		case ERRbadpath: return ENOTDIR;
		case ERRnoaccess: return EACCES;
		case ERRfilexists: return EEXIST;
		case ERRrename: return EEXIST;
		case ERRbadshare: return EBUSY;
		case ERRlock: return EBUSY;
		}
	}
	if (rcls == ERRSRV) {
		switch (code) {
		case ERRbadpw: return EPERM;
		case ERRaccess: return EACCES;
		case ERRnoresource: return ENOMEM;
		case ERRinvdevice: return ENODEV;
		case ERRinvnetname: return ENODEV;
		}
	}
	/* for other cases */
	return EINVAL;
}

