/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   client error handling routines
   Copyright (C) Andrew Tridgell 1994-1998
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


#define NO_SYSLOG

#include "includes.h"
#include "nterr.h"

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
  {0, NULL}
};  

/****************************************************************************
  return a description of a RAP error
****************************************************************************/
BOOL get_safe_rap_errstr(int rap_error, char *err_msg, size_t msglen)
{
	int i;

	slprintf(err_msg, msglen - 1, "RAP code %d", rap_error);

	for (i = 0; rap_errmap[i].message != NULL; i++)
	{
		if (rap_errmap[i].err == rap_error)
		{
			safe_strcpy( err_msg, rap_errmap[i].message, msglen);
			return True;
		}
	} 
	return False;
}

/******************************************************
 Return an error message - either an SMB error or a RAP
 error.
*******************************************************/
    
char *cli_errstr(struct cli_state *cli)
{   
	static fstring error_message;
	cli_safe_errstr(cli, error_message, sizeof(error_message));
	return error_message;
}

/****************************************************************************
  return error codes for the last packet
  returns 0 if there was no error and the best approx of a unix errno
  otherwise

  for 32 bit "warnings", a return code of 0 is expected.

****************************************************************************/
int cli_error(struct cli_state *cli, uint8 *eclass, uint32 *num)
{
	int  flgs2;
	char rcls;
	int code;

	if (!cli->initialised)
	{
		DEBUG(0,("cli_error: client state uninitialised!\n"));
		return EINVAL;
	}

	flgs2 = SVAL(cli->inbuf,smb_flg2);

	if (eclass) *eclass = 0;
	if (num   ) *num = 0;

	if (flgs2 & FLAGS2_32_BIT_ERROR_CODES)
	{
		/* 32 bit error codes detected */
		uint32 nt_err = IVAL(cli->inbuf,smb_rcls);
		if (num) *num = nt_err;
		DEBUG(10,("cli_error: 32 bit codes: code=%08x\n", nt_err));
		if (!IS_BITS_SET_ALL(nt_err, 0xc0000000)) return 0;

		switch (nt_err & 0xFFFFFF)
		{
			case NT_STATUS_ACCESS_VIOLATION     : return EACCES;
			case NT_STATUS_NO_SUCH_FILE         : return ENOENT;
			case NT_STATUS_NO_SUCH_DEVICE       : return ENODEV;
			case NT_STATUS_INVALID_HANDLE       : return EBADF;
			case NT_STATUS_NO_MEMORY            : return ENOMEM;
			case NT_STATUS_ACCESS_DENIED        : return EACCES;
			case NT_STATUS_OBJECT_NAME_NOT_FOUND: return ENOENT;
			case NT_STATUS_SHARING_VIOLATION    : return EBUSY;
			case NT_STATUS_OBJECT_PATH_INVALID  : return ENOTDIR;
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
		case ERRmoredata: return 0; /* Informational only */
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

