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

/*****************************************************
 RAP error codes - a small start but will be extended.
*******************************************************/

static const struct
{
	int err;
	const char *message;
} rap_errmap[] = {
	{5,    "RAP5: User has insufficient privilege" },
	{50,   "RAP50: Not supported by server" },
	{65,   "RAP65: Access denied" },
	{86,   "RAP86: The specified password is invalid" },
	{2220, "RAP2220: Group does not exist" },
	{2221, "RAP2221: User does not exist" },
	{2226, "RAP2226: Operation only permitted on a Primary Domain Controller"  },
	{2237, "RAP2237: User is not in group" },
	{2242, "RAP2242: The password of this user has expired." },
	{2243, "RAP2243: The password of this user cannot change." },
	{2244, "RAP2244: This password cannot be used now (password history conflict)." },
	{2245, "RAP2245: The password is shorter than required." },
	{2246, "RAP2246: The password of this user is too recent to change."},

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
static const char *cli_smb_errstr(struct cli_state *cli)
{
	return smb_dos_errstr(cli->inbuf);
}

/***************************************************************************
 Return an error message - either an NT error, SMB error or a RAP error.
 Note some of the NT errors are actually warnings or "informational" errors
 in which case they can be safely ignored.
****************************************************************************/
    
const char *cli_errstr(struct cli_state *cli)
{   
	static fstring cli_error_message;
	uint32 flgs2 = SVAL(cli->inbuf,smb_flg2), errnum;
        uint8 errclass;
        int i;
	
	if (!cli->initialised) {
		fstrcpy(cli_error_message, "[Programmer's error] cli_errstr called on unitialized cli_stat struct!\n");
		return cli_error_message;
	}
		
	/* Was it server socket error ? */
	if (cli->fd == -1 && cli->smb_rw_error) {
		switch(cli->smb_rw_error) {
			case READ_TIMEOUT:
				slprintf(cli_error_message, sizeof(cli_error_message) - 1,
					"Call timed out: server did not respond after %d milliseconds", 
					cli->timeout);
				break;
			case READ_EOF:
				slprintf(cli_error_message, sizeof(cli_error_message) - 1,
					"Call returned zero bytes (EOF)\n" );
				break;
			case READ_ERROR:
				slprintf(cli_error_message, sizeof(cli_error_message) - 1,
					"Read error: %s\n", strerror(errno) );
				break;
			case WRITE_ERROR:
				slprintf(cli_error_message, sizeof(cli_error_message) - 1,
					"Write error: %s\n", strerror(errno) );
				break;
			default:
				slprintf(cli_error_message, sizeof(cli_error_message) - 1,
					"Unknown error code %d\n", cli->smb_rw_error );
				break;
		}
		return cli_error_message;
	}

        /* Case #1: RAP error */
	if (cli->rap_error) {
		for (i = 0; rap_errmap[i].message != NULL; i++) {
			if (rap_errmap[i].err == cli->rap_error) {
				return rap_errmap[i].message;
			}
		} 

		slprintf(cli_error_message, sizeof(cli_error_message) - 1, "RAP code %d", 
			cli->rap_error);

		return cli_error_message;
	}

        /* Case #2: 32-bit NT errors */
	if (flgs2 & FLAGS2_32_BIT_ERROR_CODES) {
                NTSTATUS status = NT_STATUS(IVAL(cli->inbuf,smb_rcls));

                return get_nt_error_msg(status);
        }

        cli_dos_error(cli, &errclass, &errnum);

        /* Case #3: SMB error */

	return cli_smb_errstr(cli);
}


/* Return the 32-bit NT status code from the last packet */
NTSTATUS cli_nt_error(struct cli_state *cli)
{
        int flgs2 = SVAL(cli->inbuf,smb_flg2);

	if (!(flgs2 & FLAGS2_32_BIT_ERROR_CODES)) {
		int class  = CVAL(cli->inbuf,smb_rcls);
		int code  = SVAL(cli->inbuf,smb_err);
		return dos_to_ntstatus(class, code);
        }

        return NT_STATUS(IVAL(cli->inbuf,smb_rcls));
}


/* Return the DOS error from the last packet - an error class and an error
   code. */
void cli_dos_error(struct cli_state *cli, uint8 *eclass, uint32 *ecode)
{
	int  flgs2;
	char rcls;
	int code;

	if(!cli->initialised) return;

	flgs2 = SVAL(cli->inbuf,smb_flg2);

	if (flgs2 & FLAGS2_32_BIT_ERROR_CODES) {
		NTSTATUS ntstatus = NT_STATUS(IVAL(cli->inbuf, smb_rcls));
		ntstatus_to_dos(ntstatus, eclass, ecode);
                return;
        }

	rcls  = CVAL(cli->inbuf,smb_rcls);
	code  = SVAL(cli->inbuf,smb_err);

	if (eclass) *eclass = rcls;
	if (ecode) *ecode    = code;
}

/* Return a UNIX errno from a dos error class, error number tuple */

int cli_errno_from_dos(uint8 eclass, uint32 num)
{
	if (eclass == ERRDOS) {
		switch (num) {
		case ERRbadfile: return ENOENT;
		case ERRbadpath: return ENOTDIR;
		case ERRnoaccess: return EACCES;
		case ERRfilexists: return EEXIST;
		case ERRrename: return EEXIST;
		case ERRbadshare: return EBUSY;
		case ERRlock: return EBUSY;
		case ERRinvalidname: return ENOENT;
		case ERRnosuchshare: return ENODEV;
		}
	}

	if (eclass == ERRSRV) {
		switch (num) {
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

/* Return a UNIX errno from a NT status code */
static struct {
	NTSTATUS status;
	int error;
} nt_errno_map[] = {
        {NT_STATUS_ACCESS_VIOLATION, EACCES},
        {NT_STATUS_NO_SUCH_FILE, ENOENT},
        {NT_STATUS_NO_SUCH_DEVICE, ENODEV},
        {NT_STATUS_INVALID_HANDLE, EBADF},
        {NT_STATUS_NO_MEMORY, ENOMEM},
        {NT_STATUS_ACCESS_DENIED, EACCES},
        {NT_STATUS_OBJECT_NAME_NOT_FOUND, ENOENT},
        {NT_STATUS_SHARING_VIOLATION, EBUSY},
        {NT_STATUS_OBJECT_PATH_INVALID, ENOTDIR},
        {NT_STATUS_OBJECT_NAME_COLLISION, EEXIST},
        {NT_STATUS_PATH_NOT_COVERED, ENOENT},
	{NT_STATUS(0), 0}
};

int cli_errno_from_nt(NTSTATUS status)
{
	int i;
        DEBUG(10,("cli_errno_from_nt: 32 bit codes: code=%08x\n", NT_STATUS_V(status)));

        /* Status codes without this bit set are not errors */

        if (!(NT_STATUS_V(status) & 0xc0000000))
                return 0;

	for (i=0;nt_errno_map[i].error;i++) {
		if (NT_STATUS_V(nt_errno_map[i].status) ==
		    NT_STATUS_V(status)) return nt_errno_map[i].error;
	}

        /* for all other cases - a default code */
        return EINVAL;
}

/* Return a UNIX errno appropriate for the error received in the last
   packet. */

int cli_errno(struct cli_state *cli)
{
        NTSTATUS status;

        if (cli_is_dos_error(cli)) {
                uint8 eclass;
                uint32 ecode;

                cli_dos_error(cli, &eclass, &ecode);
                return cli_errno_from_dos(eclass, ecode);
        }

        status = cli_nt_error(cli);

        return cli_errno_from_nt(status);
}

/* Return true if the last packet was in error */

BOOL cli_is_error(struct cli_state *cli)
{
	uint32 flgs2 = SVAL(cli->inbuf,smb_flg2), rcls = 0;

        if (flgs2 & FLAGS2_32_BIT_ERROR_CODES) {
                /* Return error is error bits are set */
                rcls = IVAL(cli->inbuf, smb_rcls);
                return (rcls & 0xF0000000) == 0xC0000000;
        }
                
        /* Return error if error class in non-zero */

        rcls = CVAL(cli->inbuf, smb_rcls);
        return rcls != 0;
}

/* Return true if the last error was an NT error */

BOOL cli_is_nt_error(struct cli_state *cli)
{
	uint32 flgs2 = SVAL(cli->inbuf,smb_flg2);

        return cli_is_error(cli) && (flgs2 & FLAGS2_32_BIT_ERROR_CODES);
}

/* Return true if the last error was a DOS error */

BOOL cli_is_dos_error(struct cli_state *cli)
{
	uint32 flgs2 = SVAL(cli->inbuf,smb_flg2);

        return cli_is_error(cli) && !(flgs2 & FLAGS2_32_BIT_ERROR_CODES);
}
