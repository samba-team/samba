/* 
   Unix SMB/CIFS implementation.
   client error handling routines
   Copyright (C) Andrew Tridgell 1994-1998
   Copyright (C) Jelmer Vernooij 2003
   Copyright (C) Jeremy Allison 2006

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "libsmb/libsmb.h"

/****************************************************************************
 Return a description of an SMB error.
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
	fstring cli_error_message;
	uint32 flgs2 = SVAL(cli->inbuf,smb_flg2), errnum;
	uint8 errclass;
	char *result;

	if (!cli->initialised) {
		fstrcpy(cli_error_message, "[Programmer's error] cli_errstr called on unitialized cli_stat struct!\n");
		goto done;
	}

	/* Case #1: RAP error */
	if (cli->rap_error) {
		strlcpy(cli_error_message, win_errstr(W_ERROR(cli->rap_error)),
			sizeof(cli_error_message));
		goto done;
	}

	/* Case #2: 32-bit NT errors */
	if (flgs2 & FLAGS2_32_BIT_ERROR_CODES) {
		NTSTATUS status = NT_STATUS(IVAL(cli->inbuf,smb_rcls));

		return nt_errstr(status);
        }

	cli_dos_error(cli, &errclass, &errnum);

	/* Case #3: SMB error */

	return cli_smb_errstr(cli);

 done:
	result = talloc_strdup(talloc_tos(), cli_error_message);
	SMB_ASSERT(result);
	return result;
}


/****************************************************************************
 Return the 32-bit NT status code from the last packet.
****************************************************************************/

NTSTATUS cli_nt_error(struct cli_state *cli)
{
        int flgs2 = SVAL(cli->inbuf,smb_flg2);

	/* Deal with socket errors first. */
	if (cli->fd == -1) {
		return NT_STATUS_CONNECTION_DISCONNECTED;
	}

	if (!(flgs2 & FLAGS2_32_BIT_ERROR_CODES)) {
		int e_class  = CVAL(cli->inbuf,smb_rcls);
		int code  = SVAL(cli->inbuf,smb_err);
		return dos_to_ntstatus(e_class, code);
        }

        return NT_STATUS(IVAL(cli->inbuf,smb_rcls));
}


/****************************************************************************
 Return the DOS error from the last packet - an error class and an error
 code.
****************************************************************************/

void cli_dos_error(struct cli_state *cli, uint8 *eclass, uint32 *ecode)
{
	int  flgs2;

	if(!cli->initialised) {
		return;
	}

	if (cli->fd == -1) {
		*eclass = ERRDOS;
		*ecode = ERRnotconnected;
		return;
	}

	flgs2 = SVAL(cli->inbuf,smb_flg2);

	if (flgs2 & FLAGS2_32_BIT_ERROR_CODES) {
		NTSTATUS ntstatus = NT_STATUS(IVAL(cli->inbuf, smb_rcls));
		ntstatus_to_dos(ntstatus, eclass, ecode);
                return;
        }

	*eclass  = CVAL(cli->inbuf,smb_rcls);
	*ecode  = SVAL(cli->inbuf,smb_err);
}


/* Return a UNIX errno appropriate for the error received in the last
   packet. */

int cli_errno(struct cli_state *cli)
{
	NTSTATUS status;

	if (cli_is_nt_error(cli)) {
		status = cli_nt_error(cli);
		return map_errno_from_nt_status(status);
	}

        if (cli_is_dos_error(cli)) {
                uint8 eclass;
                uint32 ecode;

                cli_dos_error(cli, &eclass, &ecode);
		status = dos_to_ntstatus(eclass, ecode);
		return map_errno_from_nt_status(status);
        }

        /*
         * Yuck!  A special case for this Vista error.  Since its high-order
         * byte isn't 0xc0, it doesn't match cli_is_nt_error() above.
         */
        status = cli_nt_error(cli);
        if (NT_STATUS_V(status) == NT_STATUS_V(NT_STATUS_INACCESSIBLE_SYSTEM_SHORTCUT)) {
            return EACCES;
        }

	/* for other cases */
	return EINVAL;
}

/* Return true if the last packet was in error */

bool cli_is_error(struct cli_state *cli)
{
	uint32 flgs2 = SVAL(cli->inbuf,smb_flg2), rcls = 0;

	/* A socket error is always an error. */
	if (cli->fd == -1) {
		return True;
	}

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

bool cli_is_nt_error(struct cli_state *cli)
{
	uint32 flgs2 = SVAL(cli->inbuf,smb_flg2);

	/* A socket error is always an NT error. */
	if (cli->fd == -1) {
		return True;
	}

        return cli_is_error(cli) && (flgs2 & FLAGS2_32_BIT_ERROR_CODES);
}

/* Return true if the last error was a DOS error */

bool cli_is_dos_error(struct cli_state *cli)
{
	uint32 flgs2 = SVAL(cli->inbuf,smb_flg2);

	/* A socket error is always a DOS error. */
	if (cli->fd == -1) {
		return True;
	}

        return cli_is_error(cli) && !(flgs2 & FLAGS2_32_BIT_ERROR_CODES);
}

bool cli_state_is_connected(struct cli_state *cli)
{
	if (cli == NULL) {
		return false;
	}

	if (!cli->initialised) {
		return false;
	}

	if (cli->fd == -1) {
		return false;
	}

	return true;
}

