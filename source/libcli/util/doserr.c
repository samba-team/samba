/* 
 *  Unix SMB/CIFS implementation.
 *  DOS error routines
 *  Copyright (C) Tim Potter 2002.
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/* DOS error codes.  please read doserr.h */

#include "includes.h"

struct werror_code_struct {
	const char *dos_errstr;
	WERROR werror;
};

static const struct werror_code_struct dos_errs[] =
{
	{ "WERR_OK", WERR_OK },
	{ "WERR_BADFILE", WERR_BADFILE },
	{ "WERR_ACCESS_DENIED", WERR_ACCESS_DENIED },
	{ "WERR_BADFID", WERR_BADFID },
	{ "WERR_BADFUNC", WERR_BADFUNC },
	{ "WERR_BAD_NETPATH", WERR_BAD_NETPATH },
	{ "WERR_INSUFFICIENT_BUFFER", WERR_INSUFFICIENT_BUFFER },
	{ "WERR_NO_SUCH_SHARE", WERR_NO_SUCH_SHARE },
	{ "WERR_ALREADY_EXISTS", WERR_ALREADY_EXISTS },
	{ "WERR_INVALID_PARAM", WERR_INVALID_PARAM },
	{ "WERR_NOT_SUPPORTED", WERR_NOT_SUPPORTED },
	{ "WERR_BAD_PASSWORD", WERR_BAD_PASSWORD },
	{ "WERR_NOMEM", WERR_NOMEM },
	{ "WERR_INVALID_NAME", WERR_INVALID_NAME },
	{ "WERR_UNKNOWN_LEVEL", WERR_UNKNOWN_LEVEL },
	{ "WERR_OBJECT_PATH_INVALID", WERR_OBJECT_PATH_INVALID },
	{ "WERR_NO_MORE_ITEMS", WERR_NO_MORE_ITEMS },
	{ "WERR_MORE_DATA", WERR_MORE_DATA },
	{ "WERR_UNKNOWN_PRINTER_DRIVER", WERR_UNKNOWN_PRINTER_DRIVER },
	{ "WERR_INVALID_PRINTER_NAME", WERR_INVALID_PRINTER_NAME },
	{ "WERR_PRINTER_ALREADY_EXISTS", WERR_PRINTER_ALREADY_EXISTS },
	{ "WERR_INVALID_DATATYPE", WERR_INVALID_DATATYPE },
	{ "WERR_INVALID_ENVIRONMENT", WERR_INVALID_ENVIRONMENT },
	{ "WERR_INVALID_FORM_NAME", WERR_INVALID_FORM_NAME },
	{ "WERR_INVALID_FORM_SIZE", WERR_INVALID_FORM_SIZE },
	{ "WERR_BUF_TOO_SMALL", WERR_BUF_TOO_SMALL },
	{ "WERR_JOB_NOT_FOUND", WERR_JOB_NOT_FOUND },
	{ "WERR_DEST_NOT_FOUND", WERR_DEST_NOT_FOUND },
	{ "WERR_NOT_LOCAL_DOMAIN", WERR_NOT_LOCAL_DOMAIN },
	{ "WERR_PRINTER_DRIVER_IN_USE", WERR_PRINTER_DRIVER_IN_USE },
	{ "WERR_STATUS_MORE_ENTRIES  ", WERR_STATUS_MORE_ENTRIES },
	{ "WERR_DFS_NO_SUCH_VOL", WERR_DFS_NO_SUCH_VOL },
	{ "WERR_DFS_NO_SUCH_SHARE", WERR_DFS_NO_SUCH_SHARE },
	{ "WERR_DFS_NO_SUCH_SERVER", WERR_DFS_NO_SUCH_SERVER },
	{ "WERR_DFS_INTERNAL_ERROR", WERR_DFS_INTERNAL_ERROR },
	{ "WERR_DFS_CANT_CREATE_JUNCT", WERR_DFS_CANT_CREATE_JUNCT },
	{ "WERR_INVALID_SECURITY_DESCRIPTOR", WERR_INVALID_SECURITY_DESCRIPTOR },
	{ "WERR_INVALID_OWNER", WERR_INVALID_OWNER },
	{ "WERR_INVALID_DOMAINNAME", WERR_INVALID_DOMAINNAME },
	{ "WERR_NO_SUCH_USER", WERR_NO_SUCH_USER },
	{ "WERR_NO_SUCH_DOMAIN", WERR_NO_SUCH_DOMAIN },
	{ "WERR_DS_SERVICE_BUSY", WERR_DS_SERVICE_BUSY },
	{ "WERR_DS_SERVICE_UNAVAILABLE", WERR_DS_SERVICE_UNAVAILABLE },
	{ "WERR_DS_NO_SUCH_OBJECT", WERR_DS_NO_SUCH_OBJECT },
	{ "WERR_DS_OBJ_NOT_FOUND", WERR_DS_OBJ_NOT_FOUND },
	{ "WERR_GENERAL_FAILURE", WERR_GENERAL_FAILURE },
	{ "WERR_PRINTQ_FULL", WERR_PRINTQ_FULL },
	{ "WERR_NO_SPOOL_SPACE", WERR_NO_SPOOL_SPACE },
	{ "WERR_CAN_NOT_COMPLETE", WERR_CAN_NOT_COMPLETE },
	{ "WERR_SERVER_UNAVAILABLE", WERR_SERVER_UNAVAILABLE },
	{ NULL, W_ERROR(0) }
};




/* DFS errors */

/*****************************************************************************
 returns a windows error message.  not amazingly helpful, but better than a number.
 *****************************************************************************/
const char *win_errstr(WERROR werror)
{
        static pstring msg;
        int idx = 0;

	while (dos_errs[idx].dos_errstr != NULL) {
		if (W_ERROR_V(dos_errs[idx].werror) == 
                    W_ERROR_V(werror))
                        return dos_errs[idx].dos_errstr;
		idx++;
	}

	slprintf(msg, sizeof(msg), "DOS code 0x%08x", W_ERROR_V(werror));

        return msg;
}
