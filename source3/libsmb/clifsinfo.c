/* 
   Unix SMB/CIFS implementation.
   FS info functions
   Copyright (C) Stefan (metze) Metzmacher	2003
   
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


BOOL cli_get_fs_attr_info(struct cli_state *cli, uint32 *fs_attr)
{
	BOOL ret = False;
	uint16 setup;
	char param[2];
	char *rparam=NULL, *rdata=NULL;
	unsigned int rparam_count=0, rdata_count=0;

	if (!cli||!fs_attr)
		smb_panic("cli_get_fs_attr_info() called with NULL Pionter!");

	setup = TRANSACT2_QFSINFO;
	
	SSVAL(param,0,SMB_QUERY_FS_ATTRIBUTE_INFO);

	if (!cli_send_trans(cli, SMBtrans2, 
		    NULL, 
		    0, 0,
		    &setup, 1, 0,
		    param, 2, 0,
		    NULL, 0, 560)) {
		goto cleanup;
	}
	
	if (!cli_receive_trans(cli, SMBtrans2,
                              &rparam, &rparam_count,
                              &rdata, &rdata_count)) {
		goto cleanup;
	}

	if (cli_is_error(cli)) {
		ret = False;
		goto cleanup;
	} else {
		ret = True;
	}

	if (rdata_count < 12) {
		goto cleanup;
	}

	*fs_attr = IVAL(rdata,0);

	/* todo: but not yet needed 
	 *       return the other stuff
	 */

cleanup:
	SAFE_FREE(rparam);
	SAFE_FREE(rdata);

	return ret;	
}
