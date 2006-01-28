/* 
   Unix SMB/CIFS implementation.
   Named Pipe Echo test
   Copyright (C) Jelmer Vernooij 2005
   
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
#include "librpc/gen_ndr/security.h"
#include "smb.h"
#include "torture/torture.h"
#include "libcli/raw/libcliraw.h"
#include "libcli/libcli.h"

#define ECHODATA "Good Times, Bad Times"

int torture_np_echo(void)
{
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = NULL;
	struct smbcli_state *cli;
	const char *pipe_name = "\\NPECHO";
	union smb_open open;
	union smb_read read;
	union smb_write write;
	union smb_close close;
	int fnum;
	BOOL ret;

	ret = torture_open_connection_share(mem_ctx, &cli, 
				   lp_parm_string(-1, "torture", "host"), 
				   "IPC$",
				   NULL);
	if (!ret)
		return False;

	open.ntcreatex.level = RAW_OPEN_NTCREATEX;
	open.ntcreatex.in.flags = 0;
	open.ntcreatex.in.root_fid = 0;
	open.ntcreatex.in.access_mask = 
		SEC_STD_READ_CONTROL |
		SEC_FILE_WRITE_ATTRIBUTE |
		SEC_FILE_WRITE_EA |
		SEC_FILE_READ_DATA |
		SEC_FILE_WRITE_DATA;
	open.ntcreatex.in.file_attr = 0;
	open.ntcreatex.in.alloc_size = 0;
	open.ntcreatex.in.share_access = 
		NTCREATEX_SHARE_ACCESS_READ |
		NTCREATEX_SHARE_ACCESS_WRITE;
	open.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN;
	open.ntcreatex.in.create_options = 0;
	open.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_IMPERSONATION;
	open.ntcreatex.in.security_flags = 0;
	open.ntcreatex.in.fname = pipe_name;

	status = smb_raw_open(cli->tree, cli->tree, &open);
	if (NT_STATUS_IS_ERR(status))
		return False;

	fnum = open.ntcreatex.out.fnum;
	
	write.write.level = RAW_WRITE_WRITE;
	write.write.in.fnum = fnum;
	write.write.in.count = strlen(ECHODATA);
	write.write.in.offset = 0;
	write.write.in.remaining = 0;
	write.write.in.data = (const uint8_t *)ECHODATA;

	status = smb_raw_write(cli->tree, &write);
	if (NT_STATUS_IS_ERR(status))
		return False;

	if (write.write.out.nwritten != strlen(ECHODATA))
		return False;

	read.read.level = RAW_READ_READ;
	read.read.in.fnum = fnum;
	read.read.in.count = strlen(ECHODATA);
	read.read.in.offset = 0;
	read.read.in.remaining = 0;
	read.read.out.data = talloc_array(mem_ctx, uint8_t, strlen(ECHODATA));

	status = smb_raw_read(cli->tree, &read);

	if (NT_STATUS_IS_ERR(status))
		return False;

	if (read.read.out.nread != strlen(ECHODATA))
		return False;

	if (memcmp(read.read.out.data, ECHODATA, strlen(ECHODATA)) != 0) {
		printf ("np_echo: Returned data did not match!\n");
		return False;
	}

	close.close.level = RAW_CLOSE_CLOSE;
	close.close.in.fnum = fnum;
	close.close.in.write_time = 0;

	status = smb_raw_close(cli->tree, &close);
	if (NT_STATUS_IS_ERR(status)) 
		return False;

	return True;
}
