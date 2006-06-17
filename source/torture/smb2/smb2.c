/* 
   Unix SMB/CIFS implementation.
   SMB torture tester
   Copyright (C) Jelmer Vernooij 2006
   
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
#include "torture/torture.h"
#include "libcli/smb2/smb2.h"
#include "torture/smb2/proto.h"

NTSTATUS torture_smb2_init(void)
{
	register_torture_op("SMB2-CONNECT", torture_smb2_connect);
	register_torture_op("SMB2-SCAN", torture_smb2_scan);
	register_torture_op("SMB2-SCANGETINFO", torture_smb2_getinfo_scan);
	register_torture_op("SMB2-SCANSETINFO", torture_smb2_setinfo_scan);
	register_torture_op("SMB2-SCANFIND", torture_smb2_find_scan);
	register_torture_op("SMB2-GETINFO", torture_smb2_getinfo);
	register_torture_op("SMB2-SETINFO", torture_smb2_setinfo);
	register_torture_op("SMB2-FIND", torture_smb2_find);
	register_torture_op("SMB2-LOCK", torture_smb2_lock);

	return NT_STATUS_OK;
}
