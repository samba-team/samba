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
#include "libcli/raw/libcliraw.h"
#include "torture/raw/proto.h"

NTSTATUS torture_raw_init(void)
{
	/* RAW smb tests */

	register_torture_op("BENCH-OPLOCK",   torture_bench_oplock);
	register_torture_op("RAW-QFSINFO", torture_raw_qfsinfo);
	register_torture_op("RAW-QFILEINFO", torture_raw_qfileinfo);
	register_torture_op("RAW-SFILEINFO", torture_raw_sfileinfo);
	register_torture_op("RAW-SFILEINFO-BUG", torture_raw_sfileinfo_bug);
	register_torture_op("RAW-SEARCH", torture_raw_search);
	register_torture_op("RAW-CLOSE", torture_raw_close);
	register_torture_op("RAW-OPEN", torture_raw_open);
	register_torture_op("RAW-MKDIR", torture_raw_mkdir);
	register_torture_op("RAW-OPLOCK", torture_raw_oplock);
	register_torture_op("RAW-NOTIFY", torture_raw_notify);
	register_torture_op("RAW-MUX", torture_raw_mux);
	register_torture_op("RAW-IOCTL", torture_raw_ioctl);
	register_torture_op("RAW-CHKPATH", torture_raw_chkpath);
	register_torture_op("RAW-UNLINK", torture_raw_unlink);
	register_torture_op("RAW-READ", torture_raw_read);
	register_torture_op("RAW-WRITE", torture_raw_write);
	register_torture_op("RAW-LOCK", torture_raw_lock);
	register_torture_op("RAW-CONTEXT", torture_raw_context);
	register_torture_op("RAW-RENAME", torture_raw_rename);
	register_torture_op("RAW-SEEK", torture_raw_seek);
	register_torture_op("RAW-EAS", torture_raw_eas);
	register_torture_op("RAW-STREAMS", torture_raw_streams);
	register_torture_op("RAW-ACLS", torture_raw_acls);
	register_torture_op("RAW-COMPOSITE", torture_raw_composite);
	register_torture_op("RAW-SAMBA3HIDE", torture_samba3_hide);
	register_torture_op("RAW-SAMBA3CHECKFSP", torture_samba3_checkfsp);
	register_torture_op("SCAN-EAMAX", torture_max_eas);

	return NT_STATUS_OK;
}
