/* 
   Unix SMB/CIFS implementation.
   SMB torture tester utility functions
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
#include "system/filesys.h"
#include "torture/torture.h"

_PUBLIC_ NTSTATUS torture_temp_dir(TALLOC_CTX *mem_ctx, char **tempdir)
{
	*tempdir = talloc_strdup(mem_ctx, "torture-tmp.XXXXXX");

	if (mkdtemp(*tempdir) == NULL)
		return NT_STATUS_UNSUCCESSFUL;

	return NT_STATUS_OK;
}

/**
  check if 2 NTTIMEs are equal
*/
BOOL nt_time_equal(NTTIME *t1, NTTIME *t2)
{
	return *t1 == *t2;
}


