/*
 * Unix SMB/CIFS implementation. 
 * SMB parameters and setup
 * Copyright (C) Andrew Tridgell 1992-1998
 * Copyright (C) Simo Sorce 2000-2002
 * Copyright (C) Gerald Carter 2000
 * Copyright (C) Jeremy Allison 2001
 * Copyright (C) Andrew Bartlett 2002
 * 
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 675
 * Mass Ave, Cambridge, MA 02139, USA.
 */

#include "includes.h"

static int tdbgumm_debug_level = DBGC_ALL;
#undef DBGC_CLASS
#define DBGC_CLASS tdbgumm_debug_level

#define GUMM_VERSION		"20021012"
#define TDB_FILE_NAME		"gums_storage.tdb"
#define TDB_FORMAT_STRING	"B"
#define DOMAIN_PREFIX		"DOMAIN_"
#define USER_PREFIX		"USER_"
#define GROUP_PREFIX		"GROUP_"
#define SID_PREFIX		"SID_"

static TDB_CONTEXT *gumm_tdb = NULL;

/***************************************************************
 objects enumeration.
****************************************************************/

static NTSTATUS enumerate_objects(DOM_SID **sids, const DOM_SID *sid, const int obj_type);
{
	TDB_CONTEXT *enum_tdb = NULL;
	TDB_DATA key;

	/* Open tdb gums module */
	if (!(enum_tdb = tdb_open_log(TDB_FILE_NAME, 0, TDB_DEFAULT, update?(O_RDWR|O_CREAT):O_RDONLY, 0600)))
	{
		DEBUG(0, ("Unable to open/create gumm tdb database\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}
	
	enum_key = tdb_firstkey(enum_tdb);



	tdb_close(enum_tdb);

	return NT_STATUS_OK;
}


static NTSTATUS module_init()
{
}

