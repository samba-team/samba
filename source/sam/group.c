/* 
   Unix SMB/CIFS implementation.
   SAM_GROUP_HANDLE /SAM_GROUP_ENUM helpers
   
   Copyright (C) Stefan (metze) Metzmacher 	2002
      
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

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_SAM

/************************************************************
 Fill the SAM_GROUP_HANDLE with default values.
 ***********************************************************/

static void sam_fill_default_group(SAM_GROUP_HANDLE *group)
{
	ZERO_STRUCT(group->private); /* Don't touch the talloc context */

}	

static void destroy_sam_group_handle_talloc(SAM_GROUP_HANDLE **group) 
{
	if (*group) {

		talloc_destroy((*group)->mem_ctx);
		*group = NULL;
	}
}


/**********************************************************************
 Alloc memory and initialises a SAM_GROUP_HANDLE on supplied mem_ctx.
***********************************************************************/

NTSTATUS sam_init_group_talloc(TALLOC_CTX *mem_ctx, SAM_GROUP_HANDLE **group)
{
	SMB_ASSERT(*group != NULL);

	if (!mem_ctx) {
		DEBUG(0,("sam_init_group_talloc: mem_ctx was NULL!\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	*group=(SAM_GROUP_HANDLE *)talloc(mem_ctx, sizeof(SAM_GROUP_HANDLE));

	if (*group==NULL) {
		DEBUG(0,("sam_init_group_talloc: error while allocating memory\n"));
		return NT_STATUS_NO_MEMORY;
	}

	(*group)->mem_ctx = mem_ctx;

	(*group)->free_fn = NULL;

	sam_fill_default_group(*group);
	
	return NT_STATUS_OK;
}


/*************************************************************
 Alloc memory and initialises a struct SAM_GROUP_HANDLE.
 ************************************************************/

NTSTATUS sam_init_group(SAM_GROUP_HANDLE **group)
{
	TALLOC_CTX *mem_ctx;
	NTSTATUS nt_status;
	
	mem_ctx = talloc_init("sam internal SAM_GROUP_HANDLE allocation");

	if (!mem_ctx) {
		DEBUG(0,("sam_init_group: error while doing talloc_init()\n"));
		return NT_STATUS_NO_MEMORY;
	}

	if (!NT_STATUS_IS_OK(nt_status = sam_init_group_talloc(mem_ctx, group))) {
		talloc_destroy(mem_ctx);
		return nt_status;
	}
	
	(*group)->free_fn = destroy_sam_group_handle_talloc;

	return NT_STATUS_OK;
}


/************************************************************
 Reset the SAM_GROUP_HANDLE.
 ***********************************************************/

NTSTATUS sam_reset_group(SAM_GROUP_HANDLE *group)
{
	SMB_ASSERT(group != NULL);

	sam_fill_default_group(group);

	return NT_STATUS_OK;
}


/************************************************************
 Free the SAM_GROUP_HANDLE and the member pointers.
 ***********************************************************/

NTSTATUS sam_free_group(SAM_ACCOUNT_HANDLE **group)
{
	SMB_ASSERT(*group != NULL);

	if ((*group)->free_fn) {
		(*group)->free_fn(group);
	}

	return NT_STATUS_OK;	
}


/**********************************************************
 Encode the group control bits into a string.
 length = length of string to encode into (including terminating
 null). length *MUST BE MORE THAN 2* !
 **********************************************************/

char *sam_encode_acct_ctrl(uint16 group_ctrl, size_t length)
{
	static fstring group_str;
	size_t i = 0;

	group_str[i++] = '[';

	if (group_ctrl & GCB_LOCAL_GROUP )	group_str[i++] = 'L';
	if (group_ctrl & GCB_GLOBAL_GROUP )	group_str[i++] = 'G';

	for ( ; i < length - 2 ; i++ )
		group_str[i] = ' ';

	i = length - 2;
	group_str[i++] = ']';
	group_str[i++] = '\0';

	return group_str;
}     

/**********************************************************
 Decode the group control bits from a string.
 **********************************************************/

uint16 sam_decode_group_ctrl(const char *p)
{
	uint16 group_ctrl = 0;
	BOOL finished = False;

	/*
	 * Check if the account type bits have been encoded after the
	 * NT password (in the form [NDHTUWSLXI]).
	 */

	if (*p != '[')
		return 0;

	for (p++; *p && !finished; p++) {
		switch (*p) {
			case 'L': { group_ctrl |= GCB_LOCAL_GROUP; break; /* 'L'ocal Aliases Group. */ } 
			case 'G': { group_ctrl |= GCB_GLOBAL_GROUP; break; /* 'G'lobal Domain Group. */ } 
			
		        case ' ': { break; }
			case ':':
			case '\n':
			case '\0': 
			case ']':
			default:  { finished = True; }
		}
	}

	return group_ctrl;
}

