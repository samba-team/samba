/* 
   Unix SMB/CIFS implementation.
   SYS QUOTA code constants
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

#ifndef _SYSQUOTAS_H
#define _SYSQUOTAS_H


/**************************************************
 Some stuff for the sys_quota api.
 **************************************************/ 

#define SMB_QUOTAS_NO_LIMIT	((SMB_BIG_UINT)(0))
#define SMB_QUOTAS_NO_SPACE	((SMB_BIG_UINT)(1))

typedef struct _SMB_DISK_QUOTA {
	enum SMB_QUOTA_TYPE qtype;
	SMB_BIG_UINT bsize;
	SMB_BIG_UINT hardlimit; /* In bsize units. */
	SMB_BIG_UINT softlimit; /* In bsize units. */
	SMB_BIG_UINT curblocks; /* In bsize units. */
	SMB_BIG_UINT ihardlimit; /* inode hard limit. */
	SMB_BIG_UINT isoftlimit; /* inode soft limit. */
	SMB_BIG_UINT curinodes; /* Current used inodes. */
	uint32       qflags;
} SMB_DISK_QUOTA;

#endif /*_SYSQUOTAS_H */
