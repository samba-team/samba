/* 
   Unix SMB/Netbios implementation.
   Version 2.2.
   Samba system utilities for ACL support.
   Copyright (C) Jeremy Allison 2000.
   
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

extern int DEBUGLEVEL;

/*
 This file wraps all differing system ACL interfaces into a consistent
 one based on the POSIX interface. It also returns the correct errors
 for older UNIX systems that don't support ACLs.

 The interfaces that each ACL implementation must support are as follows :

 int sys_acl_get_entry( SMB_ACL_T acl, int entry_id, SMB_ACL_ENTRY_T *entry_p)
 int sys_acl_get_tag_type( SMB_ACL_ENTRY_T entry_d, SMB_ACL_TAG_T *tag_type_p)
 int sys_acl_get_permset( SMB_ACL_ENTRY_T entry_d, SMB_ACL_PERMSET_T *permset_p
 void *sys_acl_get_qualifier( SMB_ACL_ENTRY_T entry_d)
 SMB_ACL_T sys_acl_get_file( const char *path_p, SMB_ACL_TYPE_T type)
 SMB_ACL_T sys_acl_get_fd(int fd)
 int sys_acl_free( void *obj_p)
 
*/

#if defined(HAVE_POSIX_ACLS)

/* Identity mapping - easy. */

int sys_acl_get_entry( SMB_ACL_T acl, int entry_id, SMB_ACL_ENTRY_T *entry_p)
{
	return acl_get_entry( acl, entry_id, entry_p);
}

int sys_acl_get_tag_type( SMB_ACL_ENTRY_T entry_d, SMB_ACL_TAG_T *tag_type_p)
{
	return acl_get_tag_type( entry_d, tag_type_p);
}

int sys_acl_get_permset( SMB_ACL_ENTRY_T entry_d, SMB_ACL_PERMSET_T *permset_p)
{
	return acl_get_permset( entry_d, permset_p);
}

void *sys_acl_get_qualifier( SMB_ACL_ENTRY_T entry_d)
{
	return acl_get_qualifier( entry_d);
}

SMB_ACL_T sys_acl_get_file( const char *path_p, SMB_ACL_TYPE_T type)
{
	sys_acl_get_file( const char *path_p, SMB_ACL_TYPE_T type)
}

SMB_ACL_T sys_acl_get_fd(int fd)
{
	return acl_get_fd(fd);
}

int sys_acl_free( void *obj_p)
{
	return acl_free(obj_p);
}

#elif defined(HAVE_SOLARIS_ACLS)

#elif defined(HAVE_IRIX_ACLS)

#else /* No ACLs. */
int sys_acl_get_entry( SMB_ACL_T acl, int entry_id, SMB_ACL_ENTRY_T *entry_p)
{
}

int sys_acl_get_tag_type( SMB_ACL_ENTRY_T entry_d, SMB_ACL_TAG_T *tag_type_p)
{
}

int sys_acl_get_permset( SMB_ACL_ENTRY_T entry_d, SMB_ACL_PERMSET_T *permset_p)
{
}

void *sys_acl_get_qualifier( SMB_ACL_ENTRY_T entry_d)
{
}

SMB_ACL_T sys_acl_get_file( const char *path_p, SMB_ACL_TYPE_T type)
{
}

int sys_acl_free( void *obj_p)
{
}
#endif /* No ACLs. */
