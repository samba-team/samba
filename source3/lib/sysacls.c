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

 int sys_acl_get_entry( SMB_ACL_T theacl, int entry_id, SMB_ACL_ENTRY_T *entry_p)
 int sys_acl_get_tag_type( SMB_ACL_ENTRY_T entry_d, SMB_ACL_TAG_T *tag_type_p)
 int sys_acl_get_permset( SMB_ACL_ENTRY_T entry_d, SMB_ACL_PERMSET_T *permset_p
 void *sys_acl_get_qualifier( SMB_ACL_ENTRY_T entry_d)
 SMB_ACL_T sys_acl_get_file( const char *path_p, SMB_ACL_TYPE_T type)
 SMB_ACL_T sys_acl_get_fd(int fd)
 int sys_acl_clear_perms(SMB_ACL_PERMSET_T permset);
 int sys_acl_add_perm( SMB_ACL_PERMSET_T permset, SMB_ACL_PERM_T perm);
 char *sys_acl_to_text( SMB_ACL_T theacl, ssize_t *plen)
 SMB_ACL_T sys_acl_init( int count)
 int sys_acl_create_entry( SMB_ACL_T *pacl, SMB_ACL_ENTRY_T *pentry)
 int sys_acl_set_tag_type( SMB_ACL_ENTRY_T entry, SMB_ACL_TAG_T tagtype)
 int sys_acl_set_qualifier( SMB_ACL_ENTRY_T entry, void *qual)
 int sys_acl_set_permset( SMB_ACL_ENTRY_T entry, SMB_ACL_PERMSET_T permset)
 int sys_acl_valid( SMB_ACL_T theacl )
 int sys_acl_set_file( char *name, SMB_ACL_TYPE_T acltype, SMB_ACL_T theacl)
 int sys_acl_set_fd( int fd, SMB_ACL_TYPE_T acltype, SMB_ACL_T theacl)

 This next one is not POSIX complient - but we *have* to have it !
 More POSIX braindamage.

 int sys_acl_get_perm( SMB_ACL_PERMSET_T permset, SMB_ACL_PERM_T perm)

 The generic POSIX free is the following call. We split this into
 several different free functions as we may need to add tag info
 to structures when emulating the POSIX interface.

 int sys_acl_free( void *obj_p)

 The calls we actually use are :

 int sys_acl_free_text(char *text) - free acl_to_text
 int sys_acl_free_acl(SMB_ACL_T posix_acl)

*/

#if defined(HAVE_POSIX_ACLS)

/* Identity mapping - easy. */

int sys_acl_get_entry( SMB_ACL_T the_acl, int entry_id, SMB_ACL_ENTRY_T *entry_p)
{
	return acl_get_entry( the_acl, entry_id, entry_p);
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
	return acl_get_file( path_p, type);
}

SMB_ACL_T sys_acl_get_fd(int fd)
{
	return acl_get_fd(fd);
}

int sys_acl_clear_perms(SMB_ACL_PERMSET_T permset)
{
	return acl_clear_perms(permset);
}

int sys_acl_add_perm( SMB_ACL_PERMSET_T permset, SMB_ACL_PERM_T perm)
{
	return acl_add_perm(permset, perm);
}

int sys_acl_get_perm( SMB_ACL_PERMSET_T permset, SMB_ACL_PERM_T perm)
{
	return acl_get_perm(permset, perm);
}

char *sys_acl_to_text( SMB_ACL_T the_acl, ssize_t *plen)
{
	return acl_to_text( the_acl, plen);
}

SMB_ACL_T sys_acl_init( int count)
{
	return acl_init(count);
}

int sys_acl_create_entry( SMB_ACL_T *pacl, SMB_ACL_ENTRY_T *pentry)
{
	return acl_create_entry(pacl, pentry);
}

int sys_acl_set_tag_type( SMB_ACL_ENTRY_T entry, SMB_ACL_TAG_T tagtype)
{
	return acl_set_tag_type(entry, tagtype);
}

int sys_acl_set_qualifier( SMB_ACL_ENTRY_T entry, void *qual)
{
	return acl_set_qualifier(entry, qual);
}

int sys_acl_set_permset( SMB_ACL_ENTRY_T entry, SMB_ACL_PERMSET_T permset)
{
	return acl_set_permset(entry, permset);
}

int sys_acl_valid( SMB_ACL_T theacl )
{
	return acl_valid(thacl);
}

int sys_acl_set_file( char *name, SMB_ACL_TYPE_T acltype, SMB_ACL_T theacl)
{
	return acl_set_file(name, acltype, theacl);
}

int sys_acl_set_fd( int fd, SMB_ACL_TYPE_T acltype, SMB_ACL_T theacl)
{
	return acl_set_fd(fd, acltype, theacl);
}

int sys_acl_free_text(char *text)
{
	return acl_free(text);
}

int sys_acl_free_acl(SMB_ACL_T the_acl) 
{
	return acl_free(the_acl);
}

#elif defined(HAVE_SOLARIS_ACLS)

#elif defined(HAVE_IRIX_ACLS)

#else /* No ACLs. */

int sys_acl_get_entry( SMB_ACL_T the_acl, int entry_id, SMB_ACL_ENTRY_T *entry_p)
{
	return -1;
}

int sys_acl_get_tag_type( SMB_ACL_ENTRY_T entry_d, SMB_ACL_TAG_T *tag_type_p)
{
	return -1;
}

int sys_acl_get_permset( SMB_ACL_ENTRY_T entry_d, SMB_ACL_PERMSET_T *permset_p)
{
	return -1;
}

void *sys_acl_get_qualifier( SMB_ACL_ENTRY_T entry_d)
{
	return NULL;
}

SMB_ACL_T sys_acl_get_file( const char *path_p, SMB_ACL_TYPE_T type)
{
	return (SMB_ACL_T)NULL;
}

SMB_ACL_T sys_acl_get_fd(int fd)
{
	return (SMB_ACL_T)NULL;
}

int sys_acl_clear_perms(SMB_ACL_PERMSET_T permset)
{
	return -1;
}

int sys_acl_add_perm( SMB_ACL_PERMSET_T permset, SMB_ACL_PERM_T perm)
{
	return -1;
}

int sys_acl_get_perm( SMB_ACL_PERMSET_T permset, SMB_ACL_PERM_T perm)
{
	return (permset & perm) ? 1 : 0;
}

char *sys_acl_to_text( SMB_ACL_T the_acl, ssize_t *plen)
{
	return NULL;
}

int sys_acl_free_text(char *text)
{
	return -1;
}

SMB_ACL_T sys_acl_init( int count)
{
	return NULL;
}

int sys_acl_create_entry( SMB_ACL_T *pacl, SMB_ACL_ENTRY_T *pentry)
{
	return -1;
}

int sys_acl_set_tag_type( SMB_ACL_ENTRY_T entry, SMB_ACL_TAG_T tagtype)
{
	return -1;
}

int sys_acl_set_qualifier( SMB_ACL_ENTRY_T entry, void *qual)
{
	return -1;
}

int sys_acl_set_permset( SMB_ACL_ENTRY_T entry, SMB_ACL_PERMSET_T permset)
{
	return -1;
}

int sys_acl_valid( SMB_ACL_T theacl )
{
	return -1;
}

int sys_acl_set_file( char *name, SMB_ACL_TYPE_T acltype, SMB_ACL_T theacl)
{
	return -1;
}

int sys_acl_set_fd( int fd, SMB_ACL_TYPE_T acltype, SMB_ACL_T theacl)
{
	return -1;
}

int sys_acl_free_acl(SMB_ACL_T the_acl) 
{
	return -1;
}
#endif /* No ACLs. */
