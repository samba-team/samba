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
 int sys_acl_set_fd( int fd, SMB_ACL_T theacl)

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
	return acl_valid(theacl);
}

int sys_acl_set_file( char *name, SMB_ACL_TYPE_T acltype, SMB_ACL_T theacl)
{
	return acl_set_file(name, acltype, theacl);
}

int sys_acl_set_fd( int fd, SMB_ACL_T theacl)
{
	return acl_set_fd(fd, theacl);
}

int sys_acl_free_text(char *text)
{
	return acl_free(text);
}

int sys_acl_free_acl(SMB_ACL_T the_acl) 
{
	return acl_free(the_acl);
}

#elif defined(HAVE_UNIXWARE_ACLS) || defined(HAVE_SOLARIS_ACLS)

/*
 * Donated by Michael Davidson <md@sco.COM> for UnixWare / OpenUNIX.
 * Modified by Toomas Soome <tsoome@ut.ee> for Solaris.
 */

/*
 * Note that while this code implements sufficient functionality
 * to support the sys_acl_* interfaces it does not provide all
 * of the semantics of the POSIX ACL interfaces.
 *
 * In particular, an ACL entry descriptor (SMB_ACL_ENTRY_T) returned
 * from a call to sys_acl_get_entry() should not be assumed to be
 * valid after calling any of the following functions, which may
 * reorder the entries in the ACL.
 *
 *	sys_acl_valid()
 *	sys_acl_set_file()
 *	sys_acl_set_fd()
 */

/*
 * The only difference between Solaris and UnixWare / OpenUNIX is
 * that the #defines for the ACL operations have different names
 */
#if defined(HAVE_UNIXWARE_ACLS)

#define	SETACL		ACL_SET
#define	GETACL		ACL_GET
#define	GETACLCNT	ACL_CNT

#endif


int sys_acl_get_entry(SMB_ACL_T acl_d, int entry_id, SMB_ACL_ENTRY_T *entry_p)
{
	if (entry_id != SMB_ACL_FIRST_ENTRY && entry_id != SMB_ACL_NEXT_ENTRY) {
		errno = EINVAL;
		return -1;
	}

	if (entry_p == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (entry_id == SMB_ACL_FIRST_ENTRY) {
		acl_d->next = 0;
	}

	if (acl_d->next < 0) {
		errno = EINVAL;
		return -1;
	}

	if (acl_d->next >= acl_d->count) {
		return 0;
	}

	*entry_p = &acl_d->acl[acl_d->next++];

	return 1;
}

int sys_acl_get_tag_type(SMB_ACL_ENTRY_T entry_d, SMB_ACL_TAG_T *type_p)
{
	*type_p = entry_d->a_type;

	return 0;
}

int sys_acl_get_permset(SMB_ACL_ENTRY_T entry_d, SMB_ACL_PERMSET_T *permset_p)
{
	*permset_p = &entry_d->a_perm;

	return 0;
}

void *sys_acl_get_qualifier(SMB_ACL_ENTRY_T entry_d)
{
	if (entry_d->a_type != SMB_ACL_USER
	    && entry_d->a_type != SMB_ACL_GROUP) {
		errno = EINVAL;
		return NULL;
	}

	return &entry_d->a_id;
}

/*
 * There is no way of knowing what size the ACL returned by
 * GETACL will be unless you first call GETACLCNT which means
 * making an additional system call.
 *
 * In the hope of avoiding the cost of the additional system
 * call in most cases, we initially allocate enough space for
 * an ACL with INITIAL_ACL_SIZE entries. If this turns out to
 * be too small then we use GETACLCNT to find out the actual
 * size, reallocate the ACL buffer, and then call GETACL again.
 */

#define	INITIAL_ACL_SIZE	16

SMB_ACL_T sys_acl_get_file(const char *path_p, SMB_ACL_TYPE_T type)
{
	SMB_ACL_T	acl_d;
	int		count;		/* # of ACL entries allocated	*/
	int		naccess;	/* # of access ACL entries	*/
	int		ndefault;	/* # of default ACL entries	*/

	if (type != SMB_ACL_TYPE_ACCESS && type != SMB_ACL_TYPE_DEFAULT) {
		errno = EINVAL;
		return NULL;
	}

	count = INITIAL_ACL_SIZE;
	if ((acl_d = sys_acl_init(count)) == NULL) {
		return NULL;
	}

	/*
	 * If there isn't enough space for the ACL entries we use
	 * GETACLCNT to determine the actual number of ACL entries
	 * reallocate and try again. This is in a loop because it
	 * is possible that someone else could modify the ACL and
	 * increase the number of entries between the call to
	 * GETACLCNT and the call to GETACL.
	 */
	while ((count = acl(path_p, GETACL, count, &acl_d->acl[0])) < 0
	    && errno == ENOSPC) {

		sys_acl_free_acl(acl_d);

		if ((count = acl(path_p, GETACLCNT, 0, NULL)) < 0) {
			return NULL;
		}

		if ((acl_d = sys_acl_init(count)) == NULL) {
			return NULL;
		}
	}

	if (count < 0) {
		sys_acl_free_acl(acl_d);
		return NULL;
	}

	/*
	 * calculate the number of access and default ACL entries
	 *
	 * Note: we assume that the acl() system call returned a
	 * well formed ACL which is sorted so that all of the
	 * access ACL entries preceed any default ACL entries
	 */
	for (naccess = 0; naccess < count; naccess++) {
		if (acl_d->acl[naccess].a_type & ACL_DEFAULT)
			break;
	}
	ndefault = count - naccess;
	
	/*
	 * if the caller wants the default ACL we have to copy
	 * the entries down to the start of the acl[] buffer
	 * and mask out the ACL_DEFAULT flag from the type field
	 */
	if (type == SMB_ACL_TYPE_DEFAULT) {
		int	i, j;

		for (i = 0, j = naccess; i < ndefault; i++, j++) {
			acl_d->acl[i] = acl_d->acl[j];
			acl_d->acl[i].a_type &= ~ACL_DEFAULT;
		}

		acl_d->count = ndefault;
	} else {
		acl_d->count = naccess;
	}

	return acl_d;
}

SMB_ACL_T sys_acl_get_fd(int fd)
{
	SMB_ACL_T	acl_d;
	int		count;		/* # of ACL entries allocated	*/
	int		naccess;	/* # of access ACL entries	*/

	count = INITIAL_ACL_SIZE;
	if ((acl_d = sys_acl_init(count)) == NULL) {
		return NULL;
	}

	while ((count = facl(fd, GETACL, count, &acl_d->acl[0])) < 0
	    && errno == ENOSPC) {

		sys_acl_free_acl(acl_d);

		if ((count = facl(fd, GETACLCNT, 0, NULL)) < 0) {
			return NULL;
		}

		if ((acl_d = sys_acl_init(count)) == NULL) {
			return NULL;
		}
	}

	if (count < 0) {
		sys_acl_free_acl(acl_d);
		return NULL;
	}

	/*
	 * calculate the number of access ACL entries
	 */
	for (naccess = 0; naccess < count; naccess++) {
		if (acl_d->acl[naccess].a_type & ACL_DEFAULT)
			break;
	}
	
	acl_d->count = naccess;

	return acl_d;
}

int sys_acl_clear_perms(SMB_ACL_PERMSET_T permset_d)
{
	*permset_d = 0;

	return 0;
}

int sys_acl_add_perm(SMB_ACL_PERMSET_T permset_d, SMB_ACL_PERM_T perm)
{
	if (perm != SMB_ACL_READ && perm != SMB_ACL_WRITE
	    && perm != SMB_ACL_EXECUTE) {
		errno = EINVAL;
		return -1;
	}

	if (permset_d == NULL) {
		errno = EINVAL;
		return -1;
	}

	*permset_d |= perm;

	return 0;
}

int sys_acl_get_perm(SMB_ACL_PERMSET_T permset_d, SMB_ACL_PERM_T perm)
{
	return *permset_d & perm;
}

char *sys_acl_to_text(SMB_ACL_T acl_d, ssize_t *len_p)
{
	int	i;
	int	len, maxlen;
	char	*text;

	/*
	 * use an initial estimate of 20 bytes per ACL entry
	 * when allocating memory for the text representation
	 * of the ACL
	 */
	len	= 0;
	maxlen	= 20 * acl_d->count;
	if ((text = malloc(maxlen)) == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	for (i = 0; i < acl_d->count; i++) {
		struct acl	*ap	= &acl_d->acl[i];
		struct passwd	*pw;
		struct group	*gr;
		char		tagbuf[12];
		char		idbuf[12];
		char		*tag;
		char		*id	= "";
		char		perms[4];
		int		nbytes;

		switch (ap->a_type) {
			/*
			 * for debugging purposes it's probably more
			 * useful to dump unknown tag types rather
			 * than just returning an error
			 */
			default:
				slprintf(tagbuf, sizeof(tagbuf)-1, "0x%x",
					ap->a_type);
				tag = tagbuf;
				slprintf(idbuf, sizeof(idbuf)-1, "%ld",
					(long)ap->a_id);
				id = idbuf;
				break;

			case SMB_ACL_USER:
				if ((pw = sys_getpwuid(ap->a_id)) == NULL) {
					slprintf(idbuf, sizeof(idbuf)-1, "%ld",
						(long)ap->a_id);
					id = idbuf;
				} else {
					id = pw->pw_name;
				}
			case SMB_ACL_USER_OBJ:
				tag = "user";
				break;

			case SMB_ACL_GROUP:
				if ((gr = getgrgid(ap->a_id)) == NULL) {
					slprintf(idbuf, sizeof(idbuf)-1, "%ld",
						(long)ap->a_id);
					id = idbuf;
				} else {
					id = gr->gr_name;
				}
			case SMB_ACL_GROUP_OBJ:
				tag = "group";
				break;

			case SMB_ACL_OTHER:
				tag = "other";
				break;

			case SMB_ACL_MASK:
				tag = "mask";
				break;

		}

		perms[0] = (ap->a_perm & SMB_ACL_READ) ? 'r' : '-';
		perms[1] = (ap->a_perm & SMB_ACL_WRITE) ? 'w' : '-';
		perms[2] = (ap->a_perm & SMB_ACL_EXECUTE) ? 'x' : '-';
		perms[3] = '\0';

		/*          <tag>      :  <qualifier>   :  rwx \n  \0 */
		nbytes = strlen(tag) + 1 + strlen(id) + 1 + 3 + 1 + 1;

		/*
		 * If this entry would overflow the buffer
		 * allocate enough additional memory for this
		 * entry and an estimate of another 20 bytes
		 * for each entry still to be processed
		 */
		if ((len + nbytes) > maxlen) {
			char *oldtext = text;

			maxlen += nbytes + 20 * (acl_d->count - i);

			if ((text = realloc(oldtext, maxlen)) == NULL) {
				free(oldtext);
				errno = ENOMEM;
				return NULL;
			}
		}

		slprintf(&text[len], nbytes-1, "%s:%s:%s\n", tag, id, perms);
		len += nbytes - 1;
	}

	if (len_p)
		*len_p = len;

	return text;
}

SMB_ACL_T sys_acl_init(int count)
{
	SMB_ACL_T	a;

	if (count < 0) {
		errno = EINVAL;
		return NULL;
	}

	/*
	 * note that since the definition of the structure pointed
	 * to by the SMB_ACL_T includes the first element of the
	 * acl[] array, this actually allocates an ACL with room
	 * for (count+1) entries
	 */
	if ((a = malloc(sizeof(*a) + count * sizeof(struct acl))) == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	a->size = count + 1;
	a->count = 0;
	a->next = -1;

	return a;
}


int sys_acl_create_entry(SMB_ACL_T *acl_p, SMB_ACL_ENTRY_T *entry_p)
{
	SMB_ACL_T	acl_d;
	SMB_ACL_ENTRY_T	entry_d;

	if (acl_p == NULL || entry_p == NULL || (acl_d = *acl_p) == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (acl_d->count >= acl_d->size) {
		errno = ENOSPC;
		return -1;
	}

	entry_d		= &acl_d->acl[acl_d->count++];
	entry_d->a_type	= 0;
	entry_d->a_id	= -1;
	entry_d->a_perm	= 0;
	*entry_p	= entry_d;

	return 0;
}

int sys_acl_set_tag_type(SMB_ACL_ENTRY_T entry_d, SMB_ACL_TAG_T tag_type)
{
	switch (tag_type) {
		case SMB_ACL_USER:
		case SMB_ACL_USER_OBJ:
		case SMB_ACL_GROUP:
		case SMB_ACL_GROUP_OBJ:
		case SMB_ACL_OTHER:
		case SMB_ACL_MASK:
			entry_d->a_type = tag_type;
			break;
		default:
			errno = EINVAL;
			return -1;
	}

	return 0;
}

int sys_acl_set_qualifier(SMB_ACL_ENTRY_T entry_d, void *qual_p)
{
	if (entry_d->a_type != SMB_ACL_GROUP
	    && entry_d->a_type != SMB_ACL_USER) {
		errno = EINVAL;
		return -1;
	}

	entry_d->a_id = *((id_t *)qual_p);

	return 0;
}

int sys_acl_set_permset(SMB_ACL_ENTRY_T entry_d, SMB_ACL_PERMSET_T permset_d)
{
	if (*permset_d & ~(SMB_ACL_READ|SMB_ACL_WRITE|SMB_ACL_EXECUTE)) {
		return EINVAL;
	}

	entry_d->a_perm = *permset_d;

	return 0;
}

int sys_acl_valid(SMB_ACL_T acl_d)
{
	if (aclsort(acl_d->count, 0, acl_d->acl) != 0) {
		errno = EINVAL;
		return -1;
	}

	return 0;
}

int sys_acl_set_file(char *name, SMB_ACL_TYPE_T type, SMB_ACL_T acl_d)
{
	struct stat	s;
	struct acl	*acl_p;
	int		acl_count;
	struct acl	*acl_buf	= NULL;
	int		ret;

	if (type != SMB_ACL_TYPE_ACCESS && type != SMB_ACL_TYPE_DEFAULT) {
		errno = EINVAL;
		return -1;
	}

	if (stat(name, &s) != 0) {
		return -1;
	}

	acl_p		= &acl_d->acl[0];
	acl_count	= acl_d->count;

	/*
	 * if it's a directory there is extra work to do
	 * since the acl() system call will replace both
	 * the access ACLs and the default ACLs (if any)
	 */
	if (S_ISDIR(s.st_mode)) {
		SMB_ACL_T	acc_acl;
		SMB_ACL_T	def_acl;
		SMB_ACL_T	tmp_acl;
		int		i;

		if (type == SMB_ACL_TYPE_ACCESS) {
			acc_acl = acl_d;
			def_acl = 
			tmp_acl = sys_acl_get_file(name, SMB_ACL_TYPE_DEFAULT);

		} else {
			def_acl = acl_d;
			acc_acl = 
			tmp_acl = sys_acl_get_file(name, SMB_ACL_TYPE_ACCESS);
		}

		if (tmp_acl == NULL) {
			return -1;
		}

		/*
		 * allocate a temporary buffer for the complete ACL
		 */
		acl_count	= acc_acl->count + def_acl->count;
		acl_p		=
		acl_buf		= malloc(acl_count * sizeof(acl_buf[0]));

		if (acl_buf == NULL) {
			sys_acl_free_acl(tmp_acl);
			errno = ENOMEM;
			return -1;
		}

		/*
		 * copy the access control and default entries into the buffer
		 */
		memcpy(&acl_buf[0], &acc_acl->acl[0],
			acc_acl->count * sizeof(acl_buf[0]));

		memcpy(&acl_buf[acc_acl->count], &def_acl->acl[0],
			def_acl->count * sizeof(acl_buf[0]));

		/*
		 * set the ACL_DEFAULT flag on the default entries
		 */
		for (i = acc_acl->count; i < acl_count; i++) {
			acl_buf[i].a_type |= ACL_DEFAULT;
		}

		sys_acl_free_acl(tmp_acl);

	} else if (type != SMB_ACL_TYPE_ACCESS) {
		errno = EINVAL;
		return -1;
	}

	if (aclsort(acl_count, 0, acl_p) != 0) {
		errno = EINVAL;
		ret = -1;
	} else {
		ret = acl(name, SETACL, acl_count, acl_p);
	}

	if (acl_buf) {
		free(acl_buf);
	}

	return ret;
}

int sys_acl_set_fd(int fd, SMB_ACL_T acl_d)
{
	if (aclsort(acl_d->count, 0, acl_d->acl) != 0) {
		errno = EINVAL;
		return -1;
	}

	return facl(fd, SETACL, acl_d->count, &acl_d->acl[0]);
}

int sys_acl_free_text(char *text)
{
	free(text);
	return 0;
}

int sys_acl_free_acl(SMB_ACL_T acl_d) 
{
	free(acl_d);
	return 0;
}

#elif defined(HAVE_IRIX_ACLS)

int sys_acl_get_entry(SMB_ACL_T acl_d, int entry_id, SMB_ACL_ENTRY_T *entry_p)
{
	if (entry_id != SMB_ACL_FIRST_ENTRY && entry_id != SMB_ACL_NEXT_ENTRY) {
		errno = EINVAL;
		return -1;
	}

	if (entry_p == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (entry_id == SMB_ACL_FIRST_ENTRY) {
		acl_d->next = 0;
	}

	if (acl_d->next < 0) {
		errno = EINVAL;
		return -1;
	}

	if (acl_d->next >= acl_d->aclp->acl_cnt) {
		return 0;
	}

	*entry_p = &acl_d->aclp->acl_entry[acl_d->next++];

	return 1;
}

int sys_acl_get_tag_type(SMB_ACL_ENTRY_T entry_d, SMB_ACL_TAG_T *type_p)
{
	*type_p = entry_d->ae_tag;

	return 0;
}

int sys_acl_get_permset(SMB_ACL_ENTRY_T entry_d, SMB_ACL_PERMSET_T *permset_p)
{
	*permset_p = entry_d;

	return 0;
}

void *sys_acl_get_qualifier(SMB_ACL_ENTRY_T entry_d)
{
	if (entry_d->ae_tag != SMB_ACL_USER
	    && entry_d->ae_tag != SMB_ACL_GROUP) {
		errno = EINVAL;
		return NULL;
	}

	return &entry_d->ae_id;
}

SMB_ACL_T sys_acl_get_file(const char *path_p, SMB_ACL_TYPE_T type)
{
	SMB_ACL_T	a;

	if ((a = malloc(sizeof(*a))) == NULL) {
		errno = ENOMEM;
		return NULL;
	}
	if ((a->aclp = acl_get_file(path_p, type)) == NULL) {
		free(a);
		return NULL;
	}
	a->next = -1;
	a->freeaclp = True;
	return a;
}

SMB_ACL_T sys_acl_get_fd(int fd)
{
	SMB_ACL_T	a;

	if ((a = malloc(sizeof(*a))) == NULL) {
		errno = ENOMEM;
		return NULL;
	}
	if ((a->aclp = acl_get_fd(fd)) == NULL) {
		free(a);
		return NULL;
	}
	a->next = -1;
	a->freeaclp = True;
	return a;
}

int sys_acl_clear_perms(SMB_ACL_PERMSET_T permset_d)
{
	permset_d->ae_perm = 0;

	return 0;
}

int sys_acl_add_perm(SMB_ACL_PERMSET_T permset_d, SMB_ACL_PERM_T perm)
{
	if (perm != SMB_ACL_READ && perm != SMB_ACL_WRITE
	    && perm != SMB_ACL_EXECUTE) {
		errno = EINVAL;
		return -1;
	}

	if (permset_d == NULL) {
		errno = EINVAL;
		return -1;
	}

	permset_d->ae_perm |= perm;

	return 0;
}

int sys_acl_get_perm(SMB_ACL_PERMSET_T permset_d, SMB_ACL_PERM_T perm)
{
	return permset_d->ae_perm & perm;
}

char *sys_acl_to_text(SMB_ACL_T acl_d, ssize_t *len_p)
{
	return acl_to_text(acl_d->aclp, len_p);
}

SMB_ACL_T sys_acl_init(int count)
{
	SMB_ACL_T	a;

	if (count < 0) {
		errno = EINVAL;
		return NULL;
	}

	if ((a = malloc(sizeof(*a) + sizeof(struct acl))) == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	a->next = -1;
	a->freeaclp = False;
	a->aclp = (struct acl *)(&a->aclp + sizeof(struct acl *));
	a->aclp->acl_cnt = 0;

	return a;
}


int sys_acl_create_entry(SMB_ACL_T *acl_p, SMB_ACL_ENTRY_T *entry_p)
{
	SMB_ACL_T	acl_d;
	SMB_ACL_ENTRY_T	entry_d;

	if (acl_p == NULL || entry_p == NULL || (acl_d = *acl_p) == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (acl_d->aclp->acl_cnt >= ACL_MAX_ENTRIES) {
		errno = ENOSPC;
		return -1;
	}

	entry_d		= &acl_d->aclp->acl_entry[acl_d->aclp->acl_cnt++];
	entry_d->ae_tag	= 0;
	entry_d->ae_id	= 0;
	entry_d->ae_perm	= 0;
	*entry_p	= entry_d;

	return 0;
}

int sys_acl_set_tag_type(SMB_ACL_ENTRY_T entry_d, SMB_ACL_TAG_T tag_type)
{
	switch (tag_type) {
		case SMB_ACL_USER:
		case SMB_ACL_USER_OBJ:
		case SMB_ACL_GROUP:
		case SMB_ACL_GROUP_OBJ:
		case SMB_ACL_OTHER:
		case SMB_ACL_MASK:
			entry_d->ae_tag = tag_type;
			break;
		default:
			errno = EINVAL;
			return -1;
	}

	return 0;
}

int sys_acl_set_qualifier(SMB_ACL_ENTRY_T entry_d, void *qual_p)
{
	if (entry_d->ae_tag != SMB_ACL_GROUP
	    && entry_d->ae_tag != SMB_ACL_USER) {
		errno = EINVAL;
		return -1;
	}

	entry_d->ae_id = *((id_t *)qual_p);

	return 0;
}

int sys_acl_set_permset(SMB_ACL_ENTRY_T entry_d, SMB_ACL_PERMSET_T permset_d)
{
	if (permset_d->ae_perm & ~(SMB_ACL_READ|SMB_ACL_WRITE|SMB_ACL_EXECUTE)) {
		return EINVAL;
	}

	entry_d->ae_perm = permset_d->ae_perm;

	return 0;
}

int sys_acl_valid(SMB_ACL_T acl_d)
{
	return acl_valid(acl_d->aclp);
}

int sys_acl_set_file(char *name, SMB_ACL_TYPE_T type, SMB_ACL_T acl_d)
{
	return acl_set_file(name, type, acl_d->aclp);
}

int sys_acl_set_fd(int fd, SMB_ACL_T acl_d)
{
	return acl_set_fd(fd, acl_d->aclp);
}

int sys_acl_free_text(char *text)
{
	return acl_free(text);
}

int sys_acl_free_acl(SMB_ACL_T acl_d) 
{
	if (acl_d->freeaclp) {
		acl_free(acl_d->aclp);
	}
	acl_free(acl_d);
	return 0;
}

#elif defined(HAVE_XFS_ACLS)
/* For Linux SGI/XFS Filesystems    
 * contributed by J Trostel, Connex 
 *                                  */

/* based on the implementation for Solaris by Toomas Soome.. which is 
 * based on the implementation  by Micheal Davidson for Unixware...
 *
 * Linux XFS is a 'work-in-progress'
 * This interface may change...  
 * You've been warned ;->           */

/* First, do the identity mapping */

int sys_acl_get_entry( SMB_ACL_T the_acl, int entry_id, SMB_ACL_ENTRY_T *entry_p)
{
	if( acl_get_entry( the_acl, entry_id, entry_p) >= 0) {
		return 1;
	}
	else {
		return -1;
	}
}

SMB_ACL_T sys_acl_get_file( const char *path_p, SMB_ACL_TYPE_T type)
{
	return acl_get_file( path_p, type);
}

SMB_ACL_T sys_acl_get_fd(int fd)
{
	return acl_get_fd(fd);
}

char *sys_acl_to_text( SMB_ACL_T the_acl, ssize_t *plen)
{
	return acl_to_text( the_acl, plen);
}

int sys_acl_valid( SMB_ACL_T theacl )
{
	return acl_valid(theacl);
}

int sys_acl_set_file( char *name, SMB_ACL_TYPE_T acltype, SMB_ACL_T theacl)
{
	return acl_set_file(name, acltype, theacl);
}

int sys_acl_set_fd( int fd, SMB_ACL_T theacl)
{
	return acl_set_fd(fd, theacl);
}

/* Now the functions I need to define for XFS */

int sys_acl_create_entry( SMB_ACL_T *acl_p, SMB_ACL_ENTRY_T *entry_p)
{
	acl_t acl, newacl;
	acl_entry_t ace;
	int cnt;

	acl = *acl_p;
	ace = *entry_p;

	if((*acl_p == NULL) || (ace == NULL)){
		errno = EINVAL;
		return -1;
	}
	
	cnt = acl->acl_cnt;	
	if( (cnt + 1) > ACL_MAX_ENTRIES  ){
		errno = ENOSPC;
		return -1;
	}

	newacl = (acl_t)malloc(sizeof(struct acl));
	if(newacl == NULL){
		errno = ENOMEM;
		return -1;
	}
	
	*newacl = *acl;
	newacl->acl_entry[cnt] = *ace;
	newacl->acl_cnt = cnt + 1;

	acl_free(*acl_p);
	*acl_p = newacl;
	*entry_p = &newacl->acl_entry[cnt];
	return 0;
}


int sys_acl_get_tag_type( SMB_ACL_ENTRY_T entry_d, SMB_ACL_TAG_T *tag_type_p)
{
	*tag_type_p = entry_d->ae_tag;
	return 0;
}

int sys_acl_get_permset( SMB_ACL_ENTRY_T entry_d, SMB_ACL_PERMSET_T *permset_p)
{
	*permset_p = &entry_d->ae_perm;
	return 0;
}

void *sys_acl_get_qualifier( SMB_ACL_ENTRY_T entry_d)
{
	if (entry_d->ae_tag != SMB_ACL_USER
		&& entry_d->ae_tag != SMB_ACL_GROUP) {
		errno = EINVAL;
		return NULL;
	}	
	return &entry_d->ae_id;
}

int sys_acl_clear_perms(SMB_ACL_PERMSET_T permset)
{
	*permset = 0;
	return 0;
}

int sys_acl_get_perm( SMB_ACL_PERMSET_T permset, SMB_ACL_PERM_T perm)
{
	return (*permset & perm);
}

int sys_acl_add_perm( SMB_ACL_PERMSET_T permset, SMB_ACL_PERM_T perm)
{

// TO DO: Add in ALL possible permissions here
// TO DO: Include extended ones!!

	if (perm != SMB_ACL_READ && perm != SMB_ACL_WRITE && perm != SMB_ACL_EXECUTE) {
		errno = EINVAL;
		return -1;
	}
	
	if(permset == NULL) {
		errno = EINVAL;
		return -1;
	}
	
	*permset |= perm;
	
	return 0;
}

SMB_ACL_T sys_acl_init( int count)
{
	SMB_ACL_T a;
	if((count > ACL_MAX_ENTRIES) || (count < 0)) {
		errno = EINVAL;
		return NULL;
	}
	else {
		a = (struct acl *)malloc(sizeof(struct acl)); // where is this memory freed?
		a->acl_cnt = 0;
		return a;
	}
}

int sys_acl_set_tag_type( SMB_ACL_ENTRY_T entry_d, SMB_ACL_TAG_T tag_type)
{
	
	switch (tag_type) {
		case SMB_ACL_USER:
		case SMB_ACL_USER_OBJ:
		case SMB_ACL_GROUP:
		case SMB_ACL_GROUP_OBJ:
		case SMB_ACL_OTHER:
		case SMB_ACL_MASK:
			entry_d->ae_tag = tag_type;
			break;
		default:
			errno = EINVAL;
			return -1;
	}
	return 0;
}

int sys_acl_set_qualifier( SMB_ACL_ENTRY_T entry_d, void *qual_p)
{
	if(entry_d->ae_tag != SMB_ACL_GROUP &&
		entry_d->ae_tag != SMB_ACL_USER) {
		errno = EINVAL;
		return -1;
	}
	
	entry_d->ae_id = *((uid_t *)qual_p);

	return 0;
}

int sys_acl_set_permset( SMB_ACL_ENTRY_T entry_d, SMB_ACL_PERMSET_T permset_d)
{
// TO DO: expand to extended permissions eventually!

	if(*permset_d & ~(SMB_ACL_READ|SMB_ACL_WRITE|SMB_ACL_EXECUTE)) {
		return EINVAL;
	}

	return 0;
}

int sys_acl_free_text(char *text)
{
	return acl_free(text);
}

int sys_acl_free_acl(SMB_ACL_T the_acl) 
{
	return acl_free(the_acl);
}

#else /* No ACLs. */

int sys_acl_get_entry( SMB_ACL_T the_acl, int entry_id, SMB_ACL_ENTRY_T *entry_p)
{
	errno = ENOSYS;
	return -1;
}

int sys_acl_get_tag_type( SMB_ACL_ENTRY_T entry_d, SMB_ACL_TAG_T *tag_type_p)
{
	errno = ENOSYS;
	return -1;
}

int sys_acl_get_permset( SMB_ACL_ENTRY_T entry_d, SMB_ACL_PERMSET_T *permset_p)
{
	errno = ENOSYS;
	return -1;
}

void *sys_acl_get_qualifier( SMB_ACL_ENTRY_T entry_d)
{
	errno = ENOSYS;
	return NULL;
}

SMB_ACL_T sys_acl_get_file( const char *path_p, SMB_ACL_TYPE_T type)
{
	errno = ENOSYS;
	return (SMB_ACL_T)NULL;
}

SMB_ACL_T sys_acl_get_fd(int fd)
{
	errno = ENOSYS;
	return (SMB_ACL_T)NULL;
}

int sys_acl_clear_perms(SMB_ACL_PERMSET_T permset)
{
	errno = ENOSYS;
	return -1;
}

int sys_acl_add_perm( SMB_ACL_PERMSET_T permset, SMB_ACL_PERM_T perm)
{
	errno = ENOSYS;
	return -1;
}

int sys_acl_get_perm( SMB_ACL_PERMSET_T permset, SMB_ACL_PERM_T perm)
{
	errno = ENOSYS;
	return (permset & perm) ? 1 : 0;
}

char *sys_acl_to_text( SMB_ACL_T the_acl, ssize_t *plen)
{
	errno = ENOSYS;
	return NULL;
}

int sys_acl_free_text(char *text)
{
	errno = ENOSYS;
	return -1;
}

SMB_ACL_T sys_acl_init( int count)
{
	errno = ENOSYS;
	return NULL;
}

int sys_acl_create_entry( SMB_ACL_T *pacl, SMB_ACL_ENTRY_T *pentry)
{
	errno = ENOSYS;
	return -1;
}

int sys_acl_set_tag_type( SMB_ACL_ENTRY_T entry, SMB_ACL_TAG_T tagtype)
{
	errno = ENOSYS;
	return -1;
}

int sys_acl_set_qualifier( SMB_ACL_ENTRY_T entry, void *qual)
{
	errno = ENOSYS;
	return -1;
}

int sys_acl_set_permset( SMB_ACL_ENTRY_T entry, SMB_ACL_PERMSET_T permset)
{
	errno = ENOSYS;
	return -1;
}

int sys_acl_valid( SMB_ACL_T theacl )
{
	errno = ENOSYS;
	return -1;
}

int sys_acl_set_file( char *name, SMB_ACL_TYPE_T acltype, SMB_ACL_T theacl)
{
	errno = ENOSYS;
	return -1;
}

int sys_acl_set_fd( int fd, SMB_ACL_T theacl)
{
	errno = ENOSYS;
	return -1;
}

int sys_acl_free_acl(SMB_ACL_T the_acl) 
{
	errno = ENOSYS;
	return -1;
}
#endif /* No ACLs. */
