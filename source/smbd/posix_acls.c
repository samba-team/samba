#define OLD_NTDOMAIN 1
/*
   Unix SMB/Netbios implementation.
   Version 1.9.
   SMB NT Security Descriptor / Unix permission conversion.
   Copyright (C) Jeremy Allison 1994-2000

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

typedef struct canon_ace {
	struct canon_ace *next, *prev;
	SMB_ACL_TAG_T type;
	mode_t perms;
	DOM_SID sid;
} canon_ace;

/****************************************************************************
 Function to create owner and group SIDs from a SMB_STRUCT_STAT.
****************************************************************************/

static void create_file_sids(SMB_STRUCT_STAT *psbuf, DOM_SID *powner_sid, DOM_SID *pgroup_sid)
{
	uid_to_sid( powner_sid, psbuf->st_uid );
	gid_to_sid( pgroup_sid, psbuf->st_gid );
}

/****************************************************************************
 Map canon_ace perms to NT.
****************************************************************************/

static SEC_ACCESS map_canon_ace_perms(int *pacl_type, DOM_SID *powner_sid, canon_ace *ace)
{
	SEC_ACCESS sa;
	uint32 nt_mask = 0;

	*pacl_type = SEC_ACE_TYPE_ACCESS_ALLOWED;

	if((ace->perms & (S_IRWXU|S_IWUSR|S_IXUSR)) == (S_IRWXU|S_IWUSR|S_IXUSR)) {
			nt_mask = UNIX_ACCESS_RWX;
	} else if((ace->perms & (S_IRWXU|S_IWUSR|S_IXUSR)) == 0) {
		/*
		 * Here we differentiate between the owner and any other user.
		 */
		if (sid_equal(powner_sid, &ace->sid)) {
			nt_mask = UNIX_ACCESS_NONE;
		} else {
			/* Not owner, no access. */
			nt_mask = 0;
		}
	} else {
		nt_mask |= ((ace->perms & S_IRWXU) ? UNIX_ACCESS_R : 0 );
		nt_mask |= ((ace->perms & S_IWUSR) ? UNIX_ACCESS_W : 0 );
		nt_mask |= ((ace->perms & S_IXUSR) ? UNIX_ACCESS_X : 0 );
	}

	DEBUG(10,("map_canon_ace_perms: Mapped (UNIX) %x to (NT) %x\n",
			(unsigned int)ace->perms, (unsigned int)nt_mask ));

	init_sec_access(&sa,nt_mask);
	return sa;
}

/****************************************************************************
 Map NT perms to UNIX.
****************************************************************************/

#define FILE_SPECIFIC_READ_BITS (FILE_READ_DATA|FILE_READ_EA|FILE_READ_ATTRIBUTES)
#define FILE_SPECIFIC_WRITE_BITS (FILE_WRITE_DATA|FILE_APPEND_DATA|FILE_WRITE_EA|FILE_WRITE_ATTRIBUTES)
#define FILE_SPECIFIC_EXECUTE_BITS (FILE_EXECUTE)

static mode_t map_nt_perms( SEC_ACCESS sec_access, int type)
{
  mode_t mode = 0;

  switch(type) {
  case S_IRUSR:
    if(sec_access.mask & GENERIC_ALL_ACCESS)
      mode = S_IRUSR|S_IWUSR|S_IXUSR;
    else {
      mode |= (sec_access.mask & (GENERIC_READ_ACCESS|FILE_SPECIFIC_READ_BITS)) ? S_IRUSR : 0;
      mode |= (sec_access.mask & (GENERIC_WRITE_ACCESS|FILE_SPECIFIC_WRITE_BITS)) ? S_IWUSR : 0;
      mode |= (sec_access.mask & (GENERIC_EXECUTE_ACCESS|FILE_SPECIFIC_EXECUTE_BITS)) ? S_IXUSR : 0;
    }
    break;
  case S_IRGRP:
    if(sec_access.mask & GENERIC_ALL_ACCESS)
      mode = S_IRGRP|S_IWGRP|S_IXGRP;
    else {
      mode |= (sec_access.mask & (GENERIC_READ_ACCESS|FILE_SPECIFIC_READ_BITS)) ? S_IRGRP : 0;
      mode |= (sec_access.mask & (GENERIC_WRITE_ACCESS|FILE_SPECIFIC_WRITE_BITS)) ? S_IWGRP : 0;
      mode |= (sec_access.mask & (GENERIC_EXECUTE_ACCESS|FILE_SPECIFIC_EXECUTE_BITS)) ? S_IXGRP : 0;
    }
    break;
  case S_IROTH:
    if(sec_access.mask & GENERIC_ALL_ACCESS)
      mode = S_IROTH|S_IWOTH|S_IXOTH;
    else {
      mode |= (sec_access.mask & (GENERIC_READ_ACCESS|FILE_SPECIFIC_READ_BITS)) ? S_IROTH : 0;
      mode |= (sec_access.mask & (GENERIC_WRITE_ACCESS|FILE_SPECIFIC_WRITE_BITS)) ? S_IWOTH : 0;
      mode |= (sec_access.mask & (GENERIC_EXECUTE_ACCESS|FILE_SPECIFIC_EXECUTE_BITS)) ? S_IXOTH : 0;
    }
    break;
  }

  return mode;
}

/****************************************************************************
 Unpack a SEC_DESC into a owner, group and set of UNIX permissions.
****************************************************************************/

static BOOL unpack_nt_permissions(SMB_STRUCT_STAT *psbuf, uid_t *puser, gid_t *pgrp, mode_t *pmode,
                                  uint32 security_info_sent, SEC_DESC *psd, BOOL is_directory)
{
  extern DOM_SID global_sid_World;
  DOM_SID owner_sid;
  DOM_SID grp_sid;
  DOM_SID file_owner_sid;
  DOM_SID file_grp_sid;
  SEC_ACL *dacl = psd->dacl;
  BOOL all_aces_are_inherit_only = (is_directory ? True : False);
  int i;
  enum SID_NAME_USE sid_type;

  *pmode = 0;
  *puser = (uid_t)-1;
  *pgrp = (gid_t)-1;

  if(security_info_sent == 0) {
    DEBUG(0,("unpack_nt_permissions: no security info sent !\n"));
    return False;
  }

  /*
   * Windows 2000 sends the owner and group SIDs as the logged in
   * user, not the connected user. But it still sends the file
   * owner SIDs on an ACL set. So we need to check for the file
   * owner and group SIDs as well as the owner SIDs. JRA.
   */
 
  create_file_sids(psbuf, &file_owner_sid, &file_grp_sid);

  /*
   * Validate the owner and group SID's.
   */

  memset(&owner_sid, '\0', sizeof(owner_sid));
  memset(&grp_sid, '\0', sizeof(grp_sid));

  DEBUG(5,("unpack_nt_permissions: validating owner_sid.\n"));

  /*
   * Don't immediately fail if the owner sid cannot be validated.
   * This may be a group chown only set.
   */

  if (security_info_sent & OWNER_SECURITY_INFORMATION) {
	sid_copy(&owner_sid, psd->owner_sid);
    if (!sid_to_uid( &owner_sid, puser, &sid_type))
      DEBUG(3,("unpack_nt_permissions: unable to validate owner sid.\n"));
  }

  /*
   * Don't immediately fail if the group sid cannot be validated.
   * This may be an owner chown only set.
   */

  if (security_info_sent & GROUP_SECURITY_INFORMATION) {
	sid_copy(&grp_sid, psd->grp_sid);
    if (!sid_to_gid( &grp_sid, pgrp, &sid_type))
      DEBUG(3,("unpack_nt_permissions: unable to validate group sid.\n"));
  }

  /*
   * If no DACL then this is a chown only security descriptor.
   */

  if(!(security_info_sent & DACL_SECURITY_INFORMATION) || !dacl) {
    *pmode = 0;
    return True;
  }

  /*
   * Now go through the DACL and ensure that
   * any owner/group sids match.
   */

  for(i = 0; i < dacl->num_aces; i++) {
    DOM_SID ace_sid;
    SEC_ACE *psa = &dacl->ace[i];

    if((psa->type != SEC_ACE_TYPE_ACCESS_ALLOWED) &&
       (psa->type != SEC_ACE_TYPE_ACCESS_DENIED)) {
      DEBUG(3,("unpack_nt_permissions: unable to set anything but an ALLOW or DENY ACE.\n"));
      return False;
    }

    /*
     * Ignore or remove bits we don't care about on a directory ACE.
     */

    if(is_directory) {
      if(psa->flags & SEC_ACE_FLAG_INHERIT_ONLY) {
        DEBUG(3,("unpack_nt_permissions: ignoring inherit only ACE.\n"));
        continue;
      }

      /*
       * At least one of the ACE entries wasn't inherit only.
       * Flag this so we know the returned mode is valid.
       */

      all_aces_are_inherit_only = False;
    }

    /*
     * Windows 2000 sets these flags even on *file* ACE's. This is wrong
     * but we can ignore them for now. Revisit this when we go to POSIX
     * ACLs on directories.
     */

    psa->flags &= ~(SEC_ACE_FLAG_OBJECT_INHERIT|SEC_ACE_FLAG_CONTAINER_INHERIT);

    if(psa->flags != 0) {
      DEBUG(1,("unpack_nt_permissions: unable to set ACE flags (%x).\n", 
            (unsigned int)psa->flags));
      return False;
    }

    /*
     * The security mask may be UNIX_ACCESS_NONE which should map into
     * no permissions (we overload the WRITE_OWNER bit for this) or it
     * should be one of the ALL/EXECUTE/READ/WRITE bits. Arrange for this
     * to be so. Any other bits override the UNIX_ACCESS_NONE bit.
     */

    psa->info.mask &= (GENERIC_ALL_ACCESS|GENERIC_EXECUTE_ACCESS|GENERIC_WRITE_ACCESS|
                     GENERIC_READ_ACCESS|UNIX_ACCESS_NONE|FILE_ALL_ACCESS);

    if(psa->info.mask != UNIX_ACCESS_NONE)
      psa->info.mask &= ~UNIX_ACCESS_NONE;

    sid_copy(&ace_sid, &psa->sid);

    if(sid_equal(&ace_sid, &file_owner_sid)) {
      /*
       * Map the desired permissions into owner perms.
       */

      if(psa->type == SEC_ACE_TYPE_ACCESS_ALLOWED)
        *pmode |= map_nt_perms( psa->info, S_IRUSR);
      else
        *pmode &= ~(map_nt_perms( psa->info, S_IRUSR));

    } else if( sid_equal(&ace_sid, &file_grp_sid)) {
      /*
       * Map the desired permissions into group perms.
       */

      if(psa->type == SEC_ACE_TYPE_ACCESS_ALLOWED)
        *pmode |= map_nt_perms( psa->info, S_IRGRP);
      else
        *pmode &= ~(map_nt_perms( psa->info, S_IRGRP));

    } else if( sid_equal(&ace_sid, &global_sid_World)) {
      /*
       * Map the desired permissions into other perms.
       */

      if(psa->type == SEC_ACE_TYPE_ACCESS_ALLOWED)
        *pmode |= map_nt_perms( psa->info, S_IROTH);
      else
        *pmode &= ~(map_nt_perms( psa->info, S_IROTH));

    } else {
      DEBUG(0,("unpack_nt_permissions: unknown SID used in ACL.\n"));
      return False;
    }
  }

  if (is_directory && all_aces_are_inherit_only) {
    /*
     * Windows 2000 is doing one of these weird 'inherit acl'
     * traverses to conserve NTFS ACL resources. Just pretend
     * there was no DACL sent. JRA.
     */

    DEBUG(10,("unpack_nt_permissions: Win2k inherit acl traverse. Ignoring DACL.\n"));
    free_sec_acl(&psd->dacl);
  }

  return True;
}

/****************************************************************************
 Map generic UNIX permissions to POSIX ACL perms.
****************************************************************************/

static mode_t convert_permset_to_mode_t(SMB_ACL_PERMSET_T permset)
{
	mode_t ret = 0;

	ret |= (sys_acl_get_perm(permset, SMB_ACL_READ) ? S_IRUSR : 0);
	ret |= (sys_acl_get_perm(permset, SMB_ACL_WRITE) ? S_IWUSR : 0);
	ret |= (sys_acl_get_perm(permset, SMB_ACL_EXECUTE) ? S_IXUSR : 0);

	return ret;
}

/****************************************************************************
 Map generic UNIX permissions to POSIX ACL perms.
****************************************************************************/

static mode_t unix_perms_to_acl_perms(mode_t mode, int r_mask, int w_mask, int x_mask)
{
	mode_t ret = 0;

	if (mode & r_mask)
		ret |= S_IRUSR;
	if (mode & w_mask)
		ret |= S_IWUSR;
	if (mode & x_mask)
		ret |= S_IXUSR;

	return ret;
}

/****************************************************************************
 Count a linked list of canonical ACE entries.
****************************************************************************/

static size_t count_canon_ace_list( canon_ace *list_head )
{
	size_t count = 0;
	canon_ace *ace;

	for (ace = list_head; ace; ace = ace->next)
		count++;

	return count;
}

/****************************************************************************
 Free a linked list of canonical ACE entries.
****************************************************************************/

static void free_canon_ace_list( canon_ace *list_head )
{
	while (list_head) {
		canon_ace *old_head = list_head;
		DLIST_REMOVE(list_head, list_head);
		free(old_head);
	}
}

/******************************************************************************
 Fall back to the generic 3 element UNIX permissions.
********************************************************************************/

static canon_ace *unix_canonicalise_acl(files_struct *fsp, SMB_STRUCT_STAT *psbuf,
										DOM_SID *powner, DOM_SID *pgroup)
{
	extern DOM_SID global_sid_World;
	canon_ace *list_head = NULL;
	canon_ace *owner_ace = NULL;
	canon_ace *group_ace = NULL;
	canon_ace *other_ace = NULL;

	/*
	 * Create 3 linked list entries.
	 */

	if ((owner_ace = (canon_ace *)malloc(sizeof(canon_ace))) == NULL)
		goto fail;

	if ((group_ace = (canon_ace *)malloc(sizeof(canon_ace))) == NULL)
		goto fail;

	if ((other_ace = (canon_ace *)malloc(sizeof(canon_ace))) == NULL)
		goto fail;

	ZERO_STRUCTP(owner_ace);
	ZERO_STRUCTP(group_ace);
	ZERO_STRUCTP(other_ace);

	owner_ace->type = SMB_ACL_USER_OBJ;
	owner_ace->sid = *powner;

	group_ace->type = SMB_ACL_GROUP_OBJ;
	group_ace->sid = *pgroup;

	other_ace->type = SMB_ACL_OTHER;
	other_ace->sid = global_sid_World;

	if (!fsp->is_directory) {
		owner_ace->perms = unix_perms_to_acl_perms(psbuf->st_mode, S_IRUSR, S_IWUSR, S_IXUSR);
		group_ace->perms = unix_perms_to_acl_perms(psbuf->st_mode, S_IRGRP, S_IWGRP, S_IXGRP);
		other_ace->perms = unix_perms_to_acl_perms(psbuf->st_mode, S_IROTH, S_IWOTH, S_IXOTH);
	} else {
		mode_t mode = unix_mode( fsp->conn, FILE_ATTRIBUTE_ARCHIVE, fsp->fsp_name);

		owner_ace->perms = unix_perms_to_acl_perms(mode, S_IRUSR, S_IWUSR, S_IXUSR);
		group_ace->perms = unix_perms_to_acl_perms(mode, S_IRGRP, S_IWGRP, S_IXGRP);
		other_ace->perms = unix_perms_to_acl_perms(mode, S_IROTH, S_IWOTH, S_IXOTH);
	}

	DLIST_ADD(list_head, other_ace);
	DLIST_ADD(list_head, group_ace);
	DLIST_ADD(list_head, owner_ace);

	return list_head;

  fail:

	safe_free(owner_ace);
	safe_free(group_ace);
	safe_free(other_ace);

	return NULL;
}

/****************************************************************************
 Create a linked list of canonical ACE entries. This is sorted so that DENY
 entries are at the front of the list, as NT requires.
****************************************************************************/

static canon_ace *canonicalise_acl( SMB_ACL_T posix_acl, SMB_STRUCT_STAT *psbuf)
{
	extern DOM_SID global_sid_World;
	mode_t acl_mask = (S_IRUSR|S_IWUSR|S_IXUSR);
	canon_ace *list_head = NULL;
	canon_ace *ace = NULL;
	canon_ace *next_ace = NULL;
	int entry_id = SMB_ACL_FIRST_ENTRY;
	SMB_ACL_ENTRY_T entry;

	while ( sys_acl_get_entry(posix_acl, entry_id, &entry) == 1) {
		SMB_ACL_TAG_T tagtype;
		SMB_ACL_PERMSET_T permset;
		DOM_SID sid;

		/* get_next... */
		if (entry_id == SMB_ACL_FIRST_ENTRY)
			entry_id = SMB_ACL_NEXT_ENTRY;

		/* Is this a MASK entry ? */
		if (sys_acl_get_tag_type(entry, &tagtype) == -1)
			continue;

		if (sys_acl_get_permset(entry, &permset) == -1)
			continue;

		/* Decide which SID to use based on the ACL type. */
		switch(tagtype) {
			case SMB_ACL_USER_OBJ:
				/* Get the SID from the owner. */
				uid_to_sid( &sid, psbuf->st_uid );
				break;
			case SMB_ACL_USER:
				{
					uid_t *puid = (uid_t *)sys_acl_get_qualifier(entry);
					if (puid == NULL) {
						DEBUG(0,("canonicalise_acl: Failed to get uid.\n"));
						continue;
					}
					uid_to_sid( &sid, *puid);
					break;
				}
			case SMB_ACL_GROUP_OBJ:
				/* Get the SID from the owning group. */
				gid_to_sid( &sid, psbuf->st_gid );
				break;
			case SMB_ACL_GROUP:
				{
					gid_t *pgid = (gid_t *)sys_acl_get_qualifier(entry);
					if (pgid == NULL) {
						DEBUG(0,("canonicalise_acl: Failed to get gid.\n"));
						continue;
					}
					gid_to_sid( &sid, *pgid);
					break;
				}
			case SMB_ACL_MASK:
				acl_mask = convert_permset_to_mode_t(permset);
				continue; /* Don't count the mask as an entry. */
			case SMB_ACL_OTHER:
				/* Use the Everyone SID */
				sid = global_sid_World;
				break;
			default:
				DEBUG(0,("canonicalise_acl: Unknown tagtype %u\n", (unsigned int)tagtype));
				continue;
		}

		/*
		 * Add this entry to the list.
		 */

		if ((ace = (canon_ace *)malloc(sizeof(canon_ace))) == NULL)
			goto fail;

		ZERO_STRUCTP(ace);
		ace->type = tagtype;
		ace->perms = convert_permset_to_mode_t(permset);
		ace->sid = sid;
		 
		DLIST_ADD(list_head, ace);
	}

	/*
	 * Now go through the list, masking the permissions with the
	 * acl_mask. If the permissions are 0 it should be listed
	 * first.
	 */

	for ( ace = list_head; ace; ace = next_ace) {
		next_ace = ace->next;

		/* Masks are only applied to entries other than USER_OBJ and OTHER. */
		if (ace->type != SMB_ACL_OTHER && ace->type != SMB_ACL_USER_OBJ)
			ace->perms &= acl_mask;

		if (ace->perms == 0)
			DLIST_PROMOTE(list_head, ace);
	}

	if( DEBUGLVL( 10 ) ) {
		char *acl_text = sys_acl_to_text( posix_acl, NULL);

		dbgtext("canonicalize_acl: processed acl %s\n", acl_text == NULL ? "NULL" : acl_text );
		if (acl_text)
			sys_acl_free(acl_text);
	}

	return list_head;

  fail:

	free_canon_ace_list(list_head);
	return NULL;
}

/****************************************************************************
 Reply to query a security descriptor from an fsp. If it succeeds it allocates
 the space for the return elements and returns the size needed to return the
 security descriptor. This should be the only external function needed for
 the UNIX style get ACL.
****************************************************************************/

size_t get_nt_acl(files_struct *fsp, SEC_DESC **ppdesc)
{
	SMB_STRUCT_STAT sbuf;
	SEC_ACE *nt_ace_list;
	DOM_SID owner_sid;
	DOM_SID group_sid;
	size_t sd_size = 0;
	SEC_ACL *psa = NULL;
	size_t num_acls = 0;
	size_t num_dir_acls = 0;
	size_t num_aces = 0;
	SMB_ACL_T posix_acl = NULL;
	SMB_ACL_T dir_acl = NULL;
	canon_ace *file_ace = NULL;
	canon_ace *dir_ace = NULL;
 
	*ppdesc = NULL;

	if(fsp->is_directory || fsp->fd == -1) {

		/* Get the stat struct for the owner info. */
		if(vfs_stat(fsp->conn,fsp->fsp_name, &sbuf) != 0) {
			return 0;
		}
		/*
		 * Get the ACL from the path.
		 */

		posix_acl = sys_acl_get_file( dos_to_unix(fsp->fsp_name, False), SMB_ACL_TYPE_ACCESS);

		/*
		 * If it's a directory get the default POSIX ACL.
		 */

		if(fsp->is_directory)
			dir_acl = sys_acl_get_file( dos_to_unix(fsp->fsp_name, False), SMB_ACL_TYPE_DEFAULT);

	} else {

		/* Get the stat struct for the owner info. */
		if(vfs_fstat(fsp,fsp->fd,&sbuf) != 0) {
			return 0;
		}
		/*
		 * Get the ACL from the fd.
		 */
		posix_acl = sys_acl_get_fd(fsp->fd);
	}

	DEBUG(5,("get_nt_acl : file ACL %s, directory ACL %s\n",
			posix_acl ? "present" :  "absent",
			dir_acl ? "present" :  "absent" ));

	/*
	 * Get the owner, group and world SIDs.
	 */

	create_file_sids(&sbuf, &owner_sid, &group_sid);

	/* Create the canon_ace lists. */
	if (posix_acl)
		file_ace = canonicalise_acl( posix_acl, &sbuf);
	else
		file_ace = unix_canonicalise_acl(fsp, &sbuf, &owner_sid, &group_sid);

	num_acls = count_canon_ace_list(file_ace);

	if (fsp->is_directory) { 
		if (dir_ace)
			dir_ace = canonicalise_acl( dir_acl, &sbuf);
		else
			dir_ace = unix_canonicalise_acl(fsp, &sbuf, &owner_sid, &group_sid);

		num_dir_acls = count_canon_ace_list(dir_ace);
	}

	/* Allocate the ace list. */
	if ((nt_ace_list = (SEC_ACE *)malloc((num_acls + num_dir_acls)* sizeof(SEC_ACE))) == NULL) {
		DEBUG(0,("get_nt_acl: Unable to malloc space for nt_ace_list.\n"));
		goto done;
	}

	memset(nt_ace_list, '\0', (num_acls + num_dir_acls) * sizeof(SEC_ACE) );

	/*
	 * Create the NT ACE list from the canonical ace lists.
	 */

	{
		canon_ace *ace;
		int nt_acl_type;
		int i;

		ace = file_ace;

		for (i = 0; i < num_acls; i++, ace = ace->next) {
			SEC_ACCESS acc = map_canon_ace_perms(&nt_acl_type, &owner_sid, ace );
			init_sec_ace(&nt_ace_list[num_aces++], &ace->sid, nt_acl_type, acc, 0);
		}

		ace = dir_ace;

		for (i = 0; i < num_dir_acls; i++, ace = ace->next) {
			SEC_ACCESS acc = map_canon_ace_perms(&nt_acl_type, &owner_sid, ace );
			init_sec_ace(&nt_ace_list[num_aces++], &ace->sid, nt_acl_type, acc, 
					SEC_ACE_FLAG_OBJECT_INHERIT|SEC_ACE_FLAG_CONTAINER_INHERIT|SEC_ACE_FLAG_INHERIT_ONLY);
		}
	}

	if (num_acls) {
		if((psa = make_sec_acl( ACL_REVISION, num_aces, nt_ace_list)) == NULL) {
			DEBUG(0,("get_nt_acl: Unable to malloc space for acl.\n"));
			goto done;
		}
	}

	*ppdesc = make_standard_sec_desc( &owner_sid, &group_sid, psa, &sd_size);

	if(!*ppdesc) {
		DEBUG(0,("get_nt_acl: Unable to malloc space for security descriptor.\n"));
		sd_size = 0;
	}

  done:

	if (posix_acl)	
		sys_acl_free(posix_acl);
	if (dir_acl)
		sys_acl_free(dir_acl);
	if (file_ace)
		free_canon_ace_list(file_ace);
	if (dir_ace)
		free_canon_ace_list(dir_ace);
	if (nt_ace_list)
		free(nt_ace_list);
	if (psa)
		free_sec_acl(&psa);

	return sd_size;
}

/****************************************************************************
 Reply to set a security descriptor on an fsp. security_info_sent is the
 description of the following NT ACL.
 This should be the only external function needed for the UNIX style set ACL.
****************************************************************************/

BOOL set_nt_acl(files_struct *fsp, uint32 security_info_sent, SEC_DESC *psd)
{
  connection_struct *conn = fsp->conn;
  uid_t user = (uid_t)-1;
  gid_t grp = (gid_t)-1;
  mode_t perms = 0;
  SMB_STRUCT_STAT sbuf;  
  BOOL got_dacl = False;

  /*
   * Get the current state of the file.
   */

  if(fsp->is_directory || fsp->fd == -1) {
    if(vfs_stat(fsp->conn,fsp->fsp_name, &sbuf) != 0)
      return False;
  } else {
    if(conn->vfs_ops.fstat(fsp,fsp->fd,&sbuf) != 0)
      return False;
  }

  /*
   * Unpack the user/group/world id's and permissions.
   */

  if (!unpack_nt_permissions( &sbuf, &user, &grp, &perms, security_info_sent, psd, fsp->is_directory))
    return False;

  if (psd->dacl != NULL)
    got_dacl = True;

  /*
   * Do we need to chown ?
   */

  if((user != (uid_t)-1 || grp != (uid_t)-1) && (sbuf.st_uid != user || sbuf.st_gid != grp)) {

    DEBUG(3,("call_nt_transact_set_security_desc: chown %s. uid = %u, gid = %u.\n",
          fsp->fsp_name, (unsigned int)user, (unsigned int)grp ));

    if(vfs_chown( fsp->conn, fsp->fsp_name, user, grp) == -1) {
      DEBUG(3,("call_nt_transact_set_security_desc: chown %s, %u, %u failed. Error = %s.\n",
            fsp->fsp_name, (unsigned int)user, (unsigned int)grp, strerror(errno) ));
      return False;
    }

    /*
     * Recheck the current state of the file, which may have changed.
     * (suid/sgid bits, for instance)
     */

    if(fsp->is_directory) {
      if(vfs_stat(fsp->conn, fsp->fsp_name, &sbuf) != 0) {
        return False;
      }
    } else {

      int ret;
    
      if(fsp->fd == -1)
        ret = vfs_stat(fsp->conn, fsp->fsp_name, &sbuf);
      else
        ret = conn->vfs_ops.fstat(fsp,fsp->fd,&sbuf);
  
      if(ret != 0)
        return False;
    }
  }

  /*
   * Only change security if we got a DACL.
   */

  if((security_info_sent & DACL_SECURITY_INFORMATION) && got_dacl) {

    /*
     * Check to see if we need to change anything.
     * Enforce limits on modified bits *only*. Don't enforce masks
	 * on bits not changed by the user.
     */

    if(fsp->is_directory) {

      perms &= (lp_dir_security_mask(SNUM(conn)) | sbuf.st_mode);
      perms |= (lp_force_dir_security_mode(SNUM(conn)) & ( perms ^ sbuf.st_mode ));

    } else {

      perms &= (lp_security_mask(SNUM(conn)) | sbuf.st_mode); 
      perms |= (lp_force_security_mode(SNUM(conn)) & ( perms ^ sbuf.st_mode ));

    }

    /*
     * Preserve special bits.
     */

    perms |= (sbuf.st_mode & ~0777);

    /*
     * Do we need to chmod ?
     */

    if(sbuf.st_mode != perms) {

      DEBUG(3,("call_nt_transact_set_security_desc: chmod %s. perms = 0%o.\n",
            fsp->fsp_name, (unsigned int)perms ));

      if(conn->vfs_ops.chmod(conn,dos_to_unix(fsp->fsp_name, False), perms) == -1) {
        DEBUG(3,("call_nt_transact_set_security_desc: chmod %s, 0%o failed. Error = %s.\n",
              fsp->fsp_name, (unsigned int)perms, strerror(errno) ));
        return False;
      }
    }
  }

  return True;
}
#undef OLD_NTDOMAIN





