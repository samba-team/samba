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

/****************************************************************************
 Function to create owner and group SIDs from a SMB_STRUCT_STAT.
****************************************************************************/

static void create_file_sids(SMB_STRUCT_STAT *psbuf, DOM_SID *powner_sid, DOM_SID *pgroup_sid)
{
  extern DOM_SID global_sam_sid;

  sid_copy(powner_sid, &global_sam_sid);
  sid_copy(pgroup_sid, &global_sam_sid);
  sid_append_rid(powner_sid, pdb_uid_to_user_rid(psbuf->st_uid));
  sid_append_rid(pgroup_sid, pdb_gid_to_group_rid(psbuf->st_gid));
}

/****************************************************************************
 Map unix perms to NT.
****************************************************************************/

static SEC_ACCESS map_unix_perms( int *pacl_type, mode_t perm, int r_mask, int w_mask, int x_mask, BOOL is_directory)
{
	SEC_ACCESS sa;
	uint32 nt_mask = 0;

	*pacl_type = SEC_ACE_TYPE_ACCESS_ALLOWED;

	if((perm & (r_mask|w_mask|x_mask)) == (r_mask|w_mask|x_mask)) {
		nt_mask = UNIX_ACCESS_RWX;
	} else if((perm & (r_mask|w_mask|x_mask)) == 0) {
		nt_mask = UNIX_ACCESS_NONE;
	} else {
		nt_mask |= (perm & r_mask) ? UNIX_ACCESS_R : 0;
		if(is_directory)
			nt_mask |= (perm & w_mask) ? UNIX_ACCESS_W : 0;
		else
			nt_mask |= (perm & w_mask) ? UNIX_ACCESS_W : 0;
		nt_mask |= (perm & x_mask) ? UNIX_ACCESS_X : 0;
	}
	init_sec_access(&sa,nt_mask);
	return sa;
}

/****************************************************************************
 Validate a SID.
****************************************************************************/

static BOOL validate_unix_sid( DOM_SID *psid, uint32 *prid, DOM_SID *sd_sid)
{
  extern DOM_SID global_sam_sid;
  DOM_SID sid;

  if(!sd_sid) {
    DEBUG(5,("validate_unix_sid: sid missing.\n"));
    return False;
  }

  sid_copy(psid, sd_sid);
  sid_copy(&sid, sd_sid);

  if(!sid_split_rid(&sid, prid)) {
    DEBUG(5,("validate_unix_sid: cannot get RID from sid.\n"));
    return False;
  }

  if(!sid_equal( &sid, &global_sam_sid)) {
    DEBUG(5,("validate_unix_sid: sid is not ours.\n"));
    return False;
  }

  return True;
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
  uint32 owner_rid;
  uint32 grp_rid;
  SEC_ACL *dacl = psd->dacl;
  BOOL all_aces_are_inherit_only = (is_directory ? True : False);
  int i;

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

  if(!validate_unix_sid( &owner_sid, &owner_rid, psd->owner_sid))
    DEBUG(3,("unpack_nt_permissions: unable to validate owner sid.\n"));
  else if(security_info_sent & OWNER_SECURITY_INFORMATION)
    *puser = pdb_user_rid_to_uid(owner_rid);

  /*
   * Don't immediately fail if the group sid cannot be validated.
   * This may be an owner chown only set.
   */

  if(!validate_unix_sid( &grp_sid, &grp_rid, psd->grp_sid))
    DEBUG(3,("unpack_nt_permissions: unable to validate group sid.\n"));
  else if(security_info_sent & GROUP_SECURITY_INFORMATION)
    *pgrp = pdb_user_rid_to_gid(grp_rid);

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
                     GENERIC_READ_ACCESS|UNIX_ACCESS_NONE|FILE_ALL_ATTRIBUTES);

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
 Reply to query a security descriptor from an fsp. If it succeeds it allocates
 the space for the return elements and returns the size needed to return the
 security descriptor. This should be the only external function needed for
 the UNIX style get ACL.
****************************************************************************/

size_t get_nt_acl(files_struct *fsp, SEC_DESC **ppdesc)
{
  extern DOM_SID global_sid_World;
  SMB_STRUCT_STAT sbuf;
  SEC_ACE ace_list[6];
  DOM_SID owner_sid;
  DOM_SID group_sid;
  size_t sec_desc_size;
  SEC_ACL *psa = NULL;
  SEC_ACCESS owner_access;
  int owner_acl_type;
  SEC_ACCESS group_access;
  int grp_acl_type;
  SEC_ACCESS other_access;
  int other_acl_type;
  int num_acls = 0;
 
  *ppdesc = NULL;

  if(!lp_nt_acl_support()) {
    sid_copy( &owner_sid, &global_sid_World);
    sid_copy( &group_sid, &global_sid_World);
  } else {

    if(fsp->is_directory || fsp->fd == -1) {
      if(dos_stat(fsp->fsp_name, &sbuf) != 0) {
        return 0;
      }
    } else {
      if(fsp->conn->vfs_ops.fstat(fsp->fd,&sbuf) != 0) {
        return 0;
      }
    }

    /*
     * Get the owner, group and world SIDs.
     */

    create_file_sids(&sbuf, &owner_sid, &group_sid);

    /*
     * Create the generic 3 element UNIX acl.
     */

    owner_access = map_unix_perms(&owner_acl_type, sbuf.st_mode,
							S_IRUSR, S_IWUSR, S_IXUSR, fsp->is_directory);
    group_access = map_unix_perms(&grp_acl_type, sbuf.st_mode,
							S_IRGRP, S_IWGRP, S_IXGRP, fsp->is_directory);
    other_access = map_unix_perms(&other_acl_type, sbuf.st_mode,
							S_IROTH, S_IWOTH, S_IXOTH, fsp->is_directory);

    if(owner_access.mask)
      init_sec_ace(&ace_list[num_acls++], &owner_sid, owner_acl_type,
                   owner_access, 0);

    if(group_access.mask)
      init_sec_ace(&ace_list[num_acls++], &group_sid, grp_acl_type,
                   group_access, 0);

    if(other_access.mask)
      init_sec_ace(&ace_list[num_acls++], &global_sid_World, other_acl_type,
                   other_access, 0);

    if(fsp->is_directory) {
      /*
       * For directory ACLs we also add in the inherited permissions
       * ACE entries. These are the permissions a file would get when
       * being created in the directory.
       */
      mode_t mode = unix_mode( fsp->conn, FILE_ATTRIBUTE_ARCHIVE, fsp->fsp_name);

      owner_access = map_unix_perms(&owner_acl_type, mode,
                            S_IRUSR, S_IWUSR, S_IXUSR, fsp->is_directory);
      group_access = map_unix_perms(&grp_acl_type, mode,
                            S_IRGRP, S_IWGRP, S_IXGRP, fsp->is_directory);
      other_access = map_unix_perms(&other_acl_type, mode,
                            S_IROTH, S_IWOTH, S_IXOTH, fsp->is_directory);

      if(owner_access.mask)
        init_sec_ace(&ace_list[num_acls++], &owner_sid, owner_acl_type,
                     owner_access, SEC_ACE_FLAG_OBJECT_INHERIT|SEC_ACE_FLAG_INHERIT_ONLY);

      if(group_access.mask)
        init_sec_ace(&ace_list[num_acls++], &group_sid, grp_acl_type,
                     group_access, SEC_ACE_FLAG_OBJECT_INHERIT|SEC_ACE_FLAG_INHERIT_ONLY);

      if(other_access.mask)
        init_sec_ace(&ace_list[num_acls++], &global_sid_World, other_acl_type,
                     other_access, SEC_ACE_FLAG_OBJECT_INHERIT|SEC_ACE_FLAG_INHERIT_ONLY);
    }

    if(num_acls)
      if((psa = make_sec_acl( 3, num_acls, ace_list)) == NULL) {
        DEBUG(0,("get_nt_acl: Unable to malloc space for acl.\n"));
        return 0;
      }
  }

  *ppdesc = make_standard_sec_desc( &owner_sid, &group_sid, psa, &sec_desc_size);

  if(!*ppdesc) {
    DEBUG(0,("get_nt_acl: Unable to malloc space for security descriptor.\n"));
    sec_desc_size = 0;
  }

  free_sec_acl(&psa);

  return sec_desc_size;
}

/****************************************************************************
 Reply to set a security descriptor on an fsp. If it succeeds it returns
 This should be the only external function needed for the UNIX style set ACL.
****************************************************************************/

BOOL set_nt_acl(files_struct *fsp, SEC_DESC *pdesc)
{
  uid_t user = (uid_t)-1;
  gid_t grp = (gid_t)-1;
  mode_t perms = 0;
  SMB_STRUCT_STAT sbuf;  
  BOOL got_dacl = False;

  /*
   * Get the current state of the file.
   */

  if(fsp->is_directory) {
    if(dos_stat(fsp->fsp_name, &sbuf) != 0)
      return False;
  } else {

    int ret;

    if(fsp->fd == -1)
      ret = conn->vfs_ops.stat(dos_to_unix(fsp->fsp_name,False), &sbuf);
    else
      ret = conn->vfs_ops.fstat(fsp->fd,&sbuf);

    if(ret != 0)
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

    if(dos_chown( fsp->fsp_name, user, grp) == -1) {
      DEBUG(3,("call_nt_transact_set_security_desc: chown %s, %u, %u failed. Error = %s.\n",
            fsp->fsp_name, (unsigned int)user, (unsigned int)grp, strerror(errno) ));
      return False;
    }

    /*
     * Recheck the current state of the file, which may have changed.
     * (suid/sgid bits, for instance)
     */

    if(fsp->is_directory) {
      if(dos_stat(fsp->fsp_name, &sbuf) != 0) {
        return False;
      }
    } else {

      int ret;
    
      if(fsp->fd == -1)
        ret = conn->vfs_ops.stat(dos_to_unix(fsp->fsp_name,False), &sbuf);
      else
        ret = conn->vfs_ops.fstat(fsp->fd,&sbuf);
  
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

      if(conn->vfs_ops.chmod(dos_to_unix(fsp->fsp_name, False), perms) == -1) {
        DEBUG(3,("call_nt_transact_set_security_desc: chmod %s, 0%o failed. Error = %s.\n",
              fsp->fsp_name, (unsigned int)perms, strerror(errno) ));
        return False;
      }
    }
  }

  return True;
}
#undef OLD_NTDOMAIN
