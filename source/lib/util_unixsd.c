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
#include "rpc_parse.h"
#include "sids.h"


/****************************************************************************
 Map unix perms to NT.
****************************************************************************/

static SEC_ACCESS map_unix_perms(int *pacl_type, mode_t perm, int r_mask,
				 int w_mask, int x_mask, BOOL is_directory)
{
	SEC_ACCESS sa;
	uint32 nt_mask = 0;

	*pacl_type = SEC_ACE_TYPE_ACCESS_ALLOWED;

	if ((perm & (r_mask | w_mask | x_mask)) == (r_mask | w_mask | x_mask))
	{
		nt_mask = UNIX_ACCESS_RWX;
	}
	else if ((perm & (r_mask | w_mask | x_mask)) == 0)
	{
		nt_mask = UNIX_ACCESS_NONE;
	}
	else
	{
		nt_mask |= (perm & r_mask) ? UNIX_ACCESS_R : 0;
		if (is_directory)
			nt_mask |= (perm & w_mask) ? UNIX_ACCESS_W : 0;
		else
			nt_mask |= (perm & w_mask) ? UNIX_ACCESS_W : 0;
		nt_mask |= (perm & x_mask) ? UNIX_ACCESS_X : 0;
	}
	make_sec_access(&sa, nt_mask);
	return sa;
}

/****************************************************************************
 Function to create owner and group SIDs from a SMB_STRUCT_STAT.
****************************************************************************/

static BOOL create_file_sids(const SMB_STRUCT_STAT * psbuf,
			     DOM_SID *powner_sid, DOM_SID *pgroup_sid)
{
	SURS_POSIX_ID id;

	ZERO_STRUCTP(powner_sid);
	ZERO_STRUCTP(pgroup_sid);
	DEBUG(0, ("TODO: create_file_sids: not ok "
		  "to assume gid is NT group\n"));

	id.type = SURS_POSIX_UID;
	id.id = (uint32)psbuf->st_uid;

	if (!surs_unixid_to_sam_sid(&id, powner_sid, False))
	{
		DEBUG(3, ("create_file_sids: map uid %d failed\n",
			  (int)psbuf->st_uid));
		return False;
	}

	id.type = SURS_POSIX_GID;
	id.id = (uint32)psbuf->st_gid;

	if (!surs_unixid_to_sam_sid(&id, pgroup_sid, False))
	{
		DEBUG(3, ("create_file_sids: map gid %d failed\n",
			  (int)psbuf->st_gid));
		return False;
	}
	return True;
}

/****************************************************************************
 Reply to query a security descriptor from an fsp. If it succeeds it allocates
 the space for the return elements and returns True.
****************************************************************************/

size_t convertperms_unix_to_sd(const SMB_STRUCT_STAT * sbuf,
			       BOOL is_directory, mode_t mode,
			       SEC_DESC ** ppdesc)
{
	SEC_ACE *ace_list = NULL;
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

	(*ppdesc) = NULL;

	if (!lp_nt_acl_support())
	{
		sid_copy(&owner_sid, global_sid_everyone);
		sid_copy(&group_sid, global_sid_everyone);
	}
	else
	{
		if (!create_file_sids(sbuf, &owner_sid, &group_sid))
		{
			DEBUG(3, ("create_file_sids: uid or gid "
				  "not mapped to SIDS\n"));
			return 0;
		}

		/*
		 * Create the generic 3 element UNIX acl.
		 */

		owner_access = map_unix_perms(&owner_acl_type, sbuf->st_mode,
					      S_IRUSR, S_IWUSR, S_IXUSR,
					      is_directory);
		group_access = map_unix_perms(&grp_acl_type, sbuf->st_mode,
					      S_IRGRP, S_IWGRP, S_IXGRP,
					      is_directory);
		other_access = map_unix_perms(&other_acl_type, sbuf->st_mode,
					      S_IROTH, S_IWOTH, S_IXOTH,
					      is_directory);

		if (owner_access.mask)
		{
			ace_list = g_renew(SEC_ACE, ace_list, num_acls + 1);
			if (ace_list == NULL)
			{
				return 0;
			}
			make_sec_ace(&ace_list[num_acls++], &owner_sid,
				     owner_acl_type, owner_access, 0);
		}

		if (group_access.mask)
		{
			ace_list = g_renew(SEC_ACE, ace_list, num_acls + 1);
			if (ace_list == NULL)
			{
				return 0;
			}

			make_sec_ace(&ace_list[num_acls++], &group_sid,
				     grp_acl_type, group_access, 0);
		}

		if (other_access.mask)
		{
			ace_list = g_renew(SEC_ACE, ace_list, num_acls + 1);
			if (ace_list == NULL)
			{
				return 0;
			}

			make_sec_ace(&ace_list[num_acls++],
				     global_sid_everyone, other_acl_type,
				     other_access, 0);
		}

		if (is_directory)
		{
			/*
			 * For directory ACLs we also add in the
			 * inherited permissions ACE entries. These
			 * are the permissions a file would get when
			 * being created in the directory.
			 */

			owner_access = map_unix_perms(&owner_acl_type, mode,
						      S_IRUSR, S_IWUSR,
						      S_IXUSR, is_directory);
			group_access = map_unix_perms(&grp_acl_type,
						      mode, S_IRGRP,
						      S_IWGRP, S_IXGRP,
						      is_directory);
			other_access = map_unix_perms(&other_acl_type,
						      mode, S_IROTH,
						      S_IWOTH, S_IXOTH,
						      is_directory);

			if (owner_access.mask)
			{
				ace_list = g_renew(SEC_ACE, ace_list,
						   num_acls + 1);
				if (ace_list == NULL)
				{
					return 0;
				}

				make_sec_ace(&ace_list[num_acls++],
					     &owner_sid, owner_acl_type,
					     owner_access,
					     SEC_ACE_FLAG_OBJECT_INHERIT |
					     SEC_ACE_FLAG_INHERIT_ONLY);
			}

			if (group_access.mask)
			{
				ace_list = g_renew(SEC_ACE, ace_list,
						   num_acls + 1);
				if (ace_list == NULL)
				{
					return 0;
				}

				make_sec_ace(&ace_list[num_acls++],
					     &group_sid, grp_acl_type,
					     group_access,
					     SEC_ACE_FLAG_OBJECT_INHERIT |
					     SEC_ACE_FLAG_INHERIT_ONLY);
			}

			if (other_access.mask)
			{
				ace_list = g_renew(SEC_ACE, ace_list,
						   num_acls + 1);
				if (ace_list == NULL)
				{
					return 0;
				}

				make_sec_ace(&ace_list[num_acls++],
					     global_sid_everyone,
					     other_acl_type, other_access,
					     SEC_ACE_FLAG_OBJECT_INHERIT |
					     SEC_ACE_FLAG_INHERIT_ONLY);
			}
		}

		if (num_acls)
		{
			psa = g_new(SEC_ACL, 1);
			if (psa == NULL)
			{
				safe_free(ace_list);
			}
			if (!make_sec_acl(psa, 2, num_acls, ace_list))
			{
				DEBUG(0, ("get_nt_acl: Unable to malloc "
					  "space for acl.\n"));
				safe_free(ace_list);
				safe_free(psa);
				return 0;
			}
		}
	}

	(*ppdesc) = g_new(SEC_DESC, 1);

	if ((*ppdesc) == NULL)
	{
		DEBUG(0, ("get_nt_acl: Unable to malloc space "
			  "for security descriptor.\n"));
		sec_desc_size = 0;
		free_sec_acl(psa);
		safe_free(psa);
		return 0;
	}

	sec_desc_size = make_sec_desc((*ppdesc), 1,
				      SEC_DESC_SELF_RELATIVE |
				      SEC_DESC_DACL_PRESENT,
				      sid_dup(&owner_sid),
				      sid_dup(&group_sid), NULL, psa);

	return sec_desc_size;
}

/****************************************************************************
 Map NT perms to UNIX.
****************************************************************************/

#define FILE_SPECIFIC_READ_BITS \
	(FILE_READ_DATA|FILE_READ_EA|FILE_READ_ATTRIBUTES)
#define FILE_SPECIFIC_WRITE_BITS \
	(FILE_WRITE_DATA|FILE_APPEND_DATA|FILE_WRITE_EA|FILE_WRITE_ATTRIBUTES)
#define FILE_SPECIFIC_EXECUTE_BITS (FILE_EXECUTE)

#define PRINT_SPECIFIC_READ_BITS (PRINTER_READ)
#define PRINT_SPECIFIC_WRITE_BITS (PRINTER_READ)
#define PRINT_SPECIFIC_EXECUTE_BITS (PRINTER_ALL_ACCESS)

static mode_t map_nt_perms(SEC_ACCESS sec_access, int type)
{
	uint32 write_bits;
	uint32 read_bits;
	uint32 execute_bits;
	mode_t mode = 0;

	write_bits = FILE_SPECIFIC_WRITE_BITS;	
	read_bits = FILE_SPECIFIC_READ_BITS;	
	execute_bits = FILE_SPECIFIC_EXECUTE_BITS;	

	switch (type)
	{
		case S_IRUSR:
			if (sec_access.mask & GENERIC_ALL_ACCESS)
				mode = S_IRUSR | S_IWUSR | S_IXUSR;
			else
			{
				mode |=
					(sec_access.mask &
					 (GENERIC_READ_ACCESS |
					  read_bits)) ? S_IRUSR
					: 0;
				mode |=
					(sec_access.mask &
					 (GENERIC_WRITE_ACCESS |
					  write_bits)) ? S_IWUSR
					: 0;
				mode |=
					(sec_access.mask &
					 (GENERIC_EXECUTE_ACCESS |
					  execute_bits)) ?
					S_IXUSR : 0;
			}
			break;
		case S_IRGRP:
			if (sec_access.mask & GENERIC_ALL_ACCESS)
				mode = S_IRGRP | S_IWGRP | S_IXGRP;
			else
			{
				mode |=
					(sec_access.mask &
					 (GENERIC_READ_ACCESS |
					  read_bits)) ? S_IRGRP
					: 0;
				mode |=
					(sec_access.mask &
					 (GENERIC_WRITE_ACCESS |
					  write_bits)) ? S_IWGRP
					: 0;
				mode |=
					(sec_access.mask &
					 (GENERIC_EXECUTE_ACCESS |
					  execute_bits)) ?
					S_IXGRP : 0;
			}
			break;
		case S_IROTH:
			if (sec_access.mask & GENERIC_ALL_ACCESS)
				mode = S_IROTH | S_IWOTH | S_IXOTH;
			else
			{
				mode |=
					(sec_access.mask &
					 (GENERIC_READ_ACCESS |
					  read_bits)) ? S_IROTH
					: 0;
				mode |=
					(sec_access.mask &
					 (GENERIC_WRITE_ACCESS |
					  write_bits)) ? S_IWOTH
					: 0;
				mode |=
					(sec_access.mask &
					 (GENERIC_EXECUTE_ACCESS |
					  execute_bits)) ?
					S_IXOTH : 0;
			}
			break;
	}

	return mode;
}

/****************************************************************************
 Unpack a SEC_DESC into a owner, group and set of UNIX permissions.
****************************************************************************/

BOOL convertperms_sd_to_unix(SMB_STRUCT_STAT * psbuf, uid_t * puser,
			     gid_t * pgrp, mode_t * pmode,
			     uint32 security_info_sent, SEC_DESC * psd,
			     BOOL is_directory)
{
	DOM_SID file_owner_sid;
	DOM_SID file_grp_sid;
	SEC_ACL *dacl = psd->dacl;
	BOOL all_aces_are_inherit_only = (is_directory ? True : False);
	int i;
	SURS_POSIX_ID id;

	*pmode = 0;
	*puser = (uid_t) - 1;
	*pgrp = (gid_t) - 1;

	if (security_info_sent == 0)
	{
		DEBUG(0, ("unpack_nt_permissions: "
			  "no security info sent !\n"));
		return False;
	}

	/*
	 * Windows 2000 sends the owner and group SIDs as the logged in
	 * user, not the connected user. But it still sends the file
	 * owner SIDs on an ACL set. So we need to check for the file
	 * owner and group SIDs as well as the owner SIDs. JRA.
	 */

	if (!create_file_sids(psbuf, &file_owner_sid, &file_grp_sid))
	{
		DEBUG(3, ("create_file_sids: uid or gid "
			  "not mapped to SIDS\n"));
		return 0;
	}

	/*
	 * Don't immediately fail if the owner sid cannot be validated.
	 * This may be a group chown only set.
	 */

	DEBUG(0, ("TODO: LsaLookupSids to find type of owner_sid\n"));

	if (security_info_sent & OWNER_SECURITY_INFORMATION &&
	    surs_sam_sid_to_unixid(psd->owner_sid, &id, False) &&
	    id.type == SURS_POSIX_UID)
	{
		*puser = (uid_t) id.id;
	}

	/*
	 * Don't immediately fail if the group sid cannot be validated.
	 * This may be an owner chown only set.
	 */

	if (security_info_sent & GROUP_SECURITY_INFORMATION &&
	    surs_sam_sid_to_unixid(psd->grp_sid, &id, False) &&
	    (id.type == SURS_POSIX_GID))
	{
		*pgrp = (gid_t) id.id;
	}

	/*
	 * If no DACL then this is a chown only security descriptor.
	 */

	if (!(security_info_sent & DACL_SECURITY_INFORMATION) || !dacl)
	{
		*pmode = 0;
		return True;
	}

	/*
	 * Now go through the DACL and ensure that
	 * any owner/group sids match.
	 */

	for (i = 0; i < dacl->num_aces; i++)
	{
		DOM_SID ace_sid;
		SEC_ACE *psa = &dacl->ace[i];

		if ((psa->type != SEC_ACE_TYPE_ACCESS_ALLOWED) &&
		    (psa->type != SEC_ACE_TYPE_ACCESS_DENIED))
		{
			DEBUG(3, ("unpack_nt_permissions: "
				  "unable to set anything but an "
				  "ALLOW or DENY ACE.\n"));
			return False;
		}

		/*
		 * Ignore or remove bits we don't care about on a directory ACE.
		 */

		if (is_directory)
		{
			if (psa->flags & SEC_ACE_FLAG_INHERIT_ONLY)
			{
				DEBUG(3, ("unpack_nt_permissions: "
					  "ignoring inherit only ACE.\n"));
				continue;
			}

			/*
			 * At least one of the ACE entries wasn't inherit only.
			 * Flag this so we know the returned mode is valid.
			 */

			all_aces_are_inherit_only = False;
		}

		/*
		 * Windows 2000 sets these flags even on *file* ACE's.
		 * This is wrong but we can ignore them for now.
		 * Revisit this when we go to POSIX ACLs on directories.
		 */

		psa->flags &=
			~(SEC_ACE_FLAG_OBJECT_INHERIT |
			  SEC_ACE_FLAG_CONTAINER_INHERIT);

		if (psa->flags != 0)
		{
			DEBUG(1,
			      ("unpack_nt_permissions: unable to set ACE flags (%x).\n",
			       (unsigned int)psa->flags));
			return False;
		}

		/*
		 * The security mask may be UNIX_ACCESS_NONE which
		 * should map into no permissions (we overload the
		 * WRITE_OWNER bit for this) or it should be one of
		 * the ALL/EXECUTE/READ/WRITE bits. Arrange for this
		 * to be so. Any other bits override the
		 * UNIX_ACCESS_NONE bit.
		 */

		psa->info.mask &=
			(GENERIC_ALL_ACCESS | GENERIC_EXECUTE_ACCESS |
			 GENERIC_WRITE_ACCESS | GENERIC_READ_ACCESS |
			 UNIX_ACCESS_NONE | FILE_ALL_ATTRIBUTES);

		if (psa->info.mask != UNIX_ACCESS_NONE)
			psa->info.mask &= ~UNIX_ACCESS_NONE;

		sid_copy(&ace_sid, &psa->sid);

		if (sid_equal(&ace_sid, &file_owner_sid))
		{
			/*
			 * Map the desired permissions into owner perms.
			 */

			if (psa->type == SEC_ACE_TYPE_ACCESS_ALLOWED)
				*pmode |= map_nt_perms(psa->info, S_IRUSR);
			else
				*pmode &= ~(map_nt_perms(psa->info, S_IRUSR));

		}
		else if (sid_equal(&ace_sid, &file_grp_sid))
		{
			/*
			 * Map the desired permissions into group perms.
			 */

			if (psa->type == SEC_ACE_TYPE_ACCESS_ALLOWED)
				*pmode |= map_nt_perms(psa->info, S_IRGRP);
			else
				*pmode &= ~(map_nt_perms(psa->info, S_IRGRP));

		}
		else if (sid_equal(&ace_sid, global_sid_everyone))
		{
			/*
			 * Map the desired permissions into other perms.
			 */

			if (psa->type == SEC_ACE_TYPE_ACCESS_ALLOWED)
				*pmode |= map_nt_perms(psa->info, S_IROTH);
			else
				*pmode &= ~(map_nt_perms(psa->info, S_IROTH));

		}
		else
		{
			DEBUG(0, ("unpack_nt_permissions: "
				  "unknown SID used in ACL.\n"));
			return False;
		}
	}

	if (is_directory && all_aces_are_inherit_only)
	{
		/*
		 * Windows 2000 is doing one of these weird 'inherit acl'
		 * traverses to conserve NTFS ACL resources. Just pretend
		 * there was no DACL sent. JRA.
		 */

		DEBUG(10, ("unpack_nt_permissions: "
			   "Win2k inherit acl traverse. "
			   "Ignoring DACL.\n"));
		free_sec_acl(psd->dacl);
		safe_free(psd->dacl);
		psd->dacl = NULL;
	}

	return True;
}
