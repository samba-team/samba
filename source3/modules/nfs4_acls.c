/*
 * NFS4 ACL handling
 *
 * Copyright (C) Jim McDonough, 2006
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "smbd/smbd.h"
#include "nfs4_acls.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "../libcli/security/dom_sid.h"
#include "../libcli/security/security.h"
#include "dbwrap/dbwrap.h"
#include "dbwrap/dbwrap_open.h"
#include "system/filesys.h"
#include "passdb/lookup_sid.h"
#include "util_tdb.h"
#include "lib/param/loadparm.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_ACLS

#define SMBACL4_PARAM_TYPE_NAME "nfs4"

extern const struct generic_mapping file_generic_mapping;

#define SMB_ACE4_INT_MAGIC 0x76F8A967
typedef struct _SMB_ACE4_INT_T
{
	uint32	magic;
	SMB_ACE4PROP_T	prop;
	void	*next;
} SMB_ACE4_INT_T;

#define SMB_ACL4_INT_MAGIC 0x29A3E792
typedef struct _SMB_ACL4_INT_T
{
	uint32	magic;
	uint32	naces;
	SMB_ACE4_INT_T	*first;
	SMB_ACE4_INT_T	*last;
} SMB_ACL4_INT_T;

/************************************************
 Split the ACE flag mapping between nfs4 and Windows
 into two separate functions rather than trying to do
 it inline. Allows us to carefully control what flags
 are mapped to what in one place.
************************************************/

static uint32_t map_nfs4_ace_flags_to_windows_ace_flags(
	uint32_t nfs4_ace_flags)
{
	uint32_t win_ace_flags = 0;

	/* The nfs4 flags <= 0xf map perfectly. */
	win_ace_flags = nfs4_ace_flags & (SEC_ACE_FLAG_OBJECT_INHERIT|
				      SEC_ACE_FLAG_CONTAINER_INHERIT|
				      SEC_ACE_FLAG_NO_PROPAGATE_INHERIT|
				      SEC_ACE_FLAG_INHERIT_ONLY);

	/* flags greater than 0xf have diverged :-(. */
	/* See the nfs4 ace flag definitions here:
	   http://www.ietf.org/rfc/rfc3530.txt.
	   And the Windows ace flag definitions here:
	   librpc/idl/security.idl. */
	if (nfs4_ace_flags & SMB_ACE4_INHERITED_ACE) {
		win_ace_flags |= SEC_ACE_FLAG_INHERITED_ACE;
	}

	return win_ace_flags;
}

static uint32_t map_windows_ace_flags_to_nfs4_ace_flags(uint32_t win_ace_flags)
{
	uint32_t nfs4_ace_flags = 0;

	/* The windows flags <= 0xf map perfectly. */
	nfs4_ace_flags = win_ace_flags & (SMB_ACE4_FILE_INHERIT_ACE|
				      SMB_ACE4_DIRECTORY_INHERIT_ACE|
				      SMB_ACE4_NO_PROPAGATE_INHERIT_ACE|
				      SMB_ACE4_INHERIT_ONLY_ACE);

	/* flags greater than 0xf have diverged :-(. */
	/* See the nfs4 ace flag definitions here:
	   http://www.ietf.org/rfc/rfc3530.txt.
	   And the Windows ace flag definitions here:
	   librpc/idl/security.idl. */
	if (win_ace_flags & SEC_ACE_FLAG_INHERITED_ACE) {
		nfs4_ace_flags |= SMB_ACE4_INHERITED_ACE;
	}

	return nfs4_ace_flags;
}

static SMB_ACL4_INT_T *get_validated_aclint(SMB4ACL_T *theacl)
{
	SMB_ACL4_INT_T *aclint = (SMB_ACL4_INT_T *)theacl;
	if (theacl==NULL)
	{
		DEBUG(2, ("acl is NULL\n"));
		errno = EINVAL;
		return NULL;
	}
	if (aclint->magic!=SMB_ACL4_INT_MAGIC)
	{
		DEBUG(2, ("aclint bad magic 0x%x\n", aclint->magic));
		errno = EINVAL;
		return NULL;
	}
	return aclint;
}

static SMB_ACE4_INT_T *get_validated_aceint(SMB4ACE_T *ace)
{
	SMB_ACE4_INT_T *aceint = (SMB_ACE4_INT_T *)ace;
	if (ace==NULL)
	{
		DEBUG(2, ("ace is NULL\n"));
		errno = EINVAL;
		return NULL;
	}
	if (aceint->magic!=SMB_ACE4_INT_MAGIC)
	{
		DEBUG(2, ("aceint bad magic 0x%x\n", aceint->magic));
		errno = EINVAL;
		return NULL;
	}
	return aceint;
}

SMB4ACL_T *smb_create_smb4acl(void)
{
	TALLOC_CTX *mem_ctx = talloc_tos();
	SMB_ACL4_INT_T	*theacl = (SMB_ACL4_INT_T *)TALLOC_ZERO_SIZE(
		mem_ctx, sizeof(SMB_ACL4_INT_T));
	if (theacl==NULL)
	{
		DEBUG(0, ("TALLOC_SIZE failed\n"));
		errno = ENOMEM;
		return NULL;
	}
	theacl->magic = SMB_ACL4_INT_MAGIC;
	/* theacl->first, last = NULL not needed */
	return (SMB4ACL_T *)theacl;
}

SMB4ACE_T *smb_add_ace4(SMB4ACL_T *theacl, SMB_ACE4PROP_T *prop)
{
	SMB_ACL4_INT_T *aclint = get_validated_aclint(theacl);
	SMB_ACE4_INT_T *ace;

	ace = (SMB_ACE4_INT_T *)TALLOC_ZERO_SIZE(
		theacl, sizeof(SMB_ACE4_INT_T));
	if (ace==NULL)
	{
		DEBUG(0, ("TALLOC_SIZE failed\n"));
		errno = ENOMEM;
		return NULL;
	}
	ace->magic = SMB_ACE4_INT_MAGIC;
	/* ace->next = NULL not needed */
	memcpy(&ace->prop, prop, sizeof(SMB_ACE4PROP_T));

	if (aclint->first==NULL)
	{
		aclint->first = ace;
		aclint->last = ace;
	} else {
		aclint->last->next = (void *)ace;
		aclint->last = ace;
	}
	aclint->naces++;

	return (SMB4ACE_T *)ace;
}

SMB_ACE4PROP_T *smb_get_ace4(SMB4ACE_T *ace)
{
	SMB_ACE4_INT_T *aceint = get_validated_aceint(ace);
	if (aceint==NULL)
		return NULL;

	return &aceint->prop;
}

SMB4ACE_T *smb_next_ace4(SMB4ACE_T *ace)
{
	SMB_ACE4_INT_T *aceint = get_validated_aceint(ace);
	if (aceint==NULL)
		return NULL;

	return (SMB4ACE_T *)aceint->next;
}

SMB4ACE_T *smb_first_ace4(SMB4ACL_T *theacl)
{
	SMB_ACL4_INT_T *aclint = get_validated_aclint(theacl);
	if (aclint==NULL)
		return NULL;

	return (SMB4ACE_T *)aclint->first;
}

uint32 smb_get_naces(SMB4ACL_T *theacl)
{
	SMB_ACL4_INT_T *aclint = get_validated_aclint(theacl);
	if (aclint==NULL)
		return 0;

	return aclint->naces;
}

static int smbacl4_GetFileOwner(struct connection_struct *conn,
				const char *filename,
				SMB_STRUCT_STAT *psbuf)
{
	memset(psbuf, 0, sizeof(SMB_STRUCT_STAT));

	/* Get the stat struct for the owner info. */
	if (vfs_stat_smb_fname(conn, filename, psbuf) != 0)
	{
		DEBUG(8, ("vfs_stat_smb_fname failed with error %s\n",
			strerror(errno)));
		return -1;
	}

	return 0;
}

static int smbacl4_fGetFileOwner(files_struct *fsp, SMB_STRUCT_STAT *psbuf)
{
	memset(psbuf, 0, sizeof(SMB_STRUCT_STAT));

	if (fsp->fh->fd == -1) {
		return smbacl4_GetFileOwner(fsp->conn,
					    fsp->fsp_name->base_name, psbuf);
	}
	if (SMB_VFS_FSTAT(fsp, psbuf) != 0)
	{
		DEBUG(8, ("SMB_VFS_FSTAT failed with error %s\n",
			strerror(errno)));
		return -1;
	}

	return 0;
}

static bool smbacl4_nfs42win(TALLOC_CTX *mem_ctx, SMB4ACL_T *theacl, /* in */
	struct dom_sid *psid_owner, /* in */
	struct dom_sid *psid_group, /* in */
	bool is_directory, /* in */
	struct security_ace **ppnt_ace_list, /* out */
	int *pgood_aces /* out */
)
{
	SMB_ACL4_INT_T *aclint = (SMB_ACL4_INT_T *)theacl;
	SMB_ACE4_INT_T *aceint;
	struct security_ace *nt_ace_list = NULL;
	int good_aces = 0;

	DEBUG(10, ("smbacl_nfs42win entered\n"));

	aclint = get_validated_aclint(theacl);
	/* We do not check for naces being 0 or theacl being NULL here
	 * because it is done upstream */
	/* in smb_get_nt_acl_nfs4(). */
	nt_ace_list = (struct security_ace *)TALLOC_ZERO_SIZE(
		mem_ctx, aclint->naces * sizeof(struct security_ace));
	if (nt_ace_list==NULL)
	{
		DEBUG(10, ("talloc error"));
		errno = ENOMEM;
		return False;
	}

	for (aceint=aclint->first;
	     aceint!=NULL;
	     aceint=(SMB_ACE4_INT_T *)aceint->next) {
		uint32_t mask;
		struct dom_sid sid;
		SMB_ACE4PROP_T	*ace = &aceint->prop;
		uint32_t win_ace_flags;

		DEBUG(10, ("magic: 0x%x, type: %d, iflags: %x, flags: %x, "
			   "mask: %x, who: %d\n",
			   aceint->magic, ace->aceType, ace->flags,
			   ace->aceFlags, ace->aceMask, ace->who.id));

		SMB_ASSERT(aceint->magic==SMB_ACE4_INT_MAGIC);

		if (ace->flags & SMB_ACE4_ID_SPECIAL) {
			switch (ace->who.special_id) {
			case SMB_ACE4_WHO_OWNER:
				sid_copy(&sid, psid_owner);
				break;
			case SMB_ACE4_WHO_GROUP:
				sid_copy(&sid, psid_group);
				break;
			case SMB_ACE4_WHO_EVERYONE:
				sid_copy(&sid, &global_sid_World);
				break;
			default:
				DEBUG(8, ("invalid special who id %d "
					"ignored\n", ace->who.special_id));
				continue;
			}
		} else {
			if (ace->aceFlags & SMB_ACE4_IDENTIFIER_GROUP) {
				gid_to_sid(&sid, ace->who.gid);
			} else {
				uid_to_sid(&sid, ace->who.uid);
			}
		}
		DEBUG(10, ("mapped %d to %s\n", ace->who.id,
			   sid_string_dbg(&sid)));

		if (is_directory && (ace->aceMask & SMB_ACE4_ADD_FILE)) {
			ace->aceMask |= SMB_ACE4_DELETE_CHILD;
		}

		win_ace_flags = map_nfs4_ace_flags_to_windows_ace_flags(
			ace->aceFlags);
		if (!is_directory &&
		    (win_ace_flags & (SEC_ACE_FLAG_OBJECT_INHERIT|
				      SEC_ACE_FLAG_CONTAINER_INHERIT))) {
			/*
			 * GPFS sets inherits dir_inhert and file_inherit flags
			 * to files, too, which confuses windows, and seems to
			 * be wrong anyways. ==> Map these bits away for files.
			 */
			DEBUG(10, ("removing inherit flags from nfs4 ace\n"));
			win_ace_flags &= ~(SEC_ACE_FLAG_OBJECT_INHERIT|
					   SEC_ACE_FLAG_CONTAINER_INHERIT);
		}
		DEBUG(10, ("Windows mapped ace flags: 0x%x => 0x%x\n",
		      ace->aceFlags, win_ace_flags));

		mask = ace->aceMask;
		/* Windows clients expect SYNC on acls to
		   correctly allow rename. See bug #7909. */
		/* But not on DENY ace entries. See
		   bug #8442. */
		if(ace->aceType == SMB_ACE4_ACCESS_ALLOWED_ACE_TYPE) {
			mask = ace->aceMask | SMB_ACE4_SYNCHRONIZE;
		}
		init_sec_ace(&nt_ace_list[good_aces++], &sid,
			ace->aceType, mask,
			win_ace_flags);
	}

	*ppnt_ace_list = nt_ace_list;
	*pgood_aces = good_aces;

	return True;
}

static NTSTATUS smb_get_nt_acl_nfs4_common(const SMB_STRUCT_STAT *sbuf,
					   uint32 security_info, TALLOC_CTX *mem_ctx,
	struct security_descriptor **ppdesc, SMB4ACL_T *theacl)
{
	int	good_aces = 0;
	struct dom_sid sid_owner, sid_group;
	size_t sd_size = 0;
	struct security_ace *nt_ace_list = NULL;
	struct security_acl *psa = NULL;
	TALLOC_CTX *frame = talloc_stackframe();

	if (theacl==NULL || smb_get_naces(theacl)==0)
		return NT_STATUS_ACCESS_DENIED; /* special because we
						 * shouldn't alloc 0 for
						 * win */

	uid_to_sid(&sid_owner, sbuf->st_ex_uid);
	gid_to_sid(&sid_group, sbuf->st_ex_gid);

	if (smbacl4_nfs42win(mem_ctx, theacl, &sid_owner, &sid_group,
			     S_ISDIR(sbuf->st_ex_mode),
				&nt_ace_list, &good_aces)==False) {
		DEBUG(8,("smbacl4_nfs42win failed\n"));
		TALLOC_FREE(frame);
		return map_nt_error_from_unix(errno);
	}

	psa = make_sec_acl(frame, NT4_ACL_REVISION, good_aces, nt_ace_list);
	if (psa == NULL) {
		DEBUG(2,("make_sec_acl failed\n"));
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	DEBUG(10,("after make sec_acl\n"));
	*ppdesc = make_sec_desc(
		mem_ctx, SD_REVISION, SEC_DESC_SELF_RELATIVE,
		(security_info & SECINFO_OWNER) ? &sid_owner : NULL,
		(security_info & SECINFO_GROUP) ? &sid_group : NULL,
		NULL, psa, &sd_size);
	if (*ppdesc==NULL) {
		DEBUG(2,("make_sec_desc failed\n"));
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	DEBUG(10, ("smb_get_nt_acl_nfs4_common successfully exited with "
		   "sd_size %d\n",
		   (int)ndr_size_security_descriptor(*ppdesc, 0)));

	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}

NTSTATUS smb_fget_nt_acl_nfs4(files_struct *fsp,
			      uint32 security_info,
			      TALLOC_CTX *mem_ctx,
			      struct security_descriptor **ppdesc,
			      SMB4ACL_T *theacl)
{
	SMB_STRUCT_STAT sbuf;

	DEBUG(10, ("smb_fget_nt_acl_nfs4 invoked for %s\n", fsp_str_dbg(fsp)));

	if (smbacl4_fGetFileOwner(fsp, &sbuf)) {
		return map_nt_error_from_unix(errno);
	}

	return smb_get_nt_acl_nfs4_common(&sbuf, security_info,
					  mem_ctx, ppdesc,
					  theacl);
}

NTSTATUS smb_get_nt_acl_nfs4(struct connection_struct *conn,
			     const char *name,
			     uint32 security_info,
			     TALLOC_CTX *mem_ctx,
			     struct security_descriptor **ppdesc,
			     SMB4ACL_T *theacl)
{
	SMB_STRUCT_STAT sbuf;

	DEBUG(10, ("smb_get_nt_acl_nfs4 invoked for %s\n", name));

	if (smbacl4_GetFileOwner(conn, name, &sbuf)) {
		return map_nt_error_from_unix(errno);
	}

	return smb_get_nt_acl_nfs4_common(&sbuf, security_info,
					  mem_ctx, ppdesc,
					  theacl);
}

enum smbacl4_mode_enum {e_simple=0, e_special=1};
enum smbacl4_acedup_enum {e_dontcare=0, e_reject=1, e_ignore=2, e_merge=3};

typedef struct _smbacl4_vfs_params {
	enum smbacl4_mode_enum mode;
	bool do_chown;
	enum smbacl4_acedup_enum acedup;
} smbacl4_vfs_params;

/*
 * Gather special parameters for NFS4 ACL handling
 */
static int smbacl4_get_vfs_params(
	const char *type_name,
	files_struct *fsp,
	smbacl4_vfs_params *params
)
{
	static const struct enum_list enum_smbacl4_modes[] = {
		{ e_simple, "simple" },
		{ e_special, "special" },
		{ -1 , NULL }
	};
	static const struct enum_list enum_smbacl4_acedups[] = {
		{ e_dontcare, "dontcare" },
		{ e_reject, "reject" },
		{ e_ignore, "ignore" },
		{ e_merge, "merge" },
		{ -1 , NULL }
	};

	memset(params, 0, sizeof(smbacl4_vfs_params));
	params->mode = (enum smbacl4_mode_enum)lp_parm_enum(
		SNUM(fsp->conn), type_name,
		"mode", enum_smbacl4_modes, e_simple);
	params->do_chown = lp_parm_bool(SNUM(fsp->conn), type_name,
		"chown", True);
	params->acedup = (enum smbacl4_acedup_enum)lp_parm_enum(
		SNUM(fsp->conn), type_name,
		"acedup", enum_smbacl4_acedups, e_dontcare);

	DEBUG(10, ("mode:%s, do_chown:%s, acedup: %s\n",
		enum_smbacl4_modes[params->mode].name,
		params->do_chown ? "true" : "false",
		enum_smbacl4_acedups[params->acedup].name));

	return 0;
}

static void smbacl4_dump_nfs4acl(int level, SMB4ACL_T *theacl)
{
	SMB_ACL4_INT_T *aclint = get_validated_aclint(theacl);
	SMB_ACE4_INT_T *aceint;

	DEBUG(level, ("NFS4ACL: size=%d\n", aclint->naces));

	for (aceint = aclint->first;
	     aceint!=NULL;
	     aceint=(SMB_ACE4_INT_T *)aceint->next) {
		SMB_ACE4PROP_T *ace = &aceint->prop;

		DEBUG(level, ("\tACE: type=%d, flags=0x%x, fflags=0x%x, "
			      "mask=0x%x, id=%d\n",
			      ace->aceType,
			      ace->aceFlags, ace->flags,
			      ace->aceMask,
			      ace->who.id));
	}
}

/* 
 * Find 2 NFS4 who-special ACE property (non-copy!!!)
 * match nonzero if "special" and who is equal
 * return ace if found matching; otherwise NULL
 */
static SMB_ACE4PROP_T *smbacl4_find_equal_special(
	SMB4ACL_T *theacl,
	SMB_ACE4PROP_T *aceNew)
{
	SMB_ACL4_INT_T *aclint = get_validated_aclint(theacl);
	SMB_ACE4_INT_T *aceint;

	for (aceint = aclint->first; aceint != NULL;
	     aceint=(SMB_ACE4_INT_T *)aceint->next) {
		SMB_ACE4PROP_T *ace = &aceint->prop;

                DEBUG(10,("ace type:0x%x flags:0x%x aceFlags:0x%x "
			  "new type:0x%x flags:0x%x aceFlags:0x%x\n",
			  ace->aceType, ace->flags, ace->aceFlags,
			  aceNew->aceType, aceNew->flags,aceNew->aceFlags));

		if (ace->flags == aceNew->flags &&
			ace->aceType==aceNew->aceType &&
			ace->aceFlags==aceNew->aceFlags)
		{
			/* keep type safety; e.g. gid is an u.short */
			if (ace->flags & SMB_ACE4_ID_SPECIAL)
			{
				if (ace->who.special_id ==
				    aceNew->who.special_id)
					return ace;
			} else {
				if (ace->aceFlags & SMB_ACE4_IDENTIFIER_GROUP)
				{
					if (ace->who.gid==aceNew->who.gid)
						return ace;
				} else {
					if (ace->who.uid==aceNew->who.uid)
						return ace;
				}
			}
		}
	}

	return NULL;
}


static bool smbacl4_fill_ace4(
	const struct smb_filename *filename,
	smbacl4_vfs_params *params,
	uid_t ownerUID,
	gid_t ownerGID,
	const struct security_ace *ace_nt, /* input */
	SMB_ACE4PROP_T *ace_v4 /* output */
)
{
	DEBUG(10, ("got ace for %s\n", sid_string_dbg(&ace_nt->trustee)));

	memset(ace_v4, 0, sizeof(SMB_ACE4PROP_T));

	/* only ACCESS|DENY supported right now */
	ace_v4->aceType = ace_nt->type;

	ace_v4->aceFlags = map_windows_ace_flags_to_nfs4_ace_flags(
		ace_nt->flags);

	/* remove inheritance flags on files */
	if (VALID_STAT(filename->st) &&
	    !S_ISDIR(filename->st.st_ex_mode)) {
		DEBUG(10, ("Removing inheritance flags from a file\n"));
		ace_v4->aceFlags &= ~(SMB_ACE4_FILE_INHERIT_ACE|
				      SMB_ACE4_DIRECTORY_INHERIT_ACE|
				      SMB_ACE4_NO_PROPAGATE_INHERIT_ACE|
				      SMB_ACE4_INHERIT_ONLY_ACE);
	}

	ace_v4->aceMask = ace_nt->access_mask &
		(SEC_STD_ALL | SEC_FILE_ALL);

	se_map_generic(&ace_v4->aceMask, &file_generic_mapping);

	if (ace_v4->aceFlags!=ace_nt->flags)
		DEBUG(9, ("ace_v4->aceFlags(0x%x)!=ace_nt->flags(0x%x)\n",
			ace_v4->aceFlags, ace_nt->flags));

	if (ace_v4->aceMask!=ace_nt->access_mask)
		DEBUG(9, ("ace_v4->aceMask(0x%x)!=ace_nt->access_mask(0x%x)\n",
			ace_v4->aceMask, ace_nt->access_mask));

	if (dom_sid_equal(&ace_nt->trustee, &global_sid_World)) {
		ace_v4->who.special_id = SMB_ACE4_WHO_EVERYONE;
		ace_v4->flags |= SMB_ACE4_ID_SPECIAL;
	} else {
		uid_t uid;
		gid_t gid;

		if (sid_to_gid(&ace_nt->trustee, &gid)) {
			ace_v4->aceFlags |= SMB_ACE4_IDENTIFIER_GROUP;

			if (params->mode==e_special && gid==ownerGID) {
				ace_v4->flags |= SMB_ACE4_ID_SPECIAL;
				ace_v4->who.special_id = SMB_ACE4_WHO_GROUP;
			} else {
				ace_v4->who.gid = gid;
			}
		} else if (sid_to_uid(&ace_nt->trustee, &uid)) {
			if (params->mode==e_special && uid==ownerUID) {
				ace_v4->flags |= SMB_ACE4_ID_SPECIAL;
				ace_v4->who.special_id = SMB_ACE4_WHO_OWNER;
			} else {
				ace_v4->who.uid = uid;
			}
		} else {
			DEBUG(1, ("nfs4_acls.c: file [%s]: could not "
				  "convert %s to uid or gid\n",
				  filename->base_name,
				  sid_string_dbg(&ace_nt->trustee)));
			return False;
		}
	}

	return True; /* OK */
}

static int smbacl4_MergeIgnoreReject(
	enum smbacl4_acedup_enum acedup,
	SMB4ACL_T *theacl, /* may modify it */
	SMB_ACE4PROP_T *ace, /* the "new" ACE */
	bool	*paddNewACE,
	int	i
)
{
	int	result = 0;
	SMB_ACE4PROP_T *ace4found = smbacl4_find_equal_special(theacl, ace);
	if (ace4found)
	{
		switch(acedup)
		{
		case e_merge: /* "merge" flags */
			*paddNewACE = False;
			ace4found->aceFlags |= ace->aceFlags;
			ace4found->aceMask |= ace->aceMask;
			break;
		case e_ignore: /* leave out this record */
			*paddNewACE = False;
			break;
		case e_reject: /* do an error */
			DEBUG(8, ("ACL rejected by duplicate nt ace#%d\n", i));
			errno = EINVAL; /* SHOULD be set on any _real_ error */
			result = -1;
			break;
		default:
			break;
		}
	}
	return result;
}

static SMB4ACL_T *smbacl4_win2nfs4(
	const files_struct *fsp,
	const struct security_acl *dacl,
	smbacl4_vfs_params *pparams,
	uid_t ownerUID,
	gid_t ownerGID
)
{
	SMB4ACL_T *theacl;
	uint32	i;
	const char *filename = fsp->fsp_name->base_name;

	DEBUG(10, ("smbacl4_win2nfs4 invoked\n"));

	theacl = smb_create_smb4acl();
	if (theacl==NULL)
		return NULL;

	for(i=0; i<dacl->num_aces; i++) {
		SMB_ACE4PROP_T	ace_v4;
		bool	addNewACE = True;

		if (!smbacl4_fill_ace4(fsp->fsp_name, pparams,
				       ownerUID, ownerGID,
				       dacl->aces + i, &ace_v4)) {
			DEBUG(3, ("Could not fill ace for file %s, SID %s\n",
				  filename,
				  sid_string_dbg(&((dacl->aces+i)->trustee))));
			continue;
		}

		if (pparams->acedup!=e_dontcare) {
			if (smbacl4_MergeIgnoreReject(pparams->acedup, theacl,
				&ace_v4, &addNewACE, i))
				return NULL;
		}

		if (addNewACE)
			smb_add_ace4(theacl, &ace_v4);
	}

	return theacl;
}

NTSTATUS smb_set_nt_acl_nfs4(files_struct *fsp,
	uint32 security_info_sent,
	const struct security_descriptor *psd,
	set_nfs4acl_native_fn_t set_nfs4_native)
{
	smbacl4_vfs_params params;
	SMB4ACL_T *theacl = NULL;
	bool	result;

	SMB_STRUCT_STAT sbuf;
	bool set_acl_as_root = false;
	uid_t newUID = (uid_t)-1;
	gid_t newGID = (gid_t)-1;
	int saved_errno;

	DEBUG(10, ("smb_set_nt_acl_nfs4 invoked for %s\n", fsp_str_dbg(fsp)));

	if ((security_info_sent & (SECINFO_DACL |
		SECINFO_GROUP | SECINFO_OWNER)) == 0)
	{
		DEBUG(9, ("security_info_sent (0x%x) ignored\n",
			security_info_sent));
		return NT_STATUS_OK; /* won't show error - later to be
				      * refined... */
	}

	/* Special behaviours */
	if (smbacl4_get_vfs_params(SMBACL4_PARAM_TYPE_NAME, fsp, &params))
		return NT_STATUS_NO_MEMORY;

	if (smbacl4_fGetFileOwner(fsp, &sbuf))
		return map_nt_error_from_unix(errno);

	if (params.do_chown) {
		/* chown logic is a copy/paste from posix_acl.c:set_nt_acl */
		NTSTATUS status = unpack_nt_owners(fsp->conn, &newUID, &newGID,
						   security_info_sent, psd);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(8, ("unpack_nt_owners failed"));
			return status;
		}
		if (((newUID != (uid_t)-1) && (sbuf.st_ex_uid != newUID)) ||
		    ((newGID != (gid_t)-1) && (sbuf.st_ex_gid != newGID))) {

			status = try_chown(fsp, newUID, newGID);
			if (!NT_STATUS_IS_OK(status)) {
				DEBUG(3,("chown %s, %u, %u failed. Error = "
					 "%s.\n", fsp_str_dbg(fsp),
					 (unsigned int)newUID,
					 (unsigned int)newGID,
					 nt_errstr(status)));
				return status;
			}

			DEBUG(10,("chown %s, %u, %u succeeded.\n",
				  fsp_str_dbg(fsp), (unsigned int)newUID,
				  (unsigned int)newGID));
			if (smbacl4_GetFileOwner(fsp->conn,
						 fsp->fsp_name->base_name,
						 &sbuf))
				return map_nt_error_from_unix(errno);

			/* If we successfully chowned, we know we must
			 * be able to set the acl, so do it as root.
			 */
			set_acl_as_root = true;
		}
	}

	if (!(security_info_sent & SECINFO_DACL) || psd->dacl ==NULL) {
		DEBUG(10, ("no dacl found; security_info_sent = 0x%x\n",
			   security_info_sent));
		return NT_STATUS_OK;
	}

	theacl = smbacl4_win2nfs4(fsp, psd->dacl, &params,
				  sbuf.st_ex_uid, sbuf.st_ex_gid);
	if (!theacl)
		return map_nt_error_from_unix(errno);

	smbacl4_dump_nfs4acl(10, theacl);

	if (set_acl_as_root) {
		become_root();
	}
	result = set_nfs4_native(fsp, theacl);
	saved_errno = errno;
	if (set_acl_as_root) {
		unbecome_root();
	}
	if (result!=True) {
		errno = saved_errno;
		DEBUG(10, ("set_nfs4_native failed with %s\n",
			   strerror(errno)));
		return map_nt_error_from_unix(errno);
	}

	DEBUG(10, ("smb_set_nt_acl_nfs4 succeeded\n"));
	return NT_STATUS_OK;
}
