/*
 * NFS4 ACL handling
 *
 * Copyright (C) Jim McDonough, 2006
 * Copyright (C) Christof Schmitt 2019
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
#include "librpc/gen_ndr/idmap.h"
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

struct SMB4ACE_T
{
	SMB_ACE4PROP_T	prop;
	struct SMB4ACE_T *next;
};

struct SMB4ACL_T
{
	uint16_t controlflags;
	uint32_t naces;
	struct SMB4ACE_T	*first;
	struct SMB4ACE_T	*last;
};

/*
 * Gather special parameters for NFS4 ACL handling
 */
int smbacl4_get_vfs_params(struct connection_struct *conn,
			   struct smbacl4_vfs_params *params)
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
	int enumval;

	*params = (struct smbacl4_vfs_params) { 0 };

	enumval = lp_parm_enum(SNUM(conn), SMBACL4_PARAM_TYPE_NAME, "mode",
			       enum_smbacl4_modes, e_simple);
	if (enumval == -1) {
		DEBUG(10, ("value for %s:mode unknown\n",
			   SMBACL4_PARAM_TYPE_NAME));
		return -1;
	}
	params->mode = (enum smbacl4_mode_enum)enumval;
	if (params->mode == e_special) {
		DBG_WARNING("nfs4:mode special is deprecated.\n");
	}

	params->do_chown = lp_parm_bool(SNUM(conn), SMBACL4_PARAM_TYPE_NAME,
		"chown", true);

	enumval = lp_parm_enum(SNUM(conn), SMBACL4_PARAM_TYPE_NAME, "acedup",
			       enum_smbacl4_acedups, e_merge);
	if (enumval == -1) {
		DEBUG(10, ("value for %s:acedup unknown\n",
			   SMBACL4_PARAM_TYPE_NAME));
		return -1;
	}
	params->acedup = (enum smbacl4_acedup_enum)enumval;
	if (params->acedup == e_ignore) {
		DBG_WARNING("nfs4:acedup ignore is deprecated.\n");
	}
	if (params->acedup == e_reject) {
		DBG_WARNING("nfs4:acedup ignore is deprecated.\n");
	}

	params->map_full_control = lp_acl_map_full_control(SNUM(conn));

	DEBUG(10, ("mode:%s, do_chown:%s, acedup: %s map full control:%s\n",
		enum_smbacl4_modes[params->mode].name,
		params->do_chown ? "true" : "false",
		enum_smbacl4_acedups[params->acedup].name,
		params->map_full_control ? "true" : "false"));

	return 0;
}

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

struct SMB4ACL_T *smb_create_smb4acl(TALLOC_CTX *mem_ctx)
{
	struct SMB4ACL_T *theacl;

	theacl = talloc_zero(mem_ctx, struct SMB4ACL_T);
	if (theacl==NULL)
	{
		DEBUG(0, ("TALLOC_SIZE failed\n"));
		errno = ENOMEM;
		return NULL;
	}
	theacl->controlflags = SEC_DESC_SELF_RELATIVE;
	/* theacl->first, last = NULL not needed */
	return theacl;
}

struct SMB4ACE_T *smb_add_ace4(struct SMB4ACL_T *acl, SMB_ACE4PROP_T *prop)
{
	struct SMB4ACE_T *ace;

	ace = talloc_zero(acl, struct SMB4ACE_T);
	if (ace==NULL)
	{
		DBG_ERR("talloc_zero failed\n");
		errno = ENOMEM;
		return NULL;
	}
	ace->prop = *prop;

	if (acl->first==NULL)
	{
		acl->first = ace;
		acl->last = ace;
	} else {
		acl->last->next = ace;
		acl->last = ace;
	}
	acl->naces++;

	return ace;
}

SMB_ACE4PROP_T *smb_get_ace4(struct SMB4ACE_T *ace)
{
	if (ace == NULL) {
		return NULL;
	}

	return &ace->prop;
}

struct SMB4ACE_T *smb_next_ace4(struct SMB4ACE_T *ace)
{
	if (ace == NULL) {
		return NULL;
	}

	return ace->next;
}

struct SMB4ACE_T *smb_first_ace4(struct SMB4ACL_T *acl)
{
	if (acl == NULL) {
		return NULL;
	}

	return acl->first;
}

uint32_t smb_get_naces(struct SMB4ACL_T *acl)
{
	if (acl == NULL) {
		return 0;
	}

	return acl->naces;
}

uint16_t smbacl4_get_controlflags(struct SMB4ACL_T *acl)
{
	if (acl == NULL) {
		return 0;
	}

	return acl->controlflags;
}

bool smbacl4_set_controlflags(struct SMB4ACL_T *acl, uint16_t controlflags)
{
	if (acl == NULL) {
		return false;
	}

	acl->controlflags = controlflags;
	return true;
}

bool nfs_ace_is_inherit(SMB_ACE4PROP_T *ace)
{
	return ace->aceFlags & (SMB_ACE4_INHERIT_ONLY_ACE|
				SMB_ACE4_FILE_INHERIT_ACE|
				SMB_ACE4_DIRECTORY_INHERIT_ACE);
}

static int smbacl4_GetFileOwner(struct connection_struct *conn,
				const struct smb_filename *smb_fname,
				SMB_STRUCT_STAT *psbuf)
{
	ZERO_STRUCTP(psbuf);

	/* Get the stat struct for the owner info. */
	if (vfs_stat_smb_basename(conn, smb_fname, psbuf) != 0)
	{
		DEBUG(8, ("vfs_stat_smb_basename failed with error %s\n",
			strerror(errno)));
		return -1;
	}

	return 0;
}

static void check_for_duplicate_sec_ace(struct security_ace *nt_ace_list,
					int *good_aces)
{
	struct security_ace *last = NULL;
	int i;

	if (*good_aces < 2) {
		return;
	}

	last = &nt_ace_list[(*good_aces) - 1];

	for (i = 0; i < (*good_aces) - 1; i++) {
		struct security_ace *cur = &nt_ace_list[i];

		if (cur->type == last->type &&
		    cur->flags == last->flags &&
		    cur->access_mask == last->access_mask &&
		    dom_sid_equal(&cur->trustee, &last->trustee))
		{
			struct dom_sid_buf sid_buf;

			DBG_INFO("Removing duplicate entry for SID %s.\n",
				 dom_sid_str_buf(&last->trustee, &sid_buf));
			(*good_aces)--;
		}
	}
}

static bool smbacl4_nfs42win(TALLOC_CTX *mem_ctx,
	const struct smbacl4_vfs_params *params,
	struct SMB4ACL_T *acl, /* in */
	struct dom_sid *psid_owner, /* in */
	struct dom_sid *psid_group, /* in */
	bool is_directory, /* in */
	struct security_ace **ppnt_ace_list, /* out */
	int *pgood_aces /* out */
)
{
	struct SMB4ACE_T *aceint;
	struct security_ace *nt_ace_list = NULL;
	int good_aces = 0;

	DEBUG(10, ("%s entered\n", __func__));

	nt_ace_list = talloc_zero_array(mem_ctx, struct security_ace,
					2 * acl->naces);
	if (nt_ace_list==NULL)
	{
		DEBUG(10, ("talloc error with %d aces", acl->naces));
		errno = ENOMEM;
		return false;
	}

	for (aceint = acl->first; aceint != NULL; aceint = aceint->next) {
		uint32_t mask;
		struct dom_sid sid;
		struct dom_sid_buf buf;
		SMB_ACE4PROP_T	*ace = &aceint->prop;
		uint32_t win_ace_flags;

		DEBUG(10, ("type: %d, iflags: %x, flags: %x, "
			   "mask: %x, who: %d\n",
			   ace->aceType, ace->flags,
			   ace->aceFlags, ace->aceMask, ace->who.id));

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
			   dom_sid_str_buf(&sid, &buf)));

		if (!is_directory && params->map_full_control) {
			/*
			 * Do we have all access except DELETE_CHILD
			 * (not caring about the delete bit).
			 */
			uint32_t test_mask = ((ace->aceMask|SMB_ACE4_DELETE|SMB_ACE4_DELETE_CHILD) &
						SMB_ACE4_ALL_MASKS);
			if (test_mask == SMB_ACE4_ALL_MASKS) {
				ace->aceMask |= SMB_ACE4_DELETE_CHILD;
			}
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

		/* Mapping of owner@ and group@ to creator owner and
		   creator group. Keep old behavior in mode special. */
		if (params->mode != e_special &&
		    ace->flags & SMB_ACE4_ID_SPECIAL &&
		    (ace->who.special_id == SMB_ACE4_WHO_OWNER ||
		     ace->who.special_id == SMB_ACE4_WHO_GROUP)) {
			DEBUG(10, ("Map special entry\n"));
			if (!(win_ace_flags & SEC_ACE_FLAG_INHERIT_ONLY)) {
				uint32_t win_ace_flags_current;
				DEBUG(10, ("Map current sid\n"));
				win_ace_flags_current = win_ace_flags &
					~(SEC_ACE_FLAG_OBJECT_INHERIT |
					  SEC_ACE_FLAG_CONTAINER_INHERIT);
				init_sec_ace(&nt_ace_list[good_aces++], &sid,
					     ace->aceType, mask,
					     win_ace_flags_current);
			}
			if (ace->who.special_id == SMB_ACE4_WHO_OWNER &&
			    win_ace_flags & (SEC_ACE_FLAG_OBJECT_INHERIT |
					     SEC_ACE_FLAG_CONTAINER_INHERIT)) {
				uint32_t win_ace_flags_creator;
				DEBUG(10, ("Map creator owner\n"));
				win_ace_flags_creator = win_ace_flags |
					SMB_ACE4_INHERIT_ONLY_ACE;
				init_sec_ace(&nt_ace_list[good_aces++],
					     &global_sid_Creator_Owner,
					     ace->aceType, mask,
					     win_ace_flags_creator);
			}
			if (ace->who.special_id == SMB_ACE4_WHO_GROUP &&
			    win_ace_flags & (SEC_ACE_FLAG_OBJECT_INHERIT |
					     SEC_ACE_FLAG_CONTAINER_INHERIT)) {
				uint32_t win_ace_flags_creator;
				DEBUG(10, ("Map creator owner group\n"));
				win_ace_flags_creator = win_ace_flags |
					SMB_ACE4_INHERIT_ONLY_ACE;
				init_sec_ace(&nt_ace_list[good_aces++],
					     &global_sid_Creator_Group,
					     ace->aceType, mask,
					     win_ace_flags_creator);
			}
		} else {
			DEBUG(10, ("Map normal sid\n"));
			init_sec_ace(&nt_ace_list[good_aces++], &sid,
				     ace->aceType, mask,
				     win_ace_flags);
		}

		check_for_duplicate_sec_ace(nt_ace_list, &good_aces);
	}

	nt_ace_list = talloc_realloc(mem_ctx, nt_ace_list, struct security_ace,
				     good_aces);

	/* returns a NULL ace list when good_aces is zero. */
	if (good_aces && nt_ace_list == NULL) {
		DEBUG(10, ("realloc error with %d aces", good_aces));
		errno = ENOMEM;
		return false;
	}

	*ppnt_ace_list = nt_ace_list;
	*pgood_aces = good_aces;

	return true;
}

static NTSTATUS smb_get_nt_acl_nfs4_common(const SMB_STRUCT_STAT *sbuf,
					   const struct smbacl4_vfs_params *params,
					   uint32_t security_info,
					   TALLOC_CTX *mem_ctx,
					   struct security_descriptor **ppdesc,
					   struct SMB4ACL_T *theacl)
{
	int good_aces = 0;
	struct dom_sid sid_owner, sid_group;
	size_t sd_size = 0;
	struct security_ace *nt_ace_list = NULL;
	struct security_acl *psa = NULL;
	TALLOC_CTX *frame = talloc_stackframe();
	bool ok;

	if (theacl==NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_ACCESS_DENIED; /* special because we
						 * need to think through
						 * the null case.*/
	}

	uid_to_sid(&sid_owner, sbuf->st_ex_uid);
	gid_to_sid(&sid_group, sbuf->st_ex_gid);

	ok = smbacl4_nfs42win(frame, params, theacl, &sid_owner, &sid_group,
			      S_ISDIR(sbuf->st_ex_mode),
			      &nt_ace_list, &good_aces);
	if (!ok) {
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
		mem_ctx, SD_REVISION, smbacl4_get_controlflags(theacl),
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
			      const struct smbacl4_vfs_params *pparams,
			      uint32_t security_info,
			      TALLOC_CTX *mem_ctx,
			      struct security_descriptor **ppdesc,
			      struct SMB4ACL_T *theacl)
{
	struct smbacl4_vfs_params params;

	DEBUG(10, ("smb_fget_nt_acl_nfs4 invoked for %s\n", fsp_str_dbg(fsp)));

	if (!VALID_STAT(fsp->fsp_name->st)) {
		NTSTATUS status;

		status = vfs_stat_fsp(fsp);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	if (pparams == NULL) {
		/* Special behaviours */
		if (smbacl4_get_vfs_params(fsp->conn, &params)) {
			return NT_STATUS_NO_MEMORY;
		}
		pparams = &params;
	}

	return smb_get_nt_acl_nfs4_common(&fsp->fsp_name->st, pparams,
					  security_info,
					  mem_ctx, ppdesc, theacl);
}

NTSTATUS smb_get_nt_acl_nfs4(struct connection_struct *conn,
			     const struct smb_filename *smb_fname,
			     const struct smbacl4_vfs_params *pparams,
			     uint32_t security_info,
			     TALLOC_CTX *mem_ctx,
			     struct security_descriptor **ppdesc,
			     struct SMB4ACL_T *theacl)
{
	SMB_STRUCT_STAT sbuf;
	struct smbacl4_vfs_params params;
	const SMB_STRUCT_STAT *psbuf = NULL;

	DEBUG(10, ("smb_get_nt_acl_nfs4 invoked for %s\n",
		smb_fname->base_name));

	if (VALID_STAT(smb_fname->st)) {
		psbuf = &smb_fname->st;
	}

	if (psbuf == NULL) {
		if (smbacl4_GetFileOwner(conn, smb_fname, &sbuf)) {
			return map_nt_error_from_unix(errno);
		}
		psbuf = &sbuf;
	}

	if (pparams == NULL) {
		/* Special behaviours */
		if (smbacl4_get_vfs_params(conn, &params)) {
			return NT_STATUS_NO_MEMORY;
		}
		pparams = &params;
	}

	return smb_get_nt_acl_nfs4_common(psbuf, pparams, security_info,
					  mem_ctx, ppdesc, theacl);
}

static void smbacl4_dump_nfs4acl(int level, struct SMB4ACL_T *acl)
{
	struct SMB4ACE_T *aceint;

	DEBUG(level, ("NFS4ACL: size=%d\n", acl->naces));

	for (aceint = acl->first; aceint != NULL; aceint = aceint->next) {
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
	struct SMB4ACL_T *acl,
	SMB_ACE4PROP_T *aceNew)
{
	struct SMB4ACE_T *aceint;

	for (aceint = acl->first; aceint != NULL; aceint = aceint->next) {
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

static int smbacl4_MergeIgnoreReject(enum smbacl4_acedup_enum acedup,
				     struct SMB4ACL_T *theacl,
				     SMB_ACE4PROP_T *ace,
				     bool *paddNewACE)
{
	int	result = 0;
	SMB_ACE4PROP_T *ace4found = smbacl4_find_equal_special(theacl, ace);
	if (ace4found)
	{
		switch(acedup)
		{
		case e_merge: /* "merge" flags */
			*paddNewACE = false;
			ace4found->aceFlags |= ace->aceFlags;
			ace4found->aceMask |= ace->aceMask;
			break;
		case e_ignore: /* leave out this record */
			*paddNewACE = false;
			break;
		case e_reject: /* do an error */
			DBG_INFO("ACL rejected by duplicate nt ace.\n");
			errno = EINVAL; /* SHOULD be set on any _real_ error */
			result = -1;
			break;
		default:
			break;
		}
	}
	return result;
}

static int nfs4_acl_add_ace(enum smbacl4_acedup_enum acedup,
			    struct SMB4ACL_T *nfs4_acl,
			    SMB_ACE4PROP_T *nfs4_ace)
{
	bool add_ace = true;

	if (acedup != e_dontcare) {
		int ret;

		ret = smbacl4_MergeIgnoreReject(acedup, nfs4_acl,
						nfs4_ace, &add_ace);
		if (ret == -1) {
			return -1;
		}
	}

	if (add_ace) {
		smb_add_ace4(nfs4_acl, nfs4_ace);
	}

	return 0;
}

static int nfs4_acl_add_sec_ace(bool is_directory,
				const struct smbacl4_vfs_params *params,
				uid_t ownerUID,
				gid_t ownerGID,
				const struct security_ace *ace_nt,
				struct SMB4ACL_T *nfs4_acl)
{
	struct dom_sid_buf buf;
	SMB_ACE4PROP_T nfs4_ace = { 0 };
	SMB_ACE4PROP_T nfs4_ace_2 = { 0 };
	bool add_ace2 = false;
	int ret;

	DEBUG(10, ("got ace for %s\n",
		   dom_sid_str_buf(&ace_nt->trustee, &buf)));

	/* only ACCESS|DENY supported right now */
	nfs4_ace.aceType = ace_nt->type;

	nfs4_ace.aceFlags =
		map_windows_ace_flags_to_nfs4_ace_flags(ace_nt->flags);

	/* remove inheritance flags on files */
	if (!is_directory) {
		DEBUG(10, ("Removing inheritance flags from a file\n"));
		nfs4_ace.aceFlags &= ~(SMB_ACE4_FILE_INHERIT_ACE|
				       SMB_ACE4_DIRECTORY_INHERIT_ACE|
				       SMB_ACE4_NO_PROPAGATE_INHERIT_ACE|
				       SMB_ACE4_INHERIT_ONLY_ACE);
	}

	nfs4_ace.aceMask = ace_nt->access_mask & (SEC_STD_ALL | SEC_FILE_ALL);

	se_map_generic(&nfs4_ace.aceMask, &file_generic_mapping);

	if (dom_sid_equal(&ace_nt->trustee, &global_sid_World)) {
		nfs4_ace.who.special_id = SMB_ACE4_WHO_EVERYONE;
		nfs4_ace.flags |= SMB_ACE4_ID_SPECIAL;
	} else if (params->mode!=e_special &&
		   dom_sid_equal(&ace_nt->trustee,
				 &global_sid_Creator_Owner)) {
		DEBUG(10, ("Map creator owner\n"));
		nfs4_ace.who.special_id = SMB_ACE4_WHO_OWNER;
		nfs4_ace.flags |= SMB_ACE4_ID_SPECIAL;
		/* A non inheriting creator owner entry has no effect. */
		nfs4_ace.aceFlags |= SMB_ACE4_INHERIT_ONLY_ACE;
		if (!(nfs4_ace.aceFlags & SMB_ACE4_DIRECTORY_INHERIT_ACE)
		    && !(nfs4_ace.aceFlags & SMB_ACE4_FILE_INHERIT_ACE)) {
			return 0;
		}
	} else if (params->mode!=e_special &&
		   dom_sid_equal(&ace_nt->trustee,
				 &global_sid_Creator_Group)) {
		DEBUG(10, ("Map creator owner group\n"));
		nfs4_ace.who.special_id = SMB_ACE4_WHO_GROUP;
		nfs4_ace.flags |= SMB_ACE4_ID_SPECIAL;
		/* A non inheriting creator group entry has no effect. */
		nfs4_ace.aceFlags |= SMB_ACE4_INHERIT_ONLY_ACE;
		if (!(nfs4_ace.aceFlags & SMB_ACE4_DIRECTORY_INHERIT_ACE)
		    && !(nfs4_ace.aceFlags & SMB_ACE4_FILE_INHERIT_ACE)) {
			return 0;
		}
	} else {
		struct unixid unixid;
		bool ok;

		ok = sids_to_unixids(&ace_nt->trustee, 1, &unixid);
		if (!ok) {
			DBG_WARNING("Could not convert %s to uid or gid.\n",
				    dom_sid_str_buf(&ace_nt->trustee, &buf));
			return 0;
		}

		if (dom_sid_compare_domain(&ace_nt->trustee,
					   &global_sid_Unix_NFS) == 0) {
			return 0;
		}

		switch (unixid.type) {
		case ID_TYPE_BOTH:
			nfs4_ace.aceFlags |= SMB_ACE4_IDENTIFIER_GROUP;
			nfs4_ace.who.gid = unixid.id;

			if (ownerUID == unixid.id &&
			    !nfs_ace_is_inherit(&nfs4_ace))
			{
				/*
				 * IDMAP_TYPE_BOTH for owner. Add
				 * additional user entry, which can be
				 * mapped to special:owner to reflect
				 * the permissions in the modebits.
				 *
				 * This only applies to non-inheriting
				 * entries as only these are replaced
				 * with SPECIAL_OWNER in nfs4:mode=simple.
				 */
				nfs4_ace_2 = (SMB_ACE4PROP_T) {
					.who.uid = unixid.id,
					.aceFlags = (nfs4_ace.aceFlags &
						    ~SMB_ACE4_IDENTIFIER_GROUP),
					.aceMask = nfs4_ace.aceMask,
					.aceType = nfs4_ace.aceType,
				};
				add_ace2 = true;
			}
			break;
		case ID_TYPE_GID:
			nfs4_ace.aceFlags |= SMB_ACE4_IDENTIFIER_GROUP;
			nfs4_ace.who.gid = unixid.id;
			break;
		case ID_TYPE_UID:
			nfs4_ace.who.uid = unixid.id;
			break;
		case ID_TYPE_NOT_SPECIFIED:
		default:
			DBG_WARNING("Could not convert %s to uid or gid.\n",
				    dom_sid_str_buf(&ace_nt->trustee, &buf));
			return 0;
		}
	}

	ret = nfs4_acl_add_ace(params->acedup, nfs4_acl, &nfs4_ace);
	if (ret != 0) {
		return -1;
	}

	if (!add_ace2) {
		return 0;
	}

	return nfs4_acl_add_ace(params->acedup, nfs4_acl, &nfs4_ace_2);
}

static void smbacl4_substitute_special(struct SMB4ACL_T *acl,
				       uid_t ownerUID,
				       gid_t ownerGID)
{
	struct SMB4ACE_T *aceint;

	for (aceint = acl->first; aceint != NULL; aceint = aceint->next) {
		SMB_ACE4PROP_T *ace = &aceint->prop;

		DEBUG(10,("ace type: %d, iflags: %x, flags: %x, "
			  "mask: %x, who: %d\n",
			  ace->aceType, ace->flags, ace->aceFlags,
			  ace->aceMask, ace->who.id));

		if (!(ace->flags & SMB_ACE4_ID_SPECIAL) &&
		    !(ace->aceFlags & SMB_ACE4_IDENTIFIER_GROUP) &&
		    ace->who.uid == ownerUID) {
			ace->flags |= SMB_ACE4_ID_SPECIAL;
			ace->who.special_id = SMB_ACE4_WHO_OWNER;
			DEBUG(10,("replaced with special owner ace\n"));
		}

		if (!(ace->flags & SMB_ACE4_ID_SPECIAL) &&
		    ace->aceFlags & SMB_ACE4_IDENTIFIER_GROUP &&
		    ace->who.uid == ownerGID) {
			ace->flags |= SMB_ACE4_ID_SPECIAL;
			ace->who.special_id = SMB_ACE4_WHO_GROUP;
			DEBUG(10,("replaced with special group ace\n"));
		}
	}
}

static void smbacl4_substitute_simple(struct SMB4ACL_T *acl,
				      uid_t ownerUID,
				      gid_t ownerGID)
{
	struct SMB4ACE_T *aceint;

	for (aceint = acl->first; aceint != NULL; aceint = aceint->next) {
		SMB_ACE4PROP_T *ace = &aceint->prop;

		DEBUG(10,("ace type: %d, iflags: %x, flags: %x, "
			  "mask: %x, who: %d\n",
			  ace->aceType, ace->flags, ace->aceFlags,
			  ace->aceMask, ace->who.id));

		if (!(ace->flags & SMB_ACE4_ID_SPECIAL) &&
		    !(ace->aceFlags & SMB_ACE4_IDENTIFIER_GROUP) &&
		    ace->who.uid == ownerUID &&
		    !nfs_ace_is_inherit(ace)) {
			ace->flags |= SMB_ACE4_ID_SPECIAL;
			ace->who.special_id = SMB_ACE4_WHO_OWNER;
			DEBUG(10,("replaced with special owner ace\n"));
		}

		if (!(ace->flags & SMB_ACE4_ID_SPECIAL) &&
		    ace->aceFlags & SMB_ACE4_IDENTIFIER_GROUP &&
		    ace->who.gid == ownerGID &&
		    !nfs_ace_is_inherit(ace)) {
			ace->flags |= SMB_ACE4_ID_SPECIAL;
			ace->who.special_id = SMB_ACE4_WHO_GROUP;
			DEBUG(10,("replaced with special group ace\n"));
		}
	}
}

static struct SMB4ACL_T *smbacl4_win2nfs4(
	TALLOC_CTX *mem_ctx,
	bool is_directory,
	const struct security_acl *dacl,
	const struct smbacl4_vfs_params *pparams,
	uid_t ownerUID,
	gid_t ownerGID
)
{
	struct SMB4ACL_T *theacl;
	uint32_t i;

	DEBUG(10, ("smbacl4_win2nfs4 invoked\n"));

	theacl = smb_create_smb4acl(mem_ctx);
	if (theacl==NULL)
		return NULL;

	for(i=0; i<dacl->num_aces; i++) {
		int ret;

		ret = nfs4_acl_add_sec_ace(is_directory, pparams,
					   ownerUID, ownerGID,
					   dacl->aces + i, theacl);
		if (ret == -1) {
			return NULL;
		}
	}

	if (pparams->mode==e_simple) {
		smbacl4_substitute_simple(theacl, ownerUID, ownerGID);
	}

	if (pparams->mode==e_special) {
		smbacl4_substitute_special(theacl, ownerUID, ownerGID);
	}

	return theacl;
}

NTSTATUS smb_set_nt_acl_nfs4(vfs_handle_struct *handle, files_struct *fsp,
	const struct smbacl4_vfs_params *pparams,
	uint32_t security_info_sent,
	const struct security_descriptor *psd,
	set_nfs4acl_native_fn_t set_nfs4_native)
{
	struct smbacl4_vfs_params params;
	struct SMB4ACL_T *theacl = NULL;
	bool	result, is_directory;

	bool set_acl_as_root = false;
	uid_t newUID = (uid_t)-1;
	gid_t newGID = (gid_t)-1;
	int saved_errno;
	NTSTATUS status;
	TALLOC_CTX *frame = talloc_stackframe();

	DEBUG(10, ("smb_set_nt_acl_nfs4 invoked for %s\n", fsp_str_dbg(fsp)));

	if ((security_info_sent & (SECINFO_DACL |
		SECINFO_GROUP | SECINFO_OWNER)) == 0)
	{
		DEBUG(9, ("security_info_sent (0x%x) ignored\n",
			security_info_sent));
		TALLOC_FREE(frame);
		return NT_STATUS_OK; /* won't show error - later to be
				      * refined... */
	}

	if (security_descriptor_with_ms_nfs(psd)) {
		TALLOC_FREE(frame);
		return NT_STATUS_OK;
	}

	if (pparams == NULL) {
		/* Special behaviours */
		if (smbacl4_get_vfs_params(fsp->conn, &params)) {
			TALLOC_FREE(frame);
			return NT_STATUS_NO_MEMORY;
		}
		pparams = &params;
	}

	status = vfs_stat_fsp(fsp);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	is_directory = S_ISDIR(fsp->fsp_name->st.st_ex_mode);

	if (pparams->do_chown) {
		/* chown logic is a copy/paste from posix_acl.c:set_nt_acl */

		uid_t old_uid = fsp->fsp_name->st.st_ex_uid;
		uid_t old_gid = fsp->fsp_name->st.st_ex_uid;
		status = unpack_nt_owners(fsp->conn, &newUID, &newGID,
					  security_info_sent, psd);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(8, ("unpack_nt_owners failed"));
			TALLOC_FREE(frame);
			return status;
		}
		if (((newUID != (uid_t)-1) && (old_uid != newUID)) ||
		    ((newGID != (gid_t)-1) && (old_gid != newGID)))
		{
			status = try_chown(fsp, newUID, newGID);
			if (!NT_STATUS_IS_OK(status)) {
				DEBUG(3,("chown %s, %u, %u failed. Error = "
					 "%s.\n", fsp_str_dbg(fsp),
					 (unsigned int)newUID,
					 (unsigned int)newGID,
					 nt_errstr(status)));
				TALLOC_FREE(frame);
				return status;
			}

			DEBUG(10,("chown %s, %u, %u succeeded.\n",
				  fsp_str_dbg(fsp), (unsigned int)newUID,
				  (unsigned int)newGID));

			/*
			 * Owner change, need to update stat info.
			 */
			status = vfs_stat_fsp(fsp);
			if (!NT_STATUS_IS_OK(status)) {
				TALLOC_FREE(frame);
				return status;
			}

			/* If we successfully chowned, we know we must
			 * be able to set the acl, so do it as root.
			 */
			set_acl_as_root = true;
		}
	}

	if (!(security_info_sent & SECINFO_DACL) || psd->dacl ==NULL) {
		DEBUG(10, ("no dacl found; security_info_sent = 0x%x\n",
			   security_info_sent));
		TALLOC_FREE(frame);
		return NT_STATUS_OK;
	}

	theacl = smbacl4_win2nfs4(frame, is_directory, psd->dacl, pparams,
				  fsp->fsp_name->st.st_ex_uid,
				  fsp->fsp_name->st.st_ex_gid);
	if (!theacl) {
		TALLOC_FREE(frame);
		return map_nt_error_from_unix(errno);
	}

	smbacl4_set_controlflags(theacl, psd->type);
	smbacl4_dump_nfs4acl(10, theacl);

	if (set_acl_as_root) {
		become_root();
	}
	result = set_nfs4_native(handle, fsp, theacl);
	saved_errno = errno;
	if (set_acl_as_root) {
		unbecome_root();
	}

	TALLOC_FREE(frame);

	if (result!=true) {
		errno = saved_errno;
		DEBUG(10, ("set_nfs4_native failed with %s\n",
			   strerror(errno)));
		return map_nt_error_from_unix(errno);
	}

	DEBUG(10, ("smb_set_nt_acl_nfs4 succeeded\n"));
	return NT_STATUS_OK;
}
