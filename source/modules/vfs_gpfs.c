/*
   Unix SMB/CIFS implementation.
   Wrap gpfs calls in vfs functions.
 
   Copyright (C) Christian Ambach <cambach1@de.ibm.com> 2006
   
   Major code contributions by Chetan Shringarpure <chetan.sh@in.ibm.com>
                            and Gomati Mohanan <gomati.mohanan@in.ibm.com>
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
  

*/

#include "includes.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

#include <gpfs_gpl.h>
#include "nfs4_acls.h"
#include "vfs_gpfs.h"

static int vfs_gpfs_kernel_flock(vfs_handle_struct *handle, files_struct *fsp, 
				 uint32 share_mode)
{

	START_PROFILE(syscall_kernel_flock);

	kernel_flock(fsp->fh->fd, share_mode);

	if (!set_gpfs_sharemode(fsp, fsp->access_mask, fsp->share_access)) {

		return -1;

	}

	END_PROFILE(syscall_kernel_flock);

	return 0;
}

static int vfs_gpfs_setlease(vfs_handle_struct *handle, files_struct *fsp, 
			     int leasetype)
{
	int ret;
	
	START_PROFILE(syscall_linux_setlease);
	
	if ( linux_set_lease_sighandler(fsp->fh->fd) == -1)
		return -1;

	ret = set_gpfs_lease(fsp->fh->fd,leasetype);
	
	if ( ret < 0 ) {
		/* This must have come from GPFS not being available */
		/* or some other error, hence call the default */
		ret = linux_setlease(fsp->fh->fd, leasetype);
	}

	END_PROFILE(syscall_linux_setlease);

	return ret;
}



static void gpfs_dumpacl(int level, struct gpfs_acl *gacl)
{
	int	i;
	if (gacl==NULL)
	{
		DEBUG(0, ("gpfs acl is NULL\n"));
		return;
	}

	DEBUG(level, ("gpfs acl: nace: %d, type:%d, version:%d, level:%d, len:%d\n",
		gacl->acl_nace, gacl->acl_type, gacl->acl_version, gacl->acl_level, gacl->acl_len));
	for(i=0; i<gacl->acl_nace; i++)
	{
		struct gpfs_ace_v4 *gace = gacl->ace_v4 + i;
		DEBUG(level, ("\tace[%d]: type:%d, flags:0x%x, mask:0x%x, iflags:0x%x, who:%u\n",
			i, gace->aceType, gace->aceFlags, gace->aceMask,
			gace->aceIFlags, gace->aceWho));
	}
}

static struct gpfs_acl *gpfs_getacl_alloc(const char *fname, gpfs_aclType_t type)
{
	struct gpfs_acl *acl;
	size_t len = 200;
	int ret;
	TALLOC_CTX *mem_ctx = talloc_tos();

	acl = (struct gpfs_acl *)TALLOC_SIZE(mem_ctx, len);
	if (acl == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	acl->acl_len = len;
	acl->acl_level = 0;
	acl->acl_version = 0;
	acl->acl_type = type;

	ret = smbd_gpfs_getacl((char *)fname, GPFS_GETACL_STRUCT | GPFS_ACL_SAMBA, acl);
	if ((ret != 0) && (errno == ENOSPC)) {
		struct gpfs_acl *new_acl = (struct gpfs_acl *)TALLOC_SIZE(
			mem_ctx, acl->acl_len + sizeof(struct gpfs_acl));
		if (new_acl == NULL) {
			errno = ENOMEM;
			return NULL;
		}

		new_acl->acl_len = acl->acl_len;
		new_acl->acl_level = acl->acl_level;
		new_acl->acl_version = acl->acl_version;
		new_acl->acl_type = acl->acl_type;
		acl = new_acl;

		ret = smbd_gpfs_getacl((char *)fname, GPFS_GETACL_STRUCT | GPFS_ACL_SAMBA, acl);
	}
	if (ret != 0)
	{
		DEBUG(8, ("smbd_gpfs_getacl failed with %s\n",strerror(errno)));
		return NULL;
	}

	return acl;
}

/* Tries to get nfs4 acls and returns SMB ACL allocated.
 * On failure returns 1 if it got non-NFSv4 ACL to prompt 
 * retry with POSIX ACL checks.
 * On failure returns -1 if there is system (GPFS) error, check errno.
 * Returns 0 on success
 */
static int gpfs_get_nfs4_acl(const char *fname, SMB4ACL_T **ppacl)
{
	int i;
	struct gpfs_acl *gacl = NULL;
	DEBUG(10, ("gpfs_get_nfs4_acl invoked for %s\n", fname));

	/* First get the real acl length */
	gacl = gpfs_getacl_alloc(fname, 0);
	if (gacl == NULL) {
		DEBUG(9, ("gpfs_getacl failed for %s with %s\n",
			   fname, strerror(errno)));
		return -1;
	}

	if (gacl->acl_type != GPFS_ACL_TYPE_NFS4) {
		DEBUG(10, ("Got non-nfsv4 acl\n"));
		/* Retry with POSIX ACLs check */
		return 1;
	}

	*ppacl = smb_create_smb4acl();

	DEBUG(10, ("len: %d, level: %d, version: %d, nace: %d\n",
		   gacl->acl_len, gacl->acl_level, gacl->acl_version,
		   gacl->acl_nace));

	for (i=0; i<gacl->acl_nace; i++) {
		struct gpfs_ace_v4 *gace = &gacl->ace_v4[i];
		SMB_ACE4PROP_T smbace;
		DEBUG(10, ("type: %d, iflags: %x, flags: %x, mask: %x, "
			   "who: %d\n", gace->aceType, gace->aceIFlags,
			   gace->aceFlags, gace->aceMask, gace->aceWho));

		memset(&smbace, 0, sizeof(SMB4ACE_T));
		if (gace->aceIFlags & ACE4_IFLAG_SPECIAL_ID) {
			smbace.flags |= SMB_ACE4_ID_SPECIAL;
			switch (gace->aceWho) {
			case ACE4_SPECIAL_OWNER:
				smbace.who.special_id = SMB_ACE4_WHO_OWNER;
				break;
			case ACE4_SPECIAL_GROUP:
				smbace.who.special_id = SMB_ACE4_WHO_GROUP;
				break;
			case ACE4_SPECIAL_EVERYONE:
				smbace.who.special_id = SMB_ACE4_WHO_EVERYONE;
				break;
			default:
				DEBUG(8, ("invalid special gpfs id %d "
					  "ignored\n", gace->aceWho));
				continue; /* don't add it */
			}
		} else {
			if (gace->aceFlags & ACE4_FLAG_GROUP_ID)
				smbace.who.gid = gace->aceWho;
			else
				smbace.who.uid = gace->aceWho;
		}

		/* remove redundent deny entries */
		if (i > 0 && gace->aceType == SMB_ACE4_ACCESS_DENIED_ACE_TYPE) {
			struct gpfs_ace_v4 *prev = &gacl->ace_v4[i-1];
			if (prev->aceType == SMB_ACE4_ACCESS_ALLOWED_ACE_TYPE &&
			    prev->aceFlags == gace->aceFlags &&
			    prev->aceIFlags == gace->aceIFlags &&
			    (gace->aceMask & prev->aceMask) == 0 &&
			    gace->aceWho == prev->aceWho) {
				/* its redundent - skip it */
				continue;
			}                                                
		}

		smbace.aceType = gace->aceType;
		smbace.aceFlags = gace->aceFlags;
		smbace.aceMask = gace->aceMask;
		smb_add_ace4(*ppacl, &smbace);
	}

	return 0;
}

static NTSTATUS gpfsacl_fget_nt_acl(vfs_handle_struct *handle,
	files_struct *fsp, uint32 security_info,
	SEC_DESC **ppdesc)
{
	SMB4ACL_T *pacl = NULL;
	int	result;

	*ppdesc = NULL;
	result = gpfs_get_nfs4_acl(fsp->fsp_name, &pacl);

	if (result == 0)
		return smb_fget_nt_acl_nfs4(fsp, security_info, ppdesc, pacl);

	if (result > 0) {
		DEBUG(10, ("retrying with posix acl...\n"));
		return posix_fget_nt_acl(fsp, security_info, ppdesc);
	}

	/* GPFS ACL was not read, something wrong happened, error code is set in errno */
	return map_nt_error_from_unix(errno);
}

static NTSTATUS gpfsacl_get_nt_acl(vfs_handle_struct *handle,
	const char *name,
	uint32 security_info, SEC_DESC **ppdesc)
{
	SMB4ACL_T *pacl = NULL;
	int	result;

	*ppdesc = NULL;
	result = gpfs_get_nfs4_acl(name, &pacl);

	if (result == 0)
		return smb_get_nt_acl_nfs4(handle->conn, name, security_info, ppdesc, pacl);

	if (result > 0) {
		DEBUG(10, ("retrying with posix acl...\n"));
		return posix_get_nt_acl(handle->conn, name, security_info, ppdesc);
	}

	/* GPFS ACL was not read, something wrong happened, error code is set in errno */
	return map_nt_error_from_unix(errno);
}

static bool gpfsacl_process_smbacl(files_struct *fsp, SMB4ACL_T *smbacl)
{
	int ret;
	gpfs_aclLen_t gacl_len;
	SMB4ACE_T	*smbace;
	struct gpfs_acl *gacl;
	TALLOC_CTX *mem_ctx  = talloc_tos();

	gacl_len = sizeof(struct gpfs_acl) +
		(smb_get_naces(smbacl)-1)*sizeof(gpfs_ace_v4_t);

	gacl = TALLOC_SIZE(mem_ctx, gacl_len);
	if (gacl == NULL) {
		DEBUG(0, ("talloc failed\n"));
		errno = ENOMEM;
		return False;
	}

	gacl->acl_len = gacl_len;
	gacl->acl_level = 0;
	gacl->acl_version = GPFS_ACL_VERSION_NFS4;
	gacl->acl_type = GPFS_ACL_TYPE_NFS4;
	gacl->acl_nace = 0; /* change later... */

	for (smbace=smb_first_ace4(smbacl); smbace!=NULL; smbace = smb_next_ace4(smbace)) {
		struct gpfs_ace_v4 *gace = &gacl->ace_v4[gacl->acl_nace];
		SMB_ACE4PROP_T	*aceprop = smb_get_ace4(smbace);

		gace->aceType = aceprop->aceType;
		gace->aceFlags = aceprop->aceFlags;
		gace->aceMask = aceprop->aceMask;
		
		/*
		 * GPFS can't distinguish between WRITE and APPEND on
		 * files, so one being set without the other is an
		 * error. Sorry for the many ()'s :-)
		 */
		
		if (!fsp->is_directory
		    &&
		    ((((gace->aceMask & ACE4_MASK_WRITE) == 0)
		      && ((gace->aceMask & ACE4_MASK_APPEND) != 0))
		     ||
		     (((gace->aceMask & ACE4_MASK_WRITE) != 0)
		      && ((gace->aceMask & ACE4_MASK_APPEND) == 0)))
		    &&
		    lp_parm_bool(fsp->conn->params->service, "gpfs",
				 "merge_writeappend", True)) {
			DEBUG(2, ("vfs_gpfs.c: file [%s]: ACE contains "
				  "WRITE^APPEND, setting WRITE|APPEND\n",
				  fsp->fsp_name));
			gace->aceMask |= ACE4_MASK_WRITE|ACE4_MASK_APPEND;
		}
		
		gace->aceIFlags = (aceprop->flags&SMB_ACE4_ID_SPECIAL) ? ACE4_IFLAG_SPECIAL_ID : 0;
		
		if (aceprop->flags&SMB_ACE4_ID_SPECIAL)
		{
			switch(aceprop->who.special_id)
			{
			case SMB_ACE4_WHO_EVERYONE:
				gace->aceWho = ACE4_SPECIAL_EVERYONE;
				break;
			case SMB_ACE4_WHO_OWNER:
				gace->aceWho = ACE4_SPECIAL_OWNER;
				break;
			case SMB_ACE4_WHO_GROUP:
				gace->aceWho = ACE4_SPECIAL_GROUP;
				break;
			default:
				DEBUG(8, ("unsupported special_id %d\n", aceprop->who.special_id));
				continue; /* don't add it !!! */
			}
		} else {
			/* just only for the type safety... */
			if (aceprop->aceFlags&SMB_ACE4_IDENTIFIER_GROUP)
				gace->aceWho = aceprop->who.gid;
			else
				gace->aceWho = aceprop->who.uid;
		}

		gacl->acl_nace++;
	}

	ret = smbd_gpfs_putacl(fsp->fsp_name, GPFS_PUTACL_STRUCT | GPFS_ACL_SAMBA, gacl);
	if (ret != 0) {
		DEBUG(8, ("gpfs_putacl failed with %s\n", strerror(errno)));
		gpfs_dumpacl(8, gacl);
		return False;
	}

	DEBUG(10, ("gpfs_putacl succeeded\n"));
	return True;
}

static NTSTATUS gpfsacl_set_nt_acl_internal(files_struct *fsp, uint32 security_info_sent, SEC_DESC *psd)
{
	struct gpfs_acl *acl;
	NTSTATUS result = NT_STATUS_ACCESS_DENIED;

	acl = gpfs_getacl_alloc(fsp->fsp_name, 0);
	if (acl == NULL)
		return result;

	if (acl->acl_version&GPFS_ACL_VERSION_NFS4)
	{
		result = smb_set_nt_acl_nfs4(
			fsp, security_info_sent, psd,
			gpfsacl_process_smbacl);
	} else { /* assume POSIX ACL - by default... */
		result = set_nt_acl(fsp, security_info_sent, psd);
	}

	return result;
}

static NTSTATUS gpfsacl_fset_nt_acl(vfs_handle_struct *handle, files_struct *fsp, uint32 security_info_sent, SEC_DESC *psd)
{
	return gpfsacl_set_nt_acl_internal(fsp, security_info_sent, psd);
}

static NTSTATUS gpfsacl_set_nt_acl(vfs_handle_struct *handle, files_struct *fsp, char *name, uint32 security_info_sent, SEC_DESC *psd)
{
	return gpfsacl_set_nt_acl_internal(fsp, security_info_sent, psd);
}

static SMB_ACL_T gpfs2smb_acl(const struct gpfs_acl *pacl)
{
	SMB_ACL_T result;
	int i;

	result = sys_acl_init(pacl->acl_nace);
	if (result == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	result->count = pacl->acl_nace;

	for (i=0; i<pacl->acl_nace; i++) {
		struct smb_acl_entry *ace = &result->acl[i];
		const struct gpfs_ace_v1 *g_ace = &pacl->ace_v1[i];

		DEBUG(10, ("Converting type %d id %lu perm %x\n",
			   (int)g_ace->ace_type, (unsigned long)g_ace->ace_who,
			   (int)g_ace->ace_perm));

		switch (g_ace->ace_type) {
		case GPFS_ACL_USER:
			ace->a_type = SMB_ACL_USER;
			ace->uid = (uid_t)g_ace->ace_who;
			break;
		case GPFS_ACL_USER_OBJ:
			ace->a_type = SMB_ACL_USER_OBJ;
			break;
		case GPFS_ACL_GROUP:
			ace->a_type = SMB_ACL_GROUP;
			ace->gid = (gid_t)g_ace->ace_who;
			break;
		case GPFS_ACL_GROUP_OBJ:
 			ace->a_type = SMB_ACL_GROUP_OBJ;
			break;
		case GPFS_ACL_OTHER:
			ace->a_type = SMB_ACL_OTHER;
			break;
		case GPFS_ACL_MASK:
			ace->a_type = SMB_ACL_MASK;
			break;
		default:
			DEBUG(10, ("Got invalid ace_type: %d\n",
				   g_ace->ace_type));
			errno = EINVAL;
			SAFE_FREE(result);
			return NULL;
		}

		ace->a_perm = 0;
		ace->a_perm |= (g_ace->ace_perm & ACL_PERM_READ) ?
			SMB_ACL_READ : 0;
		ace->a_perm |= (g_ace->ace_perm & ACL_PERM_WRITE) ?
			SMB_ACL_WRITE : 0;
		ace->a_perm |= (g_ace->ace_perm & ACL_PERM_EXECUTE) ?
			SMB_ACL_EXECUTE : 0;

		DEBUGADD(10, ("Converted to %d perm %x\n",
			      ace->a_type, ace->a_perm));
	}

	return result;
}

static SMB_ACL_T gpfsacl_get_posix_acl(const char *path, gpfs_aclType_t type)
{
	struct gpfs_acl *pacl;
	SMB_ACL_T result = NULL;

	pacl = gpfs_getacl_alloc(path, type);

	if (pacl == NULL) {
		DEBUG(10, ("gpfs_getacl failed for %s with %s\n",
			   path, strerror(errno)));
		if (errno == 0) {
			errno = EINVAL;
		}
		goto done;
	}

	if (pacl->acl_version != GPFS_ACL_VERSION_POSIX) {
		DEBUG(10, ("Got acl version %d, expected %d\n",
			   pacl->acl_version, GPFS_ACL_VERSION_POSIX));
		errno = EINVAL;
		goto done;
	}
	
	DEBUG(10, ("len: %d, level: %d, version: %d, nace: %d\n",
		   pacl->acl_len, pacl->acl_level, pacl->acl_version,
		   pacl->acl_nace));

	result = gpfs2smb_acl(pacl);
	if (result == NULL) {
		goto done;
	}

 done:

	if (errno != 0) {
		SAFE_FREE(result);
	}
	return result;	
}

SMB_ACL_T gpfsacl_sys_acl_get_file(vfs_handle_struct *handle,
				    
				    const char *path_p,
				    SMB_ACL_TYPE_T type)
{
	gpfs_aclType_t gpfs_type;

	switch(type) {
	case SMB_ACL_TYPE_ACCESS:
		gpfs_type = GPFS_ACL_TYPE_ACCESS;
		break;
	case SMB_ACL_TYPE_DEFAULT:
		gpfs_type = GPFS_ACL_TYPE_DEFAULT;
		break;
	default:
		DEBUG(0, ("Got invalid type: %d\n", type));
		smb_panic("exiting");
	}

	return gpfsacl_get_posix_acl(path_p, gpfs_type);
}

SMB_ACL_T gpfsacl_sys_acl_get_fd(vfs_handle_struct *handle,
				 files_struct *fsp)
{
	return gpfsacl_get_posix_acl(fsp->fsp_name, GPFS_ACL_TYPE_ACCESS);
}

static struct gpfs_acl *smb2gpfs_acl(const SMB_ACL_T pacl,
				     SMB_ACL_TYPE_T type)
{
	gpfs_aclLen_t len;
	struct gpfs_acl *result;
	int i;
	union gpfs_ace_union
	{
		gpfs_ace_v1_t  ace_v1[1]; /* when GPFS_ACL_VERSION_POSIX */
		gpfs_ace_v4_t  ace_v4[1]; /* when GPFS_ACL_VERSION_NFS4  */
	};

	DEBUG(10, ("smb2gpfs_acl: Got ACL with %d entries\n", pacl->count));

	len = sizeof(struct gpfs_acl) - sizeof(union gpfs_ace_union) +
		(pacl->count)*sizeof(gpfs_ace_v1_t);

	result = SMB_MALLOC(len);
	if (result == NULL) {
		errno = ENOMEM;
		return result;
	}

	result->acl_len = len;
	result->acl_level = 0;
	result->acl_version = GPFS_ACL_VERSION_POSIX;
	result->acl_type = (type == SMB_ACL_TYPE_DEFAULT) ?
		GPFS_ACL_TYPE_DEFAULT : GPFS_ACL_TYPE_ACCESS;
	result->acl_nace = pacl->count;

	for (i=0; i<pacl->count; i++) {
		const struct smb_acl_entry *ace = &pacl->acl[i];
		struct gpfs_ace_v1 *g_ace = &result->ace_v1[i];
		
		DEBUG(10, ("Converting type %d perm %x\n",
			   (int)ace->a_type, (int)ace->a_perm));

		g_ace->ace_perm = 0;

		switch(ace->a_type) {
		case SMB_ACL_USER:
			g_ace->ace_type = GPFS_ACL_USER;
			g_ace->ace_who = (gpfs_uid_t)ace->uid;
			break;
		case SMB_ACL_USER_OBJ:
			g_ace->ace_type = GPFS_ACL_USER_OBJ;
			g_ace->ace_perm |= ACL_PERM_CONTROL;
			g_ace->ace_who = 0;
			break;
		case SMB_ACL_GROUP:
			g_ace->ace_type = GPFS_ACL_GROUP;
			g_ace->ace_who = (gpfs_uid_t)ace->gid;
			break;
		case SMB_ACL_GROUP_OBJ:
			g_ace->ace_type = GPFS_ACL_GROUP_OBJ;
			g_ace->ace_who = 0;
			break;
		case SMB_ACL_MASK:
			g_ace->ace_type = GPFS_ACL_MASK;
			g_ace->ace_perm = 0x8f;
			g_ace->ace_who = 0;
			break;
		case SMB_ACL_OTHER:
			g_ace->ace_type = GPFS_ACL_OTHER;
			g_ace->ace_who = 0;
			break;
		default:
			DEBUG(10, ("Got invalid ace_type: %d\n", ace->a_type));
			errno = EINVAL;
			SAFE_FREE(result);
			return NULL;
		}

		g_ace->ace_perm |= (ace->a_perm & SMB_ACL_READ) ?
			ACL_PERM_READ : 0;
		g_ace->ace_perm |= (ace->a_perm & SMB_ACL_WRITE) ?
			ACL_PERM_WRITE : 0;
		g_ace->ace_perm |= (ace->a_perm & SMB_ACL_EXECUTE) ?
			ACL_PERM_EXECUTE : 0;

		DEBUGADD(10, ("Converted to %d id %d perm %x\n",
			      g_ace->ace_type, g_ace->ace_who, g_ace->ace_perm));
	}

	return result;
}

int gpfsacl_sys_acl_set_file(vfs_handle_struct *handle,
			      
			      const char *name,
			      SMB_ACL_TYPE_T type,
			      SMB_ACL_T theacl)
{
	struct gpfs_acl *gpfs_acl;
	int result;

	gpfs_acl = smb2gpfs_acl(theacl, type);
	if (gpfs_acl == NULL) {
		return -1;
	}

	result = smbd_gpfs_putacl((char *)name, GPFS_PUTACL_STRUCT | GPFS_ACL_SAMBA, gpfs_acl);

	SAFE_FREE(gpfs_acl);
	return result;
}

int gpfsacl_sys_acl_set_fd(vfs_handle_struct *handle,
			    files_struct *fsp,
			    SMB_ACL_T theacl)
{
	return gpfsacl_sys_acl_set_file(handle, fsp->fsp_name, SMB_ACL_TYPE_ACCESS, theacl);
}

int gpfsacl_sys_acl_delete_def_file(vfs_handle_struct *handle,
				     
				     const char *path)
{
	errno = ENOTSUP;
	return -1;
}

/*
 * Assumed: mode bits are shiftable and standard
 * Output: the new aceMask field for an smb nfs4 ace
 */
static uint32 gpfsacl_mask_filter(uint32 aceType, uint32 aceMask, uint32 rwx)
{
	const uint32 posix_nfs4map[3] = {
                SMB_ACE4_EXECUTE, /* execute */
		SMB_ACE4_WRITE_DATA | SMB_ACE4_APPEND_DATA, /* write; GPFS specific */
                SMB_ACE4_READ_DATA /* read */
	};
	int     i;
	uint32_t        posix_mask = 0x01;
	uint32_t        posix_bit;
	uint32_t        nfs4_bits;
	
	for(i=0; i<3; i++) {
		nfs4_bits = posix_nfs4map[i];
		posix_bit = rwx & posix_mask;
		
		if (aceType==SMB_ACE4_ACCESS_ALLOWED_ACE_TYPE) {
			if (posix_bit)
				aceMask |= nfs4_bits;
			else
				aceMask &= ~nfs4_bits;
		} else {
			/* add deny bits when suitable */
			if (!posix_bit)
				aceMask |= nfs4_bits;
			else
				aceMask &= ~nfs4_bits;
		} /* other ace types are unexpected */
		
		posix_mask <<= 1;
	}
	
	return aceMask;
}

static int gpfsacl_emu_chmod(const char *path, mode_t mode)
{
	SMB4ACL_T *pacl = NULL;
	int     result;
	bool    haveAllowEntry[SMB_ACE4_WHO_EVERYONE + 1] = {False, False, False, False};
	int     i;
	files_struct    fake_fsp; /* TODO: rationalize parametrization */
	SMB4ACE_T       *smbace;
	
	DEBUG(10, ("gpfsacl_emu_chmod invoked for %s mode %o\n", path, mode));
	
	result = gpfs_get_nfs4_acl(path, &pacl);
	if (result)
		return result;
	
	if (mode & ~(S_IRWXU | S_IRWXG | S_IRWXO)) {
		DEBUG(2, ("WARNING: cutting extra mode bits %o on %s\n", mode, path));
	}
	
	for (smbace=smb_first_ace4(pacl); smbace!=NULL; smbace = smb_next_ace4(smbace)) {
		SMB_ACE4PROP_T  *ace = smb_get_ace4(smbace);
		uint32_t        specid = ace->who.special_id;
		
		if (ace->flags&SMB_ACE4_ID_SPECIAL &&
		    ace->aceType<=SMB_ACE4_ACCESS_DENIED_ACE_TYPE &&
		    specid <= SMB_ACE4_WHO_EVERYONE) {
			
			uint32_t newMask;
			
			if (ace->aceType==SMB_ACE4_ACCESS_ALLOWED_ACE_TYPE)
				haveAllowEntry[specid] = True;
			
			/* mode >> 6 for @owner, mode >> 3 for @group,
			 * mode >> 0 for @everyone */
			newMask = gpfsacl_mask_filter(ace->aceType, ace->aceMask,
						      mode >> ((SMB_ACE4_WHO_EVERYONE - specid) * 3));
			if (ace->aceMask!=newMask) {
				DEBUG(10, ("ace changed for %s (%o -> %o) id=%d\n",
					   path, ace->aceMask, newMask, specid));
			}
			ace->aceMask = newMask;
		}
	}

	/* make sure we have at least ALLOW entries
	 * for all the 3 special ids (@EVERYONE, @OWNER, @GROUP)
	 * - if necessary
	 */
	for(i = SMB_ACE4_WHO_OWNER; i<=SMB_ACE4_WHO_EVERYONE; i++) {
		SMB_ACE4PROP_T  ace;
		
		if (haveAllowEntry[i]==True)
			continue;
		
		memset(&ace, 0, sizeof(SMB_ACE4PROP_T));
		ace.aceType = SMB_ACE4_ACCESS_ALLOWED_ACE_TYPE;
		ace.flags |= SMB_ACE4_ID_SPECIAL;
		ace.who.special_id = i;
		
		if (i==SMB_ACE4_WHO_GROUP) /* not sure it's necessary... */
			ace.aceFlags |= SMB_ACE4_IDENTIFIER_GROUP;
		
		ace.aceMask = gpfsacl_mask_filter(ace.aceType, ace.aceMask,
						  mode >> ((SMB_ACE4_WHO_EVERYONE - i) * 3));
		
		/* don't add unnecessary aces */
		if (!ace.aceMask)
			continue;
		
		/* we add it to the END - as windows expects allow aces */
		smb_add_ace4(pacl, &ace);
		DEBUG(10, ("Added ALLOW ace for %s, mode=%o, id=%d, aceMask=%x\n",
			   path, mode, i, ace.aceMask));
	}
	
	/* don't add complementary DENY ACEs here */
	memset(&fake_fsp, 0, sizeof(struct files_struct));
	fake_fsp.fsp_name = (char *)path; /* no file_new is needed here */
	
	/* put the acl */
	if (gpfsacl_process_smbacl(&fake_fsp, pacl) == False)
		return -1;
	return 0; /* ok for [f]chmod */
}

static int vfs_gpfs_chmod(vfs_handle_struct *handle, const char *path, mode_t mode)
{
		 SMB_STRUCT_STAT st;
		 int rc;
		 
		 if (SMB_VFS_NEXT_STAT(handle, path, &st) != 0) {
			 return -1;
		 }
		 
		 /* avoid chmod() if possible, to preserve acls */
		 if ((st.st_mode & ~S_IFMT) == mode) {
			 return 0;
		 }

		 rc = gpfsacl_emu_chmod(path, mode);
		 if (rc == 1)
			 return SMB_VFS_NEXT_CHMOD(handle, path, mode);
		 return rc;
}

static int vfs_gpfs_fchmod(vfs_handle_struct *handle, files_struct *fsp, mode_t mode)
{
		 SMB_STRUCT_STAT st;
		 int rc;
		 
		 if (SMB_VFS_NEXT_FSTAT(handle, fsp, &st) != 0) {
			 return -1;
		 }

		 /* avoid chmod() if possible, to preserve acls */
		 if ((st.st_mode & ~S_IFMT) == mode) {
			 return 0;
		 }

		 rc = gpfsacl_emu_chmod(fsp->fsp_name, mode);
		 if (rc == 1)
			 return SMB_VFS_NEXT_FCHMOD(handle, fsp, mode);
		 return rc;
}

/* VFS operations structure */

static vfs_op_tuple gpfs_op_tuples[] = {
	
	{ SMB_VFS_OP(vfs_gpfs_kernel_flock), 
	  SMB_VFS_OP_KERNEL_FLOCK,
	  SMB_VFS_LAYER_OPAQUE },
	
        { SMB_VFS_OP(vfs_gpfs_setlease), 
	  SMB_VFS_OP_LINUX_SETLEASE,
	  SMB_VFS_LAYER_OPAQUE },
	
        { SMB_VFS_OP(gpfsacl_fget_nt_acl), 
	  SMB_VFS_OP_FGET_NT_ACL,
	  SMB_VFS_LAYER_TRANSPARENT },
	
        { SMB_VFS_OP(gpfsacl_get_nt_acl), 
	  SMB_VFS_OP_GET_NT_ACL,
	  SMB_VFS_LAYER_TRANSPARENT },
	
        { SMB_VFS_OP(gpfsacl_fset_nt_acl), 
	  SMB_VFS_OP_FSET_NT_ACL,
	  SMB_VFS_LAYER_TRANSPARENT },
	
        { SMB_VFS_OP(gpfsacl_set_nt_acl), 
	  SMB_VFS_OP_SET_NT_ACL,
	  SMB_VFS_LAYER_TRANSPARENT },
	
        { SMB_VFS_OP(gpfsacl_sys_acl_get_file), 
	  SMB_VFS_OP_SYS_ACL_GET_FILE,
	  SMB_VFS_LAYER_TRANSPARENT },
	
        { SMB_VFS_OP(gpfsacl_sys_acl_get_fd), 
	  SMB_VFS_OP_SYS_ACL_GET_FD,
	  SMB_VFS_LAYER_TRANSPARENT },
	
        { SMB_VFS_OP(gpfsacl_sys_acl_set_file), 
	  SMB_VFS_OP_SYS_ACL_SET_FILE,
	  SMB_VFS_LAYER_TRANSPARENT },
	
        { SMB_VFS_OP(gpfsacl_sys_acl_set_fd), 
	  SMB_VFS_OP_SYS_ACL_SET_FD,
	  SMB_VFS_LAYER_TRANSPARENT },
	
        { SMB_VFS_OP(gpfsacl_sys_acl_delete_def_file),
	  SMB_VFS_OP_SYS_ACL_DELETE_DEF_FILE,
	  SMB_VFS_LAYER_TRANSPARENT },
	
        { SMB_VFS_OP(vfs_gpfs_chmod), 
	  SMB_VFS_OP_CHMOD,
	  SMB_VFS_LAYER_TRANSPARENT },
	
        { SMB_VFS_OP(vfs_gpfs_fchmod), 
	  SMB_VFS_OP_FCHMOD,
	  SMB_VFS_LAYER_TRANSPARENT },

        { SMB_VFS_OP(NULL), SMB_VFS_OP_NOOP, SMB_VFS_LAYER_NOOP }

};


NTSTATUS vfs_gpfs_init(void);
NTSTATUS vfs_gpfs_init(void)
{
	init_gpfs();
	
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "gpfs",
				gpfs_op_tuples);
}
