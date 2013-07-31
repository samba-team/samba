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
#include "smbd/smbd.h"
#include "librpc/gen_ndr/ndr_xattr.h"
#include "include/smbprofile.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

#include <gpfs_gpl.h>
#include "nfs4_acls.h"
#include "vfs_gpfs.h"
#include "system/filesys.h"
#include "auth.h"
#include "lib/util/tevent_unix.h"

struct gpfs_config_data {
	bool sharemodes;
	bool leases;
	bool hsm;
	bool syncio;
	bool winattr;
	bool ftruncate;
	bool getrealfilename;
	bool dfreequota;
	bool prealloc;
	bool acl;
};


static int vfs_gpfs_kernel_flock(vfs_handle_struct *handle, files_struct *fsp, 
				 uint32 share_mode, uint32 access_mask)
{

	struct gpfs_config_data *config;
	int ret = 0;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct gpfs_config_data,
				return -1);

	START_PROFILE(syscall_kernel_flock);

	kernel_flock(fsp->fh->fd, share_mode, access_mask);

	if (config->sharemodes
		&& !set_gpfs_sharemode(fsp, access_mask, fsp->share_access)) {
		ret = -1;
	}

	END_PROFILE(syscall_kernel_flock);

	return ret;
}

static int vfs_gpfs_close(vfs_handle_struct *handle, files_struct *fsp)
{

	struct gpfs_config_data *config;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct gpfs_config_data,
				return -1);

	if (config->sharemodes && (fsp->fh != NULL) && (fsp->fh->fd != -1)) {
		set_gpfs_sharemode(fsp, 0, 0);
	}

	return SMB_VFS_NEXT_CLOSE(handle, fsp);
}

static int vfs_gpfs_setlease(vfs_handle_struct *handle, files_struct *fsp, 
			     int leasetype)
{
	struct gpfs_config_data *config;
	int ret=0;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct gpfs_config_data,
				return -1);

	if (linux_set_lease_sighandler(fsp->fh->fd) == -1)
		return -1;

	START_PROFILE(syscall_linux_setlease);

	if (config->leases) {
		/*
		 * Ensure the lease owner is root to allow
		 * correct delivery of lease-break signals.
		 */
		become_root();
		ret = set_gpfs_lease(fsp->fh->fd,leasetype);
		unbecome_root();
	}

	END_PROFILE(syscall_linux_setlease);

	return ret;
}

static int vfs_gpfs_get_real_filename(struct vfs_handle_struct *handle,
				      const char *path,
				      const char *name,
				      TALLOC_CTX *mem_ctx,
				      char **found_name)
{
	int result;
	char *full_path;
	char real_pathname[PATH_MAX+1];
	int buflen;
	bool mangled;
	struct gpfs_config_data *config;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct gpfs_config_data,
				return -1);

	if (!config->getrealfilename) {
		return SMB_VFS_NEXT_GET_REAL_FILENAME(handle, path, name,
						      mem_ctx, found_name);
	}

	mangled = mangle_is_mangled(name, handle->conn->params);
	if (mangled) {
		return SMB_VFS_NEXT_GET_REAL_FILENAME(handle, path, name,
						      mem_ctx, found_name);
	}

	full_path = talloc_asprintf(talloc_tos(), "%s/%s", path, name);
	if (full_path == NULL) {
		errno = ENOMEM;
		return -1;
	}

	buflen = sizeof(real_pathname) - 1;

	result = smbd_gpfs_get_realfilename_path(full_path, real_pathname,
						 &buflen);

	TALLOC_FREE(full_path);

	if ((result == -1) && (errno == ENOSYS)) {
		return SMB_VFS_NEXT_GET_REAL_FILENAME(
			handle, path, name, mem_ctx, found_name);
	}

	if (result == -1) {
		DEBUG(10, ("smbd_gpfs_get_realfilename_path returned %s\n",
			   strerror(errno)));
		return -1;
	}

	/*
	 * GPFS does not necessarily null-terminate the returned path
	 * but instead returns the buffer length in buflen.
	 */

	if (buflen < sizeof(real_pathname)) {
		real_pathname[buflen] = '\0';
	} else {
		real_pathname[sizeof(real_pathname)-1] = '\0';
	}

	DEBUG(10, ("smbd_gpfs_get_realfilename_path: %s/%s -> %s\n",
		   path, name, real_pathname));

	name = strrchr_m(real_pathname, '/');
	if (name == NULL) {
		errno = ENOENT;
		return -1;
	}

	*found_name = talloc_strdup(mem_ctx, name+1);
	if (*found_name == NULL) {
		errno = ENOMEM;
		return -1;
	}

	return 0;
}

static void gpfs_dumpacl(int level, struct gpfs_acl *gacl)
{
	gpfs_aclCount_t i;
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

	ret = smbd_gpfs_getacl((char *)fname, GPFS_GETACL_STRUCT, acl);
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

		ret = smbd_gpfs_getacl((char *)fname, GPFS_GETACL_STRUCT, acl);
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
	gpfs_aclCount_t i;
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
		talloc_free(gacl);
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

		ZERO_STRUCT(smbace);
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
	TALLOC_CTX *mem_ctx,
	struct security_descriptor **ppdesc)
{
	SMB4ACL_T *pacl = NULL;
	int	result;
	struct gpfs_config_data *config;

	*ppdesc = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct gpfs_config_data,
				return NT_STATUS_INTERNAL_ERROR);

	if (!config->acl) {
		return SMB_VFS_NEXT_FGET_NT_ACL(handle, fsp, security_info,
						mem_ctx, ppdesc);
	}

	result = gpfs_get_nfs4_acl(fsp->fsp_name->base_name, &pacl);

	if (result == 0)
		return smb_fget_nt_acl_nfs4(fsp, security_info, mem_ctx, ppdesc, pacl);

	if (result > 0) {
		DEBUG(10, ("retrying with posix acl...\n"));
		return posix_fget_nt_acl(fsp, security_info, mem_ctx, ppdesc);
	}

	/* GPFS ACL was not read, something wrong happened, error code is set in errno */
	return map_nt_error_from_unix(errno);
}

static NTSTATUS gpfsacl_get_nt_acl(vfs_handle_struct *handle,
	const char *name,
	uint32 security_info,
	TALLOC_CTX *mem_ctx, struct security_descriptor **ppdesc)
{
	SMB4ACL_T *pacl = NULL;
	int	result;
	struct gpfs_config_data *config;

	*ppdesc = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct gpfs_config_data,
				return NT_STATUS_INTERNAL_ERROR);

	if (!config->acl) {
		return SMB_VFS_NEXT_GET_NT_ACL(handle, name, security_info,
					       mem_ctx, ppdesc);
	}

	result = gpfs_get_nfs4_acl(name, &pacl);

	if (result == 0)
		return smb_get_nt_acl_nfs4(handle->conn, name, security_info,
					   mem_ctx, ppdesc, pacl);

	if (result > 0) {
		DEBUG(10, ("retrying with posix acl...\n"));
		return posix_get_nt_acl(handle->conn, name, security_info,
					mem_ctx, ppdesc);
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

	gacl_len = offsetof(gpfs_acl_t, ace_v4) + smb_get_naces(smbacl) *
		sizeof(gpfs_ace_v4_t);

	gacl = (struct gpfs_acl *)TALLOC_SIZE(mem_ctx, gacl_len);
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
				  fsp_str_dbg(fsp)));
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

	ret = smbd_gpfs_putacl(fsp->fsp_name->base_name,
			       GPFS_PUTACL_STRUCT | GPFS_ACL_SAMBA, gacl);
	if (ret != 0) {
		DEBUG(8, ("gpfs_putacl failed with %s\n", strerror(errno)));
		gpfs_dumpacl(8, gacl);
		return False;
	}

	DEBUG(10, ("gpfs_putacl succeeded\n"));
	return True;
}

static NTSTATUS gpfsacl_set_nt_acl_internal(files_struct *fsp, uint32 security_info_sent, const struct security_descriptor *psd)
{
	struct gpfs_acl *acl;
	NTSTATUS result = NT_STATUS_ACCESS_DENIED;

	acl = gpfs_getacl_alloc(fsp->fsp_name->base_name, 0);
	if (acl == NULL)
		return result;

	if (acl->acl_version&GPFS_ACL_VERSION_NFS4)
	{
		if (lp_parm_bool(fsp->conn->params->service, "gpfs",
				 "refuse_dacl_protected", false)
		    && (psd->type&SEC_DESC_DACL_PROTECTED)) {
			DEBUG(2, ("Rejecting unsupported ACL with DACL_PROTECTED bit set\n"));
			return NT_STATUS_NOT_SUPPORTED;
		}

		result = smb_set_nt_acl_nfs4(
			fsp, security_info_sent, psd,
			gpfsacl_process_smbacl);
	} else { /* assume POSIX ACL - by default... */
		result = set_nt_acl(fsp, security_info_sent, psd);
	}

	return result;
}

static NTSTATUS gpfsacl_fset_nt_acl(vfs_handle_struct *handle, files_struct *fsp, uint32 security_info_sent, const struct security_descriptor *psd)
{
	struct gpfs_config_data *config;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct gpfs_config_data,
				return NT_STATUS_INTERNAL_ERROR);

	if (!config->acl) {
		return SMB_VFS_NEXT_FSET_NT_ACL(handle, fsp, security_info_sent, psd);
	}

	return gpfsacl_set_nt_acl_internal(fsp, security_info_sent, psd);
}

static SMB_ACL_T gpfs2smb_acl(const struct gpfs_acl *pacl, TALLOC_CTX *mem_ctx)
{
	SMB_ACL_T result;
	gpfs_aclCount_t i;

	result = sys_acl_init(mem_ctx);
	if (result == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	result->count = pacl->acl_nace;
	result->acl = talloc_realloc(result, result->acl, struct smb_acl_entry,
				     result->count);
	if (result->acl == NULL) {
		TALLOC_FREE(result);
		errno = ENOMEM;
		return NULL;
	}

	for (i=0; i<pacl->acl_nace; i++) {
		struct smb_acl_entry *ace = &result->acl[i];
		const struct gpfs_ace_v1 *g_ace = &pacl->ace_v1[i];

		DEBUG(10, ("Converting type %d id %lu perm %x\n",
			   (int)g_ace->ace_type, (unsigned long)g_ace->ace_who,
			   (int)g_ace->ace_perm));

		switch (g_ace->ace_type) {
		case GPFS_ACL_USER:
			ace->a_type = SMB_ACL_USER;
			ace->info.user.uid = (uid_t)g_ace->ace_who;
			break;
		case GPFS_ACL_USER_OBJ:
			ace->a_type = SMB_ACL_USER_OBJ;
			break;
		case GPFS_ACL_GROUP:
			ace->a_type = SMB_ACL_GROUP;
			ace->info.group.gid = (gid_t)g_ace->ace_who;
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
			TALLOC_FREE(result);
			errno = EINVAL;
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

static SMB_ACL_T gpfsacl_get_posix_acl(const char *path, gpfs_aclType_t type,
				       TALLOC_CTX *mem_ctx)
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

	result = gpfs2smb_acl(pacl, mem_ctx);
	if (result != NULL) {
		errno = 0;
	}

 done:

	if (pacl != NULL) {
		talloc_free(pacl);
	}
	if (errno != 0) {
		TALLOC_FREE(result);
	}
	return result;	
}

static SMB_ACL_T gpfsacl_sys_acl_get_file(vfs_handle_struct *handle,
					  const char *path_p,
					  SMB_ACL_TYPE_T type,
					  TALLOC_CTX *mem_ctx)
{
	gpfs_aclType_t gpfs_type;
	struct gpfs_config_data *config;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct gpfs_config_data,
				return NULL);

	if (!config->acl) {
		return SMB_VFS_NEXT_SYS_ACL_GET_FILE(handle, path_p,
						     type, mem_ctx);
	}

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

	return gpfsacl_get_posix_acl(path_p, gpfs_type, mem_ctx);
}

static SMB_ACL_T gpfsacl_sys_acl_get_fd(vfs_handle_struct *handle,
					files_struct *fsp,
					TALLOC_CTX *mem_ctx)
{
	struct gpfs_config_data *config;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct gpfs_config_data,
				return NULL);

	if (!config->acl) {
		return SMB_VFS_NEXT_SYS_ACL_GET_FD(handle, fsp, mem_ctx);
	}

	return gpfsacl_get_posix_acl(fsp->fsp_name->base_name,
				     GPFS_ACL_TYPE_ACCESS, mem_ctx);
}

static struct gpfs_acl *smb2gpfs_acl(const SMB_ACL_T pacl,
				     SMB_ACL_TYPE_T type)
{
	gpfs_aclLen_t len;
	struct gpfs_acl *result;
	int i;

	DEBUG(10, ("smb2gpfs_acl: Got ACL with %d entries\n", pacl->count));

	len = offsetof(gpfs_acl_t, ace_v1) + (pacl->count) *
		sizeof(gpfs_ace_v1_t);

	result = (struct gpfs_acl *)SMB_MALLOC(len);
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
			g_ace->ace_who = (gpfs_uid_t)ace->info.user.uid;
			break;
		case SMB_ACL_USER_OBJ:
			g_ace->ace_type = GPFS_ACL_USER_OBJ;
			g_ace->ace_perm |= ACL_PERM_CONTROL;
			g_ace->ace_who = 0;
			break;
		case SMB_ACL_GROUP:
			g_ace->ace_type = GPFS_ACL_GROUP;
			g_ace->ace_who = (gpfs_uid_t)ace->info.group.gid;
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

static int gpfsacl_sys_acl_set_file(vfs_handle_struct *handle,
				    const char *name,
				    SMB_ACL_TYPE_T type,
				    SMB_ACL_T theacl)
{
	struct gpfs_acl *gpfs_acl;
	int result;
	struct gpfs_config_data *config;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct gpfs_config_data,
				return -1);

	if (!config->acl) {
		return SMB_VFS_NEXT_SYS_ACL_SET_FILE(handle, name, type, theacl);
	}

	gpfs_acl = smb2gpfs_acl(theacl, type);
	if (gpfs_acl == NULL) {
		return -1;
	}

	result = smbd_gpfs_putacl((char *)name, GPFS_PUTACL_STRUCT | GPFS_ACL_SAMBA, gpfs_acl);

	SAFE_FREE(gpfs_acl);
	return result;
}

static int gpfsacl_sys_acl_set_fd(vfs_handle_struct *handle,
				  files_struct *fsp,
				  SMB_ACL_T theacl)
{
	struct gpfs_config_data *config;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct gpfs_config_data,
				return -1);

	if (!config->acl) {
		return SMB_VFS_NEXT_SYS_ACL_SET_FD(handle, fsp, theacl);
	}

	return gpfsacl_sys_acl_set_file(handle, fsp->fsp_name->base_name,
					SMB_ACL_TYPE_ACCESS, theacl);
}

static int gpfsacl_sys_acl_delete_def_file(vfs_handle_struct *handle,
					   const char *path)
{
	struct gpfs_config_data *config;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct gpfs_config_data,
				return -1);

	if (!config->acl) {
		return SMB_VFS_NEXT_SYS_ACL_DELETE_DEF_FILE(handle, path);
	}

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
	NTSTATUS status;

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

		ZERO_STRUCT(ace);
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
	ZERO_STRUCT(fake_fsp);
	status = create_synthetic_smb_fname(talloc_tos(), path, NULL, NULL,
					    &fake_fsp.fsp_name);
	if (!NT_STATUS_IS_OK(status)) {
		errno = map_errno_from_nt_status(status);
		return -1;
	}
	/* put the acl */
	if (gpfsacl_process_smbacl(&fake_fsp, pacl) == False) {
		TALLOC_FREE(fake_fsp.fsp_name);
		return -1;
	}

	TALLOC_FREE(fake_fsp.fsp_name);
	return 0; /* ok for [f]chmod */
}

static int vfs_gpfs_chmod(vfs_handle_struct *handle, const char *path, mode_t mode)
{
	struct smb_filename *smb_fname_cpath;
	int rc;
	NTSTATUS status;

	status = create_synthetic_smb_fname(
		talloc_tos(), path, NULL, NULL, &smb_fname_cpath);

	if (SMB_VFS_NEXT_STAT(handle, smb_fname_cpath) != 0) {
		return -1;
	}

	/* avoid chmod() if possible, to preserve acls */
	if ((smb_fname_cpath->st.st_ex_mode & ~S_IFMT) == mode) {
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
		 if ((st.st_ex_mode & ~S_IFMT) == mode) {
			 return 0;
		 }

		 rc = gpfsacl_emu_chmod(fsp->fsp_name->base_name, mode);
		 if (rc == 1)
			 return SMB_VFS_NEXT_FCHMOD(handle, fsp, mode);
		 return rc;
}

static int gpfs_set_xattr(struct vfs_handle_struct *handle,  const char *path,
                           const char *name, const void *value, size_t size,  int flags){
	struct xattr_DOSATTRIB dosattrib;
        enum ndr_err_code ndr_err;
        DATA_BLOB blob;
        const char *attrstr = value;
        unsigned int dosmode=0;
        struct gpfs_winattr attrs;
        int ret = 0;
	struct gpfs_config_data *config;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct gpfs_config_data,
				return -1);

	if (!config->winattr) {
		DEBUG(10, ("gpfs_set_xattr:name is %s -> next\n",name));
		return SMB_VFS_NEXT_SETXATTR(handle,path,name,value,size,flags);
	}

        DEBUG(10, ("gpfs_set_xattr: %s \n",path));

        /* Only handle DOS Attributes */
        if (strcmp(name,SAMBA_XATTR_DOS_ATTRIB) != 0){
		DEBUG(5, ("gpfs_set_xattr:name is %s\n",name));
		return SMB_VFS_NEXT_SETXATTR(handle,path,name,value,size,flags);
        }

	blob.data = (uint8_t *)attrstr;
	blob.length = size;

	ndr_err = ndr_pull_struct_blob(&blob, talloc_tos(), &dosattrib,
			(ndr_pull_flags_fn_t)ndr_pull_xattr_DOSATTRIB);

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(1, ("gpfs_set_xattr: bad ndr decode "
			  "from EA on file %s: Error = %s\n",
			  path, ndr_errstr(ndr_err)));
		return false;
	}

	if (dosattrib.version != 3) {
		DEBUG(1, ("gpfs_set_xattr: expected dosattrib version 3, got "
			  "%d\n", (int)dosattrib.version));
		return false;
	}
	if (!(dosattrib.info.info3.valid_flags & XATTR_DOSINFO_ATTRIB)) {
		DEBUG(10, ("gpfs_set_xattr: XATTR_DOSINFO_ATTRIB not "
			   "valid, ignoring\n"));
		return true;
	}

	dosmode = dosattrib.info.info3.attrib;

        attrs.winAttrs = 0;
        /*Just map RD_ONLY, ARCHIVE, SYSTEM HIDDEN and SPARSE. Ignore the others*/
        if (dosmode & FILE_ATTRIBUTE_ARCHIVE){
                attrs.winAttrs |= GPFS_WINATTR_ARCHIVE;
        }
        if (dosmode & FILE_ATTRIBUTE_HIDDEN){
                        attrs.winAttrs |= GPFS_WINATTR_HIDDEN;
                }
        if (dosmode & FILE_ATTRIBUTE_SYSTEM){
                        attrs.winAttrs |= GPFS_WINATTR_SYSTEM;
                }
        if (dosmode & FILE_ATTRIBUTE_READONLY){
                        attrs.winAttrs |= GPFS_WINATTR_READONLY;
        }
        if (dosmode & FILE_ATTRIBUTE_SPARSE) {
		attrs.winAttrs |= GPFS_WINATTR_SPARSE_FILE;
	}


        ret = set_gpfs_winattrs(discard_const_p(char, path),
				GPFS_WINATTR_SET_ATTRS, &attrs);
        if ( ret == -1){
		if (errno == ENOSYS) {
			return SMB_VFS_NEXT_SETXATTR(handle, path, name, value,
						     size, flags);
		}

                DEBUG(1, ("gpfs_set_xattr:Set GPFS attributes failed %d\n",ret));
                return -1;
        }

        DEBUG(10, ("gpfs_set_xattr:Set attributes: 0x%x\n",attrs.winAttrs));
        return 0;
}

static ssize_t gpfs_get_xattr(struct vfs_handle_struct *handle,  const char *path,
                              const char *name, void *value, size_t size){
        char *attrstr = value;
        unsigned int dosmode = 0;
        struct gpfs_winattr attrs;
        int ret = 0;
	struct gpfs_config_data *config;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct gpfs_config_data,
				return -1);

	if (!config->winattr) {
		DEBUG(10, ("gpfs_get_xattr:name is %s -> next\n",name));
		return SMB_VFS_NEXT_GETXATTR(handle,path,name,value,size);
	}

        DEBUG(10, ("gpfs_get_xattr: %s \n",path));

        /* Only handle DOS Attributes */
        if (strcmp(name,SAMBA_XATTR_DOS_ATTRIB) != 0){
		DEBUG(5, ("gpfs_get_xattr:name is %s\n",name));
                return SMB_VFS_NEXT_GETXATTR(handle,path,name,value,size);
        }

        ret = get_gpfs_winattrs(discard_const_p(char, path), &attrs);
        if ( ret == -1){
		if (errno == ENOSYS) {
			return SMB_VFS_NEXT_GETXATTR(handle, path, name, value,
						     size);
		}

                DEBUG(1, ("gpfs_get_xattr: Get GPFS attributes failed: "
			  "%d (%s)\n", ret, strerror(errno)));
                return -1;
        }

        DEBUG(10, ("gpfs_get_xattr:Got attributes: 0x%x\n",attrs.winAttrs));

        /*Just map RD_ONLY, ARCHIVE, SYSTEM, HIDDEN and SPARSE. Ignore the others*/
        if (attrs.winAttrs & GPFS_WINATTR_ARCHIVE){
                dosmode |= FILE_ATTRIBUTE_ARCHIVE;
        }
        if (attrs.winAttrs & GPFS_WINATTR_HIDDEN){
                dosmode |= FILE_ATTRIBUTE_HIDDEN;
        }
        if (attrs.winAttrs & GPFS_WINATTR_SYSTEM){
                dosmode |= FILE_ATTRIBUTE_SYSTEM;
        }
        if (attrs.winAttrs & GPFS_WINATTR_READONLY){
                dosmode |= FILE_ATTRIBUTE_READONLY;
        }
        if (attrs.winAttrs & GPFS_WINATTR_SPARSE_FILE) {
		dosmode |= FILE_ATTRIBUTE_SPARSE;
	}

        snprintf(attrstr, size, "0x%2.2x",
		 (unsigned int)(dosmode & SAMBA_ATTRIBUTES_MASK));
        DEBUG(10, ("gpfs_get_xattr: returning %s\n",attrstr));
        return 4;
}

static int vfs_gpfs_stat(struct vfs_handle_struct *handle,
			 struct smb_filename *smb_fname)
{
	struct gpfs_winattr attrs;
	char *fname = NULL;
	NTSTATUS status;
	int ret;
	struct gpfs_config_data *config;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct gpfs_config_data,
				return -1);

	ret = SMB_VFS_NEXT_STAT(handle, smb_fname);
	if (ret == -1) {
		return -1;
	}

	if (!config->winattr) {
		return 0;
	}

	status = get_full_smb_filename(talloc_tos(), smb_fname, &fname);
	if (!NT_STATUS_IS_OK(status)) {
		errno = map_errno_from_nt_status(status);
		return -1;
	}
	ret = get_gpfs_winattrs(discard_const_p(char, fname), &attrs);
	TALLOC_FREE(fname);
	if (ret == 0) {
		smb_fname->st.st_ex_calculated_birthtime = false;
		smb_fname->st.st_ex_btime.tv_sec = attrs.creationTime.tv_sec;
		smb_fname->st.st_ex_btime.tv_nsec = attrs.creationTime.tv_nsec;
		smb_fname->st.vfs_private = attrs.winAttrs;
	}
	return 0;
}

static int vfs_gpfs_fstat(struct vfs_handle_struct *handle,
			  struct files_struct *fsp, SMB_STRUCT_STAT *sbuf)
{
	struct gpfs_winattr attrs;
	int ret;
	struct gpfs_config_data *config;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct gpfs_config_data,
				return -1);

	ret = SMB_VFS_NEXT_FSTAT(handle, fsp, sbuf);
	if (ret == -1) {
		return -1;
	}
	if ((fsp->fh == NULL) || (fsp->fh->fd == -1)) {
		return 0;
	}
	if (!config->winattr) {
		return 0;
	}

	ret = smbd_fget_gpfs_winattrs(fsp->fh->fd, &attrs);
	if (ret == 0) {
		sbuf->st_ex_calculated_birthtime = false;
		sbuf->st_ex_btime.tv_sec = attrs.creationTime.tv_sec;
		sbuf->st_ex_btime.tv_nsec = attrs.creationTime.tv_nsec;
	}
	return 0;
}

static int vfs_gpfs_lstat(struct vfs_handle_struct *handle,
			  struct smb_filename *smb_fname)
{
	struct gpfs_winattr attrs;
	char *path = NULL;
	NTSTATUS status;
	int ret;
	struct gpfs_config_data *config;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct gpfs_config_data,
				return -1);

	ret = SMB_VFS_NEXT_LSTAT(handle, smb_fname);
	if (ret == -1) {
		return -1;
	}
	if (!config->winattr) {
		return 0;
	}

	status = get_full_smb_filename(talloc_tos(), smb_fname, &path);
	if (!NT_STATUS_IS_OK(status)) {
		errno = map_errno_from_nt_status(status);
		return -1;
	}
	ret = get_gpfs_winattrs(discard_const_p(char, path), &attrs);
	TALLOC_FREE(path);
	if (ret == 0) {
		smb_fname->st.st_ex_calculated_birthtime = false;
		smb_fname->st.st_ex_btime.tv_sec = attrs.creationTime.tv_sec;
		smb_fname->st.st_ex_btime.tv_nsec = attrs.creationTime.tv_nsec;
		smb_fname->st.vfs_private = attrs.winAttrs;
	}
	return 0;
}

static int vfs_gpfs_ntimes(struct vfs_handle_struct *handle,
                        const struct smb_filename *smb_fname,
			struct smb_file_time *ft)
{

        struct gpfs_winattr attrs;
        int ret;
        char *path = NULL;
        NTSTATUS status;
	struct gpfs_config_data *config;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct gpfs_config_data,
				return -1);

        ret = SMB_VFS_NEXT_NTIMES(handle, smb_fname, ft);
        if(ret == -1){
		/* don't complain if access was denied */
		if (errno != EPERM && errno != EACCES) {
			DEBUG(1,("vfs_gpfs_ntimes: SMB_VFS_NEXT_NTIMES failed:"
				 "%s", strerror(errno)));
		}
                return -1;
        }

        if(null_timespec(ft->create_time)){
                DEBUG(10,("vfs_gpfs_ntimes:Create Time is NULL\n"));
                return 0;
        }

	if (!config->winattr) {
		return 0;
	}

        status = get_full_smb_filename(talloc_tos(), smb_fname, &path);
        if (!NT_STATUS_IS_OK(status)) {
                errno = map_errno_from_nt_status(status);
                return -1;
        }

        attrs.winAttrs = 0;
        attrs.creationTime.tv_sec = ft->create_time.tv_sec;
        attrs.creationTime.tv_nsec = ft->create_time.tv_nsec;

        ret = set_gpfs_winattrs(discard_const_p(char, path),
                                GPFS_WINATTR_SET_CREATION_TIME, &attrs);
        if(ret == -1 && errno != ENOSYS){
                DEBUG(1,("vfs_gpfs_ntimes: set GPFS ntimes failed %d\n",ret));
	        return -1;
        }
        return 0;

}

static int vfs_gpfs_fallocate(struct vfs_handle_struct *handle,
		       struct files_struct *fsp, enum vfs_fallocate_mode mode,
		       off_t offset, off_t len)
{
	int ret;
	struct gpfs_config_data *config;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct gpfs_config_data,
				return -1);

	if (!config->prealloc) {
		/* you should better not run fallocate() on GPFS at all */
		errno = ENOTSUP;
		return -1;
	}

	if (mode == VFS_FALLOCATE_KEEP_SIZE) {
		DEBUG(10, ("Unsupported VFS_FALLOCATE_KEEP_SIZE\n"));
		errno = ENOTSUP;
		return -1;
	}

	ret = smbd_gpfs_prealloc(fsp->fh->fd, offset, len);

	if (ret == -1 && errno != ENOSYS) {
		DEBUG(0, ("GPFS prealloc failed: %s\n", strerror(errno)));
	} else if (ret == -1 && errno == ENOSYS) {
		DEBUG(10, ("GPFS prealloc not supported.\n"));
	} else {
		DEBUG(10, ("GPFS prealloc succeeded.\n"));
	}

	return ret;
}

static int vfs_gpfs_ftruncate(vfs_handle_struct *handle, files_struct *fsp,
				off_t len)
{
	int result;
	struct gpfs_config_data *config;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct gpfs_config_data,
				return -1);

	if (!config->ftruncate) {
		return SMB_VFS_NEXT_FTRUNCATE(handle, fsp, len);
	}

	result = smbd_gpfs_ftruncate(fsp->fh->fd, len);
	if ((result == -1) && (errno == ENOSYS)) {
		return SMB_VFS_NEXT_FTRUNCATE(handle, fsp, len);
	}
	return result;
}

static bool vfs_gpfs_is_offline(struct vfs_handle_struct *handle,
				const struct smb_filename *fname,
				SMB_STRUCT_STAT *sbuf)
{
	struct gpfs_winattr attrs;
	char *path = NULL;
	NTSTATUS status;
	struct gpfs_config_data *config;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct gpfs_config_data,
				return -1);

	if (!config->winattr) {
		return SMB_VFS_NEXT_IS_OFFLINE(handle, fname, sbuf);
	}

	status = get_full_smb_filename(talloc_tos(), fname, &path);
	if (!NT_STATUS_IS_OK(status)) {
		errno = map_errno_from_nt_status(status);
		return -1;
	}

	if (VALID_STAT(*sbuf)) {
		attrs.winAttrs = sbuf->vfs_private;
	} else {
		int ret;
		ret = get_gpfs_winattrs(path, &attrs);

		if (ret == -1) {
			TALLOC_FREE(path);
			return false;
		}
	}
	if ((attrs.winAttrs & GPFS_WINATTR_OFFLINE) != 0) {
		DEBUG(10, ("%s is offline\n", path));
		TALLOC_FREE(path);
		return true;
	}
	DEBUG(10, ("%s is online\n", path));
	TALLOC_FREE(path);
	return SMB_VFS_NEXT_IS_OFFLINE(handle, fname, sbuf);
}

static bool vfs_gpfs_aio_force(struct vfs_handle_struct *handle,
			       struct files_struct *fsp)
{
	return vfs_gpfs_is_offline(handle, fsp->fsp_name, &fsp->fsp_name->st);
}

static ssize_t vfs_gpfs_sendfile(vfs_handle_struct *handle, int tofd,
				 files_struct *fsp, const DATA_BLOB *hdr,
				 off_t offset, size_t n)
{
	if ((fsp->fsp_name->st.vfs_private & GPFS_WINATTR_OFFLINE) != 0) {
		errno = ENOSYS;
		return -1;
	}
	return SMB_VFS_NEXT_SENDFILE(handle, tofd, fsp, hdr, offset, n);
}

static int vfs_gpfs_connect(struct vfs_handle_struct *handle,
			    const char *service, const char *user)
{
	struct gpfs_config_data *config;
	int ret;

	smbd_gpfs_lib_init();

	ret = SMB_VFS_NEXT_CONNECT(handle, service, user);

	if (ret < 0) {
		return ret;
	}

	config = talloc_zero(handle->conn, struct gpfs_config_data);
	if (!config) {
		SMB_VFS_NEXT_DISCONNECT(handle);
		DEBUG(0, ("talloc_zero() failed\n"));
		return -1;
	}

	config->sharemodes = lp_parm_bool(SNUM(handle->conn), "gpfs",
					"sharemodes", true);

	config->leases = lp_parm_bool(SNUM(handle->conn), "gpfs",
					"leases", true);

	config->hsm = lp_parm_bool(SNUM(handle->conn), "gpfs",
				   "hsm", false);

	config->syncio = lp_parm_bool(SNUM(handle->conn), "gpfs",
				      "syncio", false);

	config->winattr = lp_parm_bool(SNUM(handle->conn), "gpfs",
				       "winattr", false);

	config->ftruncate = lp_parm_bool(SNUM(handle->conn), "gpfs",
					 "ftruncate", true);

	config->getrealfilename = lp_parm_bool(SNUM(handle->conn), "gpfs",
					       "getrealfilename", true);

	config->dfreequota = lp_parm_bool(SNUM(handle->conn), "gpfs",
					  "dfreequota", false);

	config->prealloc = lp_parm_bool(SNUM(handle->conn), "gpfs",
				   "prealloc", true);

	config->acl = lp_parm_bool(SNUM(handle->conn), "gpfs", "acl", true);

	SMB_VFS_HANDLE_SET_DATA(handle, config,
				NULL, struct gpfs_config_data,
				return -1);

	if (config->leases) {
		/*
		 * GPFS lease code is based on kernel oplock code
		 * so make sure it is turned on
		 */
		if (!lp_kernel_oplocks(SNUM(handle->conn))) {
			DEBUG(5, ("Enabling kernel oplocks for "
				  "gpfs:leases to work\n"));
			lp_do_parameter(SNUM(handle->conn), "kernel oplocks",
					"true");
		}

		/*
		 * as the kernel does not properly support Level II oplocks
		 * and GPFS leases code is based on kernel infrastructure, we
		 * need to turn off Level II oplocks if gpfs:leases is enabled
		 */
		if (lp_level2_oplocks(SNUM(handle->conn))) {
			DEBUG(5, ("gpfs:leases are enabled, disabling "
				  "Level II oplocks\n"));
			lp_do_parameter(SNUM(handle->conn), "level2 oplocks",
					"false");
		}
	}

	return 0;
}

static int vfs_gpfs_get_quotas(const char *path, uid_t uid, gid_t gid,
			       int *fset_id,
			       struct gpfs_quotaInfo *qi_user,
			       struct gpfs_quotaInfo *qi_group,
			       struct gpfs_quotaInfo *qi_fset)
{
	int err;
	char *dir_path;
	bool b;

	/*
	 * We want to always use the directory to get the fileset id,
	 * because files might have a share mode. We also do not want
	 * to get the parent directory when there is already a
	 * directory to avoid stepping in a different fileset.  The
	 * path passed here is currently either "." or a filename, so
	 * this is ok. The proper solution would be having a way to
	 * query the fileset id without opening the file.
	 */
	b = parent_dirname(talloc_tos(), path, &dir_path, NULL);
	if (!b) {
		errno = ENOMEM;
		return -1;
	}

	DEBUG(10, ("path %s, directory %s\n", path, dir_path));

	err = get_gpfs_fset_id(dir_path, fset_id);
	if (err) {
		DEBUG(0, ("Get fset id failed path %s, dir %s, errno %d.\n",
			  path, dir_path, errno));
		return err;
	}

	err = get_gpfs_quota(path, GPFS_USRQUOTA, uid, qi_user);
	if (err) {
		return err;
	}

	err = get_gpfs_quota(path, GPFS_GRPQUOTA, gid, qi_group);
	if (err) {
		return err;
	}

	err = get_gpfs_quota(path, GPFS_FILESETQUOTA, *fset_id, qi_fset);
	if (err) {
		return err;
	}

	return 0;
}

static void vfs_gpfs_disk_free_quota(struct gpfs_quotaInfo qi, time_t cur_time,
				     uint64_t *dfree, uint64_t *dsize)
{
	uint64_t usage, limit;

	/*
	 * The quota reporting is done in units of 1024 byte blocks, but
	 * sys_fsusage uses units of 512 byte blocks, adjust the block number
	 * accordingly. Also filter possibly negative usage counts from gpfs.
	 */
	usage = qi.blockUsage < 0 ? 0 : (uint64_t)qi.blockUsage * 2;
	limit = (uint64_t)qi.blockHardLimit * 2;

	/*
	 * When the grace time for the exceeded soft block quota has been
	 * exceeded, the soft block quota becomes an additional hard limit.
	 */
	if (qi.blockSoftLimit &&
	    qi.blockGraceTime && cur_time > qi.blockGraceTime) {
		/* report disk as full */
		*dfree = 0;
		*dsize = MIN(*dsize, usage);
	}

	if (!qi.blockHardLimit)
		return;

	if (usage >= limit) {
		/* report disk as full */
		*dfree = 0;
		*dsize = MIN(*dsize, usage);

	} else {
		/* limit has not been reached, determine "free space" */
		*dfree = MIN(*dfree, limit - usage);
		*dsize = MIN(*dsize, limit);
	}
}

static uint64_t vfs_gpfs_disk_free(vfs_handle_struct *handle, const char *path,
				   bool small_query, uint64_t *bsize,
				   uint64_t *dfree, uint64_t *dsize)
{
	struct security_unix_token *utok;
	struct gpfs_quotaInfo qi_user, qi_group, qi_fset;
	struct gpfs_config_data *config;
	int err, fset_id;
	time_t cur_time;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct gpfs_config_data,
				return (uint64_t)-1);
	if (!config->dfreequota) {
		return SMB_VFS_NEXT_DISK_FREE(handle, path, small_query,
					      bsize, dfree, dsize);
	}

	err = sys_fsusage(path, dfree, dsize);
	if (err) {
		DEBUG (0, ("Could not get fs usage, errno %d\n", errno));
		return SMB_VFS_NEXT_DISK_FREE(handle, path, small_query,
					      bsize, dfree, dsize);
	}

	/* sys_fsusage returns units of 512 bytes */
	*bsize = 512;

	DEBUG(10, ("fs dfree %llu, dsize %llu\n",
		   (unsigned long long)*dfree, (unsigned long long)*dsize));

	utok = handle->conn->session_info->unix_token;
	err = vfs_gpfs_get_quotas(path, utok->uid, utok->gid, &fset_id,
				  &qi_user, &qi_group, &qi_fset);
	if (err) {
		return SMB_VFS_NEXT_DISK_FREE(handle, path, small_query,
					      bsize, dfree, dsize);
	}

	cur_time = time(NULL);

	/* Adjust free space and size according to quota limits. */
	vfs_gpfs_disk_free_quota(qi_user, cur_time, dfree, dsize);
	vfs_gpfs_disk_free_quota(qi_group, cur_time, dfree, dsize);

	/* Id 0 indicates the default quota, not an actual quota */
	if (fset_id != 0) {
		vfs_gpfs_disk_free_quota(qi_fset, cur_time, dfree, dsize);
	}

	disk_norm(small_query, bsize, dfree, dsize);
	return *dfree;
}

static uint32_t vfs_gpfs_capabilities(struct vfs_handle_struct *handle,
				      enum timestamp_set_resolution *p_ts_res)
{
	struct gpfs_config_data *config;
	uint32_t next;

	next = SMB_VFS_NEXT_FS_CAPABILITIES(handle, p_ts_res);

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct gpfs_config_data,
				return next);

	if (config->hsm) {
		next |= FILE_SUPPORTS_REMOTE_STORAGE;
	}
	return next;
}

static int vfs_gpfs_open(struct vfs_handle_struct *handle,
			 struct smb_filename *smb_fname, files_struct *fsp,
			 int flags, mode_t mode)
{
	struct gpfs_config_data *config;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct gpfs_config_data,
				return -1);

	if (config->syncio) {
		flags |= O_SYNC;
	}
	return SMB_VFS_NEXT_OPEN(handle, smb_fname, fsp, flags, mode);
}

static ssize_t vfs_gpfs_pread(vfs_handle_struct *handle, files_struct *fsp,
			      void *data, size_t n, off_t offset)
{
	ssize_t ret;

	ret = SMB_VFS_NEXT_PREAD(handle, fsp, data, n, offset);

	DEBUG(10, ("vfs_private = %x\n",
		   (unsigned int)fsp->fsp_name->st.vfs_private));

	if ((ret != -1) &&
	    ((fsp->fsp_name->st.vfs_private & GPFS_WINATTR_OFFLINE) != 0)) {
		fsp->fsp_name->st.vfs_private &= ~GPFS_WINATTR_OFFLINE;
		notify_fname(handle->conn, NOTIFY_ACTION_MODIFIED,
			     FILE_NOTIFY_CHANGE_ATTRIBUTES,
			     fsp->fsp_name->base_name);
	}

	return ret;
}

struct vfs_gpfs_pread_state {
	struct files_struct *fsp;
	ssize_t ret;
	int err;
};

static void vfs_gpfs_pread_done(struct tevent_req *subreq);

static struct tevent_req *vfs_gpfs_pread_send(struct vfs_handle_struct *handle,
					      TALLOC_CTX *mem_ctx,
					      struct tevent_context *ev,
					      struct files_struct *fsp,
					      void *data, size_t n,
					      off_t offset)
{
	struct tevent_req *req, *subreq;
	struct vfs_gpfs_pread_state *state;

	req = tevent_req_create(mem_ctx, &state, struct vfs_gpfs_pread_state);
	if (req == NULL) {
		return NULL;
	}
	state->fsp = fsp;
	subreq = SMB_VFS_NEXT_PREAD_SEND(state, ev, handle, fsp, data,
					 n, offset);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, vfs_gpfs_pread_done, req);
	return req;
}

static void vfs_gpfs_pread_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct vfs_gpfs_pread_state *state = tevent_req_data(
		req, struct vfs_gpfs_pread_state);

	state->ret = SMB_VFS_PREAD_RECV(subreq, &state->err);
	TALLOC_FREE(subreq);
	tevent_req_done(req);
}

static ssize_t vfs_gpfs_pread_recv(struct tevent_req *req, int *err)
{
	struct vfs_gpfs_pread_state *state = tevent_req_data(
		req, struct vfs_gpfs_pread_state);
	struct files_struct *fsp = state->fsp;

	if (tevent_req_is_unix_error(req, err)) {
		return -1;
	}
	*err = state->err;

	DEBUG(10, ("vfs_private = %x\n",
		   (unsigned int)fsp->fsp_name->st.vfs_private));

	if ((state->ret != -1) &&
	    ((fsp->fsp_name->st.vfs_private & GPFS_WINATTR_OFFLINE) != 0)) {
		fsp->fsp_name->st.vfs_private &= ~GPFS_WINATTR_OFFLINE;
		DEBUG(10, ("sending notify\n"));
		notify_fname(fsp->conn, NOTIFY_ACTION_MODIFIED,
			     FILE_NOTIFY_CHANGE_ATTRIBUTES,
			     fsp->fsp_name->base_name);
	}

	return state->ret;
}

static ssize_t vfs_gpfs_pwrite(vfs_handle_struct *handle, files_struct *fsp,
			       const void *data, size_t n, off_t offset)
{
	ssize_t ret;

	ret = SMB_VFS_NEXT_PWRITE(handle, fsp, data, n, offset);

	DEBUG(10, ("vfs_private = %x\n",
		   (unsigned int)fsp->fsp_name->st.vfs_private));

	if ((ret != -1) &&
	    ((fsp->fsp_name->st.vfs_private & GPFS_WINATTR_OFFLINE) != 0)) {
		fsp->fsp_name->st.vfs_private &= ~GPFS_WINATTR_OFFLINE;
		notify_fname(handle->conn, NOTIFY_ACTION_MODIFIED,
			     FILE_NOTIFY_CHANGE_ATTRIBUTES,
			     fsp->fsp_name->base_name);
	}

	return ret;
}

struct vfs_gpfs_pwrite_state {
	struct files_struct *fsp;
	ssize_t ret;
	int err;
};

static void vfs_gpfs_pwrite_done(struct tevent_req *subreq);

static struct tevent_req *vfs_gpfs_pwrite_send(
	struct vfs_handle_struct *handle,
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct files_struct *fsp,
	const void *data, size_t n,
	off_t offset)
{
	struct tevent_req *req, *subreq;
	struct vfs_gpfs_pwrite_state *state;

	req = tevent_req_create(mem_ctx, &state, struct vfs_gpfs_pwrite_state);
	if (req == NULL) {
		return NULL;
	}
	state->fsp = fsp;
	subreq = SMB_VFS_NEXT_PWRITE_SEND(state, ev, handle, fsp, data,
					 n, offset);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, vfs_gpfs_pwrite_done, req);
	return req;
}

static void vfs_gpfs_pwrite_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct vfs_gpfs_pwrite_state *state = tevent_req_data(
		req, struct vfs_gpfs_pwrite_state);

	state->ret = SMB_VFS_PWRITE_RECV(subreq, &state->err);
	TALLOC_FREE(subreq);
	tevent_req_done(req);
}

static ssize_t vfs_gpfs_pwrite_recv(struct tevent_req *req, int *err)
{
	struct vfs_gpfs_pwrite_state *state = tevent_req_data(
		req, struct vfs_gpfs_pwrite_state);
	struct files_struct *fsp = state->fsp;

	if (tevent_req_is_unix_error(req, err)) {
		return -1;
	}
	*err = state->err;

	DEBUG(10, ("vfs_private = %x\n",
		   (unsigned int)fsp->fsp_name->st.vfs_private));

	if ((state->ret != -1) &&
	    ((fsp->fsp_name->st.vfs_private & GPFS_WINATTR_OFFLINE) != 0)) {
		fsp->fsp_name->st.vfs_private &= ~GPFS_WINATTR_OFFLINE;
		DEBUG(10, ("sending notify\n"));
		notify_fname(fsp->conn, NOTIFY_ACTION_MODIFIED,
			     FILE_NOTIFY_CHANGE_ATTRIBUTES,
			     fsp->fsp_name->base_name);
	}

	return state->ret;
}


static struct vfs_fn_pointers vfs_gpfs_fns = {
	.connect_fn = vfs_gpfs_connect,
	.disk_free_fn = vfs_gpfs_disk_free,
	.fs_capabilities_fn = vfs_gpfs_capabilities,
	.kernel_flock_fn = vfs_gpfs_kernel_flock,
	.linux_setlease_fn = vfs_gpfs_setlease,
	.get_real_filename_fn = vfs_gpfs_get_real_filename,
	.fget_nt_acl_fn = gpfsacl_fget_nt_acl,
	.get_nt_acl_fn = gpfsacl_get_nt_acl,
	.fset_nt_acl_fn = gpfsacl_fset_nt_acl,
	.sys_acl_get_file_fn = gpfsacl_sys_acl_get_file,
	.sys_acl_get_fd_fn = gpfsacl_sys_acl_get_fd,
	.sys_acl_set_file_fn = gpfsacl_sys_acl_set_file,
	.sys_acl_set_fd_fn = gpfsacl_sys_acl_set_fd,
	.sys_acl_delete_def_file_fn = gpfsacl_sys_acl_delete_def_file,
	.chmod_fn = vfs_gpfs_chmod,
	.fchmod_fn = vfs_gpfs_fchmod,
	.close_fn = vfs_gpfs_close,
	.setxattr_fn = gpfs_set_xattr,
	.getxattr_fn = gpfs_get_xattr,
	.stat_fn = vfs_gpfs_stat,
	.fstat_fn = vfs_gpfs_fstat,
	.lstat_fn = vfs_gpfs_lstat,
	.ntimes_fn = vfs_gpfs_ntimes,
	.is_offline_fn = vfs_gpfs_is_offline,
	.aio_force_fn = vfs_gpfs_aio_force,
	.sendfile_fn = vfs_gpfs_sendfile,
	.fallocate_fn = vfs_gpfs_fallocate,
	.open_fn = vfs_gpfs_open,
	.pread_fn = vfs_gpfs_pread,
	.pread_send_fn = vfs_gpfs_pread_send,
	.pread_recv_fn = vfs_gpfs_pread_recv,
	.pwrite_fn = vfs_gpfs_pwrite,
	.pwrite_send_fn = vfs_gpfs_pwrite_send,
	.pwrite_recv_fn = vfs_gpfs_pwrite_recv,
	.ftruncate_fn = vfs_gpfs_ftruncate
};

NTSTATUS vfs_gpfs_init(void);
NTSTATUS vfs_gpfs_init(void)
{
	init_gpfs();

	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "gpfs",
				&vfs_gpfs_fns);
}
