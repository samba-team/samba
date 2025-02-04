/*
 *  Unix SMB/CIFS implementation.
 *  Samba VFS module for GPFS filesystem
 *  Copyright (C) Christian Ambach <cambach1@de.ibm.com> 2006
 *  Copyright (C) Christof Schmitt 2015
 *  Major code contributions by Chetan Shringarpure <chetan.sh@in.ibm.com>
 *                           and Gomati Mohanan <gomati.mohanan@in.ibm.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "smbd/smbd.h"
#include "include/smbprofile.h"
#include "modules/non_posix_acls.h"
#include "libcli/security/security.h"
#include "nfs4_acls.h"
#include "system/filesys.h"
#include "auth.h"
#include "lib/util/tevent_unix.h"
#include "lib/util/gpfswrap.h"

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include "lib/crypto/gnutls_helpers.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

#ifndef GPFS_GETACL_NATIVE
#define GPFS_GETACL_NATIVE 0x00000004
#endif

struct gpfs_config_data {
	struct smbacl4_vfs_params nfs4_params;
	bool sharemodes;
	bool leases;
	bool hsm;
	bool syncio;
	bool winattr;
	bool ftruncate;
	bool getrealfilename;
	bool dfreequota;
	bool acl;
	bool settimes;
	bool recalls;
	bool clamp_invalid_times;
};

struct gpfs_fsp_extension {
	bool offline;
};

static inline unsigned int gpfs_acl_flags(gpfs_acl_t *gacl)
{
	if (gacl->acl_level == GPFS_ACL_LEVEL_V4FLAGS) {
		return gacl->v4Level1.acl_flags;
	}
	return 0;
}

static inline gpfs_ace_v4_t *gpfs_ace_ptr(gpfs_acl_t *gacl, unsigned int i)
{
	if (gacl->acl_level == GPFS_ACL_LEVEL_V4FLAGS) {
		return &gacl->v4Level1.ace_v4[i];
	}
	return &gacl->ace_v4[i];
}

static unsigned int vfs_gpfs_access_mask_to_allow(uint32_t access_mask)
{
	unsigned int allow = GPFS_SHARE_NONE;

	if (access_mask & (FILE_WRITE_DATA|FILE_APPEND_DATA)) {
		allow |= GPFS_SHARE_WRITE;
	}
	if (access_mask & (FILE_READ_DATA|FILE_EXECUTE)) {
		allow |= GPFS_SHARE_READ;
	}

	return allow;
}

static unsigned int vfs_gpfs_share_access_to_deny(uint32_t share_access)
{
	unsigned int deny = GPFS_DENY_NONE;

	if (!(share_access & FILE_SHARE_WRITE)) {
		deny |= GPFS_DENY_WRITE;
	}
	if (!(share_access & FILE_SHARE_READ)) {
		deny |= GPFS_DENY_READ;
	}

	/*
	 * GPFS_DENY_DELETE can only be set together with either
	 * GPFS_DENY_WRITE or GPFS_DENY_READ.
	 */
	if ((deny & (GPFS_DENY_WRITE|GPFS_DENY_READ)) &&
	    !(share_access & FILE_SHARE_DELETE)) {
		deny |= GPFS_DENY_DELETE;
	}

	return deny;
}

static int set_gpfs_sharemode(files_struct *fsp, uint32_t access_mask,
			      uint32_t share_access)
{
	unsigned int allow = GPFS_SHARE_NONE;
	unsigned int deny = GPFS_DENY_NONE;
	int result;

	if (access_mask == 0) {
		DBG_DEBUG("Clearing file system share mode.\n");
	} else {
		allow = vfs_gpfs_access_mask_to_allow(access_mask);
		deny = vfs_gpfs_share_access_to_deny(share_access);
	}
	DBG_DEBUG("access_mask=0x%x, allow=0x%x, share_access=0x%x, "
		  "deny=0x%x\n", access_mask, allow, share_access, deny);

	result = gpfswrap_set_share(fsp_get_io_fd(fsp), allow, deny);
	if (result == 0) {
		return 0;
	}

	if (errno == EACCES) {
		DBG_NOTICE("GPFS share mode denied for %s/%s.\n",
			   fsp->conn->connectpath,
			   fsp->fsp_name->base_name);
	} else if (errno == EPERM) {
		DBG_ERR("Samba requested GPFS sharemode for %s/%s, but the "
			"GPFS file system is not configured accordingly. "
			"Configure file system with mmchfs -D nfs4 or "
			"set gpfs:sharemodes=no in Samba.\n",
			fsp->conn->connectpath,
			fsp->fsp_name->base_name);
	} else {
		DBG_ERR("gpfs_set_share failed: %s\n", strerror(errno));
	}

	return result;
}

static int vfs_gpfs_filesystem_sharemode(vfs_handle_struct *handle,
					 files_struct *fsp,
					 uint32_t share_access,
					 uint32_t access_mask)
{

	struct gpfs_config_data *config;
	int ret = 0;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct gpfs_config_data,
				return -1);

	if(!config->sharemodes) {
		return 0;
	}

	/*
	 * A named stream fsp will have the basefile open in the fsp
	 * fd, so lacking a distinct fd for the stream we have to skip
	 * set_gpfs_sharemode for stream.
	 */
	if (fsp_is_alternate_stream(fsp)) {
		DBG_NOTICE("Not requesting GPFS sharemode on stream: %s/%s\n",
			   fsp->conn->connectpath,
			   fsp_str_dbg(fsp));
		return 0;
	}

	ret = set_gpfs_sharemode(fsp, access_mask, share_access);

	return ret;
}

static int vfs_gpfs_close(vfs_handle_struct *handle, files_struct *fsp)
{

	struct gpfs_config_data *config;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct gpfs_config_data,
				return -1);

	if (config->sharemodes &&
	    (fsp->fsp_flags.kernel_share_modes_taken))
	{
		/*
		 * Always clear GPFS sharemode in case the actual
		 * close gets deferred due to outstanding POSIX locks
		 * (see fd_close_posix)
		 */
		int ret = gpfswrap_set_share(fsp_get_io_fd(fsp), 0, 0);
		if (ret != 0) {
			DBG_ERR("Clearing GPFS sharemode on close failed for "
				" %s/%s: %s\n",
				fsp->conn->connectpath,
				fsp->fsp_name->base_name,
				strerror(errno));
		}
	}

	return SMB_VFS_NEXT_CLOSE(handle, fsp);
}

#ifdef HAVE_KERNEL_OPLOCKS_LINUX
static int lease_type_to_gpfs(int leasetype)
{
	if (leasetype == F_RDLCK) {
		return GPFS_LEASE_READ;
	}

	if (leasetype == F_WRLCK) {
		return GPFS_LEASE_WRITE;
	}

	return GPFS_LEASE_NONE;
}

static int vfs_gpfs_setlease(vfs_handle_struct *handle,
			     files_struct *fsp,
			     int leasetype)
{
	struct gpfs_config_data *config;
	int ret=0;

	START_PROFILE(syscall_linux_setlease);

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct gpfs_config_data,
				return -1);

	ret = linux_set_lease_sighandler(fsp_get_io_fd(fsp));
	if (ret == -1) {
		goto failure;
	}

	if (config->leases) {
		int gpfs_lease_type = lease_type_to_gpfs(leasetype);
		int saved_errno = 0;

		/*
		 * Ensure the lease owner is root to allow
		 * correct delivery of lease-break signals.
		 */
		become_root();
		ret = gpfswrap_set_lease(fsp_get_io_fd(fsp), gpfs_lease_type);
		if (ret < 0) {
			saved_errno = errno;
		}
		unbecome_root();

		if (saved_errno != 0) {
			errno = saved_errno;
		}
	}

failure:
	END_PROFILE(syscall_linux_setlease);

	return ret;
}

#else /* HAVE_KERNEL_OPLOCKS_LINUX */

static int vfs_gpfs_setlease(vfs_handle_struct *handle,
				files_struct *fsp,
				int leasetype)
{
	return ENOSYS;
}
#endif /* HAVE_KERNEL_OPLOCKS_LINUX */

static NTSTATUS vfs_gpfs_get_real_filename_at(struct vfs_handle_struct *handle,
					      struct files_struct *dirfsp,
					      const char *name,
					      TALLOC_CTX *mem_ctx,
					      char **found_name)
{
	int result;
	char *full_path = NULL;
	char *to_free = NULL;
	char real_pathname[PATH_MAX+1], tmpbuf[PATH_MAX];
	size_t full_path_len;
	int buflen;
	bool mangled;
	struct gpfs_config_data *config;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct gpfs_config_data,
				return NT_STATUS_INTERNAL_ERROR);

	if (!config->getrealfilename) {
		return SMB_VFS_NEXT_GET_REAL_FILENAME_AT(
			handle, dirfsp, name, mem_ctx, found_name);
	}

	mangled = mangle_is_mangled(name, handle->conn->params);
	if (mangled) {
		return SMB_VFS_NEXT_GET_REAL_FILENAME_AT(
			handle, dirfsp, name, mem_ctx, found_name);
	}

	full_path_len = full_path_tos(dirfsp->fsp_name->base_name, name,
				      tmpbuf, sizeof(tmpbuf),
				      &full_path, &to_free);
	if (full_path_len == -1) {
		return NT_STATUS_NO_MEMORY;
	}

	buflen = sizeof(real_pathname) - 1;

	result = gpfswrap_get_realfilename_path(full_path, real_pathname,
						&buflen);

	TALLOC_FREE(to_free);

	if ((result == -1) && (errno == ENOSYS)) {
		return SMB_VFS_NEXT_GET_REAL_FILENAME_AT(
			handle, dirfsp, name, mem_ctx, found_name);
	}

	if (result == -1) {
		DEBUG(10, ("smbd_gpfs_get_realfilename_path returned %s\n",
			   strerror(errno)));
		return map_nt_error_from_unix(errno);
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

	DBG_DEBUG("%s/%s -> %s\n",
		  fsp_str_dbg(dirfsp),
		  name,
		  real_pathname);

	name = strrchr_m(real_pathname, '/');
	if (name == NULL) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	*found_name = talloc_strdup(mem_ctx, name+1);
	if (*found_name == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	return NT_STATUS_OK;
}

static void sd2gpfs_control(uint16_t control, struct gpfs_acl *gacl)
{
	unsigned int gpfs_aclflags = 0;
	control &= SEC_DESC_DACL_PROTECTED | SEC_DESC_SACL_PROTECTED |
		SEC_DESC_DACL_AUTO_INHERITED | SEC_DESC_SACL_AUTO_INHERITED |
		SEC_DESC_DACL_DEFAULTED | SEC_DESC_SACL_DEFAULTED |
		SEC_DESC_DACL_PRESENT | SEC_DESC_SACL_PRESENT;
	gpfs_aclflags = control << 8;
	if (!(control & SEC_DESC_DACL_PRESENT))
		gpfs_aclflags |= ACL4_FLAG_NULL_DACL;
	if (!(control & SEC_DESC_SACL_PRESENT))
		gpfs_aclflags |= ACL4_FLAG_NULL_SACL;
	gacl->acl_level = GPFS_ACL_LEVEL_V4FLAGS;
	gacl->v4Level1.acl_flags = gpfs_aclflags;
}

static uint16_t gpfs2sd_control(unsigned int gpfs_aclflags)
{
	uint16_t control = gpfs_aclflags >> 8;
	control &= SEC_DESC_DACL_PROTECTED | SEC_DESC_SACL_PROTECTED |
		SEC_DESC_DACL_AUTO_INHERITED | SEC_DESC_SACL_AUTO_INHERITED |
		SEC_DESC_DACL_DEFAULTED | SEC_DESC_SACL_DEFAULTED |
		SEC_DESC_DACL_PRESENT | SEC_DESC_SACL_PRESENT;
	control |= SEC_DESC_SELF_RELATIVE;
	return control;
}

static void gpfs_dumpacl(int level, struct gpfs_acl *gacl)
{
	gpfs_aclCount_t i;
	if (gacl==NULL)
	{
		DEBUG(0, ("gpfs acl is NULL\n"));
		return;
	}

	DEBUG(level, ("len: %d, level: %d, version: %d, nace: %d, "
		      "control: %x\n",
		      gacl->acl_len, gacl->acl_level, gacl->acl_version,
		      gacl->acl_nace, gpfs_acl_flags(gacl)));

	for(i=0; i<gacl->acl_nace; i++)
	{
		struct gpfs_ace_v4 *gace = gpfs_ace_ptr(gacl, i);
		DEBUG(level, ("\tace[%d]: type:%d, flags:0x%x, mask:0x%x, "
			      "iflags:0x%x, who:%u\n",
			      i, gace->aceType, gace->aceFlags, gace->aceMask,
			      gace->aceIFlags, gace->aceWho));
	}
}

static int gpfs_getacl_with_capability(struct files_struct *fsp,
				       int flags,
				       void *buf)
{
	int ret, saved_errno;

	set_effective_capability(DAC_OVERRIDE_CAPABILITY);

	ret = gpfswrap_fgetacl(fsp_get_pathref_fd(fsp), flags, buf);
	saved_errno = errno;

	drop_effective_capability(DAC_OVERRIDE_CAPABILITY);

	errno = saved_errno;
	return ret;
}

/*
 * get the ACL from GPFS, allocated on the specified mem_ctx
 * internally retries when initial buffer was too small
 *
 * caller needs to cast result to either
 * raw = yes: struct gpfs_opaque_acl
 * raw = no: struct gpfs_acl
 *
 */
static void *vfs_gpfs_getacl(TALLOC_CTX *mem_ctx,
			 struct files_struct *fsp,
			 const bool raw,
			 const gpfs_aclType_t type)
{
	const char *fname = fsp->fsp_name->base_name;
	void *aclbuf;
	size_t size = 512;
	int ret, flags;
	unsigned int *len;
	size_t struct_size;
	bool use_capability = false;

again:

	aclbuf = talloc_zero_size(mem_ctx, size);
	if (aclbuf == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	if (raw) {
		struct gpfs_opaque_acl *buf = (struct gpfs_opaque_acl *) aclbuf;
		buf->acl_type = type;
		flags = GPFS_GETACL_NATIVE;
		len = (unsigned int *) &(buf->acl_buffer_len);
		struct_size = sizeof(struct gpfs_opaque_acl);
	} else {
		struct gpfs_acl *buf = (struct gpfs_acl *) aclbuf;
		buf->acl_type = type;
		buf->acl_level = GPFS_ACL_LEVEL_V4FLAGS;
		flags = GPFS_GETACL_STRUCT;
		len = &(buf->acl_len);
		/* reserve space for control flags in gpfs 3.5 and beyond */
		struct_size = sizeof(struct gpfs_acl) + sizeof(unsigned int);
	}

	/* set the length of the buffer as input value */
	*len = size;

	if (use_capability) {
		ret = gpfs_getacl_with_capability(fsp, flags, aclbuf);
	} else {
		ret = gpfswrap_fgetacl(fsp_get_pathref_fd(fsp), flags, aclbuf);
		if ((ret != 0) && (errno == EACCES)) {
			DBG_DEBUG("Retry with DAC capability for %s\n", fname);
			use_capability = true;
			ret = gpfs_getacl_with_capability(fsp, flags, aclbuf);
		}
	}

	if ((ret != 0) && (errno == ENOSPC)) {
		/*
		 * get the size needed to accommodate the complete buffer
		 *
		 * the value returned only applies to the ACL blob in the
		 * struct so make sure to also have headroom for the first
		 * struct members by adding room for the complete struct
		 * (might be a few bytes too much then)
		 */
		size = *len + struct_size;
		talloc_free(aclbuf);
		DEBUG(10, ("Increasing ACL buffer size to %zu\n", size));
		goto again;
	}

	if (ret != 0) {
		DEBUG(5, ("smbd_gpfs_getacl failed with %s\n",
			  strerror(errno)));
		talloc_free(aclbuf);
		return NULL;
	}

	return aclbuf;
}

/* Tries to get nfs4 acls and returns SMB ACL allocated.
 * On failure returns 1 if it got non-NFSv4 ACL to prompt 
 * retry with POSIX ACL checks.
 * On failure returns -1 if there is system (GPFS) error, check errno.
 * Returns 0 on success
 */
static int gpfs_get_nfs4_acl(TALLOC_CTX *mem_ctx,
			     struct files_struct *fsp,
			     struct SMB4ACL_T **ppacl)
{
	const char *fname = fsp->fsp_name->base_name;
	gpfs_aclCount_t i;
	struct gpfs_acl *gacl = NULL;
	DEBUG(10, ("gpfs_get_nfs4_acl invoked for %s\n", fname));

	/* Get the ACL */
	gacl = (struct gpfs_acl*) vfs_gpfs_getacl(talloc_tos(), fsp,
						  false, 0);
	if (gacl == NULL) {
		DEBUG(9, ("gpfs_getacl failed for %s with %s\n",
			   fname, strerror(errno)));
		if (errno == ENODATA) {
			/*
			 * GPFS returns ENODATA for snapshot
			 * directories. Retry with POSIX ACLs check.
			 */
			return 1;
		}

		return -1;
	}

	if (gacl->acl_type != GPFS_ACL_TYPE_NFS4) {
		DEBUG(10, ("Got non-nfsv4 acl\n"));
		/* Retry with POSIX ACLs check */
		talloc_free(gacl);
		return 1;
	}

	*ppacl = smb_create_smb4acl(mem_ctx);

	if (gacl->acl_level == GPFS_ACL_LEVEL_V4FLAGS) {
		uint16_t control = gpfs2sd_control(gpfs_acl_flags(gacl));
		smbacl4_set_controlflags(*ppacl, control);
	}

	DEBUG(10, ("len: %d, level: %d, version: %d, nace: %d, control: %x\n",
		   gacl->acl_len, gacl->acl_level, gacl->acl_version,
		   gacl->acl_nace, gpfs_acl_flags(gacl)));

	for (i=0; i<gacl->acl_nace; i++) {
		struct gpfs_ace_v4 *gace = gpfs_ace_ptr(gacl, i);
		SMB_ACE4PROP_T smbace = { 0 };
		DEBUG(10, ("type: %d, iflags: %x, flags: %x, mask: %x, "
			   "who: %d\n", gace->aceType, gace->aceIFlags,
			   gace->aceFlags, gace->aceMask, gace->aceWho));

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

		/* remove redundant deny entries */
		if (i > 0 && gace->aceType == SMB_ACE4_ACCESS_DENIED_ACE_TYPE) {
			struct gpfs_ace_v4 *prev = gpfs_ace_ptr(gacl, i - 1);
			if (prev->aceType == SMB_ACE4_ACCESS_ALLOWED_ACE_TYPE &&
			    prev->aceFlags == gace->aceFlags &&
			    prev->aceIFlags == gace->aceIFlags &&
			    (gace->aceMask & prev->aceMask) == 0 &&
			    gace->aceWho == prev->aceWho) {
				/* it's redundant - skip it */
				continue;
			}
		}

		smbace.aceType = gace->aceType;
		smbace.aceFlags = gace->aceFlags;
		smbace.aceMask = gace->aceMask;
		smb_add_ace4(*ppacl, &smbace);
	}

	talloc_free(gacl);

	return 0;
}

static NTSTATUS gpfsacl_fget_nt_acl(vfs_handle_struct *handle,
	files_struct *fsp, uint32_t security_info,
	TALLOC_CTX *mem_ctx,
	struct security_descriptor **ppdesc)
{
	struct SMB4ACL_T *pacl = NULL;
	int	result;
	struct gpfs_config_data *config;
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;

	*ppdesc = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct gpfs_config_data,
				return NT_STATUS_INTERNAL_ERROR);

	if (!config->acl) {
		status = SMB_VFS_NEXT_FGET_NT_ACL(handle, fsp, security_info,
						  mem_ctx, ppdesc);
		TALLOC_FREE(frame);
		return status;
	}

	result = gpfs_get_nfs4_acl(frame, fsp, &pacl);

	if (result == 0) {
		status = smb_fget_nt_acl_nfs4(fsp, &config->nfs4_params,
					      security_info,
					      mem_ctx, ppdesc, pacl);
		TALLOC_FREE(frame);
		return status;
	}

	if (result > 0) {
		DEBUG(10, ("retrying with posix acl...\n"));
		status = posix_fget_nt_acl(fsp, security_info,
					   mem_ctx, ppdesc);
		TALLOC_FREE(frame);
		return status;
	}

	TALLOC_FREE(frame);

	/* GPFS ACL was not read, something wrong happened, error code is set in errno */
	return map_nt_error_from_unix(errno);
}

static bool vfs_gpfs_nfs4_ace_to_gpfs_ace(SMB_ACE4PROP_T *nfs4_ace,
					  struct gpfs_ace_v4 *gace,
					  uid_t owner_uid)
{
	gace->aceType = nfs4_ace->aceType;
	gace->aceFlags = nfs4_ace->aceFlags;
	gace->aceMask = nfs4_ace->aceMask;

	if (nfs4_ace->flags & SMB_ACE4_ID_SPECIAL) {
		switch(nfs4_ace->who.special_id) {
		case SMB_ACE4_WHO_EVERYONE:
			gace->aceIFlags = ACE4_IFLAG_SPECIAL_ID;
			gace->aceWho = ACE4_SPECIAL_EVERYONE;
			break;
		case SMB_ACE4_WHO_OWNER:
			/*
			 * With GPFS it is not possible to deny ACL or
			 * attribute access to the owner. Setting an
			 * ACL with such an entry is not possible.
			 * Denying ACL or attribute access for the
			 * owner through a named ACL entry can be
			 * stored in an ACL, it is just not effective.
			 *
			 * Map this case to a named entry to allow at
			 * least setting this ACL, which will be
			 * enforced by the smbd permission check. Do
			 * not do this for an inheriting OWNER entry,
			 * as this represents a CREATOR OWNER ACE. The
			 * remaining limitation is that CREATOR OWNER
			 * cannot deny ACL or attribute access.
			 */
			if (!nfs_ace_is_inherit(nfs4_ace) &&
			    nfs4_ace->aceType ==
					SMB_ACE4_ACCESS_DENIED_ACE_TYPE &&
			    nfs4_ace->aceMask & (SMB_ACE4_READ_ATTRIBUTES|
						 SMB_ACE4_WRITE_ATTRIBUTES|
						 SMB_ACE4_READ_ACL|
						 SMB_ACE4_WRITE_ACL)) {
				gace->aceIFlags = 0;
				gace->aceWho = owner_uid;
			} else {
				gace->aceIFlags = ACE4_IFLAG_SPECIAL_ID;
				gace->aceWho = ACE4_SPECIAL_OWNER;
			}
			break;
		case SMB_ACE4_WHO_GROUP:
			gace->aceIFlags = ACE4_IFLAG_SPECIAL_ID;
			gace->aceWho = ACE4_SPECIAL_GROUP;
			break;
		default:
			DBG_WARNING("Unsupported special_id %d\n",
				    nfs4_ace->who.special_id);
			return false;
		}

		return true;
	}

	gace->aceIFlags = 0;
	gace->aceWho = (nfs4_ace->aceFlags & SMB_ACE4_IDENTIFIER_GROUP) ?
		nfs4_ace->who.gid : nfs4_ace->who.uid;

	return true;
}

static struct gpfs_acl *vfs_gpfs_smbacl2gpfsacl(TALLOC_CTX *mem_ctx,
						files_struct *fsp,
						struct SMB4ACL_T *smbacl,
						bool controlflags)
{
	struct gpfs_acl *gacl;
	gpfs_aclLen_t gacl_len;
	struct SMB4ACE_T *smbace;

	gacl_len = offsetof(gpfs_acl_t, ace_v4) + sizeof(unsigned int)
		+ smb_get_naces(smbacl) * sizeof(gpfs_ace_v4_t);

	gacl = (struct gpfs_acl *)TALLOC_SIZE(mem_ctx, gacl_len);
	if (gacl == NULL) {
		DEBUG(0, ("talloc failed\n"));
		errno = ENOMEM;
		return NULL;
	}

	gacl->acl_level = GPFS_ACL_LEVEL_BASE;
	gacl->acl_version = GPFS_ACL_VERSION_NFS4;
	gacl->acl_type = GPFS_ACL_TYPE_NFS4;
	gacl->acl_nace = 0; /* change later... */

	if (controlflags) {
		gacl->acl_level = GPFS_ACL_LEVEL_V4FLAGS;
		sd2gpfs_control(smbacl4_get_controlflags(smbacl), gacl);
	}

	for (smbace=smb_first_ace4(smbacl); smbace!=NULL; smbace = smb_next_ace4(smbace)) {
		struct gpfs_ace_v4 *gace = gpfs_ace_ptr(gacl, gacl->acl_nace);
		SMB_ACE4PROP_T	*aceprop = smb_get_ace4(smbace);
		bool add_ace;

		add_ace = vfs_gpfs_nfs4_ace_to_gpfs_ace(aceprop, gace,
							fsp->fsp_name->st.st_ex_uid);
		if (!add_ace) {
			continue;
		}

		gacl->acl_nace++;
	}
	gacl->acl_len = (char *)gpfs_ace_ptr(gacl, gacl->acl_nace)
		- (char *)gacl;
	return gacl;
}

static bool gpfsacl_process_smbacl(vfs_handle_struct *handle,
				   files_struct *fsp,
				   struct SMB4ACL_T *smbacl)
{
	int ret;
	struct gpfs_acl *gacl;
	TALLOC_CTX *mem_ctx = talloc_tos();

	gacl = vfs_gpfs_smbacl2gpfsacl(mem_ctx, fsp, smbacl, true);
	if (gacl == NULL) { /* out of memory */
		return False;
	}
	ret = gpfswrap_putacl(fsp->fsp_name->base_name,
			      GPFS_PUTACL_STRUCT | GPFS_ACL_SAMBA, gacl);

	if ((ret != 0) && (errno == EINVAL)) {
		DEBUG(10, ("Retry without nfs41 control flags\n"));
		talloc_free(gacl);
		gacl = vfs_gpfs_smbacl2gpfsacl(mem_ctx, fsp, smbacl, false);
		if (gacl == NULL) { /* out of memory */
			return False;
		}
		ret = gpfswrap_putacl(fsp->fsp_name->base_name,
				      GPFS_PUTACL_STRUCT | GPFS_ACL_SAMBA,
				      gacl);
	}

	if (ret != 0) {
		DEBUG(8, ("gpfs_putacl failed with %s\n", strerror(errno)));
		gpfs_dumpacl(8, gacl);
		return False;
	}

	DEBUG(10, ("gpfs_putacl succeeded\n"));
	return True;
}

static NTSTATUS gpfsacl_set_nt_acl_internal(vfs_handle_struct *handle, files_struct *fsp, uint32_t security_info_sent, const struct security_descriptor *psd)
{
	struct gpfs_acl *acl;
	NTSTATUS result = NT_STATUS_ACCESS_DENIED;

	acl = (struct gpfs_acl*) vfs_gpfs_getacl(talloc_tos(),
						 fsp,
						 false, 0);
	if (acl == NULL) {
		return map_nt_error_from_unix(errno);
	}

	if (acl->acl_version == GPFS_ACL_VERSION_NFS4) {
		struct gpfs_config_data *config;

		SMB_VFS_HANDLE_GET_DATA(handle, config,
					struct gpfs_config_data,
					return NT_STATUS_INTERNAL_ERROR);

		result = smb_set_nt_acl_nfs4(handle,
			fsp, &config->nfs4_params, security_info_sent, psd,
			gpfsacl_process_smbacl);
	} else { /* assume POSIX ACL - by default... */
		result = set_nt_acl(fsp, security_info_sent, psd);
	}

	talloc_free(acl);
	return result;
}

static NTSTATUS gpfsacl_fset_nt_acl(vfs_handle_struct *handle, files_struct *fsp, uint32_t security_info_sent, const struct security_descriptor *psd)
{
	struct gpfs_config_data *config;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct gpfs_config_data,
				return NT_STATUS_INTERNAL_ERROR);

	if (!config->acl) {
		return SMB_VFS_NEXT_FSET_NT_ACL(handle, fsp, security_info_sent, psd);
	}

	return gpfsacl_set_nt_acl_internal(handle, fsp, security_info_sent, psd);
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

static SMB_ACL_T gpfsacl_get_posix_acl(struct files_struct *fsp,
				       gpfs_aclType_t type,
				       TALLOC_CTX *mem_ctx)
{
	struct gpfs_acl *pacl;
	SMB_ACL_T result = NULL;

	pacl = vfs_gpfs_getacl(talloc_tos(), fsp, false, type);

	if (pacl == NULL) {
		DBG_DEBUG("vfs_gpfs_getacl failed for %s with %s\n",
			   fsp_str_dbg(fsp), strerror(errno));
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

static SMB_ACL_T gpfsacl_sys_acl_get_fd(vfs_handle_struct *handle,
					files_struct *fsp,
					SMB_ACL_TYPE_T type,
					TALLOC_CTX *mem_ctx)
{
	gpfs_aclType_t gpfs_type;
	struct gpfs_config_data *config;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct gpfs_config_data,
				return NULL);

	if (!config->acl) {
		return SMB_VFS_NEXT_SYS_ACL_GET_FD(handle, fsp, type, mem_ctx);
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
	return gpfsacl_get_posix_acl(fsp, gpfs_type, mem_ctx);
}

static int gpfsacl_sys_acl_blob_get_fd(vfs_handle_struct *handle,
				      files_struct *fsp,
				      TALLOC_CTX *mem_ctx,
				      char **blob_description,
				      DATA_BLOB *blob)
{
	struct gpfs_config_data *config;
	struct gpfs_opaque_acl *acl = NULL;
	DATA_BLOB aclblob;
	int result;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct gpfs_config_data,
				return -1);

	if (!config->acl) {
		return SMB_VFS_NEXT_SYS_ACL_BLOB_GET_FD(handle, fsp, mem_ctx,
							blob_description, blob);
	}

	errno = 0;
	acl = (struct gpfs_opaque_acl *) vfs_gpfs_getacl(mem_ctx,
						fsp,
						true,
						GPFS_ACL_TYPE_NFS4);

	if (errno) {
		DEBUG(5, ("vfs_gpfs_getacl finished with errno %d: %s\n",
					errno, strerror(errno)));

		/* EINVAL means POSIX ACL, bail out on other cases */
		if (errno != EINVAL) {
			return -1;
		}
	}

	if (acl != NULL) {
		/*
		 * file has NFSv4 ACL
		 *
		 * we only need the actual ACL blob here
		 * acl_version will always be NFS4 because we asked
		 * for NFS4
		 * acl_type is only used for POSIX ACLs
		 */
		aclblob.data = (uint8_t*) acl->acl_var_data;
		aclblob.length = acl->acl_buffer_len;

		*blob_description = talloc_strdup(mem_ctx, "gpfs_nfs4_acl");
		if (!*blob_description) {
			talloc_free(acl);
			errno = ENOMEM;
			return -1;
		}

		result = non_posix_sys_acl_blob_get_fd_helper(handle, fsp,
							      aclblob, mem_ctx,
							      blob);

		talloc_free(acl);
		return result;
	}

	/* fall back to POSIX ACL */
	return posix_sys_acl_blob_get_fd(handle, fsp, mem_ctx,
					 blob_description, blob);
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

static int gpfsacl_sys_acl_set_fd(vfs_handle_struct *handle,
				  files_struct *fsp,
				  SMB_ACL_TYPE_T type,
				  SMB_ACL_T theacl)
{
	struct gpfs_config_data *config;
	struct gpfs_acl *gpfs_acl = NULL;
	int result;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct gpfs_config_data,
				return -1);

	if (!config->acl) {
		return SMB_VFS_NEXT_SYS_ACL_SET_FD(handle, fsp, type, theacl);
	}

	gpfs_acl = smb2gpfs_acl(theacl, type);
	if (gpfs_acl == NULL) {
		return -1;
	}

	/*
	 * This is no longer a handle based call.
	 */
	result = gpfswrap_putacl(fsp->fsp_name->base_name,
				 GPFS_PUTACL_STRUCT|GPFS_ACL_SAMBA,
				 gpfs_acl);
	SAFE_FREE(gpfs_acl);
	return result;
}

static int gpfsacl_sys_acl_delete_def_fd(vfs_handle_struct *handle,
				files_struct *fsp)
{
	struct gpfs_config_data *config;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct gpfs_config_data,
				return -1);

	if (!config->acl) {
		return SMB_VFS_NEXT_SYS_ACL_DELETE_DEF_FD(handle, fsp);
	}

	errno = ENOTSUP;
	return -1;
}


/*
 * Assumed: mode bits are shiftable and standard
 * Output: the new aceMask field for an smb nfs4 ace
 */
static uint32_t gpfsacl_mask_filter(uint32_t aceType, uint32_t aceMask, uint32_t rwx)
{
	const uint32_t posix_nfs4map[3] = {
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

static int gpfsacl_emu_chmod(vfs_handle_struct *handle,
			     struct files_struct *fsp,
			     mode_t mode)
{
	struct smb_filename *fname = fsp->fsp_name;
	char *path = fsp->fsp_name->base_name;
	struct SMB4ACL_T *pacl = NULL;
	int     result;
	bool    haveAllowEntry[SMB_ACE4_WHO_EVERYONE + 1] = {False, False, False, False};
	int     i;
	files_struct fake_fsp = { 0 }; /* TODO: rationalize parametrization */
	struct SMB4ACE_T *smbace;
	TALLOC_CTX *frame = talloc_stackframe();

	DEBUG(10, ("gpfsacl_emu_chmod invoked for %s mode %o\n", path, mode));

	result = gpfs_get_nfs4_acl(frame, fsp, &pacl);
	if (result) {
		TALLOC_FREE(frame);
		return result;
	}

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
		SMB_ACE4PROP_T ace = { 0 };

		if (haveAllowEntry[i]==True)
			continue;

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
	fake_fsp.fsp_name = synthetic_smb_fname(frame,
						path,
						NULL,
						NULL,
						fname->twrp,
						0);
	if (fake_fsp.fsp_name == NULL) {
		errno = ENOMEM;
		TALLOC_FREE(frame);
		return -1;
	}
	/* put the acl */
	if (gpfsacl_process_smbacl(handle, &fake_fsp, pacl) == False) {
		TALLOC_FREE(frame);
		return -1;
	}

	TALLOC_FREE(frame);
	return 0; /* ok for [f]chmod */
}

static int vfs_gpfs_fchmod(vfs_handle_struct *handle, files_struct *fsp, mode_t mode)
{
	SMB_STRUCT_STAT st;
	int rc;

	rc = SMB_VFS_NEXT_FSTAT(handle, fsp, &st);
	if (rc != 0) {
		return -1;
	}

	/* avoid chmod() if possible, to preserve acls */
	if ((st.st_ex_mode & ~S_IFMT) == mode) {
		return 0;
	}

	rc = gpfsacl_emu_chmod(handle, fsp, mode);
	if (rc == 1) {
		return SMB_VFS_NEXT_FCHMOD(handle, fsp, mode);
	}
	return rc;
}

static uint32_t vfs_gpfs_winattrs_to_dosmode(unsigned int winattrs)
{
	uint32_t dosmode = 0;

	if (winattrs & GPFS_WINATTR_ARCHIVE){
		dosmode |= FILE_ATTRIBUTE_ARCHIVE;
	}
	if (winattrs & GPFS_WINATTR_HIDDEN){
		dosmode |= FILE_ATTRIBUTE_HIDDEN;
	}
	if (winattrs & GPFS_WINATTR_SYSTEM){
		dosmode |= FILE_ATTRIBUTE_SYSTEM;
	}
	if (winattrs & GPFS_WINATTR_READONLY){
		dosmode |= FILE_ATTRIBUTE_READONLY;
	}
	if (winattrs & GPFS_WINATTR_SPARSE_FILE) {
		dosmode |= FILE_ATTRIBUTE_SPARSE;
	}
	if (winattrs & GPFS_WINATTR_OFFLINE) {
		dosmode |= FILE_ATTRIBUTE_OFFLINE;
	}

	return dosmode;
}

static unsigned int vfs_gpfs_dosmode_to_winattrs(uint32_t dosmode)
{
	unsigned int winattrs = 0;

	if (dosmode & FILE_ATTRIBUTE_ARCHIVE){
		winattrs |= GPFS_WINATTR_ARCHIVE;
	}
	if (dosmode & FILE_ATTRIBUTE_HIDDEN){
		winattrs |= GPFS_WINATTR_HIDDEN;
	}
	if (dosmode & FILE_ATTRIBUTE_SYSTEM){
		winattrs |= GPFS_WINATTR_SYSTEM;
	}
	if (dosmode & FILE_ATTRIBUTE_READONLY){
		winattrs |= GPFS_WINATTR_READONLY;
	}
	if (dosmode & FILE_ATTRIBUTE_SPARSE) {
		winattrs |= GPFS_WINATTR_SPARSE_FILE;
	}
	if (dosmode & FILE_ATTRIBUTE_OFFLINE) {
		winattrs |= GPFS_WINATTR_OFFLINE;
	}

	return winattrs;
}

static struct timespec gpfs_timestruc64_to_timespec(struct gpfs_timestruc64 g)
{
	return (struct timespec) { .tv_sec = g.tv_sec, .tv_nsec = g.tv_nsec };
}

static NTSTATUS vfs_gpfs_fget_dos_attributes(struct vfs_handle_struct *handle,
					     struct files_struct *fsp,
					     uint32_t *dosmode)
{
	struct gpfs_config_data *config;
	int fd = fsp_get_pathref_fd(fsp);
	struct gpfs_iattr64 iattr = { };
	unsigned int litemask = 0;
	struct timespec ts;
	int ret;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct gpfs_config_data,
				return NT_STATUS_INTERNAL_ERROR);

	if (!config->winattr) {
		return SMB_VFS_NEXT_FGET_DOS_ATTRIBUTES(handle, fsp, dosmode);
	}

	ret = gpfswrap_fstat_x(fd, &litemask, &iattr, sizeof(iattr));
	if (ret == -1 && errno == ENOSYS) {
		return SMB_VFS_NEXT_FGET_DOS_ATTRIBUTES(handle, fsp, dosmode);
	}

	if (ret == -1 && errno == EACCES) {
		int saved_errno = 0;

		/*
		 * According to MS-FSA 2.1.5.1.2.1 "Algorithm to Check Access to
		 * an Existing File" FILE_LIST_DIRECTORY on a directory implies
		 * FILE_READ_ATTRIBUTES for directory entries. Being able to
		 * open a file implies FILE_LIST_DIRECTORY.
		 */

		set_effective_capability(DAC_OVERRIDE_CAPABILITY);

		ret = gpfswrap_fstat_x(fd, &litemask, &iattr, sizeof(iattr));
		if (ret == -1) {
			saved_errno = errno;
		}

		drop_effective_capability(DAC_OVERRIDE_CAPABILITY);

		if (saved_errno != 0) {
			errno = saved_errno;
		}
	}

	if (ret == -1) {
		DBG_WARNING("Getting winattrs failed for %s: %s\n",
			    fsp->fsp_name->base_name, strerror(errno));
		return map_nt_error_from_unix(errno);
	}

	ts = gpfs_timestruc64_to_timespec(iattr.ia_createtime);

	*dosmode |= vfs_gpfs_winattrs_to_dosmode(iattr.ia_winflags);
	update_stat_ex_create_time(&fsp->fsp_name->st, ts);

	return NT_STATUS_OK;
}

static NTSTATUS vfs_gpfs_fset_dos_attributes(struct vfs_handle_struct *handle,
					     struct files_struct *fsp,
					     uint32_t dosmode)
{
	struct gpfs_config_data *config;
	struct gpfs_winattr attrs = { };
	int ret;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct gpfs_config_data,
				return NT_STATUS_INTERNAL_ERROR);

	if (!config->winattr) {
		return SMB_VFS_NEXT_FSET_DOS_ATTRIBUTES(handle, fsp, dosmode);
	}

	attrs.winAttrs = vfs_gpfs_dosmode_to_winattrs(dosmode);

	if (!fsp->fsp_flags.is_pathref) {
		ret = gpfswrap_set_winattrs(fsp_get_io_fd(fsp),
					    GPFS_WINATTR_SET_ATTRS, &attrs);
		if (ret == -1) {
			DBG_WARNING("Setting winattrs failed for %s: %s\n",
				    fsp_str_dbg(fsp), strerror(errno));
			return map_nt_error_from_unix(errno);
		}
		return NT_STATUS_OK;
	}

	if (fsp->fsp_flags.have_proc_fds) {
		int fd = fsp_get_pathref_fd(fsp);
		struct sys_proc_fd_path_buf buf;

		ret = gpfswrap_set_winattrs_path(sys_proc_fd_path(fd, &buf),
						 GPFS_WINATTR_SET_ATTRS,
						 &attrs);
		if (ret == -1) {
			DBG_WARNING("Setting winattrs failed for "
				    "[%s][%s]: %s\n",
				    buf.buf,
				    fsp_str_dbg(fsp),
				    strerror(errno));
			return map_nt_error_from_unix(errno);
		}
		return NT_STATUS_OK;
	}

	/*
	 * This is no longer a handle based call.
	 */
	ret = gpfswrap_set_winattrs_path(fsp->fsp_name->base_name,
					 GPFS_WINATTR_SET_ATTRS,
					 &attrs);
	if (ret == -1) {
		DBG_WARNING("Setting winattrs failed for [%s]: %s\n",
			    fsp_str_dbg(fsp), strerror(errno));
		return map_nt_error_from_unix(errno);
	}

	return NT_STATUS_OK;
}

static int timespec_to_gpfs_time(struct gpfs_config_data *config,
				 struct timespec ts,
				 gpfs_timestruc_t *gt,
				 int idx,
				 int *flags)
{
	if (is_omit_timespec(&ts)) {
		return 0;
	}

	if (ts.tv_sec < 0 || ts.tv_sec > UINT32_MAX) {
		if (!config->clamp_invalid_times) {
			DBG_NOTICE("GPFS uses 32-bit unsigned timestamps "
				   "and cannot handle %jd.\n",
				   (intmax_t)ts.tv_sec);
			errno = ERANGE;
			return -1;
		}
		if (ts.tv_sec < 0) {
			ts.tv_sec = 0;
		} else {
			ts.tv_sec = UINT32_MAX;
		}
	}

	*flags |= 1 << idx;
	gt[idx].tv_sec = ts.tv_sec;
	gt[idx].tv_nsec = ts.tv_nsec;
	DBG_DEBUG("Setting GPFS time %d, flags 0x%x\n", idx, *flags);

	return 0;
}

static int smbd_gpfs_set_times(struct gpfs_config_data *config,
			       struct files_struct *fsp,
			       struct smb_file_time *ft)
{
	gpfs_timestruc_t gpfs_times[4];
	int flags = 0;
	int rc;

	ZERO_ARRAY(gpfs_times);
	rc = timespec_to_gpfs_time(config, ft->atime, gpfs_times, 0, &flags);
	if (rc != 0) {
		return rc;
	}

	rc = timespec_to_gpfs_time(config, ft->mtime, gpfs_times, 1, &flags);
	if (rc != 0) {
		return rc;
	}

	/* No good mapping from LastChangeTime to ctime, not storing */
	rc = timespec_to_gpfs_time(config,
				   ft->create_time,
				   gpfs_times,
				   3,
				   &flags);
	if (rc != 0) {
		return rc;
	}

	if (!flags) {
		DBG_DEBUG("nothing to do, return to avoid EINVAL\n");
		return 0;
	}

	if (!fsp->fsp_flags.is_pathref) {
		rc = gpfswrap_set_times(fsp_get_io_fd(fsp), flags, gpfs_times);
		if (rc != 0) {
			DBG_WARNING("gpfs_set_times(%s) failed: %s\n",
				    fsp_str_dbg(fsp), strerror(errno));
		}
		return rc;
	}


	if (fsp->fsp_flags.have_proc_fds) {
		int fd = fsp_get_pathref_fd(fsp);
		struct sys_proc_fd_path_buf buf;

		rc = gpfswrap_set_times_path(sys_proc_fd_path(fd, &buf),
					     flags,
					     gpfs_times);
		if (rc != 0) {
			DBG_WARNING("gpfs_set_times_path(%s,%s) failed: %s\n",
				    fsp_str_dbg(fsp),
				    buf.buf,
				    strerror(errno));
		}
		return rc;
	}

	/*
	 * This is no longer a handle based call.
	 */

	rc = gpfswrap_set_times_path(fsp->fsp_name->base_name,
				     flags,
				     gpfs_times);
	if (rc != 0) {
		DBG_WARNING("gpfs_set_times_path(%s) failed: %s\n",
			    fsp_str_dbg(fsp), strerror(errno));
	}
	return rc;
}

static int vfs_gpfs_fntimes(struct vfs_handle_struct *handle,
		files_struct *fsp,
		struct smb_file_time *ft)
{

	struct gpfs_winattr attrs;
	int ret;
	struct gpfs_config_data *config;

	SMB_VFS_HANDLE_GET_DATA(handle,
				config,
				struct gpfs_config_data,
				return -1);

	/* Try to use gpfs_set_times if it is enabled and available */
	if (config->settimes) {
		return smbd_gpfs_set_times(config, fsp, ft);
	}

	DBG_DEBUG("gpfs_set_times() not available or disabled, "
		  "use ntimes and winattr\n");

	ret = SMB_VFS_NEXT_FNTIMES(handle, fsp, ft);
	if (ret == -1) {
		/* don't complain if access was denied */
		if (errno != EPERM && errno != EACCES) {
			DBG_WARNING("SMB_VFS_NEXT_FNTIMES failed: %s\n",
				    strerror(errno));
		}
		return -1;
	}

	if (is_omit_timespec(&ft->create_time)) {
		DBG_DEBUG("Create Time is NULL\n");
		return 0;
	}

	if (!config->winattr) {
		return 0;
	}

	attrs.winAttrs = 0;
	attrs.creationTime.tv_sec = ft->create_time.tv_sec;
	attrs.creationTime.tv_nsec = ft->create_time.tv_nsec;

	if (!fsp->fsp_flags.is_pathref) {
		ret = gpfswrap_set_winattrs(fsp_get_io_fd(fsp),
					    GPFS_WINATTR_SET_CREATION_TIME,
					    &attrs);
		if (ret == -1 && errno != ENOSYS) {
			DBG_WARNING("Set GPFS ntimes failed %d\n", ret);
			return -1;
		}
		return ret;
	}

	if (fsp->fsp_flags.have_proc_fds) {
		int fd = fsp_get_pathref_fd(fsp);
		struct sys_proc_fd_path_buf buf;

		ret = gpfswrap_set_winattrs_path(
			sys_proc_fd_path(fd, &buf),
			GPFS_WINATTR_SET_CREATION_TIME,
			&attrs);
		if (ret == -1 && errno != ENOSYS) {
			DBG_WARNING("Set GPFS ntimes failed %d\n", ret);
			return -1;
		}
		return ret;
	}

	/*
	 * This is no longer a handle based call.
	 */
	ret = gpfswrap_set_winattrs_path(fsp->fsp_name->base_name,
					 GPFS_WINATTR_SET_CREATION_TIME,
					 &attrs);
	if (ret == -1 && errno != ENOSYS) {
		DBG_WARNING("Set GPFS ntimes failed %d\n", ret);
		return -1;
	}

	return 0;
}

static int vfs_gpfs_fallocate(struct vfs_handle_struct *handle,
			      struct files_struct *fsp, uint32_t mode,
			      off_t offset, off_t len)
{
	if (mode == (VFS_FALLOCATE_FL_PUNCH_HOLE|VFS_FALLOCATE_FL_KEEP_SIZE) &&
	    !fsp->fsp_flags.is_sparse &&
	    lp_strict_allocate(SNUM(fsp->conn))) {
		/*
		 * This is from a ZERO_DATA request on a non-sparse
		 * file. GPFS does not support FL_KEEP_SIZE and thus
		 * cannot fill the whole again in the subsequent
		 * fallocate(FL_KEEP_SIZE). Deny this FL_PUNCH_HOLE
		 * call to not end up with a hole in a non-sparse
		 * file.
		 */
		errno = ENOTSUP;
		return -1;
	}

	return SMB_VFS_NEXT_FALLOCATE(handle, fsp, mode, offset, len);
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

	result = gpfswrap_ftruncate(fsp_get_io_fd(fsp), len);
	if ((result == -1) && (errno == ENOSYS)) {
		return SMB_VFS_NEXT_FTRUNCATE(handle, fsp, len);
	}
	return result;
}

static bool vfs_gpfs_is_offline(struct vfs_handle_struct *handle,
				struct files_struct *fsp,
				SMB_STRUCT_STAT *sbuf)
{
	struct gpfs_winattr attrs;
	struct gpfs_config_data *config;
	int ret;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct gpfs_config_data,
				return false);

	if (!config->winattr) {
		return false;
	}

	ret = gpfswrap_get_winattrs(fsp_get_pathref_fd(fsp), &attrs);
	if (ret == -1) {
		return false;
	}

	if ((attrs.winAttrs & GPFS_WINATTR_OFFLINE) != 0) {
		DBG_DEBUG("%s is offline\n", fsp_str_dbg(fsp));
		return true;
	}

	DBG_DEBUG("%s is online\n", fsp_str_dbg(fsp));
	return false;
}

static bool vfs_gpfs_fsp_is_offline(struct vfs_handle_struct *handle,
				    struct files_struct *fsp)
{
	struct gpfs_fsp_extension *ext;

	ext = VFS_FETCH_FSP_EXTENSION(handle, fsp);
	if (ext == NULL) {
		/*
		 * Something bad happened, always ask.
		 */
		return vfs_gpfs_is_offline(handle, fsp,
					   &fsp->fsp_name->st);
	}

	if (ext->offline) {
		/*
		 * As long as it's offline, ask.
		 */
		ext->offline = vfs_gpfs_is_offline(handle, fsp,
						   &fsp->fsp_name->st);
	}

	return ext->offline;
}

static bool vfs_gpfs_aio_force(struct vfs_handle_struct *handle,
			       struct files_struct *fsp)
{
	return vfs_gpfs_fsp_is_offline(handle, fsp);
}

static ssize_t vfs_gpfs_sendfile(vfs_handle_struct *handle, int tofd,
				 files_struct *fsp, const DATA_BLOB *hdr,
				 off_t offset, size_t n)
{
	if (vfs_gpfs_fsp_is_offline(handle, fsp)) {
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
	bool check_fstype;

	ret = SMB_VFS_NEXT_CONNECT(handle, service, user);
	if (ret < 0) {
		return ret;
	}

	if (IS_IPC(handle->conn)) {
		return 0;
	}

	ret = gpfswrap_init();
	if (ret < 0) {
		DBG_ERR("Could not load GPFS library.\n");
		return ret;
	}

	ret = gpfswrap_lib_init(0);
	if (ret < 0) {
		DBG_ERR("Could not open GPFS device file: %s\n",
			strerror(errno));
		return ret;
	}

	ret = gpfswrap_register_cifs_export();
	if (ret < 0) {
		DBG_ERR("Failed to register with GPFS: %s\n", strerror(errno));
		return ret;
	}

	config = talloc_zero(handle->conn, struct gpfs_config_data);
	if (!config) {
		DEBUG(0, ("talloc_zero() failed\n"));
		errno = ENOMEM;
		return -1;
	}

	check_fstype = lp_parm_bool(SNUM(handle->conn), "gpfs",
				    "check_fstype", true);

	if (check_fstype) {
		const char *connectpath = handle->conn->connectpath;
		struct statfs buf = { 0 };

		ret = statfs(connectpath, &buf);
		if (ret != 0) {
			DBG_ERR("statfs failed for share %s at path %s: %s\n",
				service, connectpath, strerror(errno));
			TALLOC_FREE(config);
			return ret;
		}

		if (buf.f_type != GPFS_SUPER_MAGIC) {
			DBG_ERR("SMB share %s, path %s not in GPFS file system."
				" statfs magic: 0x%jx\n",
				service,
				connectpath,
				(uintmax_t)buf.f_type);
			errno = EINVAL;
			TALLOC_FREE(config);
			return -1;
		}
	}

	ret = smbacl4_get_vfs_params(handle->conn, &config->nfs4_params);
	if (ret < 0) {
		TALLOC_FREE(config);
		return ret;
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

	config->acl = lp_parm_bool(SNUM(handle->conn), "gpfs", "acl", true);

	config->settimes = lp_parm_bool(SNUM(handle->conn), "gpfs",
					"settimes", true);
	config->recalls = lp_parm_bool(SNUM(handle->conn), "gpfs",
				       "recalls", true);

	config->clamp_invalid_times = lp_parm_bool(SNUM(handle->conn), "gpfs",
				       "clamp_invalid_times", false);

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

	/*
	 * Unless we have an async implementation of get_dos_attributes turn
	 * this off.
	 */
	lp_do_parameter(SNUM(handle->conn), "smbd async dosmode", "false");

	return 0;
}

static int get_gpfs_quota(const char *pathname, int type, int id,
			  struct gpfs_quotaInfo *qi)
{
	int ret;

	ret = gpfswrap_quotactl(pathname, GPFS_QCMD(Q_GETQUOTA, type), id, qi);

	if (ret) {
		if (errno == GPFS_E_NO_QUOTA_INST) {
			DEBUG(10, ("Quotas disabled on GPFS filesystem.\n"));
		} else if (errno != ENOSYS) {
			DEBUG(0, ("Get quota failed, type %d, id, %d, "
				  "errno %d.\n", type, id, errno));
		}

		return ret;
	}

	DEBUG(10, ("quota type %d, id %d, blk u:%lld h:%lld s:%lld gt:%u\n",
		   type, id, qi->blockUsage, qi->blockHardLimit,
		   qi->blockSoftLimit, qi->blockGraceTime));

	return ret;
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

static uint64_t vfs_gpfs_disk_free(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				uint64_t *bsize,
				uint64_t *dfree,
				uint64_t *dsize)
{
	struct security_unix_token *utok;
	struct gpfs_quotaInfo qi_user = { 0 }, qi_group = { 0 };
	struct gpfs_config_data *config;
	int err;
	time_t cur_time;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct gpfs_config_data,
				return (uint64_t)-1);
	if (!config->dfreequota) {
		return SMB_VFS_NEXT_DISK_FREE(handle, smb_fname,
					      bsize, dfree, dsize);
	}

	err = sys_fsusage(smb_fname->base_name, dfree, dsize);
	if (err) {
		DEBUG (0, ("Could not get fs usage, errno %d\n", errno));
		return SMB_VFS_NEXT_DISK_FREE(handle, smb_fname,
					      bsize, dfree, dsize);
	}

	/* sys_fsusage returns units of 512 bytes */
	*bsize = 512;

	DEBUG(10, ("fs dfree %llu, dsize %llu\n",
		   (unsigned long long)*dfree, (unsigned long long)*dsize));

	utok = handle->conn->session_info->unix_token;

	err = get_gpfs_quota(smb_fname->base_name,
			GPFS_USRQUOTA, utok->uid, &qi_user);
	if (err) {
		return SMB_VFS_NEXT_DISK_FREE(handle, smb_fname,
					      bsize, dfree, dsize);
	}

	/*
	 * If new files created under this folder get this folder's
	 * GID, then available space is governed by the quota of the
	 * folder's GID, not the primary group of the creating user.
	 */
	if (VALID_STAT(smb_fname->st) &&
	    S_ISDIR(smb_fname->st.st_ex_mode) &&
	    smb_fname->st.st_ex_mode & S_ISGID) {
		become_root();
		err = get_gpfs_quota(smb_fname->base_name, GPFS_GRPQUOTA,
				     smb_fname->st.st_ex_gid, &qi_group);
		unbecome_root();

	} else {
		err = get_gpfs_quota(smb_fname->base_name, GPFS_GRPQUOTA,
				     utok->gid, &qi_group);
	}

	if (err) {
		return SMB_VFS_NEXT_DISK_FREE(handle, smb_fname,
					      bsize, dfree, dsize);
	}

	cur_time = time(NULL);

	/* Adjust free space and size according to quota limits. */
	vfs_gpfs_disk_free_quota(qi_user, cur_time, dfree, dsize);
	vfs_gpfs_disk_free_quota(qi_group, cur_time, dfree, dsize);

	return *dfree / 2;
}

static int vfs_gpfs_get_quota(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				enum SMB_QUOTA_TYPE qtype,
				unid_t id,
				SMB_DISK_QUOTA *dq)
{
	switch(qtype) {
		/*
		 * User/group quota are being used for disk-free
		 * determination, which in this module is done directly
		 * by the disk-free function. It's important that this
		 * module does not return wrong quota values by mistake,
		 * which would modify the correct values set by disk-free.
		 * User/group quota are also being used for processing
		 * NT_TRANSACT_GET_USER_QUOTA in smb1 protocol, which is
		 * currently not supported by this module.
		 */
		case SMB_USER_QUOTA_TYPE:
		case SMB_GROUP_QUOTA_TYPE:
			errno = ENOSYS;
			return -1;
		default:
			return SMB_VFS_NEXT_GET_QUOTA(handle, smb_fname,
					qtype, id, dq);
	}
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

static int vfs_gpfs_openat(struct vfs_handle_struct *handle,
			   const struct files_struct *dirfsp,
			   const struct smb_filename *smb_fname,
			   files_struct *fsp,
			   const struct vfs_open_how *_how)
{
	struct vfs_open_how how = *_how;
	struct gpfs_config_data *config = NULL;
	struct gpfs_fsp_extension *ext = NULL;
	int ret;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct gpfs_config_data,
				return -1);

	if (config->hsm && !config->recalls &&
	    !fsp->fsp_flags.is_pathref &&
	    vfs_gpfs_fsp_is_offline(handle, fsp))
	{
		DBG_DEBUG("Refusing access to offline file %s\n",
			  fsp_str_dbg(fsp));
		errno = EACCES;
		return -1;
	}

	if (config->syncio) {
		how.flags |= O_SYNC;
	}

	ext = VFS_ADD_FSP_EXTENSION(handle, fsp, struct gpfs_fsp_extension,
				    NULL);
	if (ext == NULL) {
		errno = ENOMEM;
		return -1;
	}

	/*
	 * Assume the file is offline until gpfs tells us it's online.
	 */
	*ext = (struct gpfs_fsp_extension) { .offline = true };

	ret = SMB_VFS_NEXT_OPENAT(handle, dirfsp, smb_fname, fsp, &how);
	if (ret == -1) {
		VFS_REMOVE_FSP_EXTENSION(handle, fsp);
	}
	return ret;
}

static ssize_t vfs_gpfs_pread(vfs_handle_struct *handle, files_struct *fsp,
			      void *data, size_t n, off_t offset)
{
	ssize_t ret;
	bool was_offline;

	was_offline = vfs_gpfs_fsp_is_offline(handle, fsp);

	ret = SMB_VFS_NEXT_PREAD(handle, fsp, data, n, offset);

	if ((ret != -1) && was_offline) {
		notify_fname(handle->conn,
			     NOTIFY_ACTION_MODIFIED |
			     NOTIFY_ACTION_DIRLEASE_BREAK,
			     FILE_NOTIFY_CHANGE_ATTRIBUTES,
			     fsp->fsp_name,
			     fsp_get_smb2_lease(fsp));
	}

	return ret;
}

struct vfs_gpfs_pread_state {
	struct files_struct *fsp;
	ssize_t ret;
	bool was_offline;
	struct vfs_aio_state vfs_aio_state;
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
	state->was_offline = vfs_gpfs_fsp_is_offline(handle, fsp);
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

	state->ret = SMB_VFS_PREAD_RECV(subreq, &state->vfs_aio_state);
	TALLOC_FREE(subreq);
	tevent_req_done(req);
}

static ssize_t vfs_gpfs_pread_recv(struct tevent_req *req,
				   struct vfs_aio_state *vfs_aio_state)
{
	struct vfs_gpfs_pread_state *state = tevent_req_data(
		req, struct vfs_gpfs_pread_state);
	struct files_struct *fsp = state->fsp;

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		return -1;
	}
	*vfs_aio_state = state->vfs_aio_state;

	if ((state->ret != -1) && state->was_offline) {
		DEBUG(10, ("sending notify\n"));
		notify_fname(fsp->conn,
			     NOTIFY_ACTION_MODIFIED |
			     NOTIFY_ACTION_DIRLEASE_BREAK,
			     FILE_NOTIFY_CHANGE_ATTRIBUTES,
			     fsp->fsp_name,
			     fsp_get_smb2_lease(fsp));
	}

	return state->ret;
}

static ssize_t vfs_gpfs_pwrite(vfs_handle_struct *handle, files_struct *fsp,
			       const void *data, size_t n, off_t offset)
{
	ssize_t ret;
	bool was_offline;

	was_offline = vfs_gpfs_fsp_is_offline(handle, fsp);

	ret = SMB_VFS_NEXT_PWRITE(handle, fsp, data, n, offset);

	if ((ret != -1) && was_offline) {
		notify_fname(handle->conn,
			     NOTIFY_ACTION_MODIFIED |
			     NOTIFY_ACTION_DIRLEASE_BREAK,
			     FILE_NOTIFY_CHANGE_ATTRIBUTES,
			     fsp->fsp_name,
			     fsp_get_smb2_lease(fsp));
	}

	return ret;
}

struct vfs_gpfs_pwrite_state {
	struct files_struct *fsp;
	ssize_t ret;
	bool was_offline;
	struct vfs_aio_state vfs_aio_state;
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
	state->was_offline = vfs_gpfs_fsp_is_offline(handle, fsp);
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

	state->ret = SMB_VFS_PWRITE_RECV(subreq, &state->vfs_aio_state);
	TALLOC_FREE(subreq);
	tevent_req_done(req);
}

static ssize_t vfs_gpfs_pwrite_recv(struct tevent_req *req,
				    struct vfs_aio_state *vfs_aio_state)
{
	struct vfs_gpfs_pwrite_state *state = tevent_req_data(
		req, struct vfs_gpfs_pwrite_state);
	struct files_struct *fsp = state->fsp;

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		return -1;
	}
	*vfs_aio_state = state->vfs_aio_state;

	if ((state->ret != -1) && state->was_offline) {
		DEBUG(10, ("sending notify\n"));
		notify_fname(fsp->conn,
			     NOTIFY_ACTION_MODIFIED |
			     NOTIFY_ACTION_DIRLEASE_BREAK,
			     FILE_NOTIFY_CHANGE_ATTRIBUTES,
			     fsp->fsp_name,
			     fsp_get_smb2_lease(fsp));
	}

	return state->ret;
}


static struct vfs_fn_pointers vfs_gpfs_fns = {
	.connect_fn = vfs_gpfs_connect,
	.disk_free_fn = vfs_gpfs_disk_free,
	.get_quota_fn = vfs_gpfs_get_quota,
	.fs_capabilities_fn = vfs_gpfs_capabilities,
	.filesystem_sharemode_fn = vfs_gpfs_filesystem_sharemode,
	.linux_setlease_fn = vfs_gpfs_setlease,
	.get_real_filename_at_fn = vfs_gpfs_get_real_filename_at,
	.get_dos_attributes_send_fn = vfs_not_implemented_get_dos_attributes_send,
	.get_dos_attributes_recv_fn = vfs_not_implemented_get_dos_attributes_recv,
	.fget_dos_attributes_fn = vfs_gpfs_fget_dos_attributes,
	.fset_dos_attributes_fn = vfs_gpfs_fset_dos_attributes,
	.fget_nt_acl_fn = gpfsacl_fget_nt_acl,
	.fset_nt_acl_fn = gpfsacl_fset_nt_acl,
	.sys_acl_get_fd_fn = gpfsacl_sys_acl_get_fd,
	.sys_acl_blob_get_fd_fn = gpfsacl_sys_acl_blob_get_fd,
	.sys_acl_set_fd_fn = gpfsacl_sys_acl_set_fd,
	.sys_acl_delete_def_fd_fn = gpfsacl_sys_acl_delete_def_fd,
	.fchmod_fn = vfs_gpfs_fchmod,
	.close_fn = vfs_gpfs_close,
	.stat_fn = nfs4_acl_stat,
	.fstat_fn = nfs4_acl_fstat,
	.lstat_fn = nfs4_acl_lstat,
	.fstatat_fn = nfs4_acl_fstatat,
	.fntimes_fn = vfs_gpfs_fntimes,
	.aio_force_fn = vfs_gpfs_aio_force,
	.sendfile_fn = vfs_gpfs_sendfile,
	.fallocate_fn = vfs_gpfs_fallocate,
	.openat_fn = vfs_gpfs_openat,
	.pread_fn = vfs_gpfs_pread,
	.pread_send_fn = vfs_gpfs_pread_send,
	.pread_recv_fn = vfs_gpfs_pread_recv,
	.pwrite_fn = vfs_gpfs_pwrite,
	.pwrite_send_fn = vfs_gpfs_pwrite_send,
	.pwrite_recv_fn = vfs_gpfs_pwrite_recv,
	.ftruncate_fn = vfs_gpfs_ftruncate
};

static_decl_vfs;
NTSTATUS vfs_gpfs_init(TALLOC_CTX *ctx)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "gpfs",
				&vfs_gpfs_fns);
}
