/*
 * Unix SMB/CIFS implementation.
 * Support for OneFS system interfaces.
 *
 * Copyright (C) Tim Prouty, 2008
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

#include "onefs.h"

#include <ifs/ifs_syscalls.h>
#include <isi_acl/isi_acl_util.h>

/*
 * Initialize the sm_lock struct before passing it to ifs_createfile.
 */
static void smlock_init(connection_struct *conn, struct sm_lock *sml,
    bool isexe, uint32_t access_mask, uint32_t share_access,
    uint32_t create_options)
{
	sml->sm_type.doc = false;
	sml->sm_type.isexe = isexe;
	sml->sm_type.statonly = is_stat_open(access_mask);
	sml->sm_type.access_mask = access_mask;
	sml->sm_type.share_access = share_access;

	/*
	 * private_options was previously used for DENY_DOS/DENY_FCB checks in
	 * the kernel, but are now properly handled by fcb_or_dos_open. In
	 * these cases, ifs_createfile will return a sharing violation, which
	 * gives fcb_or_dos_open the chance to open a duplicate file handle.
	 */
	sml->sm_type.private_options = 0;

	/* 1 second delay is handled in onefs_open.c by deferring the open */
	sml->sm_timeout = timeval_set(0, 0);
}

static void smlock_dump(int debuglevel, const struct sm_lock *sml)
{
	if (sml == NULL) {
		DEBUG(debuglevel, ("sml == NULL\n"));
		return;
	}

	DEBUG(debuglevel,
	      ("smlock: doc=%s, isexec=%s, statonly=%s, access_mask=0x%x, "
	       "share_access=0x%x, private_options=0x%x timeout=%d/%d\n",
	       sml->sm_type.doc ? "True" : "False",
	       sml->sm_type.isexe ? "True" : "False",
	       sml->sm_type.statonly ? "True" : "False",
	       sml->sm_type.access_mask,
	       sml->sm_type.share_access,
	       sml->sm_type.private_options,
	       (int)sml->sm_timeout.tv_sec,
	       (int)sml->sm_timeout.tv_usec));
}

/*
 * Return string value of onefs oplock types.
 */
static const char *onefs_oplock_str(enum oplock_type onefs_oplock_type)
{
	switch (onefs_oplock_type) {
	case OPLOCK_NONE:
		return "OPLOCK_NONE";
	case OPLOCK_EXCLUSIVE:
		return "OPLOCK_EXCLUSIVE";
	case OPLOCK_BATCH:
		return "OPLOCK_BATCH";
	case OPLOCK_SHARED:
		return "OPLOCK_SHARED";
	default:
		break;
	}
	return "UNKNOWN";
}

/*
 * Convert from onefs to samba oplock.
 */
static int onefs_oplock_to_samba_oplock(enum oplock_type onefs_oplock)
{
	switch (onefs_oplock) {
	case OPLOCK_NONE:
		return NO_OPLOCK;
	case OPLOCK_EXCLUSIVE:
		return EXCLUSIVE_OPLOCK;
	case OPLOCK_BATCH:
		return BATCH_OPLOCK;
	case OPLOCK_SHARED:
		return LEVEL_II_OPLOCK;
	default:
		DEBUG(0, ("unknown oplock type %d found\n", onefs_oplock));
		break;
	}
	return NO_OPLOCK;
}

/*
 * Convert from samba to onefs oplock.
 */
static enum oplock_type onefs_samba_oplock_to_oplock(int samba_oplock_type)
{
	if (BATCH_OPLOCK_TYPE(samba_oplock_type)) return OPLOCK_BATCH;
	if (EXCLUSIVE_OPLOCK_TYPE(samba_oplock_type)) return OPLOCK_EXCLUSIVE;
	if (LEVEL_II_OPLOCK_TYPE(samba_oplock_type)) return OPLOCK_SHARED;
	return OPLOCK_NONE;
}

/**
 * External interface to ifs_createfile
 */
int onefs_sys_create_file(connection_struct *conn,
			  int base_fd,
			  const char *path,
		          uint32_t access_mask,
		          uint32_t open_access_mask,
			  uint32_t share_access,
			  uint32_t create_options,
			  int flags,
			  mode_t mode,
			  int oplock_request,
			  uint64_t id,
			  struct security_descriptor *sd,
			  uint32_t dos_flags,
			  int *granted_oplock)
{
	struct sm_lock sml, *psml = NULL;
	enum oplock_type onefs_oplock;
	enum oplock_type onefs_granted_oplock = OPLOCK_NONE;
	struct ifs_security_descriptor ifs_sd = {}, *pifs_sd = NULL;
	int secinfo = 0;
	int ret_fd = -1;
	uint32_t onefs_dos_attributes;

	/* Setup security descriptor and get secinfo. */
	if (sd != NULL) {
		NTSTATUS status;

		secinfo = (get_sec_info(sd) & IFS_SEC_INFO_KNOWN_MASK);

		status = onefs_samba_sd_to_sd(secinfo, sd, &ifs_sd);

		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1, ("SD initialization failure: %s",
				  nt_errstr(status)));
			errno = EINVAL;
			goto out;
		}

		pifs_sd = &ifs_sd;
	}

	onefs_oplock = onefs_samba_oplock_to_oplock(oplock_request);

	/* Temporary until oplock work is added to vfs_onefs */
	onefs_oplock = OPLOCK_NONE;

	/* Convert samba dos flags to UF_DOS_* attributes. */
	onefs_dos_attributes = dos_attributes_to_stat_dos_flags(dos_flags);

	DEBUG(10,("onefs_sys_create_file: base_fd = %d, "
		  "open_access_mask = 0x%x, flags = 0x%x, mode = 0x%x, "
		  "desired_oplock = %s, id = 0x%x, secinfo = 0x%x, sd = %p, "
		  "dos_attributes = 0x%x, path = %s\n", base_fd,
		  (unsigned int)open_access_mask,
		  (unsigned int)flags,
		  (unsigned int)mode,
		  onefs_oplock_str(onefs_oplock),
		  (unsigned int)id,
		  (unsigned int)secinfo, sd,
		  (unsigned int)onefs_dos_attributes, path));

	/* Initialize smlock struct for files/dirs but not internal opens */
	if (!(oplock_request & INTERNAL_OPEN_ONLY)) {
		smlock_init(conn, &sml, is_executable(path), access_mask,
		    share_access, create_options);
		psml = &sml;
	}

	smlock_dump(10, psml);

	ret_fd = ifs_createfile(base_fd, path,
	    (enum ifs_ace_rights)open_access_mask, flags & ~O_ACCMODE, mode,
	    onefs_oplock, id, psml, secinfo, pifs_sd, onefs_dos_attributes,
	    &onefs_granted_oplock);

	DEBUG(10,("onefs_sys_create_file(%s): ret_fd = %d, "
		  "onefs_granted_oplock = %s\n",
		  ret_fd < 0 ? strerror(errno) : "success", ret_fd,
		  onefs_oplock_str(onefs_granted_oplock)));

	if (granted_oplock) {
		*granted_oplock =
		    onefs_oplock_to_samba_oplock(onefs_granted_oplock);
	}

 out:
	aclu_free_sd(pifs_sd, false);

	return ret_fd;
}
