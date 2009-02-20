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
	struct ifs_createfile_flags cf_flags = CF_FLAGS_NONE;

	/* Setup security descriptor and get secinfo. */
	if (sd != NULL) {
		NTSTATUS status;

		secinfo = (get_sec_info(sd) & IFS_SEC_INFO_KNOWN_MASK);

		status = onefs_samba_sd_to_sd(secinfo, sd, &ifs_sd, SNUM(conn));

		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1, ("SD initialization failure: %s",
				  nt_errstr(status)));
			errno = EINVAL;
			goto out;
		}

		pifs_sd = &ifs_sd;
	}

	/* Stripping off private bits will be done for us. */
	onefs_oplock = onefs_samba_oplock_to_oplock(oplock_request);

	if (!lp_oplocks(SNUM(conn))) {
		SMB_ASSERT(onefs_oplock == OPLOCK_NONE);
	}

	/* Convert samba dos flags to UF_DOS_* attributes. */
	onefs_dos_attributes = dos_attributes_to_stat_dos_flags(dos_flags);

	/**
	 * Deal with kernel creating Default ACLs. (Isilon bug 47447.)
	 *
	 * 1) "nt acl support = no", default_acl = no
	 * 2) "inherit permissions = yes", default_acl = no
	 */
	if (lp_nt_acl_support(SNUM(conn)) && !lp_inherit_perms(SNUM(conn)))
		cf_flags = cf_flags_or(cf_flags, CF_FLAGS_DEFAULT_ACL);

	DEBUG(10,("onefs_sys_create_file: base_fd = %d, "
		  "open_access_mask = 0x%x, flags = 0x%x, mode = 0%o, "
		  "desired_oplock = %s, id = 0x%x, secinfo = 0x%x, sd = %p, "
		  "dos_attributes = 0x%x, path = %s, "
		  "default_acl=%s\n", base_fd,
		  (unsigned int)open_access_mask,
		  (unsigned int)flags,
		  (unsigned int)mode,
		  onefs_oplock_str(onefs_oplock),
		  (unsigned int)id,
		  (unsigned int)secinfo, sd,
		  (unsigned int)onefs_dos_attributes, path,
		  cf_flags_and_bool(cf_flags, CF_FLAGS_DEFAULT_ACL) ?
		      "true" : "false"));

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
	    cf_flags, &onefs_granted_oplock);

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

/**
 * Only talloc the spill buffer once (reallocing when necessary).
 */
static char *get_spill_buffer(size_t new_count)
{
	static int cur_count = 0;
	static char *spill_buffer = NULL;

	/* If a sufficiently sized buffer exists, just return. */
	if (new_count <= cur_count) {
		SMB_ASSERT(spill_buffer);
		return spill_buffer;
	}

	/* Allocate the first time. */
	if (cur_count == 0) {
		SMB_ASSERT(!spill_buffer);
		spill_buffer = talloc_array(NULL, char, new_count);
		if (spill_buffer) {
			cur_count = new_count;
		}
		return spill_buffer;
	}

	/* A buffer exists, but it's not big enough, so realloc. */
	SMB_ASSERT(spill_buffer);
	spill_buffer = talloc_realloc(NULL, spill_buffer, char, new_count);
	if (spill_buffer) {
		cur_count = new_count;
	}
	return spill_buffer;
}

/**
 * recvfile does zero-copy writes given an fd to write to, and a socket with
 * some data to write.  If recvfile read more than it was able to write, it
 * spills the data into a buffer.  After first reading any additional data
 * from the socket into the buffer, the spill buffer is then written with a
 * standard pwrite.
 */
ssize_t onefs_sys_recvfile(int fromfd, int tofd, SMB_OFF_T offset,
			   size_t count)
{
	char *spill_buffer = NULL;
	bool socket_drained = false;
	int ret;
	off_t total_rbytes = 0;
	off_t total_wbytes = 0;
	off_t rbytes;
	off_t wbytes;

	DEBUG(10,("onefs_recvfile: from = %d, to = %d, offset=%llu, count = "
		  "%lu\n", fromfd, tofd, offset, count));

	if (count == 0) {
		return 0;
	}

	/*
	 * Setup up a buffer for recvfile to spill data that has been read
	 * from the socket but not written.
	 */
	spill_buffer = get_spill_buffer(count);
	if (spill_buffer == NULL) {
		ret = -1;
		goto out;
	}

	/*
	 * Keep trying recvfile until:
	 *  - There is no data left to read on the socket, or
	 *  - bytes read != bytes written, or
	 *  - An error is returned that isn't EINTR/EAGAIN
	 */
	do {
		/* Keep track of bytes read/written for recvfile */
		rbytes = 0;
		wbytes = 0;

		DEBUG(10, ("calling recvfile loop, offset + total_wbytes = "
			   "%llu, count - total_rbytes = %llu\n",
			   offset + total_wbytes, count - total_rbytes));

		ret = recvfile(tofd, fromfd, offset + total_wbytes,
			       count - total_wbytes, &rbytes, &wbytes, 0,
			       spill_buffer);

		DEBUG(10, ("recvfile ret = %d, errno = %d, rbytes = %llu, "
			   "wbytes = %llu\n", ret, ret >= 0 ? 0 : errno,
			   rbytes, wbytes));

		/* Update our progress so far */
		total_rbytes += rbytes;
		total_wbytes += wbytes;

	} while ((count - total_rbytes) && (rbytes == wbytes) &&
		 (ret == -1 && (errno == EINTR || errno == EAGAIN)));

	DEBUG(10, ("total_rbytes = %llu, total_wbytes = %llu\n",
		   total_rbytes, total_wbytes));

	/* Log if recvfile didn't write everything it read. */
	if (total_rbytes != total_wbytes) {
		DEBUG(0, ("partial recvfile: total_rbytes=%llu but "
			  "total_wbytes=%llu, diff = %llu\n", total_rbytes,
			  total_wbytes, total_rbytes - total_wbytes));
		SMB_ASSERT(total_rbytes > total_wbytes);
	}

	/*
	 * If there is still data on the socket, read it off.
	 */
	while (total_rbytes < count) {

		DEBUG(0, ("shallow recvfile, reading %llu\n",
			  count - total_rbytes));

		/*
		 * Read the remaining data into the spill buffer.  recvfile
		 * may already have some data in the spill buffer, so start
		 * filling the buffer at total_rbytes - total_wbytes.
		 */
		ret = sys_read(fromfd,
			       spill_buffer + (total_rbytes - total_wbytes),
			       count - total_rbytes);

		if (ret == -1) {
			DEBUG(0, ("shallow recvfile read failed: %s\n",
				  strerror(errno)));
			/* Socket is dead, so treat as if it were drained. */
			socket_drained = true;
			goto out;
		}

		/* Data was read so update the rbytes */
		total_rbytes += ret;
	}

	if (total_rbytes != count) {
		smb_panic("Unread recvfile data still on the socket!");
	}

	/*
	 * Now write any spilled data + the extra data read off the socket.
	 */
	while (total_wbytes < count) {

		DEBUG(0, ("partial recvfile, writing %llu\n", count - total_wbytes));

		ret = sys_pwrite(tofd, spill_buffer, count - total_wbytes,
				 offset + total_wbytes);

		if (ret == -1) {
			DEBUG(0, ("partial recvfile write failed: %s\n",
				  strerror(errno)));
			goto out;
		}

		/* Data was written so update the wbytes */
		total_wbytes += ret;
	}

	/* Success! */
	ret = total_wbytes;

out:
	/* Make sure we always try to drain the socket. */
	if (!socket_drained && count - total_rbytes) {
		int saved_errno = errno;

		if (drain_socket(fromfd, count - total_rbytes) !=
		    count - total_rbytes) {
			/* Socket is dead! */
			DEBUG(0, ("drain socket failed: %d\n", errno));
		}
		errno = saved_errno;
	}

	return ret;
}
