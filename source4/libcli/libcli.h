/*
   Unix SMB/CIFS implementation.
   SMB parameters and setup
   Copyright (C) Andrew Tridgell 2004
   Copyright (C) James Myers 2003 <myersjj@samba.org>

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

#ifndef __LIBCLI_H__
#define __LIBCLI_H__

#include "librpc/gen_ndr/nbt.h"
#include "libcli/raw/libcliraw.h"

struct substitute_context;

/* 
   smbcli_state: internal state used in libcli library for single-threaded callers, 
   i.e. a single session on a single socket. 
 */
struct smbcli_state {
	struct smbcli_options options;
	struct smbcli_socket *sock; /* NULL if connected */
	struct smbcli_transport *transport;
	struct smbcli_session *session;
	struct smbcli_tree *tree;
	struct substitute_context *substitute;
	struct smblsa_state *lsa;
};

struct clilist_file_info {
	uint64_t size;
	uint16_t attrib;
	time_t mtime;
	const char *name;
	const char *short_name;
};

struct nbt_dc_name {
	const char *address;
	const char *name;
};

struct cli_credentials;
struct tevent_context;

/* passed to br lock code. */
enum brl_type {
	READ_LOCK,
	WRITE_LOCK,
	PENDING_READ_LOCK,
	PENDING_WRITE_LOCK
};

#include "libcli/raw/libcliraw.h"
struct gensec_settings;

ssize_t smbcli_read(struct smbcli_tree *tree, int fnum, void *_buf, off_t offset, size_t size);

/****************************************************************************
  write to a file
  write_mode: 0x0001 disallow write cacheing
              0x0002 return bytes remaining
              0x0004 use raw named pipe protocol
              0x0008 start of message mode named pipe protocol
****************************************************************************/
ssize_t smbcli_write(struct smbcli_tree *tree,
		     int fnum, uint16_t write_mode,
		     const void *_buf, off_t offset, size_t size);

/****************************************************************************
  write to a file using a SMBwrite and not bypassing 0 byte writes
****************************************************************************/
ssize_t smbcli_smbwrite(struct smbcli_tree *tree,
		     int fnum, const void *_buf, off_t offset, size_t size1);

bool smbcli_socket_connect(struct smbcli_state *cli, const char *server, 
			   const char **ports, 
			   struct tevent_context *ev_ctx,
			   struct resolve_context *resolve_ctx,
			   struct smbcli_options *options,
			   const char *socket_options,
			   struct nbt_name *calling,
			   struct nbt_name *called);
NTSTATUS smbcli_negprot(struct smbcli_state *cli, bool unicode, int maxprotocol);
NTSTATUS smbcli_session_setup(struct smbcli_state *cli, 
			      struct cli_credentials *credentials,
			      const char *workgroup,
			      struct smbcli_session_options options,
			      struct gensec_settings *gensec_settings);
NTSTATUS smbcli_tconX(struct smbcli_state *cli, const char *sharename, 
		      const char *devtype, const char *password);
NTSTATUS smbcli_full_connection(TALLOC_CTX *parent_ctx,
				struct smbcli_state **ret_cli, 
				const char *host,
				const char **ports,
				const char *sharename,
				const char *devtype,
				const char *socket_options,
				struct cli_credentials *credentials,
				struct resolve_context *resolve_ctx,
				struct tevent_context *ev,
				struct smbcli_options *options,
				struct smbcli_session_options *session_options,
				struct gensec_settings *gensec_settings);
NTSTATUS smbcli_tdis(struct smbcli_state *cli);

/****************************************************************************
 Initialise a client state structure.
****************************************************************************/
struct smbcli_state *smbcli_state_init(TALLOC_CTX *mem_ctx);
bool smbcli_parse_unc(const char *unc_name, TALLOC_CTX *mem_ctx,
		      char **hostname, char **sharename);

/****************************************************************************
 Symlink a file (UNIX extensions).
****************************************************************************/
NTSTATUS smbcli_unix_symlink(struct smbcli_tree *tree, const char *fname_src, 
			  const char *fname_dst);

/****************************************************************************
 Hard a file (UNIX extensions).
****************************************************************************/
NTSTATUS smbcli_unix_hardlink(struct smbcli_tree *tree, const char *fname_src, 
			   const char *fname_dst);

/****************************************************************************
 chmod a file (UNIX extensions).
****************************************************************************/
NTSTATUS smbcli_unix_chmod(struct smbcli_tree *tree, const char *fname, mode_t mode);

/****************************************************************************
 chown a file (UNIX extensions).
****************************************************************************/
NTSTATUS smbcli_unix_chown(struct smbcli_tree *tree, const char *fname, uid_t uid, 
			gid_t gid);

/****************************************************************************
 Rename a file.
****************************************************************************/
NTSTATUS smbcli_rename(struct smbcli_tree *tree, const char *fname_src, 
		    const char *fname_dst);

/****************************************************************************
 Delete a file.
****************************************************************************/
NTSTATUS smbcli_unlink(struct smbcli_tree *tree, const char *fname);

/****************************************************************************
 Create a directory.
****************************************************************************/
NTSTATUS smbcli_mkdir(struct smbcli_tree *tree, const char *dname);

/****************************************************************************
 Remove a directory.
****************************************************************************/
NTSTATUS smbcli_rmdir(struct smbcli_tree *tree, const char *dname);

/****************************************************************************
 Set or clear the delete on close flag.
****************************************************************************/
NTSTATUS smbcli_nt_delete_on_close(struct smbcli_tree *tree, int fnum, 
				   bool flag);

/****************************************************************************
 Create/open a file - exposing the full horror of the NT API :-).
 Used in CIFS-on-CIFS NTVFS.
****************************************************************************/
int smbcli_nt_create_full(struct smbcli_tree *tree, const char *fname,
		       uint32_t CreatFlags, uint32_t DesiredAccess,
		       uint32_t FileAttributes, uint32_t ShareAccess,
		       uint32_t CreateDisposition, uint32_t CreateOptions,
		       uint8_t SecurityFlags);

/****************************************************************************
 Open a file (using SMBopenx)
 WARNING: if you open with O_WRONLY then getattrE won't work!
****************************************************************************/
int smbcli_open(struct smbcli_tree *tree, const char *fname, int flags, 
	     int share_mode);

/****************************************************************************
 Close a file.
****************************************************************************/
NTSTATUS smbcli_close(struct smbcli_tree *tree, int fnum);

/****************************************************************************
 send a lock with a specified locktype 
 this is used for testing LOCKING_ANDX_CANCEL_LOCK
****************************************************************************/
NTSTATUS smbcli_locktype(struct smbcli_tree *tree, int fnum, 
		      uint32_t offset, uint32_t len, int timeout, 
		      uint8_t locktype);

/****************************************************************************
 Lock a file.
****************************************************************************/
NTSTATUS smbcli_lock(struct smbcli_tree *tree, int fnum, 
		  uint32_t offset, uint32_t len, int timeout, 
		  enum brl_type lock_type);

/****************************************************************************
 Unlock a file.
****************************************************************************/
NTSTATUS smbcli_unlock(struct smbcli_tree *tree, int fnum, uint32_t offset, uint32_t len);

/****************************************************************************
 Lock a file with 64 bit offsets.
****************************************************************************/
NTSTATUS smbcli_lock64(struct smbcli_tree *tree, int fnum, 
		    off_t offset, off_t len, int timeout, 
		    enum brl_type lock_type);

/****************************************************************************
 Unlock a file with 64 bit offsets.
****************************************************************************/
NTSTATUS smbcli_unlock64(struct smbcli_tree *tree, int fnum, off_t offset, 
			 off_t len);

/****************************************************************************
 Do a SMBgetattrE call.
****************************************************************************/
NTSTATUS smbcli_getattrE(struct smbcli_tree *tree, int fnum,
		      uint16_t *attr, size_t *size,
		      time_t *c_time, time_t *a_time, time_t *m_time);

/****************************************************************************
 Do a SMBgetatr call
****************************************************************************/
NTSTATUS smbcli_getatr(struct smbcli_tree *tree, const char *fname, 
		    uint16_t *attr, size_t *size, time_t *t);

/****************************************************************************
 Do a SMBsetatr call.
****************************************************************************/
NTSTATUS smbcli_setatr(struct smbcli_tree *tree, const char *fname, uint16_t mode, 
		    time_t t);

/****************************************************************************
 Do a setfileinfo basic_info call.
****************************************************************************/
NTSTATUS smbcli_fsetatr(struct smbcli_tree *tree, int fnum, uint16_t mode, 
			NTTIME create_time, NTTIME access_time, 
			NTTIME write_time, NTTIME change_time);

/****************************************************************************
 truncate a file to a given size
****************************************************************************/
NTSTATUS smbcli_ftruncate(struct smbcli_tree *tree, int fnum, uint64_t size);

/****************************************************************************
 Check for existence of a dir.
****************************************************************************/
NTSTATUS smbcli_chkpath(struct smbcli_tree *tree, const char *path);

/****************************************************************************
 Query disk space.
****************************************************************************/
NTSTATUS smbcli_dskattr(struct smbcli_tree *tree, uint32_t *bsize, 
			uint64_t *total, uint64_t *avail);

/****************************************************************************
 Create and open a temporary file.
****************************************************************************/
int smbcli_ctemp(struct smbcli_tree *tree, const char *path, char **tmp_path);

/****************************************************************************
 Interpret a long filename structure.
****************************************************************************/
int smbcli_list_new(struct smbcli_tree *tree, const char *Mask, uint16_t attribute, 
		    enum smb_search_data_level level,
		    void (*fn)(struct clilist_file_info *, const char *, void *), 
		    void *caller_state);

/****************************************************************************
 Interpret a short filename structure.
 The length of the structure is returned.
****************************************************************************/
int smbcli_list_old(struct smbcli_tree *tree, const char *Mask, uint16_t attribute, 
		 void (*fn)(struct clilist_file_info *, const char *, void *), 
		 void *caller_state);

/****************************************************************************
 Do a directory listing, calling fn on each file found.
 This auto-switches between old and new style.
****************************************************************************/
int smbcli_list(struct smbcli_tree *tree, const char *Mask,uint16_t attribute, 
		void (*fn)(struct clilist_file_info *, const char *, void *), void *state);

/****************************************************************************
send a qpathinfo call
****************************************************************************/
NTSTATUS smbcli_qpathinfo(struct smbcli_tree *tree, const char *fname, 
		       time_t *c_time, time_t *a_time, time_t *m_time, 
		       size_t *size, uint16_t *mode);

/****************************************************************************
send a qpathinfo call with the SMB_QUERY_FILE_ALL_INFO info level
****************************************************************************/
NTSTATUS smbcli_qpathinfo2(struct smbcli_tree *tree, const char *fname, 
			time_t *c_time, time_t *a_time, time_t *m_time, 
			time_t *w_time, size_t *size, uint16_t *mode,
			ino_t *ino);

/****************************************************************************
send a qfileinfo QUERY_FILE_NAME_INFO call
****************************************************************************/
NTSTATUS smbcli_qfilename(struct smbcli_tree *tree, int fnum, const char **name);

/****************************************************************************
send a qfileinfo call
****************************************************************************/
NTSTATUS smbcli_qfileinfo(struct smbcli_tree *tree, int fnum, 
		       uint16_t *mode, size_t *size,
		       time_t *c_time, time_t *a_time, time_t *m_time, 
		       time_t *w_time, ino_t *ino);

/****************************************************************************
send a qpathinfo SMB_QUERY_FILE_ALT_NAME_INFO call
****************************************************************************/
NTSTATUS smbcli_qpathinfo_alt_name(struct smbcli_tree *tree, const char *fname, 
				const char **alt_name);

/* The following definitions come from ../source4/libcli/climessage.c  */


/****************************************************************************
start a message sequence
****************************************************************************/
bool smbcli_message_start(struct smbcli_tree *tree, const char *host, const char *username, 
		       int *grp);

/****************************************************************************
send a message 
****************************************************************************/
bool smbcli_message_text(struct smbcli_tree *tree, char *msg, int len, int grp);

/****************************************************************************
end a message 
****************************************************************************/
bool smbcli_message_end(struct smbcli_tree *tree, int grp);

int smbcli_deltree(struct smbcli_tree *tree, const char *dname);

#endif /* __LIBCLI_H__ */
