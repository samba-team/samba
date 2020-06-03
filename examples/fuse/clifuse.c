/*
 * Unix SMB/CIFS implementation.
 * fusermount smb2 client
 * Copyright (C) Volker Lendecke 2016
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#define FUSE_USE_VERSION 26
#define _FILE_OFFSET_BITS 64
#include "fuse/fuse_lowlevel.h"

#include "source3/include/includes.h"
#include "client.h"
#include "trans2.h"
#include "libsmb/proto.h"
#include "libsmb/clirap.h"
#include "libsmb/cli_smb2_fnum.h"
#include "lib/util/tevent_ntstatus.h"
#include "libcli/smb/smbXcli_base.h"
#include "libcli/security/security.h"
#include "clifuse.h"

struct mount_state {
	struct tevent_context *ev;
	struct cli_state *cli;
	bool done;

	struct tevent_fd *fde;
	struct tevent_signal *signal_ev;

	struct fuse_chan *ch;
	struct fuse_session *se;

	size_t bufsize;
	char *buf;

	struct idr_context *ino_ctx;
	TALLOC_CTX *ino_parent;
};

struct inode_state {
	struct idr_context *ino_ctx;
	fuse_ino_t ino;
	char path[1];
};

static int inode_state_destructor(struct inode_state *s);

static struct inode_state *inode_state_init(TALLOC_CTX *mem_ctx,
					    struct idr_context *ino_ctx,
					    const char *path)
{
	struct inode_state *state;
	size_t pathlen;
	int ino;

	pathlen = strlen(path);
	state = talloc_size(
		mem_ctx, offsetof(struct inode_state, path) + pathlen + 1);
	if (state == NULL) {
		return NULL;
	}
	talloc_set_name_const(state, "struct inode_state");

	ino = idr_get_new_above(ino_ctx, state, 1, INT32_MAX);
	if (ino == -1) {
		TALLOC_FREE(state);
		return NULL;
	}

	state->ino = ino;
	state->ino_ctx = ino_ctx;
	memcpy(state->path, path, pathlen + 1);

	DBG_DEBUG("Creating ino %d for path %s\n", ino, path);

	talloc_set_destructor(state, inode_state_destructor);

	return state;
}

static struct inode_state *inode_state_new(struct mount_state *mstate,
					   const char *path)
{
	return inode_state_init(mstate->ino_parent, mstate->ino_ctx, path);
}

static int inode_state_destructor(struct inode_state *s)
{
	DBG_DEBUG("destroying inode %ju\n", (uintmax_t)s->ino);
	idr_remove(s->ino_ctx, s->ino);
	return 0;
}

struct ll_create_state {
	struct mount_state *mstate;
	fuse_req_t freq;
	struct fuse_file_info fi;
	char *path;
};

static void cli_ll_create_done(struct tevent_req *req);

static void cli_ll_create(fuse_req_t freq, fuse_ino_t parent, const char *name,
			  mode_t mode, struct fuse_file_info *fi)
{
	struct mount_state *mstate = talloc_get_type_abort(
		fuse_req_userdata(freq), struct mount_state);
	struct ll_create_state *state;
	struct inode_state *istate;
	struct tevent_req *req;

	DBG_DEBUG("parent=%ju, name=%s, mode=%x\n", (uintmax_t)parent,
		  name, (unsigned)mode);

	istate = idr_find(mstate->ino_ctx, parent);
	if (istate == NULL) {
		fuse_reply_err(freq, ENOENT);
		return;
	}

	state = talloc(mstate, struct ll_create_state);
	if (state == NULL) {
		fuse_reply_err(freq, ENOMEM);
		return;
	}
	state->mstate = mstate;
	state->freq = freq;
	state->fi = *fi;

	state->path = talloc_asprintf(state, "%s%s%s", istate->path,
				      strlen(istate->path) ? "\\": "",
				      name);
	if (state->path == NULL) {
		TALLOC_FREE(state);
		fuse_reply_err(freq, ENOMEM);
		return;
	}

	req = cli_smb2_create_fnum_send(
		state,
		mstate->ev,
		mstate->cli, state->path,
		0,
		SMB2_IMPERSONATION_IMPERSONATION,
		FILE_GENERIC_READ|FILE_GENERIC_WRITE,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
		FILE_CREATE,
		FILE_NON_DIRECTORY_FILE,
		NULL);
	if (req == NULL) {
		TALLOC_FREE(state);
		fuse_reply_err(freq, ENOMEM);
		return;
	}
	tevent_req_set_callback(req, cli_ll_create_done, state);
}

static void cli_ll_create_done(struct tevent_req *req)
{
	struct ll_create_state *state = tevent_req_callback_data(
		req, struct ll_create_state);
	struct fuse_entry_param e;
	struct inode_state *ino;
	uint16_t fnum;
	NTSTATUS status;

	status = cli_smb2_create_fnum_recv(req, &fnum, NULL, NULL, NULL);
	TALLOC_FREE(req);
	if (!NT_STATUS_IS_OK(status)) {
		fuse_reply_err(state->freq, map_errno_from_nt_status(status));
		return;
	}

	state->fi.fh = fnum;
	state->fi.direct_io = 0;
	state->fi.keep_cache = 0;

	ino = inode_state_new(state->mstate, state->path);
	if (ino == NULL) {
		fuse_reply_err(state->freq, ENOMEM);
		return;
	}

	e = (struct fuse_entry_param) {
		.ino = ino->ino,
		.generation = 1, /* FIXME */
		.attr_timeout = 1.0,
		.entry_timeout = 1.0
	};

	fuse_reply_create(state->freq, &e, &state->fi);

	TALLOC_FREE(state);
}

struct cli_get_unixattr_state {
	struct tevent_context *ev;
	struct cli_state *cli;
	uint64_t fid_persistent;
	uint64_t fid_volatile;

	struct timespec create_time;
	struct timespec access_time;
	struct timespec write_time;
	struct timespec change_time;
	uint32_t mode;
	uint64_t ino;
	uint64_t size;
};

static void cli_get_unixattr_opened(struct tevent_req *subreq);
static void cli_get_unixattr_gotinfo(struct tevent_req *subreq);
static void cli_get_unixattr_closed(struct tevent_req *subreq);


static struct tevent_req *cli_get_unixattr_send(TALLOC_CTX *mem_ctx,
						struct tevent_context *ev,
						struct cli_state *cli,
						const char *path)
{
	struct tevent_req *req, *subreq;
	struct cli_get_unixattr_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct cli_get_unixattr_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->cli = cli;

	subreq = smb2cli_create_send(
		state, ev, cli->conn, cli->timeout, cli->smb2.session,
		cli->smb2.tcon,	path, SMB2_OPLOCK_LEVEL_NONE,
		SMB2_IMPERSONATION_IMPERSONATION,
		SYNCHRONIZE_ACCESS|FILE_READ_ATTRIBUTES, 0,
		FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
		FILE_OPEN, 0, NULL);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_get_unixattr_opened, req);

	return req;
}

static void cli_get_unixattr_opened(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_get_unixattr_state *state = tevent_req_data(
		req, struct cli_get_unixattr_state);
	struct cli_state *cli = state->cli;
	NTSTATUS status;

	status = smb2cli_create_recv(subreq, &state->fid_persistent,
				     &state->fid_volatile, NULL, NULL, NULL);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		DBG_DEBUG("smb2cli_create_recv returned %s\n",
			  nt_errstr(status));
		return;
	}

	subreq = smb2cli_query_info_send(
		state, state->ev, cli->conn, 0,
		cli->smb2.session, cli->smb2.tcon,
		1, /* in_info_type */
		(SMB_FILE_ALL_INFORMATION - 1000), /* in_file_info_class */
		0xFFFF, /* in_max_output_length */
		NULL, /* in_input_buffer */
		0, /* in_additional_info */
		0, /* in_flags */
		state->fid_persistent,
		state->fid_volatile);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, cli_get_unixattr_gotinfo, req);
}

static void cli_get_unixattr_gotinfo(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_get_unixattr_state *state = tevent_req_data(
		req, struct cli_get_unixattr_state);
	struct cli_state *cli = state->cli;
	NTSTATUS status;
	DATA_BLOB outbuf;

	status = smb2cli_query_info_recv(subreq, state, &outbuf);
        TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		DBG_DEBUG("smb2cli_query_info_recv returned %s\n",
			  nt_errstr(status));
		return;
	}

	if (outbuf.length < 0x60) {
		tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
		return;
	}

	state->create_time = interpret_long_date((char *)outbuf.data + 0x0);
	state->access_time = interpret_long_date((char *)outbuf.data + 0x8);
	state->write_time  = interpret_long_date((char *)outbuf.data + 0x10);
	state->change_time = interpret_long_date((char *)outbuf.data + 0x18);
	state->mode        = IVAL(outbuf.data, 0x20);
	state->size        = BVAL(outbuf.data, 0x30);
	state->ino         = BVAL(outbuf.data, 0x40);

	subreq = smb2cli_close_send(state, state->ev, cli->conn, 0,
				    cli->smb2.session, cli->smb2.tcon, 0,
				    state->fid_persistent,
				    state->fid_volatile);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, cli_get_unixattr_closed, req);
}

static void cli_get_unixattr_closed(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	NTSTATUS status;

	status = smb2cli_close_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	tevent_req_done(req);
}

static NTSTATUS cli_get_unixattr_recv(struct tevent_req *req,
				      struct stat *st)
{
	struct cli_get_unixattr_state *state = tevent_req_data(
		req, struct cli_get_unixattr_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}

	if (IS_DOS_DIR(state->mode)) {
		st->st_mode = (S_IFDIR | 0555);
		st->st_nlink = 2;
	} else {
		st->st_mode = (S_IFREG | 0444);
		st->st_nlink = 1;
	}

	st->st_size = state->size;
	st->st_uid = getuid();
	st->st_gid = getgid();
	st->st_ino = state->ino;
	st->st_atime = convert_timespec_to_time_t(state->access_time);
	st->st_ctime = convert_timespec_to_time_t(state->change_time);
	st->st_mtime = convert_timespec_to_time_t(state->write_time);

	return NT_STATUS_OK;
}

struct cli_smb2_listdir_state {
	struct tevent_context *ev;
	struct smbXcli_conn *conn;
	uint32_t timeout_msec;
	struct smbXcli_session *session;
	struct smbXcli_tcon *tcon;
	uint8_t level;
	uint8_t flags;
	uint32_t file_index;
	uint64_t fid_persistent;
	uint64_t fid_volatile;
	const char *mask;
	uint32_t outbuf_len;

	uint16_t attribute;
	const char *mntpoint;
	const char *pathname;
	NTSTATUS (*fn)(const char *mntpoint, struct file_info *f,
		       const char *mask, void *private_data);
	void *private_data;
	bool processed_file;
};

static void cli_smb2_listdir_done(struct tevent_req *subreq);

static struct tevent_req *cli_smb2_listdir_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct smbXcli_conn *conn,
	uint32_t timeout_msec,
	struct smbXcli_session *session,
	struct smbXcli_tcon *tcon,
	uint8_t level,
	uint8_t flags,
	uint32_t file_index,
	uint64_t fid_persistent,
	uint64_t fid_volatile,
	const char *mask,
	uint32_t outbuf_len,
	uint16_t attribute,
	const char *mntpoint,
	const char *pathname,
	NTSTATUS (*fn)(const char *mntpoint, struct file_info *f,
		       const char *mask, void *private_data),
	void *private_data)
{
	struct tevent_req *req, *subreq;
	struct cli_smb2_listdir_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct cli_smb2_listdir_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->conn = conn;
	state->timeout_msec = timeout_msec;
	state->session = session;
	state->tcon = tcon;
	state->level = level;
	state->flags = flags;
	state->file_index = file_index;
	state->fid_persistent = fid_persistent;
	state->fid_volatile = fid_volatile;
	state->mask = mask;
	state->outbuf_len = outbuf_len;
	state->attribute = attribute;
	state->mntpoint = mntpoint;
	state->pathname = pathname;
	state->fn = fn;
	state->private_data = private_data;

	subreq = smb2cli_query_directory_send(
		state, state->ev, state->conn, state->timeout_msec,
		state->session, state->tcon, state->level,
		state->flags, state->file_index,
		state->fid_persistent, state->fid_volatile,
		state->mask, state->outbuf_len);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_smb2_listdir_done, req);
	return req;
}

static NTSTATUS parse_finfo_id_both_directory_info(uint8_t *dir_data,
				uint32_t dir_data_length,
				struct file_info *finfo,
				uint32_t *next_offset)
{
	size_t namelen = 0;
	size_t slen = 0;
	size_t ret = 0;

	if (dir_data_length < 4) {
		return NT_STATUS_INFO_LENGTH_MISMATCH;
	}

	*next_offset = IVAL(dir_data, 0);

	if (*next_offset > dir_data_length) {
		return NT_STATUS_INFO_LENGTH_MISMATCH;
	}

	if (*next_offset != 0) {
		/* Ensure we only read what in this record. */
		dir_data_length = *next_offset;
	}

	if (dir_data_length < 105) {
		return NT_STATUS_INFO_LENGTH_MISMATCH;
	}

	finfo->btime_ts = interpret_long_date((const char *)dir_data + 8);
	finfo->atime_ts = interpret_long_date((const char *)dir_data + 16);
	finfo->mtime_ts = interpret_long_date((const char *)dir_data + 24);
	finfo->ctime_ts = interpret_long_date((const char *)dir_data + 32);
	finfo->size = IVAL2_TO_SMB_BIG_UINT(dir_data + 40, 0);
	finfo->attr = IVAL(dir_data + 56, 0);
	namelen = IVAL(dir_data + 60,0);
	if (namelen > (dir_data_length - 104)) {
		return NT_STATUS_INFO_LENGTH_MISMATCH;
	}
	slen = CVAL(dir_data + 68, 0);
	if (slen > 24) {
		return NT_STATUS_INFO_LENGTH_MISMATCH;
	}
	ret = pull_string_talloc(finfo,
				dir_data,
				FLAGS2_UNICODE_STRINGS,
				&finfo->short_name,
				dir_data + 70,
				slen,
				STR_UNICODE);
	if (ret == (size_t)-1) {
		/* Bad conversion. */
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	ret = pull_string_talloc(finfo,
				dir_data,
				FLAGS2_UNICODE_STRINGS,
				&finfo->name,
				dir_data + 104,
				namelen,
				STR_UNICODE);
	if (ret == (size_t)-1) {
		/* Bad conversion. */
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}
	return NT_STATUS_OK;
}

static void cli_smb2_listdir_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_smb2_listdir_state *state = tevent_req_data(
		req, struct cli_smb2_listdir_state);
	uint8_t *data;
	uint32_t data_len;
	uint32_t next_offset = 0;
	NTSTATUS status;

	status = smb2cli_query_directory_recv(subreq, state, &data,
					      &data_len);
	TALLOC_FREE(subreq);
	if (NT_STATUS_EQUAL(status, STATUS_NO_MORE_FILES)) {
		tevent_req_done(req);
		return;
	}
	if (tevent_req_nterror(req, status)) {
		return;
	}

	do {
		struct file_info *finfo;
		bool ok;

		finfo = talloc_zero(state, struct file_info);
		if (tevent_req_nomem(finfo, req)) {
			return;
		}

		status = parse_finfo_id_both_directory_info(
			data, data_len, finfo, &next_offset);

		DEBUG(10, ("%s: parse_finfo_id_both_directory_info returned "
			   "%s\n", __func__, nt_errstr(status)));

		if (tevent_req_nterror(req, status)) {
			return;
		}

		ok = dir_check_ftype(finfo->attr, state->attribute);

		DEBUG(10, ("%s: dir_check_ftype(%u,%u) returned %u\n",
			   __func__, (unsigned)finfo->attr,
			   (unsigned)state->attribute, (unsigned)ok));

		if (ok) {
			/*
			 * Only process if attributes match. On SMB1 server
			 * does this, so on SMB2 we need to emulate in the
			 * client.
			 *
			 * https://bugzilla.samba.org/show_bug.cgi?id=10260
			 */
			state->processed_file = true;

			status = state->fn(state->mntpoint, finfo,
					   state->pathname,
					   state->private_data);
			if (tevent_req_nterror(req, status)) {
				return;
			}
		}

		TALLOC_FREE(finfo);

		if (next_offset != 0) {
			data += next_offset;
			data_len -= next_offset;
		}
	} while (next_offset != 0);

	subreq = smb2cli_query_directory_send(
		state, state->ev, state->conn, state->timeout_msec,
		state->session, state->tcon, state->level,
		state->flags, state->file_index,
		state->fid_persistent, state->fid_volatile,
		state->mask, state->outbuf_len);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, cli_smb2_listdir_done, req);
}

static NTSTATUS cli_smb2_listdir_recv(struct tevent_req *req)
{
	struct cli_smb2_listdir_state *state = tevent_req_data(
		req, struct cli_smb2_listdir_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}

	if (!state->processed_file) {
		/*
		 * In SMB1 findfirst returns NT_STATUS_NO_SUCH_FILE
		 * if no files match. Emulate this in the client.
		 */
		return NT_STATUS_NO_SUCH_FILE;
	}

	return NT_STATUS_OK;
}

struct ll_lookup_state {
	struct mount_state *mstate;
	fuse_req_t freq;
	char *path;
};

static void cli_ll_lookup_done(struct tevent_req *req);

static void cli_ll_lookup(fuse_req_t freq, fuse_ino_t parent_ino,
			  const char *name)
{
	struct mount_state *mstate = talloc_get_type_abort(
		fuse_req_userdata(freq), struct mount_state);
	struct ll_lookup_state *state;
	struct tevent_req *req;
	struct inode_state *parent;

	DBG_DEBUG("parent_ino=%ju, name=%s\n", (uintmax_t)parent_ino, name);

	parent = idr_find(mstate->ino_ctx, parent_ino);
	if (parent == NULL) {
		DBG_WARNING("could not find parent\n");
		fuse_reply_err(freq, ENOENT);
		return;
	}

	state = talloc(mstate, struct ll_lookup_state);
	if (state == NULL) {
		DBG_WARNING("talloc failed\n");
		fuse_reply_err(freq, ENOMEM);
		return;
	}
	state->mstate = mstate;
	state->freq = freq;

	state->path = talloc_asprintf(state, "%s%s%s", parent->path,
				      strlen(parent->path) ? "\\": "",
				      name);
	if (state->path == NULL) {
		TALLOC_FREE(state);
		fuse_reply_err(freq, ENOMEM);
		return;
	}

	req = cli_get_unixattr_send(state, mstate->ev, mstate->cli,
				    state->path);
	if (req == NULL) {
		TALLOC_FREE(state);
		fuse_reply_err(freq, ENOMEM);
		return;
	}
	tevent_req_set_callback(req, cli_ll_lookup_done, state);
}

static void cli_ll_lookup_done(struct tevent_req *req)
{
	struct ll_lookup_state *state = tevent_req_callback_data(
		req, struct ll_lookup_state);
	struct stat sbuf = {0};
	struct fuse_entry_param e;
	struct inode_state *ino;
	NTSTATUS status;

	status = cli_get_unixattr_recv(req, &sbuf);
	TALLOC_FREE(req);
	if (!NT_STATUS_IS_OK(status)) {
		fuse_reply_err(state->freq, map_errno_from_nt_status(status));
		return;
	}

	ino = inode_state_new(state->mstate, state->path);
	if (ino == NULL) {
		fuse_reply_err(state->freq, ENOMEM);
		return;
	}

	e = (struct fuse_entry_param) {
		.ino = ino->ino,
		.attr = sbuf,
		.generation = 1, /* FIXME */
		.attr_timeout = 1.0,
		.entry_timeout = 1.0
	};

	fuse_reply_entry(state->freq, &e);
	TALLOC_FREE(state);
}

struct ll_getattr_state {
	struct mount_state *mstate;
	fuse_req_t freq;
	struct fuse_file_info fi;
};

static void cli_ll_getattr_done(struct tevent_req *req);

static void cli_ll_getattr(fuse_req_t freq, fuse_ino_t ino,
			   struct fuse_file_info *fi)
{
	struct mount_state *mstate = talloc_get_type_abort(
		fuse_req_userdata(freq), struct mount_state);
	struct ll_getattr_state *state;
	struct inode_state *istate;
	struct tevent_req *req;

	DBG_DEBUG("ino=%ju\n", (uintmax_t)ino);

	istate = idr_find(mstate->ino_ctx, ino);
	if (istate == NULL) {
		fuse_reply_err(freq, ENOENT);
		return;
	}

	state = talloc(mstate, struct ll_getattr_state);
	if (state == NULL) {
		fuse_reply_err(freq, ENOMEM);
		return;
	}
	state->mstate = mstate;
	state->freq = freq;

	req = cli_get_unixattr_send(state, mstate->ev, mstate->cli,
				    istate->path);
	if (req == NULL) {
		TALLOC_FREE(state);
		fuse_reply_err(freq, ENOMEM);
		return;
	}
	tevent_req_set_callback(req, cli_ll_getattr_done, state);
}

static void cli_ll_getattr_done(struct tevent_req *req)
{
	struct ll_getattr_state *state = tevent_req_callback_data(
		req, struct ll_getattr_state);
	struct stat st;
	NTSTATUS status;
	int ret;

	status = cli_get_unixattr_recv(req, &st);
	TALLOC_FREE(req);
	if (!NT_STATUS_IS_OK(status)) {
		fuse_reply_err(state->freq, map_errno_from_nt_status(status));
		return;
	}

	ret = fuse_reply_attr(state->freq, &st, 1);
	if (ret != 0) {
		DBG_NOTICE("fuse_reply_attr failed: %s\n",
			   strerror(-errno));
	}
}


struct ll_open_state {
	struct mount_state *mstate;
	fuse_req_t freq;
	struct fuse_file_info fi;
};

static void cli_ll_open_done(struct tevent_req *req);

static void cli_ll_open(fuse_req_t freq, fuse_ino_t ino,
			struct fuse_file_info *fi)
{
	struct mount_state *mstate = talloc_get_type_abort(
		fuse_req_userdata(freq), struct mount_state);
	struct ll_open_state *state;
	struct inode_state *istate;
	struct tevent_req *req;
	uint32_t acc;

	DBG_DEBUG("ino=%ju\n", (uintmax_t)ino);

	istate = idr_find(mstate->ino_ctx, ino);
	if (istate == NULL) {
		fuse_reply_err(freq, ENOENT);
		return;
	}

	state = talloc(mstate, struct ll_open_state);
	if (state == NULL) {
		fuse_reply_err(freq, ENOMEM);
		return;
	}
	state->mstate = mstate;
	state->freq = freq;
	state->fi = *fi;

	switch (fi->flags & O_ACCMODE) {
	case O_RDONLY:
		acc = FILE_GENERIC_READ;
		break;
	case O_WRONLY:
		acc = FILE_GENERIC_WRITE;
		break;
	case O_RDWR:
		acc = FILE_GENERIC_READ|FILE_GENERIC_WRITE;
		break;
	default:
		fuse_reply_err(freq, EACCES);
		return;
	}

	req = cli_smb2_create_fnum_send(
		state,
		mstate->ev,
		mstate->cli,
		istate->path,
		0,
		SMB2_IMPERSONATION_IMPERSONATION,
		acc,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
		FILE_OPEN,
		FILE_NON_DIRECTORY_FILE,
		NULL);
	if (req == NULL) {
		TALLOC_FREE(state);
		fuse_reply_err(freq, ENOMEM);
		return;
	}
	tevent_req_set_callback(req, cli_ll_open_done, state);
}

static void cli_ll_open_done(struct tevent_req *req)
{
	struct ll_open_state *state = tevent_req_callback_data(
		req, struct ll_open_state);
	uint16_t fnum;
	NTSTATUS status;

	status = cli_smb2_create_fnum_recv(req, &fnum, NULL, NULL, NULL);
	TALLOC_FREE(req);
	if (!NT_STATUS_IS_OK(status)) {
		fuse_reply_err(state->freq, map_errno_from_nt_status(status));
		return;
	}

	state->fi.fh = fnum;
	state->fi.direct_io = 0;
	state->fi.keep_cache = 0;

	fuse_reply_open(state->freq, &state->fi);

	TALLOC_FREE(state);
}

struct ll_release_state {
	struct mount_state *mstate;
	fuse_req_t freq;
	fuse_ino_t ino;
};

static void cli_ll_release_done(struct tevent_req *req);

static void cli_ll_release(fuse_req_t freq, fuse_ino_t ino,
			   struct fuse_file_info *fi)
{
	struct mount_state *mstate = talloc_get_type_abort(
		fuse_req_userdata(freq), struct mount_state);
	struct ll_release_state *state;
	struct inode_state *istate;
	struct tevent_req *req;
	uint16_t fnum;

	DBG_DEBUG("ino=%ju\n", (uintmax_t)ino);

	istate = idr_find(mstate->ino_ctx, ino);
	if (istate == NULL) {
		fuse_reply_err(freq, ENOENT);
		return;
	}

	state = talloc(mstate, struct ll_release_state);
	if (state == NULL) {
		fuse_reply_err(freq, ENOMEM);
		return;
	}
	state->mstate = mstate;
	state->freq = freq;
	state->ino = ino;

	fnum = fi->fh;

	req = cli_smb2_close_fnum_send(state, mstate->ev, mstate->cli, fnum);
	if (req == NULL) {
		TALLOC_FREE(state);
		fuse_reply_err(freq, ENOMEM);
		return;
	}
	tevent_req_set_callback(req, cli_ll_release_done, state);
}

static void cli_ll_release_done(struct tevent_req *req)
{
	struct ll_release_state *state = tevent_req_callback_data(
		req, struct ll_release_state);
	struct inode_state *istate;
	NTSTATUS status;

	status = cli_smb2_close_fnum_recv(req);
	TALLOC_FREE(req);
	if (!NT_STATUS_IS_OK(status)) {
		fuse_reply_err(state->freq, map_errno_from_nt_status(status));
		return;
	}

	istate = idr_find(state->mstate->ino_ctx, state->ino);
	if (istate == NULL) {
		DEBUG(1, ("%s: inode %ju vanished!\n", __func__,
			  (uintmax_t)state->ino));
	}
	TALLOC_FREE(istate);

	fuse_reply_err(state->freq, 0);
	TALLOC_FREE(state);
}

struct ll_read_state {
	struct mount_state *mstate;
	fuse_req_t freq;
};

static void cli_ll_read_done(struct tevent_req *req);

static void cli_ll_read(fuse_req_t freq, fuse_ino_t ino,
			size_t size, off_t off,
			struct fuse_file_info *fi)
{
	struct mount_state *mstate = talloc_get_type_abort(
		fuse_req_userdata(freq), struct mount_state);
	struct ll_read_state *state;
	struct tevent_req *req;
	uint16_t fnum;

	DBG_DEBUG("ino=%ju, size=%zu, off=%ju\n", (uintmax_t)ino,
		  size, (uintmax_t)off);

	state = talloc(mstate, struct ll_read_state);
	if (state == NULL) {
		fuse_reply_err(freq, ENOMEM);
		return;
	}
	state->mstate = mstate;
	state->freq = freq;

	fnum = fi->fh;

	req = cli_smb2_read_send(state, mstate->ev, mstate->cli,
				 fnum, off, size);
	if (req == NULL) {
		TALLOC_FREE(state);
		fuse_reply_err(freq, ENOMEM);
		return;
	}
	tevent_req_set_callback(req, cli_ll_read_done, state);
}

static void cli_ll_read_done(struct tevent_req *req)
{
	struct ll_read_state *state = tevent_req_callback_data(
		req, struct ll_read_state);
	ssize_t received;
	uint8_t *rcvbuf;
	NTSTATUS status;

	status = cli_smb2_read_recv(req, &received, &rcvbuf);
	/* no talloc_free here yet */

	if (NT_STATUS_EQUAL(status, NT_STATUS_END_OF_FILE)) {
		received = 0;
		rcvbuf = NULL;
		status = NT_STATUS_OK;
	}

	if (!NT_STATUS_IS_OK(status)) {
		fuse_reply_err(state->freq, map_errno_from_nt_status(status));
		return;
	}
	fuse_reply_buf(state->freq, (char *)rcvbuf, received);
	TALLOC_FREE(state);
}

struct ll_write_state {
	struct mount_state *mstate;
	fuse_req_t freq;
};

static void cli_ll_write_done(struct tevent_req *req);

static void cli_ll_write(fuse_req_t freq, fuse_ino_t ino, const char *buf,
			 size_t size, off_t off, struct fuse_file_info *fi)
{
	struct mount_state *mstate = talloc_get_type_abort(
		fuse_req_userdata(freq), struct mount_state);
	struct ll_write_state *state;
	struct tevent_req *req;
	uint16_t fnum;

	DBG_DEBUG("ino=%ju, size=%zu, off=%ju\n", (uintmax_t)ino,
		  size, (uintmax_t)off);

	state = talloc(mstate, struct ll_write_state);
	if (state == NULL) {
		fuse_reply_err(freq, ENOMEM);
		return;
	}
	state->mstate = mstate;
	state->freq = freq;

	fnum = fi->fh;

	req = cli_smb2_write_send(state, mstate->ev, mstate->cli, fnum, 0,
				  (const uint8_t *)buf, off, size);
	if (req == NULL) {
		TALLOC_FREE(state);
		fuse_reply_err(freq, ENOMEM);
		return;
	}
	tevent_req_set_callback(req, cli_ll_write_done, state);
}

static void cli_ll_write_done(struct tevent_req *req)
{
	struct ll_write_state *state = tevent_req_callback_data(
		req, struct ll_write_state);
	size_t written;
	NTSTATUS status;

	status = cli_smb2_write_recv(req, &written);
	/* no talloc_free here yet */
	if (!NT_STATUS_IS_OK(status)) {
		fuse_reply_err(state->freq, map_errno_from_nt_status(status));
		return;
	}
	fuse_reply_write(state->freq, written);
	TALLOC_FREE(state);
}


struct ll_dir_state {
	uint64_t fid_persistent;
	uint64_t fid_volatile;

	struct file_info *finfos;
	unsigned num_finfos, num_sent;
};

static bool ll_dir_state_add(struct ll_dir_state *dir_state,
			     const char *name)
{
	struct file_info *tmp, *finfo;

	tmp = talloc_realloc(dir_state, dir_state->finfos,
			     struct file_info, dir_state->num_finfos+1);
	if (tmp == NULL) {
		return false;
	}
	dir_state->finfos = tmp;
	finfo = &dir_state->finfos[dir_state->num_finfos];

	ZERO_STRUCTP(finfo);

	finfo->name = talloc_strdup(dir_state->finfos, name);
	if (finfo->name == NULL) {
		return false;
	}
	dir_state->num_finfos += 1;

	return true;
}

struct ll_opendir_state {
	struct mount_state *mstate;
	fuse_req_t freq;
	struct fuse_file_info fi;
	struct ll_dir_state *dir_state;
};

static void cli_ll_opendir_done(struct tevent_req *req);

static void cli_ll_opendir(fuse_req_t freq, fuse_ino_t ino,
			   struct fuse_file_info *fi)
{
	struct mount_state *mstate = talloc_get_type_abort(
		fuse_req_userdata(freq), struct mount_state);
	struct cli_state *cli = mstate->cli;
	struct ll_opendir_state *state;
	struct inode_state *istate;
	struct tevent_req *req;

	DBG_DEBUG("ino=%ju\n", (uintmax_t)ino);

	istate = idr_find(mstate->ino_ctx, ino);
	if (istate == NULL) {
		fuse_reply_err(freq, ENOENT);
		return;
	}

	state = talloc(mstate, struct ll_opendir_state);
	if (state == NULL) {
		fuse_reply_err(freq, ENOMEM);
		return;
	}
	state->mstate = mstate;
	state->freq = freq;
	state->fi = *fi;

	state->dir_state = talloc_zero(state, struct ll_dir_state);
	if (state->dir_state == NULL) {
		TALLOC_FREE(state);
		fuse_reply_err(freq, ENOMEM);
		return;
	}

	req = smb2cli_create_send(
		state, mstate->ev, cli->conn, cli->timeout,
		cli->smb2.session, cli->smb2.tcon, istate->path,
		0, SMB2_IMPERSONATION_IMPERSONATION,
		FILE_GENERIC_READ, FILE_ATTRIBUTE_DIRECTORY,
		FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
		FILE_OPEN, FILE_DIRECTORY_FILE, NULL);
	if (req == NULL) {
		TALLOC_FREE(state);
		fuse_reply_err(freq, ENOMEM);
		return;
	}
	tevent_req_set_callback(req, cli_ll_opendir_done, state);
}

static void cli_ll_opendir_done(struct tevent_req *req)
{
	struct ll_opendir_state *state = tevent_req_callback_data(
		req, struct ll_opendir_state);
	NTSTATUS status;

	status = smb2cli_create_recv(req,
				     &state->dir_state->fid_persistent,
				     &state->dir_state->fid_volatile,
				     NULL, NULL, NULL);
	TALLOC_FREE(req);

	DEBUG(10, ("%s: smbcli_create_recv returned %s\n", __func__,
		   nt_errstr(status)));

	if (!NT_STATUS_IS_OK(status)) {
		fuse_reply_err(state->freq, map_errno_from_nt_status(status));
		return;
	}

	state->fi.fh = (uint64_t)talloc_move(state->mstate, &state->dir_state);
	state->fi.direct_io = 0;
	state->fi.keep_cache = 0;

	fuse_reply_open(state->freq, &state->fi);

	TALLOC_FREE(state);
}

struct ll_readdir_state {
	fuse_req_t freq;
	struct ll_dir_state *dir_state;
};

static void cli_ll_readdir_done(struct tevent_req *subreq);
static NTSTATUS cli_ll_readdir_one(const char *mnt, struct file_info *finfo,
				   const char *path, void *private_data);
static void cli_ll_readdir_reply_one(fuse_req_t freq,
				     struct ll_dir_state *dir_state);

static void cli_ll_readdir(fuse_req_t freq, fuse_ino_t ino, size_t size,
			   off_t off, struct fuse_file_info *fi)
{
	struct mount_state *mstate = talloc_get_type_abort(
		fuse_req_userdata(freq), struct mount_state);
	struct cli_state *cli = mstate->cli;
	struct ll_dir_state *dir_state;
	struct ll_readdir_state *state;
	struct tevent_req *req;

	DBG_DEBUG("ino=%ju, size=%zu, off=%ju\n", (uintmax_t)ino, size,
		  (uintmax_t)off);

	dir_state = talloc_get_type_abort((void *)fi->fh, struct ll_dir_state);

	if (dir_state->finfos != NULL) {
		DBG_DEBUG("finfos=%p\n", dir_state->finfos);
		cli_ll_readdir_reply_one(freq, dir_state);
		return;
	}

	if (!ll_dir_state_add(dir_state, ".") ||
	    !ll_dir_state_add(dir_state, "..")) {
		fuse_reply_err(freq, ENOMEM);
		return;
	}

	state = talloc(mstate, struct ll_readdir_state);
	if (state == NULL) {
		fuse_reply_err(freq, ENOMEM);
		return;
	}
	state->freq = freq;
	state->dir_state = dir_state;

	req = cli_smb2_listdir_send(
		state, mstate->ev, cli->conn, cli->timeout,
		cli->smb2.session, cli->smb2.tcon,
		SMB2_FIND_ID_BOTH_DIRECTORY_INFO, 0, 0,
		dir_state->fid_persistent, dir_state->fid_volatile,
		"*", 0xffff,
		FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_SYSTEM |
		FILE_ATTRIBUTE_HIDDEN,
		NULL, NULL, cli_ll_readdir_one,	dir_state);
	if (req == NULL) {
		TALLOC_FREE(state);
		fuse_reply_err(freq, ENOMEM);
		return;
	}
	tevent_req_set_callback(req, cli_ll_readdir_done, state);
}

static void cli_ll_readdir_reply_one(fuse_req_t freq,
				     struct ll_dir_state *dir_state)
{
	struct file_info *finfo;
	char buf[1024];
	struct stat sbuf = {};
	size_t buflen;

	if (dir_state->num_finfos == dir_state->num_sent) {
		DEBUG(10, ("%s: Done\n", __func__));
		fuse_reply_buf(freq, NULL, 0);
		return;
	}

	sbuf.st_mode = S_IFREG | 0755;
	sbuf.st_ino = random(); /* FIXME :-) */
	finfo = &dir_state->finfos[dir_state->num_sent];

	DBG_DEBUG("Adding %s\n", finfo->name);

	buflen = fuse_add_direntry(freq, buf, sizeof(buf),
				   finfo->name, &sbuf, 0);
	fuse_reply_buf(freq, buf, buflen);
	dir_state->num_sent += 1;
	return;
}

static NTSTATUS cli_ll_readdir_one(const char *mnt, struct file_info *finfo,
				   const char *path, void *private_data)
{
	struct ll_dir_state *dir_state = talloc_get_type_abort(
		private_data, struct ll_dir_state);

	if (ISDOT(finfo->name) || ISDOTDOT(finfo->name)) {
		DEBUG(10, ("%s: Ignoring %s\n", __func__, finfo->name));
		return NT_STATUS_OK;
	}

	DBG_DEBUG("Got entry %s\n", finfo->name);

	if (!ll_dir_state_add(dir_state, finfo->name)) {
		return NT_STATUS_NO_MEMORY;
	}
	return NT_STATUS_OK;
}

static void cli_ll_readdir_done(struct tevent_req *req)
{
	struct ll_readdir_state *state = tevent_req_callback_data(
		req, struct ll_readdir_state);
	NTSTATUS status;

	status = cli_smb2_listdir_recv(req);
	TALLOC_FREE(req);
	if (!NT_STATUS_IS_OK(status)) {
		fuse_reply_err(state->freq, map_errno_from_nt_status(status));
		return;
	}
	cli_ll_readdir_reply_one(state->freq, state->dir_state);
	TALLOC_FREE(state);
}


struct ll_releasedir_state {
	struct mount_state *mstate;
	fuse_req_t freq;
	struct ll_dir_state *dir_state;
};

static void cli_ll_releasedir_done(struct tevent_req *req);

static void cli_ll_releasedir(fuse_req_t freq, fuse_ino_t ino,
			      struct fuse_file_info *fi)
{
	struct mount_state *mstate = talloc_get_type_abort(
		fuse_req_userdata(freq), struct mount_state);
	struct cli_state *cli = mstate->cli;
	struct ll_releasedir_state *state;
	struct tevent_req *req;

	DBG_DEBUG("ino=%ju\n", (uintmax_t)ino);

	state = talloc(mstate, struct ll_releasedir_state);
	if (state == NULL) {
		fuse_reply_err(freq, ENOMEM);
		return;
	}
	state->mstate = mstate;
	state->freq = freq;

	state->dir_state = talloc_get_type_abort(
		(void *)fi->fh, struct ll_dir_state);

	req = smb2cli_close_send(state, mstate->ev, cli->conn, cli->timeout,
				 cli->smb2.session, cli->smb2.tcon, 0,
				 state->dir_state->fid_persistent,
				 state->dir_state->fid_volatile);
	if (req == NULL) {
		TALLOC_FREE(state);
		fuse_reply_err(freq, ENOMEM);
		return;
	}
	tevent_req_set_callback(req, cli_ll_releasedir_done, state);
}

static void cli_ll_releasedir_done(struct tevent_req *req)
{
	struct ll_releasedir_state *state = tevent_req_callback_data(
		req, struct ll_releasedir_state);
	NTSTATUS status;

	status = smb2cli_close_recv(req);
	TALLOC_FREE(req);
	if (!NT_STATUS_IS_OK(status)) {
		fuse_reply_err(state->freq, map_errno_from_nt_status(status));
		return;
	}
	TALLOC_FREE(state->dir_state);
	fuse_reply_err(state->freq, 0);
	TALLOC_FREE(state);
}

static struct fuse_lowlevel_ops cli_ll_ops = {
	.lookup = cli_ll_lookup,
	.getattr = cli_ll_getattr,
	.open = cli_ll_open,
	.create = cli_ll_create,
	.release = cli_ll_release,
	.read = cli_ll_read,
	.write = cli_ll_write,
	.opendir = cli_ll_opendir,
	.readdir = cli_ll_readdir,
	.releasedir = cli_ll_releasedir,
};

static void fuse_chan_fd_handler(struct tevent_context *ev,
				 struct tevent_fd *fde,
				 uint16_t flags,
				 void *private_data);
static void fuse_chan_signal_handler(struct tevent_context *ev,
				     struct tevent_signal *se,
				     int signum,
				     int count,
				     void *siginfo,
				     void *private_data);

static int mount_state_destructor(struct mount_state *s);

int do_mount(struct cli_state *cli, const char *mountpoint)
{
	struct mount_state *state;
	struct inode_state *ino;
	struct fuse_args args = { 0 };
	int fd;
	int ret = 1;

	state = talloc_zero(talloc_tos(), struct mount_state);
	if (state == NULL) {
		fprintf(stderr, "talloc failed\n");
		return 1;
	}

	state->ev = tevent_context_init(state);
	if (state->ev == NULL) {
		fprintf(stderr, "tevent_context_init failed\n");
		TALLOC_FREE(state);
		return 1;
	}

	state->ino_ctx = idr_init(state);
	if (state->ino_ctx == NULL) {
		fprintf(stderr, "idr_init failed\n");
		TALLOC_FREE(state);
		return 1;
	}

	state->ino_parent = talloc_new(state);
	if (state->ino_parent == NULL) {
		fprintf(stderr, "talloc_new failed\n");
		TALLOC_FREE(state);
		return 1;
	}

	talloc_set_destructor(state, mount_state_destructor);

	ino = inode_state_new(state, "");
	if (ino == NULL) {
		fprintf(stderr, "inode_state_new failed\n");
		TALLOC_FREE(state);
		return 1;
	}
	if (ino->ino != FUSE_ROOT_ID) {
		fprintf(stderr, "first inode gave %d, expected %d\n",
			(int)ino->ino, FUSE_ROOT_ID);
		TALLOC_FREE(state);
		return 1;
	}

	state->cli = cli;

	state->ch = fuse_mount(mountpoint, &args);
	if (state->ch == NULL) {
		perror("fuse_mount failed");
		goto fail_free;
	}

	state->bufsize = fuse_chan_bufsize(state->ch);
	state->buf = talloc_array(state, char, state->bufsize);
	if (state->buf == NULL) {
		fprintf(stderr, "talloc failed\n");
		goto fail_unmount;
	}

	fd = fuse_chan_fd(state->ch);

	state->fde = tevent_add_fd(state->ev, state, fd, TEVENT_FD_READ,
				   fuse_chan_fd_handler, state);
	if (state->fde == NULL) {
		fprintf(stderr, "tevent_add_fd failed\n");
		goto fail_unmount;
	}

	state->signal_ev = tevent_add_signal(state->ev, state, SIGINT, 0,
					     fuse_chan_signal_handler, state);
	if (state->signal_ev == NULL) {
		fprintf(stderr, "tevent_add_signal failed\n");
		goto fail_unmount;
	}

	state->se = fuse_lowlevel_new(&args, &cli_ll_ops, sizeof(cli_ll_ops),
				      state);
	if (state->se == NULL) {
		perror("fuse_lowlevel_new failed");
		goto fail_unmount;
	}

	fuse_session_add_chan(state->se, state->ch);

	while (!state->done) {
		ret = tevent_loop_once(state->ev);
		if (ret == -1) {
			perror("tevent_loop_once failed");
			break;
		}
	}

	fuse_session_remove_chan(state->ch);
	fuse_session_destroy(state->se);
fail_unmount:
	fuse_unmount(mountpoint, state->ch);
fail_free:
	TALLOC_FREE(state);
	return ret;
}

static int mount_state_destructor(struct mount_state *s)
{
	TALLOC_FREE(s->ino_parent);
	return 0;
}


static void fuse_chan_fd_handler(struct tevent_context *ev,
				 struct tevent_fd *fde,
				 uint16_t flags,
				 void *private_data)
{
	struct mount_state *state = talloc_get_type_abort(
		private_data, struct mount_state);
	int recvd;

	if ((flags & TEVENT_FD_READ) == 0) {
		return;
	}

	recvd = fuse_chan_recv(&state->ch, state->buf, state->bufsize);
	if (recvd <= 0) {
		state->done = true;
		return;
	}
	fuse_session_process(state->se, state->buf, recvd, state->ch);
}

static void fuse_chan_signal_handler(struct tevent_context *ev,
				     struct tevent_signal *se,
				     int signum,
				     int count,
				     void *siginfo,
				     void *private_data)
{
	struct mount_state *state = talloc_get_type_abort(
		private_data, struct mount_state);
	state->done = true;
}
