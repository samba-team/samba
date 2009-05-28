/* 
   Unix SMB/CIFS implementation.
   client file operations
   Copyright (C) Andrew Tridgell 1994-1998
   Copyright (C) Jeremy Allison 2001-2009
   
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

/***********************************************************
 Common function for pushing stings, used by smb_bytes_push_str()
 and trans_bytes_push_str(). Only difference is the align_odd
 parameter setting.
***********************************************************/

static uint8_t *internal_bytes_push_str(uint8_t *buf, bool ucs2,
				const char *str, size_t str_len,
				bool align_odd,
				size_t *pconverted_size)
{
	size_t buflen;
	char *converted;
	size_t converted_size;

	if (buf == NULL) {
		return NULL;
	}

	buflen = talloc_get_size(buf);

	if (align_odd && ucs2 && (buflen % 2 == 0)) {
		/*
		 * We're pushing into an SMB buffer, align odd
		 */
		buf = TALLOC_REALLOC_ARRAY(NULL, buf, uint8_t, buflen + 1);
		if (buf == NULL) {
			return NULL;
		}
		buf[buflen] = '\0';
		buflen += 1;
	}

	if (!convert_string_talloc(talloc_tos(), CH_UNIX,
				   ucs2 ? CH_UTF16LE : CH_DOS,
				   str, str_len, &converted,
				   &converted_size, true)) {
		return NULL;
	}

	buf = TALLOC_REALLOC_ARRAY(NULL, buf, uint8_t,
				   buflen + converted_size);
	if (buf == NULL) {
		TALLOC_FREE(converted);
		return NULL;
	}

	memcpy(buf + buflen, converted, converted_size);

	TALLOC_FREE(converted);

	if (pconverted_size) {
		*pconverted_size = converted_size;
	}

	return buf;
}

/***********************************************************
 Push a string into an SMB buffer, with odd byte alignment
 if it's a UCS2 string.
***********************************************************/

uint8_t *smb_bytes_push_str(uint8_t *buf, bool ucs2,
			    const char *str, size_t str_len,
			    size_t *pconverted_size)
{
	return internal_bytes_push_str(buf, ucs2, str, str_len,
			true, pconverted_size);
}

/***********************************************************
 Same as smb_bytes_push_str(), but without the odd byte
 align for ucs2 (we're pushing into a param or data block).
 static for now, although this will probably change when
 other modules use async trans calls.
***********************************************************/

static uint8_t *trans2_bytes_push_str(uint8_t *buf, bool ucs2,
			    const char *str, size_t str_len,
			    size_t *pconverted_size)
{
	return internal_bytes_push_str(buf, ucs2, str, str_len,
			false, pconverted_size);
}

/****************************************************************************
 Hard/Symlink a file (UNIX extensions).
 Creates new name (sym)linked to oldname.
****************************************************************************/

struct link_state {
	uint16_t setup;
	uint8_t *param;
	uint8_t *data;
};

static void cli_posix_link_internal_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
				subreq, struct tevent_req);
	struct link_state *state = tevent_req_data(req, struct link_state);
	NTSTATUS status;

	status = cli_trans_recv(subreq, state, NULL, NULL, NULL, NULL, NULL, NULL);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}
	tevent_req_done(req);
}

static struct tevent_req *cli_posix_link_internal_send(TALLOC_CTX *mem_ctx,
					struct event_context *ev,
					struct cli_state *cli,
					const char *oldname,
					const char *newname,
					bool hardlink)
{
	struct tevent_req *req = NULL, *subreq = NULL;
	struct link_state *state = NULL;

	req = tevent_req_create(mem_ctx, &state, struct link_state);
	if (req == NULL) {
		return NULL;
	}

	/* Setup setup word. */
	SSVAL(&state->setup, 0, TRANSACT2_SETPATHINFO);

	/* Setup param array. */
	state->param = talloc_array(state, uint8_t, 6);
	if (tevent_req_nomem(state->param, req)) {
		return tevent_req_post(req, ev);
	}
	memset(state->param, '\0', 6);
	SSVAL(state->param,0,hardlink ? SMB_SET_FILE_UNIX_HLINK : SMB_SET_FILE_UNIX_LINK);

	state->param = trans2_bytes_push_str(state->param, cli_ucs2(cli), newname,
				   strlen(newname)+1, NULL);

	if (tevent_req_nomem(state->param, req)) {
		return tevent_req_post(req, ev);
	}

	/* Setup data array. */
	state->data = talloc_array(state, uint8_t, 0);
	if (tevent_req_nomem(state->data, req)) {
		return tevent_req_post(req, ev);
	}
	state->data = trans2_bytes_push_str(state->data, cli_ucs2(cli), oldname,
				   strlen(oldname)+1, NULL);

	subreq = cli_trans_send(state,			/* mem ctx. */
				ev,			/* event ctx. */
				cli,			/* cli_state. */
				SMBtrans2,		/* cmd. */
				NULL,			/* pipe name. */
				-1,			/* fid. */
				0,			/* function. */
				0,			/* flags. */
				&state->setup,		/* setup. */
				1,			/* num setup uint16_t words. */
				0,			/* max returned setup. */
				state->param,		/* param. */
				talloc_get_size(state->param),	/* num param. */
				2,			/* max returned param. */
				state->data,		/* data. */
				talloc_get_size(state->data),	/* num data. */
				0);			/* max returned data. */

	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_posix_link_internal_done, req);
	return req;
}

/****************************************************************************
 Symlink a file (UNIX extensions).
****************************************************************************/

struct tevent_req *cli_posix_symlink_send(TALLOC_CTX *mem_ctx,
					struct event_context *ev,
					struct cli_state *cli,
					const char *oldname,
					const char *newname)
{
	return cli_posix_link_internal_send(mem_ctx, ev, cli,
			oldname, newname, false);
}

NTSTATUS cli_posix_symlink_recv(struct tevent_req *req)
{
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	return NT_STATUS_OK;
}

NTSTATUS cli_posix_symlink(struct cli_state *cli,
			const char *oldname,
			const char *newname)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct event_context *ev = NULL;
	struct tevent_req *req = NULL;
	NTSTATUS status = NT_STATUS_OK;

	if (cli_has_async_calls(cli)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	ev = event_context_init(frame);
	if (ev == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	req = cli_posix_symlink_send(frame,
				ev,
				cli,
				oldname,
				newname);
	if (req == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	if (!tevent_req_poll(req, ev)) {
		status = map_nt_error_from_unix(errno);
		goto fail;
	}

	status = cli_posix_symlink_recv(req);

 fail:
	TALLOC_FREE(frame);
	if (!NT_STATUS_IS_OK(status)) {
		cli_set_error(cli, status);
	}
	return status;
}

/****************************************************************************
 Read a POSIX symlink.
****************************************************************************/

struct readlink_state {
	uint16_t setup;
	uint8_t *param;
	uint8_t *data;
	uint32_t num_data;
};

static void cli_posix_readlink_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
				subreq, struct tevent_req);
	struct readlink_state *state = tevent_req_data(req, struct readlink_state);
	NTSTATUS status;

	status = cli_trans_recv(subreq, state, NULL, NULL, NULL, NULL,
			&state->data, &state->num_data);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}
	if (state->num_data == 0) {
		tevent_req_nterror(req, NT_STATUS_DATA_ERROR);
		return;
	}
	if (state->data[state->num_data-1] != '\0') {
		tevent_req_nterror(req, NT_STATUS_DATA_ERROR);
		return;
	}
	tevent_req_done(req);
}

struct tevent_req *cli_posix_readlink_send(TALLOC_CTX *mem_ctx,
					struct event_context *ev,
					struct cli_state *cli,
					const char *fname,
					size_t len)
{
	struct tevent_req *req = NULL, *subreq = NULL;
	struct readlink_state *state = NULL;
	uint32_t maxbytelen = (uint32_t)(cli_ucs2(cli) ? len*3 : len);

	if (maxbytelen < len) {
		return NULL;
	}

	req = tevent_req_create(mem_ctx, &state, struct readlink_state);
	if (req == NULL) {
		return NULL;
	}

	/* Setup setup word. */
	SSVAL(&state->setup, 0, TRANSACT2_QPATHINFO);

	/* Setup param array. */
	state->param = talloc_array(state, uint8_t, 6);
	if (tevent_req_nomem(state->param, req)) {
		return tevent_req_post(req, ev);
	}
	memset(state->param, '\0', 6);
	SSVAL(state->param,0,SMB_QUERY_FILE_UNIX_LINK);

	state->param = trans2_bytes_push_str(state->param, cli_ucs2(cli), fname,
				   strlen(fname)+1, NULL);

	if (tevent_req_nomem(state->param, req)) {
		return tevent_req_post(req, ev);
	}

	subreq = cli_trans_send(state,			/* mem ctx. */
				ev,			/* event ctx. */
				cli,			/* cli_state. */
				SMBtrans2,		/* cmd. */
				NULL,			/* pipe name. */
				-1,			/* fid. */
				0,			/* function. */
				0,			/* flags. */
				&state->setup,		/* setup. */
				1,			/* num setup uint16_t words. */
				0,			/* max returned setup. */
				state->param,		/* param. */
				talloc_get_size(state->param),	/* num param. */
				2,			/* max returned param. */
				NULL,			/* data. */
				0,			/* num data. */
				maxbytelen);		/* max returned data. */

	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_posix_readlink_done, req);
	return req;
}

NTSTATUS cli_posix_readlink_recv(struct tevent_req *req, struct cli_state *cli,
				char *retpath, size_t len)
{
	NTSTATUS status;
	char *converted = NULL;
	size_t converted_size = 0;
	struct readlink_state *state = tevent_req_data(req, struct readlink_state);

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	/* The returned data is a pushed string, not raw data. */
	if (!convert_string_talloc(state,
				cli_ucs2(cli) ? CH_UTF16LE : CH_DOS, 
				CH_UNIX,
				state->data,
				state->num_data,
				&converted,
				&converted_size,
				true)) {
		return NT_STATUS_NO_MEMORY;
	}

	len = MIN(len,converted_size);
	if (len == 0) {
		return NT_STATUS_DATA_ERROR;
	}
	memcpy(retpath, converted, len);
	return NT_STATUS_OK;
}

NTSTATUS cli_posix_readlink(struct cli_state *cli, const char *fname,
				char *linkpath, size_t len)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct event_context *ev = NULL;
	struct tevent_req *req = NULL;
	NTSTATUS status = NT_STATUS_OK;

	if (cli_has_async_calls(cli)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	ev = event_context_init(frame);
	if (ev == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	/* Len is in bytes, we need it in UCS2 units. */
	if (2*len < len) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	req = cli_posix_readlink_send(frame,
				ev,
				cli,
				fname,
				len);
	if (req == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	if (!tevent_req_poll(req, ev)) {
		status = map_nt_error_from_unix(errno);
		goto fail;
	}

	status = cli_posix_readlink_recv(req, cli, linkpath, len);

 fail:
	TALLOC_FREE(frame);
	if (!NT_STATUS_IS_OK(status)) {
		cli_set_error(cli, status);
	}
	return status;
}


/****************************************************************************
 Hard link a file (UNIX extensions).
****************************************************************************/

struct tevent_req *cli_posix_hardlink_send(TALLOC_CTX *mem_ctx,
					struct event_context *ev,
					struct cli_state *cli,
					const char *oldname,
					const char *newname)
{
	return cli_posix_link_internal_send(mem_ctx, ev, cli,
			oldname, newname, true);
}

NTSTATUS cli_posix_hardlink_recv(struct tevent_req *req)
{
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	return NT_STATUS_OK;
}

NTSTATUS cli_posix_hardlink(struct cli_state *cli,
			const char *oldname,
			const char *newname)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct event_context *ev = NULL;
	struct tevent_req *req = NULL;
	NTSTATUS status = NT_STATUS_OK;

	if (cli_has_async_calls(cli)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	ev = event_context_init(frame);
	if (ev == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	req = cli_posix_hardlink_send(frame,
				ev,
				cli,
				oldname,
				newname);
	if (req == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	if (!tevent_req_poll(req, ev)) {
		status = map_nt_error_from_unix(errno);
		goto fail;
	}

	status = cli_posix_hardlink_recv(req);

 fail:
	TALLOC_FREE(frame);
	if (!NT_STATUS_IS_OK(status)) {
		cli_set_error(cli, status);
	}
	return status;
}

/****************************************************************************
 Map standard UNIX permissions onto wire representations.
****************************************************************************/

uint32_t unix_perms_to_wire(mode_t perms)
{
        unsigned int ret = 0;

        ret |= ((perms & S_IXOTH) ?  UNIX_X_OTH : 0);
        ret |= ((perms & S_IWOTH) ?  UNIX_W_OTH : 0);
        ret |= ((perms & S_IROTH) ?  UNIX_R_OTH : 0);
        ret |= ((perms & S_IXGRP) ?  UNIX_X_GRP : 0);
        ret |= ((perms & S_IWGRP) ?  UNIX_W_GRP : 0);
        ret |= ((perms & S_IRGRP) ?  UNIX_R_GRP : 0);
        ret |= ((perms & S_IXUSR) ?  UNIX_X_USR : 0);
        ret |= ((perms & S_IWUSR) ?  UNIX_W_USR : 0);
        ret |= ((perms & S_IRUSR) ?  UNIX_R_USR : 0);
#ifdef S_ISVTX
        ret |= ((perms & S_ISVTX) ?  UNIX_STICKY : 0);
#endif
#ifdef S_ISGID
        ret |= ((perms & S_ISGID) ?  UNIX_SET_GID : 0);
#endif
#ifdef S_ISUID
        ret |= ((perms & S_ISUID) ?  UNIX_SET_UID : 0);
#endif
        return ret;
}

/****************************************************************************
 Map wire permissions to standard UNIX.
****************************************************************************/

mode_t wire_perms_to_unix(uint32_t perms)
{
        mode_t ret = (mode_t)0;

        ret |= ((perms & UNIX_X_OTH) ? S_IXOTH : 0);
        ret |= ((perms & UNIX_W_OTH) ? S_IWOTH : 0);
        ret |= ((perms & UNIX_R_OTH) ? S_IROTH : 0);
        ret |= ((perms & UNIX_X_GRP) ? S_IXGRP : 0);
        ret |= ((perms & UNIX_W_GRP) ? S_IWGRP : 0);
        ret |= ((perms & UNIX_R_GRP) ? S_IRGRP : 0);
        ret |= ((perms & UNIX_X_USR) ? S_IXUSR : 0);
        ret |= ((perms & UNIX_W_USR) ? S_IWUSR : 0);
        ret |= ((perms & UNIX_R_USR) ? S_IRUSR : 0);
#ifdef S_ISVTX
        ret |= ((perms & UNIX_STICKY) ? S_ISVTX : 0);
#endif
#ifdef S_ISGID
        ret |= ((perms & UNIX_SET_GID) ? S_ISGID : 0);
#endif
#ifdef S_ISUID
        ret |= ((perms & UNIX_SET_UID) ? S_ISUID : 0);
#endif
        return ret;
}

/****************************************************************************
 Return the file type from the wire filetype for UNIX extensions.
****************************************************************************/

static mode_t unix_filetype_from_wire(uint32_t wire_type)
{
	switch (wire_type) {
		case UNIX_TYPE_FILE:
			return S_IFREG;
		case UNIX_TYPE_DIR:
			return S_IFDIR;
#ifdef S_IFLNK
		case UNIX_TYPE_SYMLINK:
			return S_IFLNK;
#endif
#ifdef S_IFCHR
		case UNIX_TYPE_CHARDEV:
			return S_IFCHR;
#endif
#ifdef S_IFBLK
		case UNIX_TYPE_BLKDEV:
			return S_IFBLK;
#endif
#ifdef S_IFIFO
		case UNIX_TYPE_FIFO:
			return S_IFIFO;
#endif
#ifdef S_IFSOCK
		case UNIX_TYPE_SOCKET:
			return S_IFSOCK;
#endif
		default:
			return (mode_t)0;
	}
}

/****************************************************************************
 Do a POSIX getfacl (UNIX extensions).
****************************************************************************/

bool cli_unix_getfacl(struct cli_state *cli, const char *name, size_t *prb_size, char **retbuf)
{
	unsigned int param_len = 0;
	unsigned int data_len = 0;
	uint16_t setup = TRANSACT2_QPATHINFO;
	char *param;
	size_t nlen = 2*(strlen(name)+1);
	char *rparam=NULL, *rdata=NULL;
	char *p;

	param = SMB_MALLOC_ARRAY(char, 6+nlen+2);
	if (!param) {
		return false;
	}

	p = param;
	memset(p, '\0', 6);
	SSVAL(p, 0, SMB_QUERY_POSIX_ACL);
	p += 6;
	p += clistr_push(cli, p, name, nlen, STR_TERMINATE);
	param_len = PTR_DIFF(p, param);

	if (!cli_send_trans(cli, SMBtrans2,
		NULL,                        /* name */
		-1, 0,                       /* fid, flags */
		&setup, 1, 0,                /* setup, length, max */
		param, param_len, 2,         /* param, length, max */
		NULL,  0, cli->max_xmit      /* data, length, max */
		)) {
		SAFE_FREE(param);
		return false;
	}

	SAFE_FREE(param);

	if (!cli_receive_trans(cli, SMBtrans2,
			&rparam, &param_len,
			&rdata, &data_len)) {
		return false;
	}

	if (data_len < 6) {
		SAFE_FREE(rdata);
		SAFE_FREE(rparam);
		return false;
	}

	SAFE_FREE(rparam);
	*retbuf = rdata;
	*prb_size = (size_t)data_len;

	return true;
}

/****************************************************************************
 Stat a file (UNIX extensions).
****************************************************************************/

bool cli_unix_stat(struct cli_state *cli, const char *name, SMB_STRUCT_STAT *sbuf)
{
	unsigned int param_len = 0;
	unsigned int data_len = 0;
	uint16_t setup = TRANSACT2_QPATHINFO;
	char *param;
	size_t nlen = 2*(strlen(name)+1);
	char *rparam=NULL, *rdata=NULL;
	char *p;

	ZERO_STRUCTP(sbuf);

	param = SMB_MALLOC_ARRAY(char, 6+nlen+2);
	if (!param) {
		return false;
	}
	p = param;
	memset(p, '\0', 6);
	SSVAL(p, 0, SMB_QUERY_FILE_UNIX_BASIC);
	p += 6;
	p += clistr_push(cli, p, name, nlen, STR_TERMINATE);
	param_len = PTR_DIFF(p, param);

	if (!cli_send_trans(cli, SMBtrans2,
			NULL,                        /* name */
			-1, 0,                       /* fid, flags */
			&setup, 1, 0,                /* setup, length, max */
			param, param_len, 2,         /* param, length, max */
			NULL,  0, cli->max_xmit      /* data, length, max */
			)) {
		SAFE_FREE(param);
		return false;
	}

	SAFE_FREE(param);

	if (!cli_receive_trans(cli, SMBtrans2,
			&rparam, &param_len,
			&rdata, &data_len)) {
		return false;
	}

	if (data_len < 96) {
		SAFE_FREE(rdata);
		SAFE_FREE(rparam);
		return false;
	}

	sbuf->st_ex_size = IVAL2_TO_SMB_BIG_UINT(rdata,0);     /* total size, in bytes */
	sbuf->st_ex_blocks = IVAL2_TO_SMB_BIG_UINT(rdata,8);   /* number of blocks allocated */
#if defined (HAVE_STAT_ST_BLOCKS) && defined(STAT_ST_BLOCKSIZE)
	sbuf->st_ex_blocks /= STAT_ST_BLOCKSIZE;
#else
	/* assume 512 byte blocks */
	sbuf->st_ex_blocks /= 512;
#endif
	sbuf->st_ex_ctime = interpret_long_date(rdata + 16);    /* time of last change */
	sbuf->st_ex_atime = interpret_long_date(rdata + 24);    /* time of last access */
	sbuf->st_ex_mtime = interpret_long_date(rdata + 32);    /* time of last modification */

	sbuf->st_ex_uid = (uid_t) IVAL(rdata,40);      /* user ID of owner */
	sbuf->st_ex_gid = (gid_t) IVAL(rdata,48);      /* group ID of owner */
	sbuf->st_ex_mode |= unix_filetype_from_wire(IVAL(rdata, 56));
#if defined(HAVE_MAKEDEV)
	{
		uint32_t dev_major = IVAL(rdata,60);
		uint32_t dev_minor = IVAL(rdata,68);
		sbuf->st_ex_rdev = makedev(dev_major, dev_minor);
	}
#endif
	sbuf->st_ex_ino = (SMB_INO_T)IVAL2_TO_SMB_BIG_UINT(rdata,76);      /* inode */
	sbuf->st_ex_mode |= wire_perms_to_unix(IVAL(rdata,84));     /* protection */
	sbuf->st_ex_nlink = IVAL(rdata,92);    /* number of hard links */

	SAFE_FREE(rdata);
	SAFE_FREE(rparam);

	return true;
}
/****************************************************************************
 Chmod or chown a file internal (UNIX extensions).
****************************************************************************/

static bool cli_unix_chmod_chown_internal(struct cli_state *cli, const char *fname, uint32_t mode, uint32_t uid, uint32_t gid)
{
	unsigned int data_len = 0;
	unsigned int param_len = 0;
	uint16_t setup = TRANSACT2_SETPATHINFO;
	size_t nlen = 2*(strlen(fname)+1);
	char *param;
	char data[100];
	char *rparam=NULL, *rdata=NULL;
	char *p;

	param = SMB_MALLOC_ARRAY(char, 6+nlen+2);
	if (!param) {
		return false;
	}
	memset(param, '\0', 6);
	memset(data, 0, sizeof(data));

	SSVAL(param,0,SMB_SET_FILE_UNIX_BASIC);
	p = &param[6];

	p += clistr_push(cli, p, fname, nlen, STR_TERMINATE);
	param_len = PTR_DIFF(p, param);

	memset(data, 0xff, 40); /* Set all sizes/times to no change. */

	SIVAL(data,40,uid);
	SIVAL(data,48,gid);
	SIVAL(data,84,mode);

	data_len = 100;

	if (!cli_send_trans(cli, SMBtrans2,
			NULL,                        /* name */
			-1, 0,                          /* fid, flags */
			&setup, 1, 0,                   /* setup, length, max */
			param, param_len, 2,            /* param, length, max */
			(char *)&data,  data_len, cli->max_xmit /* data, length, max */
			)) {
		SAFE_FREE(param);
		return False;
	}

	SAFE_FREE(param);

	if (!cli_receive_trans(cli, SMBtrans2,
			&rparam, &param_len,
			&rdata, &data_len)) {
		return false;
	}

	SAFE_FREE(rdata);
	SAFE_FREE(rparam);

	return true;
}

/****************************************************************************
 chmod a file (UNIX extensions).
****************************************************************************/

bool cli_unix_chmod(struct cli_state *cli, const char *fname, mode_t mode)
{
	return cli_unix_chmod_chown_internal(cli, fname,
		unix_perms_to_wire(mode), SMB_UID_NO_CHANGE, SMB_GID_NO_CHANGE);
}

/****************************************************************************
 chown a file (UNIX extensions).
****************************************************************************/

bool cli_unix_chown(struct cli_state *cli, const char *fname, uid_t uid, gid_t gid)
{
	return cli_unix_chmod_chown_internal(cli, fname,
			SMB_MODE_NO_CHANGE, (uint32)uid, (uint32)gid);
}

/****************************************************************************
 Rename a file.
****************************************************************************/

static void cli_rename_done(struct tevent_req *subreq);

struct cli_rename_state {
	uint16_t vwv[1];
};

struct tevent_req *cli_rename_send(TALLOC_CTX *mem_ctx,
				struct event_context *ev,
				struct cli_state *cli,
				const char *fname_src,
				const char *fname_dst)
{
	struct tevent_req *req = NULL, *subreq = NULL;
	struct cli_rename_state *state = NULL;
	uint8_t additional_flags = 0;
	uint8_t *bytes = NULL;

	req = tevent_req_create(mem_ctx, &state, struct cli_rename_state);
	if (req == NULL) {
		return NULL;
	}

	SSVAL(state->vwv+0, 0, aSYSTEM | aHIDDEN | aDIR);

	bytes = talloc_array(state, uint8_t, 1);
	if (tevent_req_nomem(bytes, req)) {
		return tevent_req_post(req, ev);
	}
	bytes[0] = 4;
	bytes = smb_bytes_push_str(bytes, cli_ucs2(cli), fname_src,
				   strlen(fname_src)+1, NULL);
	if (tevent_req_nomem(bytes, req)) {
		return tevent_req_post(req, ev);
	}

	bytes = TALLOC_REALLOC_ARRAY(state, bytes, uint8_t,
			talloc_get_size(bytes)+1);
	if (tevent_req_nomem(bytes, req)) {
		return tevent_req_post(req, ev);
	}

	bytes[talloc_get_size(bytes)-1] = 4;
	bytes = smb_bytes_push_str(bytes, cli_ucs2(cli), fname_dst,
				   strlen(fname_dst)+1, NULL);
	if (tevent_req_nomem(bytes, req)) {
		return tevent_req_post(req, ev);
	}

	subreq = cli_smb_send(state, ev, cli, SMBmv, additional_flags,
			      1, state->vwv, talloc_get_size(bytes), bytes);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_rename_done, req);
	return req;
}

static void cli_rename_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
				subreq, struct tevent_req);
	NTSTATUS status;

	status = cli_smb_recv(subreq, 0, NULL, NULL, NULL, NULL);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}
	tevent_req_done(req);
}

NTSTATUS cli_rename_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

NTSTATUS cli_rename(struct cli_state *cli, const char *fname_src, const char *fname_dst)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct event_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_OK;

	if (cli_has_async_calls(cli)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	ev = event_context_init(frame);
	if (ev == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	req = cli_rename_send(frame, ev, cli, fname_src, fname_dst);
	if (req == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	if (!tevent_req_poll(req, ev)) {
		status = map_nt_error_from_unix(errno);
		goto fail;
	}

	status = cli_rename_recv(req);

 fail:
	TALLOC_FREE(frame);
	if (!NT_STATUS_IS_OK(status)) {
		cli_set_error(cli, status);
	}
	return status;
}

/****************************************************************************
 NT Rename a file.
****************************************************************************/

static void cli_ntrename_internal_done(struct tevent_req *subreq);

struct cli_ntrename_internal_state {
	uint16_t vwv[4];
};

static struct tevent_req *cli_ntrename_internal_send(TALLOC_CTX *mem_ctx,
				struct event_context *ev,
				struct cli_state *cli,
				const char *fname_src,
				const char *fname_dst,
				uint16_t rename_flag)
{
	struct tevent_req *req = NULL, *subreq = NULL;
	struct cli_ntrename_internal_state *state = NULL;
	uint8_t additional_flags = 0;
	uint8_t *bytes = NULL;

	req = tevent_req_create(mem_ctx, &state,
				struct cli_ntrename_internal_state);
	if (req == NULL) {
		return NULL;
	}

	SSVAL(state->vwv+0, 0 ,aSYSTEM | aHIDDEN | aDIR);
	SSVAL(state->vwv+1, 0, rename_flag);

	bytes = talloc_array(state, uint8_t, 1);
	if (tevent_req_nomem(bytes, req)) {
		return tevent_req_post(req, ev);
	}
	bytes[0] = 4;
	bytes = smb_bytes_push_str(bytes, cli_ucs2(cli), fname_src,
				   strlen(fname_src)+1, NULL);
	if (tevent_req_nomem(bytes, req)) {
		return tevent_req_post(req, ev);
	}

	bytes = TALLOC_REALLOC_ARRAY(state, bytes, uint8_t,
			talloc_get_size(bytes)+1);
	if (tevent_req_nomem(bytes, req)) {
		return tevent_req_post(req, ev);
	}

	bytes[talloc_get_size(bytes)-1] = 4;
	bytes = smb_bytes_push_str(bytes, cli_ucs2(cli), fname_dst,
				   strlen(fname_dst)+1, NULL);
	if (tevent_req_nomem(bytes, req)) {
		return tevent_req_post(req, ev);
	}

	subreq = cli_smb_send(state, ev, cli, SMBntrename, additional_flags,
			      4, state->vwv, talloc_get_size(bytes), bytes);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_ntrename_internal_done, req);
	return req;
}

static void cli_ntrename_internal_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
				subreq, struct tevent_req);
	NTSTATUS status;

	status = cli_smb_recv(subreq, 0, NULL, NULL, NULL, NULL);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}
	tevent_req_done(req);
}

static NTSTATUS cli_ntrename_internal_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

struct tevent_req *cli_ntrename_send(TALLOC_CTX *mem_ctx,
				struct event_context *ev,
				struct cli_state *cli,
				const char *fname_src,
				const char *fname_dst)
{
	return cli_ntrename_internal_send(mem_ctx,
					  ev,
					  cli,
					  fname_src,
					  fname_dst,
					  RENAME_FLAG_RENAME);
}

NTSTATUS cli_ntrename_recv(struct tevent_req *req)
{
	return cli_ntrename_internal_recv(req);
}

NTSTATUS cli_ntrename(struct cli_state *cli, const char *fname_src, const char *fname_dst)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct event_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_OK;

	if (cli_has_async_calls(cli)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	ev = event_context_init(frame);
	if (ev == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	req = cli_ntrename_send(frame, ev, cli, fname_src, fname_dst);
	if (req == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	if (!tevent_req_poll(req, ev)) {
		status = map_nt_error_from_unix(errno);
		goto fail;
	}

	status = cli_ntrename_recv(req);

 fail:
	TALLOC_FREE(frame);
	if (!NT_STATUS_IS_OK(status)) {
		cli_set_error(cli, status);
	}
	return status;
}

/****************************************************************************
 NT hardlink a file.
****************************************************************************/

struct tevent_req *cli_nt_hardlink_send(TALLOC_CTX *mem_ctx,
				struct event_context *ev,
				struct cli_state *cli,
				const char *fname_src,
				const char *fname_dst)
{
	return cli_ntrename_internal_send(mem_ctx,
					  ev,
					  cli,
					  fname_src,
					  fname_dst,
					  RENAME_FLAG_HARD_LINK);
}

NTSTATUS cli_nt_hardlink_recv(struct tevent_req *req)
{
	return cli_ntrename_internal_recv(req);
}

NTSTATUS cli_nt_hardlink(struct cli_state *cli, const char *fname_src, const char *fname_dst)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct event_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_OK;

	if (cli_has_async_calls(cli)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	ev = event_context_init(frame);
	if (ev == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	req = cli_nt_hardlink_send(frame, ev, cli, fname_src, fname_dst);
	if (req == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	if (!tevent_req_poll(req, ev)) {
		status = map_nt_error_from_unix(errno);
		goto fail;
	}

	status = cli_nt_hardlink_recv(req);

 fail:
	TALLOC_FREE(frame);
	if (!NT_STATUS_IS_OK(status)) {
		cli_set_error(cli, status);
	}
	return status;
}

/****************************************************************************
 Delete a file.
****************************************************************************/

static void cli_unlink_done(struct tevent_req *subreq);

struct cli_unlink_state {
	uint16_t vwv[1];
};

struct tevent_req *cli_unlink_send(TALLOC_CTX *mem_ctx,
				struct event_context *ev,
				struct cli_state *cli,
				const char *fname,
				uint16_t mayhave_attrs)
{
	struct tevent_req *req = NULL, *subreq = NULL;
	struct cli_unlink_state *state = NULL;
	uint8_t additional_flags = 0;
	uint8_t *bytes = NULL;

	req = tevent_req_create(mem_ctx, &state, struct cli_unlink_state);
	if (req == NULL) {
		return NULL;
	}

	SSVAL(state->vwv+0, 0, mayhave_attrs);

	bytes = talloc_array(state, uint8_t, 1);
	if (tevent_req_nomem(bytes, req)) {
		return tevent_req_post(req, ev);
	}
	bytes[0] = 4;
	bytes = smb_bytes_push_str(bytes, cli_ucs2(cli), fname,
				   strlen(fname)+1, NULL);

	if (tevent_req_nomem(bytes, req)) {
		return tevent_req_post(req, ev);
	}

	subreq = cli_smb_send(state, ev, cli, SMBunlink, additional_flags,
				1, state->vwv, talloc_get_size(bytes), bytes);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_unlink_done, req);
	return req;
}

static void cli_unlink_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	NTSTATUS status;

	status = cli_smb_recv(subreq, 0, NULL, NULL, NULL, NULL);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}
	tevent_req_done(req);
}

NTSTATUS cli_unlink_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

NTSTATUS cli_unlink(struct cli_state *cli, const char *fname, uint16_t mayhave_attrs)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct event_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_OK;

	if (cli_has_async_calls(cli)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	ev = event_context_init(frame);
	if (ev == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	req = cli_unlink_send(frame, ev, cli, fname, mayhave_attrs);
	if (req == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	if (!tevent_req_poll(req, ev)) {
		status = map_nt_error_from_unix(errno);
		goto fail;
	}

	status = cli_unlink_recv(req);

 fail:
	TALLOC_FREE(frame);
	if (!NT_STATUS_IS_OK(status)) {
		cli_set_error(cli, status);
	}
	return status;
}

/****************************************************************************
 Create a directory.
****************************************************************************/

static void cli_mkdir_done(struct tevent_req *subreq);

struct cli_mkdir_state {
	int dummy;
};

struct tevent_req *cli_mkdir_send(TALLOC_CTX *mem_ctx,
				  struct event_context *ev,
				  struct cli_state *cli,
				  const char *dname)
{
	struct tevent_req *req = NULL, *subreq = NULL;
	struct cli_mkdir_state *state = NULL;
	uint8_t additional_flags = 0;
	uint8_t *bytes = NULL;

	req = tevent_req_create(mem_ctx, &state, struct cli_mkdir_state);
	if (req == NULL) {
		return NULL;
	}

	bytes = talloc_array(state, uint8_t, 1);
	if (tevent_req_nomem(bytes, req)) {
		return tevent_req_post(req, ev);
	}
	bytes[0] = 4;
	bytes = smb_bytes_push_str(bytes, cli_ucs2(cli), dname,
				   strlen(dname)+1, NULL);

	if (tevent_req_nomem(bytes, req)) {
		return tevent_req_post(req, ev);
	}

	subreq = cli_smb_send(state, ev, cli, SMBmkdir, additional_flags,
			      0, NULL, talloc_get_size(bytes), bytes);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_mkdir_done, req);
	return req;
}

static void cli_mkdir_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	NTSTATUS status;

	status = cli_smb_recv(subreq, 0, NULL, NULL, NULL, NULL);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}
	tevent_req_done(req);
}

NTSTATUS cli_mkdir_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

NTSTATUS cli_mkdir(struct cli_state *cli, const char *dname)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct event_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_OK;

	if (cli_has_async_calls(cli)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	ev = event_context_init(frame);
	if (ev == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	req = cli_mkdir_send(frame, ev, cli, dname);
	if (req == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	if (!tevent_req_poll(req, ev)) {
		status = map_nt_error_from_unix(errno);
		goto fail;
	}

	status = cli_mkdir_recv(req);

 fail:
	TALLOC_FREE(frame);
	if (!NT_STATUS_IS_OK(status)) {
		cli_set_error(cli, status);
	}
	return status;
}

/****************************************************************************
 Remove a directory.
****************************************************************************/

static void cli_rmdir_done(struct tevent_req *subreq);

struct cli_rmdir_state {
	int dummy;
};

struct tevent_req *cli_rmdir_send(TALLOC_CTX *mem_ctx,
				  struct event_context *ev,
				  struct cli_state *cli,
				  const char *dname)
{
	struct tevent_req *req = NULL, *subreq = NULL;
	struct cli_rmdir_state *state = NULL;
	uint8_t additional_flags = 0;
	uint8_t *bytes = NULL;

	req = tevent_req_create(mem_ctx, &state, struct cli_rmdir_state);
	if (req == NULL) {
		return NULL;
	}

	bytes = talloc_array(state, uint8_t, 1);
	if (tevent_req_nomem(bytes, req)) {
		return tevent_req_post(req, ev);
	}
	bytes[0] = 4;
	bytes = smb_bytes_push_str(bytes, cli_ucs2(cli), dname,
				   strlen(dname)+1, NULL);

	if (tevent_req_nomem(bytes, req)) {
		return tevent_req_post(req, ev);
	}

	subreq = cli_smb_send(state, ev, cli, SMBrmdir, additional_flags,
			      0, NULL, talloc_get_size(bytes), bytes);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_rmdir_done, req);
	return req;
}

static void cli_rmdir_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	NTSTATUS status;

	status = cli_smb_recv(subreq, 0, NULL, NULL, NULL, NULL);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}
	tevent_req_done(req);
}

NTSTATUS cli_rmdir_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

NTSTATUS cli_rmdir(struct cli_state *cli, const char *dname)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct event_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_OK;

	if (cli_has_async_calls(cli)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	ev = event_context_init(frame);
	if (ev == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	req = cli_rmdir_send(frame, ev, cli, dname);
	if (req == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	if (!tevent_req_poll(req, ev)) {
		status = map_nt_error_from_unix(errno);
		goto fail;
	}

	status = cli_rmdir_recv(req);

 fail:
	TALLOC_FREE(frame);
	if (!NT_STATUS_IS_OK(status)) {
		cli_set_error(cli, status);
	}
	return status;
}

/****************************************************************************
 Set or clear the delete on close flag.
****************************************************************************/

int cli_nt_delete_on_close(struct cli_state *cli, uint16_t fnum, bool flag)
{
	unsigned int data_len = 1;
	unsigned int param_len = 6;
	uint16_t setup = TRANSACT2_SETFILEINFO;
	char param[6];
	unsigned char data;
	char *rparam=NULL, *rdata=NULL;

	memset(param, 0, param_len);
	SSVAL(param,0,fnum);
	SSVAL(param,2,SMB_SET_FILE_DISPOSITION_INFO);

	data = flag ? 1 : 0;

	if (!cli_send_trans(cli, SMBtrans2,
			NULL,                        /* name */
			-1, 0,                          /* fid, flags */
			&setup, 1, 0,                   /* setup, length, max */
			param, param_len, 2,            /* param, length, max */
			(char *)&data,  data_len, cli->max_xmit /* data, length, max */
			)) {
		return false;
	}

	if (!cli_receive_trans(cli, SMBtrans2,
			&rparam, &param_len,
			&rdata, &data_len)) {
		return false;
	}

	SAFE_FREE(rdata);
	SAFE_FREE(rparam);

	return true;
}

struct cli_ntcreate_state {
	uint16_t vwv[24];
	uint16_t fnum;
};

static void cli_ntcreate_done(struct tevent_req *subreq);

struct tevent_req *cli_ntcreate_send(TALLOC_CTX *mem_ctx,
				     struct event_context *ev,
				     struct cli_state *cli,
				     const char *fname,
				     uint32_t CreatFlags,
				     uint32_t DesiredAccess,
				     uint32_t FileAttributes,
				     uint32_t ShareAccess,
				     uint32_t CreateDisposition,
				     uint32_t CreateOptions,
				     uint8_t SecurityFlags)
{
	struct tevent_req *req, *subreq;
	struct cli_ntcreate_state *state;
	uint16_t *vwv;
	uint8_t *bytes;
	size_t converted_len;

	req = tevent_req_create(mem_ctx, &state, struct cli_ntcreate_state);
	if (req == NULL) {
		return NULL;
	}
	vwv = state->vwv;

	SCVAL(vwv+0, 0, 0xFF);
	SCVAL(vwv+0, 1, 0);
	SSVAL(vwv+1, 0, 0);
	SCVAL(vwv+2, 0, 0);

	if (cli->use_oplocks) {
		CreatFlags |= (REQUEST_OPLOCK|REQUEST_BATCH_OPLOCK);
	}
	SIVAL(vwv+3, 1, CreatFlags);
	SIVAL(vwv+5, 1, 0x0);	/* RootDirectoryFid */
	SIVAL(vwv+7, 1, DesiredAccess);
	SIVAL(vwv+9, 1, 0x0);	/* AllocationSize */
	SIVAL(vwv+11, 1, 0x0);	/* AllocationSize */
	SIVAL(vwv+13, 1, FileAttributes);
	SIVAL(vwv+15, 1, ShareAccess);
	SIVAL(vwv+17, 1, CreateDisposition);
	SIVAL(vwv+19, 1, CreateOptions);
	SIVAL(vwv+21, 1, 0x02);	/* ImpersonationLevel */
	SCVAL(vwv+23, 1, SecurityFlags);

	bytes = talloc_array(state, uint8_t, 0);
	bytes = smb_bytes_push_str(bytes, cli_ucs2(cli),
				   fname, strlen(fname)+1,
				   &converted_len);

	/* sigh. this copes with broken netapp filer behaviour */
	bytes = smb_bytes_push_str(bytes, cli_ucs2(cli), "", 1, NULL);

	if (tevent_req_nomem(bytes, req)) {
		return tevent_req_post(req, ev);
	}

	SIVAL(vwv+2, 1, converted_len);

	subreq = cli_smb_send(state, ev, cli, SMBntcreateX, 0, 24, vwv,
			      talloc_get_size(bytes), bytes);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_ntcreate_done, req);
	return req;
}

static void cli_ntcreate_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_ntcreate_state *state = tevent_req_data(
		req, struct cli_ntcreate_state);
	uint8_t wct;
	uint16_t *vwv;
	uint32_t num_bytes;
	uint8_t *bytes;
	NTSTATUS status;

	status = cli_smb_recv(subreq, 3, &wct, &vwv, &num_bytes, &bytes);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(subreq);
		tevent_req_nterror(req, status);
		return;
	}
	state->fnum = SVAL(vwv+2, 1);
	tevent_req_done(req);
}

NTSTATUS cli_ntcreate_recv(struct tevent_req *req, uint16_t *pfnum)
{
	struct cli_ntcreate_state *state = tevent_req_data(
		req, struct cli_ntcreate_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	*pfnum = state->fnum;
	return NT_STATUS_OK;
}

NTSTATUS cli_ntcreate(struct cli_state *cli,
		      const char *fname,
		      uint32_t CreatFlags,
		      uint32_t DesiredAccess,
		      uint32_t FileAttributes,
		      uint32_t ShareAccess,
		      uint32_t CreateDisposition,
		      uint32_t CreateOptions,
		      uint8_t SecurityFlags,
		      uint16_t *pfid)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct event_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_OK;

	if (cli_has_async_calls(cli)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	ev = event_context_init(frame);
	if (ev == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	req = cli_ntcreate_send(frame, ev, cli, fname, CreatFlags,
				DesiredAccess, FileAttributes, ShareAccess,
				CreateDisposition, CreateOptions,
				SecurityFlags);
	if (req == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	if (!tevent_req_poll(req, ev)) {
		status = map_nt_error_from_unix(errno);
		goto fail;
	}

	status = cli_ntcreate_recv(req, pfid);
 fail:
	TALLOC_FREE(frame);
	if (!NT_STATUS_IS_OK(status)) {
		cli_set_error(cli, status);
	}
	return status;
}

/****************************************************************************
 Open a file
 WARNING: if you open with O_WRONLY then getattrE won't work!
****************************************************************************/

struct cli_open_state {
	uint16_t vwv[15];
	uint16_t fnum;
	struct iovec bytes;
};

static void cli_open_done(struct tevent_req *subreq);

struct tevent_req *cli_open_create(TALLOC_CTX *mem_ctx,
				   struct event_context *ev,
				   struct cli_state *cli, const char *fname,
				   int flags, int share_mode,
				   struct tevent_req **psmbreq)
{
	struct tevent_req *req, *subreq;
	struct cli_open_state *state;
	unsigned openfn;
	unsigned accessmode;
	uint8_t additional_flags;
	uint8_t *bytes;

	req = tevent_req_create(mem_ctx, &state, struct cli_open_state);
	if (req == NULL) {
		return NULL;
	}

	openfn = 0;
	if (flags & O_CREAT) {
		openfn |= (1<<4);
	}
	if (!(flags & O_EXCL)) {
		if (flags & O_TRUNC)
			openfn |= (1<<1);
		else
			openfn |= (1<<0);
	}

	accessmode = (share_mode<<4);

	if ((flags & O_ACCMODE) == O_RDWR) {
		accessmode |= 2;
	} else if ((flags & O_ACCMODE) == O_WRONLY) {
		accessmode |= 1;
	}

#if defined(O_SYNC)
	if ((flags & O_SYNC) == O_SYNC) {
		accessmode |= (1<<14);
	}
#endif /* O_SYNC */

	if (share_mode == DENY_FCB) {
		accessmode = 0xFF;
	}

	SCVAL(state->vwv + 0, 0, 0xFF);
	SCVAL(state->vwv + 0, 1, 0);
	SSVAL(state->vwv + 1, 0, 0);
	SSVAL(state->vwv + 2, 0, 0);  /* no additional info */
	SSVAL(state->vwv + 3, 0, accessmode);
	SSVAL(state->vwv + 4, 0, aSYSTEM | aHIDDEN);
	SSVAL(state->vwv + 5, 0, 0);
	SIVAL(state->vwv + 6, 0, 0);
	SSVAL(state->vwv + 8, 0, openfn);
	SIVAL(state->vwv + 9, 0, 0);
	SIVAL(state->vwv + 11, 0, 0);
	SIVAL(state->vwv + 13, 0, 0);

	additional_flags = 0;

	if (cli->use_oplocks) {
		/* if using oplocks then ask for a batch oplock via
                   core and extended methods */
		additional_flags =
			FLAG_REQUEST_OPLOCK|FLAG_REQUEST_BATCH_OPLOCK;
		SSVAL(state->vwv+2, 0, SVAL(state->vwv+2, 0) | 6);
	}

	bytes = talloc_array(state, uint8_t, 0);
	bytes = smb_bytes_push_str(bytes, cli_ucs2(cli), fname,
				   strlen(fname)+1, NULL);

	if (tevent_req_nomem(bytes, req)) {
		return tevent_req_post(req, ev);
	}

	state->bytes.iov_base = (void *)bytes;
	state->bytes.iov_len = talloc_get_size(bytes);

	subreq = cli_smb_req_create(state, ev, cli, SMBopenX, additional_flags,
				    15, state->vwv, 1, &state->bytes);
	if (subreq == NULL) {
		TALLOC_FREE(req);
		return NULL;
	}
	tevent_req_set_callback(subreq, cli_open_done, req);
	*psmbreq = subreq;
	return req;
}

struct tevent_req *cli_open_send(TALLOC_CTX *mem_ctx, struct event_context *ev,
				 struct cli_state *cli, const char *fname,
				 int flags, int share_mode)
{
	struct tevent_req *req, *subreq;
	NTSTATUS status;

	req = cli_open_create(mem_ctx, ev, cli, fname, flags, share_mode,
			      &subreq);
	if (req == NULL) {
		return NULL;
	}

	status = cli_smb_req_send(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return tevent_req_post(req, ev);
	}
	return req;
}

static void cli_open_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_open_state *state = tevent_req_data(
		req, struct cli_open_state);
	uint8_t wct;
	uint16_t *vwv;
	NTSTATUS status;

	status = cli_smb_recv(subreq, 3, &wct, &vwv, NULL, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(subreq);
		tevent_req_nterror(req, status);
		return;
	}
	state->fnum = SVAL(vwv+2, 0);
	tevent_req_done(req);
}

NTSTATUS cli_open_recv(struct tevent_req *req, uint16_t *pfnum)
{
	struct cli_open_state *state = tevent_req_data(
		req, struct cli_open_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	*pfnum = state->fnum;
	return NT_STATUS_OK;
}

NTSTATUS cli_open(struct cli_state *cli, const char *fname, int flags,
	     int share_mode, uint16_t *pfnum)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct event_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_OK;

	if (cli_has_async_calls(cli)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	ev = event_context_init(frame);
	if (ev == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	req = cli_open_send(frame, ev, cli, fname, flags, share_mode);
	if (req == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	if (!tevent_req_poll(req, ev)) {
		status = map_nt_error_from_unix(errno);
		goto fail;
	}

	status = cli_open_recv(req, pfnum);
 fail:
	TALLOC_FREE(frame);
	if (!NT_STATUS_IS_OK(status)) {
		cli_set_error(cli, status);
	}
	return status;
}

/****************************************************************************
 Close a file.
****************************************************************************/

struct cli_close_state {
	uint16_t vwv[3];
};

static void cli_close_done(struct tevent_req *subreq);

struct tevent_req *cli_close_create(TALLOC_CTX *mem_ctx,
				struct event_context *ev,
				struct cli_state *cli,
				uint16_t fnum,
				struct tevent_req **psubreq)
{
	struct tevent_req *req, *subreq;
	struct cli_close_state *state;

	req = tevent_req_create(mem_ctx, &state, struct cli_close_state);
	if (req == NULL) {
		return NULL;
	}
	SSVAL(state->vwv+0, 0, fnum);
	SIVALS(state->vwv+1, 0, -1);

	subreq = cli_smb_req_create(state, ev, cli, SMBclose, 0, 3, state->vwv,
				    0, NULL);
	if (subreq == NULL) {
		TALLOC_FREE(req);
		return NULL;
	}
	tevent_req_set_callback(subreq, cli_close_done, req);
	*psubreq = subreq;
	return req;
}

struct tevent_req *cli_close_send(TALLOC_CTX *mem_ctx,
				struct event_context *ev,
				struct cli_state *cli,
				uint16_t fnum)
{
	struct tevent_req *req, *subreq;
	NTSTATUS status;

	req = cli_close_create(mem_ctx, ev, cli, fnum, &subreq);
	if (req == NULL) {
		return NULL;
	}

	status = cli_smb_req_send(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return tevent_req_post(req, ev);
	}
	return req;
}

static void cli_close_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	NTSTATUS status;

	status = cli_smb_recv(subreq, 0, NULL, NULL, NULL, NULL);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}
	tevent_req_done(req);
}

NTSTATUS cli_close_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

NTSTATUS cli_close(struct cli_state *cli, uint16_t fnum)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct event_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_OK;

	if (cli_has_async_calls(cli)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	ev = event_context_init(frame);
	if (ev == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	req = cli_close_send(frame, ev, cli, fnum);
	if (req == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	if (!tevent_req_poll(req, ev)) {
		status = map_nt_error_from_unix(errno);
		goto fail;
	}

	status = cli_close_recv(req);
 fail:
	TALLOC_FREE(frame);
	if (!NT_STATUS_IS_OK(status)) {
		cli_set_error(cli, status);
	}
	return status;
}

/****************************************************************************
 Truncate a file to a specified size
****************************************************************************/

bool cli_ftruncate(struct cli_state *cli, uint16_t fnum, uint64_t size)
{
	unsigned int param_len = 6;
	unsigned int data_len = 8;
	uint16_t setup = TRANSACT2_SETFILEINFO;
	char param[6];
	unsigned char data[8];
	char *rparam=NULL, *rdata=NULL;
	int saved_timeout = cli->timeout;

	SSVAL(param,0,fnum);
	SSVAL(param,2,SMB_SET_FILE_END_OF_FILE_INFO);
	SSVAL(param,4,0);

        SBVAL(data, 0, size);

	if (!cli_send_trans(cli, SMBtrans2,
                            NULL,                    /* name */
                            -1, 0,                   /* fid, flags */
                            &setup, 1, 0,            /* setup, length, max */
                            param, param_len, 2,     /* param, length, max */
                            (char *)&data,  data_len,/* data, length, ... */
                            cli->max_xmit)) {        /* ... max */
		cli->timeout = saved_timeout;
		return False;
	}

	if (!cli_receive_trans(cli, SMBtrans2,
				&rparam, &param_len,
				&rdata, &data_len)) {
		cli->timeout = saved_timeout;
		SAFE_FREE(rdata);
		SAFE_FREE(rparam);
		return False;
	}

	cli->timeout = saved_timeout;

	SAFE_FREE(rdata);
	SAFE_FREE(rparam);

	return True;
}


/****************************************************************************
 send a lock with a specified locktype
 this is used for testing LOCKING_ANDX_CANCEL_LOCK
****************************************************************************/

NTSTATUS cli_locktype(struct cli_state *cli, uint16_t fnum,
		      uint32_t offset, uint32_t len,
		      int timeout, unsigned char locktype)
{
	char *p;
	int saved_timeout = cli->timeout;

	memset(cli->outbuf,'\0',smb_size);
	memset(cli->inbuf,'\0', smb_size);

	cli_set_message(cli->outbuf,8,0,True);

	SCVAL(cli->outbuf,smb_com,SMBlockingX);
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);

	SCVAL(cli->outbuf,smb_vwv0,0xFF);
	SSVAL(cli->outbuf,smb_vwv2,fnum);
	SCVAL(cli->outbuf,smb_vwv3,locktype);
	SIVALS(cli->outbuf, smb_vwv4, timeout);
	SSVAL(cli->outbuf,smb_vwv6,0);
	SSVAL(cli->outbuf,smb_vwv7,1);

	p = smb_buf(cli->outbuf);
	SSVAL(p, 0, cli->pid);
	SIVAL(p, 2, offset);
	SIVAL(p, 6, len);

	p += 10;

	cli_setup_bcc(cli, p);

	cli_send_smb(cli);

	if (timeout != 0) {
		cli->timeout = (timeout == -1) ? 0x7FFFFFFF : (timeout + 2*1000);
	}

	if (!cli_receive_smb(cli)) {
		cli->timeout = saved_timeout;
		return NT_STATUS_UNSUCCESSFUL;
	}

	cli->timeout = saved_timeout;

	return cli_nt_error(cli);
}

/****************************************************************************
 Lock a file.
 note that timeout is in units of 2 milliseconds
****************************************************************************/

bool cli_lock(struct cli_state *cli, uint16_t fnum,
	      uint32_t offset, uint32_t len, int timeout, enum brl_type lock_type)
{
	char *p;
	int saved_timeout = cli->timeout;

	memset(cli->outbuf,'\0',smb_size);
	memset(cli->inbuf,'\0', smb_size);

	cli_set_message(cli->outbuf,8,0,True);

	SCVAL(cli->outbuf,smb_com,SMBlockingX);
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);

	SCVAL(cli->outbuf,smb_vwv0,0xFF);
	SSVAL(cli->outbuf,smb_vwv2,fnum);
	SCVAL(cli->outbuf,smb_vwv3,(lock_type == READ_LOCK? 1 : 0));
	SIVALS(cli->outbuf, smb_vwv4, timeout);
	SSVAL(cli->outbuf,smb_vwv6,0);
	SSVAL(cli->outbuf,smb_vwv7,1);

	p = smb_buf(cli->outbuf);
	SSVAL(p, 0, cli->pid);
	SIVAL(p, 2, offset);
	SIVAL(p, 6, len);

	p += 10;

	cli_setup_bcc(cli, p);

	cli_send_smb(cli);

	if (timeout != 0) {
		cli->timeout = (timeout == -1) ? 0x7FFFFFFF : (timeout*2 + 5*1000);
	}

	if (!cli_receive_smb(cli)) {
		cli->timeout = saved_timeout;
		return False;
	}

	cli->timeout = saved_timeout;

	if (cli_is_error(cli)) {
		return False;
	}

	return True;
}

/****************************************************************************
 Unlock a file.
****************************************************************************/

bool cli_unlock(struct cli_state *cli, uint16_t fnum, uint32_t offset, uint32_t len)
{
	char *p;

	memset(cli->outbuf,'\0',smb_size);
	memset(cli->inbuf,'\0',smb_size);

	cli_set_message(cli->outbuf,8,0,True);

	SCVAL(cli->outbuf,smb_com,SMBlockingX);
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);

	SCVAL(cli->outbuf,smb_vwv0,0xFF);
	SSVAL(cli->outbuf,smb_vwv2,fnum);
	SCVAL(cli->outbuf,smb_vwv3,0);
	SIVALS(cli->outbuf, smb_vwv4, 0);
	SSVAL(cli->outbuf,smb_vwv6,1);
	SSVAL(cli->outbuf,smb_vwv7,0);

	p = smb_buf(cli->outbuf);
	SSVAL(p, 0, cli->pid);
	SIVAL(p, 2, offset);
	SIVAL(p, 6, len);
	p += 10;
	cli_setup_bcc(cli, p);
	cli_send_smb(cli);
	if (!cli_receive_smb(cli)) {
		return False;
	}

	if (cli_is_error(cli)) {
		return False;
	}

	return True;
}

/****************************************************************************
 Lock a file with 64 bit offsets.
****************************************************************************/

bool cli_lock64(struct cli_state *cli, uint16_t fnum,
		uint64_t offset, uint64_t len, int timeout, enum brl_type lock_type)
{
	char *p;
        int saved_timeout = cli->timeout;
	int ltype;

	if (! (cli->capabilities & CAP_LARGE_FILES)) {
		return cli_lock(cli, fnum, offset, len, timeout, lock_type);
	}

	ltype = (lock_type == READ_LOCK? 1 : 0);
	ltype |= LOCKING_ANDX_LARGE_FILES;

	memset(cli->outbuf,'\0',smb_size);
	memset(cli->inbuf,'\0', smb_size);

	cli_set_message(cli->outbuf,8,0,True);

	SCVAL(cli->outbuf,smb_com,SMBlockingX);
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);

	SCVAL(cli->outbuf,smb_vwv0,0xFF);
	SSVAL(cli->outbuf,smb_vwv2,fnum);
	SCVAL(cli->outbuf,smb_vwv3,ltype);
	SIVALS(cli->outbuf, smb_vwv4, timeout);
	SSVAL(cli->outbuf,smb_vwv6,0);
	SSVAL(cli->outbuf,smb_vwv7,1);

	p = smb_buf(cli->outbuf);
	SIVAL(p, 0, cli->pid);
	SOFF_T_R(p, 4, offset);
	SOFF_T_R(p, 12, len);
	p += 20;

	cli_setup_bcc(cli, p);
	cli_send_smb(cli);

	if (timeout != 0) {
		cli->timeout = (timeout == -1) ? 0x7FFFFFFF : (timeout + 5*1000);
	}

	if (!cli_receive_smb(cli)) {
                cli->timeout = saved_timeout;
		return False;
	}

	cli->timeout = saved_timeout;

	if (cli_is_error(cli)) {
		return False;
	}

	return True;
}

/****************************************************************************
 Unlock a file with 64 bit offsets.
****************************************************************************/

bool cli_unlock64(struct cli_state *cli, uint16_t fnum, uint64_t offset, uint64_t len)
{
	char *p;

	if (! (cli->capabilities & CAP_LARGE_FILES)) {
		return cli_unlock(cli, fnum, offset, len);
	}

	memset(cli->outbuf,'\0',smb_size);
	memset(cli->inbuf,'\0',smb_size);

	cli_set_message(cli->outbuf,8,0,True);

	SCVAL(cli->outbuf,smb_com,SMBlockingX);
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);

	SCVAL(cli->outbuf,smb_vwv0,0xFF);
	SSVAL(cli->outbuf,smb_vwv2,fnum);
	SCVAL(cli->outbuf,smb_vwv3,LOCKING_ANDX_LARGE_FILES);
	SIVALS(cli->outbuf, smb_vwv4, 0);
	SSVAL(cli->outbuf,smb_vwv6,1);
	SSVAL(cli->outbuf,smb_vwv7,0);

	p = smb_buf(cli->outbuf);
	SIVAL(p, 0, cli->pid);
	SOFF_T_R(p, 4, offset);
	SOFF_T_R(p, 12, len);
	p += 20;
	cli_setup_bcc(cli, p);
	cli_send_smb(cli);
	if (!cli_receive_smb(cli)) {
		return False;
	}

	if (cli_is_error(cli)) {
		return False;
	}

	return True;
}

/****************************************************************************
 Get/unlock a POSIX lock on a file - internal function.
****************************************************************************/

static bool cli_posix_lock_internal(struct cli_state *cli, uint16_t fnum,
		uint64_t offset, uint64_t len, bool wait_lock, enum brl_type lock_type)
{
	unsigned int param_len = 4;
	unsigned int data_len = POSIX_LOCK_DATA_SIZE;
	uint16_t setup = TRANSACT2_SETFILEINFO;
	char param[4];
	unsigned char data[POSIX_LOCK_DATA_SIZE];
	char *rparam=NULL, *rdata=NULL;
	int saved_timeout = cli->timeout;

	SSVAL(param,0,fnum);
	SSVAL(param,2,SMB_SET_POSIX_LOCK);

	switch (lock_type) {
		case READ_LOCK:
			SSVAL(data, POSIX_LOCK_TYPE_OFFSET, POSIX_LOCK_TYPE_READ);
			break;
		case WRITE_LOCK:
			SSVAL(data, POSIX_LOCK_TYPE_OFFSET, POSIX_LOCK_TYPE_WRITE);
			break;
		case UNLOCK_LOCK:
			SSVAL(data, POSIX_LOCK_TYPE_OFFSET, POSIX_LOCK_TYPE_UNLOCK);
			break;
		default:
			return False;
	}

	if (wait_lock) {
		SSVAL(data, POSIX_LOCK_FLAGS_OFFSET, POSIX_LOCK_FLAG_WAIT);
		cli->timeout = 0x7FFFFFFF;
	} else {
		SSVAL(data, POSIX_LOCK_FLAGS_OFFSET, POSIX_LOCK_FLAG_NOWAIT);
	}

	SIVAL(data, POSIX_LOCK_PID_OFFSET, cli->pid);
	SOFF_T(data, POSIX_LOCK_START_OFFSET, offset);
	SOFF_T(data, POSIX_LOCK_LEN_OFFSET, len);

	if (!cli_send_trans(cli, SMBtrans2,
			NULL,                        /* name */
			-1, 0,                          /* fid, flags */
			&setup, 1, 0,                   /* setup, length, max */
			param, param_len, 2,            /* param, length, max */
			(char *)&data,  data_len, cli->max_xmit /* data, length, max */
			)) {
		cli->timeout = saved_timeout;
		return False;
	}

	if (!cli_receive_trans(cli, SMBtrans2,
				&rparam, &param_len,
				&rdata, &data_len)) {
		cli->timeout = saved_timeout;
		SAFE_FREE(rdata);
		SAFE_FREE(rparam);
		return False;
	}

	cli->timeout = saved_timeout;

	SAFE_FREE(rdata);
	SAFE_FREE(rparam);

	return True;
}

/****************************************************************************
 POSIX Lock a file.
****************************************************************************/

bool cli_posix_lock(struct cli_state *cli, uint16_t fnum,
			uint64_t offset, uint64_t len,
			bool wait_lock, enum brl_type lock_type)
{
	if (lock_type != READ_LOCK && lock_type != WRITE_LOCK) {
		return False;
	}
	return cli_posix_lock_internal(cli, fnum, offset, len, wait_lock, lock_type);
}

/****************************************************************************
 POSIX Unlock a file.
****************************************************************************/

bool cli_posix_unlock(struct cli_state *cli, uint16_t fnum, uint64_t offset, uint64_t len)
{
	return cli_posix_lock_internal(cli, fnum, offset, len, False, UNLOCK_LOCK);
}

/****************************************************************************
 POSIX Get any lock covering a file.
****************************************************************************/

bool cli_posix_getlock(struct cli_state *cli, uint16_t fnum, uint64_t *poffset, uint64_t *plen)
{
	return True;
}

/****************************************************************************
 Do a SMBgetattrE call.
****************************************************************************/

static void cli_getattrE_done(struct tevent_req *subreq);

struct cli_getattrE_state {
	uint16_t vwv[1];
	int zone_offset;
	uint16_t attr;
	SMB_OFF_T size;
	time_t change_time;
	time_t access_time;
	time_t write_time;
};

struct tevent_req *cli_getattrE_send(TALLOC_CTX *mem_ctx,
				struct event_context *ev,
				struct cli_state *cli,
				uint16_t fnum)
{
	struct tevent_req *req = NULL, *subreq = NULL;
	struct cli_getattrE_state *state = NULL;
	uint8_t additional_flags = 0;

	req = tevent_req_create(mem_ctx, &state, struct cli_getattrE_state);
	if (req == NULL) {
		return NULL;
	}

	state->zone_offset = cli->serverzone;
	SSVAL(state->vwv+0,0,fnum);

	subreq = cli_smb_send(state, ev, cli, SMBgetattrE, additional_flags,
			      1, state->vwv, 0, NULL);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_getattrE_done, req);
	return req;
}

static void cli_getattrE_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_getattrE_state *state = tevent_req_data(
		req, struct cli_getattrE_state);
	uint8_t wct;
	uint16_t *vwv = NULL;
	NTSTATUS status;

	status = cli_smb_recv(subreq, 11, &wct, &vwv, NULL, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}

	state->size = (SMB_OFF_T)IVAL(vwv+6,0);
	state->attr = SVAL(vwv+10,0);
	state->change_time = make_unix_date2(vwv+0, state->zone_offset);
	state->access_time = make_unix_date2(vwv+2, state->zone_offset);
	state->write_time = make_unix_date2(vwv+4, state->zone_offset);

	TALLOC_FREE(subreq);
	tevent_req_done(req);
}

NTSTATUS cli_getattrE_recv(struct tevent_req *req,
			uint16_t *attr,
			SMB_OFF_T *size,
			time_t *change_time,
			time_t *access_time,
			time_t *write_time)
{
	struct cli_getattrE_state *state = tevent_req_data(
				req, struct cli_getattrE_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	if (attr) {
		*attr = state->attr;
	}
	if (size) {
		*size = state->size;
	}
	if (change_time) {
		*change_time = state->change_time;
	}
	if (access_time) {
		*access_time = state->access_time;
	}
	if (write_time) {
		*write_time = state->write_time;
	}
	return NT_STATUS_OK;
}

NTSTATUS cli_getattrE(struct cli_state *cli,
			uint16_t fnum,
			uint16_t *attr,
			SMB_OFF_T *size,
			time_t *change_time,
			time_t *access_time,
			time_t *write_time)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct event_context *ev = NULL;
	struct tevent_req *req = NULL;
	NTSTATUS status = NT_STATUS_OK;

	if (cli_has_async_calls(cli)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	ev = event_context_init(frame);
	if (ev == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	req = cli_getattrE_send(frame, ev, cli, fnum);
	if (req == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	if (!tevent_req_poll(req, ev)) {
		status = map_nt_error_from_unix(errno);
		goto fail;
	}

	status = cli_getattrE_recv(req,
					attr,
					size,
					change_time,
					access_time,
					write_time);

 fail:
	TALLOC_FREE(frame);
	if (!NT_STATUS_IS_OK(status)) {
		cli_set_error(cli, status);
	}
	return status;
}

/****************************************************************************
 Do a SMBgetatr call
****************************************************************************/

static void cli_getatr_done(struct tevent_req *subreq);

struct cli_getatr_state {
	int zone_offset;
	uint16_t attr;
	SMB_OFF_T size;
	time_t write_time;
};

struct tevent_req *cli_getatr_send(TALLOC_CTX *mem_ctx,
				struct event_context *ev,
				struct cli_state *cli,
				const char *fname)
{
	struct tevent_req *req = NULL, *subreq = NULL;
	struct cli_getatr_state *state = NULL;
	uint8_t additional_flags = 0;
	uint8_t *bytes = NULL;

	req = tevent_req_create(mem_ctx, &state, struct cli_getatr_state);
	if (req == NULL) {
		return NULL;
	}

	state->zone_offset = cli->serverzone;

	bytes = talloc_array(state, uint8_t, 1);
	if (tevent_req_nomem(bytes, req)) {
		return tevent_req_post(req, ev);
	}
	bytes[0] = 4;
	bytes = smb_bytes_push_str(bytes, cli_ucs2(cli), fname,
				   strlen(fname)+1, NULL);

	if (tevent_req_nomem(bytes, req)) {
		return tevent_req_post(req, ev);
	}

	subreq = cli_smb_send(state, ev, cli, SMBgetatr, additional_flags,
			      0, NULL, talloc_get_size(bytes), bytes);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_getatr_done, req);
	return req;
}

static void cli_getatr_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_getatr_state *state = tevent_req_data(
		req, struct cli_getatr_state);
	uint8_t wct;
	uint16_t *vwv = NULL;
	NTSTATUS status;

	status = cli_smb_recv(subreq, 4, &wct, &vwv, NULL, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}

	state->attr = SVAL(vwv+0,0);
	state->size = (SMB_OFF_T)IVAL(vwv+3,0);
	state->write_time = make_unix_date3(vwv+1, state->zone_offset);

	TALLOC_FREE(subreq);
	tevent_req_done(req);
}

NTSTATUS cli_getatr_recv(struct tevent_req *req,
			uint16_t *attr,
			SMB_OFF_T *size,
			time_t *write_time)
{
	struct cli_getatr_state *state = tevent_req_data(
				req, struct cli_getatr_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	if (attr) {
		*attr = state->attr;
	}
	if (size) {
		*size = state->size;
	}
	if (write_time) {
		*write_time = state->write_time;
	}
	return NT_STATUS_OK;
}

NTSTATUS cli_getatr(struct cli_state *cli,
			const char *fname,
			uint16_t *attr,
			SMB_OFF_T *size,
			time_t *write_time)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct event_context *ev = NULL;
	struct tevent_req *req = NULL;
	NTSTATUS status = NT_STATUS_OK;

	if (cli_has_async_calls(cli)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	ev = event_context_init(frame);
	if (ev == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	req = cli_getatr_send(frame, ev, cli, fname);
	if (req == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	if (!tevent_req_poll(req, ev)) {
		status = map_nt_error_from_unix(errno);
		goto fail;
	}

	status = cli_getatr_recv(req,
				attr,
				size,
				write_time);

 fail:
	TALLOC_FREE(frame);
	if (!NT_STATUS_IS_OK(status)) {
		cli_set_error(cli, status);
	}
	return status;
}

/****************************************************************************
 Do a SMBsetattrE call.
****************************************************************************/

static void cli_setattrE_done(struct tevent_req *subreq);

struct cli_setattrE_state {
	int dummy;
};

struct tevent_req *cli_setattrE_send(TALLOC_CTX *mem_ctx,
				struct event_context *ev,
				struct cli_state *cli,
				uint16_t fnum,
				time_t change_time,
				time_t access_time,
				time_t write_time)
{
	struct tevent_req *req = NULL, *subreq = NULL;
	struct cli_setattrE_state *state = NULL;
	uint8_t additional_flags = 0;
	uint16_t vwv[7];

	req = tevent_req_create(mem_ctx, &state, struct cli_setattrE_state);
	if (req == NULL) {
		return NULL;
	}

	memset(vwv, '\0', sizeof(vwv));
	SSVAL(vwv+0, 0, fnum);
	cli_put_dos_date2(cli, (char *)&vwv[1], 0, change_time);
	cli_put_dos_date2(cli, (char *)&vwv[3], 0, access_time);
	cli_put_dos_date2(cli, (char *)&vwv[5], 0, write_time);

	subreq = cli_smb_send(state, ev, cli, SMBsetattrE, additional_flags,
			      7, vwv, 0, NULL);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_setattrE_done, req);
	return req;
}

static void cli_setattrE_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	NTSTATUS status;

	status = cli_smb_recv(subreq, 0, NULL, NULL, NULL, NULL);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}
	tevent_req_done(req);
}

NTSTATUS cli_setattrE_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

NTSTATUS cli_setattrE(struct cli_state *cli,
			uint16_t fnum,
			time_t change_time,
			time_t access_time,
			time_t write_time)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct event_context *ev = NULL;
	struct tevent_req *req = NULL;
	NTSTATUS status = NT_STATUS_OK;

	if (cli_has_async_calls(cli)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	ev = event_context_init(frame);
	if (ev == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	req = cli_setattrE_send(frame, ev,
			cli,
			fnum,
			change_time,
			access_time,
			write_time);

	if (req == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	if (!tevent_req_poll(req, ev)) {
		status = map_nt_error_from_unix(errno);
		goto fail;
	}

	status = cli_setattrE_recv(req);

 fail:
	TALLOC_FREE(frame);
	if (!NT_STATUS_IS_OK(status)) {
		cli_set_error(cli, status);
	}
	return status;
}

/****************************************************************************
 Do a SMBsetatr call.
****************************************************************************/

static void cli_setatr_done(struct tevent_req *subreq);

struct cli_setatr_state {
	uint16_t vwv[8];
};

struct tevent_req *cli_setatr_send(TALLOC_CTX *mem_ctx,
				struct event_context *ev,
				struct cli_state *cli,
				const char *fname,
				uint16_t attr,
				time_t mtime)
{
	struct tevent_req *req = NULL, *subreq = NULL;
	struct cli_setatr_state *state = NULL;
	uint8_t additional_flags = 0;
	uint8_t *bytes = NULL;

	req = tevent_req_create(mem_ctx, &state, struct cli_setatr_state);
	if (req == NULL) {
		return NULL;
	}

	memset(state->vwv, '\0', sizeof(state->vwv));
	SSVAL(state->vwv+0, 0, attr);
	cli_put_dos_date3(cli, (char *)&state->vwv[1], 0, mtime);

	bytes = talloc_array(state, uint8_t, 1);
	if (tevent_req_nomem(bytes, req)) {
		return tevent_req_post(req, ev);
	}
	bytes[0] = 4;
	bytes = smb_bytes_push_str(bytes, cli_ucs2(cli), fname,
				   strlen(fname)+1, NULL);
	if (tevent_req_nomem(bytes, req)) {
		return tevent_req_post(req, ev);
	}
	bytes = TALLOC_REALLOC_ARRAY(state, bytes, uint8_t,
			talloc_get_size(bytes)+1);
	if (tevent_req_nomem(bytes, req)) {
		return tevent_req_post(req, ev);
	}

	bytes[talloc_get_size(bytes)-1] = 4;
	bytes = smb_bytes_push_str(bytes, cli_ucs2(cli), "",
				   1, NULL);
	if (tevent_req_nomem(bytes, req)) {
		return tevent_req_post(req, ev);
	}

	subreq = cli_smb_send(state, ev, cli, SMBsetatr, additional_flags,
			      8, state->vwv, talloc_get_size(bytes), bytes);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_setatr_done, req);
	return req;
}

static void cli_setatr_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	NTSTATUS status;

	status = cli_smb_recv(subreq, 0, NULL, NULL, NULL, NULL);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}
	tevent_req_done(req);
}

NTSTATUS cli_setatr_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

NTSTATUS cli_setatr(struct cli_state *cli,
		const char *fname,
		uint16_t attr,
		time_t mtime)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct event_context *ev = NULL;
	struct tevent_req *req = NULL;
	NTSTATUS status = NT_STATUS_OK;

	if (cli_has_async_calls(cli)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	ev = event_context_init(frame);
	if (ev == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	req = cli_setatr_send(frame, ev, cli, fname, attr, mtime);
	if (req == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	if (!tevent_req_poll(req, ev)) {
		status = map_nt_error_from_unix(errno);
		goto fail;
	}

	status = cli_setatr_recv(req);

 fail:
	TALLOC_FREE(frame);
	if (!NT_STATUS_IS_OK(status)) {
		cli_set_error(cli, status);
	}
	return status;
}

/****************************************************************************
 Check for existance of a dir.
****************************************************************************/

static void cli_chkpath_done(struct tevent_req *subreq);

struct cli_chkpath_state {
	int dummy;
};

struct tevent_req *cli_chkpath_send(TALLOC_CTX *mem_ctx,
				  struct event_context *ev,
				  struct cli_state *cli,
				  const char *fname)
{
	struct tevent_req *req = NULL, *subreq = NULL;
	struct cli_chkpath_state *state = NULL;
	uint8_t additional_flags = 0;
	uint8_t *bytes = NULL;

	req = tevent_req_create(mem_ctx, &state, struct cli_chkpath_state);
	if (req == NULL) {
		return NULL;
	}

	bytes = talloc_array(state, uint8_t, 1);
	if (tevent_req_nomem(bytes, req)) {
		return tevent_req_post(req, ev);
	}
	bytes[0] = 4;
	bytes = smb_bytes_push_str(bytes, cli_ucs2(cli), fname,
				   strlen(fname)+1, NULL);

	if (tevent_req_nomem(bytes, req)) {
		return tevent_req_post(req, ev);
	}

	subreq = cli_smb_send(state, ev, cli, SMBcheckpath, additional_flags,
			      0, NULL, talloc_get_size(bytes), bytes);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_chkpath_done, req);
	return req;
}

static void cli_chkpath_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	NTSTATUS status;

	status = cli_smb_recv(subreq, 0, NULL, NULL, NULL, NULL);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}
	tevent_req_done(req);
}

NTSTATUS cli_chkpath_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

NTSTATUS cli_chkpath(struct cli_state *cli, const char *path)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct event_context *ev = NULL;
	struct tevent_req *req = NULL;
	char *path2 = NULL;
	NTSTATUS status = NT_STATUS_OK;

	if (cli_has_async_calls(cli)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	path2 = talloc_strdup(frame, path);
	if (!path2) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}
	trim_char(path2,'\0','\\');
	if (!*path2) {
		path2 = talloc_strdup(frame, "\\");
		if (!path2) {
			status = NT_STATUS_NO_MEMORY;
			goto fail;
		}
	}

	ev = event_context_init(frame);
	if (ev == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	req = cli_chkpath_send(frame, ev, cli, path2);
	if (req == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	if (!tevent_req_poll(req, ev)) {
		status = map_nt_error_from_unix(errno);
		goto fail;
	}

	status = cli_chkpath_recv(req);

 fail:
	TALLOC_FREE(frame);
	if (!NT_STATUS_IS_OK(status)) {
		cli_set_error(cli, status);
	}
	return status;
}

/****************************************************************************
 Query disk space.
****************************************************************************/

static void cli_dskattr_done(struct tevent_req *subreq);

struct cli_dskattr_state {
	int bsize;
	int total;
	int avail;
};

struct tevent_req *cli_dskattr_send(TALLOC_CTX *mem_ctx,
				  struct event_context *ev,
				  struct cli_state *cli)
{
	struct tevent_req *req = NULL, *subreq = NULL;
	struct cli_dskattr_state *state = NULL;
	uint8_t additional_flags = 0;

	req = tevent_req_create(mem_ctx, &state, struct cli_dskattr_state);
	if (req == NULL) {
		return NULL;
	}

	subreq = cli_smb_send(state, ev, cli, SMBdskattr, additional_flags,
			      0, NULL, 0, NULL);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_dskattr_done, req);
	return req;
}

static void cli_dskattr_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_dskattr_state *state = tevent_req_data(
		req, struct cli_dskattr_state);
	uint8_t wct;
	uint16_t *vwv = NULL;
	NTSTATUS status;

	status = cli_smb_recv(subreq, 4, &wct, &vwv, NULL, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}
	state->bsize = SVAL(vwv+1, 0)*SVAL(vwv+2,0);
	state->total = SVAL(vwv+0, 0);
	state->avail = SVAL(vwv+3, 0);
	TALLOC_FREE(subreq);
	tevent_req_done(req);
}

NTSTATUS cli_dskattr_recv(struct tevent_req *req, int *bsize, int *total, int *avail)
{
	struct cli_dskattr_state *state = tevent_req_data(
				req, struct cli_dskattr_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	*bsize = state->bsize;
	*total = state->total;
	*avail = state->avail;
	return NT_STATUS_OK;
}

NTSTATUS cli_dskattr(struct cli_state *cli, int *bsize, int *total, int *avail)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct event_context *ev = NULL;
	struct tevent_req *req = NULL;
	NTSTATUS status = NT_STATUS_OK;

	if (cli_has_async_calls(cli)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	ev = event_context_init(frame);
	if (ev == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	req = cli_dskattr_send(frame, ev, cli);
	if (req == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	if (!tevent_req_poll(req, ev)) {
		status = map_nt_error_from_unix(errno);
		goto fail;
	}

	status = cli_dskattr_recv(req, bsize, total, avail);

 fail:
	TALLOC_FREE(frame);
	if (!NT_STATUS_IS_OK(status)) {
		cli_set_error(cli, status);
	}
	return status;
}

/****************************************************************************
 Create and open a temporary file.
****************************************************************************/

int cli_ctemp(struct cli_state *cli, const char *path, char **tmp_path)
{
	int len;
	char *p;

	memset(cli->outbuf,'\0',smb_size);
	memset(cli->inbuf,'\0',smb_size);

	cli_set_message(cli->outbuf,3,0,True);

	SCVAL(cli->outbuf,smb_com,SMBctemp);
	SSVAL(cli->outbuf,smb_tid,cli->cnum);
	cli_setup_packet(cli);

	SSVAL(cli->outbuf,smb_vwv0,0);
	SIVALS(cli->outbuf,smb_vwv1,-1);

	p = smb_buf(cli->outbuf);
	*p++ = 4;
	p += clistr_push(cli, p, path,
			cli->bufsize - PTR_DIFF(p,cli->outbuf), STR_TERMINATE);

	cli_setup_bcc(cli, p);

	cli_send_smb(cli);
	if (!cli_receive_smb(cli)) {
		return -1;
	}

	if (cli_is_error(cli)) {
		return -1;
	}

	/* despite the spec, the result has a -1, followed by
	   length, followed by name */
	p = smb_buf(cli->inbuf);
	p += 4;
	len = smb_buflen(cli->inbuf) - 4;
	if (len <= 0 || len > PATH_MAX) return -1;

	if (tmp_path) {
		char *path2 = SMB_MALLOC_ARRAY(char, len+1);
		if (!path2) {
			return -1;
		}
		clistr_pull(cli->inbuf, path2, p,
			    len+1, len, STR_ASCII);
		*tmp_path = path2;
	}

	return SVAL(cli->inbuf,smb_vwv0);
}

/*
   send a raw ioctl - used by the torture code
*/
NTSTATUS cli_raw_ioctl(struct cli_state *cli, uint16_t fnum, uint32_t code, DATA_BLOB *blob)
{
	memset(cli->outbuf,'\0',smb_size);
	memset(cli->inbuf,'\0',smb_size);

	cli_set_message(cli->outbuf, 3, 0, True);
	SCVAL(cli->outbuf,smb_com,SMBioctl);
	cli_setup_packet(cli);

	SSVAL(cli->outbuf, smb_vwv0, fnum);
	SSVAL(cli->outbuf, smb_vwv1, code>>16);
	SSVAL(cli->outbuf, smb_vwv2, (code&0xFFFF));

	cli_send_smb(cli);
	if (!cli_receive_smb(cli)) {
		return NT_STATUS_UNEXPECTED_NETWORK_ERROR;
	}

	if (cli_is_error(cli)) {
		return cli_nt_error(cli);
	}

	*blob = data_blob_null;

	return NT_STATUS_OK;
}

/*********************************************************
 Set an extended attribute utility fn.
*********************************************************/

static bool cli_set_ea(struct cli_state *cli, uint16_t setup, char *param, unsigned int param_len,
			const char *ea_name, const char *ea_val, size_t ea_len)
{
	unsigned int data_len = 0;
	char *data = NULL;
	char *rparam=NULL, *rdata=NULL;
	char *p;
	size_t ea_namelen = strlen(ea_name);

	if (ea_namelen == 0 && ea_len == 0) {
		data_len = 4;
		data = (char *)SMB_MALLOC(data_len);
		if (!data) {
			return False;
		}
		p = data;
		SIVAL(p,0,data_len);
	} else {
		data_len = 4 + 4 + ea_namelen + 1 + ea_len;
		data = (char *)SMB_MALLOC(data_len);
		if (!data) {
			return False;
		}
		p = data;
		SIVAL(p,0,data_len);
		p += 4;
		SCVAL(p, 0, 0); /* EA flags. */
		SCVAL(p, 1, ea_namelen);
		SSVAL(p, 2, ea_len);
		memcpy(p+4, ea_name, ea_namelen+1); /* Copy in the name. */
		memcpy(p+4+ea_namelen+1, ea_val, ea_len);
	}

	if (!cli_send_trans(cli, SMBtrans2,
			NULL,                        /* name */
			-1, 0,                          /* fid, flags */
			&setup, 1, 0,                   /* setup, length, max */
			param, param_len, 2,            /* param, length, max */
			data,  data_len, cli->max_xmit /* data, length, max */
			)) {
		SAFE_FREE(data);
		return False;
	}

	if (!cli_receive_trans(cli, SMBtrans2,
			&rparam, &param_len,
			&rdata, &data_len)) {
			SAFE_FREE(data);
		return false;
	}

	SAFE_FREE(data);
	SAFE_FREE(rdata);
	SAFE_FREE(rparam);

	return True;
}

/*********************************************************
 Set an extended attribute on a pathname.
*********************************************************/

bool cli_set_ea_path(struct cli_state *cli, const char *path, const char *ea_name, const char *ea_val, size_t ea_len)
{
	uint16_t setup = TRANSACT2_SETPATHINFO;
	unsigned int param_len = 0;
	char *param;
	size_t srclen = 2*(strlen(path)+1);
	char *p;
	bool ret;

	param = SMB_MALLOC_ARRAY(char, 6+srclen+2);
	if (!param) {
		return false;
	}
	memset(param, '\0', 6);
	SSVAL(param,0,SMB_INFO_SET_EA);
	p = &param[6];

	p += clistr_push(cli, p, path, srclen, STR_TERMINATE);
	param_len = PTR_DIFF(p, param);

	ret = cli_set_ea(cli, setup, param, param_len, ea_name, ea_val, ea_len);
	SAFE_FREE(param);
	return ret;
}

/*********************************************************
 Set an extended attribute on an fnum.
*********************************************************/

bool cli_set_ea_fnum(struct cli_state *cli, uint16_t fnum, const char *ea_name, const char *ea_val, size_t ea_len)
{
	char param[6];
	uint16_t setup = TRANSACT2_SETFILEINFO;

	memset(param, 0, 6);
	SSVAL(param,0,fnum);
	SSVAL(param,2,SMB_INFO_SET_EA);

	return cli_set_ea(cli, setup, param, 6, ea_name, ea_val, ea_len);
}

/*********************************************************
 Get an extended attribute list utility fn.
*********************************************************/

static bool cli_get_ea_list(struct cli_state *cli,
		uint16_t setup, char *param, unsigned int param_len,
		TALLOC_CTX *ctx,
		size_t *pnum_eas,
		struct ea_struct **pea_list)
{
	unsigned int data_len = 0;
	unsigned int rparam_len, rdata_len;
	char *rparam=NULL, *rdata=NULL;
	char *p;
	size_t ea_size;
	size_t num_eas;
	bool ret = False;
	struct ea_struct *ea_list;

	*pnum_eas = 0;
	if (pea_list) {
	 	*pea_list = NULL;
	}

	if (!cli_send_trans(cli, SMBtrans2,
			NULL,           /* Name */
			-1, 0,          /* fid, flags */
			&setup, 1, 0,   /* setup, length, max */
			param, param_len, 10, /* param, length, max */
			NULL, data_len, cli->max_xmit /* data, length, max */
				)) {
		return False;
	}

	if (!cli_receive_trans(cli, SMBtrans2,
			&rparam, &rparam_len,
			&rdata, &rdata_len)) {
		return False;
	}

	if (!rdata || rdata_len < 4) {
		goto out;
	}

	ea_size = (size_t)IVAL(rdata,0);
	if (ea_size > rdata_len) {
		goto out;
	}

	if (ea_size == 0) {
		/* No EA's present. */
		ret = True;
		goto out;
	}

	p = rdata + 4;
	ea_size -= 4;

	/* Validate the EA list and count it. */
	for (num_eas = 0; ea_size >= 4; num_eas++) {
		unsigned int ea_namelen = CVAL(p,1);
		unsigned int ea_valuelen = SVAL(p,2);
		if (ea_namelen == 0) {
			goto out;
		}
		if (4 + ea_namelen + 1 + ea_valuelen > ea_size) {
			goto out;
		}
		ea_size -= 4 + ea_namelen + 1 + ea_valuelen;
		p += 4 + ea_namelen + 1 + ea_valuelen;
	}

	if (num_eas == 0) {
		ret = True;
		goto out;
	}

	*pnum_eas = num_eas;
	if (!pea_list) {
		/* Caller only wants number of EA's. */
		ret = True;
		goto out;
	}

	ea_list = TALLOC_ARRAY(ctx, struct ea_struct, num_eas);
	if (!ea_list) {
		goto out;
	}

	ea_size = (size_t)IVAL(rdata,0);
	p = rdata + 4;

	for (num_eas = 0; num_eas < *pnum_eas; num_eas++ ) {
		struct ea_struct *ea = &ea_list[num_eas];
		fstring unix_ea_name;
		unsigned int ea_namelen = CVAL(p,1);
		unsigned int ea_valuelen = SVAL(p,2);

		ea->flags = CVAL(p,0);
		unix_ea_name[0] = '\0';
		pull_ascii_fstring(unix_ea_name, p + 4);
		ea->name = talloc_strdup(ctx, unix_ea_name);
		/* Ensure the value is null terminated (in case it's a string). */
		ea->value = data_blob_talloc(ctx, NULL, ea_valuelen + 1);
		if (!ea->value.data) {
			goto out;
		}
		if (ea_valuelen) {
			memcpy(ea->value.data, p+4+ea_namelen+1, ea_valuelen);
		}
		ea->value.data[ea_valuelen] = 0;
		ea->value.length--;
		p += 4 + ea_namelen + 1 + ea_valuelen;
	}

	*pea_list = ea_list;
	ret = True;

 out :

	SAFE_FREE(rdata);
	SAFE_FREE(rparam);
	return ret;
}

/*********************************************************
 Get an extended attribute list from a pathname.
*********************************************************/

bool cli_get_ea_list_path(struct cli_state *cli, const char *path,
		TALLOC_CTX *ctx,
		size_t *pnum_eas,
		struct ea_struct **pea_list)
{
	uint16_t setup = TRANSACT2_QPATHINFO;
	unsigned int param_len = 0;
	char *param;
	char *p;
	size_t srclen = 2*(strlen(path)+1);
	bool ret;

	param = SMB_MALLOC_ARRAY(char, 6+srclen+2);
	if (!param) {
		return false;
	}
	p = param;
	memset(p, 0, 6);
	SSVAL(p, 0, SMB_INFO_QUERY_ALL_EAS);
	p += 6;
	p += clistr_push(cli, p, path, srclen, STR_TERMINATE);
	param_len = PTR_DIFF(p, param);

	ret = cli_get_ea_list(cli, setup, param, param_len, ctx, pnum_eas, pea_list);
	SAFE_FREE(param);
	return ret;
}

/*********************************************************
 Get an extended attribute list from an fnum.
*********************************************************/

bool cli_get_ea_list_fnum(struct cli_state *cli, uint16_t fnum,
		TALLOC_CTX *ctx,
		size_t *pnum_eas,
		struct ea_struct **pea_list)
{
	uint16_t setup = TRANSACT2_QFILEINFO;
	char param[6];

	memset(param, 0, 6);
	SSVAL(param,0,fnum);
	SSVAL(param,2,SMB_INFO_SET_EA);

	return cli_get_ea_list(cli, setup, param, 6, ctx, pnum_eas, pea_list);
}

/****************************************************************************
 Convert open "flags" arg to uint32_t on wire.
****************************************************************************/

static uint32_t open_flags_to_wire(int flags)
{
	int open_mode = flags & O_ACCMODE;
	uint32_t ret = 0;

	switch (open_mode) {
		case O_WRONLY:
			ret |= SMB_O_WRONLY;
			break;
		case O_RDWR:
			ret |= SMB_O_RDWR;
			break;
		default:
		case O_RDONLY:
			ret |= SMB_O_RDONLY;
			break;
	}

	if (flags & O_CREAT) {
		ret |= SMB_O_CREAT;
	}
	if (flags & O_EXCL) {
		ret |= SMB_O_EXCL;
	}
	if (flags & O_TRUNC) {
		ret |= SMB_O_TRUNC;
	}
#if defined(O_SYNC)
	if (flags & O_SYNC) {
		ret |= SMB_O_SYNC;
	}
#endif /* O_SYNC */
	if (flags & O_APPEND) {
		ret |= SMB_O_APPEND;
	}
#if defined(O_DIRECT)
	if (flags & O_DIRECT) {
		ret |= SMB_O_DIRECT;
	}
#endif
#if defined(O_DIRECTORY)
	if (flags & O_DIRECTORY) {
		ret &= ~(SMB_O_RDONLY|SMB_O_RDWR|SMB_O_WRONLY);
		ret |= SMB_O_DIRECTORY;
	}
#endif
	return ret;
}

/****************************************************************************
 Open a file - POSIX semantics. Returns fnum. Doesn't request oplock.
****************************************************************************/

struct posix_open_state {
	uint16_t setup;
	uint8_t *param;
	uint8_t data[18];
	uint16_t fnum; /* Out */
};

static void cli_posix_open_internal_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
				subreq, struct tevent_req);
	struct posix_open_state *state = tevent_req_data(req, struct posix_open_state);
	NTSTATUS status;
	uint8_t *data;
	uint32_t num_data;

	status = cli_trans_recv(subreq, state, NULL, NULL, NULL, NULL, &data, &num_data);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}
	if (num_data < 12) {
		tevent_req_nterror(req, status);
		return;
	}
	state->fnum = SVAL(data,2);
	tevent_req_done(req);
}

static struct tevent_req *cli_posix_open_internal_send(TALLOC_CTX *mem_ctx,
					struct event_context *ev,
					struct cli_state *cli,
					const char *fname,
					int flags,
					mode_t mode,
					bool is_dir)
{
	struct tevent_req *req = NULL, *subreq = NULL;
	struct posix_open_state *state = NULL;
	uint32_t wire_flags = open_flags_to_wire(flags);

	req = tevent_req_create(mem_ctx, &state, struct posix_open_state);
	if (req == NULL) {
		return NULL;
	}

	/* Setup setup word. */
	SSVAL(&state->setup, 0, TRANSACT2_SETPATHINFO);

	/* Setup param array. */
	state->param = talloc_array(state, uint8_t, 6);
	if (tevent_req_nomem(state->param, req)) {
		return tevent_req_post(req, ev);
	}
	memset(state->param, '\0', 6);
	SSVAL(state->param, 0, SMB_POSIX_PATH_OPEN);

	state->param = trans2_bytes_push_str(state->param, cli_ucs2(cli), fname,
				   strlen(fname)+1, NULL);

	if (tevent_req_nomem(state->param, req)) {
		return tevent_req_post(req, ev);
	}

	/* Setup data words. */
	if (is_dir) {
		wire_flags &= ~(SMB_O_RDONLY|SMB_O_RDWR|SMB_O_WRONLY);
		wire_flags |= SMB_O_DIRECTORY;
	}

	SIVAL(state->data,0,0); /* No oplock. */
	SIVAL(state->data,4,wire_flags);
	SIVAL(state->data,8,unix_perms_to_wire(mode));
	SIVAL(state->data,12,0); /* Top bits of perms currently undefined. */
	SSVAL(state->data,16,SMB_NO_INFO_LEVEL_RETURNED); /* No info level returned. */

	subreq = cli_trans_send(state,			/* mem ctx. */
				ev,			/* event ctx. */
				cli,			/* cli_state. */
				SMBtrans2,		/* cmd. */
				NULL,			/* pipe name. */
				-1,			/* fid. */
				0,			/* function. */
				0,			/* flags. */
				&state->setup,		/* setup. */
				1,			/* num setup uint16_t words. */
				0,			/* max returned setup. */
				state->param,		/* param. */
				talloc_get_size(state->param),/* num param. */
				2,			/* max returned param. */
				state->data,		/* data. */
				18,			/* num data. */
				12);			/* max returned data. */

	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_posix_open_internal_done, req);
	return req;
}

struct tevent_req *cli_posix_open_send(TALLOC_CTX *mem_ctx,
					struct event_context *ev,
					struct cli_state *cli,
					const char *fname,
					int flags,
					mode_t mode)
{
	return cli_posix_open_internal_send(mem_ctx, ev,
				cli, fname, flags, mode, false);
}

NTSTATUS cli_posix_open_recv(struct tevent_req *req, uint16_t *pfnum)
{
	struct posix_open_state *state = tevent_req_data(req, struct posix_open_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	*pfnum = state->fnum;
	return NT_STATUS_OK;
}

/****************************************************************************
 Open - POSIX semantics. Doesn't request oplock.
****************************************************************************/

NTSTATUS cli_posix_open(struct cli_state *cli, const char *fname,
			int flags, mode_t mode, uint16_t *pfnum)
{

	TALLOC_CTX *frame = talloc_stackframe();
	struct event_context *ev = NULL;
	struct tevent_req *req = NULL;
	NTSTATUS status = NT_STATUS_OK;

	if (cli_has_async_calls(cli)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	ev = event_context_init(frame);
	if (ev == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	req = cli_posix_open_send(frame,
				ev,
				cli,
				fname,
				flags,
				mode);
	if (req == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	if (!tevent_req_poll(req, ev)) {
		status = map_nt_error_from_unix(errno);
		goto fail;
	}

	status = cli_posix_open_recv(req, pfnum);

 fail:
	TALLOC_FREE(frame);
	if (!NT_STATUS_IS_OK(status)) {
		cli_set_error(cli, status);
	}
	return status;
}

struct tevent_req *cli_posix_mkdir_send(TALLOC_CTX *mem_ctx,
					struct event_context *ev,
					struct cli_state *cli,
					const char *fname,
					mode_t mode)
{
	return cli_posix_open_internal_send(mem_ctx, ev,
				cli, fname, O_CREAT, mode, true);
}

NTSTATUS cli_posix_mkdir_recv(struct tevent_req *req)
{
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	return NT_STATUS_OK;
}

NTSTATUS cli_posix_mkdir(struct cli_state *cli, const char *fname, mode_t mode)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct event_context *ev = NULL;
	struct tevent_req *req = NULL;
	NTSTATUS status = NT_STATUS_OK;

	if (cli_has_async_calls(cli)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	ev = event_context_init(frame);
	if (ev == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	req = cli_posix_mkdir_send(frame,
				ev,
				cli,
				fname,
				mode);
	if (req == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	if (!tevent_req_poll(req, ev)) {
		status = map_nt_error_from_unix(errno);
		goto fail;
	}

	status = cli_posix_mkdir_recv(req);

 fail:
	TALLOC_FREE(frame);
	if (!NT_STATUS_IS_OK(status)) {
		cli_set_error(cli, status);
	}
	return status;
}

/****************************************************************************
 unlink or rmdir - POSIX semantics.
****************************************************************************/

struct unlink_state {
	uint16_t setup;
	uint8_t data[2];
};

static void cli_posix_unlink_internal_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
				subreq, struct tevent_req);
	struct unlink_state *state = tevent_req_data(req, struct unlink_state);
	NTSTATUS status;

	status = cli_trans_recv(subreq, state, NULL, NULL, NULL, NULL, NULL, NULL);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}
	tevent_req_done(req);
}

static struct tevent_req *cli_posix_unlink_internal_send(TALLOC_CTX *mem_ctx,
					struct event_context *ev,
					struct cli_state *cli,
					const char *fname,
					bool is_dir)
{
	struct tevent_req *req = NULL, *subreq = NULL;
	struct unlink_state *state = NULL;
	uint8_t *param = NULL;

	req = tevent_req_create(mem_ctx, &state, struct unlink_state);
	if (req == NULL) {
		return NULL;
	}

	/* Setup setup word. */
	SSVAL(&state->setup, 0, TRANSACT2_SETPATHINFO);

	/* Setup param array. */
	param = talloc_array(state, uint8_t, 6);
	if (tevent_req_nomem(param, req)) {
		return tevent_req_post(req, ev);
	}
	memset(param, '\0', 6);
	SSVAL(param, 0, SMB_POSIX_PATH_UNLINK);

	param = trans2_bytes_push_str(param, cli_ucs2(cli), fname,
				   strlen(fname)+1, NULL);

	if (tevent_req_nomem(param, req)) {
		return tevent_req_post(req, ev);
	}

	/* Setup data word. */
	SSVAL(state->data, 0, is_dir ? SMB_POSIX_UNLINK_DIRECTORY_TARGET :
			SMB_POSIX_UNLINK_FILE_TARGET);

	subreq = cli_trans_send(state,			/* mem ctx. */
				ev,			/* event ctx. */
				cli,			/* cli_state. */
				SMBtrans2,		/* cmd. */
				NULL,			/* pipe name. */
				-1,			/* fid. */
				0,			/* function. */
				0,			/* flags. */
				&state->setup,		/* setup. */
				1,			/* num setup uint16_t words. */
				0,			/* max returned setup. */
				param,			/* param. */
				talloc_get_size(param),	/* num param. */
				2,			/* max returned param. */
				state->data,		/* data. */
				2,			/* num data. */
				0);			/* max returned data. */

	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_posix_unlink_internal_done, req);
	return req;
}

struct tevent_req *cli_posix_unlink_send(TALLOC_CTX *mem_ctx,
					struct event_context *ev,
					struct cli_state *cli,
					const char *fname)
{
	return cli_posix_unlink_internal_send(mem_ctx, ev, cli, fname, false);
}

NTSTATUS cli_posix_unlink_recv(struct tevent_req *req)
{
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	return NT_STATUS_OK;
}

/****************************************************************************
 unlink - POSIX semantics.
****************************************************************************/

NTSTATUS cli_posix_unlink(struct cli_state *cli, const char *fname)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct event_context *ev = NULL;
	struct tevent_req *req = NULL;
	NTSTATUS status = NT_STATUS_OK;

	if (cli_has_async_calls(cli)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	ev = event_context_init(frame);
	if (ev == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	req = cli_posix_unlink_send(frame,
				ev,
				cli,
				fname);
	if (req == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	if (!tevent_req_poll(req, ev)) {
		status = map_nt_error_from_unix(errno);
		goto fail;
	}

	status = cli_posix_unlink_recv(req);

 fail:
	TALLOC_FREE(frame);
	if (!NT_STATUS_IS_OK(status)) {
		cli_set_error(cli, status);
	}
	return status;
}

/****************************************************************************
 rmdir - POSIX semantics.
****************************************************************************/

struct tevent_req *cli_posix_rmdir_send(TALLOC_CTX *mem_ctx,
					struct event_context *ev,
					struct cli_state *cli,
					const char *fname)
{
	return cli_posix_unlink_internal_send(mem_ctx, ev, cli, fname, true);
}

NTSTATUS cli_posix_rmdir_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	return NT_STATUS_OK;
}

NTSTATUS cli_posix_rmdir(struct cli_state *cli, const char *fname)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct event_context *ev = NULL;
	struct tevent_req *req = NULL;
	NTSTATUS status = NT_STATUS_OK;

	if (cli_has_async_calls(cli)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	ev = event_context_init(frame);
	if (ev == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	req = cli_posix_rmdir_send(frame,
				ev,
				cli,
				fname);
	if (req == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	if (!tevent_req_poll(req, ev)) {
		status = map_nt_error_from_unix(errno);
		goto fail;
	}

	status = cli_posix_rmdir_recv(req, frame);

 fail:
	TALLOC_FREE(frame);
	if (!NT_STATUS_IS_OK(status)) {
		cli_set_error(cli, status);
	}
	return status;
}
