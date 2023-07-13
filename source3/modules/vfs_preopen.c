/*
 * Force a readahead of files by opening them and reading the first bytes
 *
 * Copyright (C) Volker Lendecke 2008
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "includes.h"
#include "system/filesys.h"
#include "smbd/smbd.h"
#include "lib/util/sys_rw.h"
#include "lib/util/sys_rw_data.h"
#include "lib/util/smb_strtox.h"
#include "lib/util_matching.h"
#include "lib/global_contexts.h"

static int vfs_preopen_debug_level = DBGC_VFS;

#undef DBGC_CLASS
#define DBGC_CLASS vfs_preopen_debug_level

#define PREOPEN_MAX_DIGITS 19
#define PREOPEN_MAX_NUMBER (uint64_t)9999999999999999999ULL

struct preopen_state;

struct preopen_helper {
	struct preopen_state *state;
	struct tevent_fd *fde;
	pid_t pid;
	int fd;
	bool busy;
};

struct preopen_state {
	int num_helpers;
	struct preopen_helper *helpers;

	size_t to_read;		/* How many bytes to read in children? */
	int queue_max;

	int queue_dbglvl;       /* DBGLVL_DEBUG by default */
	int nomatch_dbglvl;     /* DBGLVL_INFO by default */
	int match_dbglvl;       /* DBGLVL_INFO by default */
	int reset_dbglvl;       /* DBGLVL_INFO by default */
	int nodigits_dbglvl;    /* DBGLVL_WARNING by default */
	int founddigits_dbglvl; /* DBGLVL_NOTICE by default */
	int push_dbglvl;        /* DBGLVL_NOTICE by default */

	char *template_fname;	/* Filename to be sent to children */
	size_t number_start;	/* start offset into "template_fname" */
	int num_digits;		/* How many digits is the number long? */

	uint64_t fnum_sent;	/* last fname sent to children */

	uint64_t fnum_queue_end;/* last fname to be sent, based on
				 * last open call + preopen:queuelen
				 */

	struct samba_path_matching *preopen_names;
	ssize_t last_match_idx; /* remember the last match */
};

static void preopen_helper_destroy(struct preopen_helper *c)
{
	int status;
	TALLOC_FREE(c->fde);
	close(c->fd);
	c->fd = -1;
	kill(c->pid, SIGKILL);
	waitpid(c->pid, &status, 0);
	c->busy = true;
}

static void preopen_queue_run(struct preopen_state *state)
{
	char *pdelimiter;
	char delimiter;

	DBG_PREFIX(state->queue_dbglvl, ("START: "
		   "last_fname[%s] start_offset=%zu num_digits=%d "
		   "last_pushed_num=%"PRIu64" queue_end_num=%"PRIu64" num_helpers=%d\n",
		   state->template_fname,
		   state->number_start,
		   state->num_digits,
		   state->fnum_sent,
		   state->fnum_queue_end,
		   state->num_helpers));

	pdelimiter = state->template_fname + state->number_start
		+ state->num_digits;
	delimiter = *pdelimiter;

	while (state->fnum_sent < state->fnum_queue_end) {

		ssize_t written;
		size_t to_write;
		int helper;

		for (helper=0; helper<state->num_helpers; helper++) {
			if (state->helpers[helper].busy) {
				continue;
			}
			break;
		}
		if (helper == state->num_helpers) {
			/* everyone is busy */
			DBG_PREFIX(state->queue_dbglvl, ("BUSY: "
				   "template_fname[%s] start_offset=%zu num_digits=%d "
				   "last_pushed_num=%"PRIu64" queue_end_num=%"PRIu64"\n",
				   state->template_fname,
				   state->number_start,
				   state->num_digits,
				   state->fnum_sent,
				   state->fnum_queue_end));
			return;
		}

		snprintf(state->template_fname + state->number_start,
			 state->num_digits + 1,
			 "%.*llu", state->num_digits,
			 (long long unsigned int)(state->fnum_sent + 1));
		*pdelimiter = delimiter;

		DBG_PREFIX(state->push_dbglvl, (
			   "PUSH: fullpath[%s] to helper(idx=%d)\n",
			   state->template_fname, helper));

		to_write = talloc_get_size(state->template_fname);
		written = write_data(state->helpers[helper].fd,
				     state->template_fname, to_write);
		state->helpers[helper].busy = true;

		if (written != to_write) {
			preopen_helper_destroy(&state->helpers[helper]);
		}
		state->fnum_sent += 1;
	}
	DBG_PREFIX(state->queue_dbglvl, ("END: "
		   "template_fname[%s] start_offset=%zu num_digits=%d "
		   "last_pushed_num=%"PRIu64" queue_end_num=%"PRIu64"\n",
		   state->template_fname,
		   state->number_start,
		   state->num_digits,
		   state->fnum_sent,
		   state->fnum_queue_end));
}

static void preopen_helper_readable(struct tevent_context *ev,
				    struct tevent_fd *fde, uint16_t flags,
				    void *priv)
{
	struct preopen_helper *helper = (struct preopen_helper *)priv;
	struct preopen_state *state = helper->state;
	ssize_t nread;
	char c;

	if ((flags & TEVENT_FD_READ) == 0) {
		return;
	}

	nread = read(helper->fd, &c, 1);
	if (nread <= 0) {
		preopen_helper_destroy(helper);
		return;
	}

	helper->busy = false;

	DBG_PREFIX(state->queue_dbglvl, ("BEFORE: preopen_queue_run\n"));
	preopen_queue_run(state);
	DBG_PREFIX(state->queue_dbglvl, ("AFTER: preopen_queue_run\n"));
}

static int preopen_helpers_destructor(struct preopen_state *c)
{
	int i;

	for (i=0; i<c->num_helpers; i++) {
		if (c->helpers[i].fd == -1) {
			continue;
		}
		preopen_helper_destroy(&c->helpers[i]);
	}

	return 0;
}

static bool preopen_helper_open_one(int sock_fd, char **pnamebuf,
				    size_t to_read, void *filebuf)
{
	char *namebuf = *pnamebuf;
	ssize_t nread;
	char c = 0;
	int fd;

	nread = 0;

	do {
		ssize_t thistime;

		thistime = read(sock_fd, namebuf + nread,
				talloc_get_size(namebuf) - nread);
		if (thistime <= 0) {
			return false;
		}

		nread += thistime;

		if (nread == talloc_get_size(namebuf)) {
			namebuf = talloc_realloc(
				NULL, namebuf, char,
				talloc_get_size(namebuf) * 2);
			if (namebuf == NULL) {
				return false;
			}
			*pnamebuf = namebuf;
		}
	} while (namebuf[nread - 1] != '\0');

	fd = open(namebuf, O_RDONLY);
	if (fd == -1) {
		goto done;
	}
	nread = read(fd, filebuf, to_read);
	close(fd);

 done:
	sys_write_v(sock_fd, &c, 1);
	return true;
}

static bool preopen_helper(int fd, size_t to_read)
{
	char *namebuf;
	void *readbuf;

	namebuf = talloc_array(NULL, char, 1024);
	if (namebuf == NULL) {
		return false;
	}

	readbuf = talloc_size(NULL, to_read);
	if (readbuf == NULL) {
		TALLOC_FREE(namebuf);
		return false;
	}

	while (preopen_helper_open_one(fd, &namebuf, to_read, readbuf)) {
		;
	}

	TALLOC_FREE(readbuf);
	TALLOC_FREE(namebuf);
	return false;
}

static NTSTATUS preopen_init_helper(struct preopen_helper *h)
{
	int fdpair[2];
	NTSTATUS status;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fdpair) == -1) {
		status = map_nt_error_from_unix(errno);
		DEBUG(10, ("socketpair() failed: %s\n", strerror(errno)));
		return status;
	}

	h->pid = fork();

	if (h->pid == -1) {
		return map_nt_error_from_unix(errno);
	}

	if (h->pid == 0) {
		close(fdpair[0]);
		preopen_helper(fdpair[1], h->state->to_read);
		exit(0);
	}
	close(fdpair[1]);
	h->fd = fdpair[0];
	h->fde = tevent_add_fd(global_event_context(), h->state, h->fd,
			      TEVENT_FD_READ, preopen_helper_readable, h);
	if (h->fde == NULL) {
		close(h->fd);
		h->fd = -1;
		return NT_STATUS_NO_MEMORY;
	}
	h->busy = false;
	return NT_STATUS_OK;
}

static NTSTATUS preopen_init_helpers(TALLOC_CTX *mem_ctx, size_t to_read,
				     int num_helpers, int queue_max,
				     struct preopen_state **presult)
{
	struct preopen_state *result;
	int i;

	result = talloc(mem_ctx, struct preopen_state);
	if (result == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	result->num_helpers = num_helpers;
	result->helpers = talloc_array(result, struct preopen_helper,
				       num_helpers);
	if (result->helpers == NULL) {
		TALLOC_FREE(result);
		return NT_STATUS_NO_MEMORY;
	}

	result->to_read = to_read;
	result->queue_max = queue_max;
	result->template_fname = NULL;
	result->fnum_sent = 0;
	result->fnum_queue_end = 0;

	for (i=0; i<num_helpers; i++) {
		result->helpers[i].state = result;
		result->helpers[i].fd = -1;
	}

	talloc_set_destructor(result, preopen_helpers_destructor);

	for (i=0; i<num_helpers; i++) {
		preopen_init_helper(&result->helpers[i]);
	}

	*presult = result;
	return NT_STATUS_OK;
}

static void preopen_free_helpers(void **ptr)
{
	TALLOC_FREE(*ptr);
}

static struct preopen_state *preopen_state_get(vfs_handle_struct *handle)
{
	struct preopen_state *state;
	NTSTATUS status;
	const char *namelist;

	if (SMB_VFS_HANDLE_TEST_DATA(handle)) {
		SMB_VFS_HANDLE_GET_DATA(handle, state, struct preopen_state,
					return NULL);
		return state;
	}

	namelist = lp_parm_const_string(SNUM(handle->conn), "preopen", "names",
					NULL);

	if (namelist == NULL) {
		return NULL;
	}

	status = preopen_init_helpers(
		NULL,
		lp_parm_int(SNUM(handle->conn), "preopen", "num_bytes", 1),
		lp_parm_int(SNUM(handle->conn), "preopen", "helpers", 1),
		lp_parm_int(SNUM(handle->conn), "preopen", "queuelen", 10),
		&state);
	if (!NT_STATUS_IS_OK(status)) {
		return NULL;
	}

	state->queue_dbglvl = lp_parm_int(SNUM(handle->conn), "preopen", "queue_log_level", DBGLVL_DEBUG);
	state->nomatch_dbglvl = lp_parm_int(SNUM(handle->conn), "preopen", "nomatch_log_level", DBGLVL_INFO);
	state->match_dbglvl = lp_parm_int(SNUM(handle->conn), "preopen", "match_log_level", DBGLVL_INFO);
	state->reset_dbglvl = lp_parm_int(SNUM(handle->conn), "preopen", "reset_log_level", DBGLVL_INFO);
	state->nodigits_dbglvl = lp_parm_int(SNUM(handle->conn), "preopen", "nodigits_log_level", DBGLVL_WARNING);
	state->founddigits_dbglvl = lp_parm_int(SNUM(handle->conn), "preopen", "founddigits_log_level", DBGLVL_NOTICE);
	state->push_dbglvl = lp_parm_int(SNUM(handle->conn), "preopen", "push_log_level", DBGLVL_NOTICE);

	if (lp_parm_bool(SNUM(handle->conn), "preopen", "posix-basic-regex", false)) {
		status = samba_path_matching_regex_sub1_create(state,
							       namelist,
							       &state->preopen_names);
	} else {
		status = samba_path_matching_mswild_create(state,
							   true, /* case_sensitive */
							   namelist,
							   &state->preopen_names);
	}
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(state);
		return NULL;
	}
	state->last_match_idx = -1;

	if (!SMB_VFS_HANDLE_TEST_DATA(handle)) {
		SMB_VFS_HANDLE_SET_DATA(handle, state, preopen_free_helpers,
					struct preopen_state, return NULL);
	}

	return state;
}

static bool preopen_parse_fname(const char *fname, uint64_t *pnum,
				size_t *pstart_idx, int *pnum_digits)
{
	char digits[PREOPEN_MAX_DIGITS+1] = { 0, };
	const char *p;
	char *q = NULL;
	unsigned long long num;
	size_t start_idx = 0;
	int num_digits = -1;
	int error = 0;

	if (*pstart_idx > 0 && *pnum_digits > 0) {
		/*
		 * If the caller knowns
		 * how many digits are expected
		 * and on what position,
		 * we should copy the exact
		 * subset before we start
		 * parsing the string into a number
		 */

		if (*pnum_digits < 1) {
			/*
			 * We need at least one digit
			 */
			return false;
		}
		if (*pnum_digits > PREOPEN_MAX_DIGITS) {
			/*
			 * a string with as much digits as
			 * PREOPEN_MAX_DIGITS is the longest
			 * string that would make any sense for us.
			 *
			 * The rest will be checked via
			 * smb_strtoull().
			 */
			return false;
		}
		p = fname + *pstart_idx;
		memcpy(digits, p, *pnum_digits);
		p = digits;
		start_idx = *pstart_idx;
		goto parse;
	}

	p = strrchr_m(fname, '/');
	if (p == NULL) {
		p = fname;
	}

	p += 1;
	while (p[0] != '\0') {
		if (isdigit(p[0]) && isdigit(p[1]) && isdigit(p[2])) {
			break;
		}
		p += 1;
	}
	if (*p == '\0') {
		/* no digits around */
		return false;
	}

	start_idx = (p - fname);

parse:
	num = smb_strtoull(p, (char **)&q, 10, &error, SMB_STR_STANDARD);
	if (error != 0) {
		return false;
	}

	if (num >= PREOPEN_MAX_NUMBER) {
		/* overflow */
		return false;
	}

	num_digits = (q - p);

	if (*pnum_digits != -1 && *pnum_digits != num_digits) {
		/*
		 * If the caller knowns how many digits
		 * it expects we should fail if we got something
		 * different.
		 */
		return false;
	}

	*pnum = num;
	*pstart_idx = start_idx;
	*pnum_digits = num_digits;
	return true;
}

static uint64_t num_digits_max_value(int num_digits)
{
	uint64_t num_max = 1;
	int i;

	if (num_digits < 1) {
		return 0;
	}
	if (num_digits >= PREOPEN_MAX_DIGITS) {
		return PREOPEN_MAX_NUMBER;
	}

	for (i = 0; i < num_digits; i++) {
		num_max *= 10;
	}

	/*
	 * We actually want
	 * 9   instead of 10
	 * 99  instead of 100
	 * 999 instead of 1000
	 */
	return num_max - 1;
}

static int preopen_openat(struct vfs_handle_struct *handle,
			  const struct files_struct *dirfsp,
			  const struct smb_filename *smb_fname,
			  struct files_struct *fsp,
			  const struct vfs_open_how *how)
{
	const char *dirname = dirfsp->fsp_name->base_name;
	struct preopen_state *state;
	int res;
	uint64_t num;
	uint64_t num_max;
	NTSTATUS status;
	char *new_template = NULL;
	size_t new_start = 0;
	int new_digits = -1;
	size_t new_end = 0;
	ssize_t match_idx = -1;
	ssize_t replace_start = -1;
	ssize_t replace_end = -1;
	bool need_reset = false;

	DBG_DEBUG("called on %s\n", smb_fname_str_dbg(smb_fname));

	state = preopen_state_get(handle);
	if (state == NULL) {
		return SMB_VFS_NEXT_OPENAT(handle,
					   dirfsp,
					   smb_fname,
					   fsp,
					   how);
	}

	res = SMB_VFS_NEXT_OPENAT(handle, dirfsp, smb_fname, fsp, how);
	if (res == -1) {
		return -1;
	}

	if ((how->flags & O_ACCMODE) != O_RDONLY) {
		return res;
	}

	/*
	 * Make sure we can later construct an absolute pathname
	 */
	if (dirname[0] != '/') {
		return res;
	}
	/*
	 * There's no point in preopen the directory itself.
	 */
	if (ISDOT(smb_fname->base_name)) {
		return res;
	}
	/*
	 * If we got an absolute path in
	 * smb_fname it's most likely the
	 * reopen via /proc/self/fd/$fd
	 */
	if (smb_fname->base_name[0] == '/') {
		return res;
	}

	status = samba_path_matching_check_last_component(state->preopen_names,
							  smb_fname->base_name,
							  &match_idx,
							  &replace_start,
							  &replace_end);
	if (!NT_STATUS_IS_OK(status)) {
		match_idx = -1;
	}
	if (match_idx < 0) {
		DBG_PREFIX(state->nomatch_dbglvl, (
			   "No match with the preopen:names list by name[%s]\n",
		           smb_fname_str_dbg(smb_fname)));
		return res;
	}

	if (replace_start != -1 && replace_end != -1) {
		DBG_PREFIX(state->match_dbglvl, (
			   "Pattern(idx=%zd) from preopen:names list matched name[%s] hints(start=%zd,end=%zd)\n",
			   match_idx, smb_fname_str_dbg(smb_fname), replace_start, replace_end));
	} else {
		DBG_PREFIX(state->match_dbglvl, (
			   "Pattern(idx=%zd) from preopen:names list matched name[%s]\n",
			   match_idx, smb_fname_str_dbg(smb_fname)));
	}

	new_template = talloc_asprintf(
		state, "%s/%s",
		dirname, smb_fname->base_name);
	if (new_template == NULL) {
		DBG_ERR("talloc_asprintf(%s/%s) failed\n",
			dirname, smb_fname_str_dbg(smb_fname));
		return res;
	}

	if (replace_start != -1 && replace_end != -1) {
		size_t dirofs = strlen(dirname) + 1;
		new_start = dirofs + replace_start;
		new_digits = replace_end - replace_start;
	}

	if (!preopen_parse_fname(new_template, &num,
				 &new_start, &new_digits)) {
		DBG_PREFIX(state->nodigits_dbglvl, (
			   "Pattern(idx=%zd) no valid digits found on fullpath[%s]\n",
			   match_idx, new_template));
		TALLOC_FREE(new_template);
		return res;
	}
	new_end = new_start + new_digits;

	DBG_PREFIX(state->founddigits_dbglvl, (
		   "Pattern(idx=%zd) found num_digits[%d] start_offset[%zd] parsed_num[%"PRIu64"] fullpath[%s]\n",
		   match_idx, new_digits, new_start, num, new_template));

	if (state->last_match_idx != match_idx) {
		/*
		 * If a different pattern caused the match
		 * we better reset the queue
		 */
		if (state->last_match_idx != -1) {
			DBG_PREFIX(state->reset_dbglvl, ("RESET: "
				   "pattern changed from idx=%zd to idx=%zd by fullpath[%s]\n",
				   state->last_match_idx, match_idx, new_template));
		}
		need_reset = true;
	} else if (state->number_start != new_start) {
		/*
		 * If the digits started at a different position
		 * we better reset the queue
		 */
		DBG_PREFIX(state->reset_dbglvl, ("RESET: "
			   "start_offset changed from byte=%zd to byte=%zd by fullpath[%s]\n",
			   state->number_start, new_start, new_template));
		need_reset = true;
	} else if (state->num_digits != new_digits) {
		/*
		 * If number of digits changed
		 * we better reset the queue
		 */
		DBG_PREFIX(state->reset_dbglvl, ("RESET: "
			   "num_digits changed %d to %d by fullpath[%s]\n",
			   state->num_digits, new_digits, new_template));
		need_reset = true;
	} else if (strncmp(state->template_fname, new_template, new_start) != 0) {
		/*
		 * If name before the digits changed
		 * we better reset the queue
		 */
		DBG_PREFIX(state->reset_dbglvl, ("RESET: "
			   "leading pathprefix[%.*s] changed by fullpath[%s]\n",
			   (int)state->number_start, state->template_fname, new_template));
		need_reset = true;
	} else if (strcmp(state->template_fname + new_end, new_template + new_end) != 0) {
		/*
		 * If name after the digits changed
		 * we better reset the queue
		 */
		DBG_PREFIX(state->reset_dbglvl, ("RESET: "
			   "trailing suffix[%s] changed by fullpath[%s]\n",
			   state->template_fname + new_end, new_template));
		need_reset = true;
	}

	if (need_reset) {
		/*
		 * Reset the queue
		 */
		state->fnum_sent = 0;
		state->fnum_queue_end = 0;
		state->last_match_idx = match_idx;
	}

	TALLOC_FREE(state->template_fname);
	state->template_fname = new_template;
	state->number_start = new_start;
	state->num_digits = new_digits;

	if (num > state->fnum_sent) {
		/*
		 * Helpers were too slow, there's no point in reading
		 * files in helpers that we already read in the
		 * parent.
		 */
		state->fnum_sent = num;
	}

	if ((state->fnum_queue_end != 0) /* Something was started earlier */
	    && (num < (state->fnum_queue_end - state->queue_max))) {
		/*
		 * "num" is before the queue we announced. This means
		 * a new run is started.
		 */
		state->fnum_sent = num;
	}

	num_max = num_digits_max_value(state->num_digits);
	state->fnum_queue_end = MIN(num_max, num + state->queue_max);

	DBG_PREFIX(state->queue_dbglvl, ("BEFORE: preopen_queue_run\n"));
	preopen_queue_run(state);
	DBG_PREFIX(state->queue_dbglvl, ("AFTER: preopen_queue_run\n"));

	return res;
}

static struct vfs_fn_pointers vfs_preopen_fns = {
	.openat_fn = preopen_openat,
};

static_decl_vfs;
NTSTATUS vfs_preopen_init(TALLOC_CTX *ctx)
{
	NTSTATUS status;

	status = smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
				  "preopen",
				  &vfs_preopen_fns);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	vfs_preopen_debug_level = debug_add_class("preopen");
	if (vfs_preopen_debug_level == -1) {
		vfs_preopen_debug_level = DBGC_VFS;
		DBG_ERR("Couldn't register custom debugging class!\n");
	} else {
		DBG_DEBUG("Debug class number of 'preopen': %d\n",
			  vfs_preopen_debug_level);
	}

	return NT_STATUS_OK;
}
