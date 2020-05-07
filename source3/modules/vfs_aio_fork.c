/*
 * Simulate the Posix AIO using mmap/fork
 *
 * Copyright (C) Volker Lendecke 2008
 * Copyright (C) Jeremy Allison 2010
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
#include "system/shmem.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "lib/async_req/async_sock.h"
#include "lib/util/tevent_unix.h"
#include "lib/util/sys_rw.h"
#include "lib/util/sys_rw_data.h"
#include "lib/util/msghdr.h"
#include "smbprofile.h"

#if !defined(HAVE_STRUCT_MSGHDR_MSG_CONTROL) && !defined(HAVE_STRUCT_MSGHDR_MSG_ACCRIGHTS)
# error Can not pass file descriptors
#endif

#undef recvmsg

#ifndef MAP_FILE
#define MAP_FILE 0
#endif

struct aio_child_list;

struct aio_fork_config {
	bool erratic_testing_mode;
	struct aio_child_list *children;
};

struct mmap_area {
	size_t size;
	void *ptr;
};

static int mmap_area_destructor(struct mmap_area *area)
{
	munmap(discard_const(area->ptr), area->size);
	return 0;
}

static struct mmap_area *mmap_area_init(TALLOC_CTX *mem_ctx, size_t size)
{
	struct mmap_area *result;
	int fd;

	result = talloc(mem_ctx, struct mmap_area);
	if (result == NULL) {
		DEBUG(0, ("talloc failed\n"));
		goto fail;
	}

	fd = open("/dev/zero", O_RDWR);
	if (fd == -1) {
		DEBUG(3, ("open(\"/dev/zero\") failed: %s\n",
			  strerror(errno)));
		goto fail;
	}

	result->ptr = mmap(NULL, size, PROT_READ|PROT_WRITE,
			   MAP_SHARED|MAP_FILE, fd, 0);
	close(fd);
	if (result->ptr == MAP_FAILED) {
		DEBUG(1, ("mmap failed: %s\n", strerror(errno)));
		goto fail;
	}

	result->size = size;
	talloc_set_destructor(result, mmap_area_destructor);

	return result;

fail:
	TALLOC_FREE(result);
	return NULL;
}

enum cmd_type {
	READ_CMD,
	WRITE_CMD,
	FSYNC_CMD
};

static const char *cmd_type_str(enum cmd_type cmd)
{
	const char *result;

	switch (cmd) {
	case READ_CMD:
		result = "READ";
		break;
	case WRITE_CMD:
		result = "WRITE";
		break;
	case FSYNC_CMD:
		result = "FSYNC";
		break;
	default:
		result = "<UNKNOWN>";
		break;
	}
	return result;
}

struct rw_cmd {
	size_t n;
	off_t offset;
	enum cmd_type cmd;
	bool erratic_testing_mode;
};

struct rw_ret {
	ssize_t size;
	int ret_errno;
	uint64_t duration;
};

struct aio_child_list;

struct aio_child {
	struct aio_child *prev, *next;
	struct aio_child_list *list;
	pid_t pid;
	int sockfd;
	struct mmap_area *map;
	bool dont_delete;	/* Marked as in use since last cleanup */
	bool busy;
};

struct aio_child_list {
	struct aio_child *children;
	struct tevent_timer *cleanup_event;
};

static ssize_t read_fd(int fd, void *ptr, size_t nbytes, int *recvfd)
{
	struct iovec iov[1];
	struct msghdr msg = { .msg_iov = iov, .msg_iovlen = 1 };
	ssize_t n;
	size_t bufsize = msghdr_prep_recv_fds(NULL, NULL, 0, 1);
	uint8_t buf[bufsize];

	msghdr_prep_recv_fds(&msg, buf, bufsize, 1);

	iov[0].iov_base = (void *)ptr;
	iov[0].iov_len = nbytes;

	do {
		n = recvmsg(fd, &msg, 0);
	} while ((n == -1) && (errno == EINTR));

	if (n <= 0) {
		return n;
	}

	{
		size_t num_fds = msghdr_extract_fds(&msg, NULL, 0);
		int fds[num_fds];

		msghdr_extract_fds(&msg, fds, num_fds);

		if (num_fds != 1) {
			size_t i;

			for (i=0; i<num_fds; i++) {
				close(fds[i]);
			}

			*recvfd = -1;
			return n;
		}

		*recvfd = fds[0];
	}

	return(n);
}

static ssize_t write_fd(int fd, void *ptr, size_t nbytes, int sendfd)
{
	struct msghdr msg = {0};
	size_t bufsize = msghdr_prep_fds(NULL, NULL, 0, &sendfd, 1);
	uint8_t buf[bufsize];
	struct iovec iov;
	ssize_t sent;

	msghdr_prep_fds(&msg, buf, bufsize, &sendfd, 1);

	iov.iov_base = (void *)ptr;
	iov.iov_len = nbytes;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	do {
		sent = sendmsg(fd, &msg, 0);
	} while ((sent == -1) && (errno == EINTR));

	return sent;
}

static void aio_child_cleanup(struct tevent_context *event_ctx,
			      struct tevent_timer *te,
			      struct timeval now,
			      void *private_data)
{
	struct aio_child_list *list = talloc_get_type_abort(
		private_data, struct aio_child_list);
	struct aio_child *child, *next;

	TALLOC_FREE(list->cleanup_event);

	for (child = list->children; child != NULL; child = next) {
		next = child->next;

		if (child->busy) {
			DEBUG(10, ("child %d currently active\n",
				   (int)child->pid));
			continue;
		}

		if (child->dont_delete) {
			DEBUG(10, ("Child %d was active since last cleanup\n",
				   (int)child->pid));
			child->dont_delete = false;
			continue;
		}

		DEBUG(10, ("Child %d idle for more than 30 seconds, "
			   "deleting\n", (int)child->pid));

		TALLOC_FREE(child);
		child = next;
	}

	if (list->children != NULL) {
		/*
		 * Re-schedule the next cleanup round
		 */
		list->cleanup_event = tevent_add_timer(global_event_context(), list,
						      timeval_add(&now, 30, 0),
						      aio_child_cleanup, list);

	}
}

static struct aio_child_list *init_aio_children(struct vfs_handle_struct *handle)
{
	struct aio_fork_config *config;
	struct aio_child_list *children;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct aio_fork_config,
				return NULL);

	if (config->children == NULL) {
		config->children = talloc_zero(config, struct aio_child_list);
		if (config->children == NULL) {
			return NULL;
		}
	}
	children = config->children;

	/*
	 * Regardless of whether the child_list had been around or not, make
	 * sure that we have a cleanup timed event. This timed event will
	 * delete itself when it finds that no children are around anymore.
	 */

	if (children->cleanup_event == NULL) {
		children->cleanup_event =
			tevent_add_timer(global_event_context(), children,
					 timeval_current_ofs(30, 0),
					 aio_child_cleanup, children);
		if (children->cleanup_event == NULL) {
			TALLOC_FREE(config->children);
			return NULL;
		}
	}

	return children;
}

static void aio_child_loop(int sockfd, struct mmap_area *map)
{
	while (true) {
		int fd = -1;
		ssize_t ret;
		struct rw_cmd cmd_struct;
		struct rw_ret ret_struct;
		struct timespec start, end;

		ret = read_fd(sockfd, &cmd_struct, sizeof(cmd_struct), &fd);
		if (ret != sizeof(cmd_struct)) {
			DEBUG(10, ("read_fd returned %d: %s\n", (int)ret,
				   strerror(errno)));
			exit(1);
		}

		DEBUG(10, ("aio_child_loop: %s %d bytes at %d from fd %d\n",
			   cmd_type_str(cmd_struct.cmd),
			   (int)cmd_struct.n, (int)cmd_struct.offset, fd));

		if (cmd_struct.erratic_testing_mode) {
			/*
			 * For developer testing, we want erratic behaviour for
			 * async I/O times
			 */
			uint8_t randval;
			unsigned msecs;
			/*
			 * use generate_random_buffer, we just forked from a
			 * common parent state
			 */
			generate_random_buffer(&randval, sizeof(randval));
			msecs = (randval%20)+1;
			DEBUG(10, ("delaying for %u msecs\n", msecs));
			smb_msleep(msecs);
		}

		ZERO_STRUCT(ret_struct);

		PROFILE_TIMESTAMP(&start);

		switch (cmd_struct.cmd) {
		case READ_CMD:
			ret_struct.size = sys_pread_full(
				fd, discard_const(map->ptr), cmd_struct.n,
				cmd_struct.offset);
#if 0
/* This breaks "make test" when run with aio_fork module. */
#ifdef DEVELOPER
			ret_struct.size = MAX(1, ret_struct.size * 0.9);
#endif
#endif
			break;
		case WRITE_CMD:
			ret_struct.size = sys_pwrite_full(
				fd, discard_const(map->ptr), cmd_struct.n,
				cmd_struct.offset);
			break;
		case FSYNC_CMD:
			ret_struct.size = fsync(fd);
			break;
		default:
			ret_struct.size = -1;
			errno = EINVAL;
		}

		PROFILE_TIMESTAMP(&end);
		ret_struct.duration = nsec_time_diff(&end, &start);
		DEBUG(10, ("aio_child_loop: syscall returned %d\n",
			   (int)ret_struct.size));

		if (ret_struct.size == -1) {
			ret_struct.ret_errno = errno;
		}

		/*
		 * Close the fd before telling our parent we're done. The
		 * parent might close and re-open the file very quickly, and
		 * with system-level share modes (GPFS) we would get an
		 * unjustified SHARING_VIOLATION.
		 */
		close(fd);

		ret = write_data(sockfd, (char *)&ret_struct,
				 sizeof(ret_struct));
		if (ret != sizeof(ret_struct)) {
			DEBUG(10, ("could not write ret_struct: %s\n",
				   strerror(errno)));
			exit(2);
		}
	}
}

static int aio_child_destructor(struct aio_child *child)
{
	char c=0;

	SMB_ASSERT(!child->busy);

	DEBUG(10, ("aio_child_destructor: removing child %d on fd %d\n",
		   (int)child->pid, child->sockfd));

	/*
	 * closing the sockfd makes the child not return from recvmsg() on RHEL
	 * 5.5 so instead force the child to exit by writing bad data to it
	 */
	sys_write_v(child->sockfd, &c, sizeof(c));
	close(child->sockfd);
	DLIST_REMOVE(child->list->children, child);
	return 0;
}

/*
 * We have to close all fd's in open files, we might incorrectly hold a system
 * level share mode on a file.
 */

static struct files_struct *close_fsp_fd(struct files_struct *fsp,
					 void *private_data)
{
	if ((fsp->fh != NULL) && (fsp->fh->fd != -1)) {
		close(fsp->fh->fd);
		fsp->fh->fd = -1;
	}
	return NULL;
}

static int create_aio_child(struct smbd_server_connection *sconn,
			    struct aio_child_list *children,
			    size_t map_size,
			    struct aio_child **presult)
{
	struct aio_child *result;
	int fdpair[2];
	int ret;

	fdpair[0] = fdpair[1] = -1;

	result = talloc_zero(children, struct aio_child);
	if (result == NULL) {
		return ENOMEM;
	}

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fdpair) == -1) {
		ret = errno;
		DEBUG(10, ("socketpair() failed: %s\n", strerror(errno)));
		goto fail;
	}

	DEBUG(10, ("fdpair = %d/%d\n", fdpair[0], fdpair[1]));

	result->map = mmap_area_init(result, map_size);
	if (result->map == NULL) {
		ret = errno;
		DEBUG(0, ("Could not create mmap area\n"));
		goto fail;
	}

	result->pid = fork();
	if (result->pid == -1) {
		ret = errno;
		DEBUG(0, ("fork failed: %s\n", strerror(errno)));
		goto fail;
	}

	if (result->pid == 0) {
		close(fdpair[0]);
		result->sockfd = fdpair[1];
		files_forall(sconn, close_fsp_fd, NULL);
		aio_child_loop(result->sockfd, result->map);
	}

	DEBUG(10, ("Child %d created with sockfd %d\n",
		   (int)result->pid, fdpair[0]));

	result->sockfd = fdpair[0];
	close(fdpair[1]);

	result->list = children;
	DLIST_ADD(children->children, result);

	talloc_set_destructor(result, aio_child_destructor);

	*presult = result;

	return 0;

 fail:
	if (fdpair[0] != -1) close(fdpair[0]);
	if (fdpair[1] != -1) close(fdpair[1]);
	TALLOC_FREE(result);

	return ret;
}

static int get_idle_child(struct vfs_handle_struct *handle,
			  struct aio_child **pchild)
{
	struct aio_child_list *children;
	struct aio_child *child;

	children = init_aio_children(handle);
	if (children == NULL) {
		return ENOMEM;
	}

	for (child = children->children; child != NULL; child = child->next) {
		if (!child->busy) {
			break;
		}
	}

	if (child == NULL) {
		int ret;

		DEBUG(10, ("no idle child found, creating new one\n"));

		ret = create_aio_child(handle->conn->sconn, children,
					  128*1024, &child);
		if (ret != 0) {
			DEBUG(10, ("create_aio_child failed: %s\n",
				   strerror(errno)));
			return ret;
		}
	}

	child->dont_delete = true;
	child->busy = true;

	*pchild = child;
	return 0;
}

struct aio_fork_pread_state {
	struct aio_child *child;
	size_t n;
	void *data;
	ssize_t ret;
	struct vfs_aio_state vfs_aio_state;
};

static void aio_fork_pread_done(struct tevent_req *subreq);

static struct tevent_req *aio_fork_pread_send(struct vfs_handle_struct *handle,
					      TALLOC_CTX *mem_ctx,
					      struct tevent_context *ev,
					      struct files_struct *fsp,
					      void *data,
					      size_t n, off_t offset)
{
	struct tevent_req *req, *subreq;
	struct aio_fork_pread_state *state;
	struct rw_cmd cmd;
	ssize_t written;
	int err;
	struct aio_fork_config *config;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct aio_fork_config,
				return NULL);

	req = tevent_req_create(mem_ctx, &state, struct aio_fork_pread_state);
	if (req == NULL) {
		return NULL;
	}
	state->n = n;
	state->data = data;

	if (n > 128*1024) {
		/* TODO: support variable buffers */
		tevent_req_error(req, EINVAL);
		return tevent_req_post(req, ev);
	}

	err = get_idle_child(handle, &state->child);
	if (err != 0) {
		tevent_req_error(req, err);
		return tevent_req_post(req, ev);
	}

	ZERO_STRUCT(cmd);
	cmd.n = n;
	cmd.offset = offset;
	cmd.cmd = READ_CMD;
	cmd.erratic_testing_mode = config->erratic_testing_mode;

	DEBUG(10, ("sending fd %d to child %d\n", fsp->fh->fd,
		   (int)state->child->pid));

	/*
	 * Not making this async. We're writing into an empty unix
	 * domain socket. This should never block.
	 */
	written = write_fd(state->child->sockfd, &cmd, sizeof(cmd),
			   fsp->fh->fd);
	if (written == -1) {
		err = errno;

		TALLOC_FREE(state->child);

		DEBUG(10, ("write_fd failed: %s\n", strerror(err)));
		tevent_req_error(req, err);
		return tevent_req_post(req, ev);
	}

	subreq = read_packet_send(state, ev, state->child->sockfd,
				  sizeof(struct rw_ret), NULL, NULL);
	if (tevent_req_nomem(subreq, req)) {
		TALLOC_FREE(state->child); /* we sent sth down */
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, aio_fork_pread_done, req);
	return req;
}

static void aio_fork_pread_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct aio_fork_pread_state *state = tevent_req_data(
		req, struct aio_fork_pread_state);
	ssize_t nread;
	uint8_t *buf;
	int err;
	struct rw_ret *retbuf;

	nread = read_packet_recv(subreq, talloc_tos(), &buf, &err);
	TALLOC_FREE(subreq);
	if (nread == -1) {
		TALLOC_FREE(state->child);
		tevent_req_error(req, err);
		return;
	}

	retbuf = (struct rw_ret *)buf;
	state->ret = retbuf->size;
	state->vfs_aio_state.error = retbuf->ret_errno;
	state->vfs_aio_state.duration = retbuf->duration;

	if ((size_t)state->ret > state->n) {
		tevent_req_error(req, EIO);
		state->child->busy = false;
		return;
	}
	memcpy(state->data, state->child->map->ptr, state->ret);

	state->child->busy = false;

	tevent_req_done(req);
}

static ssize_t aio_fork_pread_recv(struct tevent_req *req,
				   struct vfs_aio_state *vfs_aio_state)
{
	struct aio_fork_pread_state *state = tevent_req_data(
		req, struct aio_fork_pread_state);

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		return -1;
	}
	*vfs_aio_state = state->vfs_aio_state;
	return state->ret;
}

struct aio_fork_pwrite_state {
	struct aio_child *child;
	ssize_t ret;
	struct vfs_aio_state vfs_aio_state;
};

static void aio_fork_pwrite_done(struct tevent_req *subreq);

static struct tevent_req *aio_fork_pwrite_send(
	struct vfs_handle_struct *handle, TALLOC_CTX *mem_ctx,
	struct tevent_context *ev, struct files_struct *fsp,
	const void *data, size_t n, off_t offset)
{
	struct tevent_req *req, *subreq;
	struct aio_fork_pwrite_state *state;
	struct rw_cmd cmd;
	ssize_t written;
	int err;
	struct aio_fork_config *config;
	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct aio_fork_config,
				return NULL);

	req = tevent_req_create(mem_ctx, &state, struct aio_fork_pwrite_state);
	if (req == NULL) {
		return NULL;
	}

	if (n > 128*1024) {
		/* TODO: support variable buffers */
		tevent_req_error(req, EINVAL);
		return tevent_req_post(req, ev);
	}

	err = get_idle_child(handle, &state->child);
	if (err != 0) {
		tevent_req_error(req, err);
		return tevent_req_post(req, ev);
	}

	memcpy(state->child->map->ptr, data, n);

	ZERO_STRUCT(cmd);
	cmd.n = n;
	cmd.offset = offset;
	cmd.cmd = WRITE_CMD;
	cmd.erratic_testing_mode = config->erratic_testing_mode;

	DEBUG(10, ("sending fd %d to child %d\n", fsp->fh->fd,
		   (int)state->child->pid));

	/*
	 * Not making this async. We're writing into an empty unix
	 * domain socket. This should never block.
	 */
	written = write_fd(state->child->sockfd, &cmd, sizeof(cmd),
			   fsp->fh->fd);
	if (written == -1) {
		err = errno;

		TALLOC_FREE(state->child);

		DEBUG(10, ("write_fd failed: %s\n", strerror(err)));
		tevent_req_error(req, err);
		return tevent_req_post(req, ev);
	}

	subreq = read_packet_send(state, ev, state->child->sockfd,
				  sizeof(struct rw_ret), NULL, NULL);
	if (tevent_req_nomem(subreq, req)) {
		TALLOC_FREE(state->child); /* we sent sth down */
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, aio_fork_pwrite_done, req);
	return req;
}

static void aio_fork_pwrite_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct aio_fork_pwrite_state *state = tevent_req_data(
		req, struct aio_fork_pwrite_state);
	ssize_t nread;
	uint8_t *buf;
	int err;
	struct rw_ret *retbuf;

	nread = read_packet_recv(subreq, talloc_tos(), &buf, &err);
	TALLOC_FREE(subreq);
	if (nread == -1) {
		TALLOC_FREE(state->child);
		tevent_req_error(req, err);
		return;
	}

	state->child->busy = false;

	retbuf = (struct rw_ret *)buf;
	state->ret = retbuf->size;
	state->vfs_aio_state.error = retbuf->ret_errno;
	state->vfs_aio_state.duration = retbuf->duration;
	tevent_req_done(req);
}

static ssize_t aio_fork_pwrite_recv(struct tevent_req *req,
				    struct vfs_aio_state *vfs_aio_state)
{
	struct aio_fork_pwrite_state *state = tevent_req_data(
		req, struct aio_fork_pwrite_state);

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		return -1;
	}
	*vfs_aio_state = state->vfs_aio_state;
	return state->ret;
}

struct aio_fork_fsync_state {
	struct aio_child *child;
	ssize_t ret;
	struct vfs_aio_state vfs_aio_state;
};

static void aio_fork_fsync_done(struct tevent_req *subreq);

static struct tevent_req *aio_fork_fsync_send(
	struct vfs_handle_struct *handle, TALLOC_CTX *mem_ctx,
	struct tevent_context *ev, struct files_struct *fsp)
{
	struct tevent_req *req, *subreq;
	struct aio_fork_fsync_state *state;
	struct rw_cmd cmd;
	ssize_t written;
	int err;
	struct aio_fork_config *config;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct aio_fork_config,
				return NULL);

	req = tevent_req_create(mem_ctx, &state, struct aio_fork_fsync_state);
	if (req == NULL) {
		return NULL;
	}

	err = get_idle_child(handle, &state->child);
	if (err != 0) {
		tevent_req_error(req, err);
		return tevent_req_post(req, ev);
	}

	ZERO_STRUCT(cmd);
	cmd.cmd = FSYNC_CMD;
	cmd.erratic_testing_mode = config->erratic_testing_mode;

	DEBUG(10, ("sending fd %d to child %d\n", fsp->fh->fd,
		   (int)state->child->pid));

	/*
	 * Not making this async. We're writing into an empty unix
	 * domain socket. This should never block.
	 */
	written = write_fd(state->child->sockfd, &cmd, sizeof(cmd),
			   fsp->fh->fd);
	if (written == -1) {
		err = errno;

		TALLOC_FREE(state->child);

		DEBUG(10, ("write_fd failed: %s\n", strerror(err)));
		tevent_req_error(req, err);
		return tevent_req_post(req, ev);
	}

	subreq = read_packet_send(state, ev, state->child->sockfd,
				  sizeof(struct rw_ret), NULL, NULL);
	if (tevent_req_nomem(subreq, req)) {
		TALLOC_FREE(state->child); /* we sent sth down */
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, aio_fork_fsync_done, req);
	return req;
}

static void aio_fork_fsync_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct aio_fork_fsync_state *state = tevent_req_data(
		req, struct aio_fork_fsync_state);
	ssize_t nread;
	uint8_t *buf;
	int err;
	struct rw_ret *retbuf;

	nread = read_packet_recv(subreq, talloc_tos(), &buf, &err);
	TALLOC_FREE(subreq);
	if (nread == -1) {
		TALLOC_FREE(state->child);
		tevent_req_error(req, err);
		return;
	}

	state->child->busy = false;

	retbuf = (struct rw_ret *)buf;
	state->ret = retbuf->size;
	state->vfs_aio_state.error = retbuf->ret_errno;
	state->vfs_aio_state.duration = retbuf->duration;
	tevent_req_done(req);
}

static int aio_fork_fsync_recv(struct tevent_req *req,
			       struct vfs_aio_state *vfs_aio_state)
{
	struct aio_fork_fsync_state *state = tevent_req_data(
		req, struct aio_fork_fsync_state);

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		return -1;
	}
	*vfs_aio_state = state->vfs_aio_state;
	return state->ret;
}

static int aio_fork_connect(vfs_handle_struct *handle, const char *service,
			    const char *user)
{
	int ret;
	struct aio_fork_config *config;
	ret = SMB_VFS_NEXT_CONNECT(handle, service, user);

	if (ret < 0) {
		return ret;
	}

	config = talloc_zero(handle->conn, struct aio_fork_config);
	if (!config) {
		SMB_VFS_NEXT_DISCONNECT(handle);
		DEBUG(0, ("talloc_zero() failed\n"));
		return -1;
	}

	config->erratic_testing_mode = lp_parm_bool(SNUM(handle->conn), "vfs_aio_fork",
						    "erratic_testing_mode", false);
	
	SMB_VFS_HANDLE_SET_DATA(handle, config,
				NULL, struct aio_fork_config,
				return -1);

	return 0;
}

static struct vfs_fn_pointers vfs_aio_fork_fns = {
	.connect_fn = aio_fork_connect,
	.pread_send_fn = aio_fork_pread_send,
	.pread_recv_fn = aio_fork_pread_recv,
	.pwrite_send_fn = aio_fork_pwrite_send,
	.pwrite_recv_fn = aio_fork_pwrite_recv,
	.fsync_send_fn = aio_fork_fsync_send,
	.fsync_recv_fn = aio_fork_fsync_recv,
};

static_decl_vfs;
NTSTATUS vfs_aio_fork_init(TALLOC_CTX *ctx)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
				"aio_fork", &vfs_aio_fork_fns);
}
