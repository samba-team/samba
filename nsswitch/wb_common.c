/*
   Unix SMB/CIFS implementation.

   winbind client common code

   Copyright (C) Tim Potter 2000
   Copyright (C) Andrew Tridgell 2000
   Copyright (C) Andrew Bartlett 2002
   Copyright (C) Matthew Newton 2015


   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "replace.h"
#include "system/select.h"
#include "winbind_client.h"

#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#endif

static char client_name[32];

/* Global context */

struct winbindd_context {
	int winbindd_fd;	/* winbind file descriptor */
	bool is_privileged;	/* using the privileged socket? */
	pid_t our_pid;		/* calling process pid */
};

#ifdef HAVE_PTHREAD
static pthread_mutex_t wb_global_ctx_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

static struct winbindd_context *get_wb_global_ctx(void)
{
	static struct winbindd_context wb_global_ctx = {
		.winbindd_fd = -1,
		.is_privileged = false,
		.our_pid = 0
	};

#ifdef HAVE_PTHREAD
	pthread_mutex_lock(&wb_global_ctx_mutex);
#endif
	return &wb_global_ctx;
}

static void put_wb_global_ctx(void)
{
#ifdef HAVE_PTHREAD
	pthread_mutex_unlock(&wb_global_ctx_mutex);
#endif
	return;
}

/* Free a response structure */

void winbindd_free_response(struct winbindd_response *response)
{
	/* Free any allocated extra_data */

	if (response)
		SAFE_FREE(response->extra_data.data);
}

void winbind_set_client_name(const char *name)
{
	if (name == NULL || strlen(name) == 0) {
		return;
	}

	(void)snprintf(client_name, sizeof(client_name), "%s", name);
}

static const char *winbind_get_client_name(void)
{
	if (client_name[0] == '\0') {
		const char *progname = getprogname();
		int len;

		if (progname == NULL) {
			progname = "<unknown>";
		}

		len = snprintf(client_name,
			       sizeof(client_name),
			       "%s",
			       progname);
		if (len <= 0) {
			return progname;
		}
	}

	return client_name;
}

/* Initialise a request structure */

static void winbindd_init_request(struct winbindd_request *request,
				  int request_type)
{
	request->length = sizeof(struct winbindd_request);

	request->cmd = (enum winbindd_cmd)request_type;
	request->pid = getpid();

	(void)snprintf(request->client_name,
		       sizeof(request->client_name),
		       "%s",
		       winbind_get_client_name());
}

/* Initialise a response structure */

static void init_response(struct winbindd_response *response)
{
	/* Initialise return value */

	response->result = WINBINDD_ERROR;
}

/* Close established socket */

static void winbind_close_sock(struct winbindd_context *ctx)
{
	if (!ctx) {
		return;
	}

	if (ctx->winbindd_fd != -1) {
		close(ctx->winbindd_fd);
		ctx->winbindd_fd = -1;
	}
}

/* Destructor for global context to ensure fd is closed */

#ifdef HAVE_DESTRUCTOR_ATTRIBUTE
__attribute__((destructor))
#endif
static void winbind_destructor(void)
{
	struct winbindd_context *ctx;

	ctx = get_wb_global_ctx();
	winbind_close_sock(ctx);
	put_wb_global_ctx();
}

#define CONNECT_TIMEOUT 30

/* Make sure socket handle isn't stdin, stdout or stderr */
#define RECURSION_LIMIT 3

static int make_nonstd_fd_internals(int fd, int limit /* Recursion limiter */)
{
	int new_fd;
	if (fd >= 0 && fd <= 2) {
#ifdef F_DUPFD
		if ((new_fd = fcntl(fd, F_DUPFD, 3)) == -1) {
			return -1;
		}
		/* Paranoia */
		if (new_fd < 3) {
			close(new_fd);
			return -1;
		}
		close(fd);
		return new_fd;
#else
		if (limit <= 0)
			return -1;

		new_fd = dup(fd);
		if (new_fd == -1)
			return -1;

		/* use the program stack to hold our list of FDs to close */
		new_fd = make_nonstd_fd_internals(new_fd, limit - 1);
		close(fd);
		return new_fd;
#endif
	}
	return fd;
}

/****************************************************************************
 Set a fd into blocking/nonblocking mode. Uses POSIX O_NONBLOCK if available,
 else
 if SYSV use O_NDELAY
 if BSD use FNDELAY
 Set close on exec also.
****************************************************************************/

static int make_safe_fd(int fd)
{
	int result, flags;
	int new_fd = make_nonstd_fd_internals(fd, RECURSION_LIMIT);
	if (new_fd == -1) {
		close(fd);
		return -1;
	}

	/* Socket should be nonblocking. */
#ifdef O_NONBLOCK
#define FLAG_TO_SET O_NONBLOCK
#else
#ifdef SYSV
#define FLAG_TO_SET O_NDELAY
#else /* BSD */
#define FLAG_TO_SET FNDELAY
#endif
#endif

	if ((flags = fcntl(new_fd, F_GETFL)) == -1) {
		close(new_fd);
		return -1;
	}

	flags |= FLAG_TO_SET;
	if (fcntl(new_fd, F_SETFL, flags) == -1) {
		close(new_fd);
		return -1;
	}

#undef FLAG_TO_SET

	/* Socket should be closed on exec() */
#ifdef FD_CLOEXEC
	result = flags = fcntl(new_fd, F_GETFD, 0);
	if (flags >= 0) {
		flags |= FD_CLOEXEC;
		result = fcntl( new_fd, F_SETFD, flags );
	}
	if (result < 0) {
		close(new_fd);
		return -1;
	}
#endif
	return new_fd;
}

/**
 * @internal
 *
 * @brief Check if we talk to the priviliged pipe which should be owned by root.
 *
 * This checks if we have uid_wrapper running and if this is the case it will
 * allow one to connect to the winbind privileged pipe even it is not owned by root.
 *
 * @param[in]  uid      The uid to check if we can safely talk to the pipe.
 *
 * @return              If we have access it returns true, else false.
 */
static bool winbind_privileged_pipe_is_root(uid_t uid)
{
	if (uid == 0) {
		return true;
	}

	if (uid_wrapper_enabled()) {
		return true;
	}

	return false;
}

/* Connect to winbindd socket */

static int winbind_named_pipe_sock(const char *dir)
{
	struct sockaddr_un sunaddr;
	struct stat st;
	int fd;
	int wait_time;
	int slept;
	int ret;

	/* Check permissions on unix socket directory */

	if (lstat(dir, &st) == -1) {
		errno = ENOENT;
		return -1;
	}

	/*
	 * This tells us that the pipe is owned by a privileged
	 * process, as we will be sending passwords to it.
	 */
	if (!S_ISDIR(st.st_mode) ||
	    !winbind_privileged_pipe_is_root(st.st_uid)) {
		errno = ENOENT;
		return -1;
	}

	/* Connect to socket */

	sunaddr = (struct sockaddr_un) { .sun_family = AF_UNIX };

	ret = snprintf(sunaddr.sun_path, sizeof(sunaddr.sun_path),
		       "%s/%s", dir, WINBINDD_SOCKET_NAME);
	if ((ret == -1) || (ret >= sizeof(sunaddr.sun_path))) {
		errno = ENAMETOOLONG;
		return -1;
	}

	/* If socket file doesn't exist, don't bother trying to connect
	   with retry.  This is an attempt to make the system usable when
	   the winbindd daemon is not running. */

	if (lstat(sunaddr.sun_path, &st) == -1) {
		errno = ENOENT;
		return -1;
	}

	/* Check permissions on unix socket file */

	/*
	 * This tells us that the pipe is owned by a privileged
	 * process, as we will be sending passwords to it.
	 */
	if (!S_ISSOCK(st.st_mode) ||
	    !winbind_privileged_pipe_is_root(st.st_uid)) {
		errno = ENOENT;
		return -1;
	}

	/* Connect to socket */

	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		return -1;
	}

	/* Set socket non-blocking and close on exec. */

	if ((fd = make_safe_fd( fd)) == -1) {
		return fd;
	}

	for (wait_time = 0; connect(fd, (struct sockaddr *)&sunaddr, sizeof(sunaddr)) == -1;
			wait_time += slept) {
		struct pollfd pfd;
		int connect_errno = 0;
		socklen_t errnosize;

		if (wait_time >= CONNECT_TIMEOUT)
			goto error_out;

		switch (errno) {
			case EINPROGRESS:
				pfd.fd = fd;
				pfd.events = POLLOUT;

				ret = poll(&pfd, 1, (CONNECT_TIMEOUT - wait_time) * 1000);

				if (ret > 0) {
					errnosize = sizeof(connect_errno);

					ret = getsockopt(fd, SOL_SOCKET,
							SO_ERROR, &connect_errno, &errnosize);

					if (ret >= 0 && connect_errno == 0) {
						/* Connect succeed */
						goto out;
					}
				}

				slept = CONNECT_TIMEOUT;
				break;
			case EAGAIN:
				slept = rand() % 3 + 1;
				sleep(slept);
				break;
			default:
				goto error_out;
		}

	}

  out:

	return fd;

  error_out:

	close(fd);
	return -1;
}

static const char *winbindd_socket_dir(void)
{
	if (nss_wrapper_enabled()) {
		const char *env_dir;

		env_dir = getenv("SELFTEST_WINBINDD_SOCKET_DIR");
		if (env_dir != NULL) {
			return env_dir;
		}
	}

	return WINBINDD_SOCKET_DIR;
}

/* Connect to winbindd socket */

static int winbind_open_pipe_sock(struct winbindd_context *ctx,
				  int recursing, int need_priv)
{
#ifdef HAVE_UNIXSOCKET
	struct winbindd_request request;
	struct winbindd_response response;

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	if (!ctx) {
		return -1;
	}

	if (ctx->our_pid != getpid()) {
		winbind_close_sock(ctx);
		ctx->our_pid = getpid();
	}

	if ((need_priv != 0) && !ctx->is_privileged) {
		winbind_close_sock(ctx);
	}

	if (ctx->winbindd_fd != -1) {
		return ctx->winbindd_fd;
	}

	if (recursing) {
		return -1;
	}

	ctx->winbindd_fd = winbind_named_pipe_sock(winbindd_socket_dir());

	if (ctx->winbindd_fd == -1) {
		return -1;
	}

	ctx->is_privileged = false;

	/* version-check the socket */

	request.wb_flags = WBFLAG_RECURSE;
	if ((winbindd_request_response(ctx, WINBINDD_INTERFACE_VERSION, &request,
				       &response) != NSS_STATUS_SUCCESS) ||
	    (response.data.interface_version != WINBIND_INTERFACE_VERSION)) {
		winbind_close_sock(ctx);
		return -1;
	}

	if (need_priv == 0) {
		return ctx->winbindd_fd;
	}

	/* try and get priv pipe */

	request.wb_flags = WBFLAG_RECURSE;

	/* Note that response needs to be initialized to avoid
	 * crashing on clean up after WINBINDD_PRIV_PIPE_DIR call failed
	 * as interface version (from the first request) returned as a fstring,
	 * thus response.extra_data.data will not be NULL even though
	 * winbindd response did not write over it due to a failure */
	ZERO_STRUCT(response);
	if (winbindd_request_response(ctx, WINBINDD_PRIV_PIPE_DIR, &request,
				      &response) == NSS_STATUS_SUCCESS) {
		int fd;
		fd = winbind_named_pipe_sock((char *)response.extra_data.data);
		if (fd != -1) {
			close(ctx->winbindd_fd);
			ctx->winbindd_fd = fd;
			ctx->is_privileged = true;
		}

		SAFE_FREE(response.extra_data.data);
	}

	if (!ctx->is_privileged) {
		return -1;
	}

	return ctx->winbindd_fd;
#else
	return -1;
#endif /* HAVE_UNIXSOCKET */
}

/* Write data to winbindd socket */

static int winbind_write_sock(struct winbindd_context *ctx, void *buffer,
			      int count, int recursing, int need_priv)
{
	int fd, result, nwritten;

	/* Open connection to winbind daemon */

 restart:

	fd = winbind_open_pipe_sock(ctx, recursing, need_priv);
	if (fd == -1) {
		errno = ENOENT;
		return -1;
	}

	/* Write data to socket */

	nwritten = 0;

	while(nwritten < count) {
		struct pollfd pfd;
		int ret;

		/* Catch pipe close on other end by checking if a read()
		   call would not block by calling poll(). */

		pfd.fd = fd;
		pfd.events = POLLIN|POLLOUT|POLLHUP;

		ret = poll(&pfd, 1, -1);
		if (ret == -1) {
			winbind_close_sock(ctx);
			return -1;                   /* poll error */
		}

		/* Write should be OK if fd not available for reading */

		if ((ret == 1) && (pfd.revents & (POLLIN|POLLHUP|POLLERR))) {

			/* Pipe has closed on remote end */

			winbind_close_sock(ctx);
			goto restart;
		}

		/* Do the write */

		result = write(fd, (char *)buffer + nwritten,
			       count - nwritten);

		if ((result == -1) || (result == 0)) {

			/* Write failed */

			winbind_close_sock(ctx);
			return -1;
		}

		nwritten += result;
	}

	return nwritten;
}

/* Read data from winbindd socket */

static int winbind_read_sock(struct winbindd_context *ctx,
			     void *buffer, int count)
{
	int fd;
	int nread = 0;
	int total_time = 0;

	fd = winbind_open_pipe_sock(ctx, false, false);
	if (fd == -1) {
		return -1;
	}

	/* Read data from socket */
	while(nread < count) {
		struct pollfd pfd;
		int ret;

		/* Catch pipe close on other end by checking if a read()
		   call would not block by calling poll(). */

		pfd.fd = fd;
		pfd.events = POLLIN|POLLHUP;

		/* Wait for 5 seconds for a reply. May need to parameterise this... */

		ret = poll(&pfd, 1, 5000);
		if (ret == -1) {
			winbind_close_sock(ctx);
			return -1;                   /* poll error */
		}

		if (ret == 0) {
			/* Not ready for read yet... */
			if (total_time >= 300) {
				/* Timeout */
				winbind_close_sock(ctx);
				return -1;
			}
			total_time += 5;
			continue;
		}

		if ((ret == 1) && (pfd.revents & (POLLIN|POLLHUP|POLLERR))) {

			/* Do the Read */

			int result = read(fd, (char *)buffer + nread,
			      count - nread);

			if ((result == -1) || (result == 0)) {

				/* Read failed.  I think the only useful thing we
				   can do here is just return -1 and fail since the
				   transaction has failed half way through. */

				winbind_close_sock(ctx);
				return -1;
			}

			nread += result;

		}
	}

	return nread;
}

/* Read reply */

static int winbindd_read_reply(struct winbindd_context *ctx,
			       struct winbindd_response *response)
{
	int result1, result2 = 0;

	if (!response) {
		return -1;
	}

	/* Read fixed length response */

	result1 = winbind_read_sock(ctx, response,
				    sizeof(struct winbindd_response));

	/* We actually send the pointer value of the extra_data field from
	   the server.  This has no meaning in the client's address space
	   so we clear it out. */

	response->extra_data.data = NULL;

	if (result1 == -1) {
		return -1;
	}

	if (response->length < sizeof(struct winbindd_response)) {
		return -1;
	}

	/* Read variable length response */

	if (response->length > sizeof(struct winbindd_response)) {
		int extra_data_len = response->length -
			sizeof(struct winbindd_response);

		/* Mallocate memory for extra data */

		if (!(response->extra_data.data = malloc(extra_data_len))) {
			return -1;
		}

		result2 = winbind_read_sock(ctx, response->extra_data.data,
					    extra_data_len);
		if (result2 == -1) {
			winbindd_free_response(response);
			return -1;
		}
	}

	/* Return total amount of data read */

	return result1 + result2;
}

/*
 * send simple types of requests
 */

static NSS_STATUS winbindd_send_request(
	struct winbindd_context *ctx,
	int req_type,
	int need_priv,
	struct winbindd_request *request)
{
	struct winbindd_request lrequest;

	/* Check for our tricky environment variable */

	if (winbind_env_set()) {
		return NSS_STATUS_NOTFOUND;
	}

	if (!request) {
		ZERO_STRUCT(lrequest);
		request = &lrequest;
	}

	/* Fill in request and send down pipe */

	winbindd_init_request(request, req_type);

	if (winbind_write_sock(ctx, request, sizeof(*request),
			       request->wb_flags & WBFLAG_RECURSE,
			       need_priv) == -1)
	{
		/* Set ENOENT for consistency.  Required by some apps */
		errno = ENOENT;

		return NSS_STATUS_UNAVAIL;
	}

	if ((request->extra_len != 0) &&
	    (winbind_write_sock(ctx, request->extra_data.data,
				request->extra_len,
				request->wb_flags & WBFLAG_RECURSE,
				need_priv) == -1))
	{
		/* Set ENOENT for consistency.  Required by some apps */
		errno = ENOENT;

		return NSS_STATUS_UNAVAIL;
	}

	return NSS_STATUS_SUCCESS;
}

/*
 * Get results from winbindd request
 */

static NSS_STATUS winbindd_get_response(struct winbindd_context *ctx,
					struct winbindd_response *response)
{
	struct winbindd_response lresponse;

	if (!response) {
		ZERO_STRUCT(lresponse);
		response = &lresponse;
	}

	init_response(response);

	/* Wait for reply */
	if (winbindd_read_reply(ctx, response) == -1) {
		/* Set ENOENT for consistency.  Required by some apps */
		errno = ENOENT;

		return NSS_STATUS_UNAVAIL;
	}

	/* Throw away extra data if client didn't request it */
	if (response == &lresponse) {
		winbindd_free_response(response);
	}

	/* Copy reply data from socket */
	if (response->result != WINBINDD_OK) {
		return NSS_STATUS_NOTFOUND;
	}

	return NSS_STATUS_SUCCESS;
}

/* Handle simple types of requests */

NSS_STATUS winbindd_request_response(struct winbindd_context *ctx,
				     int req_type,
				     struct winbindd_request *request,
				     struct winbindd_response *response)
{
	NSS_STATUS status = NSS_STATUS_UNAVAIL;
	bool release_global_ctx = false;

	if (ctx == NULL) {
		ctx = get_wb_global_ctx();
		release_global_ctx = true;
	}

	status = winbindd_send_request(ctx, req_type, 0, request);
	if (status != NSS_STATUS_SUCCESS) {
		goto out;
	}
	status = winbindd_get_response(ctx, response);

out:
	if (release_global_ctx) {
		put_wb_global_ctx();
	}
	return status;
}

NSS_STATUS winbindd_priv_request_response(struct winbindd_context *ctx,
					  int req_type,
					  struct winbindd_request *request,
					  struct winbindd_response *response)
{
	NSS_STATUS status = NSS_STATUS_UNAVAIL;
	bool release_global_ctx = false;

	if (ctx == NULL) {
		ctx = get_wb_global_ctx();
		release_global_ctx = true;
	}

	status = winbindd_send_request(ctx, req_type, 1, request);
	if (status != NSS_STATUS_SUCCESS) {
		goto out;
	}
	status = winbindd_get_response(ctx, response);

out:
	if (release_global_ctx) {
		put_wb_global_ctx();
	}
	return status;
}

/* Create and free winbindd context */

struct winbindd_context *winbindd_ctx_create(void)
{
	struct winbindd_context *ctx;

	ctx = calloc(1, sizeof(struct winbindd_context));

	if (!ctx) {
		return NULL;
	}

	ctx->winbindd_fd = -1;

	return ctx;
}

void winbindd_ctx_free(struct winbindd_context *ctx)
{
	winbind_close_sock(ctx);
	free(ctx);
}
