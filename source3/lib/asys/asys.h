/*
 * Async syscalls
 * Copyright (C) Volker Lendecke 2012
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

#ifndef __ASYS_H__
#define __ASYS_H__

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

/**
 * @defgroup asys The async syscall library
 *
 * This module contains a set of asynchronous functions that directly
 * wrap normally synchronous posix system calls. The reason for this
 * module's existence is the limited set of operations the posix async
 * I/O API provides.
 *
 * The basic flow of operations is:
 *
 * The application creates a asys_context structure using
 * asys_context_create()
 *
 * The application triggers a call to the library by calling for
 * example asys_ftruncate(). asys_ftruncate() takes a private_data
 * argument that will be returned later by asys_result. The calling
 * application should hand a pointer representing the async operation
 * to the private_data argument.
 *
 * The application puts the fd returned by asys_signalfd() into its
 * event loop. When the signal fd becomes readable, the application
 * calls asys_result() to grab the final result of one of the system
 * calls that were issued in the meantime.
 *
 * For multi-user applications it is necessary to create different
 * credential contexts, as it is not clear when exactly the real
 * system call will be issued. The application might have called
 * seteuid(2) or something equivalent in the meantime. Thus, all
 * system calls doing access checks, in particular all calls doing
 * path-based operations, require a struct auth_creds_context
 * parameter. asys_creds_context_create() creates such a context. All
 * credential-checking operations take a struct asys_creds_context as
 * an argument. It can be NULL if the application never changes
 * credentials.
 *
 * @{
 */

struct asys_context;
struct asys_creds_context;

enum asys_log_level {
	ASYS_LOG_FATAL = 0,
	ASYS_DEBUG_ERROR,
	ASYS_DEBUG_WARNING,
	ASYS_DEBUG_TRACE
};

#ifndef PRINTF_ATTRIBUTE
#if (__GNUC__ >= 3)
/** Use gcc attribute to check printf fns.  a1 is the 1-based index of
 * the parameter containing the format, and a2 the index of the first
 * argument. Note that some gcc 2.x versions don't handle this
 * properly **/
#define PRINTF_ATTRIBUTE(a1, a2) __attribute__ ((format (__printf__, a1, a2)))
#else
#define PRINTF_ATTRIBUTE(a1, a2)
#endif
#endif

typedef void (*asys_log_fn)(struct asys_context *ctx, void *private_data,
			    enum asys_log_level level,
			    const char *fmt, ...) PRINTF_ATTRIBUTE(4, 5);

int asys_context_init(struct asys_context **ctx, unsigned max_parallel);
int asys_context_destroy(struct asys_context *ctx);
void asys_set_log_fn(struct asys_context *ctx, asys_log_fn fn,
		     void *private_data);

/**
 * @brief Get the the signal fd
 *
 * asys_signalfd() returns a file descriptor that will become readable
 * whenever an asynchronous request has finished. When the signalfd is
 * readable, calling asys_result() will not block.
 *
 * @param[in]	ctx	The asys context
 * @return		A file descriptor indicating a finished operation
 */

int asys_signalfd(struct asys_context *ctx);

/**
 * @brief Pull the result from an async operation
 *
 * Whe the fd returned from asys_signalfd() is readable, an async
 * operation has finished. The result from the async operation can be
 * pulled with asys_result().
 *
 * @param[in]	ctx	The asys context
 * @return		success: 0, failure: errno
 */
int asys_result(struct asys_context *ctx, ssize_t *pret, int *perrno,
		void *pdata);
void asys_cancel(struct asys_context *ctx, void *private_data);

int asys_pread(struct asys_context *ctx, int fildes, void *buf, size_t nbyte,
	       off_t offset, void *private_data);
int asys_pwrite(struct asys_context *ctx, int fildes, const void *buf,
		size_t nbyte, off_t offset, void *private_data);
int asys_ftruncate(struct asys_context *ctx, int filedes, off_t length,
		   void *private_data);
int asys_fsync(struct asys_context *ctx, int fd, void *private_data);
int asys_close(struct asys_context *ctx, int fd, void *private_data);

struct asys_creds_context *asys_creds_context_create(
	struct asys_context *ctx,
	uid_t uid, gid_t gid, unsigned num_gids, gid_t *gids);

int asys_creds_context_delete(struct asys_creds_context *ctx);

int asys_open(struct asys_context *ctx, struct asys_creds_context *cctx,
	      const char *pathname, int flags, mode_t mode,
	      void *private_data);
int asys_unlink(struct asys_context *ctx, struct asys_creds_context *cctx,
		const char *pathname, void *private_data);

/* @} */

#endif /* __ASYS_H__ */
