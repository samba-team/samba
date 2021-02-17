/*
 * BSD 3-Clause License
 *
 * Copyright (c) 2005-2008, Jelmer Vernooij <jelmer@samba.org>
 * Copyright (c) 2006-2021, Stefan Metzmacher <metze@samba.org>
 * Copyright (c) 2013-2021, Andreas Schneider <asn@samba.org>
 * Copyright (c) 2014-2017, Michael Adam <obnox@samba.org>
 * Copyright (c) 2016-2018, Anoop C S <anoopcs@redhat.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the author nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef __SOCKET_WRAPPER_H__
#define __SOCKET_WRAPPER_H__ 1

#include <stdbool.h>

/*
   Socket wrapper advanced helpers.

   Applications with the need to alter their behaviour when
   socket wrapper is active, can link use these functions.

   By default it's required for applications to use any of these
   functions as libsocket_wrapper.so is injected at runtime via
   LD_PRELOAD.

   Applications using these functions should link against
   libsocket_wrapper_noop.so by using -lsocket_wrapper_noop,
   or implement their own noop stubs.
*/

/*
 * This returns true when socket wrapper is actively in use.
 */
bool socket_wrapper_enabled(void);

/*
 * This allows socket_wrapper aware applications to
 * indicate that the given fd does not belong to
 * an inet socket.
 *
 * socket_wrapper may not be able to intercept the __close_nocancel()
 * syscall made from within libc.so. As result it's possible
 * that the in memory meta date of socket_wrapper references
 * stale file descriptors, which are already reused for unrelated
 * kernel objects, e.g. files, directories, ...
 *
 * Socket wrapper already intercepts a lot of unrelated
 * functions like eventfd(), timerfd_create(), ... in order
 * to remove stale meta data for the returned fd, but
 * it will never be able to handle all possible syscalls.
 *
 * socket_wrapper_indicate_no_inet_fd() gives applications a way
 * to do the same, explicitly without waiting for new syscalls to
 * be added to libsocket_wrapper.so.
 *
 * This is a no-op if socket_wrapper is not in use or
 * if the there is no in memory meta data for the given fd.
 */
void socket_wrapper_indicate_no_inet_fd(int fd);

#endif /* __SOCKET_WRAPPER_H__ */
