/*
 * BSD 3-Clause License
 *
 * Copyright (c) 2007,      Stefan Metzmacher <metze@samba.org>
 * Copyright (c) 2009,      Guenther Deschner <gd@samba.org>
 * Copyright (c) 2014-2015, Michael Adam <obnox@samba.org>
 * Copyright (c) 2015,      Robin Hack <hack.robin@gmail.com>
 * Copyright (c) 2013-2018, Andreas Schneider <asn@samba.org>
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

#include <errno.h>
#include <grp.h>
#include <string.h>
#include <stdint.h>

#include "nss_utils.h"

int nwrap_gr_copy_r(const struct group *src, struct group *dst,
		    char *buf, size_t buflen, struct group **dstp)
{
	char *p = NULL;
	uintptr_t align = 0;
	unsigned int gr_mem_cnt = 0;
	unsigned i;
	size_t total_len;
	size_t gr_name_len = strlen(src->gr_name) + 1;
	size_t gr_passwd_len = strlen(src->gr_passwd) + 1;
	union {
		char *ptr;
		char **data;
	} g_mem;

	for (i = 0; src->gr_mem[i] != NULL; i++) {
		gr_mem_cnt++;
	}

	/* Align the memory for storing pointers */
	align = __alignof__(char *) - ((p - (char *)0) % __alignof__(char *));
	total_len = align +
		    (1 + gr_mem_cnt) * sizeof(char *) +
		    gr_name_len + gr_passwd_len;

	if (total_len > buflen) {
		errno = ERANGE;
		return -1;
	}
	buflen -= total_len;

	/* gr_mem */
	p = buf + align;
	g_mem.ptr = p;
	dst->gr_mem = g_mem.data;

	/* gr_name */
	p += (1 + gr_mem_cnt) * sizeof(char *);
	dst->gr_name = p;

	/* gr_passwd */
	p += gr_name_len;
	dst->gr_passwd = p;

	/* gr_mem[x] */
	p += gr_passwd_len;

	/* gr_gid */
	dst->gr_gid = src->gr_gid;

	memcpy(dst->gr_name, src->gr_name, gr_name_len);

	memcpy(dst->gr_passwd, src->gr_passwd, gr_passwd_len);

	/* Set the terminating entry */
	dst->gr_mem[gr_mem_cnt] = NULL;

	/* Now add the group members content */
	total_len = 0;
	for (i = 0; i < gr_mem_cnt; i++) {
		size_t len = strlen(src->gr_mem[i]) + 1;

		dst->gr_mem[i] = p;
		total_len += len;
		p += len;
	}

	if (total_len > buflen) {
		errno = ERANGE;
		return -1;
	}

	for (i = 0; i < gr_mem_cnt; i++) {
		size_t len = strlen(src->gr_mem[i]) + 1;

		memcpy(dst->gr_mem[i],
		       src->gr_mem[i],
		       len);
	}

	if (dstp != NULL) {
		*dstp = dst;
	}

	return 0;
}
