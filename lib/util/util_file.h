/*
 * Unix SMB/CIFS implementation.
 * SMB parameters and setup
 * Copyright (C) Andrew Tridgell 1992-1998 Modified by Jeremy Allison 1995.
 *
 * Added afdgets() Jelmer Vernooij 2005
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __LIB_UTIL_UTIL_FILE_H__
#define __LIB_UTIL_UTIL_FILE_H__

#include "replace.h"
#include <talloc.h>

/**
 * Read one line (data until next newline or eof) and allocate it
 */
_PUBLIC_ char *afdgets(int fd, TALLOC_CTX *mem_ctx, size_t hint);

char *fgets_slash(TALLOC_CTX *mem_ctx, char *s2, size_t maxlen, FILE *f);

/**
load a file into memory from a fd.
**/
_PUBLIC_ char *fd_load(int fd, size_t *size, size_t maxsize, TALLOC_CTX *mem_ctx);

/**
load a file into memory
**/
_PUBLIC_ char *file_load(const char *fname, size_t *size, size_t maxsize, TALLOC_CTX *mem_ctx);

/**
load a file into memory and return an array of pointers to lines in the file
must be freed with talloc_free().
**/
_PUBLIC_ char **file_lines_load(const char *fname, int *numlines, size_t maxsize, TALLOC_CTX *mem_ctx);

/**
load a fd into memory and return an array of pointers to lines in the file
must be freed with talloc_free(). If convert is true calls unix_to_dos on
the list.
**/
_PUBLIC_ char **fd_lines_load(int fd, int *numlines, size_t maxsize, TALLOC_CTX *mem_ctx);

char **file_lines_parse(const char *p, size_t size, int *numlines, TALLOC_CTX *mem_ctx);

_PUBLIC_ bool file_save_mode(const char *fname, const void *packet,
			     size_t length, mode_t mode);

/**
  save a lump of data into a file. Mostly used for debugging
*/
_PUBLIC_ bool file_save(const char *fname, const void *packet, size_t length);
_PUBLIC_ int vfdprintf(int fd, const char *format, va_list ap) PRINTF_ATTRIBUTE(2,0);
_PUBLIC_ int fdprintf(int fd, const char *format, ...) PRINTF_ATTRIBUTE(2,3);

/*
  compare two files, return true if the two files have the same content
 */
bool file_compare(const char *path1, const char *path2);

/*
  load from a pipe into memory.
 */
char *file_ploadv(char * const argl[], size_t *size);

char **file_lines_ploadv(TALLOC_CTX *mem_ctx,
			 char *const argl[],
			 int *numlines);

FILE *fdopen_keepfd(int fd, const char *mode);

#endif
