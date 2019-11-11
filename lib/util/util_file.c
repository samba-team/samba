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

#include "replace.h"
#include "system/shmem.h"
#include "system/filesys.h"
#include <talloc.h>
#include "lib/util/samba_util.h"
#include "lib/util/sys_popen.h"
#include "lib/util/sys_rw.h"
#include "lib/util/debug.h"

/**
 * Read one line (data until next newline or eof) and allocate it
 */
_PUBLIC_ char *afdgets(int fd, TALLOC_CTX *mem_ctx, size_t hint)
{
	char *data = NULL;
	ssize_t alloc_size = 0, offset = 0, ret;
	int p;

	if (hint <= 0) hint = 0x100;

	do {
		alloc_size += hint;

		data = talloc_realloc(mem_ctx, data, char, alloc_size);

		if (!data)
			return NULL;

		ret = read(fd, data + offset, hint);

		if (ret == 0) {
			return NULL;
		}

		if (ret == -1) {
			talloc_free(data);
			return NULL;
		}

		/* Find newline */
		for (p = 0; p < ret; p++) {
			if (data[offset + p] == '\n')
				break;
		}

		if (p < ret) {
			data[offset + p] = '\0';

			/* Go back to position of newline */
			lseek(fd, p - ret + 1, SEEK_CUR);
			return data;
		}

		offset += ret;

	} while ((size_t)ret == hint);

	data[offset] = '\0';

	return data;
}

char *fgets_slash(TALLOC_CTX *mem_ctx, char *s2, size_t maxlen, FILE *f)
{
	char *s = s2;
	size_t len = 0;
	int c;
	bool start_of_line = true;

	if (feof(f)) {
		return NULL;
	}

	if (maxlen < 2) {
		return NULL;
	}

	if (s2 == NULL) {
		maxlen = MIN(maxlen,8);
		s = talloc_array(mem_ctx, char, maxlen);
	}

	if (s == NULL) {
		return NULL;
	}

	*s = 0;

	while (len < maxlen-1) {
		c = getc(f);
		switch (c)
		{
		    case '\r':
			    break;
		    case '\n':
			    while (len > 0 && s[len-1] == ' ') {
				    s[--len] = 0;
			    }
			    if (len > 0 && s[len-1] == '\\') {
				    s[--len] = 0;
				    start_of_line = true;
				    break;
			    }
			    return s;
		    case EOF:
			    if (len <= 0 && (s2 == NULL)) {
				    TALLOC_FREE(s);
			    }
			    return (len>0) ? s : NULL;
		    case ' ':
			    if (start_of_line) {
				    break;
			    }

			    FALL_THROUGH;
		    default:
			    start_of_line = false;
			    s[len++] = c;
			    s[len] = 0;
		}
		if ((s2 == NULL) && (len > maxlen-3)) {
			size_t m;
			char *t;

			m = maxlen * 2;
			if (m < maxlen) {
				DBG_ERR("length overflow");
				TALLOC_FREE(s);
				return NULL;
			}
			maxlen = m;

			t = talloc_realloc(mem_ctx, s, char, maxlen);
			if (t == NULL) {
				DBG_ERR("failed to expand buffer!\n");
				TALLOC_FREE(s);
				return NULL;
			}

			s = t;
		}
	}

	return s;
}

/**
load a file into memory from a fd.
**/
_PUBLIC_ char *fd_load(int fd, size_t *psize, size_t maxsize, TALLOC_CTX *mem_ctx)
{
	FILE *file;
	char *p = NULL;
	size_t size = 0;
	size_t chunk = 1024;
	int err;

	if (maxsize == 0) {
		maxsize = SIZE_MAX;
	}

	file = fdopen(fd, "r");
	if (file == NULL) {
		return NULL;
	}

	while (size < maxsize) {
		size_t newbufsize;
		size_t nread;

		chunk = MIN(chunk, (maxsize - size));

		newbufsize = size + (chunk+1); /* chunk+1 can't overflow */
		if (newbufsize < size) {
			goto fail; /* overflow */
		}

		p = talloc_realloc(mem_ctx, p, char, newbufsize);
		if (p == NULL) {
			goto fail;
		}

		nread = fread(p+size, 1, chunk, file);
		size += nread;

		if (nread != chunk) {
			break;
		}
	}

	err = ferror(file);
	if (err != 0) {
		goto fail;
	}

	p[size] = '\0';

	if (psize != NULL) {
		*psize = size;
	}

	fclose(file);
	return p;

fail:
	TALLOC_FREE(p);
	fclose(file);
	return NULL;
}

/**
load a file into memory
**/
_PUBLIC_ char *file_load(const char *fname, size_t *size, size_t maxsize, TALLOC_CTX *mem_ctx)
{
	int fd;
	char *p;

	if (!fname || !*fname) return NULL;

	fd = open(fname,O_RDONLY);
	if (fd == -1) return NULL;

	p = fd_load(fd, size, maxsize, mem_ctx);

	close(fd);

	return p;
}

/**
parse a buffer into lines
'p' will be freed on error, and otherwise will be made a child of the returned array
**/
char **file_lines_parse(char *p, size_t size, int *numlines, TALLOC_CTX *mem_ctx)
{
	unsigned int i;
	char *s, **ret;

	if (!p) return NULL;

	for (s = p, i=0; s < p+size; s++) {
		if (s[0] == '\n') i++;
	}

	ret = talloc_zero_array(mem_ctx, char *, i+2);
	if (!ret) {
		talloc_free(p);
		return NULL;
	}

	talloc_steal(ret, p);

	ret[0] = p;
	for (s = p, i=1; s < p+size; s++) {
		if (s[0] == '\n') {
			s[0] = 0;
			ret[i] = s+1;
			i++;
		}
		if (s[0] == '\r') s[0] = 0;
	}

	/* remove any blank lines at the end */
	while (i > 0 && ret[i-1][0] == 0) {
		i--;
	}

	if (numlines) *numlines = i;

	return ret;
}


/**
load a file into memory and return an array of pointers to lines in the file
must be freed with talloc_free().
**/
_PUBLIC_ char **file_lines_load(const char *fname, int *numlines, size_t maxsize, TALLOC_CTX *mem_ctx)
{
	char *p;
	size_t size;

	p = file_load(fname, &size, maxsize, mem_ctx);
	if (!p) return NULL;

	return file_lines_parse(p, size, numlines, mem_ctx);
}

/**
load a fd into memory and return an array of pointers to lines in the file
must be freed with talloc_free(). If convert is true calls unix_to_dos on
the list.
**/
_PUBLIC_ char **fd_lines_load(int fd, int *numlines, size_t maxsize, TALLOC_CTX *mem_ctx)
{
	char *p;
	size_t size;

	p = fd_load(fd, &size, maxsize, mem_ctx);
	if (!p) return NULL;

	return file_lines_parse(p, size, numlines, mem_ctx);
}

_PUBLIC_ bool file_save_mode(const char *fname, const void *packet,
			     size_t length, mode_t mode)
{
	ssize_t num_written;
	int fd;
	fd = open(fname, O_WRONLY|O_CREAT|O_EXCL, mode);
	if (fd == -1) {
		return false;
	}
	num_written = write(fd, packet, length);
	if (num_written == -1 || (size_t)num_written != length) {
		close(fd);
		return false;
	}
	close(fd);
	return true;
}

/**
  save a lump of data into a file. Mostly used for debugging
*/
_PUBLIC_ bool file_save(const char *fname, const void *packet, size_t length)
{
	return file_save_mode(fname, packet, length, 0644);
}

_PUBLIC_ int vfdprintf(int fd, const char *format, va_list ap)
{
	char *p;
	int len, ret;
	va_list ap2;

	va_copy(ap2, ap);
	len = vasprintf(&p, format, ap2);
	va_end(ap2);
	if (len <= 0) return len;
	ret = write(fd, p, len);
	SAFE_FREE(p);
	return ret;
}

_PUBLIC_ int fdprintf(int fd, const char *format, ...)
{
	va_list ap;
	int ret;

	va_start(ap, format);
	ret = vfdprintf(fd, format, ap);
	va_end(ap);
	return ret;
}


/*
  compare two files, return true if the two files have the same content
 */
bool file_compare(const char *path1, const char *path2)
{
	FILE *f1 = NULL, *f2 = NULL;
	uint8_t buf1[1024], buf2[1024];
	bool ret = false;

	f1 = fopen(path1, "r");
	if (f1 == NULL) {
		goto done;
	}
	f2 = fopen(path2, "r");
	if (f2 == NULL) {
		goto done;
	}

	while (!feof(f1)) {
		size_t n1 = fread(buf1, 1, sizeof(buf1), f1);
		size_t n2 = fread(buf2, 1, sizeof(buf2), f2);

		if (n1 != n2) {
			goto done;
		}
		if (n1 == 0) {
			ret = (feof(f1) && feof(f2));
			goto done;
		}
		if (memcmp(buf1, buf2, n1) != 0) {
			goto done;
		}
		if (n1 < sizeof(buf1)) {
			bool has_error = (ferror(f1) || ferror(f2));
			if (has_error) {
				goto done;
			}
		}
	}
	ret = true;
done:
	if (f2 != NULL) {
		fclose(f2);
	}
	if (f1 != NULL) {
		fclose(f1);
	}
	return ret;
}

/**
 Load from a pipe into memory.
**/
char *file_ploadv(char * const argl[], size_t *size)
{
	int fd, n;
	char *p = NULL;
	char buf[1024];
	size_t total;

	fd = sys_popenv(argl);
	if (fd == -1) {
		return NULL;
	}

	total = 0;

	while ((n = sys_read(fd, buf, sizeof(buf))) > 0) {
		p = talloc_realloc(NULL, p, char, total + n + 1);
		if (p == NULL) {
		        DBG_ERR("failed to expand buffer!\n");
			close(fd);
			return NULL;
		}
		memcpy(p+total, buf, n);
		total += n;
	}

	if (p != NULL) {
		p[total] = 0;
	}

	/*
	 * FIXME: Perhaps ought to check that the command completed
	 * successfully (returned 0); if not the data may be
	 * truncated.
	 */
	sys_pclose(fd);

	if (size) {
		*size = total;
	}

	return p;
}
