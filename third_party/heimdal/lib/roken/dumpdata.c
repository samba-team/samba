/*
 * Copyright (c) 2005 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
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
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <config.h>

#include "roken.h"

/*
 * Write datablob to a filename, don't care about errors.
 */

ROKEN_LIB_FUNCTION void ROKEN_LIB_CALL
rk_dumpdata (const char *filename, const void *buf, size_t size)
{
    int fd;

    fd = open(filename, O_WRONLY|O_TRUNC|O_CREAT, 0640);
    if (fd < 0)
	return;
    net_write(fd, buf, size);
    close(fd);
}

/* For not-regular files */
static int
undump_not_file(int fd, char **out, size_t *size, int nul_terminate)
{
    size_t lim = 10 * 1024 * 1024;
    size_t bufsz = 0;
    size_t sz = 0;
    char *buf = NULL;
    char *tmp;

    *out = NULL;
    if (size && *size != 0 && *size < lim)
        lim = *size;
    if (size)
        *size = 0;

    /*
     * We can't use net_read() if we're on WIN32 because that really wants a
     * socket FD, which is in a distinct FD namespace from those returned by
     * open() on Windows.
     */
    do {
        ssize_t bytes;

        if (sz == bufsz) {
            if (bufsz == 0)
                bufsz = 1024;
            else
                bufsz += bufsz >> 1;

            tmp = realloc(buf, bufsz);
            if (tmp == NULL) {
                free(buf);
                return ENOMEM;
            }
            buf = tmp;
        }

        bytes = read(fd, buf + sz, bufsz - sz);
        if (bytes == 0)
            break;
        if (bytes < 0 &&
            (errno == EAGAIN || errno == EWOULDBLOCK))
            continue;
        if (bytes < 0) {
            free(buf);
            return errno;
        }
        sz += bytes;
    } while (sz < lim);

    *out = buf;
    if (size)
        *size = sz;

    if (!nul_terminate)
        return 0;

    if (bufsz > sz) {
        buf[sz] = '\0';
        return 0;
    }

    *out = tmp = realloc(buf, bufsz + 1);
    if (tmp == NULL) {
        free(buf);
        return ENOMEM;
    }
    buf = tmp;
    buf[sz] = '\0';
    return 0;
}

/*
 * Read all data from a file, care about errors.
 *
 * If `*size' is not zero and the file is not a regular file, then up to that
 * many bytes will be read.
 *
 * Returns zero on success or a system error code on failure.
 */

ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
rk_undumpdata(const char *filename, void **buf, size_t *size)
{
    struct stat sb;
    int fd, ret;
    ssize_t sret;

    *buf = NULL;

    fd = open(filename, O_RDONLY, 0);
    if (fd < 0)
	return errno;
    if (fstat(fd, &sb) != 0){
	ret = errno;
	goto out;
    }
    if (!S_ISREG(sb.st_mode)) {
        char *char_buf;

        ret = undump_not_file(fd, &char_buf, size, 0);
        (void) close(fd);
        *buf = char_buf;
        return ret;
    }

    if (sb.st_size < 0)
        sb.st_size = 0;
    *buf = malloc(sb.st_size);
    if (*buf == NULL) {
	ret = ENOMEM;
	goto out;
    }
    *size = sb.st_size;

    sret = read(fd, *buf, *size);
    if (sret < 0)
	ret = errno;
    else if (sret != (ssize_t)*size)
	ret = EINVAL;
    else
	ret = 0;

  out:
    if (ret) {
	free(*buf);
	*buf = NULL;
    }
    close(fd);
    return ret;
}

/*
 * Read all text from a file.
 *
 * Outputs a C string.  It is up to the caller to check for embedded NULs.
 * The number of bytes read will be stored in `*size' if `size' is not NULL.
 *
 * If `size' is not NULL and `*size' is not zero and the file is not a regular
 * file, then up to that many bytes will be read.
 *
 * Returns zero on success or a system error code on failure.
 */

ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
rk_undumptext(const char *filename, char **out, size_t *size)
{
    struct stat sb;
    int fd, ret;
    ssize_t sret;
    char *buf;

    *out = NULL;

    fd = open(filename, O_RDONLY, 0);
    if (fd < 0)
        return errno;
    if (fstat(fd, &sb) != 0) {
        (void) close(fd);
	return errno;
    }
    if (!S_ISREG(sb.st_mode)) {
        ret = undump_not_file(fd, out, size, 1);
        (void) close(fd);
        return ret;
    }

    if (sb.st_size < 0)
        sb.st_size = 0;
    buf = malloc(sb.st_size + 1);
    if (buf == NULL) {
	ret = ENOMEM;
	goto out;
    }
    if (size)
        *size = sb.st_size;

    sret = read(fd, buf, sb.st_size);
    if (sret < 0)
	ret = errno;
    else if (sret != (ssize_t)sb.st_size)
	ret = EINVAL;
    else
	ret = 0;

out:
    if (ret) {
	free(buf);
    } else {
        buf[sb.st_size] = '\0';
        *out = buf;
    }
    close(fd);
    return ret;
}
