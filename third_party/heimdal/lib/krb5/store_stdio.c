/*
 * Copyright (c) 2017 Kungliga Tekniska Högskolan
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

#include "krb5_locl.h"
#include "store-int.h"

#ifndef HAVE_FSEEKO
#define fseeko fseek
#define ftello ftell
#endif

typedef struct stdio_storage {
    FILE *f;
    off_t pos;
} stdio_storage;

#define F(S) (((stdio_storage*)(S)->data)->f)
#define POS(S) (((stdio_storage*)(S)->data)->pos)

static ssize_t
stdio_fetch(krb5_storage * sp, void *data, size_t size)
{
    char *cbuf = (char *)data;
    ssize_t count;
    size_t rem = size;

    /* similar pattern to net_read() to support pipes */
    while (rem > 0) {
	count = fread(cbuf, 1, rem, F(sp));
	if (count < 0) {
	    POS(sp) = -1;
	    if (errno == EINTR)
		continue;
	    else
		return count;
	} else if (count == 0) {
	    if (POS(sp) >= 0)
		POS(sp) += size - rem;
	    return size - rem;
	}
	cbuf += count;
	rem -= count;
    }
    if (POS(sp) >= 0)
	POS(sp) += size;
    return size;
}

static ssize_t
stdio_store(krb5_storage * sp, const void *data, size_t size)
{
    const char *cbuf = (const char *)data;
    ssize_t count;
    size_t rem = size;

    /*
     * It's possible we just went from reading to writing if the file was open
     * for both.  Per C99 (N869 final draft) section 7.18.5.3, point 6, when
     * going from reading to writing [a file opened for both] one must seek.
     */
    (void) fseeko(F(sp), 0, SEEK_CUR);

    /* similar pattern to net_write() to support pipes */
    while (rem > 0) {
	count = fwrite(cbuf, 1, rem, F(sp));
	if (count < 0) {
	    if (errno == EINTR)
		continue;
            /*
             * What does it mean to have a short write when using stdio?
             *
             * It can't mean much.  After all stdio is buffering, so
             * earlier writes that appeared complete may have failed,
             * and so we don't know how much we really failed to write.
             */
	    POS(sp) = -1;
            return -1;
	}
        if (count == 0) {
	    POS(sp) = -1;
            return -1;
	}
	cbuf += count;
	rem -= count;
    }
    if (POS(sp) >= 0)
	POS(sp) += size;
    return size;
}

static off_t
stdio_seek(krb5_storage * sp, off_t offset, int whence)
{
    int save_errno = errno;

    if (whence == SEEK_SET && POS(sp) == offset)
	return POS(sp);

    if (whence == SEEK_CUR && POS(sp) >= 0 && offset == 0)
	return POS(sp);

    if (fseeko(F(sp), offset, whence) != 0)
        return -1;
    errno = save_errno;
    return POS(sp) = ftello(F(sp));
}

static int
stdio_trunc(krb5_storage * sp, off_t offset)
{
    off_t tmpoff;
    int save_errno = errno;

    if (fflush(F(sp)) == EOF)
        return errno;
    tmpoff = ftello(F(sp));
    if (tmpoff < 0)
	return errno;
    if (tmpoff > offset)
	tmpoff = offset;
    if (ftruncate(fileno(F(sp)), offset) == -1)
	return errno;
    if (fseeko(F(sp), 0, SEEK_END) == -1)
        return errno;
    if (fseeko(F(sp), tmpoff, SEEK_SET) == -1)
	return errno;
    errno = save_errno;
    POS(sp) = tmpoff;
    return 0;
}

static int
stdio_sync(krb5_storage * sp)
{
    if (fflush(F(sp)) == EOF)
	return errno;
    if (fsync(fileno(F(sp))) == -1)
	return errno;
    return 0;
}

static void
stdio_free(krb5_storage * sp)
{
    int save_errno = errno;

    if (F(sp) != NULL && fclose(F(sp)) == 0)
        errno = save_errno;
    F(sp) = NULL;
}

/**
 * Open a krb5_storage using stdio for buffering.
 *
 * @return A krb5_storage on success, or NULL on out of memory error.
 *
 * @ingroup krb5_storage
 *
 * @sa krb5_storage_emem()
 * @sa krb5_storage_from_fd()
 * @sa krb5_storage_from_mem()
 * @sa krb5_storage_from_readonly_mem()
 * @sa krb5_storage_from_data()
 * @sa krb5_storage_from_socket()
 */

KRB5_LIB_FUNCTION krb5_storage * KRB5_LIB_CALL
krb5_storage_stdio_from_fd(int fd_in, const char *mode)
{
    krb5_storage *sp;
    off_t off;
    FILE *f;
    int saved_errno = errno;
    int fd;

    off = lseek(fd_in, 0, SEEK_CUR);
    if (off == -1)
        return NULL;

#ifdef _MSC_VER
    /*
     * This function used to try to pass the input to
     * _get_osfhandle() to test if the value is a HANDLE
     * but this doesn't work because doing so throws an
     * exception that will result in Watson being triggered
     * to file a Windows Error Report.
     */
    fd = _dup(fd_in);
#else
    fd = dup(fd_in);
#endif

    if (fd < 0)
        return NULL;

    f = fdopen(fd, mode);
    if (f == NULL) {
        (void) close(fd);
        return NULL;
    }

    errno = saved_errno;

    if (fseeko(f, off, SEEK_SET) == -1) {
        saved_errno = errno;
        (void) fclose(f);
        errno = saved_errno;
	return NULL;
    }

    errno = ENOMEM;
    sp = malloc(sizeof(krb5_storage));
    if (sp == NULL) {
	saved_errno = errno;
	(void) fclose(f);
	errno = saved_errno;
	return NULL;
    }

    errno = ENOMEM;
    sp->data = malloc(sizeof(stdio_storage));
    if (sp->data == NULL) {
	saved_errno = errno;
	(void) fclose(f);
	free(sp);
	errno = saved_errno;
	return NULL;
    }
    sp->flags = 0;
    sp->eof_code = HEIM_ERR_EOF;
    F(sp) = f;
    POS(sp) = off;
    sp->fetch = stdio_fetch;
    sp->store = stdio_store;
    sp->seek = stdio_seek;
    sp->trunc = stdio_trunc;
    sp->fsync = stdio_sync;
    sp->free = stdio_free;
    sp->max_alloc = UINT32_MAX/64;
    return sp;
}
