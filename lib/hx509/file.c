/*
 * Copyright (c) 2005 - 2006 Kungliga Tekniska Högskolan
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

#include "hx_locl.h"
RCSID("$ID$");

int
_hx509_map_file_os(const char *fn, heim_octet_string *os, struct stat *rsb)
{
    size_t length;
    void *data;
    int ret;

    ret = _hx509_map_file(fn, &data, &length, rsb);

    os->data = data;
    os->length = length;

    return ret;
}

void
_hx509_unmap_file_os(heim_octet_string *os)
{
    _hx509_unmap_file(os->data, os->length);
}

int
_hx509_map_file(const char *fn, void **data, size_t *length, struct stat *rsb)
{
    struct stat sb;
    size_t len;
    ssize_t l;
    int ret;
    void *d;
    int fd;

    *data = NULL;
    *length = 0;

    fd = open(fn, O_RDONLY);
    if (fd < 0)
	return errno;
    
    if (fstat(fd, &sb) < 0) {
	ret = errno;
	close(fd);
	return ret;
    }

    len = sb.st_size;

    d = malloc(len);
    if (d == NULL) {
	close(fd);
	return ENOMEM;
    }
    
    l = read(fd, d, len);
    close(fd);
    if (l < 0 || l != len) {
	free(d);
	return EINVAL;
    }

    if (rsb)
	*rsb = sb;
    *data = d;
    *length = len;
    return 0;
}

void
_hx509_unmap_file(void *data, size_t len)
{
    free(data);
}

int
_hx509_write_file(const char *fn, const void *data, size_t length)
{
    ssize_t sz;
    const unsigned char *p = data;
    int fd;

    fd = open(fn, O_WRONLY|O_TRUNC|O_CREAT, 0644);
    if (fd < 0)
	return errno;

    do {
	sz = write(fd, p, length);
	if (sz < 0) {
	    int saved_errno = errno;
	    close(fd);
	    return saved_errno;
	}
	if (sz == 0)
	    break;
	length -= sz;
    } while (length > 0);
		
    if (close(fd) == -1)
	return errno;

    return 0;
}

static void
header(FILE *f, const char *type, const char *str)
{
    fprintf(f, "-----%s %s-----\n", type, str);
}

int
hx509_pem_write(hx509_context context, const char *type, 
		char **headers, FILE *f,
		const void *data, size_t size)
{
    const char *p = data;
    size_t length;
    char *line;
    int i;

#define ENCODE_LINE_LENGTH	54
    
    header(f, "BEGIN", type);

    for(i = 0; headers && headers[i]; i++)
	fprintf(f, "%s\n", headers[i]);
    if (i > 0)
	fprintf(f, "\n");

    while (size > 0) {
	ssize_t l;
	
	length = size;
	if (length > ENCODE_LINE_LENGTH)
	    length = ENCODE_LINE_LENGTH;
	
	l = base64_encode(p, length, &line);
	if (l < 0) {
	    hx509_set_error_string(context, 0, ENOMEM,
				   "malloc - out of memory");
	    return ENOMEM;
	}
	size -= length;
	fprintf(f, "%s\n", line);
	p += length;
	free(line);
    }

    header(f, "END", type);

    return 0;
}
