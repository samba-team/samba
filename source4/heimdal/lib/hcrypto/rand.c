/*
 * Copyright (c) 2006 - 2007 Kungliga Tekniska Högskolan
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

RCSID("$Id: rand.c 20126 2007-02-01 22:08:41Z lha $");

#include <stdio.h>
#include <stdlib.h>
#include <rand.h>
#include <randi.h>

#include <roken.h>

#ifndef O_BINARY
#define O_BINARY 0
#endif


const static RAND_METHOD *selected_meth = NULL;

static void
init_method(void)
{
    if (selected_meth != NULL)
	return;

    if ((*hc_rand_unix_method.status)() == 1)
	selected_meth = &hc_rand_unix_method;
    else
	selected_meth = &hc_rand_fortuna_method;
}

void
RAND_seed(const void *indata, size_t size)
{
    init_method();
    (*selected_meth->seed)(indata, size);
}

int
RAND_bytes(void *outdata, size_t size)
{
    init_method();
    return (*selected_meth->bytes)(outdata, size);
}

void
RAND_cleanup(void)
{
    init_method();
    (*selected_meth->cleanup)();
}

void
RAND_add(const void *indata, size_t size, double entropi)
{
    init_method();
    (*selected_meth->add)(indata, size, entropi);
}

int
RAND_pseudo_bytes(void *outdata, size_t size)
{
    init_method();
    return (*selected_meth->pseudorand)(outdata, size);
}

int
RAND_status(void)
{
    init_method();
    return (*selected_meth->status)();
}

int
RAND_set_rand_method(const RAND_METHOD *meth)
{
    selected_meth = meth;
    return 1;
}

const RAND_METHOD *
RAND_get_rand_method(void)
{
    return selected_meth;
}

int
RAND_set_rand_engine(ENGINE *engine)
{
    return 1;
}

#define RAND_FILE_SIZE 1024

int
RAND_load_file(const char *filename, size_t size)
{
    unsigned char buf[128];
    size_t len;
    ssize_t slen;
    int fd;

    fd = open(filename, O_RDONLY | O_BINARY, 0600);
    if (fd < 0)
	return 0;

    len = 0;
    while(len < size) {
	slen = read(fd, buf, sizeof(buf));
	if (slen <= 0)
	    break;
	RAND_seed(buf, slen);
	len += slen;
    }
    close(fd);

    return len ? 1 : 0;
}

int
RAND_write_file(const char *filename)
{
    unsigned char buf[128];
    size_t len;
    int res = 0, fd;

    fd = open(filename, O_WRONLY | O_CREAT | O_BINARY, 0600);
    if (fd < 0)
	return 0;

    len = 0;
    while(len < RAND_FILE_SIZE) {
	res = RAND_bytes(buf, sizeof(buf));
	if (res != 1)
	    break;
	if (write(fd, buf, sizeof(buf)) != sizeof(buf)) {
	    res = 0;
	    break;
	}
	len += sizeof(buf);
    }

    close(fd);

    return res;
}

const char *
RAND_file_name(char *filename, size_t size)
{
    const char *e = NULL;
    int pathp = 0, ret;

    if (!issuid()) {
	e = getenv("RANDFILE");
	if (e == NULL) {
	    e = getenv("HOME");
	    if (e)
		pathp = 1;
	}
    }
    if (e == NULL) {
	struct passwd *pw = getpwuid(getuid());	
	if (pw) {
	    e = pw->pw_dir;
	    pathp = 1;
	}
    }
    if (e == NULL)
	return NULL;

    if (pathp)
	ret = snprintf(filename, size, "%s/.rnd", e);
    else
	ret = snprintf(filename, size, "%s", e);

    if (ret <= 0 || ret >= size)
	return NULL;

    return filename;
}
