/*
 * Copyright (c) 2006 Kungliga Tekniska Högskolan
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

RCSID("$Id$");

#include <stdio.h>
#include <stdlib.h>
#include <rand.h>

#include <roken.h>

const RAND_METHOD *default_meth;

static int
get_device_fd(void)
{
    static const char *rnd_devices[] = {
	"/dev/random",
	"/dev/srandom",
	"/dev/urandom",
	"/dev/arandom",
	NULL
    };
    const char **p;

    for(p = rnd_devices; *p; p++) {
	int fd = open(*p, O_RDONLY | O_NDELAY);
	if(fd >= 0)
	    return fd;
    }
    return -1;
}

int
RAND_bytes(void *outdata, size_t size)
{
    ssize_t ret;
    int fd;

    fd = get_device_fd();
    if (fd < 0)
	return 0;

    ret = read(fd, outdata, size);
    close(fd);
    if (size != ret)
	return 0;

    return 1;
}

int
RAND_pseudo_bytes(void *outdata, size_t num)
{
    return RAND_bytes(outdata, num);
}

void
RAND_seed(const void *indata, size_t size)
{
    int fd = get_device_fd();
    if (fd < 0)
	return;

    write(fd, indata, size);
    close(fd);
}

int
RAND_set_rand_method(const RAND_METHOD *meth)
{
    default_meth = meth;
    return 1;
}

const RAND_METHOD *
RAND_get_rand_method(void)
{
    return default_meth;
}

int
RAND_set_rand_engine(ENGINE *engine)
{
    return 1;
}

int
RAND_load_file(const char *filename, size_t size)
{
    return 1;
}

int
RAND_write_file(const char *filename)
{
    return 1;
}

int
RAND_status(void)
{
    return 1;
}

int
RAND_egd(const char *filename)
{
    return 1;
}
