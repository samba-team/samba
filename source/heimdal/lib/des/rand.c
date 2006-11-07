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

RCSID("$Id: rand.c,v 1.7 2006/10/16 10:23:01 lha Exp $");

#include <stdio.h>
#include <stdlib.h>
#include <rand.h>

#include <roken.h>

extern RAND_METHOD hc_rand_unix_method;
static const RAND_METHOD *selected_meth = &hc_rand_unix_method;

void
RAND_seed(const void *indata, size_t size)
{
    (*selected_meth->seed)(indata, size);
}

int
RAND_bytes(void *outdata, size_t size)
{
    return (*selected_meth->bytes)(outdata, size);
}

void
RAND_cleanup(void)
{
    (*selected_meth->cleanup)();
}

void
RAND_add(const void *indata, size_t size, double entropi)
{
    (*selected_meth->add)(indata, size, entropi);
}

int
RAND_pseudo_bytes(void *outdata, size_t size)
{
    return (*selected_meth->pseudorand)(outdata, size);
}

int
RAND_status(void)
{
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
RAND_egd(const char *filename)
{
    return 1;
}
