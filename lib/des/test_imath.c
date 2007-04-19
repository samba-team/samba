/*
 * Copyright (c) 2007 Kungliga Tekniska Högskolan
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
RCSID("$Id$");

#include <stdio.h>
#include <stdlib.h>
#include <err.h>

#include "imath/imath.h"

static void
umr_exptmod(void)
{
    mp_result res;
    mpz_t tmp, z;
    
    res = mp_int_init(&tmp);
    if (res != MP_OK)
	errx(1, "ini_init");
    
    res = mp_int_init(&z);
    if (res != MP_OK)
	errx(1, "ini_init");

    res = mp_int_read_unsigned(&z, (void*)
"\x31\xD2\xA3\x66\xB0\x82\xD2\x61\x20\x85\xDF\xAE\x14\x73\x7C\x3A\xF5\x87\xCE\xED\xD6\x46\xBB\x45\x7C\xAF\x0F\x32\x56\xA7\x93\x87\x79\x36\xED\x29\xB8\xBF\x8B\xD8\x45\x6A\x87\x59\xDD\x03\x93\xD2\x8A\x61\xC0\x61\xA7\x7B\xA6\x24\x2A\xB6\x56\x80\x5D\xE9\x07\xD6\x1F\xF4\x00\xD7\xB4\x8B\xB0\xF9\xF5\x37\x52\xD2\x3A\xE5\xA5\xC4\x46\x65\x25\xEE\xE0\xCC\x12\x0A\x82\x68\x8B\xDF\x51\x92\xB5\x70\x87\xB5\x47\x3B\x40\xF7\x34\x35\x2E\x86\x08\x68\x6B\xAD\x2D\xB1\x12\x52\x9F\xF2\x1E\xB1\xFC\xA0\x19\x87\x7F\x6A\x1A\x35\xDA\xA1", 128);
    if (res != MP_OK)
	errx(1, "int_read");

    res = mp_int_exptmod_bvalue(3, &z, &z, &tmp);
    if (res != MP_OK)
	errx(1, "exptmod_bvalue");
    
    mp_int_clear(&tmp);
    mp_int_clear(&z);
}

int
main(int argc, char **argv)
{
    umr_exptmod();

    return 0;
}
