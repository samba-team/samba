/*
 * Copyright (c) 1997 Kungliga Tekniska Högskolan
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
 * 3. All advertising materials mentioning features or use of this software 
 *    must display the following acknowledgement: 
 *      This product includes software developed by Kungliga Tekniska 
 *      Högskolan and its contributors. 
 *
 * 4. Neither the name of the Institute nor the names of its contributors 
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
RCSID("$Id$");
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "com_err.h"

static struct error_table *et_list;

const char *
error_message (long code)
{
    static char msg[128];
    const char *p = com_right(et_list, code);
    if(p){
	strncpy(msg, p, sizeof(msg));
	msg[sizeof(msg)-1] = '\0';
    } else{
	snprintf(msg, sizeof(msg), "Unknown error %d", code);
    }
    return msg;
}

int
init_error_table(const char **msgs, long base, int count)
{
    initialize_error_table_r(&et_list, msgs, count, base);
    return 0;
}

static void
default_proc (const char *whoami, long code, const char *fmt, va_list args)
{
    char f[sizeof("%s: %s %s\r\n")] = "";
    char *x;
    const void *arg[3], **ap = arg;
    
    if(whoami) {
	strcat(f, "%s: ");
	*ap++ = whoami;
    }
    if(code) {
	strcat(f, "%s ");
	*ap++ = error_message(code);
    }
    if(fmt) {
	strcat(f, "%s");
	*ap++ = fmt;
    }
    strcat(f, "\r\n");
    asprintf(&x, f, arg[0], arg[1], arg[2]);
    vfprintf(stderr, x, args);
    free(x);
    fflush(stderr);
}

static errf com_err_hook = default_proc;

void 
com_err_va (const char *whoami, 
	    long code, 
	    const char *fmt, 
	    va_list args)
{
    (*com_err_hook) (whoami, code, fmt, args);
}

void
com_err (const char *whoami,
	 long code,
	 const char *fmt, 
	 ...)
{
    va_list ap;
    va_start(ap, fmt);
    com_err_va (whoami, code, fmt, ap);
    va_end(ap);
}

errf
set_com_err_hook (errf new)
{
    errf old = com_err_hook;

    if (new)
	com_err_hook = new;
    else
	com_err_hook = default_proc;
    
    return old;
}

errf
reset_com_err_hook (void) 
{
    return set_com_err_hook(NULL);
}
