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

#include "hx_locl.h"
RCSID("$Id: error.c,v 1.4 2006/11/16 15:08:09 lha Exp $");

struct hx509_error_data {
    hx509_error next;
    int code;
    char *msg;
};

static void
free_error_string(hx509_error msg)
{
    while(msg) {
	hx509_error m2 = msg->next;
	free(msg->msg);
	free(msg);
	msg = m2;
    }
}

void
hx509_clear_error_string(hx509_context context)
{
    free_error_string(context->error);
    context->error = NULL;
}

void
hx509_set_error_stringv(hx509_context context, int flags, int code, 
			const char *fmt, va_list ap)
{
    hx509_error msg;

    msg = calloc(1, sizeof(*msg));
    if (msg == NULL) {
	hx509_clear_error_string(context);
	return;
    }

    if (vasprintf(&msg->msg, fmt, ap) == -1) {
	hx509_clear_error_string(context);
	free(msg);
	return;
    }
    msg->code = code;

    if (flags & HX509_ERROR_APPEND) {
	msg->next = context->error;
	context->error = msg;
    } else  {
	free_error_string(context->error);
	context->error = msg;
    }
}

void
hx509_set_error_string(hx509_context context, int flags, int code, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    hx509_set_error_stringv(context, flags, code, fmt, ap);
    va_end(ap);
}

char *
hx509_get_error_string(hx509_context context, int error_code)
{
    struct rk_strpool *p = NULL;
    hx509_error msg;

    if (context->error == NULL) {
	const char *cstr;
	char *str;

	cstr = com_right(context->et_list, error_code);
	if (cstr)
	    return strdup(cstr);
	cstr = strerror(error_code);
	if (cstr)
	    return strdup(cstr);
	if (asprintf(&str, "<unknown error: %d>", error_code) == -1)
	    return NULL;
	return str;
    }

    for (msg = context->error; msg; msg = msg->next)
	p = rk_strpoolprintf(p, "%s%s", msg->msg, 
			     msg->next != NULL ? "; " : "");

    return rk_strpoolcollect(p);
}

void
hx509_err(hx509_context context, int exit_code, int error_code, char *fmt, ...)
{
    va_list ap;
    char *msg, *str;

    va_start(ap, fmt);
    vasprintf(&str, fmt, ap);
    va_end(ap);
    msg = hx509_get_error_string(context, error_code);
    if (msg == NULL)
	msg = "no error";

    errx(exit_code, "%s: %s", str, msg);
}
