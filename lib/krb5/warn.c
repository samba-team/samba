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

#include "krb5_locl.h"
#include <err.h>

RCSID("$Id$");


krb5_error_code
krb5_warn(krb5_context context, krb5_error_code code, const char *fmt, ...)
{
    char *msg;
    va_list ap;
    va_start(ap, fmt);
    vasprintf(&msg, fmt, ap);
    va_end(ap);
    if(msg == NULL)
	return ENOMEM;
    if(context->warn_dest)
	krb5_log(context, context->warn_dest, 0, "%s: %s", 
		 msg, krb5_get_err_text(context, code));
    else 
	warnx("%s: %s", msg, krb5_get_err_text(context, code));
    free(msg);
    return 0;
}

krb5_error_code
krb5_warnx(krb5_context context, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    if(context->warn_dest)
	krb5_vlog(context, context->warn_dest, 0, fmt, ap);
    else
	vwarnx(fmt, ap);
    va_end(ap);
    return 0;
}

krb5_error_code
krb5_set_warn_dest(krb5_context context, krb5_log_facility *fac)
{
    context->warn_dest = fac;
    return 0;
}
