/*
 * Copyright (c) 1997 - 1999 Kungliga Tekniska Högskolan
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

RCSID("$Id$");

static char *
get_logname(void)
{
    char *p;
    if((p = getenv("USER")))
	return p;
    if((p = getenv("LOGNAME")))
	return p;
    if((p = getenv("USERNAME")))
	return p;
#if defined(HAVE_GETLOGIN) && !defined(POSIX_GETLOGIN)
    if((p = getlogin()))
	return p;
#endif
    return NULL;
}

krb5_error_code
krb5_get_default_principal (krb5_context context,
			    krb5_principal *princ)
{
    krb5_error_code ret;
    struct passwd *pw;
    char *p;
    krb5_ccache id;

    ret = krb5_cc_default(context, &id);
    if(ret == 0){
	ret = krb5_cc_get_principal(context, id, princ);
	krb5_cc_close(context, id);
	if(ret == 0)
	    return 0;
    }

    pw = getpwuid(getuid());
    if(pw == NULL) {
	p = get_logname();
	if(p == NULL)
	    return ENOTTY;
	ret = krb5_make_principal(context, princ, NULL, p, NULL);
    }else{
	if(strcmp(pw->pw_name, "root") == 0){
	    p = get_logname();
	    ret = krb5_make_principal(context, princ, NULL, pw->pw_name, 
				      "root", NULL);
	}else
	    ret = krb5_make_principal(context, princ, NULL, pw->pw_name, NULL);
    }
    return ret;
}
