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

RCSID("$Id$");

/* Public principal handling functions */

#define num_components(P) ((P)->name.name_string.len)
#define princ_type(P) ((P)->name.name_type)

void
krb5_free_principal(krb5_context context,
		    krb5_principal p)
{
    if(p){
	free_Principal(p);
	free(p);
    }
}

krb5_error_code
krb5_parse_name(krb5_context context,
		const char *name,
		krb5_principal *principal)
{

    general_string *comp;
    general_string realm;
    int ncomp;

    char *p;
    char *q;
    char *s;
    char *start;

    int n;
    char c;
    int got_realm = 0;
  
    /* count number of component */
    ncomp = 1;
    for(p = (char*)name; *p; p++){
	if(*p=='\\'){
	    if(!p[1])
		return KRB5_PARSE_MALFORMED;
	    p++;
	} else if(*p == '/')
	    ncomp++;
    }
    comp = calloc(ncomp, sizeof(*comp));
  
    n = 0;
    start = q = p = s = strdup(name);
    while(*p){
	c = *p++;
	if(c == '\\'){
	    c = *p++;
	    if(c == 'n')
		c = '\n';
	    else if(c == 't')
		c = '\t';
	    else if(c == 'b')
		c = '\b';
	    else if(c == '0')
		c = '\0';
	}else if(c == '/' || c == '@'){
	    if(got_realm){
	    exit:
		while(n>0){
		    free(comp[--n]);
		}
		free(comp);
		free(s);
		return KRB5_PARSE_MALFORMED;
	    }else{
		comp[n] = malloc(q - start + 1);
		strncpy(comp[n], start, q - start);
		comp[n][q - start] = 0;
		n++;
	    }
	    if(c == '@')
		got_realm = 1;
	    start = q;
	    continue;
	}
	if(got_realm && (c == ':' || c == '/' || c == '\0'))
	    goto exit;
	*q++ = c;
    }
    if(got_realm){
	realm = malloc(q - start + 1);
	strncpy(realm, start, q - start);
	realm[q - start] = 0;
    }else{
	krb5_get_default_realm (context, &realm);

	comp[n] = malloc(q - start + 1);
	strncpy(comp[n], start, q - start);
	comp[n][q - start] = 0;
	n++;
    }
    *principal = malloc(sizeof(**principal));
    (*principal)->name.name_type = KRB5_NT_PRINCIPAL;
    (*principal)->name.name_string.val = comp;
    num_components(*principal) = n;
    (*principal)->realm = realm;
    free(s);
    return 0;
}

static void quote_string(char *s, int len, char **out)
{
    char *q;
    char *p = *out;
    int c=0;
    len = strlen(s);
    for(q = s; q < s + len; q++){
	if(*q == '\n')
	    c = 'n';
	else if(*q == '\t')
	    c = 't';
	else if(*q == '\b')
	    c = 'b';
	else if(*q == '\0')
	    c = '0';
	else if(*q == '/')
	    c='/';      
	else if(*q == '@')
	    c = '@';
	if(c){
	    *p++ = '\\';
	    *p++ = c;
	    c = 0;
	}else
	    *p++ = *q;
    }
    *out = p;
}


krb5_error_code
krb5_unparse_name(krb5_context context,
		  krb5_principal principal,
		  char **name)
{
    int size;
    char *p;
    char *s;
    int i;
    int ncomp = num_components(principal);
    size = 2 * strlen(principal->realm) + 1;
    for (i = 0; i < ncomp; i++)
	size += 2 * strlen(principal->name.name_string.val[i]) + 1;
    s = malloc(size);
    p = s;
    for(i = 0; i < ncomp; i++){
	if(i) *p++ = '/';
	quote_string(
		     principal->name.name_string.val[i], 0,
		     &p);
    }
    *p++ = '@';
    quote_string(principal->realm, 0, &p);
    *p = 0;
    *name = s;
    return 0;
}


krb5_error_code
krb5_unparse_name_ext(krb5_context context,
		      krb5_const_principal principal,
		      char **name,
		      size_t *size)
{
    fprintf(stderr, "krb5_unparse_name_ext: not implemented\n");
    abort();
}


krb5_realm*
krb5_princ_realm(krb5_context context,
		 krb5_principal principal)
{
    return &principal->realm;
}


void
krb5_princ_set_realm(krb5_context context,
		     krb5_principal principal,
		     krb5_realm *realm)
{
    principal->realm = *realm;
}


krb5_error_code
krb5_build_principal(krb5_context context,
		     krb5_principal *principal,
		     int rlen,
		     const char *realm,
		     ...)
{
    krb5_error_code ret;
    va_list ap;
    va_start(ap, realm);
    ret = krb5_build_principal_va(context, principal, rlen, realm, ap);
    va_end(ap);
    return ret;
}

krb5_error_code
krb5_principal_set_component(krb5_context context, krb5_principal p, 
			     int n, void *data, size_t len)
{
    general_string *tmp = p->name.name_string.val;
    if(num_components(p) <= n){
	int s = n + 10;
	tmp = realloc(tmp, s * sizeof(*tmp));
	if(!tmp)
	    return ENOMEM;
	memset(tmp + num_components(p), 0, 
	       (s - num_components(p)) * sizeof(*tmp));
	p->name.name_string.val = tmp;
	num_components(p)= s;
    }
    if(p->name.name_string.val[n])
	free(p->name.name_string.val[n]);
    p->name.name_string.val[n] = malloc(len + 1);
    strncpy(p->name.name_string.val[n], data, len);
    p->name.name_string.val[n][len] = 0;
    return 0;
}

static void
va_ext_princ(krb5_context context, krb5_principal p, va_list ap)
{
    int n = 0;
    while(1){
	char *s;
	int len;
	len  = va_arg(ap, int);
	if(len == 0)
	    break;
	s = va_arg(ap, char*);
	krb5_principal_set_component(context, p, n, s, len);
	n++;
    }
    num_components(p) = n;
}

static void
va_princ(krb5_context context, krb5_principal p, va_list ap)
{
    int n = 0;
    while(1){
	char *s;
	int len;
	s = va_arg(ap, char*);
	if(s == NULL)
	    break;
	len = strlen(s);
	krb5_principal_set_component(context, p, n, s, len);
	n++;
    }
    num_components(p) = n;
}


static krb5_error_code
build_principal(krb5_context context,
		krb5_principal *principal,
		int rlen,
		const char *realm,
		void (*func)(krb5_context, krb5_principal, va_list),
		va_list ap)
{
    krb5_principal p;
    int n;
  
    p = calloc(1, sizeof(*p));
    if (p == NULL)
	return ENOMEM;
    princ_type(p) = KRB5_NT_PRINCIPAL;

    p->realm = strdup(realm);
    if(p->realm == NULL){
	free(p);
	return ENOMEM;
    }
  
    (*func)(context, p, ap);
    *principal = p;
    return 0;
}

krb5_error_code
krb5_build_principal_va(krb5_context context, 
			krb5_principal *principal, 
			int rlen,
			const char *realm,
			va_list ap)
{
    return build_principal(context, principal, rlen, realm, va_princ, ap);
}

/* Not part of MIT K5 API */
krb5_error_code
krb5_build_principal_va_ext(krb5_context context, 
			    krb5_principal *principal, 
			    int rlen,
			    const char *realm,
			    va_list ap)
{
    return build_principal(context, principal, rlen, realm, va_ext_princ, ap);
}


krb5_error_code
krb5_build_principal_ext(krb5_context context,
			 krb5_principal *principal,
			 int rlen,
			 const char *realm,
			 ...)
{
    krb5_error_code ret;
    va_list ap;
    va_start(ap, realm);
    ret = krb5_build_principal_va_ext(context, principal, rlen, realm, ap);
    va_end(ap);
    return ret;
}


krb5_error_code
krb5_copy_principal(krb5_context context,
		    krb5_const_principal inprinc,
		    krb5_principal *outprinc)
{
    krb5_principal p;
    int i;
    p = calloc(1, sizeof(*p));
    if (p == NULL)
	return ENOMEM;
    copy_PrincipalName(&inprinc->name, &p->name);
    copy_Realm(&inprinc->realm, &p->realm);
    *outprinc = p;
    return 0;
}


krb5_boolean
krb5_principal_compare(krb5_context context,
		       krb5_const_principal princ1,
		       krb5_const_principal princ2)
{
    int i;
    if(!krb5_realm_compare(context, princ1, princ2))
	return FALSE;
    if(num_components(princ1) != num_components(princ2))
	return FALSE;
    for(i = 0; i < num_components(princ1); i++){
	if(strcmp(princ1->name.name_string.val[i], 
		  princ2->name.name_string.val[i]) != 0)
	    return FALSE;
    }
    return TRUE;
}


krb5_boolean
krb5_realm_compare(krb5_context context,
		   krb5_const_principal princ1,
		   krb5_const_principal princ2)
{
    return strcmp(princ1->realm, princ2->realm) == 0;
}

		   
krb5_error_code
krb5_425_conv_principal(krb5_context context,
			const char *name,
			const char *instance,
			const char *realm,
			krb5_principal *princ)
{
    if(!strcmp(name, "rcmd"))
	name = "host";
    return krb5_build_principal(context, princ, 
				strlen(realm), 
				realm, 
				name, 
				(instance && instance[0]) ? instance : NULL, 
				0);
}

krb5_error_code
krb5_524_conv_principal(krb5_context context,
			const krb5_principal principal,
			char *name, 
			char *instance,
			char *realm)
{
    char *n, *i, *r;
    char tmpinst[40];
    r = principal->realm;

    switch(principal->name.name_string.len){
    case 1:
	n = principal->name.name_string.val[0];
	i = "";
	break;
    case 2:
	n = principal->name.name_string.val[0];
	i = principal->name.name_string.val[1];
	break;
    default:
	return KRB5_PARSE_MALFORMED;
    }
    
    if(strcmp(n, "host") == 0){
	char *p;
	n = "rcmd";
	strncpy(tmpinst, i, sizeof(tmpinst));
	tmpinst[sizeof(tmpinst) - 1] = 0;
	p = strchr(tmpinst, '.');
	if(p) *p = 0;
	i = tmpinst;
    }
    if(strlen(r) >= 40)
	return KRB5_PARSE_MALFORMED;
    if(strlen(n) >= 40)
	return KRB5_PARSE_MALFORMED;
    if(strlen(i) >= 40)
	return KRB5_PARSE_MALFORMED;
    strcpy(realm, r);
    strcpy(name, n);
    strcpy(instance, i);
    return 0;
}


			
krb5_error_code
krb5_sname_to_principal (krb5_context context,
			 const char *hostname,
			 const char *sname,
			 int32_t type,
			 krb5_principal *ret_princ)
{
    krb5_error_code ret;
    char **r;

    ret = krb5_get_host_realm (context, hostname, &r);
    if (ret)
	return ret;
    
    return krb5_build_principal (context,
				 ret_princ,
				 strlen(r[0]),
				 r[0],
				 sname,
				 hostname,
				 0);
}
