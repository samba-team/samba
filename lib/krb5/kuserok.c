/*
 * Copyright (c) 1997 - 2004 Kungliga Tekniska Högskolan
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

#include "krb5_locl.h"
#include <dirent.h>

RCSID("$Id$");

/*
 * Return TRUE iff `principal' is allowed to login as `luser'.
 */

static krb5_error_code
check_one_file(krb5_context context, 
	       const char *filename, 
	       struct passwd *pwd,
	       krb5_principal principal, 
	       krb5_boolean *result)
{
    FILE *f;
    char buf[BUFSIZ];
    krb5_error_code ret;
    struct stat st;
    
    *result = FALSE;

    f = fopen (filename, "r");
    if (f == NULL)
	return errno;
    
    /* check type and mode of file */
    if (fstat(fileno(f), &st) != 0) {
	fclose (f);
	return errno;
    }
    if (S_ISDIR(st.st_mode)) {
	fclose (f);
	return EISDIR;
    }
    if (st.st_uid != pwd->pw_uid && st.st_uid != 0) {
	fclose (f);
	return EACCES;
    }
    if ((st.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
	fclose (f);
	return EACCES;
    }

    while (fgets (buf, sizeof(buf), f) != NULL) {
	krb5_principal tmp;

	if(buf[strcspn(buf, "\n")] != '\n') {
	    int c;
	    c = fgetc(f);
	    if(c != EOF) {
		while(c != EOF && c != '\n')
		    c = fgetc(f);
		/* line was too long, so ignore it */
		continue;
	    }
	}
	buf[strcspn(buf, "\n")] = '\0';
	ret = krb5_parse_name (context, buf, &tmp);
	if (ret)
	    continue;
	*result = krb5_principal_compare (context, principal, tmp);
	krb5_free_principal (context, tmp);
	if (*result) {
	    fclose (f);
	    return 0;
	}
    }
    fclose (f);
    return 0;
}

static krb5_boolean
match_local_principals(krb5_context context,
		       krb5_principal principal,
		       const char *luser)
{
    krb5_error_code ret;
    krb5_realm *realms, *r;
    krb5_boolean result = FALSE;
    
    /* multi-component principals can never match */
    if(krb5_principal_get_comp_string(context, principal, 1) != NULL)
	return FALSE;

    ret = krb5_get_default_realms (context, &realms);
    if (ret)
	return FALSE;
	
    for (r = realms; *r != NULL; ++r) {
	if(strcmp(krb5_principal_get_realm(context, principal),
		  *r) != 0)
	    continue;
	if(strcmp(krb5_principal_get_comp_string(context, principal, 0),
		  luser) == 0) {
	    result = TRUE;
	    break;
	}
    }
    krb5_free_host_realm (context, realms);
    return result;
}

krb5_boolean KRB5_LIB_FUNCTION
krb5_kuserok (krb5_context context,
	      krb5_principal principal,
	      const char *luser)
{
    char buf[BUFSIZ];
    struct passwd *pwd;
    krb5_error_code ret;
    krb5_boolean result = FALSE;

    pwd = getpwnam (luser);	/* XXX - Should use k_getpwnam? */
    if (pwd == NULL)
	return FALSE;

    /* check user's ~/.k5login */
    snprintf (buf, sizeof(buf), "%s/.k5login", pwd->pw_dir);
    ret = check_one_file(context, buf, pwd, principal, &result);

    /* but if it doesn't exist, allow all principals
       matching <localuser>@<LOCALREALM> */
    if(ret == ENOENT)
	return match_local_principals(context, principal, luser);

#if notyet
    /* on the other hand, if it's a directory, check all files
       contained therein */
    if (ret == EISDIR) {
	DIR *d = opendir(buf);
	struct dirent *dent;
	char buf2[BUFSIZ];

	if(d == NULL)
	    return FALSE;
	while((dent = readdir(d)) != NULL) {
	    if(strcmp(dent->d_name, ".") == 0 ||
	       strcmp(dent->d_name, "..") == 0)
		continue;
	    snprintf(buf2, sizeof(buf2), "%s/%s", buf, dent->d_name);
	    ret = check_one_file(context, buf2, pwd, principal, &result);
	    if(ret == 0 && result == TRUE)
		break;
	}
	closedir(d);
    }
#endif
    if (ret)
	return FALSE;
    return result;
}
