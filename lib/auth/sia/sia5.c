/*
 * Copyright (c) 1995, 1996, 1997, 1999 Kungliga Tekniska Högskolan
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
 *      This product includes software developed by the Kungliga Tekniska
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
#include <string.h>
#include <siad.h>
#include <pwd.h>

#include <krb5.h>

#include <com_err.h>

#ifdef SIAD_GET_GROUPS /* >= 4.0 */
#define POSIX_GETPWNAM_R
#endif
#ifndef POSIX_GETPWNAM_R

int krb5_verify_user(krb5_context context, krb5_principal principal,
		     krb5_ccache ccache, const char *password, int secure, 
		     const char*service);


/* These functions translate from the old Digital UNIX 3.x interface
 * to POSIX.1c.
 */

static int
posix_getpwnam_r(const char *name, struct passwd *pwd, 
	   char *buffer, int len, struct passwd **result)
{
    int ret = getpwnam_r(name, pwd, buffer, len);
    if(ret == 0)
	*result = pwd;
    else{
	*result = NULL;
	ret = _Geterrno();
	if(ret == 0){
	    ret = ERANGE;
	    _Seterrno(ret);
	}
    }
    return ret;
}

#define getpwnam_r posix_getpwnam_r

static int
posix_getpwuid_r(uid_t uid, struct passwd *pwd, 
		 char *buffer, int len, struct passwd **result)
{
    int ret = getpwuid_r(uid, pwd, buffer, len);
    if(ret == 0)
	*result = pwd;
    else{
	*result = NULL;
	ret = _Geterrno();
	if(ret == 0){
	    ret = ERANGE;
	    _Seterrno(ret);
	}
    }
    return ret;
}

#define getpwuid_r posix_getpwuid_r

#endif /* POSIX_GETPWNAM_R */

		

struct state{
    krb5_context context;
    krb5_auth_context auth_context;
    char ticket[MaxPathLen];
    int valid;
};

int 
siad_init(void)
{
    return SIADSUCCESS;
}

int 
siad_chk_invoker(void)
{
    return SIADFAIL;
}

int 
siad_ses_init(SIAENTITY *entity, int pkgind)
{
    struct state *s = malloc(sizeof(*s));
    if(s == NULL)
	return SIADFAIL;
    memset(s, 0, sizeof(*s));
    krb5_init_context(&s->context);
    entity->mech[pkgind] = (int*)s;
    return SIADSUCCESS;
}

static int
setup_name(SIAENTITY *e, prompt_t *p)
{
    e->name = malloc(SIANAMEMIN+1);
    if(e->name == NULL)
	return SIADFAIL;
    p->prompt = (unsigned char*)"login: ";
    p->result = (unsigned char*)e->name;
    p->min_result_length = 1;
    p->max_result_length = SIANAMEMIN;
    p->control_flags = 0;
    return SIADSUCCESS;
}

static int
setup_password(SIAENTITY *e, prompt_t *p)
{
    e->password = malloc(SIAMXPASSWORD+1);
    if(e->password == NULL)
	return SIADFAIL;
    p->prompt = (unsigned char*)"Password: ";
    p->result = (unsigned char*)e->password;
    p->min_result_length = 0;
    p->max_result_length = SIAMXPASSWORD;
    p->control_flags = SIARESINVIS;
    return SIADSUCCESS;
}


static int 
common_auth(sia_collect_func_t *collect, 
	    SIAENTITY *entity, 
	    int siastat,
	    int pkgind)
{
    prompt_t prompts[2], *pr;
    
    if((siastat == SIADSUCCESS) && (geteuid() == 0))
	return SIADSUCCESS;
    if(entity == NULL)
	return SIADFAIL | SIADSTOP;
    if((entity->acctname != NULL) || (entity->pwd != NULL))
	return SIADFAIL | SIADSTOP;
    
    if((collect != NULL) && entity->colinput) {
	int num;
	pr = prompts;
	if(entity->name == NULL){
	    if(setup_name(entity, pr) != SIADSUCCESS)
		return SIADFAIL;
	    pr++;
	}
	if(entity->password == NULL){
	    if(setup_password(entity, pr) != SIADSUCCESS)
		return SIADFAIL;
	    pr++;
	}
	num = pr - prompts;
	if(num == 1){
	    if((*collect)(240, SIAONELINER, (unsigned char*)"", num, 
			  prompts) != SIACOLSUCCESS)
		return SIADFAIL | SIADSTOP;
	} else if(num > 0){
	    if((*collect)(0, SIAFORM, (unsigned char*)"", num, 
			  prompts) != SIACOLSUCCESS)
		return SIADFAIL | SIADSTOP;
	}
    }
    
    if(entity->password == NULL || strlen(entity->password) > SIAMXPASSWORD)
	return SIADFAIL;
    if(entity->name[0] == 0)
	return SIADFAIL;
    
    {
	char *realm;
	krb5_principal principal;
	krb5_ccache ccache;
	krb5_error_code ret;
	struct passwd pw, *pwd;
	char pwbuf[1024];
	struct state *s = (struct state*)entity->mech[pkgind];

	if(getpwnam_r(entity->name, &pw, pwbuf, sizeof(pwbuf), &pwd) != 0)
	    return SIADFAIL;

	ret = krb5_get_default_realm(s->context, &realm);
	krb5_build_principal(s->context, &principal, 
			     strlen(realm),
			     realm,
			     entity->name,
			     NULL);

	
	if(!krb5_kuserok(s->context, principal, entity->name))
	    return SIADFAIL;
	sprintf(s->ticket, "FILE:/tmp/krb5_cc%d_%d", pwd->pw_uid, getpid());
	ret = krb5_cc_resolve(s->context, s->ticket, &ccache);
	if(ret)
	    return SIADFAIL;
	ret = krb5_cc_initialize(s->context, ccache, principal);
	if(ret)
	    return SIADFAIL;
	ret = krb5_verify_user(s->context, principal, ccache,
			       entity->password, 1, NULL);
	if(ret){
	    /* if this is most likely a local user (such as
	       root), just silently return failure when the
	       principal doesn't exist */
	    if(ret != KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN && 
	       ret != KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN)
		SIALOG("WARNING", "krb5_verify_user(%s): %s", 
		       entity->name, error_message(ret));
	    return SIADFAIL;
	}
	if(sia_make_entity_pwd(pwd, entity) == SIAFAIL)
	    return SIADFAIL;
	s->valid = 1;
    }
    return SIADSUCCESS;
}


int 
siad_ses_authent(sia_collect_func_t *collect, 
		 SIAENTITY *entity, 
		 int siastat,
		 int pkgind)
{
    return common_auth(collect, entity, siastat, pkgind);
}

int 
siad_ses_estab(sia_collect_func_t *collect, 
	       SIAENTITY *entity, int pkgind)
{
    return SIADFAIL;
}

int 
siad_ses_launch(sia_collect_func_t *collect,
		SIAENTITY *entity,
		int pkgind)
{
    char env[1024];
    struct state *s = (struct state*)entity->mech[pkgind];
    if(s->valid){
	chown(s->ticket + sizeof("FILE:") - 1, 
	      entity->pwd->pw_uid, 
	      entity->pwd->pw_gid);
	strcpy(env, "KRB5CCNAME=");
	strncat(env, s->ticket, sizeof(env) - strlen(env));
	env[sizeof(env) - 1] = 0;
	putenv(env);
    }
    return SIADSUCCESS;
}

int 
siad_ses_release(SIAENTITY *entity, int pkgind)
{
    if(entity->mech[pkgind]){
	struct state *s = (struct state*)entity->mech[pkgind];
	krb5_free_context(s->context);
	free(entity->mech[pkgind]);
    }
    return SIADSUCCESS;
}

int 
siad_ses_suauthent(sia_collect_func_t *collect,
		   SIAENTITY *entity,
		   int siastat,
		   int pkgind)
{
    if(geteuid() != 0)
	return SIADFAIL;
    if(entity->name == NULL)
	return SIADFAIL;
    if(entity->name[0] == 0)
	strcpy(entity->name, "root");
#if 0
    return common_auth(collect, entity, siastat, pkgind);
#endif
    return SIADFAIL;
}

/* The following functions returns the default fail */

int
siad_ses_reauthent (sia_collect_func_t *collect,
			SIAENTITY *entity,
			int siastat,
			int pkgind)
{
    return SIADFAIL;
}

int
siad_chg_finger (sia_collect_func_t *collect,
		     const char *username, 
		     int argc, 
		     char *argv[])
{
    return SIADFAIL;
}

int
siad_chg_password (sia_collect_func_t *collect,
		     const char *username, 
		     int argc, 
		     char *argv[])
{
    return SIADFAIL;
}

int
siad_chg_shell (sia_collect_func_t *collect,
		     const char *username, 
		     int argc, 
		     char *argv[])
{
    return SIADFAIL;
}

int
siad_getpwent(struct passwd *result, 
	      char *buf, 
	      int bufsize, 
	      struct sia_context *context)
{
    return SIADFAIL;
}

int
siad_getpwuid (uid_t uid, 
	       struct passwd *result, 
	       char *buf, 
	       int bufsize, 
	       struct sia_context *context)
{
    return SIADFAIL;
}

int
siad_getpwnam (const char *name, 
	       struct passwd *result, 
	       char *buf, 
	       int bufsize, 
	       struct sia_context *context)
{
    return SIADFAIL;
}

int
siad_setpwent (struct sia_context *context)
{
    return SIADFAIL;
}

int
siad_endpwent (struct sia_context *context)
{
    return SIADFAIL;
}

int
siad_getgrent(struct group *result, 
	      char *buf, 
	      int bufsize, 
	      struct sia_context *context)
{
    return SIADFAIL;
}

int
siad_getgrgid (gid_t gid, 
	       struct group *result, 
	       char *buf, 
	       int bufsize, 
	       struct sia_context *context)
{
    return SIADFAIL;
}

int
siad_getgrnam (const char *name, 
	       struct group *result, 
	       char *buf, 
	       int bufsize, 
	       struct sia_context *context)
{
    return SIADFAIL;
}

int
siad_setgrent (struct sia_context *context)
{
    return SIADFAIL;
}

int
siad_endgrent (struct sia_context *context)
{
    return SIADFAIL;
}

int
siad_chk_user (const char *logname, int checkflag)
{
    return SIADFAIL;
}
