/*
 * Copyright (c) 1995, 1996 Kungliga Tekniska Högskolan (Royal Institute
 * of Technology, Stockholm, Sweden).
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

#include <krb.h>


#define POSIX_GETPW_R
#ifndef POSIX_GETPW_R

/* This code assumes that getpwnam_r et al is following POSIX.1c,
 * however, the result is only tested for inequality with zero and the
 * result parameter is never used, so there shouldn't be any problems
 * using this with Digital UNIX 3.x, which has an earlier
 * implementation.
 *
 * The following functions could be used for replacement, if necessary
 */


static int
posix_getpwnam_r(const char *name, struct passwd *pwd, 
	   char *buffer, int len, struct passwd **result)
{
    int ret = getpwnam_r(name, pwd, buffer, len);
    if(ret < 0){
	ret = errno;
	*result = NULL;
    }else{
	*result = pwd;
    }
    return ret;
}

#define getpwnam_r posix_getpwnam_r

static int
posix_getpwuid_r(uid_t uid, struct passwd *pwd, 
		 char *buffer, int len, struct passwd **result)
{
    int ret = getpwuid_r(uid, pwd, buffer, len);
    if(ret < 0){
	ret = errno;
	*result = NULL;
    }else{
	*result = pwd;
    }
    return ret;
}

#define getpwuid_r posix_getpwuid_r

#endif /* POSIX_GETPW*_R */

/* Is it necessary to have all functions? I think not. */

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
    entity->mech[pkgind] = (int*)malloc(MaxPathLen);
    if(entity->mech[pkgind] == NULL)
	return SIADFAIL;
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

int 
siad_ses_authent(sia_collect_func_t *collect, 
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
	char realm[REALM_SZ];
	int ret;
	struct passwd pw, *pwd;
	char pwbuf[1024];

	if(getpwnam_r(entity->name, &pw, pwbuf, sizeof(pwbuf), &pwd) != 0)
	    return SIADFAIL;
	sprintf((char*)entity->mech[pkgind], "%s%d_%d", 
		TKT_ROOT, pwd->pw_uid, getpid());
	krb_set_tkt_string((char*)entity->mech[pkgind]);
	
	krb_get_lrealm(realm, 1);
	ret = krb_verify_user(entity->name, "", realm, 
			      entity->password, 1, NULL);
	if(ret){
	    if(ret != KDC_PR_UNKNOWN)
		/* since this is most likely a local user (such as
                   root), just silently return failure when the
                   principal doesn't exist */
		SIALOG("WARNING", "krb_verify_user(%s): %s", 
		       entity->name, krb_get_err_text(ret));
	    return SIADFAIL;
	}
	if(sia_make_entity_pwd(pwd, entity) == SIAFAIL)
	    return SIADFAIL;
    }
    return SIADSUCCESS;
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
    char buf[MaxPathLen];
    static char env[64];
    chown((char*)entity->mech[pkgind],entity->pwd->pw_uid, entity->pwd->pw_gid);
    sprintf(env, "KRBTKFILE=%s", (char*)entity->mech[pkgind]);
    putenv(env);
    if (k_hasafs()) {
	char cell[64];
	k_setpag();
	if(k_afs_cell_of_file(entity->pwd->pw_dir, cell, sizeof(cell)) == 0)
	    k_afsklog(cell, 0);
	k_afsklog(0, 0);
    }
    return SIADSUCCESS;
}

int 
siad_ses_release(SIAENTITY *entity, int pkgind)
{
    if(entity->mech[pkgind])
	free(entity->mech[pkgind]);
    return SIADSUCCESS;
}

int 
siad_ses_suauthent(sia_collect_func_t *collect,
		   SIAENTITY *entity,
		   int siastat,
		   int pkgind)
{
    char name[ANAME_SZ];
    char toname[ANAME_SZ];
    char toinst[INST_SZ];
    char realm[REALM_SZ];
    struct passwd pw, *pwd, topw, *topwd;
    char pw_buf[1024], topw_buf[1024];
    
    if(geteuid() != 0)
	return SIADFAIL;
    if(siastat == SIADSUCCESS)
	return SIADSUCCESS;
    if(getpwuid_r(getuid(), &pw, pw_buf, sizeof(pw_buf), &pwd) != 0)
	return SIADFAIL;
    if(entity->name[0] == 0 || strcmp(entity->name, "root") == 0){
	strcpy(toname, pwd->pw_name);
	strcpy(toinst, "root");
	if(getpwnam_r("root", &topw, topw_buf, sizeof(topw_buf), &topwd) != 0)
	    return SIADFAIL;
    }else{
	strcpy(toname, entity->name);
	toinst[0] = 0;
	if(getpwnam_r(entity->name, &topw, 
		      topw_buf, sizeof(topw_buf), &topwd) != 0)
	    return SIADFAIL;
    }
    if(krb_get_lrealm(realm, 1))
      return SIADFAIL;
    if(entity->password == NULL){
	prompt_t prompt;
	if(collect == NULL)
	    return SIADFAIL;
	setup_password(entity, &prompt);
	if((*collect)(0, SIAONELINER, (unsigned char*)"", 1, 
		      &prompt) != SIACOLSUCCESS)
	    return SIADFAIL;
    }
    if(entity->password == NULL)
	return SIADFAIL;
    {
	int ret;

	if(krb_kuserok(toname, toinst, realm, entity->name))
	    return SIADFAIL;
	
	sprintf((char*)entity->mech[pkgind], "/tmp/tkt_%s_to_%s_%d", 
		pwd->pw_name, topwd->pw_name, getpid());
	krb_set_tkt_string((char*)entity->mech[pkgind]);
	ret = krb_verify_user(toname, toinst, realm, entity->password, 1, NULL);
	if(ret){
	    SIALOG("WARNING", "krb_verify_user(%s.%s): %s", toname, toinst, 
		   krb_get_err_text(ret));
	    return SIADFAIL;
	}
    }
    if(sia_make_entity_pwd(topwd, entity) == SIAFAIL)
	return SIADFAIL;
    return SIADSUCCESS;
}

/* Conflicting types between different versions of SIA, and they are
   never called anyway */

#if 0

int 
siad_ses_reauthent(sia_collect_func_t *collect,
		   SIAENTITY *entity,
		   int siastat,
		   int pkgind)
{
    return SIADFAIL;
}


int 
siad_chg_finger(sia_collect_func_t *collect,
		const char *username, int argc, char *argv[])
{
    return SIADFAIL;
}


int 
siad_chg_password(sia_collect_func_t *collect,
		  const char *username, int argc, char *argv[])
{
    return SIADFAIL;
}


int 
siad_chg_shell(sia_collect_func_t *collect,
	       const char *username, int argc, char *argv[])
{
    return SIADFAIL;
}


int siad_getpwent (struct passwd *result, char *buf, int bufsize, 
		   struct sia_context *context)
/*
  int
  siad_getpwent(const char *name, struct passwd *result, char *buf, int bufsize,
  struct sia_context *context)
  */
{
    return SIADFAIL;
}


int 
siad_getpwuid(uid_t uid, struct passwd *result, char *buf, int bufsize, 
	      struct sia_context *context)
{
    return SIADFAIL;
}


int 
siad_getpwnam(const char *name, struct passwd *result, char *buf,
	      int bufsize, struct sia_context *context)
{
    return SIADFAIL;
}


int 
siad_setpwent(struct sia_context *context)
{
    return SIADFAIL;
}


int 
siad_endpwent(struct sia_context *context)
{
    return SIADFAIL;
}


int 
siad_getgrent(struct group *result, char *buf, int bufsize, 
	      struct sia_context *context)
{
    return SIADFAIL;
}


int 
siad_getgrgid(gid_t gid, struct group *result, char *buf, int bufsize,
	      struct sia_context *context)
{
    return SIADFAIL;
}


int 
siad_getgrnam(const char *name, struct group *result, char *buf, 
	      int bufsize, struct sia_context *context)
{
    return SIADFAIL;
}


int 
siad_setgrent(struct sia_context *context)
{
    return SIADFAIL;
}


int 
siad_endgrent(struct sia_context *context)
{
    return SIADFAIL;
}


int 
siad_chk_user(const char *logname, int checkflag)
{
    return SIADFAIL;
}
#endif
