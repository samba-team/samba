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
    entity->mech[pkgind] = NULL;
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
	    if((*collect)(240, SIAONELINER, (unsigned char*)"bar", num, 
			  prompts) != SIACOLSUCCESS)
		return SIADFAIL | SIADSTOP;
	} else if(num > 0){
	    if((*collect)(0, SIAFORM, (unsigned char*)"foo", num, 
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
	struct passwd pwd;
	char buf[1024];

	sprintf(buf, "%s_%d", TKT_ROOT, getpid());
	entity->mech[pkgind] = (int*)strdup(buf);
	krb_set_tkt_string(buf);

	krb_get_lrealm(realm, 0);
	ret = krb_verify_user(entity->name, "", realm, 
			      entity->password, 0, NULL);
	if(ret){
	    SIALOG("WARNING", "krb_verify_user(%s): %s", 
		   entity->name, krb_get_err_text(ret));
	    return SIADFAIL;
	}
	getpwnam_r(entity->name, &pwd, buf, sizeof(buf));
	if(sia_make_entity_pwd(&pwd, entity) == SIAFAIL)
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
    char buf[1024];
    if(entity->mech[pkgind] == NULL)
	return SIADFAIL;
    sprintf(buf, "%s%d", TKT_ROOT, entity->pwd->pw_uid);
    rename((char*)entity->mech[pkgind], buf);
    krb_set_tkt_string(buf);
    chown(buf, entity->pwd->pw_uid, entity->pwd->pw_gid);
    return SIADSUCCESS;
}

int 
siad_ses_release(SIAENTITY *entity, int pkgind)
{
    if(entity->mech[pkgind])
	free(entity->mech[pkgind]);
    return SIADSUCCESS;
}

/* Is it necessary to have all these? I think not. */

int 
siad_ses_suauthent(sia_collect_func_t *collect,
		   SIAENTITY *entity,
		   int siastat,
		   int pkgind)
{
    return SIADFAIL;
}


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


int 
siad_getpwent(struct passwd *result, char *buf, int bufsize, FILE
	      **context)
{
    return SIADFAIL;
}


int 
siad_getpwuid(uid_t uid, struct passwd *result, char *buf, int bufsize)
{
    return SIADFAIL;
}


int 
siad_getpwnam(const char *name, struct passwd *result, char *buf,
	      int bufsize)
{
    return SIADFAIL;
}


int 
siad_setpwent(FILE **context)
{
    return SIADFAIL;
}


int 
siad_endpwent(FILE **context)
{
    return SIADFAIL;
}


int 
siad_getgrent(struct group *result, char *buf, int bufsize, FILE 
	      **context)
{
    return SIADFAIL;
}


int 
siad_getgrgid(gid_t gid, struct group *result, char *buf, int bufsize)
{
    return SIADFAIL;
}


int 
siad_getgrnam(const char *name, struct group *result, char *buf, 
	      int bufsize)
{
    return SIADFAIL;
}


int 
siad_setgrent(FILE **context)
{
    return SIADFAIL;
}


int 
siad_endgrent(FILE **context)
{
    return SIADFAIL;
}


int 
siad_chk_user(const char *logname, int checkflag)
{
    return SIADFAIL;
}
