/*
 * Copyright (c) 1999 Kungliga Tekniska Högskolan
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
 * 3. Neither the name of KTH nor the names of its contributors may be
 *    used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY KTH AND ITS CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL KTH OR ITS CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. */

#include <config.h>

RCSID("$Id$");

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <syslog.h>

#ifdef HAVE_PATHS_H
#include <paths.h>
#endif

#include <pwd.h>

#include <krb5.h>
#include <err.h>
#include <roken.h>
#include <getarg.h>

#ifndef _PATH_DEFPATH
#define _PATH_DEFPATH "/usr/bin:/bin"
#endif

#ifndef _PATH_BSHELL
#define _PATH_BSHELL "/bin/sh"
#endif

int kerberos_flag = 1;
int csh_f_flag;
int full_login;
int env_flag;
char *kerberos_instance = "root";
int help_flag;
int version_flag;
char *cmd;

struct getargs args[] = {
    { "kerberos", 'K', arg_negative_flag, &kerberos_flag,
      "don't use kerberos" },
    { NULL,	  'f', arg_flag,	  &csh_f_flag,
      "don't read .cshrc" },
    { "full",	  'l', arg_flag,          &full_login,
      "simulate full login" },
    { NULL,	  'm', arg_flag,          &env_flag,
      "leave environment unmodified" },
    { "instance", 'i', arg_string,        &kerberos_instance,
      "root instance to use" },
    { "command",  'c', arg_string,        &cmd,
      "command to execute" },
    { "help", 	  'h', arg_flag,          &help_flag },
    { "version",  0,   arg_flag,          &version_flag },
};


static void
usage (int ret)
{
    arg_printusage (args,
		    sizeof(args)/sizeof(*args),
		    NULL,
		    "[login [shell arguments]]");
    exit (ret);
}

static struct passwd*
make_info(struct passwd *pwd)
{
    struct passwd *info;
    info = malloc(sizeof(*info));
    if(info == NULL)
	return NULL;
    info->pw_name = strdup(pwd->pw_name);
    info->pw_passwd = strdup(pwd->pw_passwd);
    info->pw_uid = pwd->pw_uid;
    info->pw_gid = pwd->pw_gid;
    info->pw_dir = strdup(pwd->pw_dir);
    info->pw_shell = strdup(pwd->pw_shell);
    if(info->pw_name == NULL || info->pw_passwd == NULL ||
       info->pw_dir == NULL || info->pw_shell == NULL)
	return NULL;
    return info;
}

static int
verify_krb5(struct passwd *login_info, struct passwd *su_info,
	    const char *kerberos_instance)
{
#ifdef KRB5
    krb5_context context;
    krb5_error_code ret;
    krb5_principal p;
    krb5_ccache ccache;
	
    ret = krb5_init_context (&context);
    if (ret) {
#if 0
	warnx("krb5_init_context failed: %u", ret);
#endif
	return 1;
    }
	
    if (strcmp (su_info->pw_name, "root") == 0)
	ret = krb5_make_principal(context, &p, NULL, 
				  login_info->pw_name,
				  kerberos_instance,
				  NULL);
    else
	ret = krb5_make_principal(context, &p, NULL, 
				  login_info->pw_name,
				  NULL);
    if(ret)
	return 1;
	
    if(su_info->pw_uid != 0 || krb5_kuserok(context, p, su_info->pw_name)) {
	ret = krb5_cc_gen_new(context, &krb5_mcc_ops, &ccache);
	if(ret) {
#if 1
	    krb5_warn(context, ret, "krb5_cc_gen_new");
#endif
	    return 1;
	}
	ret = krb5_verify_user(context, p, ccache, NULL, TRUE, NULL);
	if(ret) {
	    krb5_cc_destroy(context, ccache);
#if 1
	    switch (ret) {
	    case KRB5KRB_AP_ERR_BAD_INTEGRITY:
	    case KRB5KRB_AP_ERR_MODIFIED:
		krb5_warnx(context, "Password incorrect");
	    default :
		krb5_warn(context, ret, "krb5_verify_user");
		break;
	    }
#endif
	    return 1;
	}
	{
	    krb5_ccache ccache2;
	    char *cc_name;

	    if (seteuid(su_info->pw_uid))
		krb5_err (context, 1, errno, "seteuid");
	    ret = krb5_cc_gen_new(context, &krb5_fcc_ops, &ccache2);
	    if (ret) {
		if (seteuid (0))
		    krb5_err (context, 1, errno, "seteuid");
		krb5_cc_destroy(context, ccache);
		return 1;
	    }

	    ret = krb5_cc_copy_cache(context, ccache, ccache2);
	    if (seteuid(0))
		krb5_err (context, 1, errno, "seteuid");
	    ret = krb5_cc_close(context, ccache2);

	    asprintf(&cc_name, "%s:%s", krb5_cc_get_type(context, ccache2),
		     krb5_cc_get_name(context, ccache2));
	    setenv("KRB5CCNAME", cc_name, 1);
	}
	krb5_cc_destroy(context, ccache);
	return 0;
    }
#endif
    return 1;
}

static int
verify_unix(struct passwd *su)
{
    char prompt[128];
    char pw_buf[1024];
    char *pw;
    int r;
    if(su->pw_passwd != NULL && *su->pw_passwd != '\0') {
	sprintf(prompt, "%s's password: ", su->pw_name);
	r = des_read_pw_string(pw_buf, sizeof(pw_buf), prompt, 0);
	if(r != 0)
	    exit(0);
	pw = crypt(pw_buf, su->pw_passwd);
	memset(pw_buf, 0, sizeof(pw_buf));
	if(strcmp(pw, su->pw_passwd) != 0)
	    return 1;
    }
    return 0;
}

int
main(int argc, char **argv)
{
    int optind = 0;
    char *su_user;
    struct passwd *su_info;
    char *login_user;
    struct passwd *login_info;

    struct passwd *pwd;

    char *shell;

    int ok = 0;

    set_progname (argv[0]);

    if(getarg(args, sizeof(args) / sizeof(args[0]), argc, argv, &optind))
	usage(1);

    if(help_flag)
	usage(0);
    if(version_flag) {
	print_version(NULL);
	exit(0);
    }
    if(optind >= argc)
	su_user = "root";
    else
	su_user = argv[optind++];

    pwd = k_getpwnam(su_user);
    if(pwd == NULL)
	errx (1, "unknown login %s", su_user);
    if (pwd->pw_uid == 0 && strcmp ("root", su_user) != 0) {
	syslog (LOG_ALERT, "NIS attack, user %s has uid 0", su_user);
	errx (1, "unknown login %s", su_user);
    }
    su_info = make_info(pwd);
    
    login_user = getlogin();
    if(login_user == NULL || (pwd = getpwnam(login_user)) == NULL)
	pwd = getpwuid(getuid());
    if(pwd == NULL)
	errx(1, "who are you?");
    login_info = make_info(pwd);
    if(env_flag)
	shell = login_info->pw_shell;
    else
	shell = su_info->pw_shell;
    if(shell == NULL || *shell == '\0')
	shell = _PATH_BSHELL;
    
    if(ok == 0 && verify_krb5(login_info, su_info, kerberos_instance) == 0)
	ok++;

    if(ok == 0 && verify_unix(su_info) != 0) {
	printf("Sorry!\n");
	exit(1);
    }

    {
	char *tty = ttyname (STDERR_FILENO);
	syslog (LOG_NOTICE | LOG_AUTH, tty ? "%s to %s" : "%s to %s on %s",
		login_info->pw_name, su_info->pw_name, tty);
    }

    if(!env_flag) {
	if(full_login) {
	    char *k = getenv ("KRBTKFILE");
	    char *t = getenv ("TERM");
	    
	    environ = malloc (10 * sizeof (char *));
	    if (environ == NULL)
		err (1, "malloc");
	    environ[0] = NULL;
	    setenv ("PATH", _PATH_DEFPATH, 1);
	    if (t)
		setenv ("TERM", t, 1);
	    if (k)
		setenv ("KRBTKFILE", k, 1);
	    if (chdir (pwd->pw_dir) < 0)
		errx (1, "no directory");
	}
	if (full_login || su_info->pw_uid)
	    setenv ("USER", su_info->pw_name, 1);
	setenv("HOME", su_info->pw_dir, 1);
	setenv("SHELL", shell, 1);
    }

    {
	int i;
	char **args;
	char *p;

	p = strrchr(shell, '/');
	if(p)
	    p++;
	else
	    p = shell;

	if (strcmp(p, "csh") != 0)
	    csh_f_flag = 0;

	args = malloc((1 + argc - optind + 1 + csh_f_flag) * sizeof(*args));
	if (args == NULL)
	    err (1, "malloc");
	i = 0;
	if(full_login)
	    asprintf(&args[i++], "-%s", p);
	else
	    args[i++] = p;
	if (csh_f_flag)
	    args[i++] = "-f";

	for(; i < argc - optind  + i; i++)
	    args[i] = argv[optind + i - 1];
	args[i] = NULL;
	if(setgid(su_info->pw_gid) < 0)
	    err(1, "setgid");
	if (initgroups (su_info->pw_name, su_info->pw_gid) < 0)
	    err (1, "initgroups");
	if(setuid(su_info->pw_uid) < 0)
	    err(1, "setuid");

	execv(shell, args);
    }
    
    exit(1);
}
