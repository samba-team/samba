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

/* $Id$ */

#ifndef __KADM5_LOCL_H__
#define __KADM5_LOCL_H__

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#include "admin.h"
#include "kadm5_err.h"
#include <hdb.h>
#include <roken.h>
#include <parse_units.h>

typedef struct kadm5_server_context {
    krb5_context context;
    krb5_boolean my_context;
    kadm5_config_params config;
    HDB *db;
    krb5_principal caller;
    unsigned acl_flags;
    char *acl_file;
}kadm5_server_context;

typedef struct kadm5_client_context {
    krb5_context context;
    krb5_boolean my_context;
    kadm5_config_params config;
    krb5_auth_context ac;
    char *realm;
    char *admin_server;
    int sock;
}kadm5_client_context;

enum kadm_ops {
    kadm_get,
    kadm_delete,
    kadm_create,
    kadm_rename,
    kadm_chpass,
    kadm_modify,
    kadm_randkey
};

#define KADMIN_APPL_VERSION "KADM0.0"

kadm5_ret_t
_kadm5_acl_check_permission __P((
	kadm5_server_context *context,
	unsigned op));

kadm5_ret_t
_kadm5_acl_init __P((kadm5_server_context *context));

kadm5_ret_t
_kadm5_c_init_context __P((
	kadm5_client_context **ctx,
	kadm5_config_params *params,
	krb5_context context));

kadm5_ret_t
_kadm5_client_recv __P((
	kadm5_client_context *context,
	krb5_storage *sp));

kadm5_ret_t
_kadm5_client_send __P((
	kadm5_client_context *context,
	krb5_storage *sp));

kadm5_ret_t
_kadm5_error_code __P((kadm5_ret_t code));

kadm5_ret_t
_kadm5_s_init_context __P((
	kadm5_server_context **ctx,
	kadm5_config_params *params,
	krb5_context context));

kadm5_ret_t
_kadm5_set_keys __P((
	kadm5_server_context *context,
	hdb_entry *ent,
	const char *password));

kadm5_ret_t
_kadm5_set_modifier __P((
	kadm5_server_context *context,
	hdb_entry *ent));

kadm5_ret_t
_kadm5_setup_entry __P((
	hdb_entry *ent,
	kadm5_principal_ent_t princ,
	u_int32_t mask));

#endif /* __KADM5_LOCL_H__ */
