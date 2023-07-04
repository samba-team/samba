/*
 * Copyright (c) 1997-2000 Kungliga Tekniska Högskolan
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
/* $Id$ */

#ifndef __KADM5_ADMIN_H__
#define __KADM5_ADMIN_H__

#define KADM5_API_VERSION_1 1
#define KADM5_API_VERSION_2 2

#ifndef USE_KADM5_API_VERSION
#define USE_KADM5_API_VERSION KADM5_API_VERSION_2
#endif

#if USE_KADM5_API_VERSION != KADM5_API_VERSION_2
#error No support for API versions other than 2
#endif

#define KADM5_STRUCT_VERSION 0

/* For kadm5_log_get_version_fd() */
#define LOG_VERSION_LAST -1
#define LOG_VERSION_FIRST 1
#define LOG_VERSION_UBER  0

#include <krb5.h>

#define KRB5_KDB_DISALLOW_POSTDATED	0x00000001
#define KRB5_KDB_DISALLOW_FORWARDABLE	0x00000002
#define KRB5_KDB_DISALLOW_TGT_BASED	0x00000004
#define KRB5_KDB_DISALLOW_RENEWABLE	0x00000008
#define KRB5_KDB_DISALLOW_PROXIABLE	0x00000010
#define KRB5_KDB_DISALLOW_DUP_SKEY	0x00000020
#define KRB5_KDB_DISALLOW_ALL_TIX	0x00000040
#define KRB5_KDB_REQUIRES_PRE_AUTH	0x00000080
#define KRB5_KDB_REQUIRES_HW_AUTH	0x00000100
#define KRB5_KDB_REQUIRES_PWCHANGE	0x00000200
#define KRB5_KDB_DISALLOW_SVR		0x00001000
#define KRB5_KDB_PWCHANGE_SERVICE	0x00002000
#define KRB5_KDB_SUPPORT_DESMD5		0x00004000
#define KRB5_KDB_NEW_PRINC		0x00008000
#define KRB5_KDB_OK_AS_DELEGATE		0x00010000 /* 0x00100000 in MIT */
#define KRB5_KDB_TRUSTED_FOR_DELEGATION	0x00020000 /* MIT has as 0x00200000 */
#define KRB5_KDB_ALLOW_KERBEROS4	0x00040000 /* MIT doesn't have this; XXX remove */
#define KRB5_KDB_ALLOW_DIGEST		0x00080000 /* MIT doesn't have this */
#define KRB5_KDB_MATERIALIZE            0x00100000 /* MIT doesn't have this */
#define KRB5_KDB_VIRTUAL_KEYS           0x00200000 /* MIT doesn't have this */
#define KRB5_KDB_VIRTUAL                0x00400000 /* MIT doesn't have this */
#define KRB5_KDB_DISALLOW_CLIENT        0x00800000 /* MIT doesn't have this */
#define KRB5_KDB_NO_AUTH_DATA_REQUIRED	0x01000000 /* 0x00400000 in MIT */
#define KRB5_KDB_AUTH_DATA_REQUIRED	0x02000000

/*
 * MIT has:
 *
 *  - Same as our KRB5_KDB_TRUSTED_FOR_DELEGATION:
 *
 *    #define KRB5_KDB_OK_TO_AUTH_AS_DELEGATE 0x00200000 // S4U2Self OK
 *
 *  - Misc:
 *
 *    #define KRB5_KDB_NO_AUTH_DATA_REQUIRED  0x00400000 // Don't lookup / add
 *                                                       // authz data
 *    #define KRB5_KDB_LOCKDOWN_KEYS          0x00800000 // Don't allow
 *                                                       // deletion of princ
 */


#define KADM5_PRINCIPAL		0x000001U
#define KADM5_PRINC_EXPIRE_TIME	0x000002U
#define KADM5_PW_EXPIRATION	0x000004U
#define KADM5_LAST_PWD_CHANGE	0x000008U
#define KADM5_ATTRIBUTES	0x000010U
#define KADM5_MAX_LIFE		0x000020U
#define KADM5_MOD_TIME		0x000040U
#define KADM5_MOD_NAME		0x000080U
#define KADM5_KVNO		0x000100U
#define KADM5_MKVNO		0x000200U
#define KADM5_AUX_ATTRIBUTES	0x000400U
#define KADM5_POLICY		0x000800U
#define KADM5_POLICY_CLR	0x001000U
#define KADM5_MAX_RLIFE		0x002000U
#define KADM5_LAST_SUCCESS	0x004000U
#define KADM5_LAST_FAILED	0x008000U
#define KADM5_FAIL_AUTH_COUNT	0x010000U
#define KADM5_KEY_DATA		0x020000U
#define KADM5_TL_DATA		0x040000U

#define KADM5_PRINCIPAL_NORMAL_MASK (~(KADM5_KEY_DATA | KADM5_TL_DATA))

#define KADM5_PW_MAX_LIFE 	0x004000
#define KADM5_PW_MIN_LIFE	0x008000
#define KADM5_PW_MIN_LENGTH 	0x010000
#define KADM5_PW_MIN_CLASSES	0x020000
#define KADM5_PW_HISTORY_NUM	0x040000
#define KADM5_REF_COUNT		0x080000

#define KADM5_POLICY_NORMAL_MASK (~0)

#define KADM5_ADMIN_SERVICE	"kadmin/admin"
#define KADM5_HIST_PRINCIPAL	"kadmin/history"
#define KADM5_CHANGEPW_SERVICE	"kadmin/changepw"

typedef struct {
    int16_t key_data_ver;	/* Version */
    int16_t key_data_kvno;	/* Key Version */
    int16_t key_data_type[2];	/* Array of types */
    int16_t key_data_length[2];	/* Array of lengths */
    void*   key_data_contents[2];/* Array of pointers */
} krb5_key_data;

typedef struct _krb5_keysalt {
    int16_t               type;
    krb5_data             data;                 /* Length, data */
} krb5_keysalt;

typedef struct _krb5_tl_data {
    struct _krb5_tl_data* tl_data_next;
    int16_t tl_data_type;
    int16_t tl_data_length;
    void*   tl_data_contents;
} krb5_tl_data;

#define KRB5_TL_LAST_PWD_CHANGE		0x0001
#define KRB5_TL_MOD_PRINC		0x0002
#define KRB5_TL_KADM_DATA		0x0003
#define KRB5_TL_KADM5_E_DATA		0x0004
#define KRB5_TL_RB1_CHALLENGE		0x0005
#define KRB5_TL_SECURID_STATE           0x0006
#define KRB5_TL_PASSWORD           	0x0007
#define KRB5_TL_EXTENSION           	0x0008
#define KRB5_TL_PKINIT_ACL           	0x0009
#define KRB5_TL_ALIASES           	0x000a
#define KRB5_TL_HIST_KVNO_DIFF_CLNT	0x000b
#define KRB5_TL_HIST_KVNO_DIFF_SVC	0x000c
#define KRB5_TL_ETYPES			0x000d
#define KRB5_TL_KEY_ROTATION		0x000e
#define KRB5_TL_KRB5_CONFIG		0x000f

typedef struct _kadm5_principal_ent_t {
    krb5_principal principal;

    krb5_timestamp princ_expire_time;
    krb5_timestamp last_pwd_change;
    krb5_timestamp pw_expiration;
    krb5_deltat max_life;
    krb5_principal mod_name;
    krb5_timestamp mod_date;
    krb5_flags attributes;
    krb5_kvno kvno;
    krb5_kvno mkvno;

    char * policy;
    uint32_t aux_attributes;

    krb5_deltat max_renewable_life;
    krb5_timestamp last_success;
    krb5_timestamp last_failed;
    krb5_kvno fail_auth_count;
    int16_t n_key_data;
    int16_t n_tl_data;
    krb5_tl_data *tl_data;
    krb5_key_data *key_data;
} kadm5_principal_ent_rec, *kadm5_principal_ent_t;

typedef struct _kadm5_policy_ent_t {
    char *policy;

    uint32_t pw_min_life;
    uint32_t pw_max_life;
    uint32_t pw_min_length;
    uint32_t pw_min_classes;
    uint32_t pw_history_num;
    uint32_t policy_refcnt;
} kadm5_policy_ent_rec, *kadm5_policy_ent_t;

#define KADM5_CONFIG_REALM			(1 << 0)
#define KADM5_CONFIG_PROFILE			(1 << 1)
#define KADM5_CONFIG_KADMIND_PORT		(1 << 2)
#define KADM5_CONFIG_ADMIN_SERVER		(1 << 3)
#define KADM5_CONFIG_DBNAME			(1 << 4)
#define KADM5_CONFIG_ADBNAME			(1 << 5)
#define KADM5_CONFIG_ADB_LOCKFILE		(1 << 6)
#define KADM5_CONFIG_ACL_FILE			(1 << 7)
#define KADM5_CONFIG_DICT_FILE			(1 << 8)
#define KADM5_CONFIG_ADMIN_KEYTAB		(1 << 9)
#define KADM5_CONFIG_MKEY_FROM_KEYBOARD		(1 << 10)
#define KADM5_CONFIG_STASH_FILE			(1 << 11)
#define KADM5_CONFIG_MKEY_NAME			(1 << 12)
#define KADM5_CONFIG_ENCTYPE			(1 << 13)
#define KADM5_CONFIG_MAX_LIFE			(1 << 14)
#define KADM5_CONFIG_MAX_RLIFE			(1 << 15)
#define KADM5_CONFIG_EXPIRATION			(1 << 16)
#define KADM5_CONFIG_FLAGS			(1 << 17)
#define KADM5_CONFIG_ENCTYPES			(1 << 18)
#define KADM5_CONFIG_READONLY_ADMIN_SERVER	(1 << 19)
#define KADM5_CONFIG_READONLY_KADMIN_PORT	(1 << 20)

#define KADM5_PRIV_GET		(1 << 0)
#define KADM5_PRIV_ADD 		(1 << 1)
#define KADM5_PRIV_MODIFY	(1 << 2)
#define KADM5_PRIV_DELETE	(1 << 3)
#define KADM5_PRIV_LIST		(1 << 4)
#define KADM5_PRIV_CPW		(1 << 5)
#define KADM5_PRIV_GET_KEYS	(1 << 6)

/* Note: KADM5_PRIV_GET_KEYS not included */
#define KADM5_PRIV_ALL		(KADM5_PRIV_GET | KADM5_PRIV_ADD | KADM5_PRIV_MODIFY | KADM5_PRIV_DELETE | KADM5_PRIV_LIST | KADM5_PRIV_CPW)

#define KADM5_BOGUS_KEY_DATA    "\xe5\xe5\xe5\xe5"

/*
 * ABI NOTE: We can add fields at the end of this provided that we define new
 * mask bits that must be set in the mask field when setting the new fields.
 */
typedef struct _kadm5_config_params {
    uint32_t mask;

    /* Client and server fields */
    char *realm;
    int kadmind_port;

    /* client fields */
    char *admin_server;

    /* server fields */
    char *dbname;
    char *acl_file;

    /* server library (database) fields */
    char *stash_file;

    /* read-only kadmin server */
    char *readonly_admin_server;
    int readonly_kadmind_port;
} kadm5_config_params;

typedef krb5_error_code kadm5_ret_t;

#include "kadm5-protos.h"

#endif /* __KADM5_ADMIN_H__ */
