/*
 * Copyright (c) 1997 - 2007 Kungliga Tekniska Högskolan
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

#ifndef __HDB_H__
#define __HDB_H__

#include <stdio.h>

#include <krb5.h>

#include <hdb_err.h>

#include <heimbase-svc.h>
#include <heim_asn1.h>
#include <hdb_asn1.h>

#define HDB_DB_FORMAT hdb_db_format

typedef HDB_keyset hdb_keyset;
typedef HDB_entry hdb_entry;
typedef HDB_entry_alias hdb_entry_alias;

struct hdb_dbinfo;

enum hdb_lockop{ HDB_RLOCK, HDB_WLOCK };

/* flags for various functions */
#define HDB_F_DECRYPT		0x00001	/* decrypt keys */
#define HDB_F_REPLACE		0x00002	/* replace entry */
#define HDB_F_GET_CLIENT	0x00004	/* fetch client */
#define HDB_F_GET_SERVER	0x00008	/* fetch server */
#define HDB_F_GET_KRBTGT	0x00010	/* fetch krbtgt */
#define HDB_F_GET_ANY		( HDB_F_GET_CLIENT | \
				  HDB_F_GET_SERVER | \
				  HDB_F_GET_KRBTGT ) /* fetch any of client,server,krbtgt */
#define HDB_F_CANON		0x00020	/* want canonicalization */
#define HDB_F_ADMIN_DATA	0x00040	/* want data that kdc don't use  */
#define HDB_F_KVNO_SPECIFIED	0x00080	/* we want a particular KVNO */
#define HDB_F_LIVE_CLNT_KVNOS	0x00200	/* we want all live keys for pre-auth */
#define HDB_F_LIVE_SVC_KVNOS	0x00400	/* we want all live keys for tix */
#define HDB_F_ALL_KVNOS		0x00800	/* we want all the keys, live or not */
#define HDB_F_FOR_AS_REQ	0x01000	/* fetch is for a AS REQ */
#define HDB_F_FOR_TGS_REQ	0x02000	/* fetch is for a TGS REQ */
#define HDB_F_PRECHECK		0x04000	/* check that the operation would succeed */
#define HDB_F_DELAY_NEW_KEYS	0x08000	/* apply [hdb] new_service_key_delay */
#define HDB_F_SYNTHETIC_OK	0x10000	/* synthetic principal for PKINIT or GSS preauth OK */
#define HDB_F_GET_FAST_COOKIE	0x20000	/* fetch the FX-COOKIE key (not a normal principal) */
#define HDB_F_ARMOR_PRINCIPAL	0x40000	/* fetch is for the client of an armor ticket */
#define HDB_F_USER2USER_PRINCIPAL	0x80000	/* fetch is for the server of a user2user tgs-req */
#define HDB_F_CROSS_REALM_PRINCIPAL	0x100000 /* fetch is cross-realm ticket */
#define HDB_F_S4U2SELF_PRINCIPAL	0x200000 /* fetch is for S4U2Self */
#define HDB_F_S4U2PROXY_PRINCIPAL	0x400000 /* fetch is for S4U2Proxy */

/* hdb_capability_flags */
#define HDB_CAP_F_HANDLE_ENTERPRISE_PRINCIPAL 1
#define HDB_CAP_F_HANDLE_PASSWORDS	2
#define HDB_CAP_F_PASSWORD_UPDATE_KEYS	4
#define HDB_CAP_F_SHARED_DIRECTORY      8

#define heim_pcontext krb5_context
#define heim_pconfig void *

typedef struct hdb_request_desc {
    HEIM_SVC_REQUEST_DESC_COMMON_ELEMENTS;
} *hdb_request_t;

#undef heim_pcontext
#undef heim_pconfig

/* key usage for master key */
#define HDB_KU_MKEY	0x484442

/*
 * Second component of WELLKNOWN namespace principals, the third component is
 * the common DNS suffix of the implied virtual hosts.
 */
#define HDB_WK_NAMESPACE "HOSTBASED-NAMESPACE"

typedef struct hdb_master_key_data *hdb_master_key;

/**
 * HDB backend function pointer structure
 *
 * The HDB structure is what the KDC and kadmind framework uses to
 * query the backend database when talking about principals.
 */

typedef struct HDB {
    void *hdb_db;
    void *hdb_dbc; /** don't use, only for DB3 */
    const char *hdb_method_name;
    char *hdb_name;
    int hdb_master_key_set;
    hdb_master_key hdb_master_key;
    int hdb_openp;
    int hdb_capability_flags;
    int lock_count;
    int lock_type;
    /*
     * These fields cache config values.
     *
     * XXX Move these into a structure that we point to so that we
     * don't need to break the ABI every time we add a field.
     */
    int enable_virtual_hostbased_princs;
    size_t virtual_hostbased_princ_ndots;   /* Min. # of .s in hostname */
    size_t virtual_hostbased_princ_maxdots; /* Max. # of .s in namespace */
    char **virtual_hostbased_princ_svcs;    /* Which svcs are not wildcarded */
    time_t new_service_key_delay;           /* Delay for new keys */
    /**
     * Open (or create) the a Kerberos database.
     *
     * Open (or create) the a Kerberos database that was resolved with
     * hdb_create(). The third and fourth flag to the function are the
     * same as open(), thus passing O_CREAT will create the data base
     * if it doesn't exists.
     *
     * Then done the caller should call hdb_close(), and to release
     * all resources hdb_destroy().
     */
    krb5_error_code (*hdb_open)(krb5_context, struct HDB*, int, mode_t);
    /**
     * Close the database for transaction
     *
     * Closes the database for further transactions, wont release any
     * permanant resources. the database can be ->hdb_open-ed again.
     */
    krb5_error_code (*hdb_close)(krb5_context, struct HDB*);
    /**
     * Free backend-specific entry context.
     */
    void	    (*hdb_free_entry_context)(krb5_context, struct HDB*, hdb_entry*);
    /**
     * Fetch an entry from the backend
     *
     * Fetch an entry from the backend, flags are what type of entry
     * should be fetch: client, server, krbtgt.
     * knvo (if specified and flags HDB_F_KVNO_SPECIFIED set) is the kvno to get
     */
    krb5_error_code (*hdb_fetch_kvno)(krb5_context, struct HDB*,
				      krb5_const_principal, unsigned, krb5_kvno,
				      hdb_entry*);
    /**
     * Store an entry to database
     */
    krb5_error_code (*hdb_store)(krb5_context, struct HDB*,
				 unsigned, hdb_entry*);
    /**
     * Remove an entry from the database.
     */
    krb5_error_code (*hdb_remove)(krb5_context, struct HDB*,
				  unsigned, krb5_const_principal);
    /**
     * As part of iteration, fetch one entry
     */
    krb5_error_code (*hdb_firstkey)(krb5_context, struct HDB*,
				    unsigned, hdb_entry*);
    /**
     * As part of iteration, fetch next entry
     */
    krb5_error_code (*hdb_nextkey)(krb5_context, struct HDB*,
				   unsigned, hdb_entry*);
    /**
     * Lock database
     *
     * A lock can only be held by one consumers. Transaction can still
     * happen on the database while the lock is held, so the entry is
     * only useful for syncroning creation of the database and renaming of the database.
     */
    krb5_error_code (*hdb_lock)(krb5_context, struct HDB*, int);
    /**
     * Unlock database
     */
    krb5_error_code (*hdb_unlock)(krb5_context, struct HDB*);
    /**
     * Rename the data base.
     *
     * Assume that the database is not hdb_open'ed and not locked.
     */
    krb5_error_code (*hdb_rename)(krb5_context, struct HDB*, const char*);
    /**
     * Get an hdb_entry from a classical DB backend
     *
     * This function takes a principal key (krb5_data) and returns all
     * data related to principal in the return krb5_data. The returned
     * encoded entry is of type hdb_entry or hdb_entry_alias.
     */
    krb5_error_code (*hdb__get)(krb5_context, struct HDB*,
				krb5_data, krb5_data*);
    /**
     * Store an hdb_entry from a classical DB backend
     *
     * This function takes a principal key (krb5_data) and encoded
     * hdb_entry or hdb_entry_alias as the data to store.
     *
     * For a file-based DB, this must synchronize to disk when done.
     * This is sub-optimal for kadm5_s_rename_principal(), and for
     * kadm5_s_modify_principal() when using principal aliases; to
     * improve this so that only one fsync() need be done
     * per-transaction will require HDB API extensions.
     */
    krb5_error_code (*hdb__put)(krb5_context, struct HDB*, int,
				krb5_data, krb5_data);
    /**
     * Delete and hdb_entry from a classical DB backend
     *
     * This function takes a principal key (krb5_data) naming the record
     * to delete.
     *
     * Same discussion as in @ref HDB::hdb__put
     */
    krb5_error_code (*hdb__del)(krb5_context, struct HDB*, krb5_data);
    /**
     * Destroy the handle to the database.
     *
     * Destroy the handle to the database, deallocate all memory and
     * related resources. Does not remove any permanent data. Its the
     * logical reverse of hdb_create() function that is the entry
     * point for the module.
     */
    krb5_error_code (*hdb_destroy)(krb5_context, struct HDB*);
    /**
     * Get the list of realms this backend handles.
     * This call is optional to support. The returned realms are used
     * for announcing the realms over bonjour. Free returned array
     * with krb5_free_host_realm().
     */
    krb5_error_code (*hdb_get_realms)(krb5_context, struct HDB *, krb5_realm **);
    /**
     * Change password.
     *
     * Will update keys for the entry when given password.  The new
     * keys must be written into the entry and will then later be
     * ->hdb_store() into the database. The backend will still perform
     * all other operations, increasing the kvno, and update
     * modification timestamp.
     *
     * The backend needs to call _kadm5_set_keys() and perform password
     * quality checks.
     */
    krb5_error_code (*hdb_password)(krb5_context, struct HDB*, hdb_entry*, const char *, int);

    /**
     * Authentication auditing. Note that this function is called by
     * both the AS and TGS, but currently only the AS sets the auth
     * event type. This may change in a future version.
     *
     * Event details are available by querying the request using
     * heim_audit_getkv(HDB_REQUEST_KV_...).
     *
     * In case the entry is locked out, the backend should set the
     * hdb_entry.flags.locked-out flag.
     */
    krb5_error_code (*hdb_audit)(krb5_context, struct HDB *, hdb_entry *, hdb_request_t);

    /**
     * Check if delegation is allowed.
     */
    krb5_error_code (*hdb_check_constrained_delegation)(krb5_context, struct HDB *, hdb_entry *, krb5_const_principal);

    /**
     * Check if resource-based constrained delegation (RBCD) is allowed.
     */
    krb5_error_code (*hdb_check_rbcd)(krb5_context context,
				      struct HDB *clientdb,
				      const hdb_entry *client_krbtgt,
				      krb5_const_principal client_principal,
				      const hdb_entry *client,
				      const hdb_entry *device_krbtgt,
				      krb5_const_principal device_principal,
				      const hdb_entry *device,
				      krb5_const_principal s4u_principal,
				      krb5_const_pac client_pac,
				      krb5_const_pac device_pac,
				      const hdb_entry *target);

    /**
     * Check if this name is an alias for the supplied client for PKINIT userPrinicpalName logins
     */
    krb5_error_code (*hdb_check_pkinit_ms_upn_match)(krb5_context, struct HDB *, hdb_entry *, krb5_const_principal);

    /**
     * Check if s4u2self is allowed from this client to this server or the SPN is a valid SPN of this client (for user2user)
     */
    krb5_error_code (*hdb_check_client_matches_target_service)(krb5_context, struct HDB *, hdb_entry *, hdb_entry *);

    /**
     * Enable/disable synchronous updates
     *
     * Calling this with 0 disables sync.  Calling it with non-zero enables
     * sync and does an fsync().
     */
    krb5_error_code (*hdb_set_sync)(krb5_context, struct HDB *, int);
}HDB;

#define HDB_INTERFACE_VERSION	12

struct hdb_method {
    HEIM_PLUGIN_FTABLE_COMMON_ELEMENTS(krb5_context);
    unsigned int	is_file_based:1;
    unsigned int	can_taste:1;
    const char *prefix;
    krb5_error_code (*create)(krb5_context, HDB **, const char *filename);
};

/* dump entry format, for hdb_print_entry() */
typedef enum hdb_dump_format {
    HDB_DUMP_HEIMDAL = 0,
    HDB_DUMP_MIT = 1,
} hdb_dump_format_t;

struct hdb_print_entry_arg {
    FILE *out;
    hdb_dump_format_t fmt;
};

typedef krb5_error_code (*hdb_foreach_func_t)(krb5_context, HDB*,
					      hdb_entry*, void*);
extern krb5_kt_ops hdb_kt_ops;
extern krb5_kt_ops hdb_get_kt_ops;

extern const int hdb_interface_version;

#include <hdb-protos.h>

#endif /* __HDB_H__ */
