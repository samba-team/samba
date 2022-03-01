/*
 * Copyright (c) 2006 The Regents of the University of Michigan.
 * All rights reserved.
 *
 * Portions Copyright (c) 2018, AuriStor, Inc.
 *
 * Permission is granted to use, copy, create derivative works
 * and redistribute this software and such derivative works
 * for any purpose, so long as the name of The University of
 * Michigan is not used in any advertising or publicity
 * pertaining to the use of distribution of this software
 * without specific, written prior authorization.  If the
 * above copyright notice or any other identification of the
 * University of Michigan is included in any copy of any
 * portion of this software, then the disclaimer below must
 * also be included.
 *
 * THIS SOFTWARE IS PROVIDED AS IS, WITHOUT REPRESENTATION
 * FROM THE UNIVERSITY OF MICHIGAN AS TO ITS FITNESS FOR ANY
 * PURPOSE, AND WITHOUT WARRANTY BY THE UNIVERSITY OF
 * MICHIGAN OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING
 * WITHOUT LIMITATION THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE
 * REGENTS OF THE UNIVERSITY OF MICHIGAN SHALL NOT BE LIABLE
 * FOR ANY DAMAGES, INCLUDING SPECIAL, INDIRECT, INCIDENTAL, OR
 * CONSEQUENTIAL DAMAGES, WITH RESPECT TO ANY CLAIM ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OF THE SOFTWARE, EVEN
 * IF IT HAS BEEN OR IS HEREAFTER ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGES.
 */
/*
 * Copyright 1990,1991,1992,1993,1994,2000,2004 Massachusetts Institute of
 * Technology.  All Rights Reserved.
 *
 * Original stdio support copyright 1995 by Cygnus Support.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

/*
 * This file implements a collection-enabled credential cache type where the
 * credentials are stored in the Linux keyring facility.
 *
 * A residual of this type can have three forms:
 *    anchor:collection:subsidiary
 *    anchor:collection
 *    collection
 *
 * The anchor name is "process", "thread", or "legacy" and determines where we
 * search for keyring collections.  In the third form, the anchor name is
 * presumed to be "legacy".  The anchor keyring for legacy caches is the
 * session keyring.
 *
 * If the subsidiary name is present, the residual identifies a single cache
 * within a collection.  Otherwise, the residual identifies the collection
 * itself.  When a residual identifying a collection is resolved, the
 * collection's primary key is looked up (or initialized, using the collection
 * name as the subsidiary name), and the resulting cache's name will use the
 * first name form and will identify the primary cache.
 *
 * Keyring collections are named "_krb_<collection>" and are linked from the
 * anchor keyring.  The keys within a keyring collection are links to cache
 * keyrings, plus a link to one user key named "krb_ccache:primary" which
 * contains a serialized representation of the collection version (currently 1)
 * and the primary name of the collection.
 *
 * Cache keyrings contain one user key per credential which contains a
 * serialized representation of the credential.  There is also one user key
 * named "__krb5_princ__" which contains a serialized representation of the
 * cache's default principal.
 *
 * If the anchor name is "legacy", then the initial primary cache (the one
 * named with the collection name) is also linked to the session keyring, and
 * we look for a cache in that location when initializing the collection.  This
 * extra link allows that cache to be visible to old versions of the KEYRING
 * cache type, and allows us to see caches created by that code.
 */

#include "krb5_locl.h"

#ifdef HAVE_KEYUTILS_H

#include <keyutils.h>

/*
 * We try to use the big_key key type for credentials except in legacy caches.
 * We fall back to the user key type if the kernel does not support big_key.
 * If the library doesn't support keyctl_get_persistent(), we don't even try
 * big_key since the two features were added at the same time.
 */
#ifdef HAVE_KEYCTL_GET_PERSISTENT
#define KRCC_CRED_KEY_TYPE		"big_key"
#else
#define KRCC_CRED_KEY_TYPE		"user"
#endif

/*
 * We use the "user" key type for collection primary names, for cache principal
 * names, and for credentials in legacy caches.
 */
#define KRCC_KEY_TYPE_USER		"user"

/*
 * We create ccaches as separate keyrings
 */
#define KRCC_KEY_TYPE_KEYRING		"keyring"

/*
 * Special name of the key within a ccache keyring
 * holding principal information
 */
#define KRCC_SPEC_PRINC_KEYNAME		"__krb5_princ__"

/*
 * Special name for the key to communicate the name(s)
 * of credentials caches to be used for requests.
 * This should currently contain a single name, but
 * in the future may contain a list that may be
 * intelligently chosen from.
 */
#define KRCC_SPEC_CCACHE_SET_KEYNAME	"__krb5_cc_set__"

/*
 * This name identifies the key containing the name of the current primary
 * cache within a collection.
 */
#define KRCC_COLLECTION_PRIMARY		"krb_ccache:primary"

/*
 * If the library context does not specify a keyring collection, unique ccaches
 * will be created within this collection.
 */
#define KRCC_DEFAULT_UNIQUE_COLLECTION	"session:__krb5_unique__"

/*
 * Collection keyring names begin with this prefix.  We use a prefix so that a
 * cache keyring with the collection name itself can be linked directly into
 * the anchor, for legacy session keyring compatibility.
 */
#define KRCC_CCCOL_PREFIX		"_krb_"

/*
 * For the "persistent" anchor type, we look up or create this fixed keyring
 * name within the per-UID persistent keyring.
 */
#define KRCC_PERSISTENT_KEYRING_NAME	"_krb"

/*
 * Name of the key holding time offsets for the individual cache
 */
#define KRCC_TIME_OFFSETS		"__krb5_time_offsets__"

/*
 * Keyring name prefix and length of random name part
 */
#define KRCC_NAME_PREFIX		"krb_ccache_"
#define KRCC_NAME_RAND_CHARS		8

#define KRCC_COLLECTION_VERSION		1

#define KRCC_PERSISTENT_ANCHOR		"persistent"
#define KRCC_PROCESS_ANCHOR		"process"
#define KRCC_THREAD_ANCHOR		"thread"
#define KRCC_SESSION_ANCHOR		"session"
#define KRCC_USER_ANCHOR		"user"
#define KRCC_LEGACY_ANCHOR		"legacy"

#if SIZEOF_KEY_SERIAL_T != 4
/* lockless implementation assumes 32-bit key serials */
#error only 32-bit key serial numbers supported by this version of keyring ccache
#endif

typedef heim_base_atomic(key_serial_t) atomic_key_serial_t;

typedef union _krb5_krcache_and_princ_id {
    heim_base_atomic(uint64_t) krcu_cache_and_princ_id;
    struct {
	atomic_key_serial_t cache_id;	/* keyring ID representing ccache */
	atomic_key_serial_t princ_id;	/* key ID holding principal info */
    } krcu_id;
    #define krcu_cache_id		krcu_id.cache_id
    #define krcu_princ_id		krcu_id.princ_id
} krb5_krcache_and_princ_id;

/*
 * This represents a credentials cache "file" where cache_id is the keyring
 * serial number for this credentials cache "file".  Each key in the keyring
 * contains a separate key.
 *
 * Thread-safe as long as caches are not destroyed whilst other threads are
 * using them.
 */
typedef struct _krb5_krcache {
    char *krc_name;			/* Name for this credentials cache */
    char *krc_collection;
    char *krc_subsidiary;
    heim_base_atomic(krb5_timestamp) krc_changetime;	/* update time, does not decrease (mutable) */
    krb5_krcache_and_princ_id krc_id;	/* cache and principal IDs (mutable) */
    #define krc_cache_and_principal_id	krc_id.krcu_cache_and_princ_id
    #define krc_cache_id		krc_id.krcu_id.cache_id
    #define krc_princ_id		krc_id.krcu_id.princ_id
    key_serial_t krc_coll_id;		/* collection containing this cache keyring */
    krb5_boolean krc_is_legacy;		/* */
} krb5_krcache;

#define KRCACHE(X) ((krb5_krcache *)(X)->data.data)

static krb5_error_code KRB5_CALLCONV
krcc_get_first(krb5_context, krb5_ccache id, krb5_cc_cursor *cursor);

static krb5_error_code KRB5_CALLCONV
krcc_get_next(krb5_context context,
	      krb5_ccache id,
	      krb5_cc_cursor *cursor,
	      krb5_creds *creds);

static krb5_error_code KRB5_CALLCONV
krcc_end_get(krb5_context context,
	     krb5_ccache id,
	     krb5_cc_cursor *cursor);

static krb5_error_code KRB5_CALLCONV
krcc_end_cache_get(krb5_context context, krb5_cc_cursor cursor);

static krb5_error_code
clear_cache_keyring(krb5_context context, atomic_key_serial_t *pcache_id);

static krb5_error_code
alloc_cache(krb5_context context,
 	    key_serial_t collection_id,
	    key_serial_t cache_id,
	    const char *anchor_name,
	    const char *collection_name,
	    const char *subsidiary_name,
	    krb5_krcache **data);

static krb5_error_code
save_principal(krb5_context context,
	       key_serial_t cache_id,
	       krb5_const_principal princ,
	       atomic_key_serial_t *pprinc_id);

static krb5_error_code
save_time_offsets(krb5_context context,
		  key_serial_t cache_id,
		  int32_t sec_offset,
		  int32_t usec_offset);

static void
update_change_time(krb5_context context,
		   krb5_timestamp now,
		   krb5_krcache *d);

/*
 * GET_PERSISTENT(uid) acquires the persistent keyring for uid, or falls back
 * to the user keyring if uid matches the current effective uid.
 */

static key_serial_t
get_persistent_fallback(uid_t uid)
{
    return (uid == geteuid()) ? KEY_SPEC_USER_KEYRING : -1;
}

#ifdef HAVE_KEYCTL_GET_PERSISTENT
#define GET_PERSISTENT get_persistent_real
static key_serial_t
get_persistent_real(uid_t uid)
{
    key_serial_t key;

    key = keyctl_get_persistent(uid, KEY_SPEC_PROCESS_KEYRING);

    return (key == -1 && errno == ENOTSUP) ? get_persistent_fallback(uid) : key;
}
#else
#define GET_PERSISTENT get_persistent_fallback
#endif

/*
 * If a process has no explicitly set session keyring, KEY_SPEC_SESSION_KEYRING
 * will resolve to the user session keyring for ID lookup and reading, but in
 * some kernel versions, writing to that special keyring will instead create a
 * new empty session keyring for the process.  We do not want that; the keys we
 * create would be invisible to other processes.  We can work around that
 * behavior by explicitly writing to the user session keyring when it matches
 * the session keyring.  This function returns the keyring we should write to
 * for the session anchor.
 */
static key_serial_t
session_write_anchor(void)
{
    key_serial_t s, u;

    s = keyctl_get_keyring_ID(KEY_SPEC_SESSION_KEYRING, 0);
    u = keyctl_get_keyring_ID(KEY_SPEC_USER_SESSION_KEYRING, 0);

    return (s == u) ? KEY_SPEC_USER_SESSION_KEYRING : KEY_SPEC_SESSION_KEYRING;
}

/*
 * Find or create a keyring within parent with the given name.  If possess is
 * nonzero, also make sure the key is linked from possess.  This is necessary
 * to ensure that we have possession rights on the key when the parent is the
 * user or persistent keyring.
 */
static krb5_error_code
find_or_create_keyring(key_serial_t parent,
		       key_serial_t possess,
		       const char *name,
		       atomic_key_serial_t *pkey)
{
    key_serial_t key;

    key = keyctl_search(parent, KRCC_KEY_TYPE_KEYRING, name, possess);
    if (key == -1) {
	if (possess != 0) {
	    key = add_key(KRCC_KEY_TYPE_KEYRING, name, NULL, 0, possess);
	    if (key == -1 || keyctl_link(key, parent) == -1)
		return errno;
	} else {
	    key = add_key(KRCC_KEY_TYPE_KEYRING, name, NULL, 0, parent);
	    if (key == -1)
		return errno;
	}
    }

    heim_base_atomic_store(pkey, key);

    return 0;
}

/*
 * Parse a residual name into an anchor name, a collection name, and possibly a
 * subsidiary name.
 */
static krb5_error_code
parse_residual(krb5_context context,
	       const char *residual,
	       char **panchor_name,
	       char **pcollection_name,
	       char **psubsidiary_name)
{
    char *anchor_name = NULL;
    char *collection_name = NULL;
    char *subsidiary_name = NULL;
    const char *sep;

    *panchor_name = NULL;
    *pcollection_name = NULL;
    *psubsidiary_name = NULL;

    if (residual == NULL)
        residual = "";

    /* Parse out the anchor name.  Use the legacy anchor if not present. */
    sep = strchr(residual, ':');
    if (sep == NULL) {
	anchor_name = strdup(KRCC_LEGACY_ANCHOR);
	if (anchor_name == NULL)
	    goto nomem;
    } else {
	anchor_name = strndup(residual, sep - residual);
	if (anchor_name == NULL)
	    goto nomem;
	residual = sep + 1;
    }

    /* Parse out the collection and subsidiary name. */
    sep = strchr(residual, ':');
    if (sep == NULL) {
	collection_name = strdup(residual);
	if (collection_name == NULL)
	    goto nomem;
    } else {
	collection_name = strndup(residual, sep - residual);
	if (collection_name == NULL)
	    goto nomem;

	subsidiary_name = strdup(sep + 1);
	if (subsidiary_name == NULL)
	    goto nomem;
    }

    *panchor_name = anchor_name;
    *pcollection_name = collection_name;
    *psubsidiary_name = subsidiary_name;

    return 0;

nomem:
    free(anchor_name);
    free(collection_name);
    free(subsidiary_name);

    return krb5_enomem(context);
}

/*
 * Return TRUE if residual identifies a subsidiary cache which should be linked
 * into the anchor so it can be visible to old code.  This is the case if the
 * residual has the legacy anchor and the subsidiary name matches the
 * collection name.
 */
static krb5_boolean
is_legacy_cache_name_p(const char *residual)
{
    const char *sep, *aname, *cname, *sname;
    size_t alen, clen, legacy_len = sizeof(KRCC_LEGACY_ANCHOR) - 1;

    /* Get pointers to the anchor, collection, and subsidiary names. */
    aname = residual;
    sep = strchr(residual, ':');
    if (sep == NULL)
	return FALSE;

    alen = sep - aname;
    cname = sep + 1;
    sep = strchr(cname, ':');
    if (sep == NULL)
	return FALSE;

    clen = sep - cname;
    sname = sep + 1;

    return alen == legacy_len && clen == strlen(sname) &&
	   strncmp(aname, KRCC_LEGACY_ANCHOR, alen) == 0 &&
	   strncmp(cname, sname, clen) == 0;
}

/*
 * If the default cache name for context is a KEYRING cache, parse its residual
 * string.  Otherwise set all outputs to NULL.
 */
static krb5_error_code
get_default(krb5_context context,
	    char **panchor_name,
	    char **pcollection_name,
	    char **psubsidiary_name)
{
    const char *defname;

    *panchor_name = *pcollection_name = *psubsidiary_name = NULL;

    defname = krb5_cc_default_name(context);
    if (defname == NULL || strncmp(defname, "KEYRING:", 8) != 0)
	return 0;

    return parse_residual(context, defname + 8,
			  panchor_name, pcollection_name, psubsidiary_name);
}

/* Create a residual identifying a subsidiary cache. */
static krb5_error_code
make_subsidiary_residual(krb5_context context,
			 const char *anchor_name,
			 const char *collection_name,
			 const char *subsidiary_name,
			 char **presidual)
{
    if (asprintf(presidual, "%s:%s:%s", anchor_name, collection_name,
		 subsidiary_name ? subsidiary_name : "tkt") < 0) {
	*presidual = NULL;
	return krb5_enomem(context);
    }

    return 0;
}

/*
 * Retrieve or create a keyring for collection_name within the anchor, and set
 * *collection_id to its serial number.
 */
static krb5_error_code
get_collection(krb5_context context,
	       const char *anchor_name,
	       const char *collection_name,
	       atomic_key_serial_t *pcollection_id)
{
    krb5_error_code ret;
    key_serial_t persistent_id, anchor_id, possess_id = 0;
    char *ckname, *cnend;
    uid_t uidnum;

    heim_base_atomic_init(pcollection_id, 0);

    if (!anchor_name || !collection_name)
	return KRB5_KCC_INVALID_ANCHOR;

    if (strcmp(anchor_name, KRCC_PERSISTENT_ANCHOR) == 0) {
	/*
	 * The collection name is a uid (or empty for the current effective
	 * uid), and we look up a fixed keyring name within the persistent
	 * keyring for that uid.  We link it to the process keyring to ensure
	 * that we have possession rights on the collection key.
	 */
	if (*collection_name != '\0') {
	    errno = 0;
	    uidnum = (uid_t)strtol(collection_name, &cnend, 10);
	    if (errno || *cnend != '\0')
		return KRB5_KCC_INVALID_UID;
	} else {
	    uidnum = geteuid();
	}

	persistent_id = GET_PERSISTENT(uidnum);
	if (persistent_id == -1)
	    return KRB5_KCC_INVALID_UID;

	return find_or_create_keyring(persistent_id, KEY_SPEC_PROCESS_KEYRING,
				      KRCC_PERSISTENT_KEYRING_NAME,
				      pcollection_id);
    }

    if (strcmp(anchor_name, KRCC_PROCESS_ANCHOR) == 0) {
	anchor_id = KEY_SPEC_PROCESS_KEYRING;
    } else if (strcmp(anchor_name, KRCC_THREAD_ANCHOR) == 0) {
	anchor_id = KEY_SPEC_THREAD_KEYRING;
    } else if (strcmp(anchor_name, KRCC_SESSION_ANCHOR) == 0) {
	anchor_id = session_write_anchor();
    } else if (strcmp(anchor_name, KRCC_USER_ANCHOR) == 0) {
	/*
	 * The user keyring does not confer possession, so we need to link the
	 * collection to the process keyring to maintain possession rights.
	 */
	anchor_id = KEY_SPEC_USER_KEYRING;
	possess_id = KEY_SPEC_PROCESS_KEYRING;
    } else if (strcmp(anchor_name, KRCC_LEGACY_ANCHOR) == 0) {
	anchor_id = session_write_anchor();
    } else {
	return KRB5_KCC_INVALID_ANCHOR;
    }

    /* Look up the collection keyring name within the anchor keyring. */
    if (asprintf(&ckname, "%s%s", KRCC_CCCOL_PREFIX, collection_name) == -1)
	return krb5_enomem(context);

    ret = find_or_create_keyring(anchor_id, possess_id, ckname,
				 pcollection_id);
    free(ckname);

    return ret;
}

/* Store subsidiary_name into the primary index key for collection_id. */
static krb5_error_code
set_primary_name(krb5_context context,
		 key_serial_t collection_id,
		 const char *subsidiary_name)
{
    krb5_error_code ret;
    krb5_storage *sp;
    krb5_data payload;
    key_serial_t key;

    sp = krb5_storage_emem();
    if (sp == NULL) {
	krb5_set_error_message(context, KRB5_CC_NOMEM, N_("malloc: out of memory", ""));
	return KRB5_CC_NOMEM;
    }
    krb5_storage_set_byteorder(sp, KRB5_STORAGE_BYTEORDER_BE);

    ret = krb5_store_int32(sp, KRCC_COLLECTION_VERSION);
    if (ret)
	goto cleanup;

    ret = krb5_store_string(sp, subsidiary_name);
    if (ret)
	goto cleanup;

    ret = krb5_storage_to_data(sp, &payload);
    if (ret)
	goto cleanup;

    key = add_key(KRCC_KEY_TYPE_USER, KRCC_COLLECTION_PRIMARY,
		  payload.data, payload.length, collection_id);
    ret = (key == -1) ? errno : 0;
    krb5_data_free(&payload);

cleanup:
    krb5_storage_free(sp);

    return ret;
}

static krb5_error_code
parse_index(krb5_context context,
	    int32_t *version,
	    char **primary,
	    const unsigned char *payload,
	    size_t psize)
{
    krb5_error_code ret;
    krb5_data payload_data;
    krb5_storage *sp;

    payload_data.length = psize;
    payload_data.data = rk_UNCONST(payload);

    sp = krb5_storage_from_data(&payload_data);
    if (sp == NULL)
	return KRB5_CC_NOMEM;

    krb5_storage_set_byteorder(sp, KRB5_STORAGE_BYTEORDER_BE);

    ret = krb5_ret_int32(sp, version);
    if (ret == 0)
	ret = krb5_ret_string(sp, primary);

    krb5_storage_free(sp);

    return ret;
}

/*
 * Get or initialize the primary name within collection_id and set
 * *subsidiary to its value.  If initializing a legacy collection, look
 * for a legacy cache and add it to the collection.
 */
static krb5_error_code
get_primary_name(krb5_context context,
		 const char *anchor_name,
		 const char *collection_name,
		 key_serial_t collection_id,
		 char **psubsidiary)
{
    krb5_error_code ret;
    key_serial_t primary_id, legacy;
    void *payload = NULL;
    int payloadlen;
    int32_t version;
    char *subsidiary_name = NULL;

    *psubsidiary = NULL;

    primary_id = keyctl_search(collection_id, KRCC_KEY_TYPE_USER,
			       KRCC_COLLECTION_PRIMARY, 0);
    if (primary_id == -1) {
	/*
	 * Initialize the primary key using the collection name.  We can't name
	 * a key with the empty string, so map that to an arbitrary string.
	 */
	subsidiary_name = strdup((*collection_name == '\0') ? "tkt" :
				 collection_name);
	if (subsidiary_name == NULL) {
	    ret = krb5_enomem(context);
	    goto cleanup;
	}

	ret = set_primary_name(context, collection_id, subsidiary_name);
	if (ret)
	    goto cleanup;

	if (strcmp(anchor_name, KRCC_LEGACY_ANCHOR) == 0) {
	    /*
	     * Look for a cache created by old code. If we find one, add it to
	     * the collection.
	     */
	    legacy = keyctl_search(KEY_SPEC_SESSION_KEYRING,
				   KRCC_KEY_TYPE_KEYRING, subsidiary_name, 0);
	    if (legacy != -1 && keyctl_link(legacy, collection_id) == -1) {
		ret = errno;
		goto cleanup;
	    }
	}
    } else {
	/* Read, parse, and free the primary key's payload. */
	payloadlen = keyctl_read_alloc(primary_id, &payload);
	if (payloadlen == -1) {
	    ret = errno;
	    goto cleanup;
	}
	ret = parse_index(context, &version, &subsidiary_name, payload,
			  payloadlen);
	if (ret)
	    goto cleanup;

	if (version != KRCC_COLLECTION_VERSION) {
	    ret = KRB5_KCC_UNKNOWN_VERSION;
	    goto cleanup;
	}
    }

    *psubsidiary = subsidiary_name;
    subsidiary_name = NULL;

cleanup:
    free(payload);
    free(subsidiary_name);

    return ret;
}

/*
 * Note: MIT keyring code uses krb5int_random_string() as if the second argument
 * is a character count rather than a size. The function below takes a character
 * count to match the usage in this file correctly.
 */
static krb5_error_code
generate_random_string(krb5_context context, char *s, size_t slen)
{
    static char chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    char *p;
    size_t i;

    p = malloc(slen);
    if (p == NULL)
	return krb5_enomem(context);

    krb5_generate_random_block(p, slen);

    for (i = 0; i < slen; i++)
	s[i] = chars[p[i] % (sizeof(chars) - 1)];

    s[i] = '\0';
    free(p);

    return 0;
}

/*
 * Create a keyring with a unique random name within collection_id.  Set
 * *subsidiary to its name and *cache_id to its key serial number.
 */
static krb5_error_code
add_unique_keyring(krb5_context context,
		   key_serial_t collection_id,
		   char **psubsidiary,
		   key_serial_t *pcache_id)
{
    key_serial_t key;
    krb5_error_code ret;
    char uniquename[sizeof(KRCC_NAME_PREFIX) + KRCC_NAME_RAND_CHARS];
    int prefixlen = sizeof(KRCC_NAME_PREFIX) - 1;
    int tries;

    *psubsidiary = NULL;
    *pcache_id = 0;

    memcpy(uniquename, KRCC_NAME_PREFIX, sizeof(KRCC_NAME_PREFIX));

    for (key = -1, tries = 0; tries < 5; tries++) {
	ret = generate_random_string(context, uniquename + prefixlen,
				     KRCC_NAME_RAND_CHARS);
	if (ret)
	    return ret;

	key = keyctl_search(collection_id, KRCC_KEY_TYPE_KEYRING, uniquename, 0);
	if (key == -1) {
	    /* Name does not already exist.  Create it to reserve the name. */
	    key = add_key(KRCC_KEY_TYPE_KEYRING, uniquename, NULL, 0, collection_id);
	    if (key == -1)
		return errno;
	    break;
	}
    }

    *psubsidiary = strdup(uniquename);
    if (*psubsidiary == NULL)
	return krb5_enomem(context);

    *pcache_id = key;

    return 0;
}

static krb5_error_code
add_cred_key(const char *name,
	     const void *payload,
	     size_t plen,
	     key_serial_t cache_id,
	     krb5_boolean legacy_type,
	     key_serial_t *pkey)
{
    key_serial_t key;

    *pkey = -1;

    if (!legacy_type) {
	/* Try the preferred cred key type; fall back if no kernel support. */
	key = add_key(KRCC_CRED_KEY_TYPE, name, payload, plen, cache_id);
	if (key != -1) {
	    *pkey = key;
	    return 0;
	} else if (errno != EINVAL && errno != ENODEV)
	    return errno;
    }

    /* Use the user key type. */
    key = add_key(KRCC_KEY_TYPE_USER, name, payload, plen, cache_id);
    if (key == -1)
	return errno;

    *pkey = key;

    return 0;
}

static void
update_keyring_expiration(krb5_context context,
			  krb5_ccache id,
			  key_serial_t cache_id,
			  krb5_timestamp now)
{
    krb5_cc_cursor cursor;
    krb5_creds creds;
    krb5_timestamp endtime = 0;
    unsigned int timeout;

    /*
     * We have no way to know what is the actual timeout set on the keyring.
     * We also cannot keep track of it in a local variable as another process
     * can always modify the keyring independently, so just always enumerate
     * all start TGT keys and find out the highest endtime time.
     */
    if (krcc_get_first(context, id, &cursor) != 0)
	return;

    for (;;) {
	if (krcc_get_next(context, id, &cursor, &creds) != 0)
	    break;
	if (creds.times.endtime > endtime)
	    endtime = creds.times.endtime;
	krb5_free_cred_contents(context, &creds);
    }
    (void) krcc_end_get(context, id, &cursor);

    if (endtime == 0)	/* No creds with end times */
	return;

    /*
     * Setting the timeout to zero would reset the timeout, so we set it to one
     * second instead if creds are already expired.
     */
    timeout = endtime > now ? endtime - now : 1;
    (void) keyctl_set_timeout(cache_id, timeout);
}

/*
 * Create or overwrite the cache keyring, and set the default principal.
 */
static krb5_error_code
initialize_internal(krb5_context context,
		    krb5_ccache id,
		    krb5_const_principal princ)
{
    krb5_krcache *data = KRCACHE(id);
    krb5_error_code ret;
    const char *cache_name, *p;
    krb5_krcache_and_princ_id ids;

    if (data == NULL)
	return krb5_einval(context, 2);

    memset(&ids, 0, sizeof(ids));
    ids.krcu_cache_and_princ_id = heim_base_atomic_load(&data->krc_cache_and_principal_id);

    ret = clear_cache_keyring(context, &ids.krcu_cache_id);
    if (ret)
	return ret;

    if (ids.krcu_cache_id == 0) {
	/*
	 * The key didn't exist at resolve time, or was destroyed after resolving.
	 * Check again and create the key if it still isn't there.
         */
	p = strrchr(data->krc_name, ':');
	cache_name = (p != NULL) ? p + 1 : data->krc_name;
	ret = find_or_create_keyring(data->krc_coll_id, 0, cache_name, &ids.krcu_cache_id);
	if (ret)
	    return ret;
    }

    /*
     * If this is the legacy cache in a legacy session collection, link it
     * directly to the session keyring so that old code can see it.
     */
    if (is_legacy_cache_name_p(data->krc_name))
	(void) keyctl_link(ids.krcu_cache_id, session_write_anchor());

    if (princ != NULL) {
	ret = save_principal(context, ids.krcu_cache_id, princ, &ids.krcu_princ_id);
	if (ret)
	    return ret;
    } else
	ids.krcu_princ_id = 0;

    /*
     * Save time offset if it is valid and this is not a legacy cache.  Legacy
     * applications would fail to parse the new key in the cache keyring.
     */
    if (context->kdc_sec_offset && !is_legacy_cache_name_p(data->krc_name)) {
	ret = save_time_offsets(context,
				ids.krcu_cache_id,
				context->kdc_sec_offset,
				context->kdc_usec_offset);
	if (ret)
	    return ret;
    }

    /* update cache and principal IDs atomically */
    heim_base_atomic_store(&data->krc_cache_and_principal_id, ids.krcu_cache_and_princ_id);

    return 0;
}

static krb5_error_code KRB5_CALLCONV
krcc_initialize(krb5_context context, krb5_ccache id, krb5_principal princ)
{
    krb5_krcache *data = KRCACHE(id);
    krb5_error_code ret;

    if (data == NULL)
	return krb5_einval(context, 2);

    if (princ == NULL)
	return KRB5_CC_BADNAME;

    ret = initialize_internal(context, id, princ);
    if (ret == 0)
	update_change_time(context, 0, data);

    return ret;
}

/* Release the ccache handle. */
static krb5_error_code KRB5_CALLCONV
krcc_close(krb5_context context, krb5_ccache id)
{
    krb5_krcache *data = KRCACHE(id);

    if (data == NULL)
	return krb5_einval(context, 2);

    free(data->krc_subsidiary);
    free(data->krc_collection);
    free(data->krc_name);
    krb5_data_free(&id->data);

    return 0;
}

/*
 * Clear out a ccache keyring, unlinking all keys within it.
 */
static krb5_error_code
clear_cache_keyring(krb5_context context,
		    atomic_key_serial_t *pcache_id)
{
    int res;
    key_serial_t cache_id = heim_base_atomic_load(pcache_id);

    _krb5_debug(context, 10, "clear_cache_keyring: cache_id %d\n", cache_id);

    if (cache_id != 0) {
	res = keyctl_clear(cache_id);
	if (res == -1 && (errno == EACCES || errno == ENOKEY)) {
	    /*
	     * Possibly the keyring was destroyed between krcc_resolve() and now;
	     * if we really don't have permission, we will fail later.
	     */
	    res = 0;
	    heim_base_atomic_store(pcache_id, 0);
	}
	if (res == -1)
	    return errno;
    }

    return 0;
}

/* Destroy the cache keyring */
static krb5_error_code KRB5_CALLCONV
krcc_destroy(krb5_context context, krb5_ccache id)
{
    krb5_error_code ret = 0;
    krb5_krcache *data = KRCACHE(id);
    int res;

    if (data == NULL)
	return krb5_einval(context, 2);

    /* no atomics, destroy is not thread-safe */
    (void) clear_cache_keyring(context, &data->krc_cache_id);

    if (data->krc_cache_id != 0) {
	res = keyctl_unlink(data->krc_cache_id, data->krc_coll_id);
	if (res < 0) {
	    ret = errno;
	    _krb5_debug(context, 10, "unlinking key %d from ring %d: %s",
			data->krc_cache_id, data->krc_coll_id, error_message(errno));
	}
	/* If this is a legacy cache, unlink it from the session anchor. */
	if (is_legacy_cache_name_p(data->krc_name))
	    (void) keyctl_unlink(data->krc_cache_id, session_write_anchor());
    }

    heim_base_atomic_store(&data->krc_princ_id, 0);

    /* krcc_close is called by libkrb5, do not double-free */
    return ret;
}

/* Create a cache handle for a cache ID. */
static krb5_error_code
make_cache(krb5_context context,
	   key_serial_t collection_id,
	   key_serial_t cache_id,
	   const char *anchor_name,
	   const char *collection_name,
	   const char *subsidiary_name,
	   krb5_ccache *cache)
{
    krb5_error_code ret;
    krb5_krcache *data;
    key_serial_t princ_id = 0;

    /* Determine the key containing principal information, if present. */
    princ_id = keyctl_search(cache_id, KRCC_KEY_TYPE_USER, KRCC_SPEC_PRINC_KEYNAME, 0);
    if (princ_id == -1)
	princ_id = 0;

    ret = alloc_cache(context, collection_id, cache_id,
		      anchor_name, collection_name, subsidiary_name, &data);
    if (ret)
	return ret;

    if (*cache == NULL) {
	ret = _krb5_cc_allocate(context, &krb5_krcc_ops, cache);
	if (ret) {
	    free(data->krc_name);
	    free(data);
	    return ret;
	}
    }

    data->krc_princ_id = princ_id;

    (*cache)->data.data = data;
    (*cache)->data.length = sizeof(*data);

    return 0;
}

/* Create a keyring ccache handle for the given residual string. */
static krb5_error_code KRB5_CALLCONV
krcc_resolve_2(krb5_context context,
	       krb5_ccache *id,
	       const char *residual,
	       const char *sub)
{
    krb5_error_code ret;
    atomic_key_serial_t collection_id;
    key_serial_t cache_id;
    char *anchor_name = NULL, *collection_name = NULL, *subsidiary_name = NULL;

    ret = parse_residual(context, residual, &anchor_name, &collection_name,
                         &subsidiary_name);
    if (ret)
	goto cleanup;
    if (sub) {
        free(subsidiary_name);
        if ((subsidiary_name = strdup(sub)) == NULL) {
            ret = krb5_enomem(context);
            goto cleanup;
        }
    }

    ret = get_collection(context, anchor_name, collection_name, &collection_id);
    if (ret)
	goto cleanup;

    if (subsidiary_name == NULL) {
	/* Retrieve or initialize the primary name for the collection. */
	ret = get_primary_name(context, anchor_name, collection_name,
			       collection_id, &subsidiary_name);
	if (ret)
	    goto cleanup;
    }

    /* Look up the cache keyring ID, if the cache is already initialized. */
    cache_id = keyctl_search(collection_id, KRCC_KEY_TYPE_KEYRING,
			     subsidiary_name, 0);
    if (cache_id < 0)
	cache_id = 0;

    ret = make_cache(context, collection_id, cache_id, anchor_name,
		     collection_name, subsidiary_name, id);
    if (ret)
	goto cleanup;

cleanup:
    free(anchor_name);
    free(collection_name);
    free(subsidiary_name);

    return ret;
}

struct krcc_cursor {
    size_t numkeys;
    size_t currkey;
    key_serial_t princ_id;
    key_serial_t offsets_id;
    key_serial_t *keys;
};

/* Prepare for a sequential iteration over the cache keyring. */
static krb5_error_code
krcc_get_first(krb5_context context,
	       krb5_ccache id,
	       krb5_cc_cursor *cursor)
{
    struct krcc_cursor *krcursor;
    krb5_krcache *data = KRCACHE(id);
    key_serial_t cache_id;
    void *keys;
    long size;

    if (data == NULL)
	return krb5_einval(context, 2);

    cache_id = heim_base_atomic_load(&data->krc_cache_id);
    if (cache_id == 0)
	return KRB5_FCC_NOFILE;

    size = keyctl_read_alloc(cache_id, &keys);
    if (size == -1) {
	_krb5_debug(context, 10, "Error getting from keyring: %s\n",
		    strerror(errno));
	return KRB5_CC_IO;
    }

    krcursor = calloc(1, sizeof(*krcursor));
    if (krcursor == NULL) {
	free(keys);
	return KRB5_CC_NOMEM;
    }

    krcursor->princ_id = heim_base_atomic_load(&data->krc_princ_id);
    krcursor->offsets_id = keyctl_search(cache_id, KRCC_KEY_TYPE_USER,
					 KRCC_TIME_OFFSETS, 0);
    krcursor->numkeys = size / sizeof(key_serial_t);
    krcursor->keys = keys;

    *cursor = krcursor;

    return 0;
}

static krb5_error_code
keyctl_read_krb5_data(key_serial_t keyid, krb5_data *payload)
{
    krb5_data_zero(payload);

    payload->length = keyctl_read_alloc(keyid, &payload->data);

    return (payload->length == -1) ? KRB5_FCC_NOFILE : 0;
}

/* Get the next credential from the cache keyring. */
static krb5_error_code KRB5_CALLCONV
krcc_get_next(krb5_context context,
	      krb5_ccache id,
	      krb5_cc_cursor *cursor,
	      krb5_creds *creds)
{
    struct krcc_cursor *krcursor;
    krb5_error_code ret;
    krb5_data payload;
    krb5_storage *sp;

    memset(creds, 0, sizeof(krb5_creds));

    krcursor = *cursor;
    if (krcursor == NULL)
	return KRB5_CC_END;

    if (krcursor->currkey >= krcursor->numkeys)
	return KRB5_CC_END;

    /*
     * If we're pointing at the entry with the principal, or at the key
     * with the time offsets, skip it.
     */
    while (krcursor->keys[krcursor->currkey] == krcursor->princ_id ||
	   krcursor->keys[krcursor->currkey] == krcursor->offsets_id) {
	krcursor->currkey++;
	if (krcursor->currkey >= krcursor->numkeys)
	    return KRB5_CC_END;
    }

    ret = keyctl_read_krb5_data(krcursor->keys[krcursor->currkey], &payload);
    if (ret) {
	_krb5_debug(context, 10, "Error reading key %d: %s\n",
		    krcursor->keys[krcursor->currkey],
		    strerror(errno));
	return ret;
    }
    krcursor->currkey++;

    sp = krb5_storage_from_data(&payload);
    if (sp == NULL) {
	ret = KRB5_CC_IO;
    } else {
	ret = krb5_ret_creds(sp, creds);
	krb5_storage_free(sp);
    }

    krb5_data_free(&payload);

    return ret;
}

/* Release an iteration cursor. */
static krb5_error_code KRB5_CALLCONV
krcc_end_get(krb5_context context, krb5_ccache id, krb5_cc_cursor *cursor)
{
    struct krcc_cursor *krcursor = *cursor;

    if (krcursor != NULL) {
	free(krcursor->keys);
	free(krcursor);
    }

    *cursor = NULL;

    return 0;
}

/* Create keyring data for a credential cache. */
static krb5_error_code
alloc_cache(krb5_context context,
 	    key_serial_t collection_id,
	    key_serial_t cache_id,
	    const char *anchor_name,
	    const char *collection_name,
	    const char *subsidiary_name,
	    krb5_krcache **pdata)
{
    krb5_error_code ret;
    krb5_krcache *data;

    *pdata = NULL;

    data = calloc(1, sizeof(*data));
    if (data == NULL)
	return KRB5_CC_NOMEM;

    ret = make_subsidiary_residual(context, anchor_name, collection_name,
				   subsidiary_name, &data->krc_name);
    if (ret ||
        (data->krc_collection = strdup(collection_name)) == NULL ||
        (data->krc_subsidiary = strdup(subsidiary_name ? subsidiary_name : "tkt")) == NULL) {
        if (data) {
            free(data->krc_collection);
            free(data->krc_name);
        }
	free(data);
        if (ret == 0)
            ret = krb5_enomem(context);
	return ret;
    }

    heim_base_atomic_init(&data->krc_princ_id, 0);
    heim_base_atomic_init(&data->krc_cache_id, cache_id);
    data->krc_coll_id = collection_id;
    data->krc_changetime = 0;
    data->krc_is_legacy = (strcmp(anchor_name, KRCC_LEGACY_ANCHOR) == 0);

    update_change_time(context, 0, data);

    *pdata = data;

    return 0;
}

/* Create a new keyring cache with a unique name. */
static krb5_error_code KRB5_CALLCONV
krcc_gen_new(krb5_context context, krb5_ccache *id)
{
    krb5_error_code ret;
    char *anchor_name, *collection_name, *subsidiary_name;
    char *new_subsidiary_name = NULL, *new_residual = NULL;
    krb5_krcache *data;
    atomic_key_serial_t collection_id;
    key_serial_t cache_id = 0;

    /* Determine the collection in which we will create the cache.*/
    ret = get_default(context, &anchor_name, &collection_name,
		      &subsidiary_name);
    if (ret)
	return ret;

    if (anchor_name == NULL) {
	ret = parse_residual(context, KRCC_DEFAULT_UNIQUE_COLLECTION, &anchor_name,
			     &collection_name, &subsidiary_name);
	if (ret)
	    return ret;
    }
    if (subsidiary_name != NULL) {
	krb5_set_error_message(context, KRB5_DCC_CANNOT_CREATE,
		N_("Can't create new subsidiary cache because default cache "
		   "is already a subsidiary", ""));
	ret = KRB5_DCC_CANNOT_CREATE;
	goto cleanup;
    }

    /* Make a unique keyring within the chosen collection. */
    ret = get_collection(context, anchor_name, collection_name, &collection_id);
    if (ret)
	goto cleanup;

    ret = add_unique_keyring(context, collection_id, &new_subsidiary_name, &cache_id);
    if (ret)
	goto cleanup;

    ret = alloc_cache(context, collection_id, cache_id,
		      anchor_name, collection_name, new_subsidiary_name,
		      &data);
    if (ret)
	goto cleanup;

    (*id)->data.data = data;
    (*id)->data.length = sizeof(*data);

cleanup:
    free(anchor_name);
    free(collection_name);
    free(subsidiary_name);
    free(new_subsidiary_name);
    free(new_residual);

    return ret;
}

/* Return an alias to the residual string of the cache. */
static krb5_error_code KRB5_CALLCONV
krcc_get_name_2(krb5_context context,
		krb5_ccache id,
		const char **name,
		const char **collection_name,
		const char **subsidiary_name)
{
    krb5_krcache *data = KRCACHE(id);

    if (data == NULL)
	return krb5_einval(context, 2);

    if (name)
        *name = data->krc_name;
    if (collection_name)
        *collection_name = data->krc_collection;
    if (subsidiary_name)
        *subsidiary_name = data->krc_subsidiary;
    return 0;
}

/* Retrieve a copy of the default principal, if the cache is initialized. */
static krb5_error_code KRB5_CALLCONV
krcc_get_principal(krb5_context context,
		   krb5_ccache id,
		   krb5_principal *princ)
{
    krb5_krcache *data = KRCACHE(id);
    krb5_error_code ret;
    krb5_storage *sp = NULL;
    krb5_data payload;
    krb5_krcache_and_princ_id ids;

    krb5_data_zero(&payload);
    *princ = NULL;

    if (data == NULL)
	return krb5_einval(context, 2);

    memset(&ids, 0, sizeof(ids));
    ids.krcu_cache_and_princ_id = heim_base_atomic_load(&data->krc_cache_and_principal_id);
    if (ids.krcu_cache_id == 0 || ids.krcu_princ_id == 0) {
	ret = KRB5_FCC_NOFILE;
	krb5_set_error_message(context, ret,
			       N_("Credentials cache keyring '%s' not found", ""),
			       data->krc_name);
	goto cleanup;
    }

    ret = keyctl_read_krb5_data(ids.krcu_princ_id, &payload);
    if (ret) {
	_krb5_debug(context, 10, "Reading principal key %d: %s\n",
		    ids.krcu_princ_id, strerror(errno));
	goto cleanup;
    }

    sp = krb5_storage_from_data(&payload);
    if (sp == NULL) {
	ret = KRB5_CC_IO;
	goto cleanup;
    }

    ret = krb5_ret_principal(sp, princ);
    if (ret)
	goto cleanup;

cleanup:
    krb5_storage_free(sp);
    krb5_data_free(&payload);

    return ret;
}

/* Remove a cred from the cache keyring */
static krb5_error_code KRB5_CALLCONV
krcc_remove_cred(krb5_context context, krb5_ccache id,
		 krb5_flags which, krb5_creds *mcred)
{
    krb5_krcache *data = KRCACHE(id);
    krb5_error_code ret, ret2;
    krb5_cc_cursor cursor;
    krb5_creds found_cred;
    krb5_krcache_and_princ_id ids;

    if (data == NULL)
	return krb5_einval(context, 2);

    ret = krcc_get_first(context, id, &cursor);
    if (ret)
	return ret;

    memset(&ids, 0, sizeof(ids));
    ids.krcu_cache_and_princ_id = heim_base_atomic_load(&data->krc_cache_and_principal_id);

    while ((ret = krcc_get_next(context, id, &cursor, &found_cred)) == 0) {
	struct krcc_cursor *krcursor = cursor;

	if (!krb5_compare_creds(context, which, mcred, &found_cred)) {
	    krb5_free_cred_contents(context, &found_cred);
	    continue;
	}

	_krb5_debug(context, 10, "Removing cred %d from cache_id %d, princ_id %d\n",
		    krcursor->keys[krcursor->currkey - 1],
		    ids.krcu_cache_id, ids.krcu_princ_id);

	keyctl_invalidate(krcursor->keys[krcursor->currkey - 1]);
	krcursor->keys[krcursor->currkey - 1] = 0;
	krb5_free_cred_contents(context, &found_cred);
    }

    ret2 = krcc_end_get(context, id, &cursor);
    if (ret == KRB5_CC_END)
	ret = ret2;

    return ret;
}

/* Set flags on the cache.  (We don't care about any flags.) */
static krb5_error_code KRB5_CALLCONV
krcc_set_flags(krb5_context context, krb5_ccache id, krb5_flags flags)
{
    return 0;
}

static int KRB5_CALLCONV
krcc_get_version(krb5_context context, krb5_ccache id)
{
    return 0;
}
 
/* Store a credential in the cache keyring. */
static krb5_error_code KRB5_CALLCONV
krcc_store(krb5_context context, krb5_ccache id, krb5_creds *creds)
{
    krb5_error_code ret;
    krb5_krcache *data = KRCACHE(id);
    krb5_storage *sp = NULL;
    char *keyname = NULL;
    key_serial_t cred_key, cache_id;
    krb5_timestamp now;
    krb5_data payload;

    krb5_data_zero(&payload);

    if (data == NULL)
	return krb5_einval(context, 2);

    cache_id = heim_base_atomic_load(&data->krc_cache_id);
    if (cache_id == 0)
	return KRB5_FCC_NOFILE;

    ret = krb5_unparse_name(context, creds->server, &keyname);
    if (ret)
	goto cleanup;

    sp = krb5_storage_emem();
    if (sp == NULL) {
	krb5_set_error_message(context, KRB5_CC_NOMEM, N_("malloc: out of memory", ""));
	ret = KRB5_CC_NOMEM;
	goto cleanup;
    }

    ret = krb5_store_creds(sp, creds);
    if (ret)
	goto cleanup;

    ret = krb5_storage_to_data(sp, &payload);
    if (ret)
	goto cleanup;

    _krb5_debug(context, 10, "krcc_store: adding new key '%s' to keyring %d\n",
		keyname, cache_id);
    ret = add_cred_key(keyname, payload.data, payload.length, cache_id,
		       data->krc_is_legacy, &cred_key);
    if (ret)
	goto cleanup;

    ret = krb5_timeofday(context, &now);
    if (ret)
	goto cleanup;

    update_change_time(context, now, data);

    /* Set timeout on credential key */
    if (creds->times.endtime > now)
	(void) keyctl_set_timeout(cred_key, creds->times.endtime - now);

    /* Set timeout on credential cache keyring */
    update_keyring_expiration(context, id, cache_id, now);

cleanup:
    krb5_data_free(&payload);
    krb5_storage_free(sp);
    krb5_xfree(keyname);

    return ret;
}

/*
 * Get the cache's last modification time.  (This is currently broken; it
 * returns only the last change made using this handle.)
 */
static krb5_error_code KRB5_CALLCONV
krcc_lastchange(krb5_context context,
		krb5_ccache id,
		krb5_timestamp *change_time)
{
    krb5_krcache *data = KRCACHE(id);

    if (data == NULL)
	return krb5_einval(context, 2);

    *change_time = heim_base_atomic_load(&data->krc_changetime);

    return 0;
}

static krb5_error_code
save_principal(krb5_context context,
	       key_serial_t cache_id,
	       krb5_const_principal princ,
	       atomic_key_serial_t *pprinc_id)
{
    krb5_error_code ret;
    krb5_storage *sp;
    key_serial_t newkey;
    krb5_data payload;

    krb5_data_zero(&payload);

    sp = krb5_storage_emem();
    if (sp == NULL) {
	krb5_set_error_message(context, KRB5_CC_NOMEM, N_("malloc: out of memory", ""));
	return KRB5_CC_NOMEM;
    }

    ret = krb5_store_principal(sp, princ);
    if (ret) {
	krb5_storage_free(sp);
	return ret;
    }

    ret = krb5_storage_to_data(sp, &payload);
    if (ret) {
	krb5_storage_free(sp);
	return ret;
    }

    krb5_storage_free(sp);
    {
	krb5_error_code tmp;
	char *princname = NULL;

	tmp = krb5_unparse_name(context, princ, &princname);
	_krb5_debug(context, 10, "save_principal: adding new key '%s' "
		    "to keyring %d for principal '%s'\n",
		    KRCC_SPEC_PRINC_KEYNAME, cache_id,
		    tmp ? "<unknown>" : princname);
	if (tmp == 0)
	    krb5_xfree(princname);
    }

    /* Add new key into keyring */
    newkey = add_key(KRCC_KEY_TYPE_USER, KRCC_SPEC_PRINC_KEYNAME,
		     payload.data, payload.length, cache_id);
    if (newkey == -1) {
	ret = errno;
	_krb5_debug(context, 10, "Error adding principal key: %s\n", strerror(ret));
    } else {
	ret = 0;
	heim_base_atomic_store(pprinc_id, newkey);
    }

    krb5_data_free(&payload);

    return ret;
}

/* Add a key to the cache keyring containing the given time offsets. */
static krb5_error_code
save_time_offsets(krb5_context context,
		  key_serial_t cache_id,
		  int32_t sec_offset,
		  int32_t usec_offset)
{
    krb5_error_code ret;
    key_serial_t newkey;
    krb5_storage *sp;
    krb5_data payload;

    krb5_data_zero(&payload);

    sp = krb5_storage_emem();
    if (sp == NULL) {
	krb5_set_error_message(context, KRB5_CC_NOMEM, N_("malloc: out of memory", ""));
	return KRB5_CC_NOMEM;
    }

    krb5_storage_set_byteorder(sp, KRB5_STORAGE_BYTEORDER_BE);

    ret = krb5_store_int32(sp, sec_offset);
    if (ret == 0)
	ret = krb5_store_int32(sp, usec_offset);
    if (ret) {
	krb5_storage_free(sp);
	return ret;
    }

    ret = krb5_storage_to_data(sp, &payload);
    if (ret) {
	krb5_storage_free(sp);
	return ret;
    }

    krb5_storage_free(sp);

    newkey = add_key(KRCC_KEY_TYPE_USER, KRCC_TIME_OFFSETS, payload.data,
		     payload.length, cache_id);
    ret = newkey == -1 ? errno : 0;

    krb5_data_free(&payload);

    return ret;
}

static krb5_error_code KRB5_CALLCONV
krcc_set_kdc_offset(krb5_context context, krb5_ccache id, krb5_deltat offset)
{
    krb5_krcache *data = KRCACHE(id);
    key_serial_t cache_id;
    krb5_error_code ret;

    if (data == NULL)
	return krb5_einval(context, 2);

    cache_id = heim_base_atomic_load(&data->krc_cache_id);
 
    ret = save_time_offsets(context, cache_id, (int32_t)offset, 0);
    if (ret == 0)
	update_change_time(context, 0, data);

    return ret;
}

/* Retrieve and parse the key in the cache keyring containing time offsets. */
static krb5_error_code KRB5_CALLCONV
krcc_get_kdc_offset(krb5_context context,
		    krb5_ccache id,
		    krb5_deltat *offset)
{
    krb5_krcache *data = KRCACHE(id);
    krb5_error_code ret = 0;
    key_serial_t key, cache_id;
    krb5_storage *sp = NULL;
    krb5_data payload;
    int32_t sec_offset = 0;

    if (data == NULL)
	return krb5_einval(context, 2);

    krb5_data_zero(&payload);

    cache_id = heim_base_atomic_load(&data->krc_cache_id);
    if (cache_id == 0) {
	ret = KRB5_FCC_NOFILE;
	goto cleanup;
    }

    key = keyctl_search(cache_id, KRCC_KEY_TYPE_USER, KRCC_TIME_OFFSETS, 0);
    if (key == -1) {
	ret = ENOENT;
	goto cleanup;
    }

    ret = keyctl_read_krb5_data(key, &payload);
    if (ret) {
	_krb5_debug(context, 10, "Reading time offsets key %d: %s\n",
		    key, strerror(errno));
	goto cleanup;
    }

    sp = krb5_storage_from_data(&payload);
    if (sp == NULL) {
	ret = krb5_enomem(context);;
	goto cleanup;
    }

    krb5_storage_set_byteorder(sp, KRB5_STORAGE_BYTEORDER_BE);

    ret = krb5_ret_int32(sp, &sec_offset);
    /*
     * We can't output nor use the usec_offset here, so we don't bother to read
     * it, though we do write it.
     */

cleanup:
    *offset = sec_offset;
    krb5_storage_free(sp);
    krb5_data_free(&payload);
    return ret;
}

struct krcc_iter {
    atomic_key_serial_t collection_id;
    char *anchor_name;
    char *collection_name;
    char *subsidiary_name;
    char *primary_name;
    krb5_boolean first;
    long num_keys;
    long next_key;
    key_serial_t *keys;
};

static krb5_error_code KRB5_CALLCONV
krcc_get_cache_first(krb5_context context, krb5_cc_cursor *cursor)
{
    struct krcc_iter *iter;
    krb5_error_code ret;
    void *keys;
    long size;

    *cursor = NULL;

    iter = calloc(1, sizeof(*iter));
    if (iter == NULL) {
	ret = krb5_enomem(context);
	goto error;
    }
    iter->first = TRUE;

    ret = get_default(context, &iter->anchor_name, &iter->collection_name,
		      &iter->subsidiary_name);
    if (ret)
	goto error;

    /* If there is no default collection, return an empty cursor. */
    if (iter->anchor_name == NULL) {
	*cursor = iter;
	return 0;
    }

    ret = get_collection(context, iter->anchor_name, iter->collection_name,
			 &iter->collection_id);
    if (ret)
	goto error;

    if (iter->subsidiary_name == NULL) {
	ret = get_primary_name(context, iter->anchor_name,
			       iter->collection_name, iter->collection_id,
			       &iter->primary_name);
	if (ret)
	    goto error;

	size = keyctl_read_alloc(iter->collection_id, &keys);
	if (size == -1) {
	    ret = errno;
	    goto error;
	}
	iter->keys = keys;
	iter->num_keys = size / sizeof(key_serial_t);
    }

    *cursor = iter;

    return 0;

error:
    krcc_end_cache_get(context, iter);

    return ret;
}

static krb5_error_code KRB5_CALLCONV
krcc_get_cache_next(krb5_context context,
		    krb5_cc_cursor cursor,
		    krb5_ccache *cache)
{
    krb5_error_code ret;
    struct krcc_iter *iter = cursor;
    key_serial_t key, cache_id = 0;
    const char *first_name, *keytype, *sep, *subsidiary_name;
    size_t keytypelen;
    char *description = NULL;

    *cache = NULL;

    /* No keyring available */
    if (iter->collection_id == 0)
	return KRB5_CC_END;

    if (iter->first) {
	/*
	 * Look for the primary cache for a collection cursor, or the
	 * subsidiary cache for a subsidiary cursor.
	 */
	iter->first = FALSE;
	first_name = (iter->primary_name != NULL) ? iter->primary_name :
		     iter->subsidiary_name;
	cache_id = keyctl_search(iter->collection_id, KRCC_KEY_TYPE_KEYRING,
				 first_name, 0);
	if (cache_id != -1) {
	    return make_cache(context, iter->collection_id, cache_id,
			      iter->anchor_name, iter->collection_name,
			      first_name, cache);
	}
    }

    /* A subsidiary cursor yields at most the first cache. */
    if (iter->subsidiary_name != NULL)
	return KRB5_CC_END;

    keytype = KRCC_KEY_TYPE_KEYRING ";";
    keytypelen = strlen(keytype);

    for (ret = KRB5_CC_END; iter->next_key < iter->num_keys; iter->next_key++) {
	free(description);
	description = NULL;

	/*
	 * Get the key description, which should have the form:
	 *   typename;UID;GID;permissions;description
	 */
	key = iter->keys[iter->next_key];
	if (keyctl_describe_alloc(key, &description) < 0)
	    continue;
	sep = strrchr(description, ';');
	if (sep == NULL)
	    continue;
	subsidiary_name = sep + 1;

	/* Skip this key if it isn't a keyring. */
	if (strncmp(description, keytype, keytypelen) != 0)
	    continue;

	/* Don't repeat the primary cache. */
	if (iter->primary_name &&
            strcmp(subsidiary_name, iter->primary_name) == 0)
	    continue;

	/* We found a valid key */
	iter->next_key++;
	ret = make_cache(context, iter->collection_id, key, iter->anchor_name,
			 iter->collection_name, subsidiary_name, cache);
	break;
    }

    free(description);

    return ret;
}

static krb5_error_code KRB5_CALLCONV
krcc_end_cache_get(krb5_context context, krb5_cc_cursor cursor)
{
    struct krcc_iter *iter = cursor;

    if (iter != NULL) {
	free(iter->anchor_name);
	free(iter->collection_name);
	free(iter->subsidiary_name);
	free(iter->primary_name);
	free(iter->keys);

	memset(iter, 0, sizeof(*iter));
	free(iter);
    }

    return 0;
}

static krb5_error_code KRB5_CALLCONV
krcc_set_default(krb5_context context, krb5_ccache id)
{
    krb5_krcache *data = KRCACHE(id);
    krb5_error_code ret;
    char *anchor_name, *collection_name, *subsidiary_name;
    atomic_key_serial_t collection_id;

    if (data == NULL)
	return krb5_einval(context, 2);

    ret = parse_residual(context, data->krc_name,
			 &anchor_name, &collection_name, &subsidiary_name);
    if (ret)
	goto cleanup;

    ret = get_collection(context, anchor_name, collection_name, &collection_id);
    if (ret)
	goto cleanup;

    ret = set_primary_name(context, collection_id, subsidiary_name);
    if (ret)
	goto cleanup;

cleanup:
    free(anchor_name);
    free(collection_name);
    free(subsidiary_name);

    return ret;
}

/*
 * Utility routine: called by krcc_* functions to keep
 * result of krcc_last_change_time up to date.
 */
static void
update_change_time(krb5_context context, krb5_timestamp now, krb5_krcache *data)
{
    krb5_timestamp old;

    if (now == 0)
	krb5_timeofday(context, &now);

    old = heim_base_exchange_time_t(&data->krc_changetime, now);
    if (old > now) /* don't go backwards */
	heim_base_atomic_store(&data->krc_changetime, old + 1);
}

static int
move_key_to_new_keyring(key_serial_t parent, key_serial_t key,
			char *desc, int desc_len, void *data)
{
    key_serial_t cache_id = *(key_serial_t *)data;

    if (parent) {
	if (keyctl_link(key, cache_id) == -1 ||
	    keyctl_unlink(key, parent) == -1)
	    return -1;
    }

    return 0;
}

/* Move contents of one ccache to another; destroys from cache */
static krb5_error_code KRB5_CALLCONV
krcc_move(krb5_context context, krb5_ccache from, krb5_ccache to)
{
    krb5_krcache *krfrom = KRCACHE(from);
    krb5_krcache *krto = KRCACHE(to);
    krb5_error_code ret;
    krb5_timestamp now;
    key_serial_t to_cache_id;

    if (krfrom == NULL || krto == NULL)
	return krb5_einval(context, 2);

    ret = initialize_internal(context, to, NULL);
    if (ret)
	return ret;

    krb5_timeofday(context, &now);
    to_cache_id = heim_base_atomic_load(&krto->krc_cache_id);

    if (krfrom->krc_cache_id != 0) {
	ret = recursive_key_scan(krfrom->krc_cache_id,
				 move_key_to_new_keyring, &to_cache_id);
	if (ret)
	    return KRB5_CC_IO;

	if (keyctl_unlink(krfrom->krc_cache_id, krfrom->krc_coll_id) == -1)
	    return errno;

	heim_base_exchange_32(&krto->krc_princ_id, krfrom->krc_princ_id);
    }

    update_change_time(context, now, krto);
    krb5_cc_destroy(context, from);
    return 0;
}

static krb5_error_code KRB5_CALLCONV
krcc_get_default_name(krb5_context context, char **str)
{
    *str = strdup("KEYRING:");
    if (*str == NULL)
	return krb5_enomem(context);

    return 0;
}

/*
 * ccache implementation storing credentials in the Linux keyring facility
 * The default is to put them at the session keyring level.
 * If "KEYRING:process:" or "KEYRING:thread:" is specified, then they will
 * be stored at the process or thread level respectively.
 */
KRB5_LIB_VARIABLE const krb5_cc_ops krb5_krcc_ops = {
    KRB5_CC_OPS_VERSION_5,
    "KEYRING",
    NULL,
    NULL,
    krcc_gen_new,
    krcc_initialize,
    krcc_destroy,
    krcc_close,
    krcc_store,
    NULL,		    /* retrieve */
    krcc_get_principal,
    krcc_get_first,
    krcc_get_next,
    krcc_end_get,
    krcc_remove_cred,
    krcc_set_flags,
    krcc_get_version,
    krcc_get_cache_first,
    krcc_get_cache_next,
    krcc_end_cache_get,
    krcc_move,
    krcc_get_default_name,
    krcc_set_default,
    krcc_lastchange,
    krcc_set_kdc_offset,
    krcc_get_kdc_offset,
    krcc_get_name_2,
    krcc_resolve_2
};

#endif /* HAVE_KEYUTILS_H */
