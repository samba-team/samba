/*
 * Copyright (c) 2020 Kungliga Tekniska Högskolan
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

/*
 * This program implements an ephemeral, memory-based HDB backend, stores into
 * it just one HDB entry -one for a namespace- then checks that virtual
 * principals are returned below that namespace by hdb_fetch_kvno(), and that
 * the logic for automatic key rotation of virtual principals is correct.
 */

#include "hdb_locl.h"
#include <hex.h>

static KeyRotation krs[2];
static const char *base_pw[2] = { "Testing123...", "Tested123..." };

typedef struct {
    HDB hdb;            /* generic members */
    /*
     * Make this dict a global, add a mutex lock around it, and a .finit and/or
     * atexit() handler to free it, and we'd have a first-class MEMORY HDB.
     *
     * What would a first-class MEMORY HDB be good for though, besides testing?
     *
     * However, we could move this dict into `HDB' and then have _hdb_store()
     * and friends support it as a cache for frequently-used & seldom-changing
     * entries, such as: K/M, namespaces, and krbtgt principals.  That would
     * speed up lookups, especially for backends with poor reader-writer
     * concurrency (DB, LMDB) and LDAP.  Such entries could be cached for a
     * minute or three at a time.
     */
    heim_dict_t dict;
} TEST_HDB;

struct hdb_called {
    int create;
    int init;
    int fini;
};

static krb5_error_code
TDB_close(krb5_context context, HDB *db)
{
    return 0;
}

static krb5_error_code
TDB_destroy(krb5_context context, HDB *db)
{
    TEST_HDB *tdb = (void *)db;

    heim_release(tdb->dict);
    free(tdb->hdb.hdb_name);
    free(tdb);
    return 0;
}

static krb5_error_code
TDB_set_sync(krb5_context context, HDB *db, int on)
{
    return 0;
}

static krb5_error_code
TDB_lock(krb5_context context, HDB *db, int operation)
{

    return 0;
}

static krb5_error_code
TDB_unlock(krb5_context context, HDB *db)
{

    return 0;
}

static krb5_error_code
TDB_firstkey(krb5_context context, HDB *db, unsigned flags, hdb_entry *entry)
{
    /* XXX Implement */
    /* Tricky thing: heim_dict_iterate_f() is inconvenient here */
    /* We need this to check that virtual principals aren't created */
    return 0;
}

static krb5_error_code
TDB_nextkey(krb5_context context, HDB *db, unsigned flags, hdb_entry *entry)
{
    /* XXX Implement */
    /* Tricky thing: heim_dict_iterate_f() is inconvenient here */
    /* We need this to check that virtual principals aren't created */
    return 0;
}

static krb5_error_code
TDB_rename(krb5_context context, HDB *db, const char *new_name)
{
    return EEXIST;
}

static krb5_error_code
TDB__get(krb5_context context, HDB *db, krb5_data key, krb5_data *reply)
{
    krb5_error_code ret = 0;
    TEST_HDB *tdb = (void *)db;
    heim_object_t k, v = NULL;

    if ((k = heim_data_create(key.data, key.length)) == NULL)
        ret = krb5_enomem(context);
    if (ret == 0 && (v = heim_dict_get_value(tdb->dict, k)) == NULL)
        ret = HDB_ERR_NOENTRY;
    if (ret == 0)
        ret = krb5_data_copy(reply, heim_data_get_ptr(v), heim_data_get_length(v));
    heim_release(k);
    return ret;
}

static krb5_error_code
TDB__put(krb5_context context, HDB *db, int rplc, krb5_data kd, krb5_data vd)
{
    krb5_error_code ret = 0;
    TEST_HDB *tdb = (void *)db;
    heim_object_t k = NULL;
    heim_object_t v = NULL;

    if ((k = heim_data_create(kd.data, kd.length)) == NULL ||
        (v = heim_data_create(vd.data, vd.length)) == NULL)
        ret = krb5_enomem(context);
    if (ret == 0 && !rplc && heim_dict_get_value(tdb->dict, k) != NULL)
        ret = HDB_ERR_EXISTS;
    if (ret == 0 && heim_dict_set_value(tdb->dict, k, v))
        ret = krb5_enomem(context);
    heim_release(k);
    heim_release(v);
    return ret;
}

static krb5_error_code
TDB__del(krb5_context context, HDB *db, krb5_data key)
{
    krb5_error_code ret = 0;
    TEST_HDB *tdb = (void *)db;
    heim_object_t k;

    if ((k = heim_data_create(key.data, key.length)) == NULL)
        ret = krb5_enomem(context);
    if (ret == 0 && heim_dict_get_value(tdb->dict, k) == NULL)
        ret = HDB_ERR_NOENTRY;
    if (ret == 0)
        heim_dict_delete_key(tdb->dict, k);
    heim_release(k);
    return ret;
}

static krb5_error_code
TDB_open(krb5_context context, HDB *db, int flags, mode_t mode)
{
    return 0;
}

static krb5_error_code
hdb_test_create(krb5_context context, struct HDB **db, const char *arg)
{
    TEST_HDB *tdb;

    if ((tdb = calloc(1, sizeof(tdb[0]))) == NULL ||
        (tdb->hdb.hdb_name = strdup(arg)) == NULL ||
        (tdb->dict = heim_dict_create(10)) == NULL) {
        if (tdb)
            free(tdb->hdb.hdb_name);
        free(tdb);
        return krb5_enomem(context);
    }

    tdb->hdb.hdb_db = NULL;
    tdb->hdb.hdb_master_key_set = 0;
    tdb->hdb.hdb_openp = 0;
    tdb->hdb.hdb_capability_flags = HDB_CAP_F_HANDLE_ENTERPRISE_PRINCIPAL;
    tdb->hdb.hdb_open  = TDB_open;
    tdb->hdb.hdb_close = TDB_close;
    tdb->hdb.hdb_fetch_kvno = _hdb_fetch_kvno;
    tdb->hdb.hdb_store = _hdb_store;
    tdb->hdb.hdb_remove = _hdb_remove;
    tdb->hdb.hdb_firstkey = TDB_firstkey;
    tdb->hdb.hdb_nextkey= TDB_nextkey;
    tdb->hdb.hdb_lock = TDB_lock;
    tdb->hdb.hdb_unlock = TDB_unlock;
    tdb->hdb.hdb_rename = TDB_rename;
    tdb->hdb.hdb__get = TDB__get;
    tdb->hdb.hdb__put = TDB__put;
    tdb->hdb.hdb__del = TDB__del;
    tdb->hdb.hdb_destroy = TDB_destroy;
    tdb->hdb.hdb_set_sync = TDB_set_sync;
    *db = &tdb->hdb;

    return 0;
}

static krb5_error_code
hdb_test_init(krb5_context context, void **ctx)
{
    *ctx = NULL;
    return 0;
}

static void hdb_test_fini(void *ctx)
{
}

struct hdb_method hdb_test =
{
#ifdef WIN32
    /* Not c99 */
    HDB_INTERFACE_VERSION,
    hdb_test_init,
    hdb_test_fini,
    1 /*is_file_based*/, 1 /*can_taste*/,
    "test",
    hdb_test_create
#else
    .minor_version = HDB_INTERFACE_VERSION,
    .init = hdb_test_init,
    .fini = hdb_test_fini,
    .is_file_based = 1,
    .can_taste = 1,
    .prefix = "test",
    .create = hdb_test_create
#endif
};

static krb5_error_code
make_base_key(krb5_context context,
              krb5_const_principal p,
              const char *pw,
              krb5_keyblock *k)
{
    return krb5_string_to_key(context, KRB5_ENCTYPE_AES128_CTS_HMAC_SHA256_128,
                              pw, p, k);
}

static krb5_error_code
tderive_key(krb5_context context,
            const char *p,
            KeyRotation *kr,
            int toffset,
            krb5_keyblock *base,
            krb5int32 etype,
            krb5_keyblock *k,
            uint32_t *kvno,
            time_t *set_time)
{
    krb5_error_code ret = 0;
    krb5_crypto crypto = NULL;
    EncryptionKey intermediate;
    krb5_data pad, out;
    size_t len;
    int n;

    n = toffset / kr->period;
    *set_time = kr->epoch + kr->period * n;
    *kvno = kr->base_kvno + n;

    out.data = 0;
    out.length = 0;

    /* Derive intermediate key */
    pad.data = (void *)(uintptr_t)p;
    pad.length = strlen(p);
    ret = krb5_enctype_keysize(context, base->keytype, &len);
    if (ret == 0)
        ret = krb5_crypto_init(context, base, 0, &crypto);
    if (ret == 0)
        ret = krb5_crypto_prfplus(context, crypto, &pad, len, &out);
    if (crypto)
        krb5_crypto_destroy(context, crypto);
    crypto = NULL;
    if (ret == 0)
        ret = krb5_random_to_key(context, etype, out.data, out.length,
                                 &intermediate);
    krb5_data_free(&out);

    /* Derive final key */
    pad.data = kvno;
    pad.length = sizeof(*kvno);
    if (ret == 0)
        ret = krb5_enctype_keysize(context, etype, &len);
    if (ret == 0)
        ret = krb5_crypto_init(context, &intermediate, 0, &crypto);
    if (ret == 0) {
        *kvno = htonl(*kvno);
        ret = krb5_crypto_prfplus(context, crypto, &pad, len, &out);
        *kvno = ntohl(*kvno);
    }
    if (crypto)
        krb5_crypto_destroy(context, crypto);
    if (ret == 0)
        ret = krb5_random_to_key(context, etype, out.data, out.length, k);
    krb5_data_free(&out);

    free_EncryptionKey(&intermediate);
    return ret;
}

/* Create a namespace principal */
static void
make_namespace(krb5_context context, HDB *db, const char *name)
{
    krb5_error_code ret = 0;
    hdb_entry e;
    Key k;

    memset(&k, 0, sizeof(k));
    k.mkvno = 0;
    k.salt = 0;

    /* Setup the HDB entry */
    memset(&e, 0, sizeof(e));
    e.created_by.time = krs[0].epoch;
    e.valid_start = e.valid_end = e.pw_end = 0;
    e.generation = 0;
    e.flags = int2HDBFlags(0);
    e.flags.server = e.flags.client = 1;
    e.flags.virtual = 1;

    /* Setup etypes */
    if (ret == 0 &&
        (e.etypes = malloc(sizeof(*e.etypes))) == NULL)
        ret = krb5_enomem(context);
    if (ret == 0)
        e.etypes->len = 3;
    if (ret == 0 &&
        (e.etypes->val = calloc(e.etypes->len,
                                      sizeof(e.etypes->val[0]))) == NULL)
        ret = krb5_enomem(context);
    if (ret == 0) {
        e.etypes->val[0] = KRB5_ENCTYPE_AES128_CTS_HMAC_SHA256_128;
        e.etypes->val[1] = KRB5_ENCTYPE_AES256_CTS_HMAC_SHA384_192;
        e.etypes->val[2] = KRB5_ENCTYPE_AES256_CTS_HMAC_SHA1_96;
    }

    /* Setup max_life and max_renew */
    if (ret == 0 &&
        (e.max_life = malloc(sizeof(*e.max_life))) == NULL)
        ret = krb5_enomem(context);
    if (ret == 0 &&
        (e.max_renew = malloc(sizeof(*e.max_renew))) == NULL)
        ret = krb5_enomem(context);
    if (ret == 0)
        /* Make it long, so we see the clamped max */
        *e.max_renew = 2 * ((*e.max_life = 15 * 24 * 3600));

    /* Setup principal name and created_by */
    if (ret == 0)
        ret = krb5_parse_name(context, name, &e.principal);
    if (ret == 0)
        ret = krb5_parse_name(context, "admin@BAR.EXAMPLE",
                              &e.created_by.principal);

    /* Make base keys for first epoch */
    if (ret == 0)
        ret = make_base_key(context, e.principal, base_pw[0], &k.key);
    if (ret == 0)
        add_Keys(&e.keys, &k);
    if (ret == 0)
        ret = hdb_entry_set_pw_change_time(context, &e, krs[0].epoch);
    free_Key(&k);
    e.kvno = krs[0].base_key_kvno;

    /* Move them to history */
    if (ret == 0)
        ret = hdb_add_current_keys_to_history(context, &e);
    free_Keys(&e.keys);

    /* Make base keys for second epoch */
    if (ret == 0)
        ret = make_base_key(context, e.principal, base_pw[1], &k.key);
    if (ret == 0)
        add_Keys(&e.keys, &k);
    e.kvno = krs[1].base_key_kvno;
    if (ret == 0)
        ret = hdb_entry_set_pw_change_time(context, &e, krs[1].epoch);

    /* Add the key rotation metadata */
    if (ret == 0)
        ret = hdb_entry_add_key_rotation(context, &e, 0, &krs[0]);
    if (ret == 0)
        ret = hdb_entry_add_key_rotation(context, &e, 0, &krs[1]);

    if (ret == 0)
        ret = db->hdb_store(context, db, 0, &e);
    if (ret)
        krb5_err(context, 1, ret, "failed to setup a namespace principal");
    free_Key(&k);
    hdb_free_entry(context, db, &e);
}

#define WK_PREFIX "WELLKNOWN/" HDB_WK_NAMESPACE "/"

static const char *expected[] = {
    WK_PREFIX "_/bar.example@BAR.EXAMPLE",
    "HTTP/bar.example@BAR.EXAMPLE",
    "HTTP/foo.bar.example@BAR.EXAMPLE",
    "host/foo.bar.example@BAR.EXAMPLE",
    "HTTP/blah.foo.bar.example@BAR.EXAMPLE",
};
static const char *unexpected[] = {
    WK_PREFIX "_/no.example@BAZ.EXAMPLE",
    "HTTP/no.example@BAR.EXAMPLE",
    "HTTP/foo.no.example@BAR.EXAMPLE",
    "HTTP/blah.foo.no.example@BAR.EXAMPLE",
};

/*
 * We'll fetch as many entries as we have principal names in `expected[]', for
 * as many KeyRotation periods as we have (between 1 and 3), and for up to 5
 * different time offsets in each period.
 */
#define NUM_OFFSETS 5
static hdb_entry e[
    (sizeof(expected) / sizeof(expected[0])) *
    (sizeof(krs) / sizeof(krs[0])) *
    NUM_OFFSETS
];

static int
hist_key_compar(const void *va, const void *vb)
{
    const hdb_keyset *a = va;
    const hdb_keyset *b = vb;

    return a->kvno - b->kvno;
}

/*
 * Fetch keys for some decent time in the given kr.
 *
 * `kr' is an index into the global `krs[]'.
 * `t' is a number 0..4 inclusive that identifies a time period relative to the
 * epoch of `krs[kr]' (see code below).
 */
static void
fetch_entries(krb5_context context,
              HDB *db,
              size_t kr,
              size_t t,
              int must_fail)
{
    krb5_error_code ret = 0;
    krb5_principal p = NULL;
    krb5_keyblock base_key, dk;
    hdb_entry *ep;
    hdb_entry no;
    size_t i, b;
    int toffset = 0;

    memset(&base_key, 0, sizeof(base_key));

    /* Work out offset of first entry in `e[]' */
    assert(kr < sizeof(krs) / sizeof(krs[0]));
    assert(t < NUM_OFFSETS);
    b = (kr * NUM_OFFSETS + t) * (sizeof(expected) / sizeof(expected[0]));
    assert(b < sizeof(e) / sizeof(e[0]));
    assert(sizeof(e) / sizeof(e[0]) - b >=
           (sizeof(expected) / sizeof(expected[0])));

    switch (t) {
    case 0: toffset = 1;                         break; /* epoch + 1s */
    case 1: toffset = 1 + (krs[kr].period >> 1); break; /* epoch + period/2 */
    case 2: toffset = 1 + (krs[kr].period >> 2); break; /* epoch + period/4 */
    case 3: toffset = 1 + (krs[kr].period >> 3); break; /* epoch + period/8 */
    case 4: toffset = 1 - (krs[kr].period >> 3); break; /* epoch - period/8 */
    }

    for (i = 0; ret == 0 && i < sizeof(expected) / sizeof(expected[0]); i++) {
        ep = &e[b + i];
        memset(ep, 0, sizeof(*ep));
        if (ret == 0)
            ret = krb5_parse_name(context, expected[i], &p);
        if (ret == 0 && i == 0) {
            if (toffset < 0 && kr)
                ret = make_base_key(context, p, base_pw[kr - 1], &base_key);
            else
                ret = make_base_key(context, p, base_pw[kr], &base_key);
        }
        if (ret == 0)
            ret = hdb_fetch_kvno(context, db, p,
                                 HDB_F_DECRYPT | HDB_F_ALL_KVNOS,
                                 krs[kr].epoch + toffset, 0, 0, ep);
        if (i && must_fail && ret == 0)
            krb5_errx(context, 1,
                      "virtual principal that shouldn't exist does");
        if (kr == 0 && toffset < 0 && ret == HDB_ERR_NOENTRY)
            continue;
        if (kr == 0 && toffset < 0) {
            /*
             * Virtual principals don't exist before their earliest key
             * rotation epoch's start time.
             */
            if (i == 0) {
                if (ret)
                    krb5_errx(context, 1,
                              "namespace principal does not exist before its time");
            } else if (i != 0) {
                if (ret == 0)
                    krb5_errx(context, 1,
                              "virtual principal exists before its time");
                if (ret != HDB_ERR_NOENTRY)
                    krb5_errx(context, 1, "wrong error code");
                ret = 0;
            }
        } else {
            if (ret == 0 &&
                !krb5_principal_compare(context, p, ep->principal))
            krb5_errx(context, 1, "wrong principal in fetched entry");
        }

        {
            HDB_Ext_KeySet *hist_keys;
            HDB_extension *ext;
            ext = hdb_find_extension(ep,
                                     choice_HDB_extension_data_hist_keys);
            if (ext) {
                /* Sort key history by kvno, why not */
                hist_keys = &ext->data.u.hist_keys;
                qsort(hist_keys->val, hist_keys->len,
                      sizeof(hist_keys->val[0]), hist_key_compar);
            }
        }

        krb5_free_principal(context, p);
    }
    if (ret && must_fail) {
        free_EncryptionKey(&base_key);
        return;
    }
    if (ret)
        krb5_err(context, 1, ret, "virtual principal test failed");

    for (i = 0; i < sizeof(unexpected) / sizeof(unexpected[0]); i++) {
        memset(&no, 0, sizeof(no));
        if (ret == 0)
            ret = krb5_parse_name(context, unexpected[i], &p);
        if (ret == 0)
            ret = hdb_fetch_kvno(context, db, p, HDB_F_DECRYPT,
                                 krs[kr].epoch + toffset, 0, 0, &no);
        if (ret == 0)
            krb5_errx(context, 1, "bogus principal exists, wat");
        krb5_free_principal(context, p);
        ret = 0;
    }

    if (kr == 0 && toffset < 0)
        return;

    /*
     * XXX
     *
     * Add check that derived keys are a) different, b) as expected, using a
     * set of test vectors or else by computing the expected keys here with
     * code that's not shared with lib/hdb/common.c.
     *
     * Add check that we get expected past and/or future keys, not just current
     * keys.
     */
    for (i = 1; ret == 0 && i < sizeof(expected) / sizeof(expected[0]); i++) {
        uint32_t kvno;
        time_t set_time, chg_time;

        ep = &e[b + i];
        if (toffset > 0) {
            ret = tderive_key(context, expected[i], &krs[kr], toffset,
                              &base_key, base_key.keytype, &dk, &kvno, &set_time);
        } else /* XXX */{
            /* XXX */
            assert(kr);
            ret = tderive_key(context, expected[i], &krs[kr - 1],
                              krs[kr].epoch - krs[kr - 1].epoch + toffset,
                              &base_key, base_key.keytype, &dk, &kvno, &set_time);
        }
        if (ret)
            krb5_err(context, 1, ret, "deriving keys for comparison");

        if (kvno != ep->kvno)
            krb5_errx(context, 1, "kvno mismatch (%u != %u)", kvno, ep->kvno);
        (void) hdb_entry_get_pw_change_time(ep, &chg_time);
        if (set_time != chg_time)
            krb5_errx(context, 1, "key change time mismatch");
        if (ep->keys.len == 0)
            krb5_errx(context, 1, "no keys!");
        if (ep->keys.val[0].key.keytype != dk.keytype)
            krb5_errx(context, 1, "enctype mismatch!");
        if (ep->keys.val[0].key.keyvalue.length !=
            dk.keyvalue.length)
            krb5_errx(context, 1, "key length mismatch!");
        if (memcmp(ep->keys.val[0].key.keyvalue.data,
                   dk.keyvalue.data, dk.keyvalue.length) != 0)
            krb5_errx(context, 1, "key mismatch!");
        if (memcmp(ep->keys.val[0].key.keyvalue.data,
                   e[b + i - 1].keys.val[0].key.keyvalue.data,
                   dk.keyvalue.length) == 0)
            krb5_errx(context, 1, "different virtual principals have the same keys!");
        /* XXX Add check that we have the expected number of history keys */
        free_EncryptionKey(&dk);
    }
    free_EncryptionKey(&base_key);
}

static void
check_kvnos(krb5_context context)
{
    HDB_Ext_KeySet keysets;
    size_t i, k, m, p; /* iterator indices */

    keysets.len = 0;
    keysets.val = 0;

    /* For every principal name */
    for (i = 0; i < sizeof(expected)/sizeof(expected[0]); i++) {
        free_HDB_Ext_KeySet(&keysets);

        /* For every entry we've fetched for it */
        for (k = 0; k < sizeof(e)/sizeof(e[0]); k++) {
            HDB_Ext_KeySet *hist_keys;
            HDB_extension *ext;
            hdb_entry *ep;
            int match = 0;

            if ((k % NUM_OFFSETS) != i)
                continue;

            ep = &e[k];
            if (ep->principal == NULL)
                continue; /* Didn't fetch this one */

            /*
             * Check that the current keys for it match what we've seen already
             * or else add them to `keysets'.
             */
            for (m = 0; m < keysets.len; m++) {
                if (ep->kvno == keysets.val[m].kvno) {
                    /* Check the key is the same */
                    if (ep->keys.val[0].key.keytype !=
                        keysets.val[m].keys.val[0].key.keytype ||
                        ep->keys.val[0].key.keyvalue.length !=
                        keysets.val[m].keys.val[0].key.keyvalue.length ||
                        memcmp(ep->keys.val[0].key.keyvalue.data,
                               keysets.val[m].keys.val[0].key.keyvalue.data,
                               ep->keys.val[0].key.keyvalue.length) != 0)
                        krb5_errx(context, 1,
                                  "key mismatch for same princ & kvno");
                    match = 1;
                }
            }
            if (m == keysets.len) {
                hdb_keyset ks;

                ks.kvno = ep->kvno;
                ks.keys = ep->keys;
                ks.set_time = 0;
                if (add_HDB_Ext_KeySet(&keysets, &ks))
                    krb5_err(context, 1, ENOMEM, "out of memory");
                match = 1;
            }
            if (match)
                continue;

            /* For all non-current keysets, repeat the above */
            ext = hdb_find_extension(ep,
                                     choice_HDB_extension_data_hist_keys);
            if (!ext)
                continue;
            hist_keys = &ext->data.u.hist_keys;
            for (p = 0; p < hist_keys->len; p++) {
                for (m = 0; m < keysets.len; m++) {
                    if (keysets.val[m].kvno == hist_keys->val[p].kvno)
                        if (ep->keys.val[0].key.keytype !=
                            keysets.val[m].keys.val[0].key.keytype ||
                            ep->keys.val[0].key.keyvalue.length !=
                            keysets.val[m].keys.val[0].key.keyvalue.length ||
                            memcmp(ep->keys.val[0].key.keyvalue.data,
                                   keysets.val[m].keys.val[0].key.keyvalue.data,
                                   ep->keys.val[0].key.keyvalue.length) != 0)
                            krb5_errx(context, 1,
                                      "key mismatch for same princ & kvno");
                }
                if (m == keysets.len) {
                    hdb_keyset ks;
                    ks.kvno = ep->kvno;
                    ks.keys = ep->keys;
                    ks.set_time = 0;
                    if (add_HDB_Ext_KeySet(&keysets, &ks))
                        krb5_err(context, 1, ENOMEM, "out of memory");
                }
            }
        }
    }
    free_HDB_Ext_KeySet(&keysets);
}

static void
print_em(krb5_context context)
{
    HDB_Ext_KeySet *hist_keys;
    HDB_extension *ext;
    size_t i, p;

    for (i = 0; i < sizeof(e)/sizeof(e[0]); i++) {
        const char *name = expected[i % (sizeof(expected)/sizeof(expected[0]))];
        char *x;

        if (0 == i % (sizeof(expected)/sizeof(expected[0])))
            continue;
        if (e[i].principal == NULL)
            continue;
        hex_encode(e[i].keys.val[0].key.keyvalue.data,
                   e[i].keys.val[0].key.keyvalue.length, &x);
        printf("%s %u %s\n", x, e[i].kvno, name);
        free(x);

        ext = hdb_find_extension(&e[i], choice_HDB_extension_data_hist_keys);
        if (!ext)
            continue;
        hist_keys = &ext->data.u.hist_keys;
        for (p = 0; p < hist_keys->len; p++) {
            hex_encode(hist_keys->val[p].keys.val[0].key.keyvalue.data,
                       hist_keys->val[p].keys.val[0].key.keyvalue.length, &x);
            printf("%s %u %s\n", x, hist_keys->val[p].kvno, name);
	    free(x);
        }
    }
}

#if 0
static void
check_expected_kvnos(krb5_context context)
{
    HDB_Ext_KeySet *hist_keys;
    HDB_extension *ext;
    size_t i, k, m, p;

    for (i = 0; i < sizeof(expected)/sizeof(expected[0]); i++) {
        for (k = 0; k < sizeof(krs)/sizeof(krs[0]); k++) {
            hdb_entry *ep = &e[k * sizeof(expected)/sizeof(expected[0]) + i];

            if (ep->principal == NULL)
                continue;
            for (m = 0; m < NUM_OFFSETS; m++) {
                ext = hdb_find_extension(ep,
                                         choice_HDB_extension_data_hist_keys);
                if (!ext)
                    continue;
                hist_keys = &ext->data.u.hist_keys;
                for (p = 0; p < hist_keys->len; p++) {
                    fprintf(stderr, "%s at %lu, %lu: history kvno %u\n",
                            expected[i], k, m, hist_keys->val[p].kvno);
                }
            }
            fprintf(stderr, "%s at %lu: kvno %u\n", expected[i], k,
                    ep->kvno);
        }
    }
}
#endif

#define SOME_TIME 1596318329
#define SOME_BASE_KVNO 150
#define SOME_EPOCH (SOME_TIME - (7 * 24 * 3600) - (SOME_TIME % (7 * 24 * 3600)))
#define SOME_PERIOD 3600

#define CONF                                        \
    "[hdb]\n"                                       \
    "\tenable_virtual_hostbased_princs = true\n"    \
    "\tvirtual_hostbased_princ_mindots = 1\n"       \
    "\tvirtual_hostbased_princ_maxdots = 3\n"       \

int
main(int argc, char **argv)
{
    krb5_error_code ret;
    krb5_context context;
    size_t i;
    HDB *db = NULL;

    setprogname(argv[0]);
    memset(e, 0, sizeof(e));
    ret = krb5_init_context(&context);
    if (ret == 0)
        ret = krb5_set_config(context, CONF);
    if (ret == 0)
        ret = krb5_plugin_register(context, PLUGIN_TYPE_DATA, "hdb_test_interface",
                                   &hdb_test);
    if (ret == 0)
        ret = hdb_create(context, &db, "test:mem");
    if (ret)
        krb5_err(context, 1, ret, "failed to setup HDB driver and test");

    assert(db->enable_virtual_hostbased_princs);
    assert(db->virtual_hostbased_princ_ndots == 1);
    assert(db->virtual_hostbased_princ_maxdots == 3);

    /* Setup key rotation metadata in a convenient way */
    /*
     * FIXME Reorder these two KRs to match how we store them to avoid
     * confusion.  #0 should be future-most, #1 should past-post.
     */
    krs[0].flags = krs[1].flags = int2KeyRotationFlags(0);
    krs[0].epoch = SOME_EPOCH - 20 * 24 * 3600;
    krs[0].period = SOME_PERIOD >> 1;
    krs[0].base_kvno = 150;
    krs[0].base_key_kvno = 1;
    krs[1].epoch = SOME_TIME;
    krs[1].period = SOME_PERIOD;
    krs[1].base_kvno = krs[0].base_kvno + 1 + (krs[1].epoch + (krs[0].period - 1) - krs[0].epoch) / krs[0].period;
    krs[1].base_key_kvno = 2;

    {
        HDB_Ext_KeyRotation existing_krs, new_krs;
        KeyRotation ordered_krs[2];

        ordered_krs[0] = krs[1];
        ordered_krs[1] = krs[0];
        existing_krs.len = 0;
        existing_krs.val = 0;
        new_krs.len = 1;
        new_krs.val = &ordered_krs[1];
        if ((ret = hdb_validate_key_rotations(context, NULL, &new_krs)) ||
            (ret = hdb_validate_key_rotations(context, &existing_krs,
                                              &new_krs)))
            krb5_err(context, 1, ret, "Valid KeyRotation thought invalid");
        new_krs.len = 1;
        new_krs.val = &ordered_krs[0];
        if ((ret = hdb_validate_key_rotations(context, NULL, &new_krs)) ||
            (ret = hdb_validate_key_rotations(context, &existing_krs,
                                              &new_krs)))
            krb5_err(context, 1, ret, "Valid KeyRotation thought invalid");
        new_krs.len = 2;
        new_krs.val = &ordered_krs[0];
        if ((ret = hdb_validate_key_rotations(context, NULL, &new_krs)) ||
            (ret = hdb_validate_key_rotations(context, &existing_krs,
                                              &new_krs)))
            krb5_err(context, 1, ret, "Valid KeyRotation thought invalid");
        existing_krs.len = 1;
        existing_krs.val = &ordered_krs[1];
        if ((ret = hdb_validate_key_rotations(context, &existing_krs,
                                              &new_krs)))
            krb5_err(context, 1, ret, "Valid KeyRotation thought invalid");
        existing_krs.len = 2;
        existing_krs.val = &ordered_krs[0];
        if ((ret = hdb_validate_key_rotations(context, &existing_krs,
                                              &new_krs)))
            krb5_err(context, 1, ret, "Valid KeyRotation thought invalid");

        new_krs.len = 2;
        new_krs.val = &krs[0];
        if ((ret = hdb_validate_key_rotations(context, &existing_krs,
                                              &new_krs)) == 0)
            krb5_errx(context, 1, "Invalid KeyRotation thought valid");
    }

    make_namespace(context, db, WK_PREFIX "_/bar.example@BAR.EXAMPLE");

    fetch_entries(context, db, 1, 0, 0);
    fetch_entries(context, db, 1, 1, 0);
    fetch_entries(context, db, 1, 2, 0);
    fetch_entries(context, db, 1, 3, 0);
    fetch_entries(context, db, 1, 4, 0); /* Just before newest KR */

    fetch_entries(context, db, 0, 0, 0);
    fetch_entries(context, db, 0, 1, 0);
    fetch_entries(context, db, 0, 2, 0);
    fetch_entries(context, db, 0, 3, 0);
    fetch_entries(context, db, 0, 4, 1); /* Must fail: just before 1st KR */

    /*
     * Check that for every virtual principal in `expected[]', all the keysets
     * with the same kvno, in all the entries fetched for different times,
     * match.
     */
    check_kvnos(context);

#if 0
    /*
     * Check that for every virtual principal in `expected[]' we have the
     * expected key history.
     */
    check_expected_kvnos(context);
#endif

    /*
     * XXX Add various tests here, checking `e[]':
     *
     *  - Extract all {principal, kvno, key} for all keys, current and
     *    otherwise, then sort by {key, kvno, principal}, then check that the
     *    only time we have matching keys is when the kvno and principal also
     *    match.
     */

    print_em(context);

    /*
     * XXX Test adding a third KR, a 4th KR, dropping KRs...
     */

    /* Cleanup */
    for (i = 0; ret == 0 && i < sizeof(e) / sizeof(e[0]); i++)
        hdb_free_entry(context, db, &e[i]);
    db->hdb_destroy(context, db);
    krb5_free_context(context);
    return 0;
}
