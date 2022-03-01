/*
 * Copyright (c) 2005, PADL Software Pty Ltd.
 * All rights reserved.
 *
 * Portions Copyright (c) 2009 Apple Inc. All rights reserved.
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
 * 3. Neither the name of PADL Software nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY PADL SOFTWARE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL PADL SOFTWARE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "kcm_locl.h"
#include <pwd.h>

krb5_error_code
kcm_ccache_resolve_client(krb5_context context,
			  kcm_client *client,
			  kcm_operation opcode,
			  const char *name,
			  kcm_ccache *ccache)
{
    krb5_error_code ret;
    const char *estr;

    ret = kcm_ccache_resolve(context, name, ccache);
    if (ret) {
        char *uid = NULL;

        /*
         * Both MIT and Heimdal are unable to, in krb5_cc_default(), call to
         * KCM (or CCAPI, or LSA, or...) to get the user's default ccache name
         * in their collection.  Instead, the default ccache name is obtained
         * in a static way, and for KCM that's "%{UID}".  When we
         * krb5_cc_switch(), we simply maintain a pointer to the name of the
         * ccache that was made the default, but klist can't make use of this
         * because krb5_cc_default() can't.
         *
         * The solution here is to first try resolving the ccache name given by
         * the client, and if that fails but the name happens to be what would
         * be the library's default KCM ccache name for that user, then try
         * resolving it through the default ccache name pointer saved at switch
         * time.
         */
        if (asprintf(&uid, "%llu", (unsigned long long)client->uid) == -1 ||
            uid == NULL)
            return ENOMEM;

        if (strcmp(name, uid) == 0) {
            struct kcm_default_cache *c;

            for (c = default_caches; c != NULL; c = c->next) {
                if (kcm_is_same_session(client, c->uid, c->session)) {
                    if (strcmp(c->name, name) != 0) {
                        ret = kcm_ccache_resolve(context, c->name, ccache);
                        break;
                    }
                }
            }
        }
        free(uid);
    }

    if (ret) {
	estr = krb5_get_error_message(context, ret);
	kcm_log(1, "Failed to resolve cache %s: %s", name, estr);
	krb5_free_error_message(context, estr);
	return ret;
    }

    ret = kcm_access(context, client, opcode, *ccache);
    if (ret) {
	ret = KRB5_FCC_NOFILE; /* don't disclose */
	kcm_release_ccache(context, *ccache);
    }

    return ret;
}

krb5_error_code
kcm_ccache_destroy_client(krb5_context context,
			  kcm_client *client,
			  const char *name)
{
    krb5_error_code ret;
    kcm_ccache ccache;
    const char *estr;

    ret = kcm_ccache_resolve(context, name, &ccache);
    if (ret) {
	estr = krb5_get_error_message(context, ret);
	kcm_log(1, "Failed to resolve cache %s: %s", name, estr);
	krb5_free_error_message(context, estr);
	return ret;
    }

    ret = kcm_access(context, client, KCM_OP_DESTROY, ccache);
    kcm_cleanup_events(context, ccache);
    kcm_release_ccache(context, ccache);
    if (ret)
	return ret;

    return kcm_ccache_destroy(context, name);
}

krb5_error_code
kcm_ccache_new_client(krb5_context context,
		      kcm_client *client,
		      const char *name,
		      kcm_ccache *ccache_p)
{
    krb5_error_code ret;
    kcm_ccache ccache;
    const char *estr;

    /* We insist the ccache name starts with UID or UID: */
    if (name_constraints != 0) {
	char prefix[64];
	size_t prefix_len;
	int bad = 1;

	snprintf(prefix, sizeof(prefix), "%ld:", (long)client->uid);
	prefix_len = strlen(prefix);

	if (strncmp(name, prefix, prefix_len) == 0)
	    bad = 0;
	else {
	    prefix[prefix_len - 1] = '\0';
	    if (strcmp(name, prefix) == 0)
		bad = 0;
	}

	/* Allow root to create badly-named ccaches */
	if (bad && !CLIENT_IS_ROOT(client))
	    return KRB5_CC_BADNAME;
    }

    ret = kcm_ccache_resolve(context, name, &ccache);
    if (ret == 0) {
	if ((ccache->uid != client->uid ||
	     ccache->gid != client->gid) && !CLIENT_IS_ROOT(client))
	    return KRB5_FCC_PERM;
    } else if (ret != KRB5_FCC_NOFILE && !(CLIENT_IS_ROOT(client) && ret == KRB5_FCC_PERM)) {
		return ret;
    }

    if (ret == KRB5_FCC_NOFILE) {
	ret = kcm_ccache_new(context, name, &ccache);
	if (ret) {
	    estr = krb5_get_error_message(context, ret);
	    kcm_log(1, "Failed to initialize cache %s: %s", name, estr);
	    krb5_free_error_message(context, estr);
	    return ret;
	}

	/* bind to current client */
	ccache->uid = client->uid;
	ccache->gid = client->gid;
	ccache->session = client->session;
    } else {
	ret = kcm_zero_ccache_data(context, ccache);
	if (ret) {
	    estr = krb5_get_error_message(context, ret);
	    kcm_log(1, "Failed to empty cache %s: %s", name, estr);
	    krb5_free_error_message(context, estr);
	    kcm_release_ccache(context, ccache);
	    return ret;
	}
	kcm_cleanup_events(context, ccache);
    }

    ret = kcm_access(context, client, KCM_OP_INITIALIZE, ccache);
    if (ret) {
	kcm_release_ccache(context, ccache);
	kcm_ccache_destroy(context, name);
	return ret;
    }

    /*
     * Finally, if the user is root and the cache was created under
     * another user's name, chown the cache to that user and their
     * default gid.
     */
    if (CLIENT_IS_ROOT(client)) {
	unsigned long uid;
	int matches = sscanf(name,"%ld:",&uid);
	if (matches == 0)
	    matches = sscanf(name,"%ld",&uid);
	if (matches == 1) {
	    struct passwd *pwd = getpwuid(uid);
	    if (pwd != NULL) {
		gid_t gid = pwd->pw_gid;
		kcm_chown(context, client, ccache, uid, gid);
	    }
	}
    }

    *ccache_p = ccache;
    return 0;
}

