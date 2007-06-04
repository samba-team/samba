/*
 * Copyright (c) 2007 Kungliga Tekniska Högskolan
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

#include "hx_locl.h"
#include <Security/Security.h>
RCSID("$Id$");

#ifdef HAVE_FRAMEWORK_SECURITY

static int
keychain_init(hx509_context context,
	      hx509_certs certs, void **data, int flags,
	      const char *residue, hx509_lock lock)
{
    *data = NULL;
    return 0;
}

/*
 *
 */

static int
keychain_free(hx509_certs certs, void *data)
{
    assert(data == NULL);
    return 0;
}

/*
 *
 */

struct iter {
    SecKeychainSearchRef searchRef;
    SecKeychainItemRef itemRef;
};

static int 
keychain_iter_start(hx509_context context,
		    hx509_certs certs, void *data, void **cursor)
{
    OSStatus ret;
    struct iter *iter;

    iter = calloc(1, sizeof(*iter));
    if (iter == NULL) {
	hx509_set_error_string(context, 0, ENOMEM, "out of memory");
	return ENOMEM;
    }

    ret = SecKeychainSearchCreateFromAttributes(NULL,
						kSecCertificateItemClass,
						NULL,
						&iter->searchRef);
    if (ret)
	errx(1, "SecKeychainSearchCreateFromAttributes: %d\n", ret);

    *cursor = iter;
    return 0;
}

/*
 *
 */

/*
 *
 */

static int
keychain_iter(hx509_context context,
	      hx509_certs certs, void *data, void *cursor, hx509_cert *cert)
{
    SecKeychainItemRef itemRef;
    struct iter *iter = cursor;
    Certificate t;
    OSStatus ret;
    UInt32 len;
    void *ptr;
    size_t size;
    
    *cert = NULL;

    ret = SecKeychainSearchCopyNext(iter->searchRef, &itemRef);
    if (ret == errSecItemNotFound)
	return ENOENT;
    else if (ret != 0)
	return EINVAL;
	
    ret = SecKeychainItemCopyAttributesAndData(itemRef, NULL, NULL,
					       NULL, &len, &ptr);
    if (ret)
	return EINVAL;
    
    ret = decode_Certificate(ptr, len, &t, &size);
    SecKeychainItemFreeAttributesAndData(NULL, ptr);
    CFRelease(itemRef);
    if (ret) {
	hx509_set_error_string(context, 0, ret, 
			       "Failed to parse certificate");
	return ret;
    }

    ret = hx509_cert_init(context, &t, cert);
    free_Certificate(&t);
    if (ret)
	return ret;

    return 0;
}

/*
 *
 */

static int
keychain_iter_end(hx509_context context,
		  hx509_certs certs,
		  void *data,
		  void *cursor)
{
    struct iter *iter = cursor;

    CFRelease(iter->searchRef);
    memset(iter, 0, sizeof(*iter));
    free(iter);
    return 0;
}

/*
 *
 */

struct hx509_keyset_ops keyset_keychain = {
    "KEYCHAIN",
    0,
    keychain_init,
    NULL,
    keychain_free,
    NULL,
    NULL,
    keychain_iter_start,
    keychain_iter,
    keychain_iter_end
};

#endif /* HAVE_FRAMEWORK_SECURITY */

/*
 *
 */

void
_hx509_ks_keychain_register(hx509_context context)
{
#ifdef HAVE_FRAMEWORK_SECURITY
    _hx509_ks_register(context, &keyset_keychain);
#endif
}
