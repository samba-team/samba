/*
 * $Id$
 */

#ifdef HAVE_OPENSSL

#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/md2.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/ui.h>
#include <openssl/pkcs12.h>
#include <openssl/engine.h>

#ifndef BN_is_negative
#define BN_set_negative(bn, flag) ((bn)->neg = (flag) ? 1 : 0)
#endif

#else

#include <rsa.h>
#include <dsa.h>
#include <sha.h>
#include <md5.h>
#include <md2.h>
#include <evp.h>
#include <rand.h>
#include <ui.h>
#include <engine.h>

#endif
