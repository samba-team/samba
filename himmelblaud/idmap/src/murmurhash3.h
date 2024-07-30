/* This file is based on the public domain MurmurHash3 from Austin Appleby:
 * http://code.google.com/p/smhasher/source/browse/trunk/MurmurHash3.cpp
 *
 * We use only the 32 bit variant because the 2 produce different result while
 * we need to produce the same result regardless of the architecture as
 * clients can be both 64 or 32 bit at the same time.
 */

#ifndef _SHARED_MURMURHASH3_H_
#define _SHARED_MURMURHASH3_H_

/* CAUTION:
 * This file is also used in sss_client (pam, nss). Therefore it have to be
 * minimalist and cannot include DEBUG macros or header file util.h.
 */

#include <stdint.h>

uint32_t murmurhash3(const char *key, int len, uint32_t seed);

#endif /* _SHARED_MURMURHASH3_H_ */
